#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Runs the preregistered experiments (preregistration.json) on this Linux
    host and writes one machine-readable result file plus its evidence:

        sudo python3 observatory/experiments/run_experiments.py --build-dir observatory/build

    Needs root (network namespaces, BPF), iproute2, and a built collector.
    tshark or tcpdump, zeek, editcap and systemd make more criteria
    evaluable; a criterion whose prerequisites are missing is reported
    "not_evaluable", never passed.

    The result names the preregistration digest, the configuration, the
    kernel and feature manifest, the collector build and source revision,
    timings, telemetry loss, evidence files with SHA-256 digests and the
    limitations. Everything runs on veth pairs in network namespaces
    (tests/netns.py); results describe that virtual topology on this
    kernel, not Wi-Fi hardware.

    Exit status: 0 no criterion failed, 1 a criterion failed, 2 the runner
    could not run.
"""

import argparse
import json
import os
import platform
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
OBS = os.path.dirname(HERE)
ROOT = os.path.dirname(OBS)
TESTS = os.path.join(OBS, "tests")
sys.path.insert(0, OBS)
sys.path.insert(0, TESTS)

import netns
from luca_observatory import VERSION, correlate, evidence, pcapstats, zeeklog
from luca_observatory import client as obs_client
from luca_observatory import snapshot as snapmod
from luca_observatory.config import observatory_config

RESULT_SCHEMA = "luca.observatory.experiments/1"
TRAFFIC = os.path.join(TESTS, "traffic.py")
CAPS = "CAP_BPF CAP_NET_ADMIN CAP_PERFMON"
NOT_EVALUABLE = "not_evaluable"
PYTHON = "/usr/bin/python3" if os.access("/usr/bin/python3", os.X_OK) else sys.executable
OPS = {">=": lambda v, t: v >= t, "<=": lambda v, t: v <= t, "==": lambda v, t: v == t}


def tool(name, *alternatives):
    found = shutil.which(name)
    if found:
        return found
    for a in alternatives:
        if os.access(a, os.X_OK):
            return a
    return None


def first_line(args):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        out = p.stdout.decode("utf-8", "replace").strip().splitlines()
        return out[0] if out else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def sha256(path):
    return evidence.file_digest(path)


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def kernel_at_least(major, minor):
    try:
        parts = platform.release().split(".")
        return (int(parts[0]), int(parts[1].split("-")[0])) >= (major, minor)
    except (IndexError, ValueError):
        return False


def flows(snap, **match):
    return [f for f in (snap or {}).get("flows") or [] if all(f.get(k) == v for k, v in match.items())]


def counter_sum(snap, key):
    c = (snap or {}).get("counters") or {}
    return sum((c.get(d) or {}).get(key) or 0 for d in ("tx", "rx"))


def criterion(spec, value, detail=None, evaluable=True, also=True):
    """
        :param spec: the criterion as preregistered (id, statement, metric, op, threshold)
        :param also: further preregistered conditions of the statement that must hold
    """
    out = dict(spec)
    out["value"] = value
    out["detail"] = detail
    if not evaluable:
        out["verdict"] = NOT_EVALUABLE
    else:
        try:
            out["verdict"] = "pass" if OPS[spec["op"]](value, spec["threshold"]) and also else "fail"
        except TypeError:
            out["verdict"] = "fail"
    return out


def verdict(criteria):
    v = [c["verdict"] for c in criteria]
    if "error" in v:
        return "error"
    if "fail" in v:
        return "fail"
    if v and all(x == NOT_EVALUABLE for x in v):
        return NOT_EVALUABLE
    if NOT_EVALUABLE in v:
        return "incomplete"
    return "pass"


class Capture(object):
    """
        TShark (as Luca's capture.py runs it) or tcpdump on one interface of
        the access point namespace, with Luca's filter.
    """

    def __init__(self, runner, topo, iface, path):
        self.runner, self.topo, self.iface, self.path = runner, topo, iface, path
        self.proc = None
        self.tool = None

    def start(self):
        if self.runner.tools["tshark"]:
            self.tool = "tshark"
            cmd = [self.runner.tools["tshark"], "-i", self.iface, "-w", self.path, "-f", "tcp or udp", "-q"]
        elif self.runner.tools["tcpdump"]:
            self.tool = "tcpdump"
            cmd = [self.runner.tools["tcpdump"], "-i", self.iface, "-w", self.path, "-U", "-n", "-Z", "root",
                   "tcp or udp"]
        else:
            return False
        self.log_path = self.path + ".log"
        self.log = open(self.log_path, "wb")
        self.proc = self.topo.popen(self.topo.ap, cmd, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 15
        while time.time() < deadline and self.proc.poll() is None:
            with open(self.log_path, "rb") as f:
                text = f.read()
            if b"Capturing on" in text or b"listening on" in text:
                time.sleep(0.5)
                return True
            time.sleep(0.1)
        return self.proc.poll() is None

    def stop(self):
        if self.proc is None:
            return None
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.log.close()
        return self.proc.returncode


class Runner(object):

    def __init__(self, args, prereg, prereg_path):
        self.args = args
        self.prereg = prereg
        self.prereg_path = prereg_path
        self.build = os.path.abspath(args.build_dir)
        self.run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + platform.machine()
        self.results_dir = os.path.abspath(args.out or os.path.join(HERE, "results"))
        self.evidence_dir = os.path.join(self.results_dir, self.run_id)
        os.makedirs(self.evidence_dir, exist_ok=True)
        self.tools = {"tshark": tool("tshark"), "tcpdump": tool("tcpdump"), "zeek": tool("zeek", "/opt/zeek/bin/zeek"),
                      "editcap": tool("editcap"), "systemd-run": tool("systemd-run"), "systemctl": tool("systemctl")}
        self.systemd = bool(self.tools["systemd-run"] and os.path.isdir("/run/systemd/system"))
        self.sessions = {}
        self.counter = 0
        self.server = None
        # Unprivileged runs need files that user nobody can read and write.
        self.scratch_root = tempfile.mkdtemp(prefix="luca-exp-")
        os.chmod(self.scratch_root, 0o755)
        self.unpriv_obs = os.path.join(self.scratch_root, "observatory")
        shutil.copytree(OBS, self.unpriv_obs, ignore=shutil.ignore_patterns("results", "build", "__pycache__",
                                                                           "*.pcap*"))
        shutil.copytree(self.build, os.path.join(self.unpriv_obs, "build"),
                        ignore=shutil.ignore_patterns("libbpf*", "*.d"))
        for dirpath, dirnames, filenames in os.walk(self.unpriv_obs):
            os.chmod(dirpath, 0o755)
            for f in filenames:
                p = os.path.join(dirpath, f)
                os.chmod(p, 0o755 if os.access(p, os.X_OK) else 0o644)

    # ------------------------------------------------------------ plumbing

    def spec(self, exp, cid):
        for c in self.prereg["experiments"][exp]["criteria"]:
            if c["id"] == cid:
                return {k: c[k] for k in ("id", "statement", "metric", "op", "threshold")}
        raise KeyError(cid)

    def token(self):
        self.counter += 1
        return "{:08X}".format(0xE0000000 + self.counter)

    def session_dir(self, name):
        d = os.path.join(self.evidence_dir, "sessions", name)
        os.makedirs(os.path.join(d, "assets"), exist_ok=True)
        return d

    def scratch(self, name):
        d = os.path.join(self.scratch_root, name)
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o777)
        return d

    def start_server(self, topo):
        ready = os.path.join(self.scratch_root, "server-ready-{}".format(time.time()))
        self.server = topo.popen(topo.net, [PYTHON, TRAFFIC, "serve", "--bind", netns.SERVER, "--ready", ready],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not netns.wait_for(ready, 15, self.server):
            raise RuntimeError("traffic server did not start")

    def stop_server(self):
        if self.server is not None:
            netns.stop(self.server, 5)
            self.server = None

    def traffic(self, topo, *args):
        """
            Runs tests/traffic.py on the device. :return: its JSON report.
        """
        p = topo.exec(topo.dev, [PYTHON, TRAFFIC] + list(args), check=False, timeout=300)
        out = p.stdout.decode("utf-8", "replace").strip()
        try:
            data = json.loads(out.splitlines()[-1])
        except (ValueError, IndexError):
            data = {"error": out[-2000:]}
        data["exit_code"] = p.returncode
        return data

    def mix(self, topo):
        return self.traffic(topo, "client", "--server", netns.SERVER, "--router", netns.AP, "--router6", netns.AP6,
                            "--foreign-source", netns.FOREIGN)

    def scenario(self, topo, name, *extra):
        return self.traffic(topo, "scenario", name, "--server", netns.SERVER, "--router", netns.AP, *extra)

    def collector_args(self, build, iface, out, ready, attach="auto", interval=0.5, flush=2.0, extra=()):
        return [os.path.join(build, "luca-observatory"), "--iface", iface, "--output", out, "--session", "5A0E7E57",
                "--bpf-dir", build, "--ready-file", ready, "--attach", attach, "--interval", str(interval),
                "--flush", str(flush)] + list(extra)

    def transient(self, topo, args, unit, caps=None, wait=True):
        """
            A transient systemd service in the access point's namespace, as
            user nobody with exactly `caps` (none when caps is None): the
            mechanism the installed luca-observatory unit uses.
        """
        props = ["User=nobody", "Group=nogroup" if self.has_group("nogroup") else "Group=nobody",
                 "NetworkNamespacePath=/run/netns/" + topo.ap, "NoNewPrivileges=yes", "LimitMEMLOCK=infinity"]
        if caps:
            props += ["AmbientCapabilities=" + caps, "CapabilityBoundingSet=" + caps]
        else:
            props += ["CapabilityBoundingSet="]
        cmd = [self.tools["systemd-run"], "--quiet", "--collect", "--unit", unit]
        if wait:
            cmd += ["--wait", "--pipe"]
        for p in props:
            cmd += ["-p", p]
        return cmd + ["--"] + args, props

    @staticmethod
    def has_group(name):
        try:
            import grp
            grp.getgrnam(name)
            return True
        except (ImportError, KeyError):
            return False

    def stop_collector(self, proc, unit=None):
        if proc.poll() is None:
            if unit:
                subprocess.run([self.tools["systemctl"], "stop", unit], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=30)
                try:
                    proc.wait(30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            else:
                netns.stop(proc)
        return proc.returncode

    # ------------------------------------------------------------ sessions

    def run_session(self, topo, name, traffic, iface="ap0", capture_iface="ap0", attach="auto", interval=0.5,
                    flush=2.0, extra=(), capture=True, zeek=True, transient=False, caps=None, during=None):
        """
            One observed session laid out like a Luca capture directory:
            capture.pcap, assets/observatory.json, assets/conn.log and
            assets/observatory_summary.json.
            :param traffic: callable(topo) -> dict, the traffic generated
            :param during: callable(topo, proc) -> dict, run after the traffic
            :return: dict record of the session
        """
        d = self.session_dir(name)
        work = self.scratch(name) if transient else d
        out, ready = os.path.join(work, "observatory.json"), os.path.join(work, "ready")
        rec = {"name": name, "dir": d, "interface": iface, "capture_interface": capture_iface, "attach": attach,
               "interval": interval, "extra_args": list(extra), "started_at": time.time()}
        cap = Capture(self, topo, capture_iface, os.path.join(d, "capture.pcap")) if capture else None
        if cap is not None:
            rec["capture_started"] = cap.start()
            rec["capture_tool"] = cap.tool
        build = os.path.join(self.unpriv_obs, "build") if transient else self.build
        args = self.collector_args(build, iface, out, ready, attach, interval, flush, extra)
        unit = None
        with open(os.path.join(d, "collector.log"), "wb") as log:
            if transient:
                unit = "luca-exp-{}-{}".format(name.lower(), os.getpid())
                cmd, props = self.transient(topo, args, unit, caps)
                rec["transient_unit"] = {"name": unit, "properties": props}
                proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
            else:
                proc = topo.popen(topo.ap, args, stdout=log, stderr=subprocess.STDOUT)
            rec["collector_command"] = args
            t0 = time.time()
            rec["ready"] = netns.wait_for(ready, 30, proc)
            rec["ready_after_s"] = round(time.time() - t0, 3)
            before = topo.link_stats(topo.dev, "dev0")
            rec["traffic"] = traffic(topo) if traffic else None
            if during:
                rec["during"] = during(topo, proc)
            time.sleep(0.3)
            after = topo.link_stats(topo.dev, "dev0")
            rec["dev_delta"] = {"tx": after["tx_packets"] - before["tx_packets"],
                                "rx": after["rx_packets"] - before["rx_packets"]}
            rec["collector_exit"] = self.stop_collector(proc, unit)
        if cap is not None:
            rec["capture_exit"] = cap.stop()
        snap_path = os.path.join(d, "assets", "observatory.json")
        if os.path.exists(out):
            shutil.copyfile(out, snap_path)
        rec["snapshot"] = load_json(snap_path)
        write_json(os.path.join(d, "assets", "device.json"),
                   {"ip_address": netns.DEVICE, "mac_address": topo.mac(topo.dev, "dev0")})
        rec["summary"], rec["capture"] = self.analyse(d, capture_iface, zeek=zeek and capture)
        rec["finished_at"] = time.time()
        self.sessions[name] = rec
        return rec

    def analyse(self, d, capture_iface, capture_path=None, zeek=True, out_name="observatory_summary.json"):
        """
            Luca's correlation of one session. :return: (summary, capture Summary or None)
        """
        assets = os.path.join(d, "assets")
        session, snap = {}, None
        try:
            snap = snapmod.load(os.path.join(assets, "observatory.json"))
        except snapmod.SnapshotError as e:
            session = {"status": "unavailable", "error": str(e)}
        iface = (snap or {}).get("interface") or {}
        ctx = pcapstats.Context(iface.get("mac"), iface.get("addresses"))
        capture_path = capture_path or os.path.join(d, "capture.pcap")
        cap, cap_err = None, None
        try:
            cap = pcapstats.read(capture_path, ctx)
        except pcapstats.PcapError as e:
            cap_err = str(e)
        conns = None
        if zeek and self.tools["zeek"] and cap is not None:
            zdir = os.path.join(d, "zeek")
            os.makedirs(zdir, exist_ok=True)
            subprocess.run([self.tools["zeek"], "-C", "-r", os.path.abspath(capture_path)], cwd=zdir,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
            if os.path.exists(os.path.join(zdir, "conn.log")):
                shutil.copyfile(os.path.join(zdir, "conn.log"), os.path.join(assets, "conn.log"))
                conns = zeeklog.read(os.path.join(assets, "conn.log"))
            elif cap.packets == 0:
                conns = []
        summary = correlate.correlate(snapshot=snap, session=session, capture=cap, capture_error=cap_err,
                                      conns=conns, dns=[], alerts=None, device=load_json(os.path.join(assets, "device.json")),
                                      capture_interface=capture_iface)
        write_json(os.path.join(assets, out_name), summary)
        return summary, cap

    def session_evidence(self, rec):
        d = rec["dir"]
        files = {}
        for rel in ("assets/observatory.json", "assets/observatory_summary.json", "assets/conn.log", "capture.pcap",
                    "collector.log", "assets/observatory_summary_edited.json", "edited.pcapng", "service.log"):
            p = os.path.join(d, rel)
            if os.path.exists(p):
                files[rel] = {"sha256": sha256(p), "bytes": os.path.getsize(p)}
        snap = rec.get("snapshot") or {}
        summ = rec.get("summary") or {}
        return {"session": rec["name"], "dir": os.path.relpath(d, self.results_dir), "files": files,
                "collector_exit": rec.get("collector_exit"), "status": snap.get("status"),
                "attach": snap.get("attach"), "loss": snapmod.loss_report(snap) if snap else None,
                "coverage": (summ.get("coverage") or {}).get("assessment"), "counts": summ.get("counts"),
                "capture_packets": rec["capture"].packets if rec.get("capture") is not None else None,
                "duration_s": round(rec["finished_at"] - rec["started_at"], 3)}

    # ---------------------------------------------------------- experiments

    def exp_A(self, topo):
        rec = self.run_session(topo, "A-coverage", self.mix)
        snap, cap = rec["snapshot"] or {}, rec["capture"]
        kernel = {
            "tcp": len(flows(snap, proto=6, local=netns.DEVICE, remote=netns.SERVER, remote_port=8080)) == 3,
            "udp": any(f["tx"]["packets"] == 20 and f["rx"]["packets"] == 20
                       for f in flows(snap, proto=17, local=netns.DEVICE, remote=netns.SERVER, remote_port=5353)),
            "ttl63": any(f["tx"]["ttl_min"] == 63 for f in flows(snap, proto=17, remote=netns.SERVER, remote_port=5354)),
            "foreign_source": bool(flows(snap, local=netns.FOREIGN, remote=netns.SERVER)),
            "esp": any(f["tx"]["packets"] == 3 for f in flows(snap, proto=50, remote=netns.SERVER)),
            # 3 echo requests; rx also holds the port unreachable for the
            # TTL-63 datagram, since ICMP flows are keyed without a type.
            "icmp": any(f["tx"]["packets"] == 3 and 3 <= f["rx"]["packets"] <= 4
                        for f in flows(snap, proto=1, remote=netns.SERVER)),
            "ipv6": any(f["tx"]["packets"] >= 3 for f in flows(snap, family=6, proto=17, remote=netns.AP6,
                                                               remote_port=9)),
        }
        cflows = cap.flow_list() if cap is not None else []

        def in_capture(**m):
            return [f for f in cflows if all(f.get(k) == v for k, v in m.items())]
        captured = {
            "tcp": len(in_capture(proto=6, remote=netns.SERVER, remote_port=8080)) == 3,
            "udp": bool(in_capture(proto=17, remote=netns.SERVER, remote_port=5353)),
            "ttl63": bool(in_capture(proto=17, remote=netns.SERVER, remote_port=5354)),
            "foreign_source": bool(in_capture(proto=17, local=netns.FOREIGN)),
            "esp": bool(in_capture(proto=50)),
            "icmp": bool(in_capture(proto=1)),
            "ipv6": bool(in_capture(family=6, proto=17, remote=netns.AP6, remote_port=9)),
        }
        attach = snap.get("attach") or {}
        drops = snap.get("drops") or []
        closed = sum(d["count"] for d in drops if d["direction"] == "tx" and d["remote"] == netns.AP
                     and d["remote_port"] == 9 and d["proto"] == 17)
        rpf = sum(d["count"] for d in drops if d["direction"] == "tx" and d["remote"] == netns.SERVER
                  and d["remote_port"] == 5355)
        names = {d["reason_name"] for d in drops}
        named = not kernel_at_least(5, 17) or {"NO_SOCKET", "IP_RPFILTER"} <= names
        dev = rec["dev_delta"]
        tx, rx = (snap.get("counters") or {}).get("tx") or {}, (snap.get("counters") or {}).get("rx") or {}
        diff = max(abs((tx.get("skbs") or 0) - dev["tx"]), abs((rx.get("skbs") or 0) - dev["rx"]))
        drops_ok = attach.get("drop_tracepoint") == "attached"
        criteria = [
            criterion(self.spec("A", "A1"), sum(kernel.values()) / float(len(kernel)), kernel),
            criterion(self.spec("A", "A2"), all(captured[c] for c in ("tcp", "udp", "ttl63", "foreign_source", "ipv6"))
                      and not captured["esp"] and not captured["icmp"], captured, evaluable=cap is not None),
            criterion(self.spec("A", "A3"), closed >= 3 and rpf >= 1 and named,
                      {"closed_port_drops": closed, "rp_filter_drops": rpf, "reason_names": sorted(n for n in names if n),
                       "drop_tracepoint": attach.get("drop_tracepoint"), "drop_note": attach.get("drop_note")},
                      evaluable=drops_ok),
            criterion(self.spec("A", "A4"), diff, {"kernel": {"tx": tx.get("skbs"), "rx": rx.get("skbs")},
                                                   "veth": dev}),
        ]
        kernel_only = [c for c in kernel if kernel[c] and not captured[c]] + \
            (["drop_reasons"] if drops_ok and closed else [])
        return {"criteria": criteria, "measurements": {"kernel_only_classes": kernel_only,
                                                         "traffic": rec["traffic"]},
                "evidence": [self.session_evidence(rec)]}

    def ground_truth_indices(self, snap):
        patterns = [dict(proto=6, local=netns.DEVICE, remote=netns.SERVER, remote_port=8080),
                    dict(proto=17, local=netns.DEVICE, remote=netns.SERVER, remote_port=5353),
                    dict(proto=17, local=netns.DEVICE, remote=netns.SERVER, remote_port=5354),
                    dict(proto=17, local=netns.FOREIGN, remote=netns.SERVER, remote_port=5355),
                    dict(proto=17, local=netns.DEVICE, remote=netns.AP, remote_port=9),
                    dict(proto=6, local=netns.DEVICE, remote=netns.AP, remote_port=9),
                    dict(family=6, proto=17, local=netns.DEVICE6, remote=netns.AP6, remote_port=9)]
        expected = [3, 1, 1, 1, 1, 1, 1]
        found = []
        for p, n in zip(patterns, expected):
            idx = [i for i, f in enumerate((snap or {}).get("flows") or []) if all(f.get(k) == v for k, v in p.items())]
            found += idx[:n] + [None] * (n - len(idx[:n]))
        return found

    @staticmethod
    def obs_for_flow(summary, index):
        for o in summary["observations"]:
            for e in o["evidence"]:
                if e["source"] == "kernel.tc" and e["pointer"] == "/flows/{}".format(index):
                    return o
        return None

    def exp_C(self, topo):
        criteria, evid, meas = [], [], {}
        rec = self.sessions["A-coverage"]
        summ, snap = rec["summary"], rec["snapshot"]
        have_zeek = os.path.exists(os.path.join(rec["dir"], "assets", "conn.log"))
        gt = self.ground_truth_indices(snap)
        corroborated = 0
        per_flow = []
        for i in gt:
            o = self.obs_for_flow(summ, i) if i is not None else None
            ok = o is not None and o["label"] == "CORRELATED" and o["category"] == "corroborated"
            corroborated += ok
            per_flow.append({"flow": i, "label": o and o["label"], "category": o and o["category"],
                             "reasons": o and o["reasons"]})
        ambiguous = sum("ambiguous" in o["statement"] for o in summ["observations"])
        capture_only = sum(o["sources"] == ["zeek.conn"] for o in summ["observations"])
        criteria.append(criterion(self.spec("C", "C1"), corroborated / float(len(gt)),
                                  {"flows": per_flow, "ambiguous": ambiguous, "capture_only": capture_only},
                                  evaluable=have_zeek, also=ambiguous == 0 and capture_only == 0))
        kernel_only = [o for o in summ["observations"] if o["label"] == "OBSERVED" and o["sources"] == ["kernel.tc"]]
        esp_icmp = [o for o in kernel_only if o["statement"].startswith(("ESP ", "ICMP "))]
        complete = all(o["reasons"] for o in kernel_only) and len(esp_icmp) >= 2 and \
            all(any("capture filter" in r for r in o["reasons"]) for o in esp_icmp)
        criteria.append(criterion(self.spec("C", "C2"), complete,
                                  [{"statement": o["statement"], "reasons": o["reasons"]} for o in kernel_only]))
        meas["session_A_counts"] = summ["counts"]

        # C4: capture-loss sensitivity on a paced session.
        rec4 = self.run_session(topo, "C4-paced", lambda t: self.scenario(t, "echo", "--count", "200",
                                                                            "--gap", "0.01"), zeek=False)
        evid.append(self.session_evidence(rec4))
        cov = rec4["summary"]["coverage"] or {}
        criteria.append(criterion(self.spec("C", "C4a"), cov.get("assessment") == "consistent", cov,
                                  evaluable=rec4["capture"] is not None))
        detail, ok, evaluable = {}, False, bool(self.tools["editcap"] and self.tools["tshark"] and rec4["capture"])
        if evaluable:
            pcap = os.path.join(rec4["dir"], "capture.pcap")
            p = subprocess.run([self.tools["tshark"], "-r", pcap, "-T", "fields", "-e", "frame.time_epoch"],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
            times = [float(x) for x in p.stdout.decode().split()]
            samples = snapmod.timeline_rows(rec4["snapshot"])
            inner = [r["realtime"] for r in samples if times and times[0] <= r["realtime"] <= times[-1]]
            k = 20
            start = None
            if len(inner) >= 2:
                lo, hi = inner[0] + 0.05, inner[-1] - 0.05
                inside = [i for i, t in enumerate(times) if lo < t < hi]
                for i in inside:
                    if i + k - 1 < len(times) and times[i + k - 1] < hi:
                        start = i + 1  # editcap counts from 1
                        break
            if start is None:
                evaluable = False
                detail = {"reason": "no 20 consecutive packets between two interior kernel samples",
                          "interior_samples": len(inner)}
            else:
                edited = os.path.join(rec4["dir"], "edited.pcapng")
                subprocess.run([self.tools["editcap"], pcap, edited, "{}-{}".format(start, start + k - 1)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=120)
                summ_e, _ = self.analyse(rec4["dir"], "ap0", capture_path=edited, zeek=False,
                                         out_name="observatory_summary_edited.json")
                cov_e = summ_e["coverage"] or {}
                missed = sum(d.get("missed_at_least") or 0 for d in (cov_e.get("directions") or {}).values())
                ok = cov_e.get("assessment") == "incomplete" and 1 <= missed <= k
                detail = {"deleted_packets": k, "deleted_range": [start, start + k - 1],
                          "assessment": cov_e.get("assessment"), "missed_at_least": missed,
                          "directions": cov_e.get("directions")}
        criteria.append(criterion(self.spec("C", "C4b"), ok, detail, evaluable=evaluable))
        evid.insert(0, self.session_evidence(rec))
        return {"criteria": criteria, "measurements": meas, "evidence": evid}

    def exp_C3(self):
        with netns.Topology(nat=True) as topo:
            self.start_server(topo)
            try:
                rec = self.run_session(topo, "C3-nat", self.mix, iface="up0", capture_iface="ap0")
            finally:
                self.stop_server()
        summ = rec["summary"]
        evaluable = os.path.exists(os.path.join(rec["dir"], "assets", "conn.log"))
        wrong, certain, unique, amb = 0, 0, 0, 0
        for o in summ["observations"]:
            kev = [e["record"] for e in o["evidence"] if e["source"] == "kernel.tc" and
                   str(e["pointer"]).startswith("/flows/")]
            zev = [e["record"] for e in o["evidence"] if e["source"] == "zeek.conn"]
            if o["label"] != "CORRELATED" or not kev or not zev:
                continue
            if o["category"] == "corroborated":
                certain += 1
            if "ambiguous" in o["statement"]:
                amb += 1
            else:
                unique += 1
            for z in zev:
                end = (z.get("id.resp_h"), z.get("id.resp_p"))
                if not all(end in {(k["local"], k["local_port"]), (k["remote"], k["remote_port"])} for k in kev):
                    wrong += 1
        crit = criterion(self.spec("C", "C3"), wrong + certain,
                         {"wrong_endpoint_matches": wrong, "corroborated_across_nat": certain,
                          "unique_remote_only_matches": unique, "ambiguous": amb, "counts": summ["counts"]},
                         evaluable=evaluable)
        return crit, self.session_evidence(rec)

    def exp_D(self, topo):
        labels = {"benign": set(), "icmp": {"KNO-01"}, "tunnel": {"KNO-02"}, "forwarded": {"KNO-03"},
                  "spoof": {"KNO-04"}, "twostacks": {"KNO-05"}}
        designed = {"KNO-01": "OBSERVED", "KNO-02": "OBSERVED", "KNO-03": "INFERRED", "KNO-04": "OBSERVED",
                    "KNO-05": "INFERRED"}
        found_labels, fp, prov_ok, table, evid = 0, 0, True, {}, []
        for name, expected in labels.items():
            rec = self.run_session(topo, "D-" + name, lambda t, n=name: self.scenario(t, n))
            evid.append(self.session_evidence(rec))
            findings = rec["summary"]["findings"]
            ids = [f["id"] for f in findings]
            found_labels += len(expected & set(ids))
            fp += sum(1 for i in ids if i not in expected)
            prov_ok = prov_ok and all(f["provenance"] == designed.get(f["id"]) for f in findings)
            table[name] = {"expected": sorted(expected), "found": ids, "collector_status": (rec["snapshot"] or {}).get("status"),
                           "traffic": rec["traffic"]}
        positives = sum(len(v) for v in labels.values())
        return {"criteria": [criterion(self.spec("D", "D1"), found_labels / float(positives), table),
                             criterion(self.spec("D", "D2"), fp, table),
                             criterion(self.spec("D", "D3"), prov_ok, designed)],
                "measurements": {"scenarios": table}, "evidence": evid}

    def capture_echo_packets(self, cap):
        if cap is None:
            return None
        return sum(f["tx"]["packets"] + f["rx"]["packets"] for f in cap.flow_list()
                   if f["proto"] == 17 and f["remote"] == netns.SERVER and f["remote_port"] == 5353)

    def exp_E(self, topo):
        criteria, evid, meas = [], [], {}
        echo = lambda n: (lambda t: self.scenario(t, "echo", "--count", str(n)))

        # E1: no capabilities.
        if self.systemd:
            rec = self.run_session(topo, "E1-unprivileged", echo(100), transient=True, caps=None, zeek=False)
            evid.append(self.session_evidence(rec))
            snap, summ = rec["snapshot"] or {}, rec["summary"]
            captured = self.capture_echo_packets(rec["capture"])
            unavailable = [o for o in summ["observations"] if o["label"] == "UNAVAILABLE"]
            correlated = [o for o in summ["observations"] if o["label"] == "CORRELATED"]
            ok = rec["collector_exit"] == 2 and snap.get("status") == "failed" and \
                bool((snap.get("attach") or {}).get("error")) and captured == 200 and unavailable and not correlated
            criteria.append(criterion(self.spec("E", "E1"), bool(ok), {
                "collector_exit": rec["collector_exit"], "status": snap.get("status"),
                "error": (snap.get("attach") or {}).get("error"), "capture_echo_packets": captured,
                "unavailable_statements": [o["statement"] for o in unavailable], "correlated": len(correlated)},
                evaluable=rec["capture"] is not None))
        else:
            criteria.append(criterion(self.spec("E", "E1"), None, "systemd is not available", evaluable=False))

        # E2: exactly the three capabilities.
        if self.systemd:
            rec = self.run_session(topo, "E2-minimal-caps", echo(100), transient=True, caps=CAPS, capture=False)
            evid.append(self.session_evidence(rec))
            snap = rec["snapshot"] or {}
            tx = ((snap.get("counters") or {}).get("tx") or {}).get("skbs") or 0
            rx = ((snap.get("counters") or {}).get("rx") or {}).get("skbs") or 0
            mode = (snap.get("attach") or {}).get("mode")
            ok = rec["collector_exit"] == 0 and snap.get("status") == "stopped" and mode in ("tcx", "tc") and \
                tx >= 100 and rx >= 100
            criteria.append(criterion(self.spec("E", "E2"), bool(ok), {
                "collector_exit": rec["collector_exit"], "status": snap.get("status"), "attach": snap.get("attach"),
                "tx_skbs": tx, "rx_skbs": rx, "unit": rec.get("transient_unit")}))
        else:
            criteria.append(criterion(self.spec("E", "E2"), None, "systemd is not available", evaluable=False))

        # E3: no usable BTF.
        rec = self.run_session(topo, "E3-no-btf", echo(50), extra=["--btf", "/nonexistent/vmlinux"], capture=False)
        evid.append(self.session_evidence(rec))
        snap, summ = rec["snapshot"] or {}, rec["summary"]
        tx = ((snap.get("counters") or {}).get("tx") or {}).get("skbs") or 0
        listed = any(u["conclusion"] == "Why packets were dropped on this host" for u in summ["unsupported"])
        ok = rec["collector_exit"] == 0 and snap.get("status") == "stopped" and tx >= 50 and \
            (snap.get("attach") or {}).get("drop_tracepoint") == "unavailable" and listed
        criteria.append(criterion(self.spec("E", "E3"), bool(ok), {
            "collector_exit": rec["collector_exit"], "status": snap.get("status"), "attach": snap.get("attach"),
            "tx_skbs": tx, "unsupported": summ["unsupported"]}))

        # E4: table pressure.
        def pressure(t):
            return {"flows": self.scenario(t, "udpflows", "--count", "200"),
                    "drops": self.scenario(t, "drops", "--count", "50")}
        rec = self.run_session(topo, "E4-pressure", pressure, extra=["--max-flows", "32", "--max-drops", "8"],
                               capture=False)
        evid.append(self.session_evidence(rec))
        snap, summ = rec["snapshot"] or {}, rec["summary"]
        health = snap.get("health") or {}
        dev = rec["dev_delta"]
        c = snap.get("counters") or {}
        diff = max(abs(((c.get("tx") or {}).get("skbs") or 0) - dev["tx"]),
                   abs(((c.get("rx") or {}).get("skbs") or 0) - dev["rx"]))
        reported = any("not attributed" in o["statement"] for o in summ["observations"] if o["category"] == "missing")
        drops_attached = (snap.get("attach") or {}).get("drop_tracepoint") == "attached"
        ok = counter_sum(snap, "flows_not_recorded") > 0 and counter_sum(snap, "drops_not_keyed") > 0 and \
            health.get("flow_entries") == 32 and diff <= 3 and reported
        criteria.append(criterion(self.spec("E", "E4"), bool(ok), {
            "flows_not_recorded": counter_sum(snap, "flows_not_recorded"),
            "drops_not_keyed": counter_sum(snap, "drops_not_keyed"), "flow_entries": health.get("flow_entries"),
            "drop_entries": health.get("drop_entries"), "counter_difference": diff, "summary_reports_loss": reported,
            "drop_tracepoint": (snap.get("attach") or {}).get("drop_tracepoint")}, evaluable=drops_attached))

        # E6: SIGKILL, cleanup and recovery, in tc and default mode.
        e6 = {}
        ok6 = True
        for mode in ("tc", "auto"):
            def killed(t, proc, mode=mode):
                bg = t.popen(t.dev, [PYTHON, TRAFFIC, "scenario", "echo", "--server", netns.SERVER, "--router",
                                     netns.AP, "--count", "100", "--gap", "0.005"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                time.sleep(0.2)
                proc.send_signal(signal.SIGKILL)
                proc.wait()
                bg.wait(120)
                info = {"filters_after_kill": bool(t.tc_filters())}
                if mode == "tc":
                    p = t.exec(t.ap, [os.path.join(self.build, "luca-observatory"), "--iface", "ap0", "--detach-only"],
                               check=False)
                    info["detach_only"] = p.stdout.decode("utf-8", "replace").strip()
                    info["filters_after_detach"] = bool(t.tc_filters())
                return info
            rec = self.run_session(topo, "E6-kill-" + mode, None, attach=mode, during=killed, zeek=False)
            evid.append(self.session_evidence(rec))
            captured = self.capture_echo_packets(rec["capture"])
            again = self.run_session(topo, "E6-recover-" + mode, echo(20), capture=False)
            evid.append(self.session_evidence(again))
            snap2 = again["snapshot"] or {}
            recovered = snap2.get("status") == "stopped" and \
                (((snap2.get("counters") or {}).get("tx") or {}).get("skbs") or 0) >= 20
            during = rec["during"]
            mode_ok = captured == 200 and recovered and (mode != "tc" or (during["filters_after_kill"]
                                                                         and not during["filters_after_detach"]))
            ok6 = ok6 and mode_ok
            e6[mode] = {"capture_echo_packets": captured, "during": during, "recovered": recovered,
                        "recovery_status": snap2.get("status"), "ok": mode_ok}
        criteria.append(criterion(self.spec("E", "E6"), bool(ok6), e6,
                                  evaluable=bool(self.tools["tshark"] or self.tools["tcpdump"])))

        # E7: the service, unprivileged except for three capabilities.
        if self.systemd:
            criteria.append(self.exp_E7(topo, evid))
        else:
            criteria.append(criterion(self.spec("E", "E7"), None, "systemd is not available", evaluable=False))

        # E5 last: it deletes ap0.
        criteria.insert(4, self.exp_E5(topo, evid))
        return {"criteria": criteria, "measurements": meas, "evidence": evid}

    def exp_E5(self, topo, evid):
        d = self.session_dir("E5-interface-loss")
        out, ready = os.path.join(d, "assets", "observatory.json"), os.path.join(d, "ready")
        with open(os.path.join(d, "collector.log"), "wb") as log:
            proc = topo.popen(topo.ap, self.collector_args(self.build, "ap0", out, ready, interval=0.5),
                              stdout=log, stderr=subprocess.STDOUT)
            ready_ok = netns.wait_for(ready, 30, proc)
            traffic = self.scenario(topo, "echo", "--count", "50")
            t0 = time.time()
            topo.ip(topo.ap, "link", "del", "ap0")
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            elapsed = time.time() - t0
        snap = load_json(out) or {}
        tx = ((snap.get("counters") or {}).get("tx") or {}).get("skbs") or 0
        ok = ready_ok and proc.returncode == 4 and elapsed <= 3 and snap.get("status") == "interface_lost" and tx >= 50
        rec = {"name": "E5-interface-loss", "dir": d, "snapshot": snap, "summary": None, "capture": None,
               "collector_exit": proc.returncode, "started_at": t0, "finished_at": time.time()}
        evid.append(self.session_evidence(rec))
        return criterion(self.spec("E", "E5"), bool(ok), {"collector_exit": proc.returncode,
                                                          "exit_after_s": round(elapsed, 3),
                                                          "status": snap.get("status"), "tx_skbs": tx,
                                                          "error": (snap.get("attach") or {}).get("error"),
                                                          "traffic": traffic})

    def exp_E7(self, topo, evid):
        d = self.session_dir("E7-service")
        work = self.scratch("E7-service")
        spool = os.path.join(work, "spool")
        os.makedirs(spool, exist_ok=True)
        os.chmod(spool, 0o777)
        sock = os.path.join(work, "control.sock")
        settings, problems = observatory_config({"observatory": {"enabled": True, "allowed_interfaces": ["ap0"],
                                                                 "sample_interval": 0.5, "flush_interval": 1}})
        settings_path = os.path.join(work, "settings.json")
        write_json(settings_path, {"settings": settings, "problems": problems, "interface": "ap0",
                                   "interface_problem": ""})
        os.chmod(settings_path, 0o644)
        unit = "luca-exp-service-{}".format(os.getpid())
        args = [PYTHON, "-I", os.path.join(self.unpriv_obs, "luca-observatoryd"), "serve", "--settings", settings_path,
                "--collector", os.path.join(self.unpriv_obs, "build", "luca-observatory"),
                "--bpf-dir", os.path.join(self.unpriv_obs, "build"), "--socket", sock, "--spool", spool]
        cmd, props = self.transient(topo, args, unit, CAPS, wait=False)
        detail = {"unit": {"name": unit, "properties": props}}
        t0 = time.time()
        subprocess.run(cmd, check=False, timeout=30)
        detail["socket_ready"] = netns.wait_for(sock, 15)
        section = {"enabled": True}
        token = self.token()
        try:
            status = obs_client.request("status", socket_path=sock)
        except obs_client.Unavailable as e:
            status = {"status": "unavailable", "error": str(e)}
        start = obs_client.start_session(section, token, socket_path=sock)
        traffic = self.scenario(topo, "echo", "--count", "50")
        record = obs_client.stop_session(section, token, os.path.join(d, "assets"), start, socket_path=sock)
        journal = subprocess.run(["journalctl", "-u", unit, "--no-pager", "-o", "cat"], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, timeout=30)
        with open(os.path.join(d, "service.log"), "wb") as f:
            f.write(journal.stdout)
        subprocess.run([self.tools["systemctl"], "stop", unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=30)
        after_assets = os.path.join(d, "after-stop")
        os.makedirs(after_assets, exist_ok=True)
        start2 = obs_client.start_session(section, self.token(), socket_path=sock)
        record2 = obs_client.stop_session(section, token, after_assets, start2, socket_path=sock)
        snap = load_json(os.path.join(d, "assets", "observatory.json")) or {}
        tx = ((snap.get("counters") or {}).get("tx") or {}).get("skbs") or 0
        ok = status.get("status") == "available" and start.get("status") == "running" and \
            record.get("status") == "stopped" and record.get("snapshot_copied") and not record.get("crashed") and \
            snap.get("status") == "stopped" and tx >= 50 and start2.get("status") == "unavailable" and \
            record2.get("status") == "unavailable" and \
            os.path.exists(os.path.join(after_assets, "observatory_session.json"))
        detail.update({"status": {k: status.get(k) for k in ("status", "enabled", "interface", "error")},
                       "start": start.get("status"), "stop": {k: record.get(k) for k in
                                                              ("status", "snapshot_copied", "crashed", "exit_code",
                                                               "error")},
                       "snapshot_status": snap.get("status"), "tx_skbs": tx, "traffic": traffic,
                       "after_service_stop": {"start": start2.get("status"), "stop": record2.get("status")}})
        rec = {"name": "E7-service", "dir": d, "snapshot": snap, "summary": None, "capture": None,
               "collector_exit": record.get("exit_code"), "started_at": t0, "finished_at": time.time()}
        evid.append(self.session_evidence(rec))
        return criterion(self.spec("E", "E7"), bool(ok), detail)

    def exp_B(self):
        reps = 5
        runs = {"baseline": [], "collector": []}
        evid = []
        with netns.Topology() as topo:
            self.start_server(topo)
            try:
                for rep in range(reps):
                    for cond in ("baseline", "collector"):
                        rec = {"rep": rep, "condition": cond}
                        proc = None
                        if cond == "collector":
                            d = self.session_dir("B-rep{}".format(rep))
                            out, ready = os.path.join(d, "assets", "observatory.json"), os.path.join(d, "ready")
                            log = open(os.path.join(d, "collector.log"), "wb")
                            proc = topo.popen(topo.ap, self.collector_args(self.build, "ap0", out, ready, interval=1.0,
                                                                           flush=10.0),
                                              stdout=log, stderr=subprocess.STDOUT)
                            rec["ready"] = netns.wait_for(ready, 30, proc)
                        rec["bulk"] = self.traffic(topo, "bulk", "--server", netns.SERVER, "--seconds", "5")
                        rec["rtt"] = self.traffic(topo, "rtt", "--server", netns.SERVER, "--count", "2000")
                        if proc is not None:
                            rec["collector_exit"] = netns.stop(proc)
                            log.close()
                            snap = load_json(out) or {}
                            h = snap.get("health") or {}
                            dur = ((snap.get("clock") or {}).get("realtime") or 0) - (snap.get("started_at") or 0)
                            rec.update({"status": snap.get("status"), "duration_s": dur,
                                        "cpu_seconds": h.get("collector_cpu_seconds"),
                                        "max_rss_kb": h.get("collector_max_rss_kb"),
                                        "map_memlock_bytes": h.get("map_memlock_bytes"),
                                        "loss": snapmod.loss_report(snap) if snap else None})
                            evid.append({"session": "B-rep{}".format(rep), "dir": os.path.relpath(d, self.results_dir),
                                         "files": {"assets/observatory.json": {"sha256": sha256(out)}}})
                        runs[cond].append(rec)
                # Per-invocation cost, measured separately: statistics add overhead of their own.
                d = self.session_dir("B-prog-stats")
                out, ready = os.path.join(d, "assets", "observatory.json"), os.path.join(d, "ready")
                with open(os.path.join(d, "collector.log"), "wb") as log:
                    proc = topo.popen(topo.ap, self.collector_args(self.build, "ap0", out, ready, interval=1.0,
                                                                   flush=10.0, extra=["--prog-stats"]),
                                      stdout=log, stderr=subprocess.STDOUT)
                    netns.wait_for(ready, 30, proc)
                    self.traffic(topo, "bulk", "--server", netns.SERVER, "--seconds", "5")
                    self.traffic(topo, "rtt", "--server", netns.SERVER, "--count", "2000")
                    netns.stop(proc)
                ps = ((load_json(out) or {}).get("health") or {}).get("prog_stats") or {}
            finally:
                self.stop_server()

        def mbit(r):
            return r["bulk"].get("mbit_per_s")

        def rtt(r):
            return r["rtt"].get("median_us")
        base_t = [mbit(r) for r in runs["baseline"] if mbit(r)]
        coll_t = [mbit(r) for r in runs["collector"] if mbit(r)]
        base_r = [rtt(r) for r in runs["baseline"] if rtt(r)]
        coll_r = [rtt(r) for r in runs["collector"] if rtt(r)]
        complete = len(base_t) == len(coll_t) == len(base_r) == len(coll_r) == reps
        coll = runs["collector"]
        loss = 0
        for r in coll:
            l = r.get("loss") or {}
            loss += (l.get("flows_not_recorded") or 0) + (l.get("drops_not_keyed") or 0) + \
                (l.get("parse_errors") or 0) + (l.get("snapshot_failures") or 0) + (1 if l.get("timeline_truncated") else 0)
            if r.get("status") != "stopped":
                loss += 1
        cpu = [r["cpu_seconds"] / r["duration_s"] for r in coll if r.get("cpu_seconds") is not None and r.get("duration_s")]
        rss = [r["max_rss_kb"] for r in coll if r.get("max_rss_kb") is not None]
        mem = [r["map_memlock_bytes"] for r in coll if r.get("map_memlock_bytes") is not None]
        ratio = statistics.median(coll_t) / statistics.median(base_t) if base_t and coll_t else None
        increase = statistics.median(coll_r) - statistics.median(base_r) if base_r and coll_r else None
        per_prog = [{"name": p["name"], "run_cnt": p["run_cnt"],
                     "ns_per_run": round(p["run_time_ns"] / p["run_cnt"], 1) if p["run_cnt"] else None}
                    for p in ps.get("programs") or []]
        criteria = [
            criterion(self.spec("B", "B1"), ratio, {"baseline_mbit_s": base_t, "collector_mbit_s": coll_t},
                      evaluable=complete),
            criterion(self.spec("B", "B2"), increase, {"baseline_median_us": base_r, "collector_median_us": coll_r},
                      evaluable=complete),
            criterion(self.spec("B", "B3"), loss, [r.get("loss") for r in coll], evaluable=len(coll) == reps),
            criterion(self.spec("B", "B4a"), max(cpu) if cpu else None, cpu, evaluable=len(cpu) == reps),
            criterion(self.spec("B", "B4b"), max(rss) if rss else None, rss, evaluable=len(rss) == reps),
            criterion(self.spec("B", "B4c"), max(mem) if mem else None, mem, evaluable=len(mem) == reps),
        ]
        return {"criteria": criteria,
                "measurements": {"repetitions": reps, "runs": runs, "bpf_prog_stats": {"enabled": ps.get("enabled"),
                                                                                       "note": ps.get("note"),
                                                                                       "programs": per_prog},
                                 "rtt_p99_us": {c: [r["rtt"].get("p99_us") for r in runs[c]] for c in runs}},
                "evidence": evid}

    # ----------------------------------------------------------------- run

    def guard(self, exp, fn, *args):
        try:
            return fn(*args)
        except Exception as e:
            return {"criteria": [{"id": exp, "verdict": "error", "detail": traceback.format_exc()[-4000:]}],
                    "error": repr(e), "evidence": []}

    def run(self, only):
        started = time.time()
        results = {}
        if only & set("ACDE"):
            with netns.Topology() as topo:
                self.start_server(topo)
                try:
                    if only & set("AC"):
                        results["A"] = self.guard("A", self.exp_A, topo)
                    if "C" in only:
                        results["C"] = self.guard("C", self.exp_C, topo)
                    if "D" in only:
                        results["D"] = self.guard("D", self.exp_D, topo)
                    if "E" in only:
                        results["E"] = self.guard("E", self.exp_E, topo)
                finally:
                    self.stop_server()
            if "A" not in only:
                results.pop("A", None)
        if "B" in only:
            results["B"] = self.guard("B", self.exp_B)
        if "C" in only and "C" in results and "error" not in results["C"]:
            try:
                crit, ev = self.exp_C3()
            except Exception:
                crit, ev = {"id": "C3", "verdict": "error", "detail": traceback.format_exc()[-4000:]}, None
            results["C"]["criteria"].insert(2, crit)
            if ev:
                results["C"]["evidence"].append(ev)
        finished = time.time()
        return results, started, finished

    def environment(self):
        cpu_model = None
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.lower().startswith(("model name", "cpu model", "hardware")):
                        cpu_model = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass
        virt = first_line(["systemd-detect-virt"])
        gha = os.environ.get("GITHUB_ACTIONS") == "true"
        desc = "{} ({} {}), Linux {}; veth pairs in network namespaces, not Wi-Fi hardware".format(
            "GitHub Actions runner" if gha else "Linux host", virt or "virtualization unknown", platform.machine(),
            platform.release())
        env = {"description": desc, "kind": "github-actions" if gha else "linux-host",
               "topology": "tests/netns.py: device, access point and network namespaces joined by veth",
               "wifi_hardware": False, "kernel": platform.release(), "machine": platform.machine(),
               "cpus": os.cpu_count(), "cpu_model": cpu_model, "virtualization": virt,
               "python": platform.python_version()}
        if gha:
            env["github"] = {k: os.environ.get(v) for k, v in (("repository", "GITHUB_REPOSITORY"),
                                                                ("run_id", "GITHUB_RUN_ID"), ("sha", "GITHUB_SHA"),
                                                                ("runner_os", "RUNNER_OS"),
                                                                ("runner_arch", "RUNNER_ARCH"),
                                                                ("image", "ImageOS"))}
        return env


def main():
    p = argparse.ArgumentParser(description="Run the preregistered observatory experiments (Linux, root).")
    p.add_argument("--build-dir", default=os.path.join(OBS, "build"))
    p.add_argument("--out", help="results directory (default observatory/experiments/results)")
    p.add_argument("--only", default="ABCDE", help="subset of experiments, e.g. AC")
    args = p.parse_args()
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        print("The experiments need root on Linux.", file=sys.stderr)
        return 2
    if not os.access(os.path.join(args.build_dir, "luca-observatory"), os.X_OK):
        print("No collector in {}; run make -C observatory first.".format(args.build_dir), file=sys.stderr)
        return 2
    prereg_path = os.path.join(HERE, "preregistration.json")
    with open(prereg_path) as f:
        prereg = json.load(f)
    only = set(args.only.upper()) & set("ABCDE")

    r = Runner(args, prereg, prereg_path)
    print("run {}; evidence in {}".format(r.run_id, r.evidence_dir))
    try:
        results, started, finished = r.run(only)
    finally:
        shutil.rmtree(r.scratch_root, ignore_errors=True)

    experiments = {}
    failed = False
    for key in sorted(results):
        res = results[key]
        crits = res["criteria"]
        v = verdict(crits)
        failed = failed or v in ("fail", "error")
        counts = {}
        for c in crits:
            counts[c["verdict"]] = counts.get(c["verdict"], 0) + 1
        experiments[key] = {"title": prereg["experiments"][key]["title"], "verdict": v,
                            "summary": ", ".join("{} {}".format(n, k) for k, n in sorted(counts.items())),
                            "criteria": crits, "measurements": res.get("measurements"),
                            "evidence": res.get("evidence"), "error": res.get("error"),
                            "limitations": prereg["experiments"][key].get("limitations", [])}
    a = r.sessions.get("A-coverage") or next(iter(r.sessions.values()), None)
    manifest = evidence.manifest(snapshot=(a or {}).get("snapshot"), settings={"collector": "run_experiments.py"},
                                 evidence={}, root=ROOT, build_dir=r.build)
    tools = {name: {"path": path, "version": first_line([path, "--version"]) if path and name != "systemctl" else None}
             for name, path in r.tools.items()}
    result = {
        "schema": RESULT_SCHEMA,
        "created_at": finished,
        "run_id": r.run_id,
        "synthetic": False,
        "environment": r.environment(),
        "preregistration": {"path": os.path.relpath(prereg_path, ROOT), "sha256": sha256(prereg_path),
                            "registered_at": prereg.get("registered_at"),
                            "amendments": len(prereg.get("amendments") or [])},
        "luca_observatory_version": VERSION,
        "manifest": manifest,
        "collector_binary": {"path": os.path.relpath(os.path.join(r.build, "luca-observatory"), ROOT),
                             "sha256": sha256(os.path.join(r.build, "luca-observatory"))},
        "tools": tools,
        "timing": {"started_at": started, "finished_at": finished, "duration_s": round(finished - started, 1)},
        "experiments": experiments,
        "evidence_dir": os.path.relpath(r.evidence_dir, r.results_dir),
        "limitations": [prereg["scope"]["does_not_apply_to"],
                        "Throughput and latency are measured with Python generators on veth; they show the "
                        "collector's relative cost on this path, not absolute capacity.",
                        "Criteria marked not_evaluable lacked a prerequisite (tool, systemd or kernel feature) "
                        "and were neither passed nor failed."],
    }
    out = os.path.join(r.results_dir, r.run_id + ".json")
    write_json(out, result)
    for key, e in experiments.items():
        print("{} {:<14} {}  ({})".format(key, e["verdict"], e["title"], e["summary"]))
        for c in e["criteria"]:
            print("   {:<4} {:<14} value={}".format(c["id"], c["verdict"], json.dumps(c.get("value"))[:80]))
    print("results: " + out)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
