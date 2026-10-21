#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Correlation of kernel observations with Luca's existing evidence.

    Sources and their independence:
      kernel.tc         the observatory's TC classifiers on the AP interface;
      kernel.kfree_skb  the kernel's drop events for packets on that interface;
      capture.pcap      TShark's AF_PACKET capture (filter "tcp or udp");
      zeek.conn/dns     derived from capture.pcap;
      suricata.fast     derived from capture.pcap;
      luca.alert        Luca's Zeek/Suricata/IOC alerts, derived from the capture.
    The kernel classifiers and the AF_PACKET capture are independent
    collection paths inside the same host kernel. Zeek, Suricata and the
    alerts are not independent of the capture. "Corroborated" therefore
    always means: the kernel path and a capture-derived path agree.

    Every observation records the evidence it rests on as the original
    record plus a pointer into the file it came from. Nothing is promoted:
    a match that is ambiguous stays "uncertain", a heuristic stays
    "INFERRED", and missing telemetry is reported as UNAVAILABLE.
"""

import ipaddress
import time

from . import (CORRELATED, INFERRED, OBSERVED, UNAVAILABLE, CORROBORATED, SINGLE_SOURCE,
               UNCERTAIN, MISSING, INFERENCE, CATEGORIES, SUMMARY_SCHEMA, VERSION)
from . import heuristics
from .snapshot import Clock, DIRECTIONS, flow_window, loss_report, proto_name, timeline_rows
from .snapshot import TCP_RST

CAPTURE_FILTER = "tcp or udp"
CAPTURE_PROTOS = (6, 17)
ZEEK_PROTOS = {"tcp": 6, "udp": 17, "icmp": 1}
DEFAULT_TOLERANCE = 1.0      # seconds, added to the measured clock uncertainty
PACKET_TOLERANCE = 2
MAX_OBSERVATIONS = 5000
MAX_DROP_OBSERVATIONS = 200
CATEGORY_PRIORITY = {MISSING: 0, INFERENCE: 1, UNCERTAIN: 2, SINGLE_SOURCE: 3, CORROBORATED: 4}

UNSUPPORTED = [
    {"conclusion": "Which application or process produced the device's traffic",
     "reason": "Packets of the inspected device are forwarded by the access point. They are not "
               "associated with any local process, and the observatory does not attribute them."},
    {"conclusion": "What the traffic contained",
     "reason": "The observatory records headers and counters only, never payload."},
    {"conclusion": "Whether TCP segments were retransmitted rather than reordered",
     "reason": "At this vantage point both look alike; retrans_or_reorder counts include both."},
    {"conclusion": "Whether traffic is malicious",
     "reason": "Kernel counters describe traffic, not intent. Alerts remain heuristic ratings or "
               "indicator matches; kernel corroboration confirms that traffic occurred, not what it meant."},
    {"conclusion": "Packets the device sent that never reached the access point",
     "reason": "Radio-level losses happen before the kernel sees a packet and are not observable here."},
]


def _ip(addr):
    try:
        return ipaddress.ip_address(addr)
    except (ValueError, TypeError):
        return None


def _ev(source, file, pointer, record):
    return {"source": source, "file": file, "pointer": pointer, "record": record}


def _flow_label(f):
    name = proto_name(f["proto"])
    if f.get("local_port") or f.get("remote_port"):
        return "{} {}:{} <-> {}:{}".format(name, f["local"], f["local_port"], f["remote"], f["remote_port"])
    return "{} {} <-> {}".format(name, f["local"], f["remote"])


class Correlator(object):

    def __init__(self, snapshot=None, session=None, capture=None, capture_error=None,
                 conns=None, dns=None, alerts=None, suricata=None, device=None,
                 capture_interface=None, files=None, max_observations=MAX_OBSERVATIONS):
        self.snap = snapshot
        self.session = session or {}
        self.capture = capture
        self.capture_error = capture_error
        self.conns = conns
        self.dns = dns
        self.alerts = alerts
        self.suricata = suricata
        self.device = device or {}
        self.capture_interface = capture_interface
        self.files = dict({"snapshot": "assets/observatory.json", "session": "assets/observatory_session.json",
                           "capture": "capture.pcap", "conn": "assets/conn.log", "dns": "assets/dns.log",
                           "alerts": "assets/alerts.json", "suricata": "assets/suricata_events.json"},
                          **(files or {}))
        self.max_observations = max_observations
        self.observations = []
        self.limitations = []
        self.clock = Clock(snapshot) if snapshot else None
        self.tolerance = DEFAULT_TOLERANCE
        if self.clock and self.clock.uncertainty:
            self.tolerance += self.clock.uncertainty
        self.kflows = self.kernel_flows() if snapshot else []
        self.addresses = (snapshot or {}).get("interface", {}).get("addresses") or []
        self.net = heuristics.Network(self.addresses)

    # ------------------------------------------------------------ helpers

    def add(self, label, category, statement, sources, evidence, reasons=None, details=None):
        obs = {"id": "obs-{}".format(len(self.observations) + 1), "label": label, "category": category,
               "statement": statement, "sources": sources, "reasons": reasons or [],
               "details": details or {}, "evidence": evidence}
        self.observations.append(obs)
        return obs

    def kernel_flows(self):
        """
            Kernel flows with times converted to wall-clock seconds.
        """
        out = []
        for i, f in enumerate(self.snap.get("flows") or []):
            first, last = flow_window(f)
            k = {"index": i, "family": f.get("family"), "proto": f.get("proto"), "local": f.get("local"),
                 "local_port": f.get("local_port") or 0, "remote": f.get("remote"),
                 "remote_port": f.get("remote_port") or 0, "tx": f.get("tx") or {}, "rx": f.get("rx") or {},
                 "tcp": f.get("tcp"), "first": self.clock.to_realtime(first),
                 "last": self.clock.to_realtime(last), "raw": f}
            for d in DIRECTIONS:
                k[d].setdefault("packets", 0)
                k[d].setdefault("bytes", 0)
            out.append(k)
        return out

    def kernel_evidence(self, k):
        return _ev("kernel.tc", self.files["snapshot"], "/flows/{}".format(k["index"]), k["raw"])

    def nat_boundary(self):
        iface = (self.snap or {}).get("interface", {}).get("name")
        return bool(self.capture_interface and iface and iface != self.capture_interface)

    def capture_window(self):
        if self.capture is None or self.capture.first is None:
            return None
        return (self.capture.first, self.capture.last)

    def in_capture_window(self, k):
        w = self.capture_window()
        if w is None or k["first"] is None:
            return None
        return k["last"] >= w[0] - self.tolerance and k["first"] <= w[1] + self.tolerance

    # ------------------------------------------------------- collection

    def collection(self):
        snap = self.snap or {}
        attach = snap.get("attach") or {}
        window = None
        if snap.get("started_at") and (snap.get("clock") or {}).get("realtime"):
            window = {"start": snap["started_at"], "end": snap["clock"]["realtime"]}
        return {
            "status": snap.get("status") or self.session.get("status") or "unavailable",
            "session": snap.get("session") or self.session.get("session"),
            "interface": (snap.get("interface") or {}).get("name") or self.session.get("interface"),
            "capture_interface": self.capture_interface,
            "attach_mode": attach.get("mode"),
            "attach_note": attach.get("note"),
            "drop_tracepoint": attach.get("drop_tracepoint"),
            "drop_note": attach.get("drop_note"),
            "error": attach.get("error") or self.session.get("error"),
            "kernel": (snap.get("host") or {}).get("kernel"),
            "machine": (snap.get("host") or {}).get("machine"),
            "btf": (snap.get("host") or {}).get("btf"),
            "generator": snap.get("generator"),
            "window": window,
            "clock": {"offset": self.clock.offset if self.clock else None,
                      "uncertainty_s": self.clock.uncertainty if self.clock else None,
                      "match_tolerance_s": self.tolerance},
            "limits": snap.get("limits"),
            "health": snap.get("health"),
            "loss": loss_report(snap) if snap else None,
            "session_record": {k: self.session.get(k) for k in
                               ("status", "crashed", "exit_code", "requested_at", "started_at",
                                "stopped_at", "notes") if k in self.session},
        }

    def missing_telemetry(self):
        snap, sess = self.snap, self.session
        sfile = self.files["session"]
        if snap is None:
            reason = sess.get("error") or sess.get("reason") or "no collector snapshot was produced"
            self.add(UNAVAILABLE, MISSING, "Kernel telemetry is unavailable for this session: {}.".format(reason),
                     ["observatory.session"], [_ev("observatory.session", sfile, "/", sess)] if sess else [])
            return
        status = snap.get("status")
        sev = [_ev("kernel.tc", self.files["snapshot"], "/status", status)]
        if status == "failed":
            self.add(UNAVAILABLE, MISSING, "The collector failed before observing traffic: {}.".format(
                (snap.get("attach") or {}).get("error") or "unknown error"), ["kernel.tc"],
                [_ev("kernel.tc", self.files["snapshot"], "/attach", snap.get("attach"))])
        elif status == "interface_lost":
            self.add(UNAVAILABLE, MISSING, "The monitored interface disappeared during the session; "
                     "traffic after {} was not observed.".format(_fmt_time((snap.get("clock") or {}).get("realtime"))),
                     ["kernel.tc"], sev)
        elif status != "stopped" or sess.get("crashed"):
            self.add(UNAVAILABLE, MISSING, "The collector did not stop cleanly (status {}); kernel telemetry "
                     "ends at the last snapshot, {}.".format(status, _fmt_time((snap.get("clock") or {}).get("realtime"))),
                     ["kernel.tc", "observatory.session"], sev + ([_ev("observatory.session", sfile, "/", sess)] if sess else []))
        attach = snap.get("attach") or {}
        if attach.get("drop_tracepoint") != "attached":
            self.add(UNAVAILABLE, MISSING, "Kernel drop reasons are {} on this host{}.".format(
                attach.get("drop_tracepoint") or "unavailable",
                ": " + attach["drop_note"] if attach.get("drop_note") else ""),
                ["kernel.kfree_skb"], [_ev("kernel.kfree_skb", self.files["snapshot"], "/attach", attach)])
        loss = loss_report(snap)
        lev = [_ev("kernel.tc", self.files["snapshot"], "/counters", snap.get("counters"))]
        if loss["flows_not_recorded"]:
            self.add(UNAVAILABLE, MISSING, "{} packet(s) were counted but not attributed to a flow because the "
                     "flow table was full ({} entries).".format(loss["flows_not_recorded"], loss["flow_capacity"]),
                     ["kernel.tc"], lev)
        if loss["drops_not_keyed"]:
            self.add(UNAVAILABLE, MISSING, "{} drop event(s) were counted without their reason and endpoint "
                     "because the drop table was full.".format(loss["drops_not_keyed"]), ["kernel.kfree_skb"], lev)
        if loss["parse_errors"]:
            self.add(UNAVAILABLE, MISSING, "{} packet(s) had headers the classifier could not parse; they are "
                     "counted in the totals only.".format(loss["parse_errors"]), ["kernel.tc"], lev)
        if loss["timeline_truncated"]:
            self.add(UNAVAILABLE, MISSING, "The counter timeline reached its sample limit; coverage cannot be "
                     "assessed for the end of the session.", ["kernel.tc"], lev)
        if self.capture is None:
            self.add(UNAVAILABLE, MISSING, "The capture could not be read{}; kernel observations cannot be "
                     "compared with it.".format(": " + self.capture_error if self.capture_error else ""),
                     ["capture.pcap"], [])
        elif self.capture.truncated:
            self.add(UNAVAILABLE, MISSING, "The capture file ends with a truncated record; its last packets "
                     "may be missing.", ["capture.pcap"], [])
        if self.conns is None:
            self.add(UNAVAILABLE, MISSING, "Zeek's conn.log is not available; flows cannot be compared with "
                     "Zeek's connection records.", ["zeek.conn"], [])
        if self.clock and self.clock.uncertainty and self.clock.uncertainty > 1.0:
            self.limitations.append("The wall clock moved by {:.3f} s relative to the monotonic clock during "
                                    "the session; time matching tolerance was widened accordingly."
                                    .format(self.clock.uncertainty))

    # ---------------------------------------------------------- coverage

    def coverage(self):
        """
            Tests the capture against the kernel's counts of packets matching
            the capture filter. Between two kernel samples t_i < t_j inside
            the capture, a lossless capture holds at least as many packets as
            the kernel counted socket buffers and at most as many as it
            counted GSO/GRO segments (a capture tap sees one or the other,
            depending on offloads). Fewer captured packets than that lower
            bound prove loss; more than the upper bound prove that the two
            do not observe the same traffic. Over the whole capture the
            samples enclosing it give an upper bound only.
        """
        result = {"assessment": "unknown", "explanation": "", "directions": {}}
        cap = self.capture
        if self.nat_boundary():
            result["explanation"] = ("the collector observes {} while the capture observes {}; their packet counts "
                                     "are not comparable".format(self.snap["interface"].get("name"),
                                                                 self.capture_interface))
            return result
        rows = timeline_rows(self.snap) if self.snap else []
        if cap is None or cap.first is None or len(rows) < 2:
            result["explanation"] = "needs both a capture with packets and a kernel timeline"
            return result
        if cap.as_dict()["direction_method"] == "none":
            result["explanation"] = "capture packet directions could not be determined"
            return result
        a, b = cap.first, cap.last
        inner = [r for r in rows if a <= r["realtime"] <= b]
        before = [r for r in rows if r["realtime"] <= a]
        after = [r for r in rows if r["realtime"] >= b]
        partial = not before or not after
        assessments = []
        for d in DIRECTIONS:
            skb, seg = "{}_pcap_filter_skbs".format(d), "{}_pcap_filter_segments".format(d)
            entry = {"captured": cap.directions.get(d, 0)}
            state = "partial" if partial else "consistent"
            if len(inner) >= 2:
                ti, tj = inner[0]["realtime"], inner[-1]["realtime"]
                lower = inner[-1][skb] - inner[0][skb]
                upper = inner[-1][seg] - inner[0][seg]
                got = cap.count_between(d, ti, tj)
                unknown = cap.count_between("unknown", ti, tj)
                tol = PACKET_TOLERANCE + int(0.001 * lower)
                entry.update({"interval": [ti, tj], "captured_in_interval": got, "kernel_lower": lower,
                              "kernel_upper": upper, "tolerance": tol,
                              # unknown-direction packets may belong here: never claim them lost
                              "missed_at_least": max(0, lower - (got + unknown) - tol)})
                if entry["missed_at_least"] > 0:
                    state = "incomplete"
                elif got > upper + tol:
                    state = "inconsistent"
            else:
                entry.update({"kernel_lower": None, "kernel_upper": None, "missed_at_least": 0})
            if not partial:
                total_upper = after[0][seg] - before[-1][seg]
                entry["kernel_upper_whole_capture"] = total_upper
                if entry["captured"] > total_upper + PACKET_TOLERANCE + int(0.001 * total_upper):
                    state = "inconsistent" if state != "incomplete" else state
            entry["state"] = state
            assessments.append(state)
            result["directions"][d] = entry
        result["unknown_direction_packets"] = cap.directions.get("unknown", 0)
        result["window"] = {"first": a, "last": b, "kernel_samples": len(rows), "interior_samples": len(inner),
                            "kernel_first_sample": rows[0]["realtime"], "kernel_last_sample": rows[-1]["realtime"]}
        if "incomplete" in assessments:
            result["assessment"] = "incomplete"
            result["explanation"] = ("between kernel samples the capture holds fewer packets than the kernel's "
                                     "lower bound")
        elif "inconsistent" in assessments:
            result["assessment"] = "inconsistent"
            result["explanation"] = ("the capture holds more packets than the kernel saw; the collector may "
                                     "observe a different interface or have missed part of the session")
        elif len(inner) < 2:
            result["assessment"] = "unknown"
            result["explanation"] = "the capture is shorter than two kernel sampling intervals"
        elif "partial" in assessments:
            result["assessment"] = "partial"
            result["explanation"] = "the kernel timeline does not enclose the whole capture"
        else:
            result["assessment"] = "consistent"
            result["explanation"] = ("no capture loss is detectable between kernel samples; loss within the "
                                     "tolerance or outside the sampled interval cannot be excluded")
        isb = cap.interface_stats
        result["capture_reported_drops"] = sum(s.get("ifdrop", 0) for s in isb) if isb else None
        return result

    def coverage_observation(self, cov):
        state = cov["assessment"]
        cap_ev = [_ev("capture.pcap", self.files["capture"], "interface_statistics", self.capture.interface_stats)] \
            if self.capture is not None else []
        kev = [_ev("kernel.tc", self.files["snapshot"], "/timeline", "{} samples".format(
            len((self.snap or {}).get("timeline", {}).get("samples") or [])))]
        if state == "incomplete":
            missed = sum(v["missed_at_least"] for v in cov["directions"].values())
            reported = cov.get("capture_reported_drops")
            if reported:
                self.add(CORRELATED, CORROBORATED, "The capture is incomplete: the kernel counted at least {} more "
                         "packet(s) matching the capture filter than the capture holds, and the capture itself "
                         "reported {} dropped packet(s).".format(missed, reported),
                         ["kernel.tc", "capture.pcap"], kev + cap_ev, details=cov)
            else:
                self.add(OBSERVED, SINGLE_SOURCE, "The capture is incomplete: the kernel counted at least {} more "
                         "packet(s) matching the capture filter than the capture holds; the capture reported no "
                         "drops of its own.".format(missed), ["kernel.tc"], kev + cap_ev, details=cov)
        elif state == "inconsistent":
            self.add(CORRELATED, UNCERTAIN, "Kernel and capture packet counts disagree: the capture holds more "
                     "packets than the kernel counted on {}.".format((self.snap or {}).get("interface", {}).get("name")),
                     ["kernel.tc", "capture.pcap"], kev + cap_ev, reasons=[cov["explanation"]], details=cov)
        elif state == "consistent":
            self.add(CORRELATED, CORROBORATED, "Capture completeness is consistent with the kernel's packet counts "
                     "for the capture window.", ["kernel.tc", "capture.pcap"], kev + cap_ev,
                     reasons=[cov["explanation"]], details=cov)
        elif state == "partial":
            self.add(UNAVAILABLE, MISSING, "Capture completeness can only be bounded from below: the kernel "
                     "timeline does not cover the whole capture.", ["kernel.tc", "capture.pcap"], kev + cap_ev,
                     details=cov)

    # -------------------------------------------------------------- flows

    def zeek_conn(self, line, rec):
        proto = ZEEK_PROTOS.get(str(rec.get("proto")).lower())
        orig, resp = rec.get("id.orig_h"), rec.get("id.resp_h")
        oip, rip = _ip(orig), _ip(resp)
        if proto is None or oip is None or rip is None:
            return None
        family = oip.version
        if proto == 1 and family == 6:
            proto = 58
        oport, rport = rec.get("id.orig_p") or 0, rec.get("id.resp_p") or 0
        if proto in (1, 58):
            oport = rport = 0  # Zeek stores ICMP type/code in the port fields
        dev = _ip(self.device.get("ip_address"))
        orig_local = True
        if dev is not None:
            orig_local = oip == dev or rip != dev
        elif self.net.nets:
            orig_local = self.net.local(oip) or not self.net.local(rip)
        if orig_local:
            local, lport, remote, rport_n, local_dir = orig, oport, resp, rport, "tx"
        else:
            local, lport, remote, rport_n, local_dir = resp, rport, orig, oport, "rx"
        ts = rec.get("ts")
        dur = rec.get("duration") or 0.0
        return {"line": line, "record": rec, "family": family, "proto": proto, "local": local,
                "local_port": lport, "remote": remote, "remote_port": rport_n, "orig_dir": local_dir,
                "start": ts, "end": (ts + dur) if isinstance(ts, (int, float)) else None,
                "orig_pkts": rec.get("orig_pkts") or 0, "resp_pkts": rec.get("resp_pkts") or 0,
                "conn_state": rec.get("conn_state")}

    def match_flows(self):
        key = lambda f: (f["family"], f["proto"], f["local"], f["local_port"], f["remote"], f["remote_port"])
        by_key = {key(k): k for k in self.kflows}
        by_remote, by_local = {}, {}
        for k in self.kflows:
            by_remote.setdefault((k["family"], k["proto"], k["remote"], k["remote_port"]), []).append(k)
            by_local.setdefault((k["family"], k["proto"], k["local"], k["local_port"]), []).append(k)
        nat = self.nat_boundary()
        groups, ambiguous, capture_only = {}, [], []
        conns = [c for c in (self.zeek_conn(l, r) for l, r in (self.conns or [])) if c]
        for c in conns:
            k = by_key.get(key(c))
            if k is None:
                swapped = (c["family"], c["proto"], c["remote"], c["remote_port"], c["local"], c["local_port"])
                k = by_key.get(swapped)
                if k is not None:
                    c["swapped"] = True
            if k is None and nat:
                end = (c["family"], c["proto"], c["remote"], c["remote_port"])
                cands = [x for x in by_remote.get(end, []) if self._overlaps(x, c)]
                # On an interface facing the network, the remote host is the kernel flow's local end.
                reverse = [x for x in by_local.get(end, []) if self._overlaps(x, c)]
                if not cands and reverse:
                    cands = reverse
                    c["reversed"] = True
                if len(cands) == 1:
                    k = cands[0]
                    c["via_nat"] = True
                elif len(cands) > 1:
                    ambiguous.append((c, cands))
                    continue
            if k is None:
                capture_only.append(c)
            else:
                groups.setdefault(k["index"], (k, []))[1].append(c)
        return groups, ambiguous, capture_only

    def _overlaps(self, k, c):
        if k["first"] is None or c["start"] is None:
            return True
        return c["end"] >= k["first"] - self.tolerance and c["start"] <= k["last"] + self.tolerance

    def tcp_facts(self, k):
        t = k.get("tcp") or {}
        facts = {}
        if not t:
            return facts
        if t.get("syn_ns"):
            facts["syn_from"] = t.get("syn_dir")
            facts["syn_count"] = t.get("syn_count")
        if t.get("syn_ns") and t.get("synack_ns"):
            facts["synack_after_ms"] = round((t["synack_ns"] - t["syn_ns"]) / 1e6, 3)
            facts["handshake"] = "completed" if t.get("ack_ns") else "no final ACK"
            if t.get("ack_ns"):
                facts["ack_after_ms"] = round((t["ack_ns"] - t["synack_ns"]) / 1e6, 3)
            if (t.get("syn_count") or 0) > 1:
                facts["rtt_ambiguous"] = "SYN was sent {} times".format(t["syn_count"])
        elif t.get("syn_ns"):
            facts["handshake"] = "SYN without SYN-ACK"
        flags = (k["tx"].get("tcp_flags") or 0) | (k["rx"].get("tcp_flags") or 0)
        if flags & TCP_RST:
            facts["rst_from"] = [d for d in DIRECTIONS if (k[d].get("tcp_flags") or 0) & TCP_RST]
        retrans = {d: k[d].get("retrans_or_reorder") or 0 for d in DIRECTIONS}
        if any(retrans.values()):
            facts["retrans_or_reorder"] = retrans
        return facts

    def flow_observations(self):
        groups, ambiguous, capture_only = self.match_flows()
        nat = self.nat_boundary()
        matched = set(groups)
        for idx, (k, cs) in sorted(groups.items()):
            reasons = []
            ev = [self.kernel_evidence(k)] + [_ev("zeek.conn", self.files["conn"], "line:{}".format(c["line"]),
                                                    c["record"]) for c in cs]
            z = {"tx": 0, "rx": 0}
            for c in cs:
                # Capture directions in the kernel flow's terms.
                d = c["orig_dir"] if not c.get("reversed") else ("rx" if c["orig_dir"] == "tx" else "tx")
                z[d] += c["orig_pkts"]
                z["rx" if d == "tx" else "tx"] += c["resp_pkts"]
                if not self._overlaps(k, c):
                    reasons.append("Zeek connection at {} lies outside the kernel's flow window".format(
                        _fmt_time(c["start"])))
                if c.get("via_nat"):
                    reasons.append("matched across a NAT boundary on the remote endpoint only")
                if c.get("reversed"):
                    reasons.append("the collector's interface faces the network, so its tx/rx and local/remote "
                                   "roles are the reverse of the capture's")
                if c.get("swapped"):
                    reasons.append("local and remote ends were assigned in reverse by the orientation rule")
            for d in DIRECTIONS:
                if z[d] > k[d]["packets"] + PACKET_TOLERANCE:
                    reasons.append("the capture counted {} {} packet(s), the kernel {}".format(
                        z[d], d, k[d]["packets"]))
            facts = self.tcp_facts(k)
            states = sorted({c["conn_state"] for c in cs if c["conn_state"]})
            if facts.get("handshake") == "completed" and states and all(s in ("S0", "OTH") for s in states):
                reasons.append("Zeek saw no reply (conn_state {}) but the kernel saw a completed handshake".format(
                    "/".join(states)))
            details = {"kernel": {d: {"packets": k[d]["packets"], "bytes": k[d]["bytes"]} for d in DIRECTIONS},
                       "capture": {"zeek_connections": len(cs), "packets": z, "conn_states": states},
                       "tcp": facts}
            statement = "{}: recorded by the kernel classifier ({} packets out, {} in) and by the capture " \
                        "({} Zeek connection(s), {} packets).".format(_flow_label(k), k["tx"]["packets"],
                                                                     k["rx"]["packets"], len(cs), z["tx"] + z["rx"])
            if reasons:
                self.add(CORRELATED, UNCERTAIN, statement, ["kernel.tc", "zeek.conn"], ev, reasons, details)
            else:
                self.add(CORRELATED, CORROBORATED, statement, ["kernel.tc", "zeek.conn"], ev, [], details)
            k["matched"] = True

        for c, cands in ambiguous:
            ev = [_ev("zeek.conn", self.files["conn"], "line:{}".format(c["line"]), c["record"])] + \
                 [self.kernel_evidence(k) for k in cands[:10]]
            self.add(CORRELATED, UNCERTAIN, "{}: one Zeek connection matches {} kernel flows on its remote "
                     "endpoint; the match is ambiguous.".format(_flow_label(c), len(cands)),
                     ["kernel.tc", "zeek.conn"], ev, ["several kernel flows share the remote endpoint across NAT"])

        for k in self.kflows:
            if k["index"] in matched:
                continue
            ev = [self.kernel_evidence(k)]
            details = {"kernel": {d: {"packets": k[d]["packets"], "bytes": k[d]["bytes"]} for d in DIRECTIONS},
                       "tcp": self.tcp_facts(k)}
            label = _flow_label(k)
            fragments = k["tx"].get("fragments") or k["rx"].get("fragments")
            inside = self.in_capture_window(k)
            if k["proto"] not in CAPTURE_PROTOS:
                why = "the capture filter (\"{}\") excludes {}".format(CAPTURE_FILTER, proto_name(k["proto"]))
            elif fragments and not k["local_port"] and not k["remote_port"]:
                why = ("non-first IP fragments carry no ports, so the kernel keys them separately; the capture "
                       "reassembles them into their connection")
            elif inside is False:
                why = "the flow lies outside the capture's time window"
            elif self.conns is None:
                why = "Zeek records are not available for comparison"
            elif nat:
                why = ("no Zeek connection matches; the collector observes {} while the capture observes {}, where "
                       "traffic of the access point itself or of other devices does not appear".format(
                           self.snap["interface"].get("name"), self.capture_interface))
            else:
                why = "no Zeek connection matches; the capture may have missed it or Zeek did not log it"
            self.add(OBSERVED, SINGLE_SOURCE, "{}: recorded by the kernel only; {}.".format(label, why),
                     ["kernel.tc"], ev, [why], details)

        kernel_ok = self.snap is not None and (self.snap.get("status") in ("stopped", "running", "interface_lost"))
        loss = loss_report(self.snap) if self.snap else {}
        for c in capture_only:
            ev = [_ev("zeek.conn", self.files["conn"], "line:{}".format(c["line"]), c["record"])]
            if not kernel_ok:
                why = "kernel telemetry is unavailable"
            elif loss.get("flows_not_recorded"):
                why = "the kernel flow table was full, so the flow may be among the unattributed packets"
            elif nat:
                why = "the collector observes {} while the capture observes {}".format(
                    self.snap["interface"].get("name"), self.capture_interface)
            else:
                why = "the kernel has no matching flow, which is unexpected on the same interface"
            category = SINGLE_SOURCE if kernel_ok else MISSING
            self.add(OBSERVED, category, "{}: recorded by the capture only; {}.".format(_flow_label(c), why),
                     ["zeek.conn"], ev, [why], {"capture": {"packets": c["orig_pkts"] + c["resp_pkts"],
                                                            "conn_state": c["conn_state"]}})

    # -------------------------------------------------------------- drops

    def drop_observations(self):
        drops = sorted(enumerate((self.snap or {}).get("drops") or []), key=lambda x: -(x[1].get("count") or 0))
        conns = [c for c in (self.zeek_conn(l, r) for l, r in (self.conns or [])) if c]
        for i, d in drops[:MAX_DROP_OBSERVATIONS]:
            reason = d.get("reason_name") or ("reason {}".format(d["reason"]) if d.get("reason") else "no reason code")
            where = "arriving from the device" if d.get("direction") == "tx" else "leaving towards the device"
            target = "{} {}:{}".format(proto_name(d.get("proto") or 0), d.get("remote"), d.get("remote_port")) \
                if d.get("family") else "non-IP or unparsed packets"
            statement = "The kernel dropped {} packet(s) {} ({}), reason {}.".format(d.get("count"), where, target, reason)
            ev = [_ev("kernel.kfree_skb", self.files["snapshot"], "/drops/{}".format(i), d)]
            related = [c for c in conns if d.get("family") and c["remote"] == d.get("remote") and
                       c["proto"] == d.get("proto") and c["remote_port"] == d.get("remote_port")]
            if related:
                ev += [_ev("zeek.conn", self.files["conn"], "line:{}".format(c["line"]), c["record"]) for c in related[:10]]
                states = sorted({c["conn_state"] for c in related if c["conn_state"]})
                self.add(CORRELATED, CORROBORATED, statement + " The capture records the same exchange "
                         "(conn_state {}).".format("/".join(states) or "unknown"),
                         ["kernel.kfree_skb", "zeek.conn"], ev, details={"drop": d, "conn_states": states})
            else:
                self.add(OBSERVED, SINGLE_SOURCE, statement, ["kernel.kfree_skb"], ev, details={"drop": d})

    # ------------------------------------------------------------- alerts

    def alert_observations(self):
        dns_map = {}
        for line, rec in self.dns or []:
            answers = rec.get("answers")
            if isinstance(answers, str):
                answers = answers.split(",")
            for a in answers or []:
                if _ip(a) is not None and rec.get("query"):
                    dns_map.setdefault(str(rec["query"]).lower(), []).append((a, line, rec))
        by_remote = {}
        for k in self.kflows:
            by_remote.setdefault(k["remote"], []).append(k)
        kernel_ok = self.snap is not None and self.snap.get("status") != "failed"
        for level in ("high", "moderate", "low"):
            for i, alert in enumerate((self.alerts or {}).get(level) or []):
                if str(alert.get("id", "")).startswith("KNO-"):
                    continue
                host = alert.get("host")
                aev = _ev("luca.alert", self.files["alerts"], "/{}/{}".format(level, i), alert)
                if not host:
                    continue
                if not kernel_ok:
                    self.add(UNAVAILABLE, MISSING, "Alert {} ({}) cannot be checked against kernel telemetry, "
                             "which is unavailable.".format(alert.get("id"), host), ["luca.alert"], [aev])
                    continue
                via_dns = []
                if _ip(host) is not None:
                    flows = by_remote.get(str(_ip(host)), [])
                else:
                    flows = []
                    for addr, line, rec in dns_map.get(str(host).lower(), []):
                        f = by_remote.get(addr, [])
                        if f:
                            flows += f
                            via_dns.append(_ev("zeek.dns", self.files["dns"], "line:{}".format(line), rec))
                if flows:
                    packets = sum(f["tx"]["packets"] + f["rx"]["packets"] for f in flows)
                    completed = sum(1 for f in flows if self.tcp_facts(f).get("handshake") == "completed")
                    statement = "Alert {} ({}): the kernel independently recorded {} flow(s), {} packet(s), with " \
                                "this host{}. This corroborates that the traffic occurred, not the alert's " \
                                "interpretation.".format(alert.get("id"), host, len(flows), packets,
                                                         ", {} completed TCP handshake(s)".format(completed) if completed else "")
                    ev = [aev] + via_dns[:10] + [self.kernel_evidence(f) for f in flows[:10]]
                    if via_dns:
                        self.add(CORRELATED, UNCERTAIN, statement, ["luca.alert", "zeek.dns", "kernel.tc"], ev,
                                 ["the host name was linked to addresses through DNS answers, which other "
                                  "names may share"], {"flows": len(flows), "packets": packets})
                    else:
                        self.add(CORRELATED, CORROBORATED, statement, ["luca.alert", "kernel.tc"], ev, [],
                                 {"flows": len(flows), "packets": packets})
                else:
                    why = "no address for the host name was found in dns.log" if _ip(host) is None and not \
                        dns_map.get(str(host).lower()) else "the kernel recorded no flow with this host"
                    self.add(OBSERVED, SINGLE_SOURCE, "Alert {} ({}): not corroborated by the kernel; {}.".format(
                        alert.get("id"), host, why), ["luca.alert"], [aev], [why])

        key = lambda f: (f["proto"], f["local"], f["local_port"], f["remote"], f["remote_port"])
        by_key = {key(k): k for k in self.kflows}
        for i, e in enumerate(self.suricata or []):
            proto = {"TCP": 6, "UDP": 17, "ICMP": 1}.get(str(e.get("proto")).upper())
            if proto is None:
                continue
            fwd = (proto, e.get("src"), e.get("sport") or 0, e.get("dst"), e.get("dport") or 0)
            rev = (proto, e.get("dst"), e.get("dport") or 0, e.get("src"), e.get("sport") or 0)
            k = by_key.get(fwd) or by_key.get(rev)
            sev = _ev("suricata.fast", self.files["suricata"], "/{}".format(i), e)
            if k is not None:
                self.add(CORRELATED, CORROBORATED, "Suricata signature \"{}\": the kernel recorded the same flow ({})."
                         .format(e.get("msg"), _flow_label(k)), ["suricata.fast", "kernel.tc"],
                         [sev, self.kernel_evidence(k)])
            elif kernel_ok:
                self.add(OBSERVED, SINGLE_SOURCE, "Suricata signature \"{}\" on {}:{} -> {}:{}: the kernel has no "
                         "matching flow.".format(e.get("msg"), e.get("src"), e.get("sport"), e.get("dst"),
                                                e.get("dport")), ["suricata.fast"], [sev],
                         ["no kernel flow with this tuple"])

    # ---------------------------------------------------------- heuristics

    def findings(self):
        obs_for = {}
        for o in self.observations:
            for e in o["evidence"]:
                if e["source"] == "kernel.tc" and str(e["pointer"]).startswith("/flows/"):
                    obs_for.setdefault(int(e["pointer"].split("/")[2]), o["id"])
        for k in self.kflows:
            k["obs_id"] = obs_for.get(k["index"])
        if self.nat_boundary():
            # The KNO-xx rules assume the collector faces the inspected device.
            self.limitations.append("Device heuristics (KNO-xx) were not evaluated: the collector observes {}, not "
                                    "the capture interface {}.".format(self.snap["interface"].get("name"),
                                                                       self.capture_interface))
            return []
        found = heuristics.run(self.kflows, self.addresses)
        for f in found:
            if f["provenance"] == INFERRED:
                tpl = heuristics.TEMPLATES[f["id"]]
                obs = self.add(INFERRED, INFERENCE, tpl["description"].format(*f["description_args"]),
                               ["observatory.heuristic"],
                               [_ev("observation", "observatory_summary.json", "#" + oid, None) for oid in f["basis"]],
                               ["heuristic {}: {}".format(f["id"], f["inference"])], f["facts"])
                f["observation"] = obs["id"]
        return found

    def statistics(self):
        snap = self.snap or {}
        c = snap.get("counters") or {}
        protos = {}
        for p in snap.get("protocols") or []:
            e = protos.setdefault(p["proto"], {"proto": p["proto"], "name": proto_name(p["proto"]),
                                               "tx_packets": 0, "rx_packets": 0, "bytes": 0})
            e["{}_packets".format(p["direction"])] += p.get("packets") or 0
            e["bytes"] += p.get("bytes") or 0
        remotes = {}
        tcp = {"flows": 0, "handshakes_completed": 0, "syn_without_synack": 0, "rst_seen": 0,
               "retrans_or_reorder": 0, "synack_after_ms": []}
        for k in self.kflows:
            r = remotes.setdefault(k["remote"], {"remote": k["remote"], "flows": 0, "packets": 0, "bytes": 0})
            r["flows"] += 1
            r["packets"] += k["tx"]["packets"] + k["rx"]["packets"]
            r["bytes"] += k["tx"]["bytes"] + k["rx"]["bytes"]
            if k["proto"] == 6:
                facts = self.tcp_facts(k)
                tcp["flows"] += 1
                tcp["handshakes_completed"] += facts.get("handshake") == "completed"
                tcp["syn_without_synack"] += facts.get("handshake") == "SYN without SYN-ACK"
                tcp["rst_seen"] += bool(facts.get("rst_from"))
                tcp["retrans_or_reorder"] += sum((facts.get("retrans_or_reorder") or {}).values())
                if "synack_after_ms" in facts and "rtt_ambiguous" not in facts:
                    tcp["synack_after_ms"].append(facts["synack_after_ms"])
        rtts = sorted(tcp.pop("synack_after_ms"))
        tcp["synack_after_ms_median"] = rtts[len(rtts) // 2] if rtts else None
        tcp["synack_samples"] = len(rtts)
        return {"totals": {d: {k: (c.get(d) or {}).get(k) for k in ("skbs", "segments", "bytes", "ipv4", "ipv6",
                                                                    "arp", "eapol", "other_l2", "pcap_filter_skbs")}
                           for d in DIRECTIONS},
                "flows": len(self.kflows),
                "protocols": sorted(protos.values(), key=lambda p: -(p["tx_packets"] + p["rx_packets"])),
                "top_remotes": sorted(remotes.values(), key=lambda r: -r["bytes"])[:20],
                "tcp": tcp,
                "drops": sum(d.get("count") or 0 for d in snap.get("drops") or [])}

    # ---------------------------------------------------------------- run

    def run(self):
        self.missing_telemetry()
        cov = None
        if self.snap is not None and self.snap.get("status") != "failed":
            cov = self.coverage()
            self.coverage_observation(cov)
            self.flow_observations()
            self.drop_observations()
        self.alert_observations()
        found = self.findings() if self.snap is not None else []

        counts = {c: 0 for c in CATEGORIES}
        labels = {}
        for o in self.observations:
            counts[o["category"]] += 1
            labels[o["label"]] = labels.get(o["label"], 0) + 1
        ordered = sorted(self.observations, key=lambda o: CATEGORY_PRIORITY.get(o["category"], 9))
        truncated = len(ordered) > self.max_observations
        unsupported = list(UNSUPPORTED)
        attach = (self.snap or {}).get("attach") or {}
        if attach.get("drop_tracepoint") not in (None, "attached"):
            unsupported.append({"conclusion": "Why packets were dropped on this host",
                                "reason": "kernel drop events are {}".format(attach.get("drop_tracepoint"))})
        limitations = list(self.limitations) + [
            "Corroboration means two collection paths inside the same host kernel agree: the TC classifier "
            "and the AF_PACKET capture. Both depend on the configured interface being the access point.",
            "Kernel flows aggregate every packet of a 5-tuple over the collector's lifetime, which starts "
            "before and ends after the capture; per-flow counts can exceed the capture's.",
            "Retransmission counts are passive estimates (data below the highest sequence already seen).",
        ]
        if self.nat_boundary():
            limitations.append("The collector and the capture observe different interfaces; flows were matched on "
                               "the remote endpoint only because NAT may rewrite the local one.")
        return {
            "schema": SUMMARY_SCHEMA,
            "generator": {"name": "luca_observatory.correlate", "version": VERSION},
            "generated_at": time.time(),
            "synthetic": bool((self.snap or {}).get("synthetic")),
            "collection": self.collection(),
            "capture": self.capture.as_dict() if self.capture is not None else
            {"error": self.capture_error or "not provided"},
            "coverage": cov,
            "statistics": self.statistics() if self.snap is not None else None,
            "counts": counts,
            "labels": labels,
            "observations": ordered[:self.max_observations],
            "observations_truncated": truncated,
            "findings": found,
            "unsupported": unsupported,
            "limitations": limitations,
            "evidence_files": self.files,
        }


def _fmt_time(ts):
    if not isinstance(ts, (int, float)):
        return "an unknown time"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)) + " UTC"


def correlate(**kwargs):
    """
        :return: dict summary (schema luca.observatory.summary/1)
    """
    return Correlator(**kwargs).run()
