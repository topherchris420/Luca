#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    End-to-end check of the INSTALLED luca-observatory systemd service
    (Linux, root), as CI runs it after install-observatory.sh:

      - the service runs as user luca-observatory with exactly CAP_BPF,
        CAP_NET_ADMIN and CAP_PERFMON in its effective set;
      - luca_observatory.client starts and stops a session, as Luca's
        frontend does, and the snapshot is copied next to the capture;
      - the snapshot counts the traffic generated on the interface.

        sudo python3 observatory/tests/service_e2e.py --peer-ns lcdev --target 192.168.200.1
"""

import argparse
import json
import os
import pwd
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from luca_observatory import client

CAP_NET_ADMIN, CAP_PERFMON, CAP_BPF = 12, 38, 39
EXPECTED_CAPS = (1 << CAP_NET_ADMIN) | (1 << CAP_PERFMON) | (1 << CAP_BPF)
FAILURES = []


def check(name, ok, detail=""):
    print("{} {}{}".format("PASS" if ok else "FAIL", name, " - " + str(detail) if detail != "" else ""))
    if not ok:
        FAILURES.append(name)


def proc_status(pid):
    out = {}
    with open("/proc/{}/status".format(pid)) as f:
        for line in f:
            key, _, value = line.partition(":")
            out[key] = value.strip()
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--peer-ns", required=True, help="namespace of the device end of the observed veth")
    p.add_argument("--target", required=True, help="address of the observed interface")
    p.add_argument("--count", type=int, default=20)
    args = p.parse_args()
    if os.geteuid() != 0:
        print("SKIP: needs root")
        return 77

    pid = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", "luca-observatory"],
                         stdout=subprocess.PIPE).stdout.decode().strip()
    check("service running", pid not in ("", "0"), "MainPID " + pid)
    if pid not in ("", "0"):
        st = proc_status(pid)
        uid = int(st["Uid"].split()[0])
        user = pwd.getpwuid(uid).pw_name
        check("service user", user == "luca-observatory", user)
        eff, bnd = int(st["CapEff"], 16), int(st["CapBnd"], 16)
        check("effective capabilities", eff == EXPECTED_CAPS, "CapEff {:#x}, expected {:#x}".format(eff, EXPECTED_CAPS))
        check("bounding set", bnd == EXPECTED_CAPS, "CapBnd {:#x}".format(bnd))
        check("no new privileges", st.get("NoNewPrivs") == "1", st.get("NoNewPrivs"))

    status = client.status({"enabled": True})
    check("status available", status.get("status") == "available", status.get("error", ""))
    print("     interface {}, problem: {}".format(status.get("interface"), status.get("interface_problem")))

    token = "C0FFEE01"
    start = client.start_session({"enabled": True}, token)
    check("session started", start.get("status") in ("running", "starting"), json.dumps(start)[:300])
    ping = subprocess.run(["ip", "netns", "exec", args.peer_ns, "ping", "-c", str(args.count), "-i", "0.05",
                           args.target], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    check("traffic generated", ping.returncode == 0, ping.stdout.decode().strip().splitlines()[-1:])

    assets = tempfile.mkdtemp(prefix="luca-e2e-")
    rec = client.stop_session({"enabled": True}, token, assets, start)
    check("session stopped", rec.get("status") == "stopped", json.dumps(rec)[:500])
    check("not crashed", rec.get("crashed") is False, rec.get("crashed"))
    check("snapshot copied", rec.get("snapshot_copied") is True)
    try:
        with open(os.path.join(assets, "observatory.json")) as f:
            snap = json.load(f)
    except (OSError, ValueError) as e:
        snap = {}
        check("snapshot readable", False, e)
    if snap:
        c = snap["counters"]
        print("     attach {}, drops {}, kernel {}".format(snap["attach"]["mode"], snap["attach"]["drop_tracepoint"],
                                                        snap["host"]["kernel"]))
        check("traffic counted", c["tx"]["skbs"] >= args.count and c["rx"]["skbs"] >= args.count,
              "tx {} rx {}".format(c["tx"]["skbs"], c["rx"]["skbs"]))
        check("snapshot status stopped", snap["status"] == "stopped", snap["status"])
    print("{} check(s) failed".format(len(FAILURES)) if FAILURES else "service end-to-end checks passed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
