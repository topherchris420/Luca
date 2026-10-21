#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Kernel smoke test of the collector (Linux, root): builds the namespace
    topology of tests/netns.py, runs the collector on the access point's
    ap0, generates known traffic from the device and checks the snapshot
    against that traffic and against the veth's own packet counters.

        sudo python3 tests/netns_smoke.py --build-dir build [--attach tc|tcx]

    Skips (exit 77) when not root or not on Linux, so it never reports a
    pass it did not run. Exit 0 means every check passed on this kernel.
"""

import argparse
import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import netns

SKIP = 77


def collector_cmd(build, out, ready, attach, extra=()):
    return [os.path.join(build, "luca-observatory"), "--iface", "ap0", "--output", out, "--session", "5A0E7E57",
            "--bpf-dir", build, "--ready-file", ready, "--attach", attach, "--interval", "0.5", "--flush", "1",
            "--prog-stats", "-v"] + list(extra)


def start_collector(topo, cmd, ready, log):
    proc = topo.popen(topo.ap, cmd, stdout=log, stderr=subprocess.STDOUT)
    if not netns.wait_for(ready, 30, proc):
        netns.stop(proc)
        return proc, False
    return proc, True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--build-dir", default=os.path.join(os.path.dirname(HERE), "build"))
    p.add_argument("--attach", default="auto", choices=("auto", "tcx", "tc"))
    p.add_argument("--expect-drops", default="any", help="attached|unavailable|disabled|failed|any")
    p.add_argument("--out", help="keep the snapshot and logs here")
    args = p.parse_args()

    if not sys.platform.startswith("linux"):
        print("SKIP: the kernel smoke test needs Linux")
        return SKIP
    if os.geteuid() != 0:
        print("SKIP: the kernel smoke test needs root (network namespaces, BPF)")
        return SKIP
    build = os.path.abspath(args.build_dir)
    if not os.access(os.path.join(build, "luca-observatory"), os.X_OK):
        print("FAIL: {} has no luca-observatory binary; run make first".format(build))
        return 1

    out_dir = args.out or tempfile.mkdtemp(prefix="luca-smoke-")
    os.makedirs(out_dir, exist_ok=True)
    snap_path = os.path.join(out_dir, "snapshot-{}.json".format(args.attach))
    ready = os.path.join(out_dir, "ready-{}".format(args.attach))
    for f in (snap_path, ready):
        if os.path.exists(f):
            os.unlink(f)
    print("kernel {} {}; output in {}".format(platform.release(), platform.machine(), out_dir))

    failures = []
    with netns.Topology() as topo:
        server_ready = os.path.join(out_dir, "server-ready")
        if os.path.exists(server_ready):
            os.unlink(server_ready)
        server = topo.popen(topo.net, [sys.executable, os.path.join(HERE, "traffic.py"), "serve", "--bind",
                                       netns.SERVER, "--ready", server_ready],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not netns.wait_for(server_ready, 10, server):
                print("FAIL: traffic server did not start")
                return 1
            with open(os.path.join(out_dir, "collector-{}.log".format(args.attach)), "wb") as log:
                proc, ok = start_collector(topo, collector_cmd(build, snap_path, ready, args.attach), ready, log)
            if not ok:
                print("FAIL: collector did not become ready (exit {})".format(proc.returncode))
                print(open(os.path.join(out_dir, "collector-{}.log".format(args.attach))).read())
                if os.path.exists(snap_path):
                    print(json.dumps(json.load(open(snap_path)).get("attach"), indent=2))
                return 1
            before = topo.link_stats(topo.dev, "dev0")
            client = topo.exec(topo.dev, [sys.executable, os.path.join(HERE, "traffic.py"), "client",
                                          "--server", netns.SERVER, "--router", netns.AP, "--router6", netns.AP6,
                                          "--foreign-source", netns.FOREIGN], check=False)
            print("client: " + client.stdout.decode("utf-8", "replace").strip())
            time.sleep(0.5)
            after = topo.link_stats(topo.dev, "dev0")
            code = netns.stop(proc)
            if code != 0:
                failures.append("collector exit code {}".format(code))
            if client.returncode != 0:
                failures.append("traffic client failed")
            if topo.tc_filters():
                failures.append("tc filters left after a clean stop: " + topo.tc_filters())
            if args.attach == "tc" and topo.has_clsact():
                failures.append("clsact qdisc created by the collector was not removed")

            print("collector exit {}; checking {}".format(code, snap_path))
            check = subprocess.run([sys.executable, os.path.join(HERE, "check_snapshot.py"), snap_path,
                                    "--device", netns.DEVICE, "--device6", netns.DEVICE6,
                                    "--server", netns.SERVER, "--router", netns.AP,
                                    "--router6", netns.AP6, "--foreign", netns.FOREIGN,
                                    "--dev-tx", str(after["tx_packets"] - before["tx_packets"]),
                                    "--dev-rx", str(after["rx_packets"] - before["rx_packets"]),
                                    "--expect-mode", args.attach,
                                    "--expect-drops", args.expect_drops])
            if check.returncode != 0:
                failures.append("snapshot checks")

            if args.attach == "tc":
                # A killed collector cannot detach classic tc filters; --detach-only must.
                kill_snap = os.path.join(out_dir, "snapshot-killed.json")
                kill_ready = os.path.join(out_dir, "ready-killed")
                with open(os.path.join(out_dir, "collector-killed.log"), "wb") as log:
                    proc, ok = start_collector(topo, collector_cmd(build, kill_snap, kill_ready, "tc"),
                                               kill_ready, log)
                if ok:
                    proc.send_signal(signal.SIGKILL)
                    proc.wait()
                    left = topo.tc_filters()
                    cleanup = topo.exec(topo.ap, [os.path.join(build, "luca-observatory"), "--iface", "ap0",
                                                  "--detach-only"], check=False)
                    print("after SIGKILL: filters {}; --detach-only: {}".format(
                        "present" if left else "absent", cleanup.stdout.decode().strip()))
                    if not left:
                        failures.append("expected filters to survive SIGKILL in tc mode")
                    if topo.tc_filters():
                        failures.append("--detach-only left filters: " + topo.tc_filters())
                else:
                    failures.append("second tc-mode collector did not start")
        finally:
            netns.stop(server, 5)

    for f in failures:
        print("FAIL " + f)
    print("smoke test {}".format("FAILED" if failures else "passed"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
