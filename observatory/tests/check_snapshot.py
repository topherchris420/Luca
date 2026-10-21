#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Checks a luca-observatory snapshot produced by tests/netns_smoke.py
    against the traffic that tests/traffic.py generated and against the
    device veth's own counters. Prints one PASS/FAIL line per check and
    exits non-zero when any check fails.
"""

import argparse
import json
import platform
import sys

FAILURES = []


def check(name, ok, detail=""):
    print("{} {}{}".format("PASS" if ok else "FAIL", name,
                           " - " + detail if detail else ""))
    if not ok:
        FAILURES.append(name)


def kernel_at_least(major, minor):
    try:
        parts = platform.release().split(".")
        return (int(parts[0]), int(parts[1].split("-")[0])) >= (major, minor)
    except (IndexError, ValueError):
        return False


def find_flows(snapshot, **match):
    return [f for f in snapshot["flows"]
            if all(f.get(k) == v for k, v in match.items())]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("snapshot")
    p.add_argument("--device", required=True)
    p.add_argument("--device6")
    p.add_argument("--server", required=True)
    p.add_argument("--router", required=True)
    p.add_argument("--router6")
    p.add_argument("--foreign", required=True)
    p.add_argument("--tcp-port", type=int, default=8080)
    p.add_argument("--udp-port", type=int, default=5353)
    p.add_argument("--udp-count", type=int, default=20)
    p.add_argument("--tcp-conns", type=int, default=3)
    p.add_argument("--closed-port", type=int, default=9)
    p.add_argument("--dev-tx", type=int, required=True,
                   help="dev0 tx_packets delta over the observation")
    p.add_argument("--dev-rx", type=int, required=True,
                   help="dev0 rx_packets delta over the observation")
    p.add_argument("--tolerance", type=int, default=3)
    p.add_argument("--expect-mode", default="any")
    p.add_argument("--expect-drops", default="any")
    args = p.parse_args()

    with open(args.snapshot) as f:
        snap = json.load(f)

    print("kernel {} ({}), libbpf {}, attach={}, drops={}".format(
        snap["host"]["kernel"], snap["host"]["machine"], snap["generator"]["libbpf"],
        snap["attach"]["mode"], snap["attach"]["drop_tracepoint"]))
    if snap["attach"].get("note"):
        print("attach note: " + snap["attach"]["note"])
    if snap["attach"].get("drop_note"):
        print("drop note: " + snap["attach"]["drop_note"])

    check("schema", snap.get("schema") == "luca.observatory/1", snap.get("schema"))
    check("status stopped", snap["status"] == "stopped",
          "{} {}".format(snap["status"], snap["attach"].get("error") or ""))
    check("attach mode", args.expect_mode == "any" and snap["attach"]["mode"] in ("tcx", "tc")
          or snap["attach"]["mode"] == args.expect_mode, snap["attach"]["mode"])
    check("drop tracepoint", args.expect_drops == "any"
          or snap["attach"]["drop_tracepoint"] == args.expect_drops,
          snap["attach"]["drop_tracepoint"])

    tx, rx = snap["counters"]["tx"], snap["counters"]["rx"]
    check("tx skbs match device tx_packets",
          abs(tx["skbs"] - args.dev_tx) <= args.tolerance,
          "kernel {} vs veth {}".format(tx["skbs"], args.dev_tx))
    check("rx skbs match device rx_packets",
          abs(rx["skbs"] - args.dev_rx) <= args.tolerance,
          "kernel {} vs veth {}".format(rx["skbs"], args.dev_rx))
    check("segments >= skbs", tx["segments"] >= tx["skbs"] and rx["segments"] >= rx["skbs"])
    check("no parse errors", tx["parse_errors"] == 0 and rx["parse_errors"] == 0)
    check("flow table not full", tx["flows_not_recorded"] == 0 and rx["flows_not_recorded"] == 0)
    check("timeline sampled", len(snap["timeline"]["samples"]) >= 2,
          "{} samples".format(len(snap["timeline"]["samples"])))
    fields = snap["timeline"]["fields"]
    last = dict(zip(fields, snap["timeline"]["samples"][-1]))
    check("final sample equals counters", last["tx_skbs"] == tx["skbs"] and last["rx_skbs"] == rx["skbs"],
          "{} {} vs {} {}".format(last["tx_skbs"], last["rx_skbs"], tx["skbs"], rx["skbs"]))
    lo, hi = snap["started_monotonic_ns"], snap["clock"]["monotonic_ns"]
    times = [(f[d]["first_ns"], f[d]["last_ns"]) for f in snap["flows"] for d in ("tx", "rx") if f[d]["packets"]]
    check("flow times within the session", all(lo <= a <= b <= hi for a, b in times),
          "{} directions".format(len(times)))
    check("collector health reported", snap["health"]["collector_max_rss_kb"] > 0
          and snap["health"]["map_memlock_bytes"] > 0,
          "rss {} kB, maps {} B".format(snap["health"]["collector_max_rss_kb"], snap["health"]["map_memlock_bytes"]))
    ps = snap["health"]["prog_stats"]
    if ps["enabled"]:
        runs = {p["name"]: p for p in ps["programs"]}
        check("classifier run counts", sum(p["run_cnt"] for n, p in runs.items() if "drop" not in n
                                           and "kfree" not in n) >= tx["skbs"] + rx["skbs"],
              json.dumps(ps["programs"]))

    tcp = find_flows(snap, proto=6, local=args.device, remote=args.server,
                     remote_port=args.tcp_port)
    check("tcp flows recorded", len(tcp) == args.tcp_conns, "{} flows".format(len(tcp)))
    handshakes = [f for f in tcp if f["tcp"]["syn_ns"] and f["tcp"]["synack_ns"] and f["tcp"]["ack_ns"]]
    check("tcp handshakes timed", len(handshakes) == len(tcp) and len(tcp) > 0)
    check("handshake order", all(f["tcp"]["syn_ns"] <= f["tcp"]["synack_ns"] <= f["tcp"]["ack_ns"]
                                 for f in handshakes))
    check("one SYN per connection", all(f["tcp"]["syn_count"] == 1 for f in handshakes))
    check("tcp initiated by device", all(f["tcp"]["syn_dir"] == "tx" for f in handshakes))
    check("tcp payload received", all(f["rx"]["bytes"] > 200000 for f in tcp),
          ", ".join(str(f["rx"]["bytes"]) for f in tcp))
    check("device ttl 64", all(f["tx"]["ttl_min"] == 64 and f["tx"]["ttl_max"] == 64 for f in tcp))
    check("no retransmission estimated on a clean link",
          all(f["tx"]["retrans_or_reorder"] == 0 and f["rx"]["retrans_or_reorder"] == 0 for f in tcp),
          ", ".join("{}/{}".format(f["tx"]["retrans_or_reorder"], f["rx"]["retrans_or_reorder"]) for f in tcp))
    for f in handshakes:
        print("     rtt upstream {:.3f} ms, device {:.3f} ms".format(
            (f["tcp"]["synack_ns"] - f["tcp"]["syn_ns"]) / 1e6,
            (f["tcp"]["ack_ns"] - f["tcp"]["synack_ns"]) / 1e6))

    udp = find_flows(snap, proto=17, local=args.device, remote=args.server,
                     remote_port=args.udp_port)
    check("udp flow counted", len(udp) == 1 and udp[0]["tx"]["packets"] == args.udp_count
          and udp[0]["rx"]["packets"] == args.udp_count,
          json.dumps([(f["tx"]["packets"], f["rx"]["packets"]) for f in udp]))

    ttl63 = find_flows(snap, proto=17, local=args.device, remote=args.server,
                       remote_port=args.udp_port + 1)
    check("ttl 63 observed", len(ttl63) == 1 and ttl63[0]["tx"]["ttl_min"] == 63)

    foreign = find_flows(snap, local=args.foreign, remote=args.server)
    check("foreign source observed", len(foreign) == 1)

    esp = find_flows(snap, proto=50, local=args.device, remote=args.server)
    check("esp observed", len(esp) == 1 and esp[0]["tx"]["packets"] == 3)
    icmp = find_flows(snap, proto=1, local=args.device, remote=args.server)
    check("icmp echo observed", len(icmp) == 1 and icmp[0]["tx"]["packets"] == 3
          and icmp[0]["rx"]["packets"] == 3)

    protos = {(p["direction"], p["proto"]): p["packets"] for p in snap["protocols"]}
    check("protocol table has esp", protos.get(("tx", 50)) == 3)
    pcap_tx = tx["pcap_filter_skbs"]
    check("pcap filter excludes esp/icmp", pcap_tx < tx["ipv4"] + tx["ipv6"])

    if args.router6:
        v6 = find_flows(snap, family=6, proto=17, remote=args.router6,
                        remote_port=args.closed_port)
        check("ipv6 flow observed", len(v6) == 1 and v6[0]["tx"]["packets"] >= 3)

    if snap["attach"]["drop_tracepoint"] == "attached":
        drops = snap["drops"]
        closed = [d for d in drops if d["direction"] == "tx" and d["remote"] == args.router
                  and d["remote_port"] == args.closed_port and d["proto"] == 17]
        check("udp drop to closed port keyed", sum(d["count"] for d in closed) >= 3,
              json.dumps(closed))
        rpf = [d for d in drops if d["direction"] == "tx" and d["remote"] == args.server
               and d["remote_port"] == args.udp_port + 2]
        check("rp_filter drop of foreign source keyed", sum(d["count"] for d in rpf) >= 1,
              json.dumps(rpf))
        if kernel_at_least(5, 17):
            check("drop reason NO_SOCKET named",
                  any(d["reason_name"] == "NO_SOCKET" for d in closed),
                  ", ".join(str(d["reason_name"]) for d in closed))
            check("drop reason IP_RPFILTER named",
                  any(d["reason_name"] == "IP_RPFILTER" for d in rpf),
                  ", ".join(str(d["reason_name"]) for d in rpf))
        if args.router6:
            closed6 = [d for d in drops if d["family"] == 6 and d["remote"] == args.router6
                       and d["remote_port"] == args.closed_port]
            check("ipv6 drop keyed", sum(d["count"] for d in closed6) >= 3, json.dumps(closed6))
        for d in sorted(drops, key=lambda d: -d["count"]):
            print("     drop {:>4} x {} {} {}:{}".format(d["count"], d["reason_name"] or d["reason"],
                                                       d["direction"], d["remote"], d["remote_port"]))

    print("{} check(s) failed".format(len(FAILURES)) if FAILURES else "all checks passed")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
