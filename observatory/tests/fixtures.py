#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    SYNTHETIC test fixtures. Nothing here was measured.

    One list of invented packets is turned into the three views Luca would
    have of it: a collector snapshot (what the kernel counted), a pcapng
    capture (what TShark's "tcp or udp" capture would hold) and a Zeek
    conn.log. Because all three derive from the same packets they are
    mutually consistent, and tests perturb them to create disagreements.
    Every artefact is marked synthetic.
"""

import ipaddress
import struct

T0 = 1760000000.0           # arbitrary epoch second for the fixture
BOOT_OFFSET = 1000.0        # CLOCK_MONOTONIC = realtime - T0 + BOOT_OFFSET
AP_MAC = "02:00:00:00:00:01"
DEVICE_MAC = "02:00:00:00:00:02"
AP_ADDRESSES = ["192.168.100.1/24", "fe80::1/64"]
DEVICE = "192.168.100.2"

TCP_SYN, TCP_ACK, TCP_RST = 0x02, 0x10, 0x04


def mono_ns(realtime):
    return int(round((realtime - T0 + BOOT_OFFSET) * 1e9))


def packet(t, direction, proto, src, dst, sport=0, dport=0, length=100, ttl=64, flags=0):
    return {"t": t, "dir": direction, "proto": proto, "src": src, "dst": dst, "sport": sport,
            "dport": dport, "len": length, "ttl": ttl, "flags": flags}


def scenario():
    """
        :return: list of packets of a small mixed session (all invented).
    """
    p = []
    t = T0 + 2.2
    # 1. TCP with a full handshake and a short download.
    p.append(packet(t, "tx", 6, DEVICE, "93.184.216.34", 50000, 443, 74, flags=TCP_SYN))
    p.append(packet(t + 0.020, "rx", 6, "93.184.216.34", DEVICE, 443, 50000, 74, ttl=52, flags=TCP_SYN | TCP_ACK))
    p.append(packet(t + 0.021, "tx", 6, DEVICE, "93.184.216.34", 50000, 443, 66, flags=TCP_ACK))
    for i in range(8):
        p.append(packet(t + 0.05 + i * 0.01, "rx", 6, "93.184.216.34", DEVICE, 443, 50000, 1400, ttl=52, flags=TCP_ACK))
        p.append(packet(t + 0.055 + i * 0.01, "tx", 6, DEVICE, "93.184.216.34", 50000, 443, 66, flags=TCP_ACK))
    # 2. DNS over UDP.
    t = T0 + 3.0
    for i in range(2):
        p.append(packet(t + i * 0.1, "tx", 17, DEVICE, "9.9.9.9", 40000, 53, 80))
        p.append(packet(t + i * 0.1 + 0.01, "rx", 17, "9.9.9.9", DEVICE, 53, 40000, 150, ttl=57))
    # 3. ICMP echo: outside the capture filter.
    t = T0 + 4.0
    for i in range(3):
        p.append(packet(t + i, "tx", 1, DEVICE, "8.8.8.8", length=98))
        p.append(packet(t + i + 0.012, "rx", 1, "8.8.8.8", DEVICE, length=98, ttl=117))
    # 4. ESP: outside the capture filter.
    for i in range(3):
        p.append(packet(T0 + 4.5 + i * 0.1, "tx", 50, DEVICE, "203.0.113.7", length=120))
    # 5. A datagram whose TTL shows one hop before the AP.
    p.append(packet(T0 + 5.0, "tx", 17, DEVICE, "198.51.100.9", 41000, 5353, 60, ttl=63))
    # 6. A datagram from an address outside the AP prefix.
    p.append(packet(T0 + 5.5, "tx", 17, "10.99.0.5", "198.51.100.10", 42000, 9999, 60))
    # 7. A TCP connection attempt that is never answered (SYN sent twice).
    p.append(packet(T0 + 6.0, "tx", 6, DEVICE, "192.0.2.80", 50001, 80, 74, flags=TCP_SYN))
    p.append(packet(T0 + 7.0, "tx", 6, DEVICE, "192.0.2.80", 50001, 80, 74, flags=TCP_SYN))
    # 8. mDNS: multicast with TTL 255, which heuristics must ignore.
    p.append(packet(T0 + 7.5, "tx", 17, DEVICE, "224.0.0.251", 5353, 5353, 90, ttl=255))
    return sorted(p, key=lambda x: x["t"])


def drops():
    return [{"reason": 3, "reason_name": "NO_SOCKET", "subsystem": 0, "direction": "tx", "family": 4,
             "proto": 17, "remote": "192.168.100.1", "remote_port": 9, "count": 3}]


def _flow_key(pk):
    if pk["dir"] == "tx":
        return (pk["proto"], pk["src"], pk["sport"], pk["dst"], pk["dport"])
    return (pk["proto"], pk["dst"], pk["dport"], pk["src"], pk["sport"])


def snapshot(packets=None, status="stopped", start=None, end=None, drop_list=None, drops_attached=True,
             interface="wlan0", sample_every=1.0, max_flows=65536):
    """
        :return: dict collector snapshot (schema luca.observatory/1), synthetic.
    """
    packets = scenario() if packets is None else packets
    start = T0 if start is None else start
    end = T0 + 10.0 if end is None else end
    flows, order = {}, []
    stats = {d: {k: 0 for k in ("skbs", "segments", "bytes", "ipv4", "ipv6", "arp", "eapol", "other_l2",
                                "pcap_filter_skbs", "pcap_filter_segments", "parse_errors",
                                "flows_not_recorded", "drops", "drops_not_keyed")} for d in ("tx", "rx")}
    protocols = {}
    for pk in packets:
        if not start <= pk["t"] <= end:
            continue
        d = pk["dir"]
        s = stats[d]
        s["skbs"] += 1
        s["segments"] += 1
        s["bytes"] += pk["len"]
        s["ipv4"] += 1
        if pk["proto"] in (6, 17):
            s["pcap_filter_skbs"] += 1
            s["pcap_filter_segments"] += 1
        protocols[(d, pk["proto"])] = protocols.get((d, pk["proto"]), 0) + 1
        key = _flow_key(pk)
        if key not in flows:
            if len(flows) >= max_flows:
                s["flows_not_recorded"] += 1
                continue
            flows[key] = {"first_dir": d, "tx": None, "rx": None, "tcp": {"syn_ns": None, "synack_ns": None,
                                                                         "ack_ns": None, "syn_count": 0,
                                                                         "syn_dir": None}}
            order.append(key)
        f = flows[key]
        fd = f[d] or {"packets": 0, "bytes": 0, "first_ns": None, "last_ns": None, "tcp_flags": 0,
                      "ttl_min": 255, "ttl_max": 0, "retrans_or_reorder": 0, "fragments": False}
        fd["packets"] += 1
        fd["bytes"] += pk["len"]
        ns = mono_ns(pk["t"])
        fd["first_ns"] = fd["first_ns"] or ns
        fd["last_ns"] = ns
        fd["tcp_flags"] |= pk["flags"]
        fd["ttl_min"] = min(fd["ttl_min"], pk["ttl"])
        fd["ttl_max"] = max(fd["ttl_max"], pk["ttl"])
        f[d] = fd
        tcp = f["tcp"]
        if pk["proto"] == 6:
            if pk["flags"] & (TCP_SYN | TCP_ACK) == TCP_SYN and not tcp["synack_ns"]:
                tcp["syn_ns"], tcp["syn_dir"] = ns, d
                tcp["syn_count"] += 1
            elif pk["flags"] & (TCP_SYN | TCP_ACK) == TCP_SYN | TCP_ACK and tcp["syn_ns"] and not tcp["synack_ns"]:
                tcp["synack_ns"] = ns
            elif pk["flags"] & TCP_ACK and tcp["synack_ns"] and not tcp["ack_ns"] and d == tcp["syn_dir"]:
                tcp["ack_ns"] = ns
    empty = {"packets": 0, "bytes": 0, "first_ns": None, "last_ns": None, "tcp_flags": 0, "ttl_min": None,
             "ttl_max": None, "retrans_or_reorder": 0, "fragments": False}
    flow_list = []
    for key in order:
        proto, local, lport, remote, rport = key
        f = flows[key]
        entry = {"family": 4, "proto": proto, "local": local, "local_port": lport, "remote": remote,
                 "remote_port": rport, "first_dir": f["first_dir"], "tx": f["tx"] or dict(empty),
                 "rx": f["rx"] or dict(empty)}
        if proto == 6:
            entry["tcp"] = f["tcp"]
        flow_list.append(entry)

    fields = ["realtime", "monotonic_ns", "tx_skbs", "rx_skbs", "tx_segments", "rx_segments", "tx_bytes",
              "rx_bytes", "tx_pcap_filter_skbs", "rx_pcap_filter_skbs", "tx_pcap_filter_segments",
              "rx_pcap_filter_segments"]
    samples = []
    t = start
    while t <= end + 1e-9:
        row = [t, mono_ns(t)]
        cum = {f: 0 for f in fields[2:]}
        for pk in packets:
            if start <= pk["t"] <= t:
                d = pk["dir"]
                cum[d + "_skbs"] += 1
                cum[d + "_segments"] += 1
                cum[d + "_bytes"] += pk["len"]
                if pk["proto"] in (6, 17):
                    cum[d + "_pcap_filter_skbs"] += 1
                    cum[d + "_pcap_filter_segments"] += 1
        samples.append(row + [cum[f] for f in fields[2:]])
        t += sample_every
    drop_list = drops() if drop_list is None and drops_attached else (drop_list or [])
    for d in drop_list:
        stats[d["direction"]]["drops"] += d["count"]
    return {
        "schema": "luca.observatory/1",
        "synthetic": True,
        "generator": {"name": "luca-observatory", "version": "1.0.0", "commit": "synthetic", "libbpf": "1.5"},
        "session": "ABCDEF12",
        "host": {"kernel": "synthetic", "machine": "synthetic", "btf": True, "btf_path": "/sys/kernel/btf/vmlinux"},
        "interface": {"name": interface, "ifindex": 3, "mac": AP_MAC, "addresses": list(AP_ADDRESSES)},
        "status": status,
        "attach": {"mode": "tcx", "note": None, "drop_tracepoint": "attached" if drops_attached else "unavailable",
                   "drop_note": None if drops_attached else "kernel BTF not found", "error": None},
        "clock": {"realtime": end, "monotonic_ns": mono_ns(end)},
        "started_at": start,
        "started_monotonic_ns": mono_ns(start),
        "limits": {"max_flows": max_flows, "max_drops": 4096, "sample_interval": sample_every,
                   "flush_interval": 10.0, "max_samples": 86400},
        "counters": stats,
        "timeline": {"fields": fields, "samples": samples},
        "protocols": [{"direction": d, "proto": p, "packets": n, "bytes": 0} for (d, p), n in sorted(protocols.items())],
        "flows": flow_list,
        "drops": drop_list,
        "health": {"flow_entries": len(flow_list), "flow_capacity": max_flows, "drop_entries": len(drop_list),
                   "drop_capacity": 4096, "flows_not_recorded": 0, "drops_not_keyed": 0, "parse_errors": 0,
                   "samples": len(samples), "timeline_truncated": False, "max_sample_gap_ns": int(sample_every * 1e9),
                   "snapshot_failures": 0, "map_memlock_bytes": 0, "collector_cpu_seconds": 0.0,
                   "collector_max_rss_kb": 0, "prog_stats": {"enabled": False, "note": None, "programs": []}},
    }


# ----------------------------------------------------------- capture

def _mac(s):
    return bytes.fromhex(s.replace(":", ""))


def frame(pk):
    """
        :return: bytes of an Ethernet/IPv4 frame for a synthetic packet.
    """
    src_mac, dst_mac = (_mac(DEVICE_MAC), _mac(AP_MAC)) if pk["dir"] == "tx" else (_mac(AP_MAC), _mac(DEVICE_MAC))
    if pk["proto"] == 6:
        l4 = struct.pack("!HHIIBBHHH", pk["sport"], pk["dport"], 1, 0, 5 << 4, pk["flags"], 65535, 0, 0)
    elif pk["proto"] == 17:
        l4 = struct.pack("!HHHH", pk["sport"], pk["dport"], 8, 0)
    else:
        l4 = b""
    payload = b"\0" * max(0, pk["len"] - 14 - 20 - len(l4))
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4) + len(payload), 0, 0, pk["ttl"], pk["proto"], 0,
                     ipaddress.ip_address(pk["src"]).packed, ipaddress.ip_address(pk["dst"]).packed)
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + ip + l4 + payload


def captured(packets, start=None, end=None):
    """
        :return: the packets a "tcp or udp" capture between start and end holds.
    """
    return [p for p in packets if p["proto"] in (6, 17) and (start is None or p["t"] >= start)
            and (end is None or p["t"] <= end)]


def _block(btype, body):
    body += b"\0" * ((4 - len(body) % 4) % 4)
    total = len(body) + 12
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def _option(code, value):
    return struct.pack("<HH", code, len(value)) + value + b"\0" * ((4 - len(value) % 4) % 4)


def pcapng(packets, ifdrop=0, flags=True, isb=True):
    """
        :return: bytes of a pcapng file: one Ethernet interface with
                 nanosecond timestamps, EPB direction flags and an ISB.
    """
    out = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += _block(1, struct.pack("<HHI", 1, 0, 262144) + _option(9, b"\x09") + _option(0, b""))
    for pk in packets:
        data = frame(pk)
        ts = int(round(pk["t"] * 1e9))
        body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xffffffff, len(data), len(data))
        body += data + b"\0" * ((4 - len(data) % 4) % 4)
        if flags:
            body += _option(2, struct.pack("<I", 1 if pk["dir"] == "tx" else 2)) + _option(0, b"")
        out += _block(6, body)
    if isb:
        ts = int(round((packets[-1]["t"] if packets else T0) * 1e9))
        body = struct.pack("<III", 0, ts >> 32, ts & 0xffffffff)
        body += _option(4, struct.pack("<Q", len(packets) + ifdrop)) + _option(5, struct.pack("<Q", ifdrop))
        body += _option(0, b"")
        out += _block(5, body)
    return out


def pcap(packets, nanoseconds=False, big_endian=False):
    """
        :return: bytes of a classic pcap file (Ethernet).
    """
    e = ">" if big_endian else "<"
    magic = 0xa1b23c4d if nanoseconds else 0xa1b2c3d4
    out = struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 262144, 1)
    for pk in packets:
        data = frame(pk)
        sec = int(pk["t"])
        frac = int(round((pk["t"] - sec) * (1e9 if nanoseconds else 1e6)))
        out += struct.pack(e + "IIII", sec, frac, len(data), len(data)) + data
    return out


# --------------------------------------------------------------- zeek

CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
               "orig_bytes", "resp_bytes", "conn_state", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes",
               "resp_pkts", "resp_ip_bytes"]
CONN_TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count", "count",
              "string", "count", "string", "count", "count", "count", "count"]


def conns(packets):
    """
        :return: Zeek-like connection records for captured packets.
    """
    out = {}
    for pk in packets:
        key = _flow_key(pk)
        c = out.get(key)
        if c is None:
            c = out[key] = {"first": pk["t"], "last": pk["t"], "orig": (pk["src"], pk["sport"]),
                            "resp": (pk["dst"], pk["dport"]), "proto": pk["proto"], "orig_pkts": 0, "resp_pkts": 0,
                            "orig_bytes": 0, "resp_bytes": 0, "reply": False, "syn": False}
        c["last"] = pk["t"]
        if (pk["src"], pk["sport"]) == c["orig"]:
            c["orig_pkts"] += 1
            c["orig_bytes"] += pk["len"] - 14
            c["syn"] = c["syn"] or bool(pk["flags"] & TCP_SYN)
        else:
            c["resp_pkts"] += 1
            c["resp_bytes"] += pk["len"] - 14
            c["reply"] = True
    records = []
    for i, c in enumerate(sorted(out.values(), key=lambda x: x["first"])):
        state = ("SF" if c["reply"] else "S0") if c["proto"] == 6 else ("SF" if c["reply"] else "S0")
        records.append({"ts": c["first"], "uid": "Csynthetic{}".format(i), "id.orig_h": c["orig"][0],
                        "id.orig_p": c["orig"][1], "id.resp_h": c["resp"][0], "id.resp_p": c["resp"][1],
                        "proto": {6: "tcp", 17: "udp"}[c["proto"]], "service": None,
                        "duration": c["last"] - c["first"], "orig_bytes": 0, "resp_bytes": 0, "conn_state": state,
                        "missed_bytes": 0, "history": None, "orig_pkts": c["orig_pkts"],
                        "orig_ip_bytes": c["orig_bytes"], "resp_pkts": c["resp_pkts"], "resp_ip_bytes": c["resp_bytes"]})
    return records


def conn_log(records):
    """
        :return: str of a Zeek TSV conn.log.
    """
    lines = ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-",
             "#path\tconn", "#fields\t" + "\t".join(CONN_FIELDS), "#types\t" + "\t".join(CONN_TYPES)]
    for r in records:
        vals = []
        for f in CONN_FIELDS:
            v = r.get(f)
            vals.append("-" if v is None else ("{:.6f}".format(v) if isinstance(v, float) else str(v)))
        lines.append("\t".join(vals))
    lines.append("#close\t2025-01-01-00-00-00")
    return "\n".join(lines) + "\n"


def write_session(directory, packets=None, snapshot_kwargs=None, capture_start=T0 + 1.5, capture_end=T0 + 8.5,
                  drop_capture=0, conn=True, session_status="stopped"):
    """
        Writes a synthetic Luca capture directory with observatory output.
        :return: dict of the paths written
    """
    import json
    import os
    packets = scenario() if packets is None else packets
    os.makedirs(os.path.join(directory, "assets"), exist_ok=True)
    snap = snapshot(packets, **(snapshot_kwargs or {}))
    cap = captured(packets, capture_start, capture_end)
    if drop_capture:
        # Lose packets from the middle, keeping the capture's first and last.
        cap = cap[:1] + cap[1 + drop_capture:]
    paths = {"snapshot": os.path.join(directory, "assets", "observatory.json"),
             "session": os.path.join(directory, "assets", "observatory_session.json"),
             "capture": os.path.join(directory, "capture.pcap"),
             "conn": os.path.join(directory, "assets", "conn.log"),
             "device": os.path.join(directory, "assets", "device.json")}
    with open(paths["snapshot"], "w") as f:
        json.dump(snap, f)
    with open(paths["session"], "w") as f:
        json.dump({"schema": "luca.observatory.session/1", "session": "ABCDEF12", "status": session_status,
                   "synthetic": True}, f)
    with open(paths["capture"], "wb") as f:
        f.write(pcapng(cap))
    if conn:
        with open(paths["conn"], "w") as f:
            f.write(conn_log(conns(cap)))
    with open(paths["device"], "w") as f:
        json.dump({"name": "synthetic-device", "ip_address": DEVICE, "mac_address": DEVICE_MAC}, f)
    return paths
