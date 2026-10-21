#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Reading the collector's JSON snapshot (schema luca.observatory/1).

    The collector records BPF timestamps as CLOCK_MONOTONIC nanoseconds.
    Each snapshot carries a (CLOCK_REALTIME, CLOCK_MONOTONIC) pair read back
    to back, and every timeline sample carries another. Converting a kernel
    timestamp to wall-clock time uses the snapshot's pair; the spread of
    (realtime - monotonic) over the samples bounds how far the wall clock was
    stepped or slewed during the session, and is reported as the conversion
    uncertainty rather than hidden.
"""

import json

from . import SNAPSHOT_SCHEMA

DIRECTIONS = ("tx", "rx")

PROTO_NAMES = {1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 17: "UDP", 41: "IPv6-in-IPv4",
               47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM",
               112: "VRRP", 115: "L2TP", 132: "SCTP", 136: "UDPLITE"}

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10

REQUIRED = {"schema": str, "status": str, "attach": dict, "interface": dict,
            "counters": dict, "timeline": dict, "flows": list, "drops": list,
            "protocols": list, "clock": dict, "generator": dict, "host": dict}


class SnapshotError(ValueError):
    pass


def proto_name(proto):
    return PROTO_NAMES.get(proto, "IP protocol {}".format(proto))


def validate(snap):
    """
        :return: list of str problems; empty when the snapshot is usable.
    """
    if not isinstance(snap, dict):
        return ["snapshot is not a JSON object"]
    problems = []
    for key, kind in REQUIRED.items():
        if not isinstance(snap.get(key), kind):
            problems.append("missing or malformed field: {}".format(key))
    if snap.get("schema") not in (None, SNAPSHOT_SCHEMA) and isinstance(snap.get("schema"), str):
        problems.append("unsupported schema {}".format(snap["schema"]))
    if isinstance(snap.get("counters"), dict):
        for d in DIRECTIONS:
            if not isinstance(snap["counters"].get(d), dict):
                problems.append("missing counters.{}".format(d))
    if isinstance(snap.get("timeline"), dict):
        t = snap["timeline"]
        if not isinstance(t.get("fields"), list) or not isinstance(t.get("samples"), list):
            problems.append("malformed timeline")
        elif any(not isinstance(s, list) or len(s) != len(t["fields"]) for s in t["samples"]):
            problems.append("timeline sample width does not match its fields")
    return problems


def load(path):
    """
        :return: dict snapshot. Raises SnapshotError when unusable.
    """
    try:
        with open(path, "r") as f:
            snap = json.load(f)
    except (OSError, ValueError) as e:
        raise SnapshotError("cannot read snapshot {}: {}".format(path, e))
    problems = validate(snap)
    if problems:
        raise SnapshotError("; ".join(problems))
    return snap


class Clock(object):
    """
        Converts collector CLOCK_MONOTONIC nanoseconds to epoch seconds.
    """

    def __init__(self, snap):
        clock = snap.get("clock") or {}
        self.realtime = clock.get("realtime")
        self.monotonic_ns = clock.get("monotonic_ns")
        self.valid = isinstance(self.realtime, (int, float)) and isinstance(self.monotonic_ns, int)
        self.offset = self.realtime - self.monotonic_ns / 1e9 if self.valid else None

        offsets = [o for o in (self._sample_offset(s) for s in timeline_rows(snap)) if o is not None]
        if self.valid:
            offsets.append(self.offset)
        # Wall-clock steps between samples show up as a spread of offsets.
        self.uncertainty = (max(offsets) - min(offsets)) if len(offsets) > 1 else None

    @staticmethod
    def _sample_offset(row):
        rt, mono = row.get("realtime"), row.get("monotonic_ns")
        if isinstance(rt, (int, float)) and isinstance(mono, int):
            return rt - mono / 1e9
        return None

    def to_realtime(self, ns):
        if not self.valid or not isinstance(ns, int) or ns <= 0:
            return None
        return self.offset + ns / 1e9


def timeline_rows(snap):
    """
        :return: list of dict samples keyed by the timeline field names.
    """
    t = snap.get("timeline") or {}
    fields = t.get("fields") or []
    return [dict(zip(fields, s)) for s in t.get("samples") or [] if isinstance(s, list)]


def flow_window(flow):
    """
        :return: (first_ns, last_ns) over both directions, or (None, None).
    """
    firsts = [flow[d]["first_ns"] for d in DIRECTIONS if flow.get(d, {}).get("first_ns")]
    lasts = [flow[d]["last_ns"] for d in DIRECTIONS if flow.get(d, {}).get("last_ns")]
    return (min(firsts) if firsts else None, max(lasts) if lasts else None)


def loss_report(snap):
    """
        Every way the collector can lose or truncate telemetry, as numbers.
        :return: dict
    """
    c = snap.get("counters") or {}
    h = snap.get("health") or {}
    tx, rx = c.get("tx") or {}, c.get("rx") or {}

    def both(key):
        return int(tx.get(key) or 0) + int(rx.get(key) or 0)

    return {
        "flows_not_recorded": both("flows_not_recorded"),
        "drops_not_keyed": both("drops_not_keyed"),
        "parse_errors": both("parse_errors"),
        "timeline_truncated": bool(h.get("timeline_truncated") or (snap.get("timeline") or {}).get("truncated")),
        "snapshot_failures": int(h.get("snapshot_failures") or 0),
        "max_sample_gap_ns": h.get("max_sample_gap_ns"),
        "flow_entries": h.get("flow_entries"),
        "flow_capacity": h.get("flow_capacity"),
    }
