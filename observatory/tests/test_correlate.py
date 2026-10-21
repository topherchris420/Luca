#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Correlation, provenance and uncertainty rules, on synthetic fixtures.
"""

import copy
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import fixtures
from luca_observatory import (CORRELATED, INFERRED, OBSERVED, UNAVAILABLE, CORROBORATED, SINGLE_SOURCE,
                              UNCERTAIN, MISSING, INFERENCE, LABELS, CATEGORIES)
from luca_observatory import correlate, pcapstats

KERNEL = {"kernel.tc", "kernel.kfree_skb"}
CAPTURE_DERIVED = {"capture.pcap", "zeek.conn", "zeek.dns", "suricata.fast", "luca.alert"}


def run(packets=None, snap=None, capture=None, conns=None, alerts=None, dns=None, suricata=None,
        capture_interface="wlan0", lose=None, **snap_kw):
    packets = fixtures.scenario() if packets is None else packets
    snap = fixtures.snapshot(packets, **snap_kw) if snap is None else snap
    cap_packets = fixtures.captured(packets, fixtures.T0 + 1.5, fixtures.T0 + 8.5)
    if lose:
        cap_packets = [p for p in cap_packets if not lose(p)]
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "c.pcap")
        with open(path, "wb") as f:
            f.write(fixtures.pcapng(cap_packets))
        cap = capture if capture is not None else pcapstats.read(
            path, pcapstats.Context(fixtures.AP_MAC, fixtures.AP_ADDRESSES))
    if conns is None:
        conns = [(i + 8, r) for i, r in enumerate(fixtures.conns(cap_packets))]
    return correlate.correlate(snapshot=snap, capture=cap, conns=conns, dns=dns or [],
                               alerts=alerts, suricata=suricata, device={"ip_address": fixtures.DEVICE},
                               capture_interface=capture_interface)


def find(summary, text, category=None):
    return [o for o in summary["observations"] if text in o["statement"] and
            (category is None or o["category"] == category)]


class ProvenanceInvariants(unittest.TestCase):
    """
        Rules every summary must satisfy, whatever the input.
    """

    def check(self, s):
        for o in s["observations"]:
            self.assertIn(o["label"], LABELS)
            self.assertIn(o["category"], CATEGORIES)
            sources = set(o["sources"])
            if o["label"] == CORRELATED:
                # Corroboration needs the kernel path and a capture-derived path.
                self.assertTrue(sources & KERNEL and sources & CAPTURE_DERIVED, o)
                self.assertIn(o["category"], (CORROBORATED, UNCERTAIN), o)
            if o["label"] == OBSERVED:
                self.assertEqual(len(sources), 1, o)
                self.assertIn(o["category"], (SINGLE_SOURCE, MISSING), o)
            if o["label"] == INFERRED:
                self.assertEqual(o["category"], INFERENCE, o)
                self.assertTrue(o["statement"].startswith("Inferred, not measured"), o)
            if o["label"] == UNAVAILABLE:
                self.assertEqual(o["category"], MISSING, o)
            if o["category"] == UNCERTAIN:
                self.assertTrue(o["reasons"], o)
            if o["label"] in (OBSERVED, CORRELATED):
                # Measured statements preserve the original records they rest on.
                self.assertTrue(o["evidence"], o)
                for e in o["evidence"]:
                    self.assertTrue(e["source"] and e["pointer"] is not None, e)
        ids = [o["id"] for o in s["observations"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(sum(s["counts"].values()), len(s["observations"]))
        for f in s["findings"]:
            self.assertIn(f["provenance"], (OBSERVED, INFERRED))
            if f["id"] in ("KNO-03", "KNO-05"):
                self.assertEqual(f["provenance"], INFERRED)
        conclusions = " ".join(u["conclusion"] for u in s["unsupported"])
        self.assertIn("process", conclusions)

    def test_invariants_hold_across_scenarios(self):
        alerts = {"high": [{"id": "IOC-01", "host": "93.184.216.34", "title": "t", "description": "d", "level": "High"}],
                  "moderate": [], "low": [{"id": "PROTO-01", "host": "example.org", "title": "t", "description": "d",
                                           "level": "Low"}]}
        cases = [run(), run(lose=lambda p: fixtures.T0 + 3 < p["t"] < fixtures.T0 + 6), run(alerts=alerts), run(capture_interface="eth0"),
                 run(status="failed"), run(drops_attached=False), run(max_flows=2), run(conns=[]),
                 correlate.correlate(snapshot=None, session={"status": "unavailable", "error": "no socket"})]
        for s in cases:
            self.check(s)


class FlowCorrelationTest(unittest.TestCase):

    def test_consistent_session(self):
        s = run()
        self.assertEqual(s["counts"][UNCERTAIN], 0)
        self.assertEqual(s["counts"][MISSING], 0)
        tcp = find(s, "93.184.216.34:443", CORROBORATED)
        self.assertEqual(len(tcp), 1)
        self.assertEqual(tcp[0]["label"], CORRELATED)
        self.assertEqual(tcp[0]["details"]["tcp"]["handshake"], "completed")
        sources = [e["source"] for e in tcp[0]["evidence"]]
        self.assertEqual(sources, ["kernel.tc", "zeek.conn"])
        self.assertEqual(tcp[0]["evidence"][0]["record"]["remote"], "93.184.216.34")
        self.assertTrue(tcp[0]["evidence"][1]["pointer"].startswith("line:"))
        self.assertEqual(s["coverage"]["assessment"], "consistent")

    def test_kernel_only_traffic_outside_the_filter(self):
        s = run()
        for proto in ("ICMP", "ESP"):
            obs = find(s, proto + " 192.168.100.2", SINGLE_SOURCE)
            self.assertEqual(len(obs), 1, proto)
            self.assertEqual(obs[0]["label"], OBSERVED)
            self.assertIn("capture filter", obs[0]["reasons"][0])

    def test_unanswered_syn_is_reported_as_observed(self):
        s = run()
        obs = find(s, "192.0.2.80:80")[0]
        self.assertEqual(obs["details"]["tcp"]["handshake"], "SYN without SYN-ACK")
        self.assertEqual(obs["details"]["tcp"]["syn_count"], 2)
        self.assertEqual(s["statistics"]["tcp"]["syn_without_synack"], 1)

    def test_capture_counting_more_than_kernel_is_uncertain(self):
        packets = fixtures.scenario()
        snap = fixtures.snapshot(packets)
        tcp = [f for f in snap["flows"] if f["remote"] == "93.184.216.34"][0]
        tcp["rx"]["packets"] = 3
        s = run(packets, snap=snap)
        obs = find(s, "93.184.216.34:443")[0]
        self.assertEqual(obs["category"], UNCERTAIN)
        self.assertIn("the capture counted 9 rx packet(s), the kernel 3", obs["reasons"])

    def test_time_mismatch_is_uncertain(self):
        packets = fixtures.scenario()
        snap = fixtures.snapshot(packets)
        conns = [(i + 8, r) for i, r in enumerate(fixtures.conns(fixtures.captured(packets)))]
        conns[0][1]["ts"] += 3600  # the capture host's clock is an hour off
        s = run(packets, snap=snap, conns=conns)
        obs = find(s, "93.184.216.34:443")[0]
        self.assertEqual(obs["category"], UNCERTAIN)
        self.assertTrue(any("outside the kernel's flow window" in r for r in obs["reasons"]))

    def test_capture_only_flow_when_kernel_table_full(self):
        s = run(max_flows=2)
        capture_only = [o for o in s["observations"] if o["sources"] == ["zeek.conn"]]
        self.assertTrue(capture_only)
        for o in capture_only:
            self.assertEqual(o["label"], OBSERVED)
            self.assertIn("flow table was full", o["reasons"][0])
        self.assertTrue(find(s, "not attributed to a flow", MISSING))

    def test_nat_boundary_matches_on_remote_only(self):
        packets = fixtures.scenario()
        snap = fixtures.snapshot(packets, interface="eth0")
        # Behind NAT the uplink shows the AP's public address instead of the device's.
        for f in snap["flows"]:
            if f["local"] == fixtures.DEVICE:
                f["local"] = "203.0.113.200"
        s = run(packets, snap=snap, capture_interface="wlan0")
        obs = find(s, "93.184.216.34:443")[0]
        self.assertEqual(obs["label"], CORRELATED)
        self.assertEqual(obs["category"], UNCERTAIN)
        self.assertIn("matched across a NAT boundary on the remote endpoint only", obs["reasons"])
        self.assertTrue(any("different interfaces" in l for l in s["limitations"]))

    def test_uplink_collector_sees_reversed_roles(self):
        packets = fixtures.scenario()
        snap = fixtures.snapshot(packets, interface="eth0")
        snap["interface"]["addresses"] = ["203.0.113.200/24"]
        # On the uplink, ingress comes from the network: local and remote, tx and rx swap.
        for f in snap["flows"]:
            if f["local"] == fixtures.DEVICE:
                f["local"], f["local_port"], f["remote"], f["remote_port"] = (
                    f["remote"], f["remote_port"], "203.0.113.200", 61000 + f["local_port"] % 1000)
                f["tx"], f["rx"] = f["rx"], f["tx"]
        s = run(packets, snap=snap, capture_interface="wlan0")
        obs = find(s, "93.184.216.34:443")[0]
        self.assertEqual((obs["label"], obs["category"]), (CORRELATED, UNCERTAIN))
        self.assertTrue(any("faces the network" in r for r in obs["reasons"]))
        self.assertFalse(any("the capture counted" in r for r in obs["reasons"]), obs["reasons"])
        self.assertEqual(s["findings"], [])
        self.assertTrue(any("KNO-xx" in l for l in s["limitations"]))
        self.assertEqual(s["coverage"]["assessment"], "unknown")

    def test_ambiguous_nat_match(self):
        packets = fixtures.scenario()
        snap = fixtures.snapshot(packets, interface="eth0")
        tcp = [f for f in snap["flows"] if f["remote"] == "93.184.216.34"][0]
        twin = copy.deepcopy(tcp)
        tcp["local"], tcp["local_port"] = "203.0.113.200", 61000
        twin["local"], twin["local_port"] = "203.0.113.200", 61001
        snap["flows"].append(twin)
        s = run(packets, snap=snap, capture_interface="wlan0")
        amb = find(s, "matches 2 kernel flows", UNCERTAIN)
        self.assertEqual(len(amb), 1)
        self.assertEqual(len([e for e in amb[0]["evidence"] if e["source"] == "kernel.tc"]), 2)


class CoverageTest(unittest.TestCase):

    def test_capture_loss_is_detected(self):
        # The capture loses the packets between two kernel samples.
        s = run(lose=lambda p: fixtures.T0 + 3 < p["t"] < fixtures.T0 + 6)
        cov = s["coverage"]
        self.assertEqual(cov["assessment"], "incomplete")
        self.assertGreater(sum(d["missed_at_least"] for d in cov["directions"].values()), 0)
        obs = find(s, "The capture is incomplete")[0]
        # The capture reported no drops of its own, so this rests on the kernel alone.
        self.assertEqual(obs["label"], OBSERVED)

    def test_loss_at_the_window_edges_is_not_claimed(self):
        # Packets lost before the first interior sample cannot be proven missing.
        s = run(lose=lambda p: p["t"] < fixtures.T0 + 2.4 and p["t"] > fixtures.T0 + 2.2)
        self.assertEqual(s["coverage"]["assessment"], "consistent")
        self.assertIn("cannot be excluded", s["coverage"]["explanation"])

    def test_extra_capture_packets_are_inconsistent(self):
        packets = fixtures.scenario()
        snap = fixtures.snapshot(packets)
        rx = snap["timeline"]["fields"].index("rx_pcap_filter_segments")
        for row in snap["timeline"]["samples"]:
            row[rx] = 0
        s = run(packets, snap=snap)
        self.assertEqual(s["coverage"]["assessment"], "inconsistent")
        self.assertEqual(find(s, "counts disagree")[0]["category"], UNCERTAIN)

    def test_collector_started_late_is_partial(self):
        s = run(start=fixtures.T0 + 3.0)
        self.assertEqual(s["coverage"]["assessment"], "partial")
        self.assertTrue(find(s, "bounded from below", MISSING))

    def test_unknown_without_timeline(self):
        snap = fixtures.snapshot()
        snap["timeline"]["samples"] = snap["timeline"]["samples"][:1]
        self.assertEqual(run(snap=snap)["coverage"]["assessment"], "unknown")


class MissingTelemetryTest(unittest.TestCase):

    def test_no_snapshot(self):
        s = correlate.correlate(snapshot=None, session={"status": "unavailable", "error": "service not running"})
        self.assertEqual(s["counts"][MISSING], 1)
        self.assertIn("service not running", s["observations"][0]["statement"])
        self.assertIsNone(s["statistics"])
        self.assertEqual(s["findings"], [])

    def test_failed_collector_produces_no_flow_statements(self):
        packets = fixtures.scenario()
        snap = fixtures.snapshot(packets, status="failed")
        snap["attach"]["error"] = "loading BPF programs failed: Operation not permitted"
        s = run(packets, snap=snap)
        self.assertTrue(find(s, "Operation not permitted", MISSING))
        self.assertFalse([o for o in s["observations"] if o["label"] == CORRELATED])

    def test_crashed_collector(self):
        s = run(status="running")
        self.assertTrue(find(s, "did not stop cleanly", MISSING))

    def test_drop_reasons_unavailable(self):
        s = run(drops_attached=False)
        self.assertTrue(find(s, "drop reasons are unavailable", MISSING))
        self.assertTrue(any("dropped" in u["conclusion"] for u in s["unsupported"]))

    def test_without_zeek(self):
        packets = fixtures.scenario()
        snap = fixtures.snapshot(packets)
        s = correlate.correlate(snapshot=snap, capture=None, capture_error="no capture", conns=None)
        self.assertTrue(find(s, "conn.log is not available", MISSING))
        self.assertTrue(find(s, "capture could not be read", MISSING))
        tcp = find(s, "93.184.216.34:443")[0]
        self.assertEqual(tcp["label"], OBSERVED)


class AlertCorrelationTest(unittest.TestCase):

    def test_ip_alert_is_corroborated_not_confirmed(self):
        alerts = {"high": [{"id": "IOC-01", "host": "93.184.216.34", "title": "t", "description": "d",
                            "level": "High"}], "moderate": [], "low": []}
        s = run(alerts=alerts)
        obs = find(s, "Alert IOC-01")[0]
        self.assertEqual((obs["label"], obs["category"]), (CORRELATED, CORROBORATED))
        self.assertIn("not the alert's interpretation", obs["statement"])
        self.assertEqual(obs["evidence"][0]["pointer"], "/high/0")
        self.assertEqual(obs["evidence"][0]["record"]["id"], "IOC-01")

    def test_domain_alert_through_dns_is_uncertain(self):
        alerts = {"high": [], "moderate": [{"id": "IOC-05", "host": "example.org", "title": "t", "description": "d",
                                            "level": "Moderate"}], "low": []}
        dns = [(9, {"query": "example.org", "answers": "93.184.216.34"})]
        obs = find(run(alerts=alerts, dns=dns), "Alert IOC-05")[0]
        self.assertEqual((obs["label"], obs["category"]), (CORRELATED, UNCERTAIN))
        self.assertIn("zeek.dns", obs["sources"])

    def test_alert_without_kernel_flow(self):
        alerts = {"high": [], "moderate": [], "low": [{"id": "PROTO-02", "host": "198.18.0.1", "title": "t",
                                                       "description": "d", "level": "Low"}]}
        obs = find(run(alerts=alerts), "Alert PROTO-02")[0]
        self.assertEqual((obs["label"], obs["category"]), (OBSERVED, SINGLE_SOURCE))

    def test_suricata_tuple(self):
        ev = [{"msg": "WiFi name sent in clear text", "proto": "TCP", "src": fixtures.DEVICE, "sport": 50000,
               "dst": "93.184.216.34", "dport": 443}]
        obs = find(run(suricata=ev), "Suricata signature")[0]
        self.assertEqual(obs["category"], CORROBORATED)

    def test_kno_alerts_are_not_correlated_with_themselves(self):
        alerts = {"high": [], "moderate": [], "low": [{"id": "KNO-01", "host": "8.8.8.8", "title": "t",
                                                       "description": "d", "level": "Low"}]}
        self.assertFalse(find(run(alerts=alerts), "Alert KNO-01"))


class DropCorrelationTest(unittest.TestCase):

    def test_drop_with_matching_capture_exchange(self):
        packets = fixtures.scenario()
        packets.append(fixtures.packet(fixtures.T0 + 6.5, "tx", 17, fixtures.DEVICE, "192.168.100.1", 43000, 9, 60))
        packets.sort(key=lambda p: p["t"])
        s = run(packets)
        obs = find(s, "reason NO_SOCKET")[0]
        self.assertEqual((obs["label"], obs["category"]), (CORRELATED, CORROBORATED))
        self.assertEqual([e["source"] for e in obs["evidence"]][:2], ["kernel.kfree_skb", "zeek.conn"])


if __name__ == "__main__":
    unittest.main()
