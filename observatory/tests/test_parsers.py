#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Parsing of collector snapshots, captures and Zeek logs. All inputs are
    synthetic fixtures (see fixtures.py).
"""

import json
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import fixtures
from luca_observatory import pcapstats, snapshot, zeeklog


def write(directory, name, data):
    path = os.path.join(directory, name)
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)
    return path


class SnapshotTest(unittest.TestCase):

    def test_fixture_is_valid(self):
        self.assertEqual(snapshot.validate(fixtures.snapshot()), [])

    def test_validation_problems(self):
        snap = fixtures.snapshot()
        del snap["counters"]["rx"]
        snap["timeline"]["samples"][0] = [1, 2]
        problems = snapshot.validate(snap)
        self.assertIn("missing counters.rx", problems)
        self.assertIn("timeline sample width does not match its fields", problems)
        self.assertEqual(snapshot.validate([]), ["snapshot is not a JSON object"])
        snap = fixtures.snapshot()
        snap["schema"] = "luca.observatory/9"
        self.assertTrue(snapshot.validate(snap))

    def test_load_errors(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.load(os.path.join(d, "missing.json"))
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.load(write(d, "bad.json", "{not json"))
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.load(write(d, "partial.json", json.dumps({"schema": "luca.observatory/1"})))
            self.assertEqual(snapshot.load(write(d, "ok.json", json.dumps(fixtures.snapshot())))["status"], "stopped")

    def test_clock_conversion(self):
        snap = fixtures.snapshot()
        clock = snapshot.Clock(snap)
        self.assertAlmostEqual(clock.to_realtime(fixtures.mono_ns(fixtures.T0 + 3.25)), fixtures.T0 + 3.25, places=6)
        self.assertAlmostEqual(clock.uncertainty, 0.0, places=6)
        self.assertIsNone(clock.to_realtime(None))
        self.assertIsNone(clock.to_realtime(0))

    def test_clock_step_is_measured(self):
        snap = fixtures.snapshot()
        # The wall clock jumps by 2 s half-way through the session.
        i = snap["timeline"]["fields"].index("realtime")
        for row in snap["timeline"]["samples"][5:]:
            row[i] += 2.0
        snap["clock"]["realtime"] += 2.0
        self.assertAlmostEqual(snapshot.Clock(snap).uncertainty, 2.0, places=6)

    def test_loss_report(self):
        snap = fixtures.snapshot()
        snap["counters"]["tx"]["flows_not_recorded"] = 4
        snap["counters"]["rx"]["drops_not_keyed"] = 1
        snap["health"]["timeline_truncated"] = True
        loss = snapshot.loss_report(snap)
        self.assertEqual(loss["flows_not_recorded"], 4)
        self.assertEqual(loss["drops_not_keyed"], 1)
        self.assertTrue(loss["timeline_truncated"])

    def test_flow_window(self):
        f = {"tx": {"first_ns": 5, "last_ns": 9}, "rx": {"first_ns": None, "last_ns": None}}
        self.assertEqual(snapshot.flow_window(f), (5, 9))
        self.assertEqual(snapshot.flow_window({"tx": {}, "rx": {}}), (None, None))


class CaptureTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.packets = fixtures.captured(fixtures.scenario())
        self.ctx = pcapstats.Context(fixtures.AP_MAC, fixtures.AP_ADDRESSES)

    def tearDown(self):
        self.tmp.cleanup()

    def summary(self, data, ctx=None):
        return pcapstats.read(write(self.tmp.name, "c.pcap", data), ctx or self.ctx)

    def expected_directions(self):
        return {"tx": sum(p["dir"] == "tx" for p in self.packets), "rx": sum(p["dir"] == "rx" for p in self.packets),
                "unknown": 0}

    def test_pcapng_with_flags_and_isb(self):
        s = self.summary(fixtures.pcapng(self.packets, ifdrop=7))
        self.assertEqual(s.format, "pcapng")
        self.assertEqual(s.packets, len(self.packets))
        self.assertEqual(s.directions, self.expected_directions())
        self.assertEqual(s.as_dict()["direction_method"], "pcapng_flags")
        self.assertAlmostEqual(s.first, self.packets[0]["t"], places=6)  # nanosecond if_tsresol
        self.assertAlmostEqual(s.last, self.packets[-1]["t"], places=6)
        self.assertEqual(s.interface_stats[0]["ifdrop"], 7)
        self.assertFalse(s.truncated)

    def test_direction_from_mac_without_flags(self):
        s = self.summary(fixtures.pcapng(self.packets, flags=False))
        self.assertEqual(s.directions, self.expected_directions())
        self.assertEqual(s.as_dict()["direction_method"], "mac")

    def test_direction_from_addresses_without_mac(self):
        s = self.summary(fixtures.pcapng(self.packets, flags=False),
                         pcapstats.Context(None, fixtures.AP_ADDRESSES))
        self.assertEqual(s.as_dict()["direction_method"], "ip")
        # The foreign-source datagram cannot be oriented by address alone.
        self.assertEqual(s.directions["unknown"], 1)

    def test_classic_pcap_variants(self):
        for ns in (False, True):
            for be in (False, True):
                s = self.summary(fixtures.pcap(self.packets, nanoseconds=ns, big_endian=be))
                self.assertEqual(s.format, "pcap")
                self.assertEqual(s.packets, len(self.packets))
                self.assertAlmostEqual(s.first, self.packets[0]["t"], places=5)
                self.assertEqual(s.directions, self.expected_directions())

    def test_flows_are_oriented(self):
        s = self.summary(fixtures.pcapng(self.packets))
        flows = {(f["proto"], f["local"], f["local_port"], f["remote"], f["remote_port"]): f for f in s.flow_list()}
        tcp = flows[(6, fixtures.DEVICE, 50000, "93.184.216.34", 443)]
        self.assertEqual(tcp["tx"]["packets"], 10)
        self.assertEqual(tcp["rx"]["packets"], 9)

    def test_truncated_capture(self):
        data = fixtures.pcapng(self.packets)
        s = self.summary(data[:-30])
        self.assertTrue(s.truncated)
        self.assertGreater(s.packets, 0)

    def test_not_a_capture(self):
        with self.assertRaises(pcapstats.PcapError):
            self.summary(b"hello world")
        with self.assertRaises(pcapstats.PcapError):
            self.summary(b"")
        with self.assertRaises(pcapstats.PcapError):
            pcapstats.read(os.path.join(self.tmp.name, "absent.pcap"))

    def test_vlan_ipv6_and_fragments(self):
        eth = bytes(6) + bytes(6)
        # 802.1Q-tagged IPv4 UDP.
        ip4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 17, 0, bytes([192, 168, 100, 2]), bytes([1, 1, 1, 1]))
        vlan = eth + struct.pack("!HHH", 0x8100, 5, 0x0800) + ip4 + struct.pack("!HHHH", 1000, 53, 8, 0)
        # IPv6 with a hop-by-hop header, then UDP.
        src6 = bytes.fromhex("20010db8000000000000000000000002")
        dst6 = bytes.fromhex("20010db8000000000000000000000099")
        ip6 = struct.pack("!IHBB", 6 << 28, 16, 0, 64) + src6 + dst6
        hbh = struct.pack("!BB6x", 17, 0)
        v6 = eth + struct.pack("!H", 0x86DD) + ip6 + hbh + struct.pack("!HHHH", 2000, 443, 8, 0)
        # A non-first IPv4 fragment carries no ports.
        frag = eth + struct.pack("!H", 0x0800) + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 100, 64, 17, 0,
                                                             bytes([192, 168, 100, 2]), bytes([1, 1, 1, 1])) + bytes(8)
        self.assertEqual(pcapstats.parse_l3(vlan, 18, 0x0800)["dport"], 53)
        p6 = pcapstats.parse_l3(v6, 14, 0x86DD)
        self.assertEqual((p6["proto"], p6["sport"], p6["dport"]), (17, 2000, 443))
        pf = pcapstats.parse_l3(frag, 14, 0x0800)
        self.assertTrue(pf["fragment"])
        self.assertEqual((pf["sport"], pf["dport"]), (0, 0))

    def test_linux_cooked_direction(self):
        ip4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 17, 0, bytes([1, 1, 1, 1]), bytes([192, 168, 100, 2]))
        sll_out = struct.pack("!HHH8sH", 4, 1, 6, bytes(8), 0x0800) + ip4 + bytes(8)
        s = pcapstats.Summary()
        s.add(1.0, pcapstats.LINK_SLL, sll_out, len(sll_out))
        self.assertEqual(s.directions["rx"], 1)
        self.assertEqual(s.as_dict()["direction_method"], "sll_packet_type")


class ZeekTest(unittest.TestCase):

    def test_tsv_types_and_unset(self):
        records = fixtures.conns(fixtures.captured(fixtures.scenario()))
        with tempfile.TemporaryDirectory() as d:
            parsed = zeeklog.read(write(d, "conn.log", fixtures.conn_log(records)))
        self.assertEqual(len(parsed), len(records))
        line, first = parsed[0]
        self.assertEqual(line, 8)
        self.assertIsInstance(first["ts"], float)
        self.assertIsInstance(first["id.orig_p"], int)
        self.assertIsNone(first["service"])
        self.assertEqual(first["proto"], "tcp")

    def test_json_lines_and_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            parsed = zeeklog.read(write(d, "conn.log", '{"ts": 1.5, "proto": "udp"}\nnot json\n'))
            self.assertEqual(parsed, [(1, {"ts": 1.5, "proto": "udp"})])
            self.assertEqual(zeeklog.read(os.path.join(d, "absent.log")), [])


if __name__ == "__main__":
    unittest.main()
