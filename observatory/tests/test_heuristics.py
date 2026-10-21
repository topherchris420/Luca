#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import fixtures
from luca_observatory import INFERRED, OBSERVED, heuristics

ADDRESSES = fixtures.AP_ADDRESSES


def flow(proto, local, remote, lport=0, rport=0, tx=1, rx=0, ttl=64, obs="obs-1"):
    return {"proto": proto, "local": local, "local_port": lport, "remote": remote, "remote_port": rport,
            "tx": {"packets": tx, "ttl_max": ttl if tx else None}, "rx": {"packets": rx}, "obs_id": obs}


def ids(findings):
    return sorted(f["id"] for f in findings)


class HeuristicsTest(unittest.TestCase):

    def test_fixture_scenario(self):
        flows = [dict(f, obs_id="obs-x") for f in
                 __import__("luca_observatory.correlate", fromlist=["x"]).Correlator(
                     snapshot=fixtures.snapshot()).kflows]
        found = heuristics.run(flows, ADDRESSES)
        self.assertEqual(ids(found), ["KNO-01", "KNO-02", "KNO-03", "KNO-04"])
        by_id = {f["id"]: f for f in found}
        self.assertEqual(by_id["KNO-01"]["host"], "8.8.8.8")
        self.assertEqual(by_id["KNO-01"]["facts"]["packets"], 6)
        self.assertEqual(by_id["KNO-02"]["facts"]["protocol"], "ESP")
        self.assertEqual(by_id["KNO-03"]["provenance"], INFERRED)
        self.assertEqual(by_id["KNO-03"]["facts"]["observed_ttls"], [63])
        self.assertEqual(by_id["KNO-04"]["host"], "10.99.0.5")
        for f in found:
            self.assertTrue(f["basis"], f)

    def test_local_and_multicast_traffic_is_ignored(self):
        flows = [flow(1, fixtures.DEVICE, "192.168.100.1"),            # ping the access point
                 flow(58, "fe80::2", "ff02::2"),                          # router solicitation
                 flow(17, fixtures.DEVICE, "224.0.0.251", 5353, 5353, ttl=255),  # mDNS
                 flow(17, "0.0.0.0", "255.255.255.255", 68, 67),        # DHCP discover
                 flow(17, fixtures.DEVICE, "192.168.100.255", 137, 137),  # subnet broadcast
                 flow(2, fixtures.DEVICE, "224.0.0.22"),                 # IGMP
                 flow(6, fixtures.DEVICE, "93.184.216.34", 50000, 443, tx=20)]
        self.assertEqual(heuristics.run(flows, ADDRESSES), [])

    def test_ttl_families(self):
        flows = [flow(6, fixtures.DEVICE, "93.184.216.34", 50000 + i, 443, tx=10) for i in range(5)]
        flows += [flow(6, fixtures.DEVICE, "198.51.100.1", 51000 + i, 443, tx=2, ttl=128) for i in range(2)]
        found = heuristics.run(flows, ADDRESSES)
        self.assertEqual(ids(found), ["KNO-05"])
        self.assertEqual(found[0]["provenance"], INFERRED)
        self.assertEqual(found[0]["facts"]["ttl_families"], [64, 128])

    def test_device_behind_its_own_router(self):
        # Every flow arrives with TTL 63: that is the baseline, not an anomaly.
        flows = [flow(6, fixtures.DEVICE, "93.184.216.34", 50000 + i, 443, tx=5, ttl=63) for i in range(3)]
        self.assertEqual(heuristics.run(flows, ADDRESSES), [])

    def test_foreign_source_needs_a_prefix_of_that_family(self):
        # The access point has no global IPv6 prefix, so IPv6 sources cannot be judged.
        flows = [flow(17, "2001:db8::5", "2001:db8:1::1", 1000, 53)]
        self.assertEqual(heuristics.run(flows, ADDRESSES), [])
        flows = [flow(17, "10.0.0.9", "1.1.1.1", 1000, 53)]
        found = heuristics.run(flows, ADDRESSES)
        self.assertEqual(ids(found), ["KNO-04"])
        self.assertEqual(found[0]["provenance"], OBSERVED)

    def test_templates_match_arguments(self):
        flows = [dict(f, obs_id="o") for f in __import__("luca_observatory.correlate", fromlist=["x"]).Correlator(
            snapshot=fixtures.snapshot()).kflows]
        flows += [flow(6, fixtures.DEVICE, "198.51.100.1", 51000 + i, 443, tx=2, ttl=128) for i in range(2)]
        for f in heuristics.run(flows, ADDRESSES):
            tpl = heuristics.TEMPLATES[f["id"]]
            self.assertEqual(tpl["title"].count("{}"), len(f["title_args"]), f["id"])
            self.assertEqual(tpl["description"].count("{}"), len(f["description_args"]), f["id"])


if __name__ == "__main__":
    unittest.main()
