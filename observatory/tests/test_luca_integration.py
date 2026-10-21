#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    The adapter that adds observatory evidence to Luca's analysis
    (analysis/classes/observatoryengine.py), on synthetic sessions.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.append(os.path.join(ROOT, "analysis"))

import fixtures
from classes import observatoryengine
from classes.observatoryengine import ObservatoryEngine, observatory_alerts, parse_fast_log_line

FAST_LOG = ("10/20/2026-14:03:11.123456  [**] [1:2000001:1] WiFi name sent in clear text [**] "
            "[Classification: (null)] [Priority: 3] {TCP} 192.168.100.2:50000 -> 93.184.216.34:443\n")


class FastLogTest(unittest.TestCase):

    def test_ipv4_line(self):
        ev = parse_fast_log_line(FAST_LOG)
        self.assertEqual((ev["sid"], ev["proto"], ev["src"], ev["sport"], ev["dst"], ev["dport"]),
                         (2000001, "TCP", "192.168.100.2", 50000, "93.184.216.34", 443))
        self.assertEqual(ev["msg"], "WiFi name sent in clear text")
        self.assertAlmostEqual(ev["ts"] % 1, 0.123456, places=5)

    def test_ipv6_line(self):
        line = ("10/20/2026-14:03:11.5  [**] [1:9:2] Test [**] [Priority: 1] {UDP} "
                "[2001:db8::2]:5353 -> [2001:db8::99]:53")
        ev = parse_fast_log_line(line)
        self.assertEqual((ev["src"], ev["dst"], ev["dport"]), ("2001:db8::2", "2001:db8::99", 53))

    def test_unparseable_lines(self):
        self.assertIsNone(parse_fast_log_line(""))
        self.assertIsNone(parse_fast_log_line("[**] no tuple here [**]"))


class AdapterTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def read(self, name):
        with open(os.path.join(self.dir, "assets", name)) as f:
            return json.load(f)

    def test_without_observatory_output_nothing_changes(self):
        os.makedirs(os.path.join(self.dir, "assets"))
        self.assertEqual(observatory_alerts(self.dir, {"high": [], "moderate": [], "low": []}), [])
        self.assertEqual(os.listdir(os.path.join(self.dir, "assets")), [])

    def test_alerts_and_summary(self):
        fixtures.write_session(self.dir)
        alerts = observatory_alerts(self.dir, {"high": [], "moderate": [], "low": []}, "en", "wlan0",
                                    [parse_fast_log_line(FAST_LOG)])
        self.assertEqual(sorted(a["id"] for a in alerts), ["KNO-01", "KNO-02", "KNO-03", "KNO-04"])
        for a in alerts:
            self.assertEqual(set(a), {"title", "description", "host", "level", "id", "provenance", "evidence"})
            self.assertNotIn("{}", a["title"] + a["description"])
            self.assertTrue(a["evidence"].startswith("observatory_summary.json#/findings/"))
        kno03 = [a for a in alerts if a["id"] == "KNO-03"][0]
        self.assertEqual(kno03["provenance"], "INFERRED")
        self.assertTrue(kno03["description"].startswith("Inferred, not measured"))
        summary = self.read("observatory_summary.json")
        self.assertEqual(summary["collection"]["status"], "stopped")
        self.assertEqual(self.read("suricata_events.json")[0]["sid"], 2000001)
        self.assertTrue([o for o in summary["observations"] if "Suricata signature" in o["statement"]])

    def test_corrupt_snapshot_is_reported_not_fatal(self):
        paths = fixtures.write_session(self.dir)
        with open(paths["snapshot"], "w") as f:
            f.write("{truncated")
        self.assertEqual(observatory_alerts(self.dir, {}), [])
        summary = self.read("observatory_summary.json")
        missing = [o for o in summary["observations"] if o["category"] == "missing"]
        self.assertTrue(any("snapshot unusable" in o["statement"] for o in missing))

    def test_session_record_without_snapshot(self):
        os.makedirs(os.path.join(self.dir, "assets"))
        with open(os.path.join(self.dir, "assets", "observatory_session.json"), "w") as f:
            json.dump({"status": "unavailable", "error": "collector service is not running"}, f)
        self.assertEqual(observatory_alerts(self.dir, {}), [])
        summary = self.read("observatory_summary.json")
        self.assertIn("collector service is not running", summary["observations"][0]["statement"])

    def test_translation_with_wrong_placeholders_falls_back(self):
        fixtures.write_session(self.dir)
        engine = ObservatoryEngine(self.dir, "en", "wlan0")
        engine.run({})
        saved = observatoryengine.load_templates
        observatoryengine.load_templates = lambda lang: {
            k: {"title": "{} {} {} {} {}", "description": "{}"} for k in saved("en")}
        try:
            alerts = engine.alerts()
        finally:
            observatoryengine.load_templates = saved
        self.assertTrue(alerts)
        self.assertTrue(all("{}" not in a["title"] for a in alerts))

    def test_luca_locale_matches_package_templates(self):
        from luca_observatory.heuristics import TEMPLATES
        with open(os.path.join(ROOT, "analysis", "locales", "en.json"), encoding="utf-8") as f:
            locale = json.load(f)["alerts"]
        for key, tpl in TEMPLATES.items():
            self.assertEqual(locale[key]["title"].count("{}"), tpl["title"].count("{}"), key)
            self.assertEqual(locale[key]["description"].count("{}"), tpl["description"].count("{}"), key)


if __name__ == "__main__":
    unittest.main()
