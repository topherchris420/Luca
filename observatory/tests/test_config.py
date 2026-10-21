#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from luca_observatory.config import (DEFAULTS, observatory_config, parse_bool, parse_list, resolve_interface,
                                     valid_session, btf_path_allowed)


class ConfigTest(unittest.TestCase):

    def test_missing_section_is_disabled(self):
        settings, problems = observatory_config({"network": {"in": "wlan0"}})
        self.assertFalse(settings["enabled"])
        self.assertEqual(problems, [])
        self.assertEqual(settings["max_flows"], DEFAULTS["max_flows"])

    def test_old_config_without_any_section(self):
        settings, _ = observatory_config(None)
        self.assertFalse(settings["enabled"])

    def test_admin_interface_string_values(self):
        settings, problems = observatory_config({"observatory": {
            "enabled": "true", "drop_reasons": "False", "max_flows": "131072",
            "sample_interval": "0.5", "allowed_interfaces": "wlan0|wlan1"}})
        self.assertEqual(problems, [])
        self.assertTrue(settings["enabled"])
        self.assertFalse(settings["drop_reasons"])
        self.assertEqual(settings["max_flows"], 131072)
        self.assertEqual(settings["sample_interval"], 0.5)
        self.assertEqual(settings["allowed_interfaces"], ["wlan0", "wlan1"])

    def test_invalid_values_fall_back_and_are_reported(self):
        settings, problems = observatory_config({"observatory": {
            "enabled": "maybe", "max_flows": 10, "attach": "xdp", "sample_interval": "fast",
            "allowed_interfaces": ["wlan0", "bad iface;rm"], "colour": "blue"}})
        self.assertFalse(settings["enabled"])
        self.assertEqual(settings["max_flows"], DEFAULTS["max_flows"])
        self.assertEqual(settings["attach"], "auto")
        self.assertEqual(settings["allowed_interfaces"], ["wlan0"])
        self.assertEqual(len(problems), 6)

    def test_section_not_a_mapping(self):
        settings, problems = observatory_config({"observatory": "yes"})
        self.assertFalse(settings["enabled"])
        self.assertEqual(len(problems), 1)

    def test_flush_not_below_sample(self):
        settings, problems = observatory_config({"observatory": {"sample_interval": 5, "flush_interval": 1}})
        self.assertEqual(settings["flush_interval"], 5)
        self.assertTrue(problems)

    def test_defaults_not_shared_between_calls(self):
        a, _ = observatory_config({"observatory": {"allowed_interfaces": ["wlan0"]}})
        b, _ = observatory_config({})
        self.assertEqual(b["allowed_interfaces"], [])
        self.assertEqual(DEFAULTS["allowed_interfaces"], [])

    def test_parse_helpers(self):
        self.assertIsNone(parse_bool("perhaps"))
        self.assertTrue(parse_bool(1))
        self.assertEqual(parse_list(None), [])
        self.assertIsNone(parse_list(3))

    def test_interface_is_network_in(self):
        settings, _ = observatory_config({"observatory": {"enabled": True}})
        self.assertEqual(resolve_interface(settings, {"in": "wlan0", "out": "eth0"}), ("wlan0", ""))

    def test_allowlist_refuses_other_interfaces(self):
        settings, _ = observatory_config({"observatory": {"allowed_interfaces": ["wlan1"]}})
        iface, problem = resolve_interface(settings, {"in": "wlan0", "out": "eth0"})
        self.assertIsNone(iface)
        self.assertIn("allowed_interfaces", problem)

    def test_uplink_needs_explicit_allowlisting(self):
        settings, _ = observatory_config({})
        iface, problem = resolve_interface(settings, {"in": "eth0", "out": "eth0"})
        self.assertIsNone(iface)
        self.assertIn("uplink", problem)
        settings, _ = observatory_config({"observatory": {"allowed_interfaces": ["eth0"]}})
        self.assertEqual(resolve_interface(settings, {"in": "eth0", "out": "eth0"})[0], "eth0")

    def test_invalid_interface_name(self):
        settings, _ = observatory_config({})
        self.assertIsNone(resolve_interface(settings, {"in": "iface_in;reboot"})[0])
        self.assertIsNone(resolve_interface(settings, None)[0])

    def test_session_tokens(self):
        self.assertTrue(valid_session("ABCDEF12"))
        for bad in ("abcdef12", "ABCDEF1", "../ETC/PW", None, 12345678):
            self.assertFalse(valid_session(bad))

    def test_btf_path_rules(self):
        self.assertEqual(btf_path_allowed(""), "")
        self.assertIn("absolute", btf_path_allowed("vmlinux"))
        self.assertIn("absolute", btf_path_allowed("/boot/../tmp/x"))
        self.assertIn("under", btf_path_allowed("/tmp/vmlinux"))
        settings, problems = observatory_config({"observatory": {"btf": "/tmp/evil.btf"}})
        self.assertEqual(settings["btf"], "")
        self.assertTrue(problems)


if __name__ == "__main__":
    unittest.main()
