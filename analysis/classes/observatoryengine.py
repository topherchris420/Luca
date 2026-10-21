#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Adds the optional kernel observatory evidence to an analysis.

    Runs only when the capture directory holds observatory output, which
    the frontend writes only if observatory.enabled is true. Otherwise it
    does nothing and Luca's results are unchanged.
"""

import json
import os
import re
import sys

OBSERVATORY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                               "observatory")
if os.path.isdir(OBSERVATORY_DIR) and OBSERVATORY_DIR not in sys.path:
    sys.path.append(OBSERVATORY_DIR)  # appended: Luca derives its root from sys.path[0]

from luca_observatory import correlate, pcapstats, snapshot, zeeklog
from luca_observatory.heuristics import TEMPLATES

LOCALES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "locales")
MAX_ALERTS_PER_ID = 5
FAST_LOG_RE = re.compile(r"^(?P<ts>\d\d/\d\d/\d{4}-\d\d:\d\d:\d\d\.\d+)\s+\[\*\*\]\s+\[\d+:(?P<sid>\d+):\d+\]\s+"
                         r"(?P<msg>.*?)\s+\[\*\*\].*\{(?P<proto>[A-Za-z0-9-]+)\}\s+(?P<src>\S+?):(?P<sport>\d+)"
                         r"\s+->\s+(?P<dst>\S+?):(?P<dport>\d+)\s*$")


def parse_fast_log_line(line):
    """
        :return: dict event with the flow tuple of a Suricata fast.log line, or None.
    """
    import time
    m = FAST_LOG_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = time.mktime(time.strptime(m.group("ts").split(".")[0], "%m/%d/%Y-%H:%M:%S")) + \
            float("0." + m.group("ts").split(".")[1])
    except ValueError:
        ts = None
    return {"ts": ts, "sid": int(m.group("sid")), "msg": m.group("msg"), "proto": m.group("proto").upper(),
            "src": m.group("src").strip("[]"), "sport": int(m.group("sport")),
            "dst": m.group("dst").strip("[]"), "dport": int(m.group("dport")), "raw": line.rstrip("\n")}


def load_templates(lang):
    """
        KNO-xx alert texts in the user's language, falling back to English.
    """
    templates = {k: dict(v) for k, v in TEMPLATES.items()}
    for code in ("en", lang):
        if not re.match("^[a-z]{2,3}$", code or ""):
            continue
        try:
            with open(os.path.join(LOCALES_DIR, "{}.json".format(code)), encoding="utf-8") as f:
                alerts = json.load(f).get("alerts", {})
        except (OSError, ValueError):
            continue
        for key in templates:
            if isinstance(alerts.get(key), dict):
                templates[key].update(alerts[key])
    return templates


class ObservatoryEngine(object):

    def __init__(self, capture_directory, userlang="en", capture_interface=None):
        self.wdir = capture_directory
        self.assets = os.path.join(capture_directory, "assets")
        self.userlang = userlang
        self.capture_interface = capture_interface
        self.summary = None

    def present(self):
        return any(os.path.isfile(os.path.join(self.assets, f))
                   for f in ("observatory.json", "observatory_session.json"))

    def _json(self, name):
        try:
            with open(os.path.join(self.assets, name)) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def run(self, alerts=None, suricata_events=None):
        """
            Correlate and write assets/observatory_summary.json.
            :return: list of KNO-xx alerts in Luca's alert format.
        """
        session = self._json("observatory_session.json") or {}
        snap, snap_problem = None, None
        path = os.path.join(self.assets, "observatory.json")
        if os.path.isfile(path):
            try:
                snap = snapshot.load(path)
            except snapshot.SnapshotError as e:
                snap_problem = str(e)
        if snap_problem:
            session = dict(session, error="collector snapshot unusable: " + snap_problem)

        iface = (snap or {}).get("interface") or {}
        context = pcapstats.Context(iface.get("mac"), iface.get("addresses"))
        capture, capture_error = None, None
        try:
            capture = pcapstats.read(os.path.join(self.wdir, "capture.pcap"), context)
        except pcapstats.PcapError as e:
            capture_error = str(e)

        conn_path = os.path.join(self.assets, "conn.log")
        dns_path = os.path.join(self.assets, "dns.log")
        conns = zeeklog.read(conn_path) if os.path.isfile(conn_path) else None
        if conns is None and capture is not None and capture.packets == 0:
            conns = []  # an empty capture produces no conn.log
        dns = zeeklog.read(dns_path) if os.path.isfile(dns_path) else []

        if suricata_events is not None:
            with open(os.path.join(self.assets, "suricata_events.json"), "w") as f:
                json.dump(suricata_events, f, indent=2)

        self.summary = correlate.correlate(snapshot=snap, session=session, capture=capture,
                                           capture_error=capture_error, conns=conns, dns=dns, alerts=alerts,
                                           suricata=suricata_events, device=self._json("device.json"),
                                           capture_interface=self.capture_interface)
        with open(os.path.join(self.assets, "observatory_summary.json"), "w") as f:
            json.dump(self.summary, f, indent=2)
        return self.alerts()

    def alerts(self):
        templates = load_templates(self.userlang)
        out, per_id = [], {}
        for i, finding in enumerate((self.summary or {}).get("findings") or []):
            per_id[finding["id"]] = per_id.get(finding["id"], 0) + 1
            if per_id[finding["id"]] > MAX_ALERTS_PER_ID:
                continue
            tpl = templates[finding["id"]]
            try:
                title = tpl["title"].format(*finding["title_args"])
                description = tpl["description"].format(*finding["description_args"])
            except (IndexError, KeyError):  # a translation with different placeholders
                title = TEMPLATES[finding["id"]]["title"].format(*finding["title_args"])
                description = TEMPLATES[finding["id"]]["description"].format(*finding["description_args"])
            out.append({"title": title,
                        "description": description,
                        "host": finding.get("host") or "",
                        "level": finding["level"],
                        "id": finding["id"],
                        "provenance": finding["provenance"],
                        "evidence": "observatory_summary.json#/findings/{}".format(i)})
        return out


def observatory_alerts(capture_directory, alerts, userlang="en", capture_interface=None, suricata_events=None):
    """
        :return: list of KNO-xx alerts; empty when the observatory was not used.
    """
    engine = ObservatoryEngine(capture_directory, userlang, capture_interface)
    if not engine.present():
        return []
    try:
        return engine.run(alerts, suricata_events)
    except Exception as e:  # the optional feature must never break the analysis
        sys.stderr.write("observatory analysis failed: {!r}\n".format(e))
        return []
