#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Regenerates offline_session_summary.json: a correlated summary computed
    from the SYNTHETIC fixtures in tests/fixtures.py. It exists only to show
    the Kernel Observatory view without a Linux collector. It is not a
    measurement and is labelled synthetic wherever it is displayed.

    Also writes a trimmed copy for the public web demo
    (web-demo/api/observatory_example.json), whose Vercel service cannot
    read files outside web-demo/api.

        python3 observatory/examples/make_offline_example.py
"""

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OBS = os.path.dirname(HERE)
sys.path.insert(0, OBS)
sys.path.insert(0, os.path.join(OBS, "tests"))

import fixtures
from luca_observatory import correlate, pcapstats, zeeklog
from luca_observatory.heuristics import TEMPLATES

DEMO = os.path.join(os.path.dirname(OBS), "web-demo", "api", "observatory_example.json")

NOTE = ("SYNTHETIC OFFLINE EXAMPLE. Computed from invented packets in observatory/tests/fixtures.py; "
        "no kernel, network or device was observed.")


def build():
    alerts = {"high": [{"id": "IOC-01", "host": "93.184.216.34", "level": "High",
                        "title": "Example IOC match", "description": "Synthetic alert for the offline example."}],
              "moderate": [], "low": []}
    with tempfile.TemporaryDirectory() as d:
        paths = fixtures.write_session(d)
        with open(paths["snapshot"]) as f:
            snap = json.load(f)
        cap = pcapstats.read(paths["capture"], pcapstats.Context(fixtures.AP_MAC, fixtures.AP_ADDRESSES))
        conns = zeeklog.read(paths["conn"])
    summary = correlate.correlate(snapshot=snap, session={"status": "stopped", "synthetic": True}, capture=cap,
                                  conns=conns, dns=[], alerts=alerts, device={"ip_address": fixtures.DEVICE},
                                  capture_interface="wlan0")
    summary["synthetic"] = True
    summary["note"] = NOTE
    summary["generated_at"] = fixtures.T0 + 12.0  # fixed, so the file is reproducible
    return summary


def demo(summary):
    """
        :return: dict, the parts of the summary the public demo displays.
    """
    findings = []
    for f in summary["findings"]:
        tpl = TEMPLATES[f["id"]]
        findings.append({"id": f["id"], "provenance": f["provenance"], "level": f["level"], "host": f["host"],
                         "title": tpl["title"].format(*f["title_args"]),
                         "description": tpl["description"].format(*f["description_args"])})
    return {"mode": "demo", "synthetic": True, "note": summary["note"],
            "collection": {k: summary["collection"].get(k) for k in ("status", "attach_mode", "drop_tracepoint")},
            "coverage": {k: (summary["coverage"] or {}).get(k) for k in ("assessment", "explanation")},
            "counts": summary["counts"], "labels": summary["labels"],
            "observations": [{"label": o["label"], "category": o["category"], "statement": o["statement"],
                              "reasons": o["reasons"], "sources": o["sources"], "evidence_items": len(o["evidence"])}
                             for o in summary["observations"]],
            "findings": findings, "unsupported": summary["unsupported"], "limitations": summary["limitations"]}


def write(path, data):
    with open(path, "w", newline="\n") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    print("wrote " + path)


def main():
    summary = build()
    write(os.path.join(HERE, "offline_session_summary.json"), summary)
    if os.path.isdir(os.path.dirname(DEMO)):
        write(DEMO, demo(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
