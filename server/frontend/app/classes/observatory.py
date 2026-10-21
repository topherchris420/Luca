#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Frontend side of the optional kernel observatory: asks the separate
    luca-observatory service to observe a capture session. The frontend
    needs no kernel privilege for this; it only talks to the service's
    local socket. With observatory.enabled unset nothing happens at all.
"""

from app.utils import read_config
import json
import os
import sys

OBSERVATORY_DIR = os.path.join("/".join(sys.path[0].split("/")[:-2]), "observatory")
if os.path.isdir(OBSERVATORY_DIR) and OBSERVATORY_DIR not in sys.path:
    sys.path.append(OBSERVATORY_DIR)  # appended: Luca derives its root from sys.path[0]

try:
    from luca_observatory import client
except ImportError:  # observatory/ not installed: the feature is unavailable
    client = None


def section():
    try:
        return read_config(("observatory",))
    except Exception:
        return None


def start(token):
    """
        :return: dict, the service's answer or why there is none.
    """
    if client is None:
        return {"status": "disabled"}
    return client.start_session(section(), token)


def stop(token, assets_dir, start_response=None):
    if client is None:
        return {"status": "disabled"}
    return client.stop_session(section(), token, assets_dir, start_response)


def summary(token):
    """
        Headline of the correlated summary for the device-owner report:
        status, coverage and counts only, never raw telemetry.
        :return: dict or None when the session has no observatory output.
    """
    path = "/tmp/{}/assets/observatory_summary.json".format(token)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return {"status": (data.get("collection") or {}).get("status"),
            "coverage": (data.get("coverage") or {}).get("assessment"),
            "counts": data.get("counts"),
            "labels": data.get("labels")}
