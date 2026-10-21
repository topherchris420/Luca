#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, jsonify, send_file
from app.decorators import *
from app.utils import read_config
import io
import json
import os
import re
import sys

OBSERVATORY_DIR = os.path.join("/".join(sys.path[0].split("/")[:-2]), "observatory")
if os.path.isdir(OBSERVATORY_DIR) and OBSERVATORY_DIR not in sys.path:
    sys.path.append(OBSERVATORY_DIR)  # appended: Luca derives its root from sys.path[0]

try:
    from luca_observatory import capabilities, client, evidence
    from luca_observatory.config import observatory_config, resolve_interface
except ImportError:  # observatory/ not installed
    client = None

observatory_bp = Blueprint("observatory", __name__)
TOKEN_RE = re.compile(r"^[A-F0-9]{8}$")
EXAMPLE = os.path.join(OBSERVATORY_DIR, "examples", "offline_session_summary.json")
RESULTS_DIR = os.path.join(OBSERVATORY_DIR, "experiments", "results")
BUILD_DIR = os.path.join(OBSERVATORY_DIR, "build")


def not_installed():
    return jsonify({"status": "not_installed",
                    "message": "The observatory/ directory is not installed on this Luca instance."})


def session_dir(token):
    return "/tmp/{}".format(token) if TOKEN_RE.match(token or "") else None


def read_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


@observatory_bp.route("/status", methods=["GET"])
@require_header_token
def status():
    """
        Configuration, service and host compatibility. Host features are a
        prediction unless the service reports a session's attach result.
        :return: status in JSON
    """
    if client is None:
        return not_installed()
    section = read_config(("observatory",))
    settings, problems = observatory_config({"observatory": section})
    iface, iface_problem = resolve_interface(settings, read_config(("network",)))
    res = client.status(section)
    if not isinstance(res.get("capabilities"), dict):
        res["capabilities"] = capabilities.detect(BUILD_DIR)
    res.update({"enabled": settings["enabled"], "settings": settings, "config_problems": problems,
                "configured_interface": iface, "interface_problem": iface_problem})
    return jsonify(res)


@observatory_bp.route("/sessions", methods=["GET"])
@require_header_token
def sessions():
    """
        Capture sessions that carry observatory output.
        :return: list in JSON, newest first
    """
    out = []
    try:
        entries = [d for d in os.listdir("/tmp/") if TOKEN_RE.match(d)]
    except OSError:
        entries = []
    for token in entries:
        assets = os.path.join("/tmp", token, "assets")
        rec = read_json(os.path.join(assets, "observatory_session.json"))
        summary = read_json(os.path.join(assets, "observatory_summary.json"))
        if rec is None and summary is None:
            continue
        out.append({"token": token, "mtime": os.path.getmtime(os.path.join("/tmp", token)),
                    "status": (summary or {}).get("collection", {}).get("status") or (rec or {}).get("status"),
                    "analysed": summary is not None,
                    "coverage": ((summary or {}).get("coverage") or {}).get("assessment"),
                    "counts": (summary or {}).get("counts")})
    return jsonify({"sessions": sorted(out, key=lambda s: -s["mtime"])})


@observatory_bp.route("/session/<token>", methods=["GET"])
@require_header_token
def session(token):
    """
        The correlated summary of one session, with its evidence records.
        :return: summary in JSON
    """
    d = session_dir(token)
    if d is None:
        return jsonify({"status": False, "message": "Bad token provided"})
    summary = read_json(os.path.join(d, "assets", "observatory_summary.json"))
    if summary is None:
        rec = read_json(os.path.join(d, "assets", "observatory_session.json"))
        return jsonify({"status": False, "message": "Not analysed yet", "session": rec})
    return jsonify({"status": True, "summary": summary})


@observatory_bp.route("/export/<token>", methods=["GET"])
@require_get_token
def export(token):
    """
        Evidence bundle (zip) of one session: snapshot, session record,
        summary and a manifest with digests. The pcap is not included.
        :return: zip file
    """
    if client is None:
        return not_installed()
    d = session_dir(token)
    if d is None or not os.path.isdir(d):
        return jsonify({"status": False, "message": "Bad token provided"})
    settings, _ = observatory_config({"observatory": read_config(("observatory",))})
    return send_file(io.BytesIO(evidence.session_bundle(d, settings)), mimetype="application/zip",
                     as_attachment=True, attachment_filename="luca-observatory-{}.zip".format(token))


@observatory_bp.route("/example", methods=["GET"])
@require_header_token
def example():
    """
        The offline example: a summary computed from synthetic fixtures,
        labelled as such. It is never presented as a measurement.
        :return: summary in JSON
    """
    summary = read_json(EXAMPLE)
    if summary is None:
        return jsonify({"status": False, "message": "Offline example not installed"})
    return jsonify({"status": True, "synthetic": True, "summary": summary})


@observatory_bp.route("/experiments", methods=["GET"])
@require_header_token
def experiments():
    """
        Results written by observatory/experiments/run_experiments.py on
        this host. None are shipped with Luca.
        :return: list in JSON
    """
    out = []
    try:
        names = sorted((n for n in os.listdir(RESULTS_DIR) if n.endswith(".json")), reverse=True)
    except OSError:
        names = []
    for name in names[:20]:
        r = read_json(os.path.join(RESULTS_DIR, name))
        if not isinstance(r, dict):
            continue
        out.append({"file": name, "created_at": r.get("created_at"), "environment": r.get("environment"),
                    "experiments": {k: {"verdict": v.get("verdict"), "summary": v.get("summary")}
                                    for k, v in (r.get("experiments") or {}).items() if isinstance(v, dict)}})
    return jsonify({"results": out})
