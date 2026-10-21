#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Reproducibility manifests and evidence bundles.

    A manifest names everything a result depends on: the collection
    configuration, the kernel and its features, the collector build, the
    session's timing, its telemetry loss, the evidence files (with SHA-256
    digests) and the stated limitations. Bundles package a session's
    evidence files together with that manifest.
"""

import hashlib
import io
import json
import os
import subprocess
import time
import zipfile

from . import MANIFEST_SCHEMA, VERSION
from . import capabilities
from .snapshot import loss_report

SESSION_FILES = ("assets/observatory.json", "assets/observatory_session.json",
                 "assets/observatory_summary.json", "assets/capinfos.json", "assets/alerts.json")


def file_digest(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def source_commit(root):
    """
        :return: the Luca source revision, from git or the installed VERSION file.
    """
    try:
        out = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=5)
        if out.returncode == 0:
            commit = out.stdout.decode().strip()
            dirty = subprocess.run(["git", "-C", root, "status", "--porcelain", "--untracked-files=no"],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
            return {"commit": commit, "dirty": bool(dirty.stdout.strip()), "source": "git"}
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        with open(os.path.join(root, "VERSION")) as f:
            return {"commit": f.read().strip(), "dirty": None, "source": "VERSION file"}
    except OSError:
        return {"commit": None, "dirty": None, "source": "unknown"}


def manifest(snapshot=None, settings=None, evidence=None, limitations=None, root=None,
             build_dir=None, extra=None):
    """
        :param evidence: dict name -> path of files the result rests on
        :return: dict manifest (schema luca.observatory.manifest/1)
    """
    snap = snapshot or {}
    started, ended = snap.get("started_at"), (snap.get("clock") or {}).get("realtime")
    m = {
        "schema": MANIFEST_SCHEMA,
        "created_at": time.time(),
        "tool": {"name": "luca_observatory", "version": VERSION},
        "source": source_commit(root) if root else None,
        "collector": snap.get("generator"),
        "collection_configuration": {"settings": settings, "limits": snap.get("limits"),
                                     "attach": snap.get("attach"), "interface": snap.get("interface")},
        "kernel": {"snapshot_host": snap.get("host"), "features": capabilities.detect(build_dir)},
        "session": {"id": snap.get("session"), "status": snap.get("status"), "started_at": started,
                    "ended_at": ended, "duration_s": (ended - started) if started and ended else None},
        "event_loss": loss_report(snap) if snap else None,
        "evidence": {name: {"path": path, "sha256": file_digest(path),
                            "bytes": os.path.getsize(path) if path and os.path.exists(path) else None}
                     for name, path in (evidence or {}).items()},
        "limitations": limitations or [],
    }
    if extra:
        m.update(extra)
    return m


def session_bundle(capture_dir, settings=None):
    """
        Zip the observatory evidence of one Luca capture session. The pcap
        itself is not included: it can be large and holds payload.
        :return: bytes of a zip archive
    """
    paths = {name: os.path.join(capture_dir, name) for name in SESSION_FILES
             if os.path.isfile(os.path.join(capture_dir, name))}
    snap = None
    try:
        with open(paths.get("assets/observatory.json", "")) as f:
            snap = json.load(f)
    except (OSError, ValueError):
        pass
    summary_limits = []
    try:
        with open(paths.get("assets/observatory_summary.json", "")) as f:
            summary_limits = json.load(f).get("limitations") or []
    except (OSError, ValueError):
        pass
    m = manifest(snap, settings, paths, summary_limits,
                 extra={"note": "capture.pcap is referenced but not included",
                        "capture_pcap_sha256": file_digest(os.path.join(capture_dir, "capture.pcap"))})
    for entry in m["evidence"].values():
        entry["path"] = os.path.relpath(entry["path"], capture_dir)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, path in paths.items():
            z.write(path, name)
        z.writestr("manifest.json", json.dumps(m, indent=2))
    return buf.getvalue()
