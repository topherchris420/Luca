#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    The optional "observatory" section of Luca's config.yaml.

    The section may be absent (configurations written before the observatory
    existed); every key has a default and the feature stays disabled unless
    "enabled" is explicitly true. Values may arrive as strings because the
    admin interface writes them that way, so they are coerced and checked;
    an invalid value falls back to its default and is reported as a problem
    rather than breaking Luca.

    Paths that decide what runs with kernel privileges (the collector binary,
    its control socket and spool directory) are deliberately not read from
    config.yaml, which the web administration interface can edit. They are
    fixed below and can only be overridden on the collector service's own
    command line.
"""

import os
import re

SOCKET_PATH = "/run/luca-observatory/control.sock"
SPOOL_DIR = "/var/lib/luca-observatory"
SERVICE_GROUP = "luca-observatory"

SESSION_RE = re.compile(r"^[A-F0-9]{8}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
ATTACH_MODES = ("auto", "tcx", "tc")

DEFAULTS = {
    "enabled": False,
    "allowed_interfaces": [],
    "attach": "auto",
    "drop_reasons": True,
    "btf": "",
    "sample_interval": 1.0,
    "flush_interval": 10.0,
    "max_flows": 65536,
    "max_drops": 4096,
    "max_session_seconds": 7200,
    "retention_days": 7,
    "retention_sessions": 20,
}

# Numeric keys: (type, minimum, maximum).
RANGES = {
    "sample_interval": (float, 0.1, 60.0),
    "flush_interval": (float, 1.0, 300.0),
    "max_flows": (int, 1024, 1048576),
    "max_drops": (int, 256, 65536),
    "max_session_seconds": (int, 60, 86400),
    "retention_days": (int, 0, 365),
    "retention_sessions": (int, 1, 1000),
}

# A custom BTF file is passed to libbpf by the privileged collector, so it
# must live where only root can place files.
BTF_DIRS = ("/sys/kernel/btf/", "/boot/", "/usr/lib/", "/usr/share/luca/observatory/btf/")


def parse_bool(value):
    """
        Coerce YAML booleans and the strings the admin interface writes.
        :return: bool, or None when the value is not a boolean.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "on", "1"):
            return True
        if v in ("false", "no", "off", "0", ""):
            return False
    return None


def parse_list(value):
    """
        Lists may be YAML sequences or "a|b" strings (the admin format).
        :return: list of str, or None when the value is not list-like.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [v.strip() for v in value.split("|") if v.strip()]
    return None


def btf_path_allowed(path):
    """
        :return: str - why the BTF path is refused, or "" when acceptable.
    """
    if not path:
        return ""
    if not os.path.isabs(path) or ".." in path.split("/"):
        return "must be an absolute path without '..'"
    if not path.startswith(BTF_DIRS):
        return "must be under one of " + ", ".join(BTF_DIRS)
    try:
        st = os.stat(path)
    except OSError as e:
        return "cannot be read ({})".format(e.strerror)
    if st.st_uid != 0 or st.st_mode & 0o022:
        return "must be owned by root and not group/world writable"
    return ""


def observatory_config(config):
    """
        Normalise the observatory section of a parsed config.yaml.
        :return: (dict settings, list of problem strings)
    """
    section = (config or {}).get("observatory") if isinstance(config, dict) else None
    settings = dict(DEFAULTS)
    settings["allowed_interfaces"] = []
    problems = []
    if section is None:
        return settings, problems
    if not isinstance(section, dict):
        return settings, ["observatory section is not a mapping; feature disabled"]

    for key, value in section.items():
        if key not in DEFAULTS:
            problems.append("unknown key observatory.{} ignored".format(key))
            continue
        if key in ("enabled", "drop_reasons"):
            b = parse_bool(value)
            if b is None:
                problems.append("observatory.{} must be true or false".format(key))
            else:
                settings[key] = b
        elif key == "allowed_interfaces":
            names = parse_list(value)
            if names is None:
                problems.append("observatory.allowed_interfaces must be a list")
                continue
            for name in names:
                if IFACE_RE.match(name):
                    settings[key].append(name)
                else:
                    problems.append("invalid interface name {!r} ignored".format(name))
        elif key == "attach":
            v = str(value).strip().lower()
            if v in ATTACH_MODES:
                settings[key] = v
            else:
                problems.append("observatory.attach must be one of " + ", ".join(ATTACH_MODES))
        elif key == "btf":
            v = "" if value is None else str(value).strip()
            why = btf_path_allowed(v)
            if why:
                problems.append("observatory.btf {}; ignored".format(why))
            else:
                settings[key] = v
        else:
            kind, low, high = RANGES[key]
            try:
                v = kind(float(value)) if kind is int else kind(value)
            except (TypeError, ValueError):
                problems.append("observatory.{} must be a number".format(key))
                continue
            if not low <= v <= high:
                problems.append("observatory.{} must be between {} and {}".format(key, low, high))
                continue
            settings[key] = v

    if settings["flush_interval"] < settings["sample_interval"]:
        settings["flush_interval"] = settings["sample_interval"]
        problems.append("observatory.flush_interval raised to sample_interval")
    return settings, problems


def resolve_interface(settings, network):
    """
        Choose the interface to observe: Luca's access-point interface
        (network.in), and only if the allowlist permits it. The uplink
        (network.out) carries traffic of other hosts and is refused unless
        it is listed explicitly.
        :return: (str interface or None, str problem or "")
    """
    network = network if isinstance(network, dict) else {}
    iface = str(network.get("in") or "").strip()
    uplink = str(network.get("out") or "").strip()
    if not iface or not IFACE_RE.match(iface):
        return None, "network.in is not a valid interface name"
    allowed = settings.get("allowed_interfaces") or []
    if allowed and iface not in allowed:
        return None, "interface {} is not in observatory.allowed_interfaces".format(iface)
    if iface == uplink and iface not in allowed:
        return None, "interface {} is the uplink (network.out); list it explicitly to observe it".format(iface)
    return iface, ""


def valid_session(token):
    return isinstance(token, str) and bool(SESSION_RE.match(token))
