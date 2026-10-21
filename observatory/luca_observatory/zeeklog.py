#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Minimal reader for Zeek logs (TSV with #fields headers, or JSON lines).
    Records keep their original field values and their line number so that
    correlations can cite the exact evidence they rely on.
"""

import json

INT_TYPES = ("count", "int", "port")
FLOAT_TYPES = ("time", "interval", "double")


def _convert(value, kind, unset, empty):
    if value == unset:
        return None
    if value == empty:
        return [] if kind.startswith(("set", "vector")) else ""
    try:
        if kind in INT_TYPES:
            return int(value)
        if kind in FLOAT_TYPES:
            return float(value)
        if kind == "bool":
            return value == "T"
    except ValueError:
        return value
    return value


def read(path):
    """
        :return: list of (line number, dict record). Missing file -> [].
    """
    records = []
    try:
        f = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return records
    with f:
        sep, unset, empty = "\t", "-", "(empty)"
        fields, types = None, None
        for number, line in enumerate(f, 1):
            line = line.rstrip("\n").rstrip("\r")
            if not line:
                continue
            if line.startswith("{"):
                try:
                    records.append((number, json.loads(line)))
                except ValueError:
                    pass
                continue
            if line.startswith("#"):
                if line.startswith("#separator"):
                    raw = line.split(" ", 1)[1] if " " in line else "\\x09"
                    sep = raw.encode().decode("unicode_escape") if raw.startswith("\\x") else raw
                    continue
                key, _, rest = line[1:].partition(sep)
                if key == "fields":
                    fields = rest.split(sep)
                elif key == "types":
                    types = rest.split(sep)
                elif key == "unset_field":
                    unset = rest
                elif key == "empty_field":
                    empty = rest
                continue
            if not fields:
                continue
            values = line.split(sep)
            kinds = types if types and len(types) == len(fields) else ["string"] * len(fields)
            records.append((number, {k: _convert(v, t, unset, empty)
                                     for k, v, t in zip(fields, values, kinds)}))
    return records
