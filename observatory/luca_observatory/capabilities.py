#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Host capability detection for the observatory. Read-only, works without
    root, and never loads anything into the kernel: it predicts what the
    collector should be able to do. Only the collector's own attach result
    (recorded in its snapshot) proves that it works.

    Usage: python3 -m luca_observatory.capabilities [--json] [--build-dir DIR]
"""

import gzip
import json
import os
import platform
import re
import sys

MIN_KERNEL = (5, 10)
TCX_KERNEL = (6, 6)
DROP_REASON_KERNEL = (5, 17)
CONFIG_OPTIONS = ("CONFIG_BPF_SYSCALL", "CONFIG_NET_CLS_BPF", "CONFIG_NET_SCH_INGRESS",
                  "CONFIG_NET_XGRESS", "CONFIG_BPF_EVENTS", "CONFIG_DEBUG_INFO_BTF")
ARTIFACTS = ("luca-observatory", "luca_observatory.bpf.o", "luca_drops.bpf.o")


def kernel_version(release=None):
    m = re.match(r"(\d+)\.(\d+)", release or platform.release())
    return (int(m.group(1)), int(m.group(2))) if m else None


def kernel_config(release):
    """
        :return: dict option -> "y"/"m"/"n", or None when no config is readable.
    """
    text = None
    try:
        with gzip.open("/proc/config.gz", "rt") as f:
            text = f.read()
    except OSError:
        try:
            with open("/boot/config-{}".format(release)) as f:
                text = f.read()
        except OSError:
            return None
    values = {}
    for opt in CONFIG_OPTIONS:
        m = re.search(r"^{}=(\w)".format(opt), text, re.M)
        values[opt] = m.group(1) if m else "n"
    return values


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def tracepoint_present():
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                if line.endswith((" __tracepoint_kfree_skb\n", " __traceiter_kfree_skb\n")):
                    return True
    except OSError:
        return None
    return False


def detect(build_dir=None):
    """
        :return: dict describing the host and the expected features.
    """
    info = {"platform": sys.platform, "machine": platform.machine(), "kernel": platform.release(),
            "detected_by": "luca_observatory.capabilities (prediction, not an attach test)"}
    if not sys.platform.startswith("linux"):
        info.update({"supported": False, "reason": "the observatory requires Linux",
                     "features": {f: "unavailable" for f in ("classifiers", "tcx", "drop_events", "drop_reasons")}})
        return info

    version = kernel_version(info["kernel"])
    config = kernel_config(info["kernel"])
    btf = os.path.exists("/sys/kernel/btf/vmlinux")
    tracepoint = tracepoint_present()
    lockdown = _read("/sys/kernel/security/lockdown")
    lockdown_mode = re.search(r"\[(\w+)\]", lockdown).group(1) if lockdown and "[" in lockdown else None

    def opt(name):
        return None if config is None else config.get(name) in ("y", "m")

    problems = []
    if version is None or version < MIN_KERNEL:
        problems.append("kernel {} is older than {}.{}".format(info["kernel"], *MIN_KERNEL))
    if opt("CONFIG_BPF_SYSCALL") is False:
        problems.append("CONFIG_BPF_SYSCALL is not set")

    def feature(*conditions):
        if any(c is False for c in conditions):
            return "unavailable"
        return "unknown" if any(c is None for c in conditions) else "expected"

    old_ok = version is not None and version >= MIN_KERNEL
    classic_tc = feature(old_ok, opt("CONFIG_NET_CLS_BPF"), opt("CONFIG_NET_SCH_INGRESS"))
    tcx = feature(version is not None and version >= TCX_KERNEL, opt("CONFIG_NET_XGRESS"))
    drop_events = feature(old_ok, btf, opt("CONFIG_BPF_EVENTS"), tracepoint,
                          lockdown_mode != "confidentiality")
    drop_reasons = feature(drop_events != "unavailable", version is not None and version >= DROP_REASON_KERNEL)
    classifiers = "expected" if "expected" in (classic_tc, tcx) else \
        ("unknown" if "unknown" in (classic_tc, tcx) else "unavailable")

    info.update({
        "supported": not problems,
        "problems": problems,
        "kernel_version": list(version) if version else None,
        "kernel_config": config,
        "btf": btf,
        "kfree_skb_tracepoint": tracepoint,
        "lockdown": lockdown_mode,
        "unprivileged_bpf_disabled": _read("/proc/sys/kernel/unprivileged_bpf_disabled"),
        "features": {"classifiers": classifiers, "tcx": tcx, "classic_tc": classic_tc,
                     "drop_events": drop_events, "drop_reasons": drop_reasons},
        "required_capabilities": ["CAP_BPF", "CAP_NET_ADMIN", "CAP_PERFMON"],
    })
    if build_dir:
        info["artifacts"] = {a: os.path.exists(os.path.join(build_dir, a)) for a in ARTIFACTS}
    return info


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--json", action="store_true")
    p.add_argument("--build-dir")
    args = p.parse_args(argv)
    info = detect(args.build_dir)
    if args.json:
        json.dump(info, sys.stdout, indent=2)
        print()
    else:
        print("kernel {} ({}), supported: {}".format(info["kernel"], info["machine"], info["supported"]))
        for p_ in info.get("problems") or [info.get("reason")]:
            if p_:
                print("  problem: " + p_)
        for k, v in info["features"].items():
            print("  {:<13} {}".format(k, v))
        print("Prediction only; the collector's attach result is authoritative.")
    return 0 if info["supported"] else 1


if __name__ == "__main__":
    sys.exit(main())
