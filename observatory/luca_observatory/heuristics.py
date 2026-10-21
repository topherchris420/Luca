#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Kernel-observation heuristics (KNO-xx).

    Each finding states which part is measured and which part is inferred:
      KNO-01  ICMP with a host outside the local network       OBSERVED
      KNO-02  IP protocol other than TCP/UDP/ICMP (tunnels)     OBSERVED
      KNO-03  TTL / hop limit decremented before the AP         INFERRED
              (traffic forwarded through the device)
      KNO-04  source address outside the access point's prefix  OBSERVED
      KNO-05  two initial TTL families: two network stacks      INFERRED
    KNO-01, -02 and -04 report facts the kernel counted; their level is a
    heuristic rating of how much the fact deserves attention, as for every
    Luca alert. KNO-03 and KNO-05 conclude something that was not measured
    (that another host or stack exists behind the device) and are labelled
    INFERRED accordingly.

    All of them describe traffic the capture filter ("tcp or udp") or the
    capture's vantage point cannot show, which is what makes them new.
"""

import ipaddress

from . import OBSERVED, INFERRED
from .snapshot import proto_name

TTL_FAMILIES = (64, 128, 255)
MAX_EXAMPLES = 20

# English text; the analysis engine substitutes Luca's locale when present.
TEMPLATES = {
    "KNO-01": {
        "title": "ICMP exchanged with {} outside the local network.",
        "description": "The kernel recorded {} ICMP packet(s) between the device and {}. "
                       "Luca's capture filter keeps only TCP and UDP, so this traffic is absent "
                       "from the capture and from the Zeek and Suricata analysis. ICMP is often "
                       "benign (reachability tests, error reports); check whether {} is expected."
    },
    "KNO-02": {
        "title": "{} traffic with {}, invisible to the capture.",
        "description": "The kernel recorded {} packet(s) of {} between the device and {}. "
                       "Protocols other than TCP, UDP and ICMP are typically tunnels or VPNs "
                       "(for example IPsec ESP or GRE). Luca's capture filter excludes them, so "
                       "their content and destinations were not analysed further."
    },
    "KNO-03": {
        "title": "Traffic that appears to be forwarded through the device.",
        "description": "Inferred, not measured: {} flow(s) left the device with a TTL/hop limit {} "
                       "below the device's usual initial value ({}). A decremented TTL normally "
                       "means another host, virtual machine or container sends traffic through "
                       "the device (for example hotspot tethering). Applications can also set "
                       "their own TTL, so this is an indication to verify, not a conclusion."
    },
    "KNO-05": {
        "title": "Two different network stacks appear to send traffic through the device.",
        "description": "Inferred, not measured: the device's flows use initial TTL values from "
                       "different families ({}). Different operating systems choose different "
                       "initial TTLs, so this suggests a second system (virtual machine, "
                       "tethered host) behind the device, or an application setting its own TTL."
    },
    "KNO-04": {
        "title": "Packets from {}, outside the access point's network.",
        "description": "The kernel recorded {} packet(s) arriving from the device with source "
                       "address {}, which is outside the access point's prefixes ({}). This "
                       "happens with forwarding or misconfigured devices and with address "
                       "spoofing; which one cannot be determined at this vantage point."
    },
}


class Network(object):
    """
        The access point's own addresses and on-link prefixes.
    """

    def __init__(self, addresses):
        self.own = set()
        self.nets = []
        for a in addresses or []:
            try:
                iface = ipaddress.ip_interface(a)
            except ValueError:
                continue
            self.own.add(iface.ip)
            if not iface.ip.is_link_local:
                self.nets.append(iface.network)

    def has_prefix(self, version):
        return any(n.version == version for n in self.nets)

    def local(self, ip):
        return ip in self.own or any(ip.version == n.version and ip in n for n in self.nets)

    def remote(self, addr):
        """
            :return: True for unicast addresses beyond the local network.
        """
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_loopback:
            return False
        if ip.version == 4 and (ip == ipaddress.IPv4Address("255.255.255.255") or
                                any(n.version == 4 and ip == n.broadcast_address for n in self.nets)):
            return False
        return not self.local(ip)

    def prefixes(self):
        return ", ".join(str(n) for n in self.nets) or "none"


def _ttl_family(ttl):
    for fam in TTL_FAMILIES:
        if ttl <= fam:
            return fam
    return 255


def _finding(fid, level, provenance, host, title_args, description_args, flows, facts, inference=None):
    return {"id": fid, "level": level, "provenance": provenance, "host": host,
            "title_args": title_args, "description_args": description_args, "basis": [f["obs_id"] for f in flows[:MAX_EXAMPLES] if f.get("obs_id")],
            "facts": facts, "inference": inference}


def icmp_remote(flows, net):
    out = []
    by_remote = {}
    for f in flows:
        if f["proto"] in (1, 58) and net.remote(f["remote"]):
            by_remote.setdefault(f["remote"], []).append(f)
    for remote, fl in sorted(by_remote.items()):
        packets = sum(f["tx"]["packets"] + f["rx"]["packets"] for f in fl)
        out.append(_finding("KNO-01", "Low", OBSERVED, remote, [remote], [packets, remote, remote], fl,
                            {"packets": packets, "tx_packets": sum(f["tx"]["packets"] for f in fl),
                             "rx_packets": sum(f["rx"]["packets"] for f in fl)}))
    return out


def uncommon_protocols(flows, net):
    out = []
    groups = {}
    for f in flows:
        if f["proto"] not in (1, 2, 6, 17, 58) and net.remote(f["remote"]):
            groups.setdefault((f["proto"], f["remote"]), []).append(f)
    for (proto, remote), fl in sorted(groups.items()):
        packets = sum(f["tx"]["packets"] + f["rx"]["packets"] for f in fl)
        name = proto_name(proto)
        out.append(_finding("KNO-02", "Moderate", OBSERVED, remote, [name, remote], [packets, name, remote], fl,
                            {"proto": proto, "protocol": name, "packets": packets}))
    return out


def ttl_anomalies(flows, net):
    """
        Flows the device itself sends carry its initial TTL unchanged (the
        access point is the first hop). Only unicast TCP/UDP to remote hosts
        is considered: multicast and local services use special TTLs.
    """
    sent = [f for f in flows if f["proto"] in (6, 17) and f["tx"]["packets"] and
            f["tx"].get("ttl_max") is not None and net.remote(f["remote"])]
    if not sent:
        return []
    weight = {}
    for f in sent:
        ttl = f["tx"]["ttl_max"]
        fam = _ttl_family(ttl)
        key = (fam, fam - ttl)
        weight[key] = weight.get(key, 0) + f["tx"]["packets"]
    (base_fam, base_hops) = max(weight, key=weight.get)
    out = []

    forwarded = [f for f in sent if _ttl_family(f["tx"]["ttl_max"]) == base_fam and
                 base_fam - f["tx"]["ttl_max"] > base_hops]
    if forwarded:
        hops = sorted({base_fam - f["tx"]["ttl_max"] - base_hops for f in forwarded})
        out.append(_finding("KNO-03", "Low", INFERRED, "", [],
                            [len(forwarded), "/".join(str(h) for h in hops), base_fam - base_hops],
                            forwarded,
                            {"flows": len(forwarded), "baseline_ttl": base_fam - base_hops,
                             "observed_ttls": sorted({f["tx"]["ttl_max"] for f in forwarded})},
                            "another host or stack forwards traffic through the device"))

    families = sorted({_ttl_family(f["tx"]["ttl_max"]) for f in sent})
    other = [f for f in sent if _ttl_family(f["tx"]["ttl_max"]) != base_fam]
    if len(families) > 1 and len(other) >= 2:
        out.append(_finding("KNO-05", "Low", INFERRED, "", [], [", ".join(str(x) for x in families)], other,
                            {"ttl_families": families, "baseline_family": base_fam, "flows": len(other)},
                            "a second network stack sends traffic through the device"))
    return out


def foreign_sources(flows, net):
    out = []
    groups = {}
    for f in flows:
        if not f["tx"]["packets"]:
            continue
        try:
            ip = ipaddress.ip_address(f["local"])
        except ValueError:
            continue
        if ip.is_unspecified or ip.is_link_local or ip.is_multicast or not net.has_prefix(ip.version):
            continue
        if not net.local(ip):
            groups.setdefault(f["local"], []).append(f)
    for local, fl in sorted(groups.items()):
        packets = sum(f["tx"]["packets"] for f in fl)
        out.append(_finding("KNO-04", "Moderate", OBSERVED, local, [local], [packets, local, net.prefixes()], fl,
                            {"source": local, "packets": packets, "prefixes": net.prefixes()}))
    return out


def run(flows, addresses):
    """
        :param flows: normalised kernel flows (see correlate.kernel_flows)
        :param addresses: the access point's "addr/prefix" strings
        :return: list of findings
    """
    net = Network(addresses)
    findings = []
    for check in (icmp_remote, uncommon_protocols, ttl_anomalies, foreign_sources):
        findings += check(flows, net)
    return findings
