#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Streaming reader for the capture TShark writes (pcapng by default, or
    classic pcap) that extracts only what the observatory compares against
    the kernel: packet timestamps, directions, IP protocols, flow tuples and
    the capture's own drop statistics (pcapng Interface Statistics Blocks).
    No payload is retained.

    The direction of a captured packet is taken, in order of preference,
    from the pcapng packet flags, the Linux cooked header packet type, the
    access-point interface's MAC address, or the access-point's addresses.
    The method used is reported with the result.
"""

import bisect
import ipaddress
import struct
from array import array

PCAP_MAGIC = {0xa1b2c3d4: 1e-6, 0xa1b23c4d: 1e-9}
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BOM = 0x1A2B3C4D

LINK_ETHERNET, LINK_RAW, LINK_SLL, LINK_SLL2, LINK_IPV4, LINK_IPV6 = 1, 101, 113, 276, 228, 229

ETH_P_IP, ETH_P_IPV6, ETH_P_8021Q, ETH_P_8021AD = 0x0800, 0x86DD, 0x8100, 0x88A8
IPV6_EXT = (0, 43, 60)
IPV6_FRAG = 44
PORT_PROTOS = (6, 17, 132, 136)

DEFAULT_MAX_FLOWS = 200000


class PcapError(ValueError):
    pass


class Context(object):
    """
        What is known about the capture interface, used to orient packets.
        mac: "aa:bb:..." of the access-point interface; addresses: list of
        "addr/prefix" strings as reported by the collector snapshot.
    """

    def __init__(self, mac=None, addresses=None):
        self.mac = bytes.fromhex(mac.replace(":", "")) if mac else None
        self.own = set()
        self.nets = []
        for a in addresses or []:
            try:
                iface = ipaddress.ip_interface(a)
            except ValueError:
                continue
            self.own.add(iface.ip.packed)
            if not iface.ip.is_link_local:
                self.nets.append(iface.network)

    def in_prefix(self, family, packed):
        try:
            ip = ipaddress.ip_address(packed)
        except ValueError:
            return False
        return any(ip.version == n.version and ip in n for n in self.nets)


def _ip_string(packed):
    return str(ipaddress.ip_address(packed))


def parse_l3(data, offset, ethertype):
    """
        :return: dict(family, proto, src, dst, sport, dport, ttl) or None.
    """
    if ethertype == ETH_P_IP and len(data) >= offset + 20:
        vihl = data[offset]
        if vihl >> 4 != 4 or vihl & 0xf < 5:
            return None
        ihl = (vihl & 0xf) * 4
        frag = struct.unpack_from("!H", data, offset + 6)[0]
        proto = data[offset + 9]
        p = {"family": 4, "proto": proto, "ttl": data[offset + 8],
             "src": bytes(data[offset + 12:offset + 16]), "dst": bytes(data[offset + 16:offset + 20]),
             "sport": 0, "dport": 0, "fragment": bool(frag & 0x3fff)}
        l4 = offset + ihl if not frag & 0x1fff else None
    elif ethertype == ETH_P_IPV6 and len(data) >= offset + 40:
        if data[offset] >> 4 != 6:
            return None
        nh = data[offset + 6]
        p = {"family": 6, "ttl": data[offset + 7], "src": bytes(data[offset + 8:offset + 24]),
             "dst": bytes(data[offset + 24:offset + 40]), "sport": 0, "dport": 0, "fragment": False}
        l4 = offset + 40
        for _ in range(4):
            if nh in IPV6_EXT and len(data) >= l4 + 2:
                nh, l4 = data[l4], l4 + (data[l4 + 1] + 1) * 8
            elif nh == IPV6_FRAG and len(data) >= l4 + 8:
                p["fragment"] = True
                later = struct.unpack_from("!H", data, l4 + 2)[0] & 0xfff8
                nh, l4 = data[l4], (None if later else l4 + 8)
                break
            else:
                break
        p["proto"] = nh
    else:
        return None
    if l4 is not None and p["proto"] in PORT_PROTOS and len(data) >= l4 + 4:
        p["sport"], p["dport"] = struct.unpack_from("!HH", data, l4)
    return p


def _link_header(link, data):
    """
        :return: (l3 offset, ethertype, src mac, sll packet type) or None.
    """
    if link == LINK_ETHERNET:
        if len(data) < 14:
            return None
        off, et = 14, struct.unpack_from("!H", data, 12)[0]
        if et in (ETH_P_8021Q, ETH_P_8021AD) and len(data) >= 18:
            off, et = 18, struct.unpack_from("!H", data, 16)[0]
        return off, et, bytes(data[6:12]), None
    if link == LINK_SLL and len(data) >= 16:
        return 16, struct.unpack_from("!H", data, 14)[0], None, struct.unpack_from("!H", data, 0)[0]
    if link == LINK_SLL2 and len(data) >= 20:
        return 20, struct.unpack_from("!H", data, 0)[0], None, data[10]
    if link in (LINK_RAW, LINK_IPV4, LINK_IPV6) and data:
        return 0, ETH_P_IP if data[0] >> 4 == 4 else ETH_P_IPV6, None, None
    return None


class Summary(object):

    def __init__(self, context=None, keep_flows=True, max_flows=DEFAULT_MAX_FLOWS):
        self.context = context or Context()
        self.keep_flows = keep_flows
        self.max_flows = max_flows
        self.format = None
        self.link_types = []
        self.packets = 0
        self.bytes = 0
        self.first = None
        self.last = None
        self.directions = {"tx": 0, "rx": 0, "unknown": 0}
        self.times = {"tx": array("d"), "rx": array("d"), "unknown": array("d")}
        self._sorted = True
        self.methods = {}
        self.non_ip = 0
        self.protocols = {}
        self.flows = {}
        self.flows_not_recorded = 0
        self.interface_stats = []
        self.drop_counts = 0
        self.truncated = False
        self.errors = []

    def _direction(self, flags, mac, pkttype, l3):
        if flags & 0x3 == 1:
            return "tx", "pcapng_flags"  # inbound to the access point
        if flags & 0x3 == 2:
            return "rx", "pcapng_flags"
        if pkttype is not None:
            return ("rx" if pkttype == 4 else "tx"), "sll_packet_type"
        ctx = self.context
        if mac is not None and ctx.mac is not None:
            return ("rx" if mac == ctx.mac else "tx"), "mac"
        if l3 is not None and ctx.nets:
            if l3["src"] in ctx.own:
                return "rx", "ip"
            if ctx.in_prefix(l3["family"], l3["src"]):
                return "tx", "ip"
            if ctx.in_prefix(l3["family"], l3["dst"]):
                return "rx", "ip"
        return "unknown", "none"

    def add(self, ts, link, data, length, flags=0):
        self.packets += 1
        self.bytes += length
        if self.first is None or ts < self.first:
            self.first = ts
        if self.last is None or ts > self.last:
            self.last = ts
        hdr = _link_header(link, data)
        l3 = parse_l3(data, hdr[0], hdr[1]) if hdr else None
        direction, method = self._direction(flags, hdr[2] if hdr else None,
                                            hdr[3] if hdr else None, l3)
        self.directions[direction] += 1
        times = self.times[direction]
        if times and ts < times[-1]:
            self._sorted = False
        times.append(ts)
        self.methods[method] = self.methods.get(method, 0) + 1
        if l3 is None:
            self.non_ip += 1
            return
        pkey = (direction, l3["proto"])
        self.protocols[pkey] = self.protocols.get(pkey, 0) + 1
        if not self.keep_flows or direction == "unknown":
            return
        if direction == "tx":
            key = (l3["family"], l3["proto"], l3["src"], l3["sport"], l3["dst"], l3["dport"])
        else:
            key = (l3["family"], l3["proto"], l3["dst"], l3["dport"], l3["src"], l3["sport"])
        f = self.flows.get(key)
        if f is None:
            if len(self.flows) >= self.max_flows:
                self.flows_not_recorded += 1
                return
            f = self.flows[key] = {"tx": [0, 0, None, None], "rx": [0, 0, None, None]}
        d = f[direction]
        d[0] += 1
        d[1] += length
        d[2] = ts if d[2] is None or ts < d[2] else d[2]
        d[3] = ts if d[3] is None or ts > d[3] else d[3]

    def count_between(self, direction, start, end):
        """
            :return: int packets of a direction with start < timestamp <= end.
        """
        if not self._sorted:
            for d in self.times:
                self.times[d] = array("d", sorted(self.times[d]))
            self._sorted = True
        t = self.times[direction]
        return bisect.bisect_right(t, end) - bisect.bisect_right(t, start)

    def flow_list(self):
        out = []
        for (family, proto, local, lport, remote, rport), f in self.flows.items():
            out.append({"family": family, "proto": proto, "local": _ip_string(local),
                        "local_port": lport, "remote": _ip_string(remote), "remote_port": rport,
                        "tx": {"packets": f["tx"][0], "bytes": f["tx"][1], "first": f["tx"][2], "last": f["tx"][3]},
                        "rx": {"packets": f["rx"][0], "bytes": f["rx"][1], "first": f["rx"][2], "last": f["rx"][3]}})
        return out

    def as_dict(self, include_flows=False):
        method = max(self.methods, key=self.methods.get) if self.methods else "none"
        d = {"format": self.format, "link_types": self.link_types, "packets": self.packets,
             "bytes": self.bytes, "first": self.first, "last": self.last,
             "directions": dict(self.directions), "direction_method": method,
             "non_ip": self.non_ip,
             "protocols": [{"direction": k[0], "proto": k[1], "packets": v}
                           for k, v in sorted(self.protocols.items())],
             "interface_stats": self.interface_stats, "block_drop_counts": self.drop_counts,
             "truncated": self.truncated, "errors": self.errors,
             "flows_recorded": len(self.flows), "flows_not_recorded": self.flows_not_recorded}
        if include_flows:
            d["flows"] = self.flow_list()
        return d


def _read_pcap(f, head, summary):
    magic_le = struct.unpack("<I", head)[0]
    magic_be = struct.unpack(">I", head)[0]
    if magic_le in PCAP_MAGIC:
        endian, scale = "<", PCAP_MAGIC[magic_le]
    else:
        endian, scale = ">", PCAP_MAGIC[magic_be]
    rest = f.read(20)
    if len(rest) < 20:
        raise PcapError("truncated pcap header")
    link = struct.unpack(endian + "I", rest[16:20])[0] & 0x0fffffff
    summary.format, summary.link_types = "pcap", [link]
    rec = struct.Struct(endian + "IIII")
    while True:
        h = f.read(16)
        if not h:
            return
        if len(h) < 16:
            summary.truncated = True
            return
        sec, frac, incl, orig = rec.unpack(h)
        data = f.read(incl)
        if len(data) < incl:
            summary.truncated = True
            return
        summary.add(sec + frac * scale, link, data, orig)


def _options(body, offset, endian):
    """
        :return: dict option code -> list of raw values.
    """
    opts = {}
    while offset + 4 <= len(body):
        code, length = struct.unpack_from(endian + "HH", body, offset)
        if code == 0:
            break
        opts.setdefault(code, []).append(body[offset + 4:offset + 4 + length])
        offset += 4 + ((length + 3) & ~3)
    return opts


def _tsresol(raw):
    v = raw[0]
    return 2.0 ** -(v & 0x7f) if v & 0x80 else 10.0 ** -v


def _read_pcapng(f, summary):
    summary.format = "pcapng"
    endian = "<"
    interfaces = []
    while True:
        h = f.read(8)
        if not h:
            return
        if len(h) < 8:
            summary.truncated = True
            return
        if struct.unpack_from("<I", h, 0)[0] == PCAPNG_SHB:  # same in both byte orders
            bom = f.read(4)
            if len(bom) < 4:
                summary.truncated = True
                return
            if struct.unpack("<I", bom)[0] == PCAPNG_BOM:
                endian = "<"
            elif struct.unpack(">I", bom)[0] == PCAPNG_BOM:
                endian = ">"
            else:
                raise PcapError("bad pcapng byte-order magic")
            total = struct.unpack_from(endian + "I", h, 4)[0]
            if len(f.read(total - 12)) < total - 12:
                summary.truncated = True
                return
            interfaces = []  # interface ids restart in every section
            continue
        btype, total = struct.unpack_from(endian + "II", h, 0)
        if total < 12 or total % 4:
            summary.errors.append("malformed pcapng block length {}".format(total))
            return
        body = f.read(total - 8)
        if len(body) < total - 8:
            summary.truncated = True
            return
        body = body[:-4]
        if btype == 1:  # Interface Description Block
            link = struct.unpack_from(endian + "H", body, 0)[0]
            opts = _options(body, 8, endian)
            resol = _tsresol(opts[9][0]) if 9 in opts and opts[9][0] else 1e-6
            interfaces.append((link, resol))
            if link not in summary.link_types:
                summary.link_types.append(link)
        elif btype == 6:  # Enhanced Packet Block
            iface, hi, lo, cap, orig = struct.unpack_from(endian + "IIIII", body, 0)
            if iface >= len(interfaces):
                summary.errors.append("packet for undefined interface {}".format(iface))
                continue
            link, resol = interfaces[iface]
            flags = 0
            opts_at = 20 + ((cap + 3) & ~3)
            if opts_at < len(body):
                opts = _options(body, opts_at, endian)
                if 2 in opts and len(opts[2][0]) >= 4:
                    flags = struct.unpack(endian + "I", opts[2][0][:4])[0]
                if 4 in opts and len(opts[4][0]) >= 8:
                    summary.drop_counts += struct.unpack(endian + "Q", opts[4][0][:8])[0]
            summary.add(((hi << 32) | lo) * resol, link, body[20:20 + cap], orig, flags)
        elif btype == 3:  # Simple Packet Block: no timestamp, interface 0
            summary.errors.append("simple packet blocks carry no timestamps; skipped")
        elif btype == 5:  # Interface Statistics Block
            iface = struct.unpack_from(endian + "I", body, 0)[0]
            opts = _options(body, 12, endian)
            stats = {"interface": iface}
            for code, name in ((4, "ifrecv"), (5, "ifdrop"), (6, "filteraccept"),
                               (7, "osdrop"), (8, "usrdeliv")):
                if code in opts and len(opts[code][0]) >= 8:
                    stats[name] = struct.unpack(endian + "Q", opts[code][0][:8])[0]
            summary.interface_stats.append(stats)


def read(path, context=None, keep_flows=True, max_flows=DEFAULT_MAX_FLOWS):
    """
        :return: Summary of the capture file. Raises PcapError when the
                 file is not a capture at all; truncation is reported.
    """
    summary = Summary(context, keep_flows, max_flows)
    try:
        with open(path, "rb") as f:
            head = f.read(4)
            if len(head) < 4:
                raise PcapError("empty capture file")
            if struct.unpack("<I", head)[0] in PCAP_MAGIC or struct.unpack(">I", head)[0] in PCAP_MAGIC:
                _read_pcap(f, head, summary)
            elif struct.unpack("<I", head)[0] == PCAPNG_SHB:
                f.seek(0)
                _read_pcapng(f, summary)
            else:
                raise PcapError("unknown capture format")
    except OSError as e:
        raise PcapError("cannot read {}: {}".format(path, e.strerror))
    except struct.error as e:
        summary.errors.append("malformed record: {}".format(e))
        summary.truncated = True
    return summary
