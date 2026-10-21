#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Known traffic for the observatory smoke test (tests/netns_smoke.py) and
    the experiments. "serve" runs on the remote network; "client", "bulk",
    "rtt" and "scenario" run on the device. Only the standard library is
    used; raw sockets need root.
"""

import argparse
import json
import socket
import struct
import sys
import threading
import time

SCENARIOS = ("benign", "icmp", "tunnel", "forwarded", "spoof", "twostacks", "udpflows", "echo", "drops")


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total & 0xffff


def listener(bind, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.listen(64)
    return s


def accept_loop(sock, handler):
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def serve(args):
    tcp = listener(args.bind, args.tcp_port)
    bulk = listener(args.bind, args.tcp_port + 1)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((args.bind, args.udp_port))

    def udp_echo():
        while True:
            data, peer = udp.recvfrom(4096)
            udp.sendto(data, peer)

    def respond(conn):
        with conn:
            try:
                conn.recv(1024)
                conn.sendall(b"x" * args.payload)
            except OSError:
                pass

    def stream(conn):
        chunk = b"x" * 65536
        with conn:
            try:
                while True:
                    conn.sendall(chunk)
            except OSError:
                pass

    threading.Thread(target=udp_echo, daemon=True).start()
    threading.Thread(target=accept_loop, args=(bulk, stream), daemon=True).start()
    if args.ready:
        open(args.ready, "w").close()
    accept_loop(tcp, respond)


def tcp_exchange(server, port, ttl=None):
    """
        :return: int bytes received in one request/response connection.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if ttl:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    s.settimeout(5)
    received = 0
    with s:
        s.connect((server, port))
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            received += len(chunk)
    return received


def udp_echo(server, port, count, source=None, gap=0.0):
    """
        :return: list of round-trip times in microseconds (None when lost).
    """
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if source:
        u.bind((source, 0))
    u.settimeout(1)
    rtts = []
    with u:
        for i in range(count):
            t0 = time.perf_counter()
            u.sendto(b"luca-%d" % i, (server, port))
            try:
                u.recvfrom(4096)
                rtts.append((time.perf_counter() - t0) * 1e6)
            except socket.timeout:
                rtts.append(None)
            if gap:
                time.sleep(gap)
    return rtts


def icmp_echo(server, count):
    icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    with icmp:
        for seq in range(1, count + 1):
            payload = b"luca-observatory"
            header = struct.pack("!BBHHH", 8, 0, 0, 0x4c55, seq)
            header = struct.pack("!BBHHH", 8, 0, checksum(header + payload), 0x4c55, seq)
            icmp.sendto(header + payload, (server, 0))
            time.sleep(0.01)


def esp_packets(server, count):
    esp = socket.socket(socket.AF_INET, socket.SOCK_RAW, 50)
    with esp:
        for seq in range(1, count + 1):
            esp.sendto(struct.pack("!II", 0x4c55, seq) + b"\0" * 24, (server, 0))


def bulk(args):
    """
        Receives the server's stream for --seconds and reports throughput.
    """
    s = socket.create_connection((args.server, args.tcp_port + 1), timeout=5)
    received = 0
    t0 = time.perf_counter()
    end = t0 + args.seconds
    with s:
        while time.perf_counter() < end:
            chunk = s.recv(1 << 20)
            if not chunk:
                break
            received += len(chunk)
    elapsed = time.perf_counter() - t0
    json.dump({"bytes": received, "seconds": elapsed, "mbit_per_s": received * 8 / elapsed / 1e6}, sys.stdout)
    print()


def rtt(args):
    samples = udp_echo(args.server, args.udp_port, args.count)
    got = sorted(x for x in samples if x is not None)

    def pick(q):
        return got[min(len(got) - 1, int(q * len(got)))] if got else None
    json.dump({"count": args.count, "lost": samples.count(None), "median_us": pick(0.5), "p90_us": pick(0.9),
               "p99_us": pick(0.99)}, sys.stdout)
    print()


def scenario(args):
    """
        Labeled traffic for experiments D and E. The labeled anomaly
        scenarios start with the same benign baseline (TCP and UDP with the
        device's own TTL), then add what their label names.
    """
    done = {"scenario": args.name}
    if args.name not in ("udpflows", "echo", "drops"):
        done["tcp_bytes"] = sum(tcp_exchange(args.server, args.tcp_port) for _ in range(5))
        done["udp_echoed"] = sum(x is not None for x in udp_echo(args.server, args.udp_port, 10))
    if args.name == "benign":
        # ICMP to the access point itself is local, not remote, traffic.
        icmp_echo(args.router, 3)
    elif args.name == "icmp":
        icmp_echo(args.server, 3)
    elif args.name == "tunnel":
        esp_packets(args.server, 5)
    elif args.name == "forwarded":
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 63)
        for _ in range(3):
            t.sendto(b"ttl", (args.server, args.udp_port + 1))
        t.close()
    elif args.name == "spoof":
        f = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        f.bind((args.foreign_source, 0))
        f.sendto(b"src", (args.server, args.udp_port + 2))
        f.close()
    elif args.name == "twostacks":
        done["tcp_bytes_ttl128"] = sum(tcp_exchange(args.server, args.tcp_port, ttl=128) for _ in range(3))
    elif args.name == "udpflows":
        # Many distinct flows, to fill a small flow table.
        socks = []
        for _ in range(args.count):
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.sendto(b"flow", (args.server, args.udp_port))
            socks.append(u)
        for u in socks:
            u.close()
        done["flows"] = args.count
    elif args.name == "echo":
        rtts = udp_echo(args.server, args.udp_port, args.count, gap=args.gap)
        done["udp_echoed"] = sum(x is not None for x in rtts)
        done["udp_sent"] = args.count
    elif args.name == "drops":
        # Distinct closed ports on the access point: one drop key each.
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(args.count):
            c.sendto(b"drop", (args.router, 20000 + i))
        c.close()
        done["drop_ports"] = args.count
    time.sleep(0.5)
    json.dump(done, sys.stdout)
    print()


def client(args):
    done = {}

    # TCP exchanges with complete handshakes and a sizeable response.
    received = 0
    for _ in range(args.tcp_conns):
        with socket.create_connection((args.server, args.tcp_port), timeout=5) as s:
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                received += len(chunk)
    done["tcp_bytes_received"] = received

    # UDP request/response pairs.
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    echoed = 0
    for i in range(args.udp_count):
        u.sendto(b"luca-%d" % i, (args.server, args.udp_port))
        try:
            u.recvfrom(4096)
            echoed += 1
        except socket.timeout:
            pass
    done["udp_echoed"] = echoed

    # A datagram that looks like it crossed one more router (TTL 63).
    t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 63)
    t.sendto(b"ttl", (args.server, args.udp_port + 1))

    # A datagram from an address the access point never assigned.
    f = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    f.bind((args.foreign_source, 0))
    f.sendto(b"src", (args.server, args.udp_port + 2))

    # IPsec ESP (IP protocol 50), which a "tcp or udp" capture excludes.
    esp = socket.socket(socket.AF_INET, socket.SOCK_RAW, 50)
    for seq in range(1, 4):
        esp.sendto(struct.pack("!II", 0x4c55, seq) + b"\0" * 24, (args.server, 0))

    # ICMP echo to the remote host.
    icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    for seq in range(1, 4):
        header = struct.pack("!BBHHH", 8, 0, 0, 0x4c55, seq)
        payload = b"luca-observatory"
        header = struct.pack("!BBHHH", 8, 0, checksum(header + payload), 0x4c55, seq)
        icmp.sendto(header + payload, (args.server, 0))

    # Closed ports on the router: the kernel frees these with NO_SOCKET.
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(args.drop_count):
        c.sendto(b"drop", (args.router, args.closed_port))
    try:
        socket.create_connection((args.router, args.closed_port), timeout=2).close()
    except OSError:
        pass

    # IPv6 to the router's closed port: exercises the IPv6 parsing path.
    if args.router6:
        c6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        for _ in range(args.drop_count):
            c6.sendto(b"drop6", (args.router6, args.closed_port))

    time.sleep(1)  # let responses and ICMP errors arrive
    json.dump(done, sys.stdout)
    print()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode")
    s = sub.add_parser("serve")
    s.add_argument("--bind", required=True)
    s.add_argument("--tcp-port", type=int, default=8080)
    s.add_argument("--udp-port", type=int, default=5353)
    s.add_argument("--payload", type=int, default=200000)
    s.add_argument("--ready")
    b = sub.add_parser("bulk")
    b.add_argument("--server", required=True)
    b.add_argument("--tcp-port", type=int, default=8080)
    b.add_argument("--seconds", type=float, default=5)
    r = sub.add_parser("rtt")
    r.add_argument("--server", required=True)
    r.add_argument("--udp-port", type=int, default=5353)
    r.add_argument("--count", type=int, default=2000)
    sc = sub.add_parser("scenario")
    sc.add_argument("name", choices=SCENARIOS)
    sc.add_argument("--server", required=True)
    sc.add_argument("--router", required=True)
    sc.add_argument("--foreign-source", default="10.99.0.5")
    sc.add_argument("--tcp-port", type=int, default=8080)
    sc.add_argument("--udp-port", type=int, default=5353)
    sc.add_argument("--count", type=int, default=200)
    sc.add_argument("--gap", type=float, default=0.0, help="seconds between echo round trips")
    c = sub.add_parser("client")
    c.add_argument("--server", required=True)
    c.add_argument("--router", required=True)
    c.add_argument("--router6")
    c.add_argument("--foreign-source", required=True)
    c.add_argument("--tcp-port", type=int, default=8080)
    c.add_argument("--udp-port", type=int, default=5353)
    c.add_argument("--tcp-conns", type=int, default=3)
    c.add_argument("--udp-count", type=int, default=20)
    c.add_argument("--closed-port", type=int, default=9)
    c.add_argument("--drop-count", type=int, default=3)
    args = parser.parse_args()
    if args.mode == "serve":
        serve(args)
    elif args.mode == "client":
        client(args)
    elif args.mode == "bulk":
        bulk(args)
    elif args.mode == "rtt":
        rtt(args)
    elif args.mode == "scenario":
        scenario(args)
    else:
        parser.print_help()
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
