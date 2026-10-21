#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Network-namespace test topology for the observatory (Linux, root).

        lcdev                 lcluca (access point)            lcnet
      +---------+ veth  +------------------------------+ veth +---------+
      |  dev0   |-------|  ap0      routing      up0   |------|  net0   |
      +---------+       +------------------------------+      +---------+
      192.168.100.2/24   192.168.100.1/24   198.18.0.1/24     198.18.0.2/24
      fd00:100::2/64     fd00:100::1/64     fd00:198::1/64    fd00:198::2/64

    "dev" plays the inspected device, "luca" the access point running Luca
    and the collector (on ap0, as Luca would on network.in), "net" the
    Internet. ap0 has strict reverse-path filtering so that a spoofed
    source is dropped by the kernel with a known reason. With nat=True the
    access point masquerades traffic leaving through up0.

    This is a virtual topology: veth devices have no radio, no driver
    queues of a Wi-Fi card and different offloads. Results obtained on it
    say nothing about Wi-Fi hardware.
"""

import os
import shutil
import subprocess
import time

DEVICE, DEVICE6 = "192.168.100.2", "fd00:100::2"
AP, AP6 = "192.168.100.1", "fd00:100::1"
UPLINK, UPLINK6 = "198.18.0.1", "fd00:198::1"
SERVER, SERVER6 = "198.18.0.2", "fd00:198::2"
FOREIGN = "10.99.0.5"
AP_PREFIX = "192.168.100.0/24"


class CommandError(Exception):
    pass


def run(args, check=True, **kw):
    kw.setdefault("stdout", subprocess.PIPE)
    kw.setdefault("stderr", subprocess.STDOUT)
    p = subprocess.run(args, **kw)
    if check and p.returncode != 0:
        out = p.stdout.decode("utf-8", "replace") if isinstance(p.stdout, bytes) else (p.stdout or "")
        raise CommandError("{} -> {}: {}".format(" ".join(args), p.returncode, out.strip()))
    return p


def sysctl(ns, key, value):
    run(["ip", "netns", "exec", ns, "sysctl", "-qw", "{}={}".format(key, value)])


class Topology(object):

    def __init__(self, prefix="lc", nat=False, ipv6=True):
        self.dev, self.ap, self.net = prefix + "dev", prefix + "luca", prefix + "net"
        self.nat = nat
        self.ipv6 = ipv6
        self.created = False

    # -- lifecycle

    def __enter__(self):
        self.up()
        return self

    def __exit__(self, *exc):
        self.down()

    def up(self):
        self.down()
        for ns in (self.dev, self.ap, self.net):
            run(["ip", "netns", "add", ns])
        self.created = True
        run(["ip", "link", "add", "dev0", "netns", self.dev, "type", "veth", "peer", "name", "ap0",
             "netns", self.ap])
        run(["ip", "link", "add", "up0", "netns", self.ap, "type", "veth", "peer", "name", "net0",
             "netns", self.net])
        for ns in (self.dev, self.ap, self.net):
            if self.ipv6:
                sysctl(ns, "net.ipv6.conf.all.accept_dad", 0)
                sysctl(ns, "net.ipv6.conf.default.accept_dad", 0)
                sysctl(ns, "net.ipv6.conf.default.accept_ra", 0)
                sysctl(ns, "net.ipv6.conf.default.router_solicitations", 0)
            self.ip(ns, "link", "set", "lo", "up")
        self.ip(self.dev, "addr", "add", DEVICE + "/24", "dev", "dev0")
        self.ip(self.dev, "addr", "add", FOREIGN + "/32", "dev", "dev0")
        self.ip(self.ap, "addr", "add", AP + "/24", "dev", "ap0")
        self.ip(self.ap, "addr", "add", UPLINK + "/24", "dev", "up0")
        self.ip(self.net, "addr", "add", SERVER + "/24", "dev", "net0")
        if self.ipv6:
            self.ip(self.dev, "addr", "add", DEVICE6 + "/64", "dev", "dev0", "nodad")
            self.ip(self.ap, "addr", "add", AP6 + "/64", "dev", "ap0", "nodad")
            self.ip(self.ap, "addr", "add", UPLINK6 + "/64", "dev", "up0", "nodad")
            self.ip(self.net, "addr", "add", SERVER6 + "/64", "dev", "net0", "nodad")
        for ns, ifs in ((self.dev, ["dev0"]), (self.ap, ["ap0", "up0"]), (self.net, ["net0"])):
            for i in ifs:
                self.ip(ns, "link", "set", i, "up")
        self.ip(self.dev, "route", "add", "default", "via", AP, "src", DEVICE)
        self.ip(self.net, "route", "add", "default", "via", UPLINK)
        if self.ipv6:
            self.ip(self.dev, "-6", "route", "add", "default", "via", AP6)
            self.ip(self.net, "-6", "route", "add", "default", "via", UPLINK6)
            sysctl(self.ap, "net.ipv6.conf.all.forwarding", 1)
        sysctl(self.ap, "net.ipv4.ip_forward", 1)
        sysctl(self.ap, "net.ipv4.conf.all.rp_filter", 1)
        sysctl(self.ap, "net.ipv4.conf.ap0.rp_filter", 1)
        if self.nat:
            if not shutil.which("iptables") and not shutil.which("nft"):
                raise CommandError("NAT needs iptables or nft")
            if shutil.which("nft"):
                rules = ("table ip lucanat {\n"
                         "  chain post {\n"
                         "    type nat hook postrouting priority 100;\n"
                         "    oifname \"up0\" masquerade\n"
                         "  }\n"
                         "}\n")
                run(["ip", "netns", "exec", self.ap, "nft", "-f", "-"], input=rules.encode())
            else:
                run(["ip", "netns", "exec", self.ap, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "up0",
                     "-j", "MASQUERADE"])
        # Let neighbour discovery and the initial MLD reports finish before
        # anything is counted.
        self.exec(self.dev, ["ping", "-c", "1", "-W", "2", AP], check=False)
        self.exec(self.net, ["ping", "-c", "1", "-W", "2", UPLINK], check=False)
        time.sleep(2)

    def down(self):
        for ns in (self.dev, self.ap, self.net):
            run(["ip", "netns", "del", ns], check=False)
        self.created = False

    # -- helpers

    def ip(self, ns, *args):
        return run(["ip", "-n", ns] + list(args))

    def cmd(self, ns, args):
        return ["ip", "netns", "exec", ns] + list(args)

    def exec(self, ns, args, check=True, **kw):
        return run(self.cmd(ns, args), check=check, **kw)

    def popen(self, ns, args, **kw):
        return subprocess.Popen(self.cmd(ns, args), **kw)

    def link_stats(self, ns, ifname):
        """
            :return: dict of the interface's kernel statistics.
        """
        out = {}
        for key in ("tx_packets", "rx_packets", "tx_bytes", "rx_bytes", "tx_dropped", "rx_dropped"):
            p = self.exec(ns, ["cat", "/sys/class/net/{}/statistics/{}".format(ifname, key)])
            out[key] = int(p.stdout.decode().strip())
        return out

    def mac(self, ns, ifname):
        p = self.exec(ns, ["cat", "/sys/class/net/{}/address".format(ifname)])
        return p.stdout.decode().strip()

    def tc_filters(self, ifname="ap0"):
        """
            :return: str of the classic tc filters left on ifname (both hooks).
        """
        out = []
        for hook in ("ingress", "egress"):
            p = self.exec(self.ap, ["tc", "filter", "show", "dev", ifname, hook], check=False)
            out.append(p.stdout.decode("utf-8", "replace").strip())
        return "\n".join(o for o in out if o)

    def has_clsact(self, ifname="ap0"):
        p = self.exec(self.ap, ["tc", "qdisc", "show", "dev", ifname], check=False)
        return "clsact" in p.stdout.decode("utf-8", "replace")


def wait_for(path, timeout, proc=None):
    """
        :return: True once path exists; False on timeout or if proc exited.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return True
        if proc is not None and proc.poll() is not None:
            return os.path.exists(path)
        time.sleep(0.05)
    return False


def stop(proc, timeout=15):
    """
        SIGTERM, then SIGKILL. :return: the exit code.
    """
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    return proc.returncode
