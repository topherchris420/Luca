#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Collector service, its client and evidence bundles. The service tests
    supervise a fake collector (a Python script), so they exercise process
    handling and the socket protocol without loading any eBPF program.
"""

import io
import json
import os
import socket
import stat
import sys
import tempfile
import textwrap
import threading
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import fixtures
from luca_observatory import client, daemon, evidence

POSIX = hasattr(socket, "AF_UNIX") and os.name == "posix"
LINUX = sys.platform.startswith("linux")
TOKEN = "ABCDEF12"

FAKE_COLLECTOR = textwrap.dedent('''\
    #!{python}
    # Fake collector for tests: honours the real collector's file contract.
    import json, signal, sys, time
    args = sys.argv[1:]
    opt = lambda name: args[args.index(name) + 1] if name in args else None
    out, ready, mode = opt("--output"), opt("--ready-file"), opt("--attach")
    def snap(status):
        with open(out, "w") as f:
            json.dump({{"schema": "luca.observatory/1", "status": status, "synthetic": True,
                        "attach": {{"mode": "tcx" if mode == "auto" else mode, "drop_tracepoint": "attached"}}}}, f)
    if "--fake-fail" in args:
        snap("failed")
        print("loading BPF programs failed: Operation not permitted")
        sys.exit(2)
    def stop(sig, frame):
        snap("stopped")
        sys.exit(0)
    signal.signal(signal.SIGTERM, signal.SIG_IGN if "--fake-hang" in args else stop)
    snap("running")
    with open(ready, "w") as f:
        f.write("tcx\\n")
    if "--fake-crash" in args:
        time.sleep(0.2)
        sys.exit(3)
    while True:
        time.sleep(0.05)
''')


def settings_doc(enabled=True, interface="wlan0", **overrides):
    s = {"enabled": enabled, "attach": "auto", "drop_reasons": True, "btf": "", "sample_interval": 1.0,
         "flush_interval": 10.0, "max_flows": 65536, "max_drops": 4096, "max_session_seconds": 7200,
         "retention_days": 7, "retention_sessions": 20, "allowed_interfaces": []}
    s.update(overrides)
    return {"settings": s, "problems": [], "interface": interface, "interface_problem": ""}


class ClientWithoutServiceTest(unittest.TestCase):
    """
        Behaviour when the service is absent, on every platform.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sock = os.path.join(self.tmp.name, "absent.sock")

    def tearDown(self):
        self.tmp.cleanup()

    def test_disabled_writes_nothing(self):
        self.assertEqual(client.start_session(None, TOKEN), {"status": "disabled"})
        self.assertEqual(client.stop_session({"enabled": False}, TOKEN, self.tmp.name)["status"], "disabled")
        self.assertEqual(os.listdir(self.tmp.name), [])
        self.assertEqual(client.status({})["status"], "disabled")

    def test_unavailable_service_is_recorded(self):
        section = {"enabled": True}
        start = client.start_session(section, TOKEN, socket_path=self.sock)
        self.assertEqual(start["status"], "unavailable")
        rec = client.stop_session(section, TOKEN, self.tmp.name, start, socket_path=self.sock)
        self.assertEqual(rec["status"], "unavailable")
        with open(os.path.join(self.tmp.name, "observatory_session.json")) as f:
            self.assertEqual(json.load(f)["error"], rec["error"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "observatory.json")))
        self.assertEqual(client.status(section, socket_path=self.sock)["status"], "unavailable")

    def test_invalid_token_refused_without_contacting_the_service(self):
        self.assertEqual(client.start_session({"enabled": "true"}, "../../x")["status"], "refused")


@unittest.skipUnless(POSIX, "needs Unix domain sockets")
class ClientProtocolTest(unittest.TestCase):

    def serve_once(self, response):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "s.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(1)
        got = {}

        def run():
            conn, _ = srv.accept()
            with conn:
                data = b""
                while not data.endswith(b"\n"):
                    data += conn.recv(1024)
                got["request"] = json.loads(data.decode())
                conn.sendall(response)
            srv.close()
        t = threading.Thread(target=run, daemon=True)
        t.start()
        return path, got, t

    def test_request_and_response(self):
        path, got, t = self.serve_once(b'{"ok": true, "status": "running"}\n')
        self.assertEqual(client.request("start", TOKEN, path)["status"], "running")
        t.join(2)
        self.assertEqual(got["request"], {"op": "start", "session": TOKEN})

    def test_malformed_response(self):
        path, _, t = self.serve_once(b"[1, 2]\n")
        with self.assertRaises(client.Unavailable):
            client.request("status", socket_path=path)
        t.join(2)

    def test_stop_copies_the_snapshot(self):
        tmp = tempfile.mkdtemp()
        snap = os.path.join(tmp, "spool.json")
        with open(snap, "w") as f:
            json.dump(fixtures.snapshot(), f)
        resp = {"ok": True, "status": "stopped", "snapshot": snap,
                "record": {"crashed": False, "exit_code": 0, "interface": "wlan0", "notes": []}}
        path, _, t = self.serve_once(json.dumps(resp).encode() + b"\n")
        assets = os.path.join(tmp, "assets")
        os.mkdir(assets)
        rec = client.stop_session({"enabled": True}, TOKEN, assets, {"status": "running"}, socket_path=path)
        t.join(2)
        self.assertTrue(rec["snapshot_copied"])
        self.assertEqual(rec["exit_code"], 0)
        with open(os.path.join(assets, "observatory.json")) as f:
            self.assertEqual(json.load(f)["session"], "ABCDEF12")


@unittest.skipUnless(LINUX, "the service supervises Linux processes and checks SO_PEERCRED")
class ServiceTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.collector = os.path.join(self.tmp.name, "luca-observatory")
        with open(self.collector, "w") as f:
            f.write(FAKE_COLLECTOR.format(python=sys.executable))
        os.chmod(self.collector, stat.S_IRWXU)
        self.spool = os.path.join(self.tmp.name, "spool")
        os.makedirs(os.path.join(self.spool, "sessions"))

    def tearDown(self):
        self.tmp.cleanup()

    def service(self, extra=None, **kw):
        return daemon.Service(settings_doc(**kw), os.path.join(self.tmp.name, "s.sock"), self.spool,
                              self.collector, self.tmp.name, extra)

    def test_start_and_stop(self):
        svc = self.service()
        resp = svc.op_start({"session": TOKEN})
        self.assertEqual((resp["status"], resp["attach_mode"]), ("running", "tcx"))
        args = resp["record"]["collector"]["args"]
        self.assertEqual(args[args.index("--iface") + 1], "wlan0")
        self.assertTrue(resp["record"]["collector"]["sha256"])
        stop = svc.op_stop({"session": TOKEN})
        self.assertTrue(stop["ok"])
        self.assertEqual(stop["record"]["status"], "stopped")
        self.assertFalse(stop["record"]["crashed"])
        with open(stop["snapshot"]) as f:
            self.assertEqual(json.load(f)["status"], "stopped")
        with open(os.path.join(self.spool, "sessions", TOKEN, "session.json")) as f:
            self.assertEqual(json.load(f)["exit_code"], 0)
        # Stopping again reports the finished session instead of failing.
        self.assertEqual(svc.op_stop({"session": TOKEN})["status"], "stopped")

    def test_refusals(self):
        self.assertEqual(self.service(enabled=False).op_start({"session": TOKEN})["status"], "disabled")
        self.assertEqual(self.service(interface=None).op_start({"session": TOKEN})["status"], "refused")
        self.assertEqual(self.service().op_start({"session": "../etc"})["status"], "refused")
        self.assertEqual(self.service().op_stop({"session": TOKEN})["status"], "unknown_session")
        os.chmod(self.collector, 0o600)
        self.assertEqual(self.service().op_start({"session": TOKEN})["status"], "failed")

    def test_load_failure_is_reported(self):
        resp = self.service(["--fake-fail"]).op_start({"session": TOKEN})
        self.assertEqual(resp["status"], "failed")
        self.assertEqual(resp["record"]["exit_code"], 2)
        self.assertIn("Operation not permitted", resp["error"])

    def test_crash_is_detected(self):
        svc = self.service(["--fake-crash"])
        self.assertEqual(svc.op_start({"session": TOKEN})["status"], "running")
        svc.current.proc.wait(5)
        svc.tick()
        rec = svc.op_stop({"session": TOKEN})["record"]
        self.assertTrue(rec["crashed"])
        self.assertEqual(rec["status"], "crashed")
        self.assertEqual(rec["exit_code"], 3)

    def test_hung_collector_is_killed(self):
        daemon.STOP_TIMEOUT, saved = 0.5, daemon.STOP_TIMEOUT
        try:
            svc = self.service(["--fake-hang"])
            svc.op_start({"session": TOKEN})
            rec = svc.op_stop({"session": TOKEN})["record"]
        finally:
            daemon.STOP_TIMEOUT = saved
        self.assertTrue(rec["crashed"])
        self.assertTrue(any("killed" in n for n in rec["notes"]))

    def test_new_session_supersedes(self):
        svc = self.service()
        svc.op_start({"session": TOKEN})
        svc.op_start({"session": "12345678"})
        self.assertEqual(svc.current.token, "12345678")
        self.assertEqual(svc.last.record["status"], "stopped")
        svc.op_stop({"session": "12345678"})

    def test_retention(self):
        svc = self.service(retention_sessions=2, retention_days=0)
        for i, token in enumerate(("AAAAAAA1", "AAAAAAA2", "AAAAAAA3")):
            d = os.path.join(self.spool, "sessions", token)
            os.mkdir(d)
            os.utime(d, (1000 + i, 1000 + i))
        os.mkdir(os.path.join(self.spool, "sessions", "not-a-session"))
        svc.apply_retention()
        self.assertEqual(sorted(os.listdir(os.path.join(self.spool, "sessions"))),
                         ["AAAAAAA2", "AAAAAAA3", "not-a-session"])

    def test_socket_protocol(self):
        svc = self.service()
        for raw, status in ((b'{"op": "status"}\n', "available"), (b"garbage\n", "bad_request"),
                            (b'{"op": "rm -rf"}\n', "bad_request"), (b"x" * 5000, "bad_request")):
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            with a, b:
                a.sendall(raw)
                if not raw.endswith(b"\n"):
                    a.shutdown(socket.SHUT_WR)
                svc.handle(b)
                self.assertEqual(json.loads(a.recv(1 << 20).decode())["status"], status, raw[:20])


class EvidenceTest(unittest.TestCase):

    def test_manifest_contents(self):
        snap = fixtures.snapshot()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "observatory.json")
            with open(path, "w") as f:
                json.dump(snap, f)
            m = evidence.manifest(snap, {"enabled": True}, {"snapshot": path}, ["a limitation"])
            self.assertEqual(m["schema"], "luca.observatory.manifest/1")
            self.assertEqual(m["collector"]["commit"], "synthetic")
            self.assertEqual(m["session"]["duration_s"], 10.0)
            self.assertEqual(m["event_loss"]["flows_not_recorded"], 0)
            self.assertEqual(m["evidence"]["snapshot"]["sha256"], evidence.file_digest(path))
            self.assertIn("features", m["kernel"])
            self.assertEqual(m["limitations"], ["a limitation"])

    def test_bundle_excludes_the_capture(self):
        with tempfile.TemporaryDirectory() as d:
            fixtures.write_session(d)
            data = evidence.session_bundle(d)
            digest = evidence.file_digest(os.path.join(d, "capture.pcap"))
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            m = json.loads(z.read("manifest.json").decode())
        self.assertIn("assets/observatory.json", names)
        self.assertNotIn("capture.pcap", names)
        self.assertEqual(m["capture_pcap_sha256"], digest)
        self.assertEqual(m["evidence"]["assets/observatory.json"]["path"].replace("\\", "/"),
                         "assets/observatory.json")


if __name__ == "__main__":
    unittest.main()
