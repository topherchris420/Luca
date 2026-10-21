#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    luca-observatory collector service.

    Runs as the unprivileged system user luca-observatory with only the
    capabilities the collector needs (CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON,
    granted by systemd as ambient capabilities), so neither Luca's web
    applications nor this service need root. It supervises at most one
    collector process at a time, for one Luca capture session, on the one
    interface its settings allow.

      render-settings  (root, before start) turns config.yaml into a small
                       JSON settings file readable by the service user, so
                       the service never reads Luca's credentials;
      serve            answers status/start/stop on a Unix socket.

    The collector binary, socket and spool paths come from this command
    line (the systemd unit), never from config.yaml.
"""

import argparse
import hashlib
import json
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

from . import SESSION_SCHEMA, VERSION
from . import capabilities
from .config import (SERVICE_GROUP, SOCKET_PATH, SPOOL_DIR, observatory_config, resolve_interface,
                     valid_session)

MAX_REQUEST = 4096
READY_TIMEOUT = 4.0
STOP_TIMEOUT = 15.0
TICK = 1.0
RETENTION_EVERY = 3600
LOG_LIMIT = 1 << 20


def log(msg):
    sys.stderr.write("luca-observatory: {}\n".format(msg))
    sys.stderr.flush()


def notify_ready(status=None):
    """
        Tells systemd (Type=notify) that the service is ready, so that
        "systemctl start" returns only once the socket accepts requests.
        Does nothing outside systemd.
        :return: True if systemd was notified
    """
    path = os.environ.get("NOTIFY_SOCKET")
    if not path:
        return False
    if path.startswith("@"):
        path = "\0" + path[1:]  # abstract namespace
    msg = "READY=1" + ("\nSTATUS=" + status if status else "")
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        with s:
            s.sendto(msg.encode(), path)
        return True
    except OSError as e:
        log("cannot notify systemd: {}".format(e))
        return False


def write_json(path, data, mode=0o640):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


# ------------------------------------------------------------ settings

def render_settings(config_path, out_path, group):
    """
        Runs as root. Extracts only the observatory settings and the two
        interface names from config.yaml.
    """
    import yaml  # Luca already depends on PyYAML; the service itself does not
    with open(config_path) as f:
        config = yaml.load(f, Loader=yaml.SafeLoader) or {}
    settings, problems = observatory_config(config)
    network = config.get("network") if isinstance(config.get("network"), dict) else {}
    iface, iface_problem = resolve_interface(settings, network)
    data = {"settings": settings, "problems": problems, "interface": iface,
            "interface_problem": iface_problem, "rendered_at": time.time(), "source": config_path}
    write_json(out_path, data, 0o640)
    try:
        import grp
        os.chown(out_path, 0, grp.getgrnam(group).gr_gid)
    except (ImportError, KeyError, OSError) as e:
        log("could not give group {} access to {}: {}".format(group, out_path, e))
    print("settings written to {} (enabled={}, interface={}{})".format(
        out_path, settings["enabled"], iface, "; " + iface_problem if iface_problem else ""))
    return 0


# ------------------------------------------------------------- service

class Session(object):

    def __init__(self, token, directory):
        self.token = token
        self.dir = directory
        self.snapshot = os.path.join(directory, "observatory.json")
        self.ready = os.path.join(directory, "ready")
        self.logfile = os.path.join(directory, "collector.log")
        self.record_path = os.path.join(directory, "session.json")
        self.proc = None
        self.attach_mode = None
        self.record = {}


class Service(object):

    def __init__(self, settings_doc, socket_path, spool, collector, bpf_dir=None, extra_args=None):
        self.doc = settings_doc
        self.settings = settings_doc.get("settings") or {}
        self.interface = settings_doc.get("interface")
        self.interface_problem = settings_doc.get("interface_problem") or ""
        self.socket_path = socket_path
        self.spool = spool
        self.sessions_dir = os.path.join(spool, "sessions")
        self.collector = collector
        self.bpf_dir = bpf_dir or os.path.dirname(collector)
        self.extra_args = extra_args or []
        self.current = None
        self.last = None
        self.started = time.time()
        self.caps = None
        self.caps_at = 0
        self.last_retention = 0
        self.stopping = False

    # -- helpers

    def capability_report(self):
        if self.caps is None or time.time() - self.caps_at > 60:
            self.caps = capabilities.detect(self.bpf_dir)
            self.caps_at = time.time()
        return self.caps

    def collector_args(self, s):
        st = self.settings
        args = [self.collector, "--iface", self.interface, "--output", s.snapshot, "--session", s.token,
                "--ready-file", s.ready, "--bpf-dir", self.bpf_dir,
                "--attach", st.get("attach", "auto"),
                "--interval", str(st.get("sample_interval", 1.0)),
                "--flush", str(st.get("flush_interval", 10.0)),
                "--max-flows", str(st.get("max_flows", 65536)),
                "--max-drops", str(st.get("max_drops", 4096)),
                "--duration", str(st.get("max_session_seconds", 7200))]
        if not st.get("drop_reasons", True):
            args.append("--no-drops")
        if st.get("btf"):
            args += ["--btf", st["btf"]]
        return args + self.extra_args

    def save_record(self, s):
        try:
            write_json(s.record_path, s.record)
        except OSError as e:
            log("cannot write {}: {}".format(s.record_path, e))

    def snapshot_status(self, s):
        try:
            with open(s.snapshot) as f:
                snap = json.load(f)
            return snap.get("status"), (snap.get("attach") or {})
        except (OSError, ValueError):
            return None, {}

    # -- operations

    def op_status(self, req):
        cur = self.current
        return {"ok": True, "status": "available", "service": {"version": VERSION, "pid": os.getpid(),
                                                               "uptime": time.time() - self.started},
                "enabled": bool(self.settings.get("enabled")), "interface": self.interface,
                "interface_problem": self.interface_problem, "settings_problems": self.doc.get("problems"),
                "settings": {k: self.settings.get(k) for k in ("attach", "drop_reasons", "sample_interval",
                                                                "flush_interval", "max_flows", "max_drops",
                                                                "max_session_seconds", "retention_days",
                                                                "retention_sessions", "allowed_interfaces")},
                "collector": {"path": self.collector, "present": os.access(self.collector, os.X_OK)},
                "capabilities": self.capability_report(),
                "session": cur.record if cur else None,
                "last_session": self.last.record if self.last else None}

    def op_start(self, req):
        token = req.get("session")
        if not valid_session(token):
            return {"ok": False, "status": "refused", "error": "invalid session token"}
        if not self.settings.get("enabled"):
            return {"ok": False, "status": "disabled", "error": "observatory.enabled is false"}
        if not self.interface:
            return {"ok": False, "status": "refused", "error": self.interface_problem or "no interface"}
        if not os.access(self.collector, os.X_OK):
            return {"ok": False, "status": "failed",
                    "error": "collector binary not found at {} (build it with make -C observatory)".format(self.collector)}
        if self.current is not None:
            self.finish(self.current, "superseded by session {}".format(token))

        directory = os.path.join(self.sessions_dir, token)
        if os.path.isdir(directory):
            shutil.rmtree(directory, ignore_errors=True)
        os.makedirs(directory, mode=0o750)
        s = Session(token, directory)
        args = self.collector_args(s)
        s.record = {"schema": SESSION_SCHEMA, "session": token, "interface": self.interface,
                    "requested_at": time.time(), "status": "starting", "crashed": False, "exit_code": None,
                    "collector": {"path": self.collector, "sha256": sha256(self.collector), "args": args},
                    "service_version": VERSION, "notes": []}
        logf = open(s.logfile, "wb")
        try:
            s.proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=logf, stderr=logf,
                                      close_fds=True, start_new_session=True,
                                      env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
        except OSError as e:
            logf.close()
            s.record.update({"status": "failed", "error": "cannot run the collector: {}".format(e)})
            self.save_record(s)
            self.last = s
            return {"ok": False, "status": "failed", "error": s.record["error"], "record": s.record}
        logf.close()
        deadline = time.time() + READY_TIMEOUT
        while time.time() < deadline and s.proc.poll() is None and not os.path.exists(s.ready):
            time.sleep(0.05)
        if os.path.exists(s.ready):
            try:
                with open(s.ready) as f:
                    s.attach_mode = f.read().strip() or None
            except OSError:
                pass
            s.record.update({"status": "running", "started_at": time.time(), "attach_mode": s.attach_mode})
            self.current = s
            self.save_record(s)
            _, attach = self.snapshot_status(s)
            return {"ok": True, "status": "running", "attach_mode": s.attach_mode,
                    "drop_tracepoint": attach.get("drop_tracepoint"), "record": s.record}
        if s.proc.poll() is None:
            # Still loading (slow verifier or BTF parsing): keep supervising it.
            s.record.update({"status": "starting", "started_at": time.time()})
            s.record["notes"].append("collector not ready after {:.0f} s".format(READY_TIMEOUT))
            self.current = s
            self.save_record(s)
            return {"ok": True, "status": "starting", "record": s.record}
        status, attach = self.snapshot_status(s)
        s.record.update({"status": "failed", "exit_code": s.proc.returncode,
                         "error": attach.get("error") or self.log_tail(s) or "collector exited with {}".format(
                             s.proc.returncode)})
        self.save_record(s)
        self.last = s
        return {"ok": False, "status": "failed", "error": s.record["error"], "snapshot": s.snapshot
                if os.path.exists(s.snapshot) else None, "record": s.record}

    def op_stop(self, req):
        token = req.get("session")
        if not valid_session(token):
            return {"ok": False, "status": "refused", "error": "invalid session token"}
        s = self.current
        if s is None or s.token != token:
            if self.last is not None and self.last.token == token:
                s = self.last
                return {"ok": True, "status": s.record.get("status"), "record": s.record,
                        "snapshot": s.snapshot if os.path.exists(s.snapshot) else None}
            return {"ok": False, "status": "unknown_session", "error": "no collector session {}".format(token)}
        self.finish(s, None)
        return {"ok": s.record.get("status") in ("stopped", "interface_lost"), "status": s.record.get("status"),
                "record": s.record, "error": s.record.get("error"),
                "snapshot": s.snapshot if os.path.exists(s.snapshot) else None}

    # -- supervision

    def log_tail(self, s, limit=600):
        try:
            with open(s.logfile, "rb") as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - limit))
                return f.read().decode("utf-8", "replace").strip()
        except OSError:
            return ""

    def finish(self, s, note):
        """
            Stops the collector (SIGTERM, then SIGKILL), cleans up tc
            filters a killed collector cannot remove, and records the result.
        """
        killed = False
        if s.proc is not None and s.proc.poll() is None:
            s.proc.send_signal(signal.SIGTERM)
            try:
                s.proc.wait(STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                s.proc.kill()
                s.proc.wait()
                killed = True
        code = s.proc.returncode if s.proc is not None else None
        status, attach = self.snapshot_status(s)
        crashed = killed or code not in (0, 4) or status not in ("stopped", "interface_lost")
        mode = attach.get("mode") or s.attach_mode
        if crashed and mode == "tc":
            self.detach_legacy(s)
        s.record.update({"stopped_at": time.time(), "exit_code": code, "crashed": crashed,
                         "status": status if not crashed else ("crashed" if status in ("running", None) else status),
                         "snapshot_sha256": sha256(s.snapshot)})
        if attach.get("error"):
            s.record["error"] = attach["error"]
        if killed:
            s.record["notes"].append("collector did not stop within {:.0f} s and was killed".format(STOP_TIMEOUT))
        if crashed and status is None:
            s.record["notes"].append(self.log_tail(s) or "collector left no snapshot")
        if note:
            s.record["notes"].append(note)
        self.save_record(s)
        if self.current is s:
            self.current = None
        self.last = s

    def detach_legacy(self, s):
        try:
            out = subprocess.run([self.collector, "--iface", self.interface, "--detach-only"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 timeout=10, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
            s.record["notes"].append("cleanup: " + out.stdout.decode("utf-8", "replace").strip())
        except (OSError, subprocess.TimeoutExpired) as e:
            s.record["notes"].append("cleanup of tc filters failed: {}".format(e))

    def tick(self):
        s = self.current
        if s is not None and s.proc is not None and s.proc.poll() is not None:
            # The collector exited on its own: duration limit, lost interface or crash.
            if s.record.get("status") == "starting" and os.path.exists(s.ready):
                s.record["status"] = "running"
            self.finish(s, "collector exited on its own with status {}".format(s.proc.returncode))
        elif s is not None and s.record.get("status") == "starting" and os.path.exists(s.ready):
            s.record.update({"status": "running"})
            self.save_record(s)
        if time.time() - self.last_retention > RETENTION_EVERY:
            self.apply_retention()
            self.last_retention = time.time()

    def apply_retention(self):
        days = self.settings.get("retention_days", 7)
        keep = self.settings.get("retention_sessions", 20)
        try:
            entries = [e for e in os.listdir(self.sessions_dir) if valid_session(e)]
        except OSError:
            return
        active = self.current.token if self.current else None
        dated = sorted(((os.path.getmtime(os.path.join(self.sessions_dir, e)), e) for e in entries), reverse=True)
        now = time.time()
        for rank, (mtime, e) in enumerate(dated):
            if e == active:
                continue
            if rank >= keep or (days and now - mtime > days * 86400):
                shutil.rmtree(os.path.join(self.sessions_dir, e), ignore_errors=True)
                log("retention: removed session {}".format(e))

    # -- socket

    def peer_allowed(self, conn):
        try:
            pid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                                  struct.calcsize("3i")))
        except (OSError, AttributeError):
            return False, None
        if uid in (0, os.getuid()):
            return True, uid
        try:
            import grp
            import pwd
            g = grp.getgrgid(os.getgid())
            name = pwd.getpwuid(uid).pw_name
            return (gid == g.gr_gid or name in g.gr_mem), uid
        except (ImportError, KeyError):
            return False, uid

    def handle(self, conn):
        conn.settimeout(2.0)
        allowed, uid = self.peer_allowed(conn)
        if not allowed:
            log("refused a request from uid {}".format(uid))
            resp = {"ok": False, "status": "refused", "error": "peer not permitted"}
        else:
            data = b""
            try:
                while not data.endswith(b"\n") and len(data) <= MAX_REQUEST:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                req = json.loads(data.decode()) if len(data) <= MAX_REQUEST else None
            except (OSError, ValueError, UnicodeDecodeError):
                req = None
            ops = {"status": self.op_status, "start": self.op_start, "stop": self.op_stop}
            if not isinstance(req, dict) or req.get("op") not in ops:
                resp = {"ok": False, "status": "bad_request", "error": "expected {\"op\": status|start|stop}"}
            else:
                try:
                    resp = ops[req["op"]](req)
                except Exception as e:  # keep serving; report the failure to the caller
                    log("{} failed: {!r}".format(req["op"], e))
                    resp = {"ok": False, "status": "failed", "error": "service error: {}".format(e)}
                if req["op"] != "status":
                    log("{} {} by uid {} -> {}".format(req["op"], req.get("session"), uid, resp.get("status")))
        try:
            conn.sendall(json.dumps(resp).encode() + b"\n")
        except OSError:
            pass

    def serve(self):
        os.makedirs(self.sessions_dir, mode=0o750, exist_ok=True)
        if os.path.exists(self.socket_path) and not os.path.isdir(self.socket_path):
            os.unlink(self.socket_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.socket_path)
        os.chmod(self.socket_path, 0o660)
        srv.listen(8)
        notify_ready("listening on {}".format(self.socket_path))

        def on_signal(sig, frame):
            self.stopping = True
        signal.signal(signal.SIGTERM, on_signal)
        signal.signal(signal.SIGINT, on_signal)
        log("listening on {} (interface {}{})".format(self.socket_path, self.interface,
                                                      "; " + self.interface_problem if self.interface_problem else ""))
        self.apply_retention()
        self.last_retention = time.time()
        try:
            while not self.stopping:
                try:
                    ready, _, _ = select.select([srv], [], [], TICK)
                except InterruptedError:
                    ready = []
                if ready:
                    try:
                        conn, _ = srv.accept()
                    except OSError:
                        continue
                    with conn:
                        self.handle(conn)
                self.tick()
        finally:
            if self.current is not None:
                self.finish(self.current, "service stopped")
            srv.close()
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="luca-observatoryd", description="Luca observatory collector service")
    sub = p.add_subparsers(dest="cmd")
    r = sub.add_parser("render-settings", help="(root) derive the service settings from config.yaml")
    r.add_argument("--config", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--group", default=SERVICE_GROUP)
    s = sub.add_parser("serve", help="run the collector service")
    s.add_argument("--settings", required=True)
    s.add_argument("--collector", required=True)
    s.add_argument("--bpf-dir")
    s.add_argument("--socket", default=SOCKET_PATH)
    s.add_argument("--spool", default=SPOOL_DIR)
    s.add_argument("--collector-arg", action="append", default=[],
                   help="extra collector argument (tests only)")
    args = p.parse_args(argv)
    if args.cmd == "render-settings":
        return render_settings(args.config, args.out, args.group)
    if args.cmd != "serve":
        p.print_help()
        return 1
    try:
        with open(args.settings) as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        log("cannot read settings {}: {}".format(args.settings, e))
        return 2
    if not (doc.get("settings") or {}).get("enabled"):
        log("observatory.enabled is false in config.yaml; nothing to do")
        notify_ready("disabled in config.yaml")  # a clean start and exit, not a failed one
        return 0
    os.umask(0o027)
    return Service(doc, args.socket, args.spool, args.collector, args.bpf_dir, args.collector_arg).serve()


if __name__ == "__main__":
    sys.exit(main())
