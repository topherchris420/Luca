#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Client for the observatory collector service, used by Luca's frontend.

    The service listens on a Unix socket that only root and members of the
    luca-observatory group can open. The protocol is one JSON request line
    and one JSON response line per connection, with three operations:
      {"op": "status"}
      {"op": "start", "session": "<capture token>"}
      {"op": "stop",  "session": "<capture token>"}
    The client cannot choose interfaces, files or collector options; the
    service derives all of them from its own settings.

    Every function here degrades instead of raising: a capture must never
    fail because the optional observatory is unavailable.

    Usage: python3 -m luca_observatory.client status|start TOKEN|stop TOKEN
"""

import json
import os
import shutil
import socket
import sys
import time

from . import SESSION_SCHEMA
from .config import SOCKET_PATH, observatory_config, valid_session

MAX_RESPONSE = 1 << 20
CONNECT_TIMEOUT = 1.0
TIMEOUTS = {"status": 5.0, "start": 6.0, "stop": 25.0}


class Unavailable(Exception):
    pass


def request(op, session=None, socket_path=SOCKET_PATH, timeout=None):
    """
        :return: dict response. Raises Unavailable on any transport problem.
    """
    if not hasattr(socket, "AF_UNIX"):
        raise Unavailable("Unix sockets are not supported on this platform")
    msg = {"op": op}
    if session is not None:
        msg["session"] = session
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(CONNECT_TIMEOUT)
        try:
            s.connect(socket_path)
        except FileNotFoundError:
            raise Unavailable("collector service is not running (no socket at {})".format(socket_path))
        except PermissionError:
            raise Unavailable("not permitted to contact the collector service at {}".format(socket_path))
        except OSError as e:
            raise Unavailable("cannot contact the collector service: {}".format(e.strerror or e))
        s.settimeout(timeout or TIMEOUTS.get(op, 5.0))
        s.sendall(json.dumps(msg).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_RESPONSE:
                raise Unavailable("oversized response from the collector service")
    except socket.timeout:
        raise Unavailable("the collector service did not answer in time")
    except OSError as e:
        raise Unavailable("collector service connection failed: {}".format(e.strerror or e))
    finally:
        s.close()
    try:
        resp = json.loads(data.decode())
    except ValueError:
        raise Unavailable("malformed response from the collector service")
    if not isinstance(resp, dict):
        raise Unavailable("malformed response from the collector service")
    return resp


def enabled(section):
    settings, _ = observatory_config({"observatory": section})
    return settings["enabled"]


def status(section, socket_path=SOCKET_PATH):
    settings, problems = observatory_config({"observatory": section})
    if not settings["enabled"]:
        return {"status": "disabled", "config_problems": problems}
    try:
        resp = request("status", socket_path=socket_path)
    except Unavailable as e:
        return {"status": "unavailable", "error": str(e), "config_problems": problems}
    resp.setdefault("status", "available")
    resp["config_problems"] = problems
    return resp


def start_session(section, token, socket_path=SOCKET_PATH):
    """
        Ask the service to observe a new capture session.
        :return: dict with at least "status".
    """
    if not enabled(section):
        return {"status": "disabled"}
    if not valid_session(token):
        return {"status": "refused", "error": "invalid session token"}
    try:
        return request("start", token, socket_path)
    except Unavailable as e:
        return {"status": "unavailable", "error": str(e)}


def _copy(src, dst):
    try:
        shutil.copyfile(src, dst)
        return True
    except (OSError, TypeError):
        return False


def stop_session(section, token, assets_dir, start_response=None, socket_path=SOCKET_PATH):
    """
        Stop observing and place the session's evidence next to the capture:
          assets/observatory.json          the collector's final snapshot
          assets/observatory_session.json  how the session went, including failures
        Nothing is written when the observatory is disabled, so Luca's
        output is unchanged for installations that do not use it.
        :return: dict with at least "status".
    """
    if not enabled(section):
        return {"status": "disabled"}
    record = {"schema": SESSION_SCHEMA, "session": token, "recorded_at": time.time(),
              "start_response": start_response}
    if not valid_session(token):
        record.update({"status": "refused", "error": "invalid session token"})
    else:
        try:
            resp = request("stop", token, socket_path)
            record["stop_response"] = resp
            record["status"] = resp.get("status", "unknown")
            if resp.get("error"):
                record["error"] = resp["error"]
            service = resp.get("record")
            if isinstance(service, dict):
                record["service"] = service
                for k in ("crashed", "exit_code", "requested_at", "started_at", "stopped_at", "interface", "notes"):
                    if k in service:
                        record[k] = service[k]
            record["snapshot_copied"] = _copy(resp.get("snapshot"), os.path.join(assets_dir, "observatory.json"))
            if not record["snapshot_copied"] and resp.get("snapshot"):
                record.setdefault("notes", []).append("the snapshot could not be copied from the service spool")
        except Unavailable as e:
            prior = (start_response or {}).get("status")
            record.update({"status": "unavailable" if prior in (None, "unavailable") else prior,
                           "error": str(e)})
    try:
        with open(os.path.join(assets_dir, "observatory_session.json"), "w") as f:
            json.dump(record, f, indent=2)
    except OSError:
        pass
    return record


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    socket_path = SOCKET_PATH
    if len(argv) >= 2 and argv[0] == "--socket":
        socket_path, argv = argv[1], argv[2:]
    if not argv or argv[0] not in ("status", "start", "stop") or (argv[0] != "status" and len(argv) != 2):
        print("usage: python3 -m luca_observatory.client [--socket PATH] status|start TOKEN|stop TOKEN")
        return 1
    try:
        resp = request(argv[0], argv[1] if len(argv) > 1 else None, socket_path)
    except Unavailable as e:
        print("unavailable: {}".format(e))
        return 2
    json.dump(resp, sys.stdout, indent=2)
    print()
    return 0 if resp.get("ok", True) else 3


if __name__ == "__main__":
    sys.exit(main())
