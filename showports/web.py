"""Local dashboard.

Bound to loopback by default. Every mutating endpoint requires a per-run token
that only the served page knows, so another page in the same browser cannot
drive it via a cross-site request.
"""

from __future__ import annotations

import secrets
from functools import wraps

import psutil
from flask import Flask, jsonify, render_template, request

from . import __version__
from .actions import ActionError, restart, start, stop, tail_log
from .registry import Registry
from .scan import scan

TOKEN = secrets.token_urlsafe(24)


def _json_error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def guarded(view):
    """Token + same-origin check for anything that changes state."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if request.headers.get("X-ShowPorts-Token") != TOKEN:
            return _json_error("missing or bad token", 403)
        origin = request.headers.get("Origin")
        if origin and origin != request.host_url.rstrip("/"):
            return _json_error("cross-origin request refused", 403)
        try:
            return view(*args, **kwargs)
        except ActionError as exc:
            return _json_error(str(exc), 409)
        except psutil.NoSuchProcess:
            return _json_error("process is no longer running", 410)
        except psutil.AccessDenied:
            return _json_error("permission denied (process owned by another user)", 403)

    return wrapper


def create_app(probe: bool = True, capture_env: bool = True) -> Flask:
    app = Flask(__name__)
    registry = Registry()

    def _entry_or_404(entry_id: str):
        entry = registry.get(entry_id)
        if entry is None:
            raise ActionError(f"no saved launch spec with id {entry_id!r}")
        return entry

    @app.get("/")
    def index():
        return render_template("index.html", token=TOKEN, version=__version__)

    @app.get("/api/services")
    def api_services():
        show_all = request.args.get("all") == "1"
        services = scan(probe=probe)
        by_port = {e.port: e for e in registry.entries.values()}
        out = []
        for svc in services:
            if not show_all and svc.kind != "web":
                continue
            data = svc.to_dict()
            entry = by_port.get(svc.port)
            if entry:
                data["registry_id"] = entry.id
                data["saved_command"] = entry.command
                data["saved_label"] = entry.label
            out.append(data)

        running_ports = {s.port for s in services}
        stopped = [
            e.to_dict() for e in registry.entries.values()
            if e.port not in running_ports
        ]
        return jsonify({
            "services": out,
            "stopped": stopped,
            "counts": {
                "total": len(services),
                "web": sum(1 for s in services if s.kind == "web"),
                "hidden": sum(1 for s in services if not s.visible),
            },
        })

    @app.post("/api/capture")
    @guarded
    def api_capture():
        body = request.get_json(silent=True) or {}
        pid, port = body.get("pid"), body.get("port")
        if not pid or not port:
            return _json_error("pid and port are required")
        entry = registry.capture(int(pid), int(port), label=body.get("label"),
                                 include_env=capture_env)
        return jsonify({"ok": True, "entry": entry.to_dict()})

    @app.post("/api/stop")
    @guarded
    def api_stop():
        body = request.get_json(silent=True) or {}
        pid = body.get("pid")
        if not pid:
            return _json_error("pid is required")
        # Snapshot the launch spec before the command line disappears with the
        # process, so "restart" is still on the table afterwards.
        saved = None
        if body.get("capture", True) and body.get("port"):
            try:
                saved = registry.capture(int(pid), int(body["port"]),
                                         include_env=capture_env).to_dict()
            except (psutil.Error, ValueError, OSError):
                saved = None
        report = stop(int(pid), tree=body.get("tree", True),
                      force=body.get("force", False))
        return jsonify({"ok": report["ok"], "report": report, "entry": saved})

    @app.post("/api/start")
    @guarded
    def api_start():
        body = request.get_json(silent=True) or {}
        entry = _entry_or_404(body.get("id", ""))
        return jsonify(start(entry))

    @app.post("/api/restart")
    @guarded
    def api_restart():
        body = request.get_json(silent=True) or {}
        entry_id = body.get("id")
        pid = body.get("pid")
        if not entry_id and pid and body.get("port"):
            entry_id = registry.capture(int(pid), int(body["port"]),
                                        include_env=capture_env).id
        entry = _entry_or_404(entry_id or "")
        result = restart(entry, pid=int(pid) if pid else None,
                         force=body.get("force", False))
        registry.save()
        return jsonify(result)

    @app.get("/api/logs/<entry_id>")
    def api_logs(entry_id: str):
        entry = registry.get(entry_id)
        if not entry:
            return _json_error("unknown id", 404)
        return jsonify({"ok": True, "log": tail_log(entry), "path": entry.log_path})

    @app.patch("/api/registry/<entry_id>")
    @guarded
    def api_update(entry_id: str):
        body = request.get_json(silent=True) or {}
        cmdline = body.get("cmdline")
        if isinstance(cmdline, str):
            import shlex
            cmdline = shlex.split(cmdline)
        entry = registry.update(entry_id, label=body.get("label"), cwd=body.get("cwd"),
                                cmdline=cmdline, note=body.get("note"))
        if not entry:
            return _json_error("unknown id", 404)
        return jsonify({"ok": True, "entry": entry.to_dict()})

    @app.delete("/api/registry/<entry_id>")
    @guarded
    def api_forget(entry_id: str):
        return jsonify({"ok": registry.remove(entry_id)})

    return app
