"""Saved launch specs.

Once a process is killed, /proc forgets its command, cwd and environment. So we
snapshot those *before* killing anything, and keep them on disk so a restart
still works in a later session.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict

import psutil

# Environment variables that would actively break a relaunch if we replayed
# them: they describe the old process, not the command.
ENV_BLOCKLIST = {
    "_", "PWD", "OLDPWD", "SHLVL", "LINES", "COLUMNS",
    "LISTEN_FDS", "LISTEN_PID", "NOTIFY_SOCKET", "INVOCATION_ID", "JOURNAL_STREAM",
}


def _state_home() -> str:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, "show-ports")


def _config_home() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "show-ports")


REGISTRY_PATH = os.path.join(_config_home(), "registry.json")
LOG_DIR = os.path.join(_state_home(), "logs")


@dataclass
class Entry:
    """Everything needed to bring a service back up."""

    id: str
    label: str
    port: int
    cmdline: list[str]
    cwd: str
    env: dict[str, str] = field(default_factory=dict)
    exe: str | None = None
    user: str | None = None
    captured_at: float = field(default_factory=time.time)
    last_started_at: float | None = None
    last_pid: int | None = None
    note: str | None = None

    @property
    def command(self) -> str:
        return " ".join(self.cmdline)

    @property
    def log_path(self) -> str:
        return os.path.join(LOG_DIR, f"{self.id}.log")

    def to_dict(self, include_env: bool = False) -> dict:
        d = asdict(self)
        d["command"] = self.command
        d["log_path"] = self.log_path
        d["env_count"] = len(self.env)
        if not include_env:
            d.pop("env", None)
        return d


def make_id(cmdline: list[str], cwd: str, port: int) -> str:
    """Stable id for a service, so re-capturing updates rather than duplicates."""
    seed = json.dumps([cmdline, cwd, port], sort_keys=True).encode()
    digest = hashlib.sha256(seed).hexdigest()[:10]
    stem = os.path.basename(cwd.rstrip("/")) or "svc"
    stem = "".join(c if c.isalnum() or c in "-_" else "-" for c in stem)[:24]
    return f"{stem}-{port}-{digest}"


class Registry:
    def __init__(self, path: str = REGISTRY_PATH):
        self.path = path
        self.entries: dict[str, Entry] = {}
        self.load()

    def load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            return
        for item in raw.get("entries", []):
            try:
                item.pop("command", None)
                item.pop("log_path", None)
                item.pop("env_count", None)
                entry = Entry(**item)
            except TypeError:
                continue
            self.entries[entry.id] = entry

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        payload = {"version": 1, "entries": [asdict(e) for e in self.entries.values()]}
        tmp = f"{self.path}.tmp"
        # The env snapshots can hold API keys, so the file is owner-only from
        # the moment it exists, not after the write.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    def get(self, entry_id: str) -> Entry | None:
        return self.entries.get(entry_id)

    def by_port(self, port: int) -> Entry | None:
        for entry in self.entries.values():
            if entry.port == port:
                return entry
        return None

    def remove(self, entry_id: str) -> bool:
        if entry_id in self.entries:
            del self.entries[entry_id]
            self.save()
            return True
        return False

    def update(self, entry_id: str, **fields) -> Entry | None:
        entry = self.entries.get(entry_id)
        if not entry:
            return None
        for key, value in fields.items():
            if key in {"label", "cmdline", "cwd", "port", "note"} and value is not None:
                setattr(entry, key, value)
        self.save()
        return entry

    def capture(self, pid: int, port: int, label: str | None = None,
                include_env: bool = True) -> Entry:
        """Snapshot a running process into a relaunchable spec."""
        proc = psutil.Process(pid)
        with proc.oneshot():
            cmdline = proc.cmdline()
            cwd = proc.cwd()
            try:
                exe = proc.exe()
            except (psutil.Error, OSError):
                exe = None
            try:
                user = proc.username()
            except (psutil.Error, KeyError):
                user = None

        if not cmdline:
            raise ValueError(f"pid {pid} has no readable command line (kernel thread?)")

        env: dict[str, str] = {}
        if include_env:
            try:
                env = {k: v for k, v in proc.environ().items() if k not in ENV_BLOCKLIST}
            except (psutil.Error, OSError):
                env = {}

        entry_id = make_id(cmdline, cwd, port)
        existing = self.entries.get(entry_id)
        entry = Entry(
            id=entry_id,
            label=label or (existing.label if existing else os.path.basename(cwd.rstrip("/")) or f"port {port}"),
            port=port,
            cmdline=cmdline,
            cwd=cwd,
            env=env,
            exe=exe,
            user=user,
            captured_at=existing.captured_at if existing else time.time(),
            last_pid=pid,
            note=existing.note if existing else None,
        )
        self.entries[entry_id] = entry
        self.save()
        return entry
