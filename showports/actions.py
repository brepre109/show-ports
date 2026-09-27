"""Stop, start and restart services."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import time

import psutil

from .registry import Entry, LOG_DIR

# Killing any of these takes down the desktop, the network or the SSH session
# the user is typing in. Refused unless explicitly forced.
PROTECTED_NAMES = {
    "systemd", "init", "sshd", "dbus-daemon", "Xorg", "Xwayland",
    "gnome-shell", "plasmashell", "NetworkManager", "systemd-resolved",
    "systemd-logind", "wpa_supplicant", "gdm", "sddm", "lightdm",
}


class ActionError(RuntimeError):
    """A refusal or failure we want to show the user verbatim."""


def _guard(proc: psutil.Process, force: bool) -> None:
    if proc.pid == 1:
        raise ActionError("refusing to signal pid 1 (init)")
    if proc.pid == os.getpid():
        raise ActionError("refusing to kill show-ports itself")
    try:
        if os.getpgid(proc.pid) == os.getpgid(0):
            raise ActionError(
                f"pid {proc.pid} is in this tool's own process group; "
                "killing it would take show-ports down with it"
            )
    except (ProcessLookupError, PermissionError):
        pass
    if force:
        return
    try:
        name = proc.name()
    except psutil.Error:
        return
    if name in PROTECTED_NAMES:
        raise ActionError(
            f"{name!r} (pid {proc.pid}) is a protected system process; "
            "pass force to override"
        )


def port_is_listening(port: int, host: str = "127.0.0.1", timeout: float = 0.4) -> bool:
    for candidate in (host, "::1"):
        try:
            with socket.create_connection((candidate, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def wait_for_port(port: int, up: bool, timeout: float = 15.0) -> bool:
    """Poll until the port reaches the wanted state. True if it got there."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_is_listening(port) == up:
            return True
        time.sleep(0.25)
    return port_is_listening(port) == up


def stop(pid: int, *, tree: bool = True, force: bool = False,
         grace: float = 8.0) -> dict:
    """SIGTERM, wait, then SIGKILL whatever is left."""
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        raise ActionError(f"pid {pid} is not running") from None

    _guard(proc, force)

    try:
        targets = [proc] + (proc.children(recursive=True) if tree else [])
    except psutil.Error:
        targets = [proc]

    report = {"pid": pid, "signalled": [], "killed": [], "survivors": []}

    for target in targets:
        try:
            target.terminate()
            report["signalled"].append(target.pid)
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            raise ActionError(
                f"not permitted to signal pid {target.pid} "
                f"(owned by another user; try sudo)"
            ) from None

    gone, alive = psutil.wait_procs(targets, timeout=grace)

    for target in alive:
        try:
            target.kill()
            report["killed"].append(target.pid)
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            report["survivors"].append(target.pid)

    _, still_alive = psutil.wait_procs(alive, timeout=3)
    report["survivors"] = sorted({p.pid for p in still_alive} | set(report["survivors"]))
    report["ok"] = not report["survivors"]
    return report


def start(entry: Entry, *, wait: float = 20.0) -> dict:
    """Relaunch from a saved spec, detached, with output going to a log file."""
    if not entry.cmdline:
        raise ActionError(f"{entry.id} has no stored command")
    if not os.path.isdir(entry.cwd):
        raise ActionError(f"working directory is gone: {entry.cwd}")
    if port_is_listening(entry.port):
        raise ActionError(f"port {entry.port} is already in use; stop it first")

    os.makedirs(LOG_DIR, exist_ok=True)
    # Remember where this launch's output begins, so a failure report shows
    # only what this attempt printed and not the whole run history.
    try:
        log_offset = os.path.getsize(entry.log_path)
    except OSError:
        log_offset = 0
    env = dict(entry.env) if entry.env else os.environ.copy()
    env.setdefault("PATH", os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"))

    log = open(entry.log_path, "ab", buffering=0)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log.write(f"\n===== show-ports start {stamp} :: {entry.command} =====\n".encode())

    try:
        proc = subprocess.Popen(
            entry.cmdline,
            cwd=entry.cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,   # survives this tool exiting
            close_fds=True,
        )
    except (OSError, ValueError) as exc:
        log.close()
        raise ActionError(f"could not launch: {exc}") from None
    finally:
        try:
            log.close()
        except OSError:
            pass

    entry.last_pid = proc.pid
    entry.last_started_at = time.time()

    listening = wait_for_port(entry.port, up=True, timeout=wait)
    exited = proc.poll()

    result = {
        "ok": listening and exited is None,
        "pid": proc.pid,
        "port": entry.port,
        "listening": listening,
        "exit_code": exited,
        "log_path": entry.log_path,
    }
    if not result["ok"]:
        result["log_tail"] = tail_log(entry, lines=25, since=log_offset)
        if exited is not None:
            result["error"] = f"process exited immediately with code {exited}"
        else:
            result["error"] = f"started (pid {proc.pid}) but port {entry.port} never opened within {wait:.0f}s"
    return result


def restart(entry: Entry, pid: int | None = None, *, force: bool = False,
            wait: float = 20.0) -> dict:
    """Stop what holds the port, then start from the saved spec."""
    steps = {}
    target = pid if pid is not None else entry.last_pid

    if target and psutil.pid_exists(target):
        steps["stop"] = stop(target, force=force)
    elif port_is_listening(entry.port):
        raise ActionError(
            f"port {entry.port} is held by a process show-ports can't identify; "
            "stop it manually first"
        )
    else:
        steps["stop"] = {"ok": True, "note": "was not running"}

    if not wait_for_port(entry.port, up=False, timeout=10):
        raise ActionError(f"port {entry.port} is still held after stopping")

    steps["start"] = start(entry, wait=wait)
    steps["ok"] = steps["start"]["ok"]
    return steps


def tail_log(entry: Entry, lines: int = 200, since: int | None = None) -> str:
    """Last `lines` of the log, or everything written after byte `since`."""
    try:
        with open(entry.log_path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(since if since is not None else max(0, size - 64 * 1024))
            data = fh.read()
    except OSError:
        return "(no log yet)"
    text = data.decode("utf-8", "replace").splitlines()
    return "\n".join(text[-lines:]).strip() or "(no output)"
