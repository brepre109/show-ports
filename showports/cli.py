"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys

import psutil

from . import __version__
from .actions import ActionError, restart, start, stop, tail_log
from .registry import Registry
from .scan import scan

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
GREEN, YELLOW, RED, BLUE = "\033[32m", "\033[33m", "\033[31m", "\033[34m"


def _colour(text: str, code: str) -> str:
    return text if not sys.stdout.isatty() else f"{code}{text}{RESET}"


def _clip(text: str, width: int) -> str:
    text = text or ""
    return text if len(text) <= width else text[: width - 1] + "…"


SORTS = {
    "web": lambda s: (not s.is_webapp, s.port),
    "port": lambda s: (s.port,),
    "name": lambda s: (s.label.lower(), s.port),
    "user": lambda s: (s.user or "\uffff", s.port),
    "uptime": lambda s: (s.create_time or float("inf"), s.port),
    "memory": lambda s: (-(s.memory_mb or 0), s.port),
}


def cmd_list(args) -> int:
    services = scan(probe=not args.no_probe)
    registry = Registry()
    saved_ports = {e.port for e in registry.entries.values()}

    if not args.all:
        services = [s for s in services if s.kind == "web"]
    services.sort(key=SORTS[args.sort], reverse=args.reverse)

    if args.json:
        print(json.dumps([s.to_dict() for s in services], indent=2))
        return 0

    if not services:
        print("Nothing listening." if args.all else "No listening port answered HTTP. Use --all.")
        return 0

    width = max((len(s.label) for s in services), default=10)
    width = min(max(width, 12), 34)
    header = (f"{'PORT':>6}  {'WEB':<3}  {'SERVICE'.ljust(width)}  {'PID':>7}  "
              f"{'USER':<9} {'UP':>7}  COMMAND")
    print(_colour(header, BOLD))
    print(_colour("─" * min(os.get_terminal_size().columns if sys.stdout.isatty() else 120, 160), DIM))

    for svc in services:
        if svc.visible:
            pid, user = str(svc.pid), _clip(svc.user or "?", 9)
            command = svc.command or _colour("(no command line)", DIM)
        else:
            pid, user = "-", "-"
            command = _colour("owner hidden — re-run with sudo", DIM)

        label = _clip(svc.label, width).ljust(width)
        if svc.kind == "web":
            label = _colour(label, GREEN)
        mark = "*" if svc.port in saved_ports else " "

        web = _colour("yes", GREEN) if svc.is_webapp else _colour(" no", DIM)
        print(f"{svc.port:>6}{mark} {web}  {label}  {pid:>7}  {user:<9} "
              f"{(svc.uptime or '-'):>7}  {_clip(command, 200)}")
        if args.verbose and svc.cwd:
            print(f"        {_colour('cwd: ' + svc.cwd, DIM)}")
        if args.verbose and svc.supervised_by:
            managed = f"managed by {svc.supervised_by}"
            if svc.restart_hint:
                managed += f" — {svc.restart_hint}"
            print(f"        {_colour(managed, YELLOW)}")

    hidden = sum(1 for s in services if not s.visible)
    web = sum(1 for s in services if s.kind == "web")
    print()
    print(_colour(f"{len(services)} ports · {web} web apps · {hidden} with a hidden owner"
                  f"{'  (* = launch spec saved)' if saved_ports else ''}", DIM))

    stopped = [e for e in registry.entries.values()
               if e.port not in {s.port for s in services}]
    if stopped:
        print()
        print(_colour("Saved but not running:", BOLD))
        for entry in stopped:
            print(f"{entry.port:>6}  {_clip(entry.label, width).ljust(width)}  "
                  f"{_colour(entry.id, DIM)}  {_clip(entry.command, 80)}")
    return 0


def _resolve(target: str, registry: Registry):
    """Accept a port, a pid, or a saved-spec id."""
    entry = registry.get(target)
    if entry:
        return entry, entry.last_pid

    if not target.isdigit():
        raise ActionError(f"{target!r} is not a port, a pid or a known spec id")

    number = int(target)
    for svc in scan(probe=False):
        if svc.port == number:
            return registry.by_port(number), svc.pid
    if psutil.pid_exists(number):
        return None, number
    entry = registry.by_port(number)
    if entry:
        return entry, None
    raise ActionError(f"nothing is listening on port {number} and no pid {number} exists")


def cmd_stop(args) -> int:
    registry = Registry()
    entry, pid = _resolve(args.target, registry)
    if pid is None:
        print(f"Not running: {args.target}")
        return 1
    if entry is None and str(args.target).isdigit():
        # Snapshot before the command line vanishes with the process.
        try:
            entry = registry.capture(pid, int(args.target), include_env=not args.no_env)
            print(_colour(f"Saved launch spec {entry.id} "
                          f"(bring it back with: show-ports start {entry.id})", DIM))
        except (psutil.Error, ValueError, OSError):
            pass

    report = stop(pid, tree=not args.no_tree, force=args.force)
    if not report["ok"]:
        print(_colour(f"Could not stop: {report['survivors']} still alive", RED))
        return 1

    extra = len(report["signalled"]) - 1
    suffix = f" and {extra} child process{'es' if extra > 1 else ''}" if extra > 0 else ""
    print(_colour(f"Stopped pid {pid}{suffix}", GREEN))
    return 0


def cmd_start(args) -> int:
    registry = Registry()
    entry, _ = _resolve(args.target, registry)
    if entry is None:
        raise ActionError(f"no saved launch spec for {args.target!r}; "
                          "run `show-ports capture <port>` while it is running")
    result = start(entry, wait=args.wait)
    if result["ok"]:
        print(_colour(f"Started {entry.label} on port {entry.port} (pid {result['pid']})", GREEN))
        registry.save()
        return 0
    print(_colour(result.get("error", "failed to start"), RED))
    print(result.get("log_tail", ""))
    return 1


def cmd_restart(args) -> int:
    registry = Registry()
    entry, pid = _resolve(args.target, registry)
    if entry is None and pid:
        entry = registry.capture(pid, int(args.target), include_env=not args.no_env)
    if entry is None:
        raise ActionError(f"no saved launch spec for {args.target!r}")
    result = restart(entry, pid=pid, force=args.force, wait=args.wait)
    registry.save()
    if result["ok"]:
        print(_colour(f"Restarted {entry.label} on port {entry.port} "
                      f"(pid {result['start']['pid']})", GREEN))
        return 0
    print(_colour(result["start"].get("error", "restart failed"), RED))
    print(result["start"].get("log_tail", ""))
    return 1


def cmd_capture(args) -> int:
    registry = Registry()
    _, pid = _resolve(args.target, registry)
    if pid is None:
        raise ActionError(f"nothing running for {args.target!r}")
    port = int(args.target) if args.target.isdigit() else 0
    for svc in scan(probe=False):
        if svc.pid == pid:
            port = svc.port
            break
    entry = registry.capture(pid, port, label=args.label, include_env=not args.no_env)
    print(_colour(f"Captured {entry.id}", GREEN))
    print(f"  command: {entry.command}")
    print(f"  cwd:     {entry.cwd}")
    print(f"  env:     {len(entry.env)} variables")
    return 0


def cmd_logs(args) -> int:
    registry = Registry()
    entry, _ = _resolve(args.target, registry)
    if entry is None:
        raise ActionError(f"no saved spec for {args.target!r}")
    print(tail_log(entry, lines=args.lines))
    return 0


def cmd_forget(args) -> int:
    registry = Registry()
    entry, _ = _resolve(args.target, registry)
    if entry and registry.remove(entry.id):
        print(f"Forgot {entry.id}")
        return 0
    print("No such saved spec")
    return 1


def cmd_serve(args) -> int:
    from .web import TOKEN, create_app

    app = create_app(probe=not args.no_probe, capture_env=not args.no_env)
    url = f"http://{args.host}:{args.port}/"
    print(_colour(f"show-ports dashboard  →  {url}", BOLD))
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(_colour("WARNING: bound to a non-loopback address. Anyone who can reach this "
                      "host can stop and start your services.", RED))
    print(_colour(f"session token: {TOKEN[:8]}… (mutating calls need the X-ShowPorts-Token header)", DIM))
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="show-ports",
        description="Show every web app and the port it listens on, "
                    "with the command that launched it — and stop/restart it.",
    )
    parser.add_argument("--version", action="version", version=f"show-ports {__version__}")
    subs = parser.add_subparsers(dest="command")

    def add_common(sub):
        sub.add_argument("--no-env", action="store_true",
                         help="don't snapshot the process environment (safer, less faithful restarts)")

    ls = subs.add_parser("list", help="list listening services (default)")
    ls.add_argument("-a", "--all", action="store_true", help="include non-HTTP ports")
    ls.add_argument("-v", "--verbose", action="store_true", help="show cwd and supervisor")
    ls.add_argument("--json", action="store_true")
    ls.add_argument("--no-probe", action="store_true",
                    help="skip protocol probing (faster, but nothing is identified)")
    ls.add_argument("--sort", choices=sorted(SORTS), default="web",
                    help="sort order (default: web apps first, then port)")
    ls.add_argument("--reverse", action="store_true", help="reverse the sort")
    ls.set_defaults(func=cmd_list)

    srv = subs.add_parser("serve", help="run the web dashboard")
    srv.add_argument("-p", "--port", type=int, default=7317)
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--no-probe", action="store_true")
    add_common(srv)
    srv.set_defaults(func=cmd_serve)

    st = subs.add_parser("stop", help="stop the service on a port / pid / spec id")
    st.add_argument("target")
    st.add_argument("--force", action="store_true", help="allow killing protected system processes")
    st.add_argument("--no-tree", action="store_true", help="signal only the listener, not its children")
    add_common(st)
    st.set_defaults(func=cmd_stop)

    sa = subs.add_parser("start", help="start a saved service")
    sa.add_argument("target")
    sa.add_argument("--wait", type=float, default=20.0)
    sa.set_defaults(func=cmd_start)

    rs = subs.add_parser("restart", help="stop then start again")
    rs.add_argument("target")
    rs.add_argument("--force", action="store_true")
    rs.add_argument("--wait", type=float, default=20.0)
    add_common(rs)
    rs.set_defaults(func=cmd_restart)

    cp = subs.add_parser("capture", help="save a running service's launch spec")
    cp.add_argument("target")
    cp.add_argument("--label")
    add_common(cp)
    cp.set_defaults(func=cmd_capture)

    lg = subs.add_parser("logs", help="show the log of a service started by show-ports")
    lg.add_argument("target")
    lg.add_argument("-n", "--lines", type=int, default=200)
    lg.set_defaults(func=cmd_logs)

    fg = subs.add_parser("forget", help="delete a saved launch spec")
    fg.add_argument("target")
    fg.set_defaults(func=cmd_forget)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    # Bare `show-ports` (and `show-ports -a`) means list.
    if not argv or argv[0].startswith("-") and argv[0] not in ("--version", "-h", "--help"):
        argv.insert(0, "list")
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except ActionError as exc:
        print(_colour(f"error: {exc}", RED), file=sys.stderr)
        return 2
    except psutil.AccessDenied:
        print(_colour("error: permission denied — that process belongs to another user; try sudo",
                      RED), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
