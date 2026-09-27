"""Discovery: what is listening, who owns it, and is it a web app."""

from __future__ import annotations

import json
import os
import socket
import ssl
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict

import psutil

# Ports that speak a binary protocol. Throwing an HTTP request at them is
# pointless and litters their logs, so we label them from this table instead.
BINARY_PROTOCOL_PORTS = {
    22: "SSH", 25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP",
    465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    1716: "KDE Connect", 3306: "MySQL", 33060: "MySQL X",
    5432: "PostgreSQL", 6379: "Redis", 9050: "Tor SOCKS", 9051: "Tor control",
    11211: "Memcached", 27017: "MongoDB", 5672: "AMQP", 9800: "FluidSynth",
    5900: "VNC", 5901: "VNC", 3389: "RDP",
}

# Recognisable services that *do* speak HTTP, for a friendlier label than the
# page title alone.
KNOWN_HTTP_PORTS = {
    80: "HTTP", 443: "HTTPS", 631: "CUPS", 6333: "Qdrant",
    8008: "Matrix / Synapse", 9200: "Elasticsearch",
}

# Display names for fingerprinted protocols.
PROTOCOL_NAMES = {
    "http": "HTTP", "mysql": "MySQL", "mariadb": "MariaDB",
    "postgresql": "PostgreSQL", "redis": "Redis", "memcached": "Memcached",
    "ssh": "SSH", "smtp": "SMTP", "imap": "IMAP", "pop3": "POP3",
    "ftp": "FTP", "vnc": "VNC",
}

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


@dataclass
class Probe:
    """What a port turned out to be speaking."""

    protocol: str | None = None   # http, mysql, postgresql, redis, ssh, ...
    version: str | None = None    # server version, when the protocol reveals it
    is_http: bool = False
    scheme: str = "http"
    status: int | None = None
    title: str | None = None
    server: str | None = None
    location: str | None = None
    error: str | None = None


@dataclass
class Service:
    port: int
    addresses: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    pid: int | None = None
    visible: bool = True          # False when the socket's owner is another user
    user: str | None = None
    name: str | None = None
    exe: str | None = None
    cmdline: list[str] = field(default_factory=list)
    cwd: str | None = None
    create_time: float | None = None
    ppid: int | None = None
    parent_name: str | None = None
    parent_cmdline: str | None = None
    supervised_by: str | None = None   # systemd unit / container / supervisor
    restart_hint: str | None = None    # the command that manager expects
    children: int = 0
    memory_mb: float | None = None
    project: str | None = None         # inferred project name from the cwd
    probe: Probe = field(default_factory=Probe)
    registry_id: str | None = None     # set later if we have a saved launch spec
    controllable: bool = False         # can this user actually signal it

    @property
    def is_webapp(self) -> bool:
        return self.probe.is_http

    @property
    def kind(self) -> str:
        if self.probe.is_http:
            return "web"
        if self.probe.protocol or self.port in BINARY_PROTOCOL_PORTS:
            return "service"
        return "unknown"

    @property
    def protocol_name(self) -> str:
        """What this port speaks, detected if possible and guessed if not."""
        if self.probe.protocol:
            return PROTOCOL_NAMES.get(self.probe.protocol, self.probe.protocol)
        if self.port in BINARY_PROTOCOL_PORTS:
            return BINARY_PROTOCOL_PORTS[self.port] + "?"
        return "unknown"

    @property
    def label(self) -> str:
        if self.probe.title:
            return self.probe.title
        if self.probe.protocol and self.probe.protocol != "http":
            name = PROTOCOL_NAMES.get(self.probe.protocol, self.probe.protocol)
            version = self.probe.version
            if version and self.probe.protocol in ("mysql", "mariadb"):
                version = version.split("-")[0]   # "8.0.45-0ubuntu0.22.04.1"
            return f"{name} {version}" if version else name
        if self.port in KNOWN_HTTP_PORTS:
            return KNOWN_HTTP_PORTS[self.port]
        if self.port in BINARY_PROTOCOL_PORTS:
            return BINARY_PROTOCOL_PORTS[self.port]
        if self.project:
            return self.project
        if self.name:
            return self.name
        return f"port {self.port}"

    @property
    def url(self) -> str | None:
        if not self.probe.is_http:
            return None
        host = "127.0.0.1" if any(a in ("0.0.0.0", "::", "127.0.0.1", "::1") for a in self.addresses) else self.addresses[0]
        if ":" in host:
            host = f"[{host}]"
        return f"{self.probe.scheme}://{host}:{self.port}/"

    @property
    def command(self) -> str:
        return " ".join(self.cmdline) if self.cmdline else ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind
        d["is_webapp"] = self.is_webapp
        d["protocol_name"] = self.protocol_name
        d["label"] = self.label
        d["url"] = self.url
        d["command"] = self.command
        d["uptime"] = self.uptime
        return d

    @property
    def uptime(self) -> str | None:
        if not self.create_time:
            return None
        secs = int(time.time() - self.create_time)
        days, rem = divmod(secs, 86400)
        hours, rem = divmod(rem, 3600)
        mins = rem // 60
        if days:
            return f"{days}d {hours}h"
        if hours:
            return f"{hours}h {mins}m"
        return f"{mins}m"


def probe_http(host: str, port: int, timeout: float = 1.5) -> Probe:
    """Ask a port for a page. Speaks raw HTTP so a non-HTTP server can't raise."""
    if port in BINARY_PROTOCOL_PORTS:
        return Probe(error="binary protocol (not probed)")

    for scheme in ("http", "https"):
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
        except OSError as exc:
            return Probe(error=str(exc))
        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                raw = ctx.wrap_socket(raw, server_hostname=host)
            raw.settimeout(timeout)
            request = (
                f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n"
                "User-Agent: show-ports/1.0\r\nAccept: text/html\r\n"
                "Connection: close\r\n\r\n"
            )
            raw.sendall(request.encode())
            chunks, total = [], 0
            while total < 65536:
                try:
                    buf = raw.recv(16384)
                except (socket.timeout, ssl.SSLError):
                    break
                if not buf:
                    break
                chunks.append(buf)
                total += len(buf)
            data = b"".join(chunks)
        except (ssl.SSLError, OSError) as exc:
            data = b""
            err = str(exc)
        else:
            err = None
        finally:
            try:
                raw.close()
            except OSError:
                pass

        if data.startswith(b"HTTP/"):
            return _parse_http(data, scheme)
        # A plaintext GET against a TLS port gets a handshake alert or a reset;
        # that is our cue to retry the same port over TLS.
        if scheme == "http" and (not data or data[:1] == b"\x15"):
            continue
        return Probe(error=err or "not an HTTP response")
    return Probe(error="no HTTP response")


def _recv(sock: socket.socket, limit: int = 4096) -> bytes:
    try:
        return sock.recv(limit)
    except (socket.timeout, OSError):
        return b""


def _banner_probe(host: str, port: int, timeout: float) -> Probe:
    """Listen for a greeting. Protocols that speak first identify themselves free."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return Probe(error=str(exc))
    try:
        sock.settimeout(min(timeout, 0.8))
        data = _recv(sock)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not data:
        return Probe()

    if data.startswith(b"SSH-"):
        banner = data.split(b"\r")[0].split(b"\n")[0].decode("ascii", "replace")
        # SSH-<wire version>-<software>; the software is the informative half.
        parts = banner.split("-", 2)
        software = parts[2].split()[0] if len(parts) > 2 and parts[2].strip() else None
        return Probe(protocol="ssh", version=software)
    if data.startswith(b"RFB "):
        return Probe(protocol="vnc", version=data[4:11].decode("ascii", "replace"))
    if data.startswith(b"+OK"):
        return Probe(protocol="pop3")
    if data.startswith(b"* OK"):
        return Probe(protocol="imap")
    if data.startswith(b"220"):
        head = data[:120].upper()
        if b"FTP" in head:
            return Probe(protocol="ftp")
        return Probe(protocol="smtp")

    # MySQL/MariaDB: 3-byte length, sequence 0, then protocol version 10 and a
    # NUL-terminated version string. An 0xff payload is its "host blocked" error,
    # which still identifies the server.
    if len(data) > 5 and data[3] == 0:
        if data[4] == 0x0A:
            version = data[5:].split(b"\x00")[0].decode("ascii", "replace")[:40]
            flavour = "mariadb" if "mariadb" in version.lower() else "mysql"
            return Probe(protocol=flavour, version=version or None)
        if data[4] == 0xFF:
            return Probe(protocol="mysql")

    return Probe()


def _ask(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    """Send one probe and read the reply."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return b""
    try:
        sock.settimeout(timeout)
        sock.sendall(payload)
        return _recv(sock)
    except OSError:
        return b""
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _active_probe(host: str, port: int, timeout: float) -> Probe:
    """For protocols where the client must speak first."""
    # PostgreSQL answers an SSLRequest with a single 'S' or 'N'.
    reply = _ask(host, port, b"\x00\x00\x00\x08\x04\xd2\x16\x2f", timeout)
    if reply in (b"S", b"N"):
        return Probe(protocol="postgresql")

    reply = _ask(host, port, b"PING\r\n", timeout)
    if reply.startswith(b"+PONG") or b"NOAUTH" in reply[:40]:
        return Probe(protocol="redis")

    reply = _ask(host, port, b"version\r\n", timeout)
    if reply.startswith(b"VERSION "):
        return Probe(protocol="memcached",
                     version=reply[8:].split(b"\r")[0].decode("ascii", "replace"))
    return Probe()


def fingerprint(host: str, port: int, timeout: float = 1.5) -> Probe:
    """Identify what a port speaks, by conversation rather than by port number."""
    probe = _banner_probe(host, port, timeout)
    if probe.protocol:
        return probe
    if probe.error:                       # could not connect at all
        return probe

    # Most ports here are web, so try HTTP first — except on ports whose usual
    # occupant would log a stray GET as a protocol error.
    if port in BINARY_PROTOCOL_PORTS:
        active = _active_probe(host, port, timeout)
        if active.protocol:
            return active
        return probe_http(host, port, timeout)

    http = probe_http(host, port, timeout)
    if http.is_http:
        return http
    active = _active_probe(host, port, timeout)
    return active if active.protocol else http


def _parse_http(data: bytes, scheme: str) -> Probe:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        status = None

    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(b":")
        headers[key.strip().lower().decode("latin-1")] = value.strip().decode("latin-1", "replace")

    title = None
    match = TITLE_RE.search(body)
    if match:
        title = re.sub(r"\s+", " ", match.group(1).decode("utf-8", "replace")).strip()[:80] or None

    return Probe(
        protocol="http",
        is_http=True,
        scheme=scheme,
        status=status,
        title=title,
        server=headers.get("server"),
        location=headers.get("location"),
    )


# Directories that say nothing about what a process is. A daemon started from
# a home directory or / would otherwise be labelled "ubuntu" or "/".
UNINFORMATIVE_CWDS = {"/", "/root", "/tmp", "/usr", "/var", "/etc", "/opt", "/srv"}


def _project_name(cwd: str | None) -> str | None:
    """Best-effort project label from the working directory."""
    if not cwd or not os.path.isdir(cwd):
        return None
    normalised = cwd.rstrip("/") or "/"
    if normalised in UNINFORMATIVE_CWDS or os.path.dirname(normalised) == "/home":
        return None
    pkg = os.path.join(cwd, "package.json")
    if os.path.isfile(pkg):
        try:
            with open(pkg, encoding="utf-8") as fh:
                name = json.load(fh).get("name")
            if name:
                return str(name)
        except (OSError, ValueError):
            pass
    return os.path.basename(cwd.rstrip("/")) or None


def _supervisor(proc: psutil.Process) -> tuple[str | None, str | None]:
    """Identify what manages this process, as (description, restart hint).

    The parent pid alone lies here: a process started from a terminal that has
    since closed is re-parented to pid 1 and looks identical to a systemd
    service. The cgroup distinguishes them — a real unit sits in a *.service
    cgroup, while an orphan stays in the login session's *.scope.
    """
    try:
        with open(f"/proc/{proc.pid}/cgroup", encoding="utf-8") as fh:
            cgroup = fh.readline().strip()
    except OSError:
        cgroup = ""

    leaf = cgroup.rsplit("/", 1)[-1] if cgroup else ""
    user_scoped = "user@" in cgroup

    if "docker" in cgroup or "containerd" in cgroup or "libpod" in cgroup:
        return "a container", "manage it with docker/podman, not here"

    if leaf.endswith(".service"):
        unit = leaf[: -len(".service")]
        scope = "--user " if user_scoped else ""
        return f"systemd unit {unit}.service", f"systemctl {scope}restart {unit}"

    # Not a unit. Fall back to naming a userspace supervisor by process name.
    try:
        parent = proc.parent()
        pname = parent.name() if parent else ""
    except psutil.Error:
        pname = ""

    for marker, label, hint in (
        ("supervisord", "supervisor", "supervisorctl restart <program>"),
        ("pm2", "pm2", "pm2 restart <app>"),
    ):
        if marker in pname:
            return label, hint

    # Anything else is unmanaged — including a process re-parented to pid 1
    # because its launching shell exited. Nothing will bring that back on its own.
    return None, None


def _collect_sockets() -> dict[int, dict]:
    """Group LISTEN sockets by port, remembering every bind address."""
    ports: dict[int, dict] = {}
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_LISTEN:
            continue
        port = conn.laddr.port
        entry = ports.setdefault(port, {"addresses": set(), "families": set(), "pid": None})
        entry["addresses"].add(conn.laddr.ip)
        entry["families"].add("IPv6" if conn.family == socket.AF_INET6 else "IPv4")
        if conn.pid:
            entry["pid"] = conn.pid
    return ports


def scan(probe: bool = True, timeout: float = 1.5) -> list[Service]:
    """Enumerate every listening TCP port and everything we can learn about it."""
    me = os.getuid()
    services: list[Service] = []

    for port, entry in _collect_sockets().items():
        svc = Service(
            port=port,
            addresses=sorted(entry["addresses"]),
            families=sorted(entry["families"]),
            pid=entry["pid"],
            visible=entry["pid"] is not None,
        )
        if svc.pid:
            try:
                proc = psutil.Process(svc.pid)
                with proc.oneshot():
                    svc.name = proc.name()
                    svc.cmdline = proc.cmdline()
                    svc.create_time = proc.create_time()
                    svc.ppid = proc.ppid()
                    try:
                        svc.user = proc.username()
                    except (psutil.Error, KeyError):
                        pass
                    try:
                        svc.exe = proc.exe()
                    except (psutil.Error, OSError):
                        pass
                    try:
                        svc.cwd = proc.cwd()
                    except (psutil.Error, OSError):
                        pass
                    try:
                        svc.memory_mb = round(proc.memory_info().rss / 1048576, 1)
                    except psutil.Error:
                        pass
                    try:
                        svc.controllable = proc.uids().real == me or me == 0
                    except psutil.Error:
                        svc.controllable = False
                try:
                    svc.children = len(proc.children(recursive=True))
                except psutil.Error:
                    pass
                parent = proc.parent()
                if parent:
                    try:
                        svc.parent_name = parent.name()
                        svc.parent_cmdline = " ".join(parent.cmdline())[:300]
                    except psutil.Error:
                        pass
                svc.supervised_by, svc.restart_hint = _supervisor(proc)
                svc.project = _project_name(svc.cwd)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                svc.visible = False
        services.append(svc)

    if probe:
        targets = []
        for svc in services:
            host = "127.0.0.1"
            if svc.addresses and all(a in ("::", "::1") for a in svc.addresses):
                host = "::1"
            targets.append((svc, host))
        with ThreadPoolExecutor(max_workers=24) as pool:
            futures = {pool.submit(fingerprint, host, s.port, timeout): s for s, host in targets}
            for future, svc in futures.items():
                try:
                    svc.probe = future.result()
                except Exception as exc:  # a probe must never sink the scan
                    svc.probe = Probe(error=str(exc))

    services.sort(key=lambda s: (s.kind != "web", s.port))
    return services
