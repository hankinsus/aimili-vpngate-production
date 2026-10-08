#!/usr/bin/env python3
from __future__ import annotations
import json
import errno
import fcntl
import base64
import ipaddress
import os
import re
import secrets
import select
import socket
import subprocess
import threading
import urllib.parse
import time
from pathlib import Path
from typing import Any

def parse_positive_int(value: str | None, default: int) -> int:
    try:
        return max(1, int(value or default))
    except (TypeError, ValueError):
        return default

MAX_PROXY_CONNECTIONS = parse_positive_int(os.environ.get("LOCAL_PROXY_MAX_CONNECTIONS"), 256)
proxy_connection_sem = threading.BoundedSemaphore(MAX_PROXY_CONNECTIONS)

# Keep DNS results for a short time so each HTTPS connection does not pay for
# another DNS round trip over the active VPN interface.
DNS_CACHE_TTL_SECONDS = 60.0
DNS_NEGATIVE_TTL_SECONDS = 30.0
DNS_POSITIVE_MIN_SECONDS = 30.0
DNS_POSITIVE_MAX_SECONDS = 300.0
DNS_STAGE_TIMEOUT_SECONDS = 1.0
DNS_TUNNEL_RESOLVERS = ("8.8.8.8", "8.8.4.4")
DNS_CACHE: dict[tuple[str, str], tuple[float, str | None]] = {}
DNS_CACHE_LOCK = threading.Lock()
_DNS_FLIGHTS: dict[tuple[str, str], tuple[threading.Event, dict[str, str | None]]] = {}
_DNS_BIND_LOG_AT: dict[str, float] = {}
PROXY_SOCKET_BUFFER_BYTES = 262144
PROXY_UDP_ASSOCIATION_IDLE_SECONDS = 6 * 3600
PROXY_UDP_MAX_PACKET_BYTES = 65535
_last_forward_mono = 0.0
_forward_dirty = False

def note_proxy_forwarded(nbytes: int = 0) -> None:
    """Count forwarded bytes in memory. A side thread writes the timestamp."""
    global _last_forward_mono, _forward_dirty
    if nbytes <= 0:
        return
    _last_forward_mono = time.monotonic()
    _forward_dirty = True


def _forward_heartbeat() -> None:
    global _forward_dirty
    while True:
        time.sleep(1.0)
        if not _forward_dirty:
            _write_dataplane_snapshot()
            time.sleep(1.0)
            continue
        _forward_dirty = False
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            path = DATA_DIR / "proxy_forward_at"
            tmp = path.with_suffix(".tmp")
            tmp.write_text(str(time.time()), encoding="utf-8")
            tmp.replace(path)
            _write_dataplane_snapshot()
        except OSError:
            pass

def proxy_forwarding_busy(grace: float = 3.0) -> bool:
    """True while client bytes have moved across 8500 inside the grace window."""
    grace = max(0.0, float(grace))
    if (time.monotonic() - _last_forward_mono) < grace:
        return True
    try:
        ts = float((DATA_DIR / "proxy_forward_at").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return (time.time() - ts) < grace

DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else Path(__file__).resolve().parent / "vpngate_data"
ACTIVE_IFACE_FILE = DATA_DIR / "active_iface.txt"

_iface_cache_value = ""
_iface_cache_at = 0.0
_iface_cache_token: tuple[int, int] | None = None
_DIRECT_IFACE_SENTINELS = {"", "-", "direct", "default"}

def _normalize_iface(iface: str) -> str:
    iface = str(iface or "").strip()
    if iface.lower() in _DIRECT_IFACE_SENTINELS:
        return ""
    return iface

def get_active_interface() -> str:
    """Tunnel NIC, or "" when direct / unset. Never invent tun0."""
    global _iface_cache_value, _iface_cache_at, _iface_cache_token
    env_iface = str(os.environ.get("ACTIVE_TUNNEL_IFACE") or "").strip()
    if env_iface:
        return _normalize_iface(env_iface)
    try:
        st = ACTIVE_IFACE_FILE.stat()
        token = (int(st.st_mtime_ns), int(st.st_size))
    except OSError:
        _iface_cache_value = ""
        _iface_cache_token = None
        _iface_cache_at = time.monotonic()
        return ""
    if token == _iface_cache_token:
        return _iface_cache_value
    try:
        iface = _normalize_iface(ACTIVE_IFACE_FILE.read_text(encoding="utf-8"))
    except OSError:
        iface = ""
    _iface_cache_value = iface
    _iface_cache_token = token
    _iface_cache_at = time.monotonic()
    return iface

_last_tuned_iface = ""

def _iptables_mss(action: str, iface: str) -> None:
    subprocess.run(
        [
            "iptables", "-t", "mangle", action, "OUTPUT",
            "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS", "--clamp-mss-to-pmtu",
        ],
        capture_output=True, text=True, timeout=3,
    )

def tune_forwarding_interface(iface: str) -> None:
    """Keep a short fair queue on the tunnel NIC and clamp TCP MSS.

    One video flow must not fill a 1000-packet FIFO and block web requests.
    Do not overwrite a negotiated MTU that is already at or below 1400.
    Only an oversized device, such as an SSTP PPP that came up at 1500, is
    lowered. OpenVPN, SoftEther and L2TP keep the MTU they negotiated.
    """
    global _last_tuned_iface
    iface = str(iface or "").strip()
    if not iface or not re.fullmatch(r"[A-Za-z0-9._:-]{1,15}", iface):
        return
    if _last_tuned_iface and _last_tuned_iface != iface:
        try:
            _iptables_mss("-D", _last_tuned_iface)
        except Exception:
            pass
    try:
        subprocess.run(
            ["ip", "link", "set", "dev", iface, "txqueuelen", "80"],
            capture_output=True, text=True, timeout=3,
        )
        subprocess.run(
            ["tc", "qdisc", "replace", "dev", iface, "root", "fq_codel",
             "limit", "1024", "flows", "1024", "target", "20ms", "interval", "100ms"],
            capture_output=True, text=True, timeout=3,
        )
        shown = subprocess.run(
            ["ip", "-o", "link", "show", "dev", iface],
            capture_output=True, text=True, timeout=2,
        )
        mtu = 0
        parts = (shown.stdout or "").split()
        if "mtu" in parts:
            mtu = parse_int(parts[parts.index("mtu") + 1])
        if mtu > 1400:
            subprocess.run(
                ["ip", "link", "set", "dev", iface, "mtu", "1400"],
                capture_output=True, text=True, timeout=3,
            )
    except Exception:
        pass
    try:
        check = subprocess.run(
            [
                "iptables", "-t", "mangle", "-C", "OUTPUT",
                "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                "-j", "TCPMSS", "--clamp-mss-to-pmtu",
            ],
            capture_output=True, text=True, timeout=3,
        )
        if check.returncode != 0:
            _iptables_mss("-A", iface)
    except Exception:
        pass
    _last_tuned_iface = iface

def set_active_interface(iface: str) -> None:
    iface = str(iface or "").strip()
    if not iface:
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = ACTIVE_IFACE_FILE.with_suffix(".tmp")
    tmp.write_text(iface, encoding="utf-8")
    tmp.replace(ACTIVE_IFACE_FILE)
    tune_forwarding_interface(iface)

def clear_active_interface() -> None:
    """Direct mode. An empty file is visible to the proxy process; unlink looked like tun0."""
    global _iface_cache_value, _iface_cache_at, _iface_cache_token
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = ACTIVE_IFACE_FILE.with_suffix(".tmp")
        tmp.write_text("", encoding="utf-8")
        tmp.replace(ACTIVE_IFACE_FILE)
    except OSError:
        try:
            ACTIVE_IFACE_FILE.unlink(missing_ok=True)
        except Exception:
            pass
    _iface_cache_value = ""
    _iface_cache_token = None
    _iface_cache_at = 0.0

_egress_mode_cache = ""
_egress_mode_at = 0.0
_physical_iface_cache = ""
_physical_iface_at = 0.0

def get_egress_mode() -> str:
    global _egress_mode_cache, _egress_mode_at
    now = time.monotonic()
    if _egress_mode_cache and now - _egress_mode_at < 0.05:
        return _egress_mode_cache
    mode = "proxy"
    try:
        raw = (DATA_DIR / "egress_mode.txt").read_text(encoding="utf-8").strip().lower()
        if raw == "direct":
            mode = "direct"
    except OSError:
        pass
    _egress_mode_cache = mode
    _egress_mode_at = now
    return mode

def set_egress_mode(mode: str) -> str:
    global _egress_mode_cache, _egress_mode_at
    mode = "direct" if str(mode or "").strip().lower() == "direct" else "proxy"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / "egress_mode.txt"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(mode, encoding="utf-8")
    tmp.replace(path)
    _egress_mode_cache = mode
    _egress_mode_at = time.monotonic()
    return mode

def physical_egress_interface() -> str:
    """Server NIC that owns the default route. Never a tunnel device."""
    global _physical_iface_cache, _physical_iface_at
    now = time.monotonic()
    if _physical_iface_cache and now - _physical_iface_at < 5:
        return _physical_iface_cache
    iface = ""
    try:
        res = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=2,
        )
        for line in (res.stdout or "").splitlines():
            parts = line.split()
            if "dev" not in parts:
                continue
            dev = parts[parts.index("dev") + 1]
            if dev.startswith(("tun", "tap", "vpn", "ppp", "wg", "lo")):
                continue
            iface = dev
            break
    except Exception:
        iface = ""
    if not iface:
        return _physical_iface_cache
    _physical_iface_cache = iface
    _physical_iface_at = now
    return iface

def get_forward_interface() -> str:
    """Interface the local proxy binds to. Direct mode uses the server NIC."""
    if get_egress_mode() == "direct":
        return physical_egress_interface()
    return get_active_interface()


_live_clients: set[socket.socket] = set()
_client_generation: dict[socket.socket, int] = {}
_udp_controls: set[socket.socket] = set()
_egress_generation = 0
_switch_report = {
    "generation": 0,
    "mode": "",
    "old_iface": "",
    "new_iface": "",
    "tcp_scheduled": 0,
    "tcp_old_closed": 0,
    "udp_live": 0,
    "udp_associations_rotated": 0,
}
_live_clients_lock = threading.Lock()


def egress_switch_report() -> dict[str, Any]:
    with _live_clients_lock:
        return dict(_switch_report)


def _note_udp_rotation() -> None:
    with _live_clients_lock:
        _switch_report["udp_associations_rotated"] = int(_switch_report.get("udp_associations_rotated") or 0) + 1


_dataplane_lock = threading.Lock()
_quic_flows: dict[str, dict[str, Any]] = {}
_quic_hosts: dict[str, float] = {}
_tcp443_at: list[float] = []
_retrans_samples: list[tuple[float, int, int]] = []
_dataplane = {
    "quic_flow_created": 0,
    "quic_flow_reused": 0,
    "quic_flow_rotated": 0,
    "quic_flow_timeout": 0,
    "quic_fallback_tcp": 0,
    "tcp_retrans_delta": 0,
    "tcp443_flows": 0,
    "jitter": False,
}


def _tcp_retrans_segs() -> int:
    try:
        lines = Path("/proc/net/snmp").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0
    for index, line in enumerate(lines):
        if not line.startswith("Tcp:") or index + 1 >= len(lines) or not lines[index + 1].startswith("Tcp:"):
            continue
        header = line.split()
        values = lines[index + 1].split()
        if "RetransSegs" not in header or len(values) <= header.index("RetransSegs"):
            return 0
        try:
            return int(values[header.index("RetransSegs")])
        except ValueError:
            return 0
    return 0


def _note_quic_packet(host: str, generation: int, iface: str) -> None:
    host = str(host or "").strip().lower().rstrip(".")
    if not host:
        return
    now = time.monotonic()
    with _dataplane_lock:
        _quic_hosts[host] = now
        flow = _quic_flows.get(host)
        if flow is None:
            _dataplane["quic_flow_created"] = int(_dataplane["quic_flow_created"]) + 1
            _quic_flows[host] = {"last": now, "generation": generation, "iface": iface}
            return
        if int(flow.get("generation") or -1) != generation or str(flow.get("iface") or "") != iface:
            _dataplane["quic_flow_rotated"] = int(_dataplane["quic_flow_rotated"]) + 1
            flow["generation"] = generation
            flow["iface"] = iface
        else:
            _dataplane["quic_flow_reused"] = int(_dataplane["quic_flow_reused"]) + 1
        flow["last"] = now


def _note_quic_rotated(count: int) -> None:
    if count <= 0:
        return
    with _dataplane_lock:
        _dataplane["quic_flow_rotated"] = int(_dataplane["quic_flow_rotated"]) + count


def _note_tcp_host(host: str, port: int) -> None:
    if int(port) != 443:
        return
    host = str(host or "").strip().lower().rstrip(".")
    now = time.monotonic()
    with _dataplane_lock:
        _tcp443_at.append(now)
        del _tcp443_at[:-400]
        seen = _quic_hosts.get(host)
        if seen and now - seen < 20:
            _dataplane["quic_fallback_tcp"] = int(_dataplane["quic_fallback_tcp"]) + 1


def _expire_quic_flows(now: float) -> None:
    stale = [host for host, flow in _quic_flows.items() if now - float(flow.get("last") or 0) > 30]
    if stale:
        _dataplane["quic_flow_timeout"] = int(_dataplane["quic_flow_timeout"]) + len(stale)
        for host in stale:
            _quic_flows.pop(host, None)
    cutoff = now - 60
    for host, seen in list(_quic_hosts.items()):
        if seen < cutoff:
            _quic_hosts.pop(host, None)


def dataplane_snapshot() -> dict[str, Any]:
    now = time.monotonic()
    retrans = _tcp_retrans_segs()
    with _live_clients_lock:
        tcp_sessions = len(_live_clients)
        udp_associations = len(_udp_controls)
    pressure = _accept_pressure()
    with _dataplane_lock:
        _expire_quic_flows(now)
        _retrans_samples.append((now, retrans, int(_dataplane["quic_fallback_tcp"])))
        _retrans_samples[:] = [item for item in _retrans_samples if now - item[0] <= 20]
        base = _retrans_samples[0]
        delta = max(0, retrans - int(base[1]))
        fallback_delta = max(0, int(_dataplane["quic_fallback_tcp"]) - int(base[2]))
        recent_tcp = sum(1 for item in _tcp443_at if now - item <= 15)
        # Whole-host RetransSegs also counts probes. A healthy Japan path
        # can retransmit a few dozen segments with no client session open.
        jitter = tcp_sessions > 0 and (delta >= 80 or fallback_delta >= 8)
        _dataplane["tcp_retrans_delta"] = delta
        _dataplane["tcp443_flows"] = recent_tcp
        _dataplane["jitter"] = jitter
        snap = dict(_dataplane)
        snap.update({
            "active_tcp_sessions": tcp_sessions,
            "active_udp_associations": udp_associations,
            "active_connections": tcp_sessions,
            "queued_connections": pressure["queued"],
            "worker_busy": tcp_sessions,
            "accept_wait_ms": pressure["accept_wait_ms"],
            "udp443_flows": len(_quic_flows),
            "at": time.time(),
        })
    return snap


_accept_gate = threading.Lock()
_accept_queued = 0
_accept_queued_since = 0.0
_accept_wait_ms = 0
_accept_alarm_at = 0.0


def _note_accept_queued() -> None:
    global _accept_queued, _accept_queued_since
    with _accept_gate:
        _accept_queued += 1
        if _accept_queued_since <= 0:
            _accept_queued_since = time.monotonic()


def _note_accept_started(accepted_at: float) -> None:
    global _accept_queued, _accept_queued_since, _accept_wait_ms
    wait_ms = max(0, int((time.monotonic() - accepted_at) * 1000))
    with _accept_gate:
        _accept_queued = max(0, _accept_queued - 1)
        if _accept_queued == 0:
            _accept_queued_since = 0.0
        _accept_wait_ms = wait_ms


def _accept_pressure() -> dict[str, int]:
    with _accept_gate:
        queued = _accept_queued
        since = _accept_queued_since
        wait_ms = _accept_wait_ms
    stalled = queued > 0 and since > 0 and (time.monotonic() - since) >= 1.0
    return {"queued": queued, "accept_wait_ms": wait_ms, "stalled": int(stalled)}


def _warn_accept_queue() -> None:
    global _accept_alarm_at
    pressure = _accept_pressure()
    if not pressure["stalled"]:
        return
    now = time.monotonic()
    if now - _accept_alarm_at < 5:
        return
    _accept_alarm_at = now
    print(
        f"[8500 排队] queued_connections={pressure['queued']} accept_wait_ms={pressure['accept_wait_ms']} 新连接等了超过 1 秒",
        flush=True,
    )


def _write_dataplane_snapshot() -> None:
    _warn_accept_queue()
    snap = dataplane_snapshot()
    try:
        path = DATA_DIR / "dataplane.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(snap, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


_stage_local = threading.local()


def _stage_begin(accepted_at: float | None = None) -> None:
    now = time.monotonic()
    _stage_local.marks = {"accept": accepted_at or now, "run": now}
    _stage_local.logged = False


def _stage_mark(name: str) -> None:
    marks = getattr(_stage_local, "marks", None)
    if marks is not None and name not in marks:
        marks[name] = time.monotonic()


def _stage_ms(start: str, end: str) -> int:
    marks = getattr(_stage_local, "marks", None) or {}
    if start not in marks or end not in marks:
        return 0
    return max(0, int((marks[end] - marks[start]) * 1000))


def _stage_log(host: str, port: int) -> None:
    marks = getattr(_stage_local, "marks", None)
    if not marks or getattr(_stage_local, "logged", False):
        return
    _stage_local.logged = True
    _note_tcp_host(host, port)
    stages = {
        "socks_accept_ms": _stage_ms("accept", "run"),
        "auth_ms": _stage_ms("auth_start", "auth"),
        "dns_ms": _stage_ms("dns_start", "dns"),
        "upstream_connect_ms": _stage_ms("connect_start", "connect"),
        "socks_reply_ms": _stage_ms("connect", "reply"),
        "splice_start_ms": _stage_ms("reply", "splice"),
        "first_byte_ms": _stage_ms("splice", "first_byte"),
    }
    overhead = stages["socks_accept_ms"] + stages["auth_ms"] + stages["dns_ms"] + stages["socks_reply_ms"] + stages["splice_start_ms"]
    if overhead <= 300 and max(stages.values()) <= 300:
        return
    print(
        "[8500 慢连接] "
        + f"{host}:{port} "
        + " ".join(f"{name}={value}" for name, value in stages.items())
        + f" overhead_ms={overhead}",
        flush=True,
    )


def _current_egress_generation() -> int:
    with _live_clients_lock:
        return _egress_generation


def _track_client(client: socket.socket) -> None:
    with _live_clients_lock:
        _live_clients.add(client)
        _client_generation[client] = _egress_generation


def _untrack_client(client: socket.socket) -> None:
    with _live_clients_lock:
        _live_clients.discard(client)
        _client_generation.pop(client, None)
        _udp_controls.discard(client)


def _keep_udp_control(client: socket.socket) -> None:
    """Leave the SOCKS UDP control connection up when the exit changes."""
    with _live_clients_lock:
        _udp_controls.add(client)
        _live_clients.discard(client)
        _client_generation.pop(client, None)


def _close_tracked_clients(clients: list[socket.socket]) -> int:
    closed = 0
    for client in clients:
        try:
            client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            client.close()
            closed += 1
        except OSError:
            pass
    return closed


def _drop_live_clients() -> int:
    with _live_clients_lock:
        clients = list(_live_clients)
    return _close_tracked_clients(clients)


def _publish_egress_generation() -> int:
    """Move new accepts onto the next generation. Return the one being retired."""
    global _egress_generation
    with _live_clients_lock:
        retired = _egress_generation
        _egress_generation += 1
        tcp_scheduled = sum(
            1 for sock, gen in _client_generation.items()
            if gen <= retired and sock not in _udp_controls
        )
        _switch_report["generation"] = _egress_generation
        _switch_report["tcp_scheduled"] = tcp_scheduled
        _switch_report["tcp_old_closed"] = 0
        _switch_report["udp_live"] = len(_udp_controls)
        _switch_report["udp_associations_rotated"] = 0
        return retired


def _retire_old_generation(retired: int, pause: float = 0.5) -> None:
    """Close old TCP sockets after a short grace. Keep UDP ASSOCIATE controls.

    Those controls drop their upstream UDP sockets themselves as soon as they
    see the new generation, then bind the next packet to the new interface.
    """
    def _run() -> None:
        time.sleep(pause if pause > 0 else 0.5)
        with _live_clients_lock:
            stale = [
                sock for sock, gen in _client_generation.items()
                if gen <= retired and sock not in _udp_controls
            ]
            udp_kept = len(_udp_controls)
        closed = _close_tracked_clients(stale)
        with _live_clients_lock:
            _switch_report["tcp_old_closed"] = closed
            udp_kept = int(_switch_report.get("udp_live") or 0)
        print(f"[网关] 旧连接代际 {retired} 已关闭 TCP {closed} 条，保留 UDP 关联 {udp_kept} 个", flush=True)

    threading.Thread(target=_run, name="egress-retire", daemon=True).start()


def _write_applied(name: str, value: str) -> None:
    path = DATA_DIR / name
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(value, encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def _write_egress_applied(mode: str) -> None:
    _write_applied("egress_mode.applied", mode)


def _read_active_iface_file() -> str:
    try:
        return _normalize_iface(ACTIVE_IFACE_FILE.read_text(encoding="utf-8"))
    except OSError:
        return ""


def _read_egress_mode_file() -> str:
    try:
        raw = (DATA_DIR / "egress_mode.txt").read_text(encoding="utf-8").strip().lower()
    except OSError:
        return "proxy"
    return "direct" if raw == "direct" else "proxy"


def _watch_egress_mode() -> None:
    """Cut old sockets when the exit or the active VPN NIC changes."""
    current = _read_egress_mode_file()
    current_iface = _read_active_iface_file()
    _write_egress_applied(current)
    _write_applied("active_iface.applied", current_iface)
    while True:
        time.sleep(0.1)
        mode = _read_egress_mode_file()
        iface = _read_active_iface_file()
        if mode == current and iface == current_iface:
            continue
        previous_iface = current_iface
        mode_changed = mode != current
        iface_changed = iface != current_iface
        current = mode
        current_iface = iface
        retired = _publish_egress_generation()
        with _live_clients_lock:
            _switch_report["mode"] = mode
            _switch_report["old_iface"] = previous_iface
            _switch_report["new_iface"] = iface
        with DNS_CACHE_LOCK:
            DNS_CACHE.clear()
        with _UDP_DEST_LOCK:
            _UDP_DEST_CACHE.clear()
        if mode_changed:
            _write_egress_applied(mode)
        if iface_changed:
            _write_applied("active_iface.applied", iface)
        _retire_old_generation(retired, 0.5)
        label = "服务器直连" if mode == "direct" else (iface or "代理隧道")
        print(f"[网关] 出口已切到 {label}，新连接走代际 {retired + 1}，旧代际 {retired} 0.5 秒后关闭", flush=True)


def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    _quickack(sock)
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Unexpected disconnect.")
        data += chunk
        _quickack(sock)
    return data

def parse_host_port(authority: str, default_port: int) -> tuple[str, int]:
    authority = authority.strip()
    if authority.startswith("["):
        host_part, sep, rest = authority.partition("]")
        host = host_part.lstrip("[")
        port = default_port
        if sep and rest.startswith(":"):
            port_text = rest[1:]
            port = parse_int(port_text) or default_port
        return host, port
    if authority.count(":") == 1:
        host, _, port_text = authority.rpartition(":")
        return host, parse_int(port_text) or default_port
    return authority, default_port

def get_proxy_credentials() -> tuple[str | None, str | None]:
    user = os.environ.get("LOCAL_PROXY_USER") or os.environ.get("LOCAL_PROXY_USERNAME")
    password = os.environ.get("LOCAL_PROXY_PASS") or os.environ.get("LOCAL_PROXY_PASSWORD")
    if user is None and password is None:
        return None, None
    return user or "", password or ""

def get_proxy_allowlist() -> list[Any]:
    raw = str(os.environ.get("LOCAL_PROXY_ALLOW", "127.0.0.1/32,::1/128") or "").strip()
    if raw.lower() in {"*", "any", "all"}:
        return [ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")]
    networks = []
    for item in raw.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            print(f"[代理访问控制] 忽略无效地址/CIDR: {item}", flush=True)
    return networks

def proxy_client_allowed(address: tuple[str, int]) -> bool:
    try:
        client_ip = ipaddress.ip_address(address[0])
        if isinstance(client_ip, ipaddress.IPv6Address) and client_ip.ipv4_mapped:
            client_ip = client_ip.ipv4_mapped
    except ValueError:
        return False
    allowlist = get_proxy_allowlist()
    return bool(allowlist) and any(client_ip in network for network in allowlist)

def proxy_auth_enabled() -> bool:
    user, password = get_proxy_credentials()
    return user is not None and password is not None

def parse_http_basic_auth(lines: list[str]) -> tuple[str | None, str | None]:
    for line in lines:
        name, sep, value = line.partition(":")
        if not sep or name.strip().lower() != "proxy-authorization":
            continue
        scheme, _, token = value.strip().partition(" ")
        if scheme.lower() != "basic" or not token:
            return None, None
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="replace")
        except Exception:
            return None, None
        username, sep, password = decoded.partition(":")
        if not sep:
            return None, None
        return username, password
    return None, None

def check_credentials(username: str | None, password: str | None) -> bool:
    expected_user, expected_pass = get_proxy_credentials()
    if expected_user is None or expected_pass is None:
        return True
    return secrets.compare_digest(username or "", expected_user) and secrets.compare_digest(password or "", expected_pass)

def _socks5_pack_udp(destination: tuple[str, int], payload: bytes) -> bytes:
    host, port = destination
    try:
        ipaddress.ip_address(host)
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv4Address):
            addr = b"\x01" + ip.packed
        else:
            addr = b"\x04" + ip.packed
    except ValueError:
        raw = host.encode("idna")
        if len(raw) > 255:
            raise ValueError("UDP destination hostname too long")
        addr = b"\x03" + bytes([len(raw)]) + raw
    return b"\x00\x00\x00" + addr + int(port).to_bytes(2, "big") + payload


def _socks5_unpack_udp(packet: bytes) -> tuple[str, int, bytes] | None:
    if len(packet) < 4 or packet[0:2] != b"\x00\x00" or packet[2] != 0:
        return None
    offset = 4
    atyp = packet[3]
    try:
        if atyp == 1:
            if len(packet) < offset + 4 + 2:
                return None
            host = socket.inet_ntoa(packet[offset:offset + 4])
            offset += 4
        elif atyp == 3:
            if len(packet) < offset + 1:
                return None
            size = packet[offset]
            offset += 1
            if len(packet) < offset + size + 2:
                return None
            host = packet[offset:offset + size].decode("idna")
            offset += size
        elif atyp == 4:
            if len(packet) < offset + 16 + 2:
                return None
            host = socket.inet_ntop(socket.AF_INET6, packet[offset:offset + 16])
            offset += 16
        else:
            return None
        port = int.from_bytes(packet[offset:offset + 2], "big")
        payload = packet[offset + 2:]
        if not payload:
            return None
        return host, port, payload
    except (OSError, UnicodeError, ValueError):
        return None


def _set_udp_socket_options(sock: socket.socket, bind_device: bool = True) -> None:
    for level, opt in (
        (socket.SOL_SOCKET, socket.SO_REUSEADDR),
        (socket.SOL_SOCKET, socket.SO_RCVBUF),
        (socket.SOL_SOCKET, socket.SO_SNDBUF),
    ):
        try:
            value = 1 if opt == socket.SO_REUSEADDR else PROXY_SOCKET_BUFFER_BYTES
            sock.setsockopt(level, opt, value)
        except OSError:
            pass
    if sock.family == socket.AF_INET:
        try:
            # 10 is IP_MTU_DISCOVER. 2 is IP_PMTUDISC_DO: refuse to fragment.
            mtu_discover = getattr(socket, "IP_MTU_DISCOVER", 10)
            sock.setsockopt(socket.IPPROTO_IP, mtu_discover, 2)
        except (OSError, AttributeError):
            pass
    if not bind_device:
        return
    try:
        iface = get_forward_interface()
        if iface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode("utf-8"))
    except OSError:
        raise


_UDP_DEST_CACHE: dict[tuple[str, str, str, int], tuple[float, list[tuple[int, tuple[Any, ...]]]]] = {}
_UDP_DEST_LOCK = threading.Lock()
_UDP_DEST_FLIGHTS: set[tuple[str, str, str, int]] = set()


def _resolve_udp_destinations(host: str, port: int) -> list[tuple[int, tuple[Any, ...]]]:
    host = str(host or "").strip()
    iface = get_forward_interface() or ""
    generation = _current_egress_generation()
    key = (str(generation), iface, host, int(port))
    now = time.monotonic()
    with _UDP_DEST_LOCK:
        cached = _UDP_DEST_CACHE.get(key)
        if cached and now - cached[0] < 60:
            return cached[1]
    literal = _host_is_ip(host)
    ip = literal or resolve_dns_over_active_tunnel(host, iface=get_forward_interface())
    if not ip:
        with _UDP_DEST_LOCK:
            _UDP_DEST_CACHE[key] = (now - 55.0, [])
        return []
    try:
        found = [
            (af, sa)
            for af, socktype, proto, canonname, sa in socket.getaddrinfo(
                ip, port, 0, socket.SOCK_DGRAM
            )
            if af in (socket.AF_INET, socket.AF_INET6)
        ]
    except OSError:
        return []
    with _UDP_DEST_LOCK:
        if len(_UDP_DEST_CACHE) > 512:
            _UDP_DEST_CACHE.clear()
        _UDP_DEST_CACHE[key] = (now, found)
    return found


def _udp_destinations_ready(host: str, port: int) -> list[tuple[int, tuple[Any, ...]]]:
    """Never block the relay. A new name resolves on the side; the datagram waits for the retry."""
    host = str(host or "").strip()
    if _host_is_ip(host):
        return _resolve_udp_destinations(host, port)
    iface = get_forward_interface() or ""
    generation = _current_egress_generation()
    key = (str(generation), iface, host, int(port))
    now = time.monotonic()
    start = False
    with _UDP_DEST_LOCK:
        cached = _UDP_DEST_CACHE.get(key)
        if cached and now - cached[0] < 60:
            return cached[1]
        if key not in _UDP_DEST_FLIGHTS:
            _UDP_DEST_FLIGHTS.add(key)
            start = True
    if start:
        def run() -> None:
            try:
                _resolve_udp_destinations(host, port)
            finally:
                with _UDP_DEST_LOCK:
                    _UDP_DEST_FLIGHTS.discard(key)
        threading.Thread(target=run, daemon=True, name="udp-dns").start()
    return []


def _socks5_reply_ipv4(client: socket.socket) -> str:
    """Address the remote client can send UDP to. Never its own 127.0.0.1."""
    try:
        peer_ip = str(client.getpeername()[0] or "")
    except OSError:
        peer_ip = ""
    if peer_ip in ("127.0.0.1", "::1"):
        return "127.0.0.1"
    try:
        local_ip = str(client.getsockname()[0] or "")
    except OSError:
        local_ip = ""
    if local_ip.startswith("::ffff:"):
        local_ip = local_ip[7:]
    try:
        socket.inet_aton(local_ip)
        if local_ip not in ("0.0.0.0", "127.0.0.1"):
            return local_ip
    except OSError:
        pass
    return "0.0.0.0"


def socks5_udp_associate(client: socket.socket, control_address: tuple[str, int]) -> None:
    """RFC 1928 UDP ASSOCIATE relay over the active VPN interface."""
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstreams: dict[tuple, socket.socket] = {}
    client_ip = str(control_address[0] or "")
    client_udp_addr: tuple[str, int] | None = None
    last_activity = time.monotonic()
    association_generation = _current_egress_generation()
    association_iface = get_forward_interface() or ""
    _keep_udp_control(client)

    def _drop_upstreams() -> None:
        for old in upstreams.values():
            try:
                old.close()
            except OSError:
                pass
        upstreams.clear()

    def _rotate_if_needed() -> bool:
        nonlocal association_generation, association_iface
        current_generation = _current_egress_generation()
        current_iface = get_forward_interface() or ""
        if not current_iface:
            current_iface = association_iface
        if current_iface == association_iface:
            association_generation = current_generation
            return False
        quic_live = sum(1 for key in upstreams if key and key[0] == "quic")
        had_upstream = bool(upstreams)
        old_iface = association_iface
        _drop_upstreams()
        association_generation = current_generation
        association_iface = current_iface
        if had_upstream:
            _note_udp_rotation()
            _note_quic_rotated(quic_live)
            print(
                f"[SOCKS5 UDP] udp_generation={association_generation} {old_iface or '-'} -> {association_iface or '-'} upstream sockets recreated",
                flush=True,
            )
        return True

    try:
        _set_udp_socket_options(relay, bind_device=False)
        relay.bind(("0.0.0.0", 0))
        bind_port = int(relay.getsockname()[1])
        reply_ip = _socks5_reply_ipv4(client)
        reply_octets = socket.inet_aton(reply_ip if reply_ip != "0.0.0.0" else "0.0.0.0")
        client.sendall(b"\x05\x00\x00\x01" + reply_octets + bind_port.to_bytes(2, "big"))
        relay.setblocking(False)
        client.setblocking(False)

        while time.monotonic() - last_activity < PROXY_UDP_ASSOCIATION_IDLE_SECONDS:
            sources: list[socket.socket] = [client, relay]
            sources.extend(upstreams.values())
            readable, _, errored = select.select(sources, [], sources, 0.2)
            rotated = _rotate_if_needed()
            if rotated:
                readable = [source for source in readable if source is client or source is relay]
            if errored:
                return

            if not readable:
                continue

            for source in readable:
                if source is client:
                    try:
                        data = client.recv(1)
                    except BlockingIOError:
                        data = b""
                    if not data:
                        return
                    last_activity = time.monotonic()
                    continue

                if source is relay:
                    for _ in range(24):
                        try:
                            packet, peer = relay.recvfrom(PROXY_UDP_MAX_PACKET_BYTES)
                        except BlockingIOError:
                            break
                        peer_ip = str(peer[0] or "")
                        if peer_ip != client_ip and not (
                            client_ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1")
                            and peer_ip == "127.0.0.1"
                        ):
                            continue
                        decoded = _socks5_unpack_udp(packet)
                        if not decoded:
                            continue
                        host, port, payload = decoded
                        if _rotate_if_needed():
                            pass
                        destinations = _udp_destinations_ready(host, port)
                        destinations.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
                        destinations = [item for item in destinations if item[0] == socket.AF_INET]
                        if not destinations:
                            continue
                        client_udp_addr = (peer_ip, int(peer[1]))
                        if port in (500, 4500):
                            now_mono = time.monotonic()
                            if now_mono - float(getattr(socks5_udp_associate, "ike_log_at", 0.0)) > 2:
                                socks5_udp_associate.ike_log_at = now_mono
                                print(f"[WiFi Calling] UDP {host}:{port} {len(payload)} bytes", flush=True)
                        kind = "wifi" if port in (500, 4500) else ("quic" if port == 443 else "other")
                        sent = False
                        for af, sa in destinations:
                            flow_key = (kind, af, "") if kind == "wifi" else (kind, af, sa[0])
                            sock = upstreams.get(flow_key)
                            if sock is None:
                                if len(upstreams) >= 32:
                                    for old_key in list(upstreams):
                                        if old_key == flow_key or old_key[0] == "wifi":
                                            continue
                                        old_sock = upstreams.pop(old_key, None)
                                        if old_sock is not None:
                                            try:
                                                old_sock.close()
                                            except OSError:
                                                pass
                                        break
                                try:
                                    sock = socket.socket(af, socket.SOCK_DGRAM)
                                    _set_udp_socket_options(sock)
                                    bind_addr = ("0.0.0.0", 0) if af == socket.AF_INET else ("::", 0)
                                    sock.bind(bind_addr)
                                    sock.setblocking(False)
                                    upstreams[flow_key] = sock
                                except OSError:
                                    if sock is not None:
                                        sock.close()
                                    continue
                            try:
                                sock.sendto(payload, sa)
                                sent = True
                                note_proxy_forwarded(len(payload))
                                if kind == "quic":
                                    _note_quic_packet(host, association_generation, association_iface)
                                break
                            except OSError as exc:
                                # One destination refused or the datagram is too big.
                                # This socket belongs to one peer, not every QUIC site.
                                if exc.errno in (11, 90, 101, 113):
                                    continue
                                try:
                                    sock.close()
                                except OSError:
                                    pass
                                upstreams.pop(flow_key, None)
                                continue
                        if sent:
                            last_activity = time.monotonic()
                    continue

                # Upstream UDP response -> SOCKS5 client UDP socket.
                for _ in range(24):
                    try:
                        response, source_addr = source.recvfrom(PROXY_UDP_MAX_PACKET_BYTES)
                    except BlockingIOError:
                        break
                    if client_udp_addr is not None:
                        try:
                            relay.sendto(
                                _socks5_pack_udp((str(source_addr[0]), int(source_addr[1])), response),
                                client_udp_addr,
                            )
                            note_proxy_forwarded(len(response))
                        except OSError:
                            break
                        last_activity = time.monotonic()
    except Exception as exc:
        print(f"[SOCKS5 UDP] UDP ASSOCIATE 失败: {exc}", flush=True)
    finally:
        _untrack_client(client)
        try:
            relay.close()
        except Exception:
            pass
        for sock in upstreams.values():
            try:
                sock.close()
            except Exception:
                pass


def _write_json_if_changed(path: Path, payload: dict[str, Any]) -> bool:
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    try:
        if path.is_file() and path.read_text(encoding="utf-8") == text:
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
        return True
    except OSError as exc:
        print(f"[内核] 写 {path} 失败: {exc}", flush=True)
        return False


def ensure_kernel_socks_outbounds() -> None:
    """Send sing-box and Xray out the tunnel with one fwmark.

    Table 100 is updated when the tunnel changes. These processes are not
    reloaded for that. 8500 stays on 127.0.0.1 for health checks only.
    """
    user, password = get_proxy_credentials()
    user = str(user or "")
    password = str(password or "")
    sing_path = Path("/etc/v2ray-agent/sing-box/conf/config/socks5_outbound.json")
    if (not user or not password) and sing_path.is_file():
        try:
            outbound = json.loads(sing_path.read_text(encoding="utf-8"))["outbounds"][0]
            user = user or str(outbound.get("username") or "")
            password = password or str(outbound.get("password") or "")
        except (OSError, KeyError, IndexError, TypeError, json.JSONDecodeError):
            pass
    sing_dir = Path("/etc/v2ray-agent/sing-box/conf/config")
    sing_root = Path("/etc/v2ray-agent/sing-box/conf")
    sing_bin = Path("/etc/v2ray-agent/sing-box/sing-box")
    changed = False
    if sing_dir.is_dir():
        changed = _write_json_if_changed(sing_dir / "socks5_outbound.json", {
            "outbounds": [{
                "type": "direct",
                "tag": "socks5_outbound",
                "routing_mark": 100,
                "domain_resolver": "tunnel-dns",
            }],
        }) or changed
        changed = _write_json_if_changed(sing_dir / "00_dns.json", {
            "dns": {
                "servers": [{
                    "type": "udp",
                    "tag": "tunnel-dns",
                    "server": "8.8.8.8",
                    "server_port": 53,
                    "routing_mark": 100,
                }],
                "strategy": "ipv4_only",
                "final": "tunnel-dns",
            },
        }) or changed
        if user and password:
            changed = _write_json_if_changed(sing_dir / "14_socks_inbounds.json", {
                "inbounds": [{
                    "type": "socks",
                    "tag": "aimili-socks",
                    "listen": "::",
                    "listen_port": 10808,
                    "users": [{"username": user, "password": password}],
                }],
            }) or changed
        if changed and sing_bin.is_file():
            config_path = sing_root / "config.json"
            backup = sing_root / "config.json.bak-direct"
            try:
                if config_path.is_file():
                    backup.write_bytes(config_path.read_bytes())
                merge = subprocess.run(
                    [str(sing_bin), "merge", "config.json", "-C", str(sing_dir), "-D", str(sing_root)],
                    capture_output=True, text=True, timeout=20,
                )
                check = subprocess.run(
                    [str(sing_bin), "check", "-c", str(config_path)],
                    capture_output=True, text=True, timeout=20,
                )
                if merge.returncode != 0 or check.returncode != 0:
                    detail = ((check.stderr or check.stdout or merge.stderr or merge.stdout or "").strip().splitlines() or ["未知错误"])[-1]
                    if backup.is_file():
                        config_path.write_bytes(backup.read_bytes())
                    print(f"[内核] sing-box 直连出站检查失败，保持原配置：{detail}", flush=True)
                else:
                    restarted = subprocess.run(["systemctl", "restart", "sing-box"], capture_output=True, text=True, timeout=20)
                    if restarted.returncode == 0:
                        print("[内核] sing-box 已改走标记 100，经路由表进入当前隧道。SOCKS 入站 10808。", flush=True)
                    else:
                        print(f"[内核] sing-box 重启失败：{(restarted.stderr or restarted.stdout or '').strip()}", flush=True)
            except (OSError, subprocess.TimeoutExpired) as exc:
                print(f"[内核] sing-box 出站没有切过去：{exc}", flush=True)
    if not user or not password:
        print("[内核] 未写 Xray 出站：缺少账号", flush=True)
        return
    conf_dir = Path("/etc/v2ray-agent/xray/conf")
    if not conf_dir.is_dir():
        return
    outbound_doc = {
        "outbounds": [{
            "protocol": "freedom",
            "tag": "socks5_outbound",
            "settings": {"domainStrategy": "UseIPv4"},
            "streamSettings": {"sockopt": {"mark": 100}},
        }]
    }
    _write_json_if_changed(conf_dir / "00_socks5_outbound.json", outbound_doc)
    route_path = conf_dir / "09_routing.json"
    route_text = ""
    try:
        route_text = route_path.read_text(encoding="utf-8") if route_path.is_file() else ""
    except OSError:
        route_text = ""
    if "socks5_outbound" not in route_text:
        _write_json_if_changed(route_path, {
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [{
                    "type": "field",
                    "network": "tcp,udp",
                    "outboundTag": "socks5_outbound",
                }],
            }
        })
    binary = Path("/etc/v2ray-agent/xray/xray")
    if not binary.is_file():
        print("[内核] Xray 程序不在。sing-box 已走标记路由。", flush=True)
        return
    try:
        test = subprocess.run(
            [str(binary), "run", "-test", "-confdir", str(conf_dir)],
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[内核] Xray 配置测试没有跑起来：{exc}", flush=True)
        return
    if test.returncode == 0:
        print("[内核] Xray freedom 标记 100 配置测试通过。未启动，避免抢 sing-box 端口。", flush=True)
    else:
        detail = ((test.stderr or test.stdout or "").strip().splitlines() or ["未知错误"])[-1]
        print(f"[内核] Xray 配置测试失败，未启动：{detail}", flush=True)


def probe_socks_udp_dns(timeout: float = 2.0) -> dict[str, Any]:
    """Open a new SOCKS5 UDP association and ask 8.8.8.8:53 for example.com."""
    port = int(os.environ.get("LOCAL_PROXY_PORT", "8500"))
    user, password = get_proxy_credentials()
    control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    query = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        control.settimeout(timeout)
        control.connect(("127.0.0.1", port))
        if user is not None and password is not None:
            control.sendall(b"\x05\x01\x02")
            if control.recv(2) != b"\x05\x02":
                return {"ok": False, "error": "SOCKS5 UDP 认证方法被拒绝"}
            user_b = user.encode("utf-8")
            pass_b = password.encode("utf-8")
            control.sendall(bytes([1, len(user_b)]) + user_b + bytes([len(pass_b)]) + pass_b)
            if control.recv(2) != b"\x01\x00":
                return {"ok": False, "error": "SOCKS5 UDP 认证失败"}
        else:
            control.sendall(b"\x05\x01\x00")
            if control.recv(2) != b"\x05\x00":
                return {"ok": False, "error": "SOCKS5 UDP 握手失败"}
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = control.recv(10)
        if len(reply) < 10 or reply[1] != 0:
            return {"ok": False, "error": "SOCKS5 UDP ASSOCIATE 失败"}
        relay_port = int.from_bytes(reply[8:10], "big")
        tx_id = secrets.token_bytes(2)
        dns = _build_dns_query("example.com", 1, tx_id)
        if not dns:
            return {"ok": False, "error": "DNS 查询构造失败"}
        header = b"\x00\x00\x00\x01" + socket.inet_aton("8.8.8.8") + (53).to_bytes(2, "big")
        query.settimeout(timeout)
        query.sendto(header + dns, ("127.0.0.1", relay_port))
        packet, _peer = query.recvfrom(2048)
        if len(packet) < 10 or packet[:3] != b"\x00\x00\x00":
            return {"ok": False, "error": "SOCKS5 UDP 回包无效"}
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        try:
            query.close()
        except OSError:
            pass
        try:
            control.close()
        except OSError:
            pass


def probe_socks_quic(timeout: float = 4.0) -> dict[str, Any]:
    """Real QUIC handshake through 8500. UDP DNS success is not this check."""
    target_name = "www.google.com"
    try:
        infos = socket.getaddrinfo(target_name, 443, socket.AF_INET, socket.SOCK_DGRAM)
        target_ip = str(infos[0][4][0]) if infos else ""
    except OSError as exc:
        return {"ok": False, "error": f"QUIC 目标解析失败: {exc}"}
    if not target_ip:
        return {"ok": False, "error": "QUIC 目标没有 IPv4"}
    port = int(os.environ.get("LOCAL_PROXY_PORT", "8500"))
    user, password = get_proxy_credentials()
    control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    query = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    shim = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stop = threading.Event()
    bridge: threading.Thread | None = None
    try:
        control.settimeout(min(2.0, timeout))
        control.connect(("127.0.0.1", port))
        if user is not None and password is not None:
            control.sendall(b"\x05\x01\x02")
            if control.recv(2) != b"\x05\x02":
                return {"ok": False, "error": "SOCKS5 QUIC 认证方法被拒绝"}
            user_b = user.encode("utf-8")
            pass_b = password.encode("utf-8")
            control.sendall(bytes([1, len(user_b)]) + user_b + bytes([len(pass_b)]) + pass_b)
            if control.recv(2) != b"\x01\x00":
                return {"ok": False, "error": "SOCKS5 QUIC 认证失败"}
        else:
            control.sendall(b"\x05\x01\x00")
            if control.recv(2) != b"\x05\x00":
                return {"ok": False, "error": "SOCKS5 QUIC 握手失败"}
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = control.recv(10)
        if len(reply) < 10 or reply[1] != 0:
            return {"ok": False, "error": "SOCKS5 QUIC ASSOCIATE 失败"}
        relay_port = int.from_bytes(reply[8:10], "big")
        shim.bind(("127.0.0.1", 0))
        shim_port = int(shim.getsockname()[1])
        client_box: dict[str, tuple[str, int]] = {}

        def _bridge() -> None:
            query.setblocking(False)
            shim.setblocking(False)
            while not stop.is_set():
                try:
                    readable, _, _ = select.select([shim, query], [], [], 0.2)
                except OSError:
                    return
                for source in readable:
                    try:
                        if source is shim:
                            data, addr = shim.recvfrom(65535)
                            client_box["peer"] = (str(addr[0]), int(addr[1]))
                            query.sendto(
                                _socks5_pack_udp((target_ip, 443), data),
                                ("127.0.0.1", relay_port),
                            )
                        else:
                            packet, _peer = query.recvfrom(65535)
                            decoded = _socks5_unpack_udp(packet)
                            peer = client_box.get("peer")
                            if not decoded or peer is None:
                                continue
                            shim.sendto(decoded[2], peer)
                    except (BlockingIOError, OSError):
                        continue

        bridge = threading.Thread(target=_bridge, daemon=True)
        bridge.start()
        proc = subprocess.run(
            [
                "openssl", "s_client", "-quic",
                "-connect", f"127.0.0.1:{shim_port}",
                "-servername", target_name,
                "-alpn", "h3",
                "-brief",
            ],
            input=b"",
            capture_output=True,
            timeout=timeout,
        )
        text = ((proc.stdout or b"") + (proc.stderr or b"")).decode("utf-8", "replace")
        if "CONNECTION ESTABLISHED" in text and "QUIC" in text:
            return {"ok": True}
        line = next((item.strip() for item in text.splitlines() if item.strip()), "QUIC 握手失败")
        return {"ok": False, "error": line[:180]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "QUIC 握手超时"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        stop.set()
        for sock in (shim, query, control):
            try:
                sock.close()
            except OSError:
                pass
        if bridge is not None:
            bridge.join(timeout=0.5)

def _host_is_ip(host: str) -> str | None:
    host = str(host or "").strip()
    if not host:
        return None
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        return None


def _build_dns_query(host: str, qtype: int, tx_id: bytes) -> bytes | None:
    qname = b""
    for part in host.split("."):
        if not part:
            continue
        part_bytes = part.encode("idna")
        if len(part_bytes) > 63:
            return None
        qname += len(part_bytes).to_bytes(1, "big") + part_bytes
    qname += b"\x00"
    return tx_id + b"\x01\x00" + b"\x00\x01" + b"\x00\x00\x00\x00\x00\x00" + qname + qtype.to_bytes(2, "big") + b"\x00\x01"


def _parse_dns_a(resp: bytes, tx_id: bytes, qtype: int) -> tuple[str | None, float]:
    try:
        if len(resp) < 12 or resp[:2] != tx_id:
            return None, 0.0
        if resp[3] & 0x0F:
            return None, 0.0
        offset = 12
        while offset < len(resp):
            length = resp[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                offset += 2
                break
            offset += 1 + length
        offset += 4
        answers = int.from_bytes(resp[6:8], "big")
        for _ in range(answers):
            if offset >= len(resp):
                break
            while offset < len(resp):
                length = resp[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += 1 + length
            if offset + 10 > len(resp):
                break
            atype = int.from_bytes(resp[offset:offset + 2], "big")
            aclass = int.from_bytes(resp[offset + 2:offset + 4], "big")
            ttl = int.from_bytes(resp[offset + 4:offset + 8], "big")
            rdlength = int.from_bytes(resp[offset + 8:offset + 10], "big")
            offset += 10
            if offset + rdlength > len(resp):
                break
            record = resp[offset:offset + rdlength]
            offset += rdlength
            if atype == qtype and aclass == 1:
                if qtype == 1 and rdlength == 4:
                    return socket.inet_ntoa(record), float(ttl)
                if qtype == 28 and rdlength == 16:
                    return socket.inet_ntop(socket.AF_INET6, record), float(ttl)
    except Exception:
        return None, 0.0
    return None, 0.0


def _dns_is_final_negative(resp: bytes, tx_id: bytes) -> bool:
    """A finished NODATA/NXDOMAIN. Do not sit out the rest of the timeout."""
    if len(resp) < 12 or resp[:2] != tx_id:
        return False
    if resp[2] & 0x02:
        return False
    rcode = resp[3] & 0x0F
    if rcode == 3:
        return True
    if rcode != 0:
        return False
    return int.from_bytes(resp[6:8], "big") == 0


def _log_dns_bind_failure(iface: str, exc: OSError) -> None:
    now = time.monotonic()
    if now - _DNS_BIND_LOG_AT.get(iface, 0.0) < 30.0:
        return
    _DNS_BIND_LOG_AT[iface] = now
    message = str(exc).lower()
    errno = getattr(exc, "errno", None)
    if "operation not permitted" in message or errno == 1:
        print("[DNS 绑定失败] [错误代码 3006] DNS 解析绑定当前 VPN 网卡 权限不足，请确保程序以 root 权限运行！", flush=True)
    elif "no such device" in message or errno == 19:
        print(f"[DNS 绑定失败] [错误代码 3004] DNS 解析绑定 {iface} 失败，当前活动 VPN 网卡不存在，请检查 VPN 连接！", flush=True)


def _dns_udp_query(host: str, qtype: int, dns_server: str, timeout: float, iface: str) -> tuple[str | None, float]:
    import random
    sock = None
    try:
        tx_id = random.getrandbits(16).to_bytes(2, "big")
        packet = _build_dns_query(host, qtype, tx_id)
        if packet is None:
            return None, 0.0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        if iface:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode("utf-8"))
            except OSError as exc:
                _log_dns_bind_failure(iface, exc)
                return None, 0.0
        sock.sendto(packet, (dns_server, 53))
        resp, _ = sock.recvfrom(4096)
    except Exception:
        return None, 0.0
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return _parse_dns_a(resp, tx_id, qtype)


def dns_query_over_active_tunnel(host: str, qtype: int, dns_server: str, timeout: float) -> str | None:
    ip, _ttl = _dns_udp_query(host, qtype, dns_server, timeout, get_forward_interface())
    return ip


def _race_tunnel_dns(host: str, iface: str, servers: tuple[str, ...], timeout: float) -> tuple[str | None, float, bool]:
    """Ask every resolver at once. Return the first answer. No extra threads."""
    import random
    pending: list[tuple[socket.socket, bytes]] = []
    poller = select.poll()
    try:
        for server in servers:
            tx_id = random.getrandbits(16).to_bytes(2, "big")
            packet = _build_dns_query(host, 1, tx_id)
            if packet is None:
                continue
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            if iface:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode("utf-8"))
                except OSError as exc:
                    _log_dns_bind_failure(iface, exc)
                    sock.close()
                    continue
            try:
                sock.sendto(packet, (server, 53))
            except OSError:
                sock.close()
                continue
            pending.append((sock, tx_id))
            poller.register(sock, select.POLLIN)
        if not pending:
            return None, 0.0, False
        deadline = time.monotonic() + max(0.05, timeout)
        while time.monotonic() < deadline:
            remain_ms = max(1, int((deadline - time.monotonic()) * 1000))
            try:
                events = poller.poll(remain_ms)
            except OSError:
                break
            for fd, _mask in events:
                sock = next((item[0] for item in pending if item[0].fileno() == fd), None)
                tx_id = next((item[1] for item in pending if item[0].fileno() == fd), b"")
                if sock is None:
                    continue
                try:
                    resp, _addr = sock.recvfrom(4096)
                except OSError:
                    continue
                ip, ttl = _parse_dns_a(resp, tx_id, 1)
                if ip:
                    return ip, ttl, False
                if _dns_is_final_negative(resp, tx_id):
                    return None, 0.0, True
        return None, 0.0, False
    finally:
        for sock, _tx in pending:
            try:
                sock.close()
            except OSError:
                pass


def _system_dns_ipv4(host: str, timeout: float) -> str | None:
    box: dict[str, str] = {}

    def run() -> None:
        try:
            infos = socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            return
        if infos:
            box["ip"] = str(infos[0][4][0])

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    return box.get("ip")


def _remember_dns(key: tuple[str, str], ip: str | None, raw_ttl: float, now: float) -> None:
    if ip:
        ttl = raw_ttl if raw_ttl > 0 else DNS_CACHE_TTL_SECONDS
        ttl = min(DNS_POSITIVE_MAX_SECONDS, max(DNS_POSITIVE_MIN_SECONDS, ttl))
    else:
        ttl = DNS_NEGATIVE_TTL_SECONDS
    with DNS_CACHE_LOCK:
        DNS_CACHE[key] = (now + ttl, ip)
        if len(DNS_CACHE) > 1024:
            cutoff = time.monotonic()
            stale = [item for item, (expiry, _ip) in DNS_CACHE.items() if expiry <= cutoff]
            for item in stale[:256]:
                DNS_CACHE.pop(item, None)


def resolve_dns_over_active_tunnel(host: str, dns_server: str = "8.8.8.8", timeout: float = DNS_STAGE_TIMEOUT_SECONDS, iface: str | None = None) -> str | None:
    """Resolve on the same NIC 8500 will bind.

    Direct binds the server NIC. Proxy binds the tunnel NIC. 8.8.8.8 and
    8.8.4.4 race inside one second. Same name shares one flight. The cache
    key includes the NIC, so a mode switch cannot reuse the other path.
    """
    literal = _host_is_ip(host)
    if literal:
        return literal
    key_host = str(host or "").strip().rstrip(".").lower()
    if not key_host:
        return None
    if iface is None:
        iface = get_forward_interface()
    scope = iface or "@direct"
    cache_key = (scope, key_host)
    stage_timeout = timeout if timeout and timeout > 0 else DNS_STAGE_TIMEOUT_SECONDS
    now = time.monotonic()
    with DNS_CACHE_LOCK:
        cached = DNS_CACHE.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]
        flight = _DNS_FLIGHTS.get(cache_key)
        if flight is None:
            flight = (threading.Event(), {})
            _DNS_FLIGHTS[cache_key] = flight
            owner = True
        else:
            owner = False
    event, box = flight
    if not owner:
        event.wait(stage_timeout * 2 + 0.5)
        return box.get("ip")

    ip: str | None = None
    raw_ttl = 0.0
    try:
        if not iface:
            ip = _system_dns_ipv4(key_host, stage_timeout)
        else:
            servers = []
            for server in (dns_server, *DNS_TUNNEL_RESOLVERS):
                server = str(server or "").strip()
                if server and server not in servers:
                    servers.append(server)
            ip, raw_ttl, negative = _race_tunnel_dns(key_host, iface, tuple(servers), stage_timeout)
            if not ip and not negative:
                ip = _system_dns_ipv4(key_host, stage_timeout)
                raw_ttl = DNS_POSITIVE_MIN_SECONDS if ip else 0.0
        box["ip"] = ip
        _remember_dns(cache_key, ip, raw_ttl, time.monotonic())
        return ip
    finally:
        event.set()
        with DNS_CACHE_LOCK:
            _DNS_FLIGHTS.pop(cache_key, None)


def _quickack(sock: socket.socket) -> None:
    option = getattr(socket, "TCP_QUICKACK", 12)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, option, 1)
    except OSError:
        pass


def _tune_socket(sock: socket.socket) -> socket.socket:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    _quickack(sock)
    for level, opt, value in (
        (socket.SOL_SOCKET, socket.SO_RCVBUF, PROXY_SOCKET_BUFFER_BYTES),
        (socket.SOL_SOCKET, socket.SO_SNDBUF, PROXY_SOCKET_BUFFER_BYTES),
    ):
        try:
            sock.setsockopt(level, opt, value)
        except OSError:
            pass
    for name, value in (
        # Refresh NAT without treating a quiet session as dead.
        # A 20s user-timeout was aborting idle TCP as soon as the first
        # keepalive probe was delayed by the VPN.
        ("TCP_KEEPIDLE", 45),
        ("TCP_KEEPINTVL", 15),
        ("TCP_KEEPCNT", 8),
        ("TCP_USER_TIMEOUT", 180000),
    ):
        opt = getattr(socket, name, None)
        if opt is None:
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, opt, value)
        except OSError:
            pass
    return sock


def _iface_has_ipv6(iface: str) -> bool:
    iface = str(iface or "").strip()
    if not iface:
        return False
    try:
        lines = Path("/proc/net/if_inet6").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    for line in lines:
        parts = line.split()
        if parts and parts[-1] == iface:
            return True
    return False


def _repair_policy_route(iface: str) -> None:
    """Reattach table 100 to the live NIC without deleting the current rule first."""
    iface = str(iface or "").strip()
    if not iface or not re.fullmatch(r"[A-Za-z0-9._:-]{1,15}", iface):
        return
    table = str(os.environ.get("ACTIVE_ROUTE_TABLE") or "100")
    try:
        probe = subprocess.run(
            ["ip", "route", "get", "8.8.8.8", "oif", iface],
            capture_output=True, text=True, timeout=2,
        )
    except Exception:
        return
    if probe.returncode == 0 and ("dev " + iface) in (probe.stdout or ""):
        return
    gateway = ""
    try:
        gateway = (DATA_DIR / "active_gateway.txt").read_text(encoding="utf-8").strip()
    except OSError:
        gateway = ""
    cmd = ["ip", "route", "replace", "default"]
    if gateway:
        cmd.extend(["via", gateway, "dev", iface, "onlink"])
    else:
        cmd.extend(["dev", iface])
    cmd.extend(["table", table])
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        shown = subprocess.run(["ip", "-4", "rule", "show"], capture_output=True, text=True, timeout=2)
        already = False
        for line in (shown.stdout or "").splitlines():
            if ("oif " + iface) in line and ("lookup " + table) in line:
                already = True
                break
        if not already:
            subprocess.run(["ip", "rule", "add", "oif", iface, "table", table], capture_output=True, text=True, timeout=2)
    except Exception:
        return


def create_connection(address: tuple[str, int], timeout: float = 20) -> socket.socket:
    host, port = address
    iface = get_forward_interface()
    if get_egress_mode() != "direct" and not iface:
        raise OSError("[DNS] 代理模式没有活动网卡")
    _stage_mark("dns_start")
    if not _host_is_ip(host):
        resolved_ip = resolve_dns_over_active_tunnel(host, iface=iface)
        _stage_mark("dns")
        if not resolved_ip:
            raise OSError("[DNS] 当前出站没有解析结果")
        host = resolved_ip
    else:
        _stage_mark("dns")

    try:
        results = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except OSError:
        results = []
    allow_v6 = _iface_has_ipv6(iface)
    ordered = [item for item in results if item[0] != socket.AF_INET6 or allow_v6]
    ordered.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
    if not ordered:
        raise OSError("getaddrinfo returns empty list")

    err = None
    repaired = False
    for res in ordered:
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            _tune_socket(sock)
            if iface:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode("utf-8"))
            _stage_mark("connect_start")
            sock.connect(sa)
            _stage_mark("connect")
            sock.settimeout(None)
            return sock
        except OSError as e:
            err = e
            if sock is not None:
                sock.close()
                sock = None
            unreachable = e.errno in (101, 113)
            if unreachable and not repaired and get_egress_mode() != "direct":
                repaired = True
                _repair_policy_route(iface)
                try:
                    sock = socket.socket(af, socktype, proto)
                    sock.settimeout(timeout)
                    _tune_socket(sock)
                    if iface:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode("utf-8"))
                    _stage_mark("connect_start")
                    sock.connect(sa)
                    _stage_mark("connect")
                    sock.settimeout(None)
                    return sock
                except OSError as retry_error:
                    err = retry_error
                    if sock is not None:
                        sock.close()
            elif "operation not permitted" in str(e).lower() or e.errno == 1:
                err = OSError("[错误代码 3006] [ERR_PROXY_BIND_TUN_PERM_DENIED] 绑定当前 VPN 网卡失败，权限不足！必须以 root 权限运行，或者进程缺少 CAP_NET_RAW 权限。")
            elif "no such device" in str(e).lower() or e.errno == 19:
                err = OSError("[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] 绑定当前 VPN 网卡失败，找不到当前活动 VPN 网卡！这通常是因为 VPN 隧道未成功建立或已异常退出。")
    if err is not None:
        raise err
    raise OSError("getaddrinfo returns empty list")

def relay(left: socket.socket, right: socket.socket) -> None:
    """Forward TCP after the SOCKS/HTTP handshake.

    OpenVPN, SSTP, L2TP/IPsec and SSL-VPN all publish one tunnel interface.
    8500 binds that interface and splices both directions. The bytes never
    enter this process. UDP associate still carries a SOCKS header, so that
    path stays in userspace. The copy fallback is only for a kernel that
    rejects splice before any byte has moved.
    """
    _stage_mark("splice")
    try:
        _relay_splice(left, right)
    except _SpliceUnsupported:
        global _splice_fallback_logged
        if not _splice_fallback_logged:
            _splice_fallback_logged = True
            print("[网关] 本机 splice 不可用，退回用户态转发", flush=True)
        _relay_copy(left, right)


class _SpliceUnsupported(Exception):
    pass


_splice_fallback_logged = False
_SPLICE_REJECT = {errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP, getattr(errno, "ENOTSUP", 95)}


class _SpliceLeg:
    __slots__ = ("src", "dst", "pipe_r", "pipe_w", "cap", "pending", "src_eof", "dst_shut")

    def __init__(self, src: socket.socket, dst: socket.socket, pipe_r: int, pipe_w: int, cap: int) -> None:
        self.src = src
        self.dst = dst
        self.pipe_r = pipe_r
        self.pipe_w = pipe_w
        self.cap = cap
        self.pending = 0
        self.src_eof = False
        self.dst_shut = False


def _pipe_cap(read_fd: int) -> int:
    try:
        fcntl.fcntl(read_fd, getattr(fcntl, "F_SETPIPE_SZ", 1031), 1024 * 1024)
    except (OSError, AttributeError):
        pass
    try:
        size = int(fcntl.fcntl(read_fd, fcntl.F_GETPIPE_SZ))
    except (OSError, AttributeError):
        size = 65536
    return size if size > 0 else 65536


def _poll_ready(rlist: list[socket.socket], wlist: list[socket.socket], timeout: float) -> tuple[list[socket.socket], list[socket.socket], list[socket.socket]]:
    poller = select.poll()
    watched: dict[int, socket.socket] = {}
    for sock in rlist:
        poller.register(sock, select.POLLIN)
        watched[sock.fileno()] = sock
    for sock in wlist:
        fd = sock.fileno()
        if fd in watched:
            poller.modify(sock, select.POLLIN | select.POLLOUT)
        else:
            poller.register(sock, select.POLLOUT)
            watched[fd] = sock
    try:
        events = poller.poll(max(0, int(timeout * 1000)))
    except OSError:
        return [], [], list(watched.values())
    readable: list[socket.socket] = []
    writable: list[socket.socket] = []
    errored: list[socket.socket] = []
    for fd, mask in events:
        sock = watched.get(fd)
        if sock is None:
            continue
        if mask & (select.POLLERR | select.POLLHUP | select.POLLNVAL):
            errored.append(sock)
        if mask & select.POLLIN:
            readable.append(sock)
        if mask & select.POLLOUT:
            writable.append(sock)
    return readable, writable, errored


def _splice_once(src_fd: int, dst_fd: int, count: int, flags: int, moved: bool) -> int | None:
    try:
        return os.splice(src_fd, dst_fd, count, flags=flags)
    except BlockingIOError:
        return None
    except InterruptedError:
        return None
    except OSError as exc:
        if not moved and exc.errno in _SPLICE_REJECT:
            raise _SpliceUnsupported from exc
        raise


def _relay_splice(left: socket.socket, right: socket.socket) -> None:
    if not hasattr(os, "splice"):
        raise _SpliceUnsupported
    peers = (left, right)
    for sock in peers:
        try:
            sock.settimeout(None)
            sock.setblocking(False)
        except OSError:
            return
    pipes: list[int] = []
    try:
        in_flags = os.SPLICE_F_MOVE | os.SPLICE_F_NONBLOCK | os.SPLICE_F_MORE
        out_flags = os.SPLICE_F_MOVE | os.SPLICE_F_NONBLOCK
        legs: list[_SpliceLeg] = []
        for src, dst in ((left, right), (right, left)):
            pipe_r, pipe_w = os.pipe()
            pipes.extend((pipe_r, pipe_w))
            os.set_blocking(pipe_r, False)
            os.set_blocking(pipe_w, False)
            legs.append(_SpliceLeg(src, dst, pipe_r, pipe_w, _pipe_cap(pipe_r)))
        moved = False
        while True:
            progressed = False
            for leg in legs:
                if leg.pending and not leg.dst_shut:
                    sent = _splice_once(leg.pipe_r, leg.dst.fileno(), leg.pending, out_flags, moved)
                    if sent is None:
                        pass
                    elif sent <= 0:
                        leg.dst_shut = True
                    else:
                        leg.pending -= sent
                        moved = True
                        progressed = True
                        note_proxy_forwarded(sent)
                        if leg.dst is left:
                            _stage_mark("first_byte")
                            _stage_log(getattr(_stage_local, "host", "") or "", int(getattr(_stage_local, "port", 0) or 0))
                room = leg.cap - leg.pending
                if room > 0 and not leg.src_eof:
                    got = _splice_once(leg.src.fileno(), leg.pipe_w, room, in_flags, moved)
                    if got == 0:
                        leg.src_eof = True
                    elif got:
                        leg.pending += got
                        moved = True
                        progressed = True
                if leg.src_eof and leg.pending == 0 and not leg.dst_shut:
                    try:
                        leg.dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    leg.dst_shut = True
            if all(leg.dst_shut for leg in legs):
                return
            if progressed:
                continue
            rlist = [leg.src for leg in legs if not leg.src_eof and leg.pending < leg.cap]
            wlist = [leg.dst for leg in legs if leg.pending and not leg.dst_shut]
            if not rlist and not wlist:
                return
            try:
                _readable, _writable, errored = _poll_ready(rlist, wlist, 60)
            except (OSError, ValueError):
                return
            if errored:
                return
    except _SpliceUnsupported:
        raise
    except OSError:
        return
    finally:
        for fd in pipes:
            try:
                os.close(fd)
            except OSError:
                pass


def _relay_copy(left: socket.socket, right: socket.socket) -> None:
    """Copy both ways. An offset avoids rewriting the buffer on every send.

    `del buf[:sent]` memmoves the whole window on each packet. Under load that
    burns the only cores and the forward rate collapses as soon as it rises.
    """
    peers = (left, right)
    for sock in peers:
        try:
            sock.setblocking(False)
        except OSError:
            return
    bufs: dict[socket.socket, bytearray] = {left: bytearray(), right: bytearray()}
    offs = {left: 0, right: 0}
    closed = {left: False, right: False}
    while True:
        if all(closed[sock] and offs[sock] >= len(bufs[sock]) for sock in peers):
            return
        rlist = []
        wlist = []
        for sock in peers:
            other = right if sock is left else left
            pending_other = len(bufs[other]) - offs[other]
            if not closed[sock] and pending_other < 1024 * 1024:
                rlist.append(sock)
            if offs[sock] < len(bufs[sock]):
                wlist.append(sock)
        if not rlist and not wlist:
            return
        try:
            readable, writable, errored = _poll_ready(rlist, wlist, 60)
        except (OSError, ValueError):
            return
        if errored:
            return
        for sock in writable:
            start = offs[sock]
            if start >= len(bufs[sock]):
                continue
            view = memoryview(bufs[sock])
            try:
                sent = sock.send(view[start:])
            except BlockingIOError:
                view.release()
                continue
            except OSError:
                view.release()
                return
            view.release()
            if sent <= 0:
                return
            offs[sock] = start + sent
            note_proxy_forwarded(sent)
            if offs[sock] >= 256 * 1024 or offs[sock] >= len(bufs[sock]):
                if offs[sock] >= len(bufs[sock]):
                    bufs[sock].clear()
                    offs[sock] = 0
                elif offs[sock] >= 256 * 1024:
                    del bufs[sock][:offs[sock]]
                    offs[sock] = 0
        for sock in readable:
            other = right if sock is left else left
            try:
                data = sock.recv(262144)
            except BlockingIOError:
                continue
            except OSError:
                return
            if not data:
                closed[sock] = True
                continue
            if offs[other] and offs[other] >= len(bufs[other]):
                bufs[other].clear()
                offs[other] = 0
            bufs[other].extend(data)

def socks5_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    host = ""
    port = 0
    try:
        _stage_mark("auth_start")
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        if proxy_auth_enabled():
            if 2 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x02")
            auth_version = recv_exact(client, 1)[0]
            if auth_version != 1:
                client.sendall(b"\x01\x01")
                return
            username = recv_exact(client, recv_exact(client, 1)[0]).decode("utf-8", errors="replace")
            password = recv_exact(client, recv_exact(client, 1)[0]).decode("utf-8", errors="replace")
            if not check_credentials(username, password):
                client.sendall(b"\x01\x01")
                return
            client.sendall(b"\x01\x00")
        else:
            client.sendall(b"\x05\x00")
        _stage_mark("auth")
        _quickack(client)
        version, command, _, address_type = recv_exact(client, 4)
        if version != 5:
            client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        if command == 3:  # UDP ASSOCIATE (RFC 1928)
            socks5_udp_associate(client, client.getpeername())
            return
        if command != 1:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        if address_type == 1:
            host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3:
            host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = int.from_bytes(recv_exact(client, 2), "big")
        _stage_local.host = host
        _stage_local.port = port
        try:
            upstream = create_connection((host, port), timeout=20)
        except Exception as e:
            if str(host or "").lower() != "api6.ipify.org":
                print(f"[SOCKS5 代理失败] 目标 {host}:{port} 连接失败: {e}", flush=True)
            try:
                client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
            raise
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        _stage_mark("reply")
        _quickack(client)
        relay(client, upstream)
    finally:
        if host:
            _stage_log(host, port)
        client.close()
        if upstream:
            upstream.close()

def read_http_header(client: socket.socket, first_byte: bytes) -> bytes:
    data = first_byte
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = client.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def http_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
        header = read_http_header(client, first_byte)
        if b"\r\n\r\n" not in header:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        head, rest = header.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        if not version.startswith("HTTP/"):
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        if proxy_auth_enabled():
            username, password = parse_http_basic_auth(lines[1:])
            if not check_credentials(username, password):
                client.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"AimiliVPN Proxy\"\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                return
        if method.upper() == "CONNECT":
            host, port = parse_host_port(target, 443)
            upstream = create_connection((host, port), timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest:
                upstream.sendall(rest)
            relay(client, upstream)
            return

        try:
            parsed = urllib.parse.urlsplit(target)
        except ValueError:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        hostname = parsed.hostname
        port = parsed.port
        scheme = parsed.scheme
        if not hostname:
            # Fallback to Host header
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host_val = line.split(":", 1)[1].strip()
                    if "[" in host_val and "]" in host_val:
                        host_part, _, port_part = host_val.rpartition("]")
                        hostname = host_part.lstrip("[")
                        if port_part.startswith(":"):
                            p_val = port_part.lstrip(":")
                            port = int(p_val) if p_val.isdigit() else None
                        else:
                            port = None
                    else:
                        hostname, parsed_port = parse_host_port(host_val, 0)
                        port = parsed_port or None
                    break
        if not hostname:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            return
        port = port or (443 if scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))]
        request = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\nConnection: close\r\n\r\n"
        upstream = create_connection((hostname, port), timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except Exception as e:
        print(f"[HTTP 代理失败] 代理请求目标连接失败: {e}", flush=True)
        try:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
    finally:
        client.close()
        if upstream:
            upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int], accepted_at: float | None = None) -> None:
    _track_client(client)
    _stage_begin(accepted_at)
    try:
        _tune_socket(client)
        client.settimeout(30)
        if not proxy_client_allowed(address):
            print(f"[代理访问控制] 拒绝客户端 {address[0]}:{address[1]}", flush=True)
            client.close()
            return
        first = recv_exact(client, 1)
        if first == b"\x05":
            socks5_client(client, first)
        else:
            http_client(client, first)
    except Exception as e:
        err_msg = str(e)
        if "[错误代码" in err_msg:
            print(f"[代理客户端连接失败] 客户端 {address} 遭遇系统性阻碍: {err_msg}", flush=True)
        try:
            client.close()
        except OSError:
            pass
    finally:
        _untrack_client(client)

def start_proxy_server(host: str, port: int) -> None:
    is_ipv6 = ":" in host or host == ""
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    server = None
    try:
        server = socket.socket(af, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if is_ipv6:
            try:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        _tune_socket(server)
        server.bind((host, port))
        server.listen(1024)
        print(f"HTTP/SOCKS5 proxy listening on {host}:{port} (SOCKS5 TCP + UDP ASSOCIATE)", flush=True)
    except Exception as e:
        if server is not None:
            try:
                server.close()
            except Exception:
                pass
        if is_ipv6 and host in ("::", ""):
            print(f"[警告] 绑定 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 0.0.0.0 ...", flush=True)
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                _tune_socket(server)
                server.bind(("0.0.0.0", port))
                server.listen(1024)
                print(f"HTTP/SOCKS5 proxy listening on 0.0.0.0:{port} (仅 IPv4)", flush=True)
            except Exception as ex:
                import vpn_utils
                diag = vpn_utils.diagnose_local_obstructions(port, host="0.0.0.0")
                diag_msg = diag[1] if diag else str(ex)
                print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on 0.0.0.0:{port}: {diag_msg}", flush=True)
                return
        elif is_ipv6 and host == "::1":
            print(f"[警告] 绑定 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 127.0.0.1 ...", flush=True)
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                _tune_socket(server)
                server.bind(("127.0.0.1", port))
                server.listen(1024)
                print(f"HTTP/SOCKS5 proxy listening on 127.0.0.1:{port} (仅 IPv4)", flush=True)
            except Exception as ex:
                import vpn_utils
                diag = vpn_utils.diagnose_local_obstructions(port, host="127.0.0.1")
                diag_msg = diag[1] if diag else str(ex)
                print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on 127.0.0.1:{port}: {diag_msg}", flush=True)
                return
        else:
            import vpn_utils
            diag = vpn_utils.diagnose_local_obstructions(port, host=host)
            diag_msg = diag[1] if diag else str(e)
            print(f"[ERROR] Failed to start HTTP/SOCKS5 proxy on {host}:{port}: {diag_msg}", flush=True)
            return

    plane = "splice" if hasattr(os, "splice") else "userspace"
    print(f"[网关] 8500 数据面 {plane}。TCP 握手之后走内核管道，业务字节不进用户态。", flush=True)
    try:
        ensure_kernel_socks_outbounds()
    except Exception as exc:
        print(f"[内核] 出站配置检查失败：{exc}", flush=True)
    threading.Thread(target=_watch_egress_mode, daemon=True, name="egress-watch").start()
    threading.Thread(target=_forward_heartbeat, daemon=True, name="forward-heartbeat").start()

    def run_client(client: socket.socket, address: tuple[str, int], accepted_at: float) -> None:
        try:
            _note_accept_started(accepted_at)
            proxy_client(client, address, accepted_at)
        finally:
            proxy_connection_sem.release()

    while True:
        try:
            client, address = server.accept()
            accepted_at = time.monotonic()
            try:
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            _quickack(client)
            if not proxy_connection_sem.acquire(blocking=False):
                print(f"[代理限流] 当前连接数已达到上限 {MAX_PROXY_CONNECTIONS}，拒绝客户端 {address}", flush=True)
                try:
                    client.close()
                except OSError:
                    pass
                continue
            _note_accept_queued()
            try:
                threading.Thread(
                    target=run_client,
                    args=(client, address, accepted_at),
                    daemon=True,
                    name="socks-client",
                ).start()
            except Exception:
                _note_accept_started(accepted_at)
                proxy_connection_sem.release()
                try:
                    client.close()
                except OSError:
                    pass
                raise
        except Exception as e:
            print(f"[ERROR] Proxy accept failed: {e}", flush=True)
            time.sleep(0.5)

if __name__ == "__main__":
    host = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
    port = int(os.environ.get("LOCAL_PROXY_PORT", "8500"))
    start_proxy_server(host, port)
