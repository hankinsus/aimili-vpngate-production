#!/usr/bin/env python3
from __future__ import annotations
import base64
import ipaddress
import os
import secrets
import select
import socket
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
DNS_NEGATIVE_TTL_SECONDS = 5.0
DNS_CACHE: dict[str, tuple[float, str | None]] = {}
DNS_CACHE_LOCK = threading.Lock()
PROXY_SOCKET_BUFFER_BYTES = 262144
PROXY_UDP_ASSOCIATION_IDLE_SECONDS = 600
PROXY_UDP_MAX_PACKET_BYTES = 65535

DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else Path(__file__).resolve().parent / "vpngate_data"
ACTIVE_IFACE_FILE = DATA_DIR / "active_iface.txt"

def get_active_interface() -> str:
    env_iface = str(os.environ.get("ACTIVE_TUNNEL_IFACE") or "").strip()
    if env_iface:
        return env_iface
    try:
        iface = ACTIVE_IFACE_FILE.read_text(encoding="utf-8").strip()
        if iface:
            return iface
    except OSError:
        pass
    return "tun0"

def set_active_interface(iface: str) -> None:
    iface = str(iface or "").strip()
    if not iface:
        return
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = ACTIVE_IFACE_FILE.with_suffix(".tmp")
    tmp.write_text(iface, encoding="utf-8")
    tmp.replace(ACTIVE_IFACE_FILE)

def clear_active_interface() -> None:
    try:
        ACTIVE_IFACE_FILE.unlink(missing_ok=True)
    except Exception:
        pass

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Unexpected disconnect.")
        data += chunk
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


def socks5_udp_associate(client: socket.socket, control_address: tuple[str, int]) -> None:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream = None
    client_ip = control_address[0]
    last_activity = time.monotonic()
    try:
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, PROXY_SOCKET_BUFFER_BYTES)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, PROXY_SOCKET_BUFFER_BYTES)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, get_active_interface().encode("utf-8"))
        udp.bind(("127.0.0.1", 0))
        bind_port = int(udp.getsockname()[1])
        client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + bind_port.to_bytes(2, "big"))
        udp.setblocking(False)
        client.setblocking(False)
        while time.monotonic() - last_activity < PROXY_UDP_ASSOCIATION_IDLE_SECONDS:
            readable, _, errored = select.select([client, udp], [], [client, udp], 5)
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
                    # The SOCKS5 control connection normally carries no more
                    # data after UDP ASSOCIATE; any data means the client is
                    # still alive, so simply refresh the association timer.
                    last_activity = time.monotonic()
                    continue
                try:
                    packet, peer = udp.recvfrom(PROXY_UDP_MAX_PACKET_BYTES)
                except BlockingIOError:
                    continue
                if peer[0] != client_ip and not (
                    client_ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1") and peer[0] == "127.0.0.1"
                ):
                    continue
                decoded = _socks5_unpack_udp(packet)
                if not decoded:
                    continue
                host, port, payload = decoded
                resolved = resolve_dns_over_active_tunnel(host)
                if not resolved:
                    try:
                        resolved = socket.gethostbyname(host)
                    except OSError:
                        continue
                destination = (resolved, port)
                if upstream is None:
                    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    upstream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    upstream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, PROXY_SOCKET_BUFFER_BYTES)
                    upstream.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, PROXY_SOCKET_BUFFER_BYTES)
                    upstream.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, get_active_interface().encode("utf-8"))
                    upstream.bind(("0.0.0.0", 0))
                    upstream.setblocking(False)
                upstream.sendto(payload, destination)
                last_activity = time.monotonic()
                # Drain one response immediately when available. The outer
                # select loop will handle subsequent responses.
                try:
                    response, source_addr = upstream.recvfrom(PROXY_UDP_MAX_PACKET_BYTES)
                    udp.sendto(_socks5_pack_udp(source_addr, response), peer)
                except BlockingIOError:
                    pass
            if upstream is not None:
                try:
                    while True:
                        response, source_addr = upstream.recvfrom(PROXY_UDP_MAX_PACKET_BYTES)
                        udp.sendto(_socks5_pack_udp(source_addr, response), (client_ip, peer[1]))
                        last_activity = time.monotonic()
                except BlockingIOError:
                    pass
    except Exception as exc:
        print(f"[SOCKS5 UDP] UDP ASSOCIATE 失败: {exc}", flush=True)
    finally:
        try:
            udp.close()
        except Exception:
            pass
        if upstream is not None:
            try:
                upstream.close()
            except Exception:
                pass


def dns_query_over_active_tunnel(host: str, qtype: int, dns_server: str, timeout: float) -> str | None:
    import random
    sock = None
    try:
        tx_id = random.getrandbits(16).to_bytes(2, "big")
        flags = b"\x01\x00"
        questions = b"\x00\x01"
        rrs = b"\x00\x00\x00\x00\x00\x00"

        qname = b""
        for part in host.split("."):
            if not part:
                continue
            part_bytes = part.encode("idna")
            if len(part_bytes) > 63:
                return None
            qname += len(part_bytes).to_bytes(1, "big") + part_bytes
        qname += b"\x00"

        qtype_qclass = qtype.to_bytes(2, "big") + b"\x00\x01"
        packet = tx_id + flags + questions + rrs + qname + qtype_qclass

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, get_active_interface().encode("utf-8"))
        except OSError as e:
            if "operation not permitted" in str(e).lower() or e.errno == 1:
                print("[DNS 绑定失败] [错误代码 3006] DNS 解析绑定当前 VPN 网卡 权限不足，请确保程序以 root 权限运行！", flush=True)
            elif "no such device" in str(e).lower() or e.errno == 19:
                print("[DNS 绑定失败] [错误代码 3004] DNS 解析绑定当前 VPN 网卡 失败，当前活动 VPN 网卡不存在，请检查 VPN 连接！", flush=True)
            return None
        sock.sendto(packet, (dns_server, 53))
        resp, _ = sock.recvfrom(4096)
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    try:
        if len(resp) < 12 or resp[:2] != tx_id:
            return None
        rcode = resp[3] & 0x0F
        if rcode != 0:
            return None

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
        answers_count = int.from_bytes(resp[6:8], "big")
        for _ in range(answers_count):
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
            atype = int.from_bytes(resp[offset : offset + 2], "big")
            aclass = int.from_bytes(resp[offset + 2 : offset + 4], "big")
            rdlength = int.from_bytes(resp[offset + 8 : offset + 10], "big")
            offset += 10
            if offset + rdlength > len(resp):
                break
            record = resp[offset : offset + rdlength]
            if atype == qtype and aclass == 1:
                if qtype == 1 and rdlength == 4:
                    return socket.inet_ntoa(record)
                if qtype == 28 and rdlength == 16:
                    return socket.inet_ntop(socket.AF_INET6, record)
            offset += rdlength
    except Exception:
        return None
    return None

def resolve_dns_over_active_tunnel(host: str, dns_server: str = "8.8.8.8", timeout: float = 3.0) -> str | None:
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass

    key = str(host or "").strip().rstrip(".").lower()
    if not key:
        return None
    now = time.monotonic()
    with DNS_CACHE_LOCK:
        cached = DNS_CACHE.get(key)
        if cached and cached[0] > now:
            return cached[1]

    resolved = (
        dns_query_over_active_tunnel(key, 1, dns_server, timeout)
        or dns_query_over_active_tunnel(key, 28, dns_server, timeout)
    )
    ttl = DNS_CACHE_TTL_SECONDS if resolved else DNS_NEGATIVE_TTL_SECONDS
    with DNS_CACHE_LOCK:
        DNS_CACHE[key] = (now + ttl, resolved)
        if len(DNS_CACHE) > 1024:
            cutoff = time.monotonic()
            stale = [k for k, (expiry, _) in DNS_CACHE.items() if expiry <= cutoff]
            for k in stale[:256]:
                DNS_CACHE.pop(k, None)
    return resolved

def _tune_socket(sock: socket.socket) -> socket.socket:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    for level, opt in (
        (socket.SOL_SOCKET, socket.SO_RCVBUF),
        (socket.SOL_SOCKET, socket.SO_SNDBUF),
    ):
        try:
            sock.setsockopt(level, opt, PROXY_SOCKET_BUFFER_BYTES)
        except OSError:
            pass
    return sock


def create_connection(address: tuple[str, int], timeout: float = 20) -> socket.socket:
    host, port = address
    resolved_ip = resolve_dns_over_active_tunnel(host)
    if resolved_ip:
        host = resolved_ip

    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            _tune_socket(sock)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, get_active_interface().encode("utf-8"))
            sock.connect(sa)
            # The timeout protects only connection establishment. Long-lived
            # HTTPS/WebSocket sessions should not be dropped after 30 seconds
            # of idle time.
            sock.settimeout(None)
            return sock
        except OSError as e:
            err = e
            if "operation not permitted" in str(e).lower() or e.errno == 1:
                err = OSError(f"[错误代码 3006] [ERR_PROXY_BIND_TUN_PERM_DENIED] 绑定当前 VPN 网卡失败，权限不足！必须以 root 权限运行，或者进程缺少 CAP_NET_RAW 权限。")
            elif "no such device" in str(e).lower() or e.errno == 19:
                err = OSError(f"[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] 绑定当前 VPN 网卡失败，找不到当前活动 VPN 网卡！这通常是因为 VPN 隧道未成功建立或已异常退出。")
            if sock is not None:
                sock.close()
    if err is not None:
        raise err
    else:
        raise OSError("getaddrinfo returns empty list")

def relay(left: socket.socket, right: socket.socket) -> None:
    # Handshake timeouts should not apply once the tunnel is established.
    for sock in (left, right):
        try:
            sock.settimeout(None)
        except OSError:
            pass
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored or not readable:
            return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data:
                return
            target.sendall(data)

def socks5_client(client: socket.socket, first_byte: bytes) -> None:
    upstream = None
    try:
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
        version, command, _, address_type = recv_exact(client, 4)
        if version != 5:
            client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        if command == 3:  # UDP ASSOCIATE (RFC 1928)
            socks5_udp_associate(client, ("127.0.0.1", client.getpeername()[1]))
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
        try:
            upstream = create_connection((host, port), timeout=20)
        except Exception as e:
            print(f"[SOCKS5 代理失败] 目标 {host}:{port} 连接失败: {e}", flush=True)
            try:
                client.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
            raise
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        relay(client, upstream)
    finally:
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

def proxy_client(client: socket.socket, address: tuple[str, int]) -> None:
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
        server.listen(256)
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

    while True:
        try:
            client, address = server.accept()
            if not proxy_connection_sem.acquire(blocking=False):
                print(f"[代理限流] 当前连接数已达到上限 {MAX_PROXY_CONNECTIONS}，拒绝客户端 {address}", flush=True)
                try:
                    client.close()
                except OSError:
                    pass
                continue

            def run_client() -> None:
                try:
                    proxy_client(client, address)
                finally:
                    proxy_connection_sem.release()

            threading.Thread(target=run_client, daemon=True).start()
        except Exception as e:
            print(f"[ERROR] Proxy accept failed: {e}", flush=True)
            time.sleep(0.5)
