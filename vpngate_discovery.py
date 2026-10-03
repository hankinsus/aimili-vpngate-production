#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import html
import re
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any

VPNGATE_HTML_URL = "https://www.vpngate.net/en/"
VPNGATE_MIRROR_LIST_URL = "https://www.vpngate.net/en/sites.aspx"

class _TableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[list[dict[str, Any]]] = []
        self._row: list[dict[str, Any]] | None = None
        self._cell: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_d = dict(attrs)
        if tag == "tr":
            self._row = []
        elif tag == "td" and self._row is not None:
            self._cell = {"text": [], "links": [], "html": []}
        elif self._cell is not None:
            if tag == "a" and attrs_d.get("href"):
                self._cell["links"].append(attrs_d["href"])
            self._cell["html"].append(self.get_starttag_text() or "")

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell["text"].append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "td" and self._row is not None and self._cell is not None:
            self._cell["text"] = " ".join(" ".join(self._cell["text"]).split())
            self._row.append(self._cell)
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if len(self._row) >= 10:
                self.rows.append(self._row)
            self._row = None
            self._cell = None

def _int(text: str) -> int:
    m = re.search(r"([\d,]+)", text or "")
    return int(m.group(1).replace(",", "")) if m else 0

def _speed_bps(text: str) -> int:
    m = re.search(r"([\d,.]+)\s*Mbps", text or "", re.I)
    if not m:
        return 0
    try:
        return int(float(m.group(1).replace(",", "")) * 1_000_000)
    except ValueError:
        return 0

def _ping_ms(text: str) -> int:
    m = re.search(r"Ping:\s*([\d,.]+)\s*ms", text or "", re.I)
    if not m:
        return 0
    try:
        return int(float(m.group(1).replace(",", "")))
    except ValueError:
        return 0

def _hostname_and_ip(cell_text: str) -> tuple[str, str]:
    hostname = ""
    ip = ""
    hm = re.search(r"([a-z0-9][a-z0-9.-]*\.opengw\.net)", cell_text or "", re.I)
    if hm:
        hostname = hm.group(1).lower()
    im = re.search(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])", cell_text or "")
    if im:
        ip = im.group(1)
    return hostname, ip

def _openvpn_ports(links: list[str]) -> tuple[str, str, int, int]:
    hostname = ""
    ip = ""
    tcp = 0
    udp = 0
    for href in links:
        if not href.startswith("do_openvpn.aspx?"):
            continue
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(href).query)
        hostname = (qs.get("fqdn") or [""])[0].lower()
        ip = (qs.get("ip") or [""])[0]
        try:
            tcp = int((qs.get("tcp") or ["0"])[0] or 0)
        except ValueError:
            tcp = 0
        try:
            udp = int((qs.get("udp") or ["0"])[0] or 0)
        except ValueError:
            udp = 0
        break
    return hostname, ip, tcp, udp

def parse_server_table(raw_html: str) -> list[dict[str, Any]]:
    parser = _TableParser()
    parser.feed(raw_html)

    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for cells in parser.rows:
        if len(cells) < 10:
            continue
        country = str(cells[0].get("text") or "").strip()
        host_cell = str(cells[1].get("text") or "")
        hostname, ip = _hostname_and_ip(host_cell)

        ovpn_host, ovpn_ip, ovpn_tcp, ovpn_udp = _openvpn_ports(cells[6].get("links") or [])
        hostname = ovpn_host or hostname
        ip = ovpn_ip or ip

        if not hostname and not ip:
            continue
        if "country" in country.lower() and not ip:
            continue

        identity = (hostname, ip)
        if identity in seen:
            continue
        seen.add(identity)

        protocols: list[dict[str, Any]] = []

        # SoftEther column (td[4]): e.g. "TCP: 443 UDP: Supported"
        softether_text = str(cells[4].get("text") or "")
        sm = re.search(r"TCP:\s*(\d+)", softether_text, re.I)
        if sm:
            se_port = int(sm.group(1))
            protocols.append({"protocol": "softether", "transport": "tcp", "port": se_port})
            if re.search(r"UDP:\s*Supported", softether_text, re.I):
                protocols.append({"protocol": "softether", "transport": "udp", "port": se_port})

        # L2TP has fixed protocol ports; keep port=0 because it is a compound
        # IPsec/L2TP endpoint rather than one TCP/UDP service port.
        l2tp_links = cells[5].get("links") or []
        if any("howto_l2tp.aspx" in href for href in l2tp_links):
            protocols.append({"protocol": "l2tp-ipsec", "transport": "udp", "port": 0})

        if ovpn_tcp:
            protocols.append({"protocol": "openvpn", "transport": "tcp", "port": ovpn_tcp})
        if ovpn_udp:
            protocols.append({"protocol": "openvpn", "transport": "udp", "port": ovpn_udp})

        # SSTP hostname can differ from the displayed DDNS hostname and may
        # include a non-443 port in the protocol cell.
        sstp_text = str(cells[7].get("text") or "")
        sstp_links = cells[7].get("links") or []
        if any("howto_sstp.aspx" in href for href in sstp_links):
            sstp_host = hostname
            sstp_port = 443
            sm = re.search(r"SSTP\s*Hostname\s*:\s*([a-z0-9.-]+\.opengw\.net)(?::(\d+))?", sstp_text, re.I)
            if sm:
                sstp_host = sm.group(1).lower()
                if sm.group(2):
                    sstp_port = int(sm.group(2))
            protocols.append({
                "protocol": "sstp",
                "transport": "tcp",
                "port": sstp_port,
                "hostname": sstp_host,
            })

        if not protocols:
            continue

        results.append({
            "hostname": hostname,
            "ip": ip,
            "country": country,
            "sessions": _int(str(cells[2].get("text") or "")),
            "speed": _speed_bps(str(cells[3].get("text") or "")),
            "ping": _ping_ms(str(cells[3].get("text") or "")),
            "score": _int(str(cells[9].get("text") or "")),
            "protocols": protocols,
        })

    return results

_PROTOCOL_FILTER_NAMES = {
    "softether": "C_SoftEther",
    "l2tp-ipsec": "C_L2TP",
    "openvpn": "C_OpenVPN",
    "sstp": "C_SSTP",
}

def fetch_server_table_protocol(url: str, protocol: str, timeout: int = 12) -> list[dict[str, Any]]:
    """Submit VPN Gate's own protocol filter and parse the returned partial table."""
    key = str(protocol or "").strip().lower()
    checkbox = _PROTOCOL_FILTER_NAMES.get(key)
    if not checkbox:
        raise ValueError(f"unsupported VPN Gate protocol filter: {protocol}")

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 AimiliVPN/3.0", "Accept": "text/html"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read().decode("utf-8", errors="replace")

    form_match = re.search(
        r"<form[^>]+method=[\"']post[\"'][^>]*action=[\"']([^\"']*)[\"'][^>]*>",
        raw,
        re.I,
    )
    action = form_match.group(1) if form_match else "./"
    post_url = urllib.parse.urljoin(url, html.unescape(action))

    fields: dict[str, str] = {}
    for match in re.finditer(
        r"<input[^>]+type=[\"']hidden[\"'][^>]*name=[\"']([^\"']+)[\"'][^>]*value=[\"']([^\"']*)[\"']",
        raw,
        re.I,
    ):
        fields[html.unescape(match.group(1))] = html.unescape(match.group(2))

    fields["__EVENTTARGET"] = ""
    fields["__EVENTARGUMENT"] = ""
    fields["Button3"] = "Refresh Servers List"
    for name in _PROTOCOL_FILTER_NAMES.values():
        fields.pop(name, None)
    fields[checkbox] = "on"

    encoded = urllib.parse.urlencode(fields).encode("utf-8")
    post_req = urllib.request.Request(
        post_url,
        data=encoded,
        headers={
            "User-Agent": "Mozilla/5.0 AimiliVPN/3.0",
            "Accept": "text/html",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    with urllib.request.urlopen(post_req, timeout=timeout) as response:
        filtered_html = response.read().decode("utf-8", errors="replace")
    return parse_server_table(filtered_html)


def fetch_server_table(url: str = VPNGATE_HTML_URL, timeout: int = 15) -> list[dict[str, Any]]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 AimiliVPN/3.0",
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read().decode("utf-8", errors="replace")
    return parse_server_table(raw)


def fetch_mirror_urls(url: str = VPNGATE_MIRROR_LIST_URL, timeout: int = 10) -> list[str]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 AimiliVPN/3.0", "Accept": "text/html"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read().decode("utf-8", errors="replace")
    urls = []
    seen = set()
    for match in re.finditer(r"https?://[^\s\"'<>]+/(?:en|cn|ja)/", raw, re.I):
        mirror = html.unescape(match.group(0)).strip()
        if mirror.lower().startswith(("https://www.vpngate.net/", "http://www.vpngate.net/")):
            continue
        mirror = re.sub(r"/(?:cn|ja)/?$", "/en/", mirror, flags=re.I)
        if mirror not in seen:
            seen.add(mirror)
            urls.append(mirror)
    return urls


def fetch_openvpn_endpoint_page(host: str, timeout: int = 12) -> dict[str, Any] | None:
    """Use VPN Gate's direct OpenVPN endpoint page as an exact-host fallback."""
    target = str(host or "").strip()
    if not target or not (target.lower().endswith(".opengw.net") or re.fullmatch(r"[0-9a-fA-F:.]+", target)):
        return None
    query = urllib.parse.urlencode({"fqdn": target})
    url = f"https://www.vpngate.net/en/do_openvpn.aspx?{query}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 AimiliVPN/3.0", "Accept": "text/html"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    host_match = re.search(r"Destination DDNS Hostname:\s*([^<\r\n]+)", raw, re.I)
    ddns = (html.unescape(host_match.group(1)).strip().lower() if host_match else target.lower())
    ip_match = re.search(r"Destination IP Address:\s*([0-9a-fA-F:.]+)", raw, re.I)
    ip = ip_match.group(1).strip() if ip_match else ""
    ports = re.findall(r"OpenVPN Configuration File:\s*[^<\r\n]+?\((TCP|UDP)\s+(\d+)\)", html.unescape(raw), re.I)
    protocols = []
    seen = set()
    for transport, port_text in ports:
        item = ("openvpn", transport.lower(), int(port_text))
        if item not in seen:
            seen.add(item)
            protocols.append({"protocol": "openvpn", "transport": transport.lower(), "port": int(port_text)})
    if not protocols:
        return None
    return {
        "hostname": ddns,
        "ip": ip,
        "country": "",
        "sessions": 0,
        "speed": 0,
        "ping": 0,
        "score": 0,
        "protocols": protocols,
        "_sources": [url],
    }

def find_server_by_endpoint(host: str, port: int, max_mirrors: int | None = None) -> tuple[dict[str, Any] | None, list[str]]:
    """Find one VPN Gate server by hostname/IP + advertised port, returning as soon as a source matches."""
    target_host = str(host or "").strip().lower()
    target_port = int(port or 0)
    sources = [VPNGATE_HTML_URL]
    try:
        mirrors = fetch_mirror_urls()
        if max_mirrors is not None:
            mirrors = mirrors[:max(0, int(max_mirrors))]
        sources.extend(mirrors)
    except Exception:
        pass

    def match_source(source: str) -> tuple[str, list[dict[str, Any]], dict[str, Any] | None]:
        try:
            servers = fetch_server_table(source, timeout=10)
        except Exception:
            return source, [], None
        for server in servers:
            hostname = str(server.get("hostname") or "").strip().lower()
            ip = str(server.get("ip") or "").strip()
            if target_host not in {hostname, ip}:
                continue
            if not any(int(item.get("port") or 0) == target_port for item in server.get("protocols") or []):
                continue
            return source, servers, dict(server)
        return source, servers, None

    successful: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(sources)))) as executor:
        futures = {executor.submit(match_source, source): source for source in sources}
        for future in concurrent.futures.as_completed(futures):
            source, servers, matched = future.result()
            if servers:
                successful.append(source)
            if matched:
                matched["_sources"] = [source]
                # Collect corroborating protocol metadata from already completed/fast sources later
                # only when it arrives; the caller can safely probe the selected endpoint locally.
                matched["source_count"] = 1
                matched["trusted_observation"] = source == VPNGATE_HTML_URL
                return matched, successful

    endpoint_page = fetch_openvpn_endpoint_page(target_host)
    if endpoint_page:
        endpoint_page["source_count"] = 1
        endpoint_page["trusted_observation"] = True
        successful.append("https://www.vpngate.net/en/do_openvpn.aspx")
        return endpoint_page, successful
    return None, successful

def merge_servers(snapshots: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for snapshot in snapshots:
        for server in snapshot:
            key = str(server.get("hostname") or server.get("ip") or "").strip().lower()
            if not key:
                continue
            existing = merged.get(key)
            if existing is None:
                cloned = dict(server)
                cloned["protocols"] = [dict(p) for p in (server.get("protocols") or [])]
                source_url = str(server.get("_source_url") or "")
                cloned["_sources"] = [source_url] if source_url else []
                merged[key] = cloned
                continue

            # Keep fresher non-empty scalar values and union protocol endpoints.
            for field in ("hostname", "ip", "country", "sessions", "speed", "ping", "score"):
                value = server.get(field)
                if value not in (None, "", 0):
                    existing[field] = value

            source_url = str(server.get("_source_url") or "")
            if source_url and source_url not in existing.setdefault("_sources", []):
                existing["_sources"].append(source_url)

            protocol_keys = {
                (
                    str(p.get("protocol") or ""),
                    str(p.get("transport") or ""),
                    int(p.get("port") or 0),
                    str(p.get("hostname") or ""),
                )
                for p in existing.get("protocols") or []
            }
            for endpoint in server.get("protocols") or []:
                pkey = (
                    str(endpoint.get("protocol") or ""),
                    str(endpoint.get("transport") or ""),
                    int(endpoint.get("port") or 0),
                    str(endpoint.get("hostname") or ""),
                )
                if pkey not in protocol_keys:
                    existing.setdefault("protocols", []).append(dict(endpoint))
                    protocol_keys.add(pkey)
    result = list(merged.values())
    for server in result:
        sources = [str(s) for s in (server.get("_sources") or []) if s]
        server["source_count"] = len(sources)
        server["trusted_observation"] = (
            VPNGATE_HTML_URL in sources
            or len(set(sources)) >= 2
        )
    return result

def fetch_multi_source_tables(max_mirrors: int | None = None, include_protocol_filters: bool = True) -> tuple[list[dict[str, Any]], list[str]]:
    """Fetch the main site plus all current mirrors independently and optionally repeat through VPN Gate protocol filters."""
    sources = [VPNGATE_HTML_URL]
    try:
        mirrors = fetch_mirror_urls()
        if max_mirrors is not None:
            mirrors = mirrors[:max(0, int(max_mirrors))]
        sources.extend(mirrors)
    except Exception:
        pass

    protocols = ("softether", "l2tp-ipsec", "openvpn", "sstp")

    def fetch_one(source: str) -> tuple[str, list[list[dict[str, Any]]]]:
        snapshots: list[list[dict[str, Any]]] = []
        try:
            servers = fetch_server_table(source, timeout=12)
            for server in servers:
                server["_source_url"] = source
            if servers:
                snapshots.append(servers)
        except Exception:
            pass

        if include_protocol_filters:
            for protocol in protocols:
                try:
                    servers = fetch_server_table_protocol(source, protocol, timeout=12)
                    for server in servers:
                        server["_source_url"] = f"{source}#protocol={protocol}"
                    if servers:
                        snapshots.append(servers)
                except Exception:
                    continue
        return source, snapshots

    snapshots: list[list[dict[str, Any]]] = []
    successful_sources: list[str] = []
    workers = min(8, max(1, len(sources)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for source, source_snapshots in executor.map(fetch_one, sources):
            if source_snapshots:
                snapshots.extend(source_snapshots)
                successful_sources.append(source)
    return merge_servers(snapshots), successful_sources