#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any

from vpn_utils import COUNTRY_TRANSLATIONS, canonical_country_name, country_from_location

# Same buckets as protocol_endpoint_to_ui_node. DEGRADED and UNAVAILABLE
# render as 不可用; only TESTING renders as 检测中. Counting DEGRADED as
# 检测中 made the dropdown disagree with the rows.
_UI_STATUS_GROUPS = {
    "usable": ("HOT", "AVAILABLE", "TESTING", "NEW"),
    "available": ("HOT", "AVAILABLE"),
    "testing": ("TESTING",),
    "not_checked": ("NEW",),
    "unavailable": ("DEGRADED", "COOLDOWN", "STALE", "RETIRED", "UNAVAILABLE"),
}

# dedupe_ui_nodes collapses identical protocol/IP/port rows and keeps every
# port-less endpoint. Counts have to use that same identity or the dropdown
# and the footer stay ahead of the table.
_UI_ROW_KEY_SQL = (
    "CASE WHEN COALESCE(e.port,0)>0 "
    "THEN LOWER(e.protocol)||'|'||s.current_ip||'|'||CAST(e.port AS TEXT) "
    "ELSE 'id:'||e.endpoint_id END"
)


_UI_LATENCY_SQL = (
    "CASE "
    "WHEN CAST(COALESCE(json_extract(e.metadata_json,'$.tcp_rtt_ms'),0) AS INTEGER) BETWEEN 1 AND 1500 "
    "THEN CAST(COALESCE(json_extract(e.metadata_json,'$.tcp_rtt_ms'),0) AS INTEGER) "
    "WHEN CAST(e.latency_ewma AS INTEGER) BETWEEN 1 AND 1500 THEN CAST(e.latency_ewma AS INTEGER) "
    "ELSE 0 END"
)
_UI_STATUS_RANK = {
    "HOT": 0,
    "AVAILABLE": 1,
    "TESTING": 2,
    "NEW": 3,
    "DEGRADED": 4,
    "COOLDOWN": 5,
    "STALE": 6,
    "RETIRED": 7,
    "UNAVAILABLE": 8,
}
_LATENCY_FILTERS = {"", "100", "200", "400", "800", "1000", "gt1000"}


def normalize_latency_filter(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in ("0", "all", "any", "none"):
        return ""
    return text if text in _LATENCY_FILTERS else ""


def _ui_list_filters(country="", status="", protocol="", ip_type="", speed_min_bps=0, latency=""):
    """WHERE clause shared by the table, the status badges, and the country menu.

    Every predicate is on the same endpoint. Separate EXISTS checks counted a
    server that had the protocol on one endpoint and the status on another.
    """
    country = str(country or "").strip()
    status = str(status or "").strip().lower()
    protocol = str(protocol or "").strip().lower()
    ip_type = str(ip_type or "").strip().lower()
    speed_min_bps = int(speed_min_bps or 0)
    latency = normalize_latency_filter(latency)
    where = [
        "TRIM(COALESCE(s.current_ip,''))<>''",
        "TRIM(COALESCE(e.protocol,''))<>''",
    ]
    params: list[Any] = []
    if country:
        where.append("s.country=?")
        params.append(country)
    if protocol and protocol != "all":
        where.append("LOWER(e.protocol)=?")
        params.append(protocol)
    if ip_type and ip_type != "all":
        where.append("LOWER(COALESCE(json_extract(s.metadata_json,'$.ip_type'),''))=?")
        params.append(ip_type)
    if speed_min_bps < 0:
        where.append(
            "CAST(COALESCE((SELECT o.speed FROM observations o "
            "WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS INTEGER) "
            "BETWEEN 1 AND 9999999"
        )
    elif speed_min_bps > 0:
        where.append(
            "CAST(COALESCE((SELECT o.speed FROM observations o "
            "WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS INTEGER) >= ?"
        )
        params.append(speed_min_bps)
    if latency == "gt1000":
        where.append("COALESCE(e.ui_latency_ms,0) > 1000")
    elif latency:
        where.append("COALESCE(e.ui_latency_ms,0) BETWEEN 1 AND ?")
        params.append(int(latency))
    if status and status != "all":
        allowed = _UI_STATUS_GROUPS.get(status)
        if allowed:
            where.append("UPPER(e.status) IN (" + ",".join("?" for _ in allowed) + ")")
            params.extend(allowed)
    return where, params


def _attach_latest_observations(db: sqlite3.Connection, rows: list[dict[str, Any]]) -> None:
    """Fill ping/speed/sessions/score for an already limited page.

    The list query used to run four observation lookups for every matching
    endpoint before LIMIT. Only the rows actually returned need that data.
    """
    keys: list[str] = []
    seen: set[str] = set()
    for row in rows:
        key = str(row.get("server_key") or "")
        if key and key not in seen:
            seen.add(key)
            keys.append(key)
    by_key: dict[str, sqlite3.Row] = {}
    for key in keys:
        obs = db.execute(
            "SELECT ping, speed, sessions, score FROM observations "
            "WHERE server_key=? ORDER BY seen_at DESC, id DESC LIMIT 1",
            (key,),
        ).fetchone()
        if obs is not None:
            by_key[key] = obs
    for row in rows:
        obs = by_key.get(str(row.get("server_key") or ""))
        row["latest_ping"] = int(obs["ping"] or 0) if obs is not None else 0
        row["latest_speed"] = int(obs["speed"] or 0) if obs is not None else 0
        row["latest_sessions"] = int(obs["sessions"] or 0) if obs is not None else 0
        row["latest_server_score"] = int(obs["score"] or 0) if obs is not None else 0



_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS servers (
    server_key TEXT PRIMARY KEY,
    hostname TEXT,
    current_ip TEXT,
    country TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    last_source TEXT,
    missing_count INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'NEW',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id TEXT PRIMARY KEY,
    server_key TEXT NOT NULL,
    protocol TEXT NOT NULL,
    transport TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 0,
    config_ref TEXT,
    status TEXT NOT NULL DEFAULT 'NEW',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    last_success REAL NOT NULL DEFAULT 0,
    last_failure REAL NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    fail_streak INTEGER NOT NULL DEFAULT 0,
    success_streak INTEGER NOT NULL DEFAULT 0,
    next_test REAL NOT NULL DEFAULT 0,
    latency_ewma REAL NOT NULL DEFAULT 0,
    jitter_ewma REAL NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY(server_key) REFERENCES servers(server_key)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_sched ON endpoints(status, next_test, last_success);
CREATE INDEX IF NOT EXISTS idx_endpoints_server ON endpoints(server_key);
CREATE INDEX IF NOT EXISTS idx_endpoints_protocol_status ON endpoints(protocol, status, server_key);
CREATE INDEX IF NOT EXISTS idx_servers_seen ON servers(last_seen, state);
CREATE INDEX IF NOT EXISTS idx_servers_country_ip ON servers(country, current_ip);
CREATE INDEX IF NOT EXISTS idx_servers_country_ip_state ON servers(country, current_ip, state);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_key TEXT NOT NULL,
    source TEXT NOT NULL,
    seen_at REAL NOT NULL,
    ip TEXT,
    ping INTEGER NOT NULL DEFAULT 0,
    speed INTEGER NOT NULL DEFAULT 0,
    sessions INTEGER NOT NULL DEFAULT 0,
    score INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_obs_server_time ON observations(server_key, seen_at DESC);
"""

def _empty_upsert_stats() -> dict[str, Any]:
    return {
        "inserted_servers": 0,
        "updated_servers": 0,
        "unchanged_servers": 0,
        "inserted_endpoints": 0,
        "updated_endpoints": 0,
        "recovered_endpoints": 0,
        "unchanged_endpoints": 0,
        "ip_changed_endpoints": 0,
        "new_endpoint_ids": [],
    }


class NodePool:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.lock = threading.RLock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._stats_cache: tuple[float, dict[str, Any]] | None = None
        self._status_counts_cache: dict[tuple[str, str, str], tuple[float, dict[str, int]]] = {}
        self._scoped_page_cache: dict[tuple, tuple[float, tuple[list[dict[str, Any]], int]]] = {}
        self._scoped_page_stale: dict[tuple, tuple[list[dict[str, Any]], int]] = {}
        self._country_catalog_cache: dict[tuple[str, str, str], tuple[float, dict[str, Any]]] = {}
        self._scoped_query_gate_guard = threading.Lock()
        self._scoped_query_gates: dict[tuple, threading.Lock] = {}
        self._ui_order_cache: dict[tuple, tuple[float, list[dict[str, Any]]]] = {}
        self._ui_order_lock = threading.Lock()
        self._country_catalog_gate = threading.Lock()
        self._status_counts_gate = threading.Lock()
        with closing(self._connect()) as db:
            db.executescript(_SCHEMA)
            self._ensure_endpoint_columns(db)
            self._ensure_ui_indexes(db)
            removed = self._purge_duplicate_rows(db)
            db.commit()
        if removed:
            threading.Thread(target=self._vacuum_freed_space, daemon=True).start()

    @staticmethod
    def _ensure_endpoint_columns(db: sqlite3.Connection) -> None:
        cols = {str(row[1]) for row in db.execute("PRAGMA table_info(endpoints)")}
        if "last_connected_at" not in cols:
            db.execute("ALTER TABLE endpoints ADD COLUMN last_connected_at REAL NOT NULL DEFAULT 0")
        if "last_session_seconds" not in cols:
            db.execute("ALTER TABLE endpoints ADD COLUMN last_session_seconds INTEGER NOT NULL DEFAULT 0")
        if "stability" not in cols:
            db.execute("ALTER TABLE endpoints ADD COLUMN stability TEXT NOT NULL DEFAULT ''")
        if "ui_latency_ms" not in cols:
            db.execute("ALTER TABLE endpoints ADD COLUMN ui_latency_ms INTEGER NOT NULL DEFAULT 0")
            db.execute(
                """
                UPDATE endpoints SET ui_latency_ms = CASE
                    WHEN CAST(COALESCE(json_extract(metadata_json,'$.tcp_rtt_ms'),0) AS INTEGER) BETWEEN 1 AND 1500
                        THEN CAST(json_extract(metadata_json,'$.tcp_rtt_ms') AS INTEGER)
                    WHEN CAST(latency_ewma AS INTEGER) BETWEEN 1 AND 1500 THEN CAST(latency_ewma AS INTEGER)
                    ELSE 0 END
                """
            )

    @staticmethod
    def _ensure_ui_indexes(db: sqlite3.Connection) -> None:
        # Expression index matches _ui_list_filters ip_type predicate. Older
        # SQLite builds skip it; the filter still works without the index.
        try:
            db.execute(
                "CREATE INDEX IF NOT EXISTS idx_servers_ip_type_country ON servers("
                "LOWER(COALESCE(json_extract(metadata_json,'$.ip_type'),'')), country, current_ip)"
            )
        except sqlite3.OperationalError:
            pass

    @staticmethod
    def availability_label(seconds: int, unstable: bool) -> str:
        if unstable:
            return "不稳定"
        if int(seconds or 0) >= 24 * 3600:
            return "高可用"
        if int(seconds or 0) >= 3600:
            return "可用"
        return "待可用"

    @staticmethod
    def session_grade(sessions: int, speed_bps: int) -> str:
        """0 会话且带宽够用是非常优质。10 以内优质，再按 20/30/50/80/100/100+。"""
        sessions = int(sessions or 0)
        speed_bps = int(speed_bps or 0)
        if sessions <= 0 and speed_bps >= 50_000_000:
            return "非常优质"
        if sessions <= 10:
            return "优质"
        if sessions <= 20:
            return "20"
        if sessions <= 30:
            return "30"
        if sessions <= 50:
            return "50"
        if sessions <= 80:
            return "80"
        if sessions <= 100:
            return "100"
        return "100+"

    @staticmethod
    def session_grade_rank(sessions: int | None, speed_bps: int, known: bool) -> int:
        if not known or sessions is None:
            return 4
        order = {"非常优质": 0, "优质": 1, "20": 2, "30": 3, "50": 4, "80": 5, "100": 6, "100+": 7}
        return order.get(NodePool.session_grade(int(sessions), speed_bps), 4)

    @staticmethod
    def _stability_decision(meta: dict[str, Any], now: float, session_seconds: int, fail_streak: int) -> str:
        """1 小时以上可标可用。1 到 6 小时里频繁掉线才标不稳定。"""
        if not meta.get("watched_since"):
            meta["watched_since"] = now
        watched = max(0.0, now - float(meta.get("watched_since") or now))
        events = meta.get("stability_events") if isinstance(meta.get("stability_events"), list) else []
        flaps = len([item for item in events if isinstance(item, dict) and now - float(item.get("t") or 0) <= 30 * 60])
        if float(meta.get("slow_until") or 0) > now:
            meta["stability"] = "不稳定"
            return "不稳定"
        frequent = flaps >= 4
        seconds = int(session_seconds or 0)
        in_watch = (3600 <= watched < 6 * 3600) or (3600 <= seconds < 6 * 3600)
        if seconds >= 3600 and not frequent:
            label = NodePool.availability_label(seconds, False)
        elif in_watch and frequent:
            label = "不稳定"
        elif seconds < 3600 and watched < 3600:
            label = "待可用"
        elif str(meta.get("stability") or "") in ("不稳定", "unstable") and frequent:
            label = "不稳定"
        elif seconds >= 3600:
            label = NodePool.availability_label(seconds, False)
        else:
            label = "待可用"
        meta["stability"] = label
        return label

    def mark_slow(self, endpoint_id: str, seconds: int = 1800) -> None:
        """Measured under 10 Mbps. The tag drops when slow_until passes."""
        endpoint_id = str(endpoint_id or "").strip()
        if not endpoint_id:
            return
        now = time.time()
        with self.lock, closing(self._connect()) as db:
            row = db.execute(
                "SELECT metadata_json FROM endpoints WHERE endpoint_id=?",
                (endpoint_id,),
            ).fetchone()
            if not row:
                return
            try:
                meta = json.loads(row["metadata_json"] or "{}")
            except Exception:
                meta = {}
            if not isinstance(meta, dict):
                meta = {}
            meta["slow_until"] = now + max(60, int(seconds))
            meta["stability"] = "不稳定"
            db.execute(
                "UPDATE endpoints SET stability=?, metadata_json=? WHERE endpoint_id=?",
                ("不稳定", json.dumps(meta, ensure_ascii=False), endpoint_id),
            )
            db.commit()

    def _purge_duplicate_rows(self, db: sqlite3.Connection) -> int:
        """Delete duplicate protocol+IP+port rows and leftover observations."""
        removed = 0
        cur = db.execute(
            """
            DELETE FROM endpoints
            WHERE endpoint_id IN (
                SELECT endpoint_id FROM (
                    SELECT e.endpoint_id,
                           ROW_NUMBER() OVER (
                             PARTITION BY LOWER(e.protocol), s.current_ip, e.port
                             ORDER BY CASE UPPER(e.status)
                               WHEN 'HOT' THEN 0 WHEN 'AVAILABLE' THEN 1 WHEN 'TESTING' THEN 2
                               WHEN 'RETIRED' THEN 9 ELSE 3 END,
                               e.last_success DESC, e.last_seen DESC
                           ) AS rn
                    FROM endpoints e
                    JOIN servers s ON s.server_key=e.server_key
                    WHERE COALESCE(e.port,0)>0 AND TRIM(COALESCE(s.current_ip,''))<>''
                ) WHERE rn>1
            )
            """
        )
        removed += int(cur.rowcount or 0)
        cur = db.execute("DELETE FROM servers WHERE server_key NOT IN (SELECT DISTINCT server_key FROM endpoints)")
        removed += int(cur.rowcount or 0)
        cur = db.execute(
            """
            DELETE FROM observations
            WHERE id NOT IN (SELECT MAX(id) FROM observations GROUP BY server_key)
            """
        )
        removed += int(cur.rowcount or 0)
        cur = db.execute("DELETE FROM observations WHERE server_key NOT IN (SELECT server_key FROM servers)")
        removed += int(cur.rowcount or 0)
        return removed

    def _vacuum_freed_space(self) -> None:
        try:
            with closing(self._connect(30000)) as db:
                db.execute("VACUUM")
        except Exception:
            return

    @staticmethod
    def _touch_stability(meta: dict[str, Any], now: float, kind: str, fail_streak: int, success_streak: int, session_seconds: int) -> str:
        events = meta.get("stability_events")
        if not isinstance(events, list):
            events = []
        events.append({"t": now, "k": kind})
        window = 30 * 60
        events = [item for item in events if isinstance(item, dict) and now - float(item.get("t") or 0) <= window][-8:]
        meta["stability_events"] = events
        label = NodePool._stability_decision(meta, now, int(session_seconds or 0), int(fail_streak or 0))
        return label

    def note_connection_started(self, endpoint_id: str) -> None:
        endpoint_id = str(endpoint_id or "").strip()
        if not endpoint_id:
            return
        now = time.time()
        with self.lock, closing(self._connect()) as db:
            row = db.execute(
                "SELECT metadata_json, fail_streak, success_streak, last_session_seconds FROM endpoints WHERE endpoint_id=?",
                (endpoint_id,),
            ).fetchone()
            if not row:
                return
            try:
                meta = json.loads(row["metadata_json"] or "{}")
            except Exception:
                meta = {}
            if not isinstance(meta, dict):
                meta = {}
            stability = self._touch_stability(meta, now, "up", int(row["fail_streak"] or 0), int(row["success_streak"] or 0), int(row["last_session_seconds"] or 0))
            db.execute(
                "UPDATE endpoints SET last_connected_at=?, stability=?, metadata_json=? WHERE endpoint_id=?",
                (now, stability, json.dumps(meta, ensure_ascii=False), endpoint_id),
            )
            db.commit()

    def note_connection_ended(self, endpoint_id: str) -> None:
        endpoint_id = str(endpoint_id or "").strip()
        if not endpoint_id:
            return
        now = time.time()
        with self.lock, closing(self._connect()) as db:
            row = db.execute(
                "SELECT metadata_json, fail_streak, success_streak, last_connected_at FROM endpoints WHERE endpoint_id=?",
                (endpoint_id,),
            ).fetchone()
            if not row:
                return
            started = float(row["last_connected_at"] or 0)
            session = int(max(0, now - started)) if started > 0 else 0
            try:
                meta = json.loads(row["metadata_json"] or "{}")
            except Exception:
                meta = {}
            if not isinstance(meta, dict):
                meta = {}
            meta["last_session_seconds"] = session
            stability = self._touch_stability(meta, now, "down", int(row["fail_streak"] or 0), int(row["success_streak"] or 0), session)
            db.execute(
                "UPDATE endpoints SET last_session_seconds=?, stability=?, metadata_json=? WHERE endpoint_id=?",
                (session, stability, json.dumps(meta, ensure_ascii=False), endpoint_id),
            )
            db.commit()

    def refresh_live_availability(self, endpoint_id: str) -> str:
        """Promote the live exit as its current connection gets longer."""
        endpoint_id = str(endpoint_id or "").strip()
        if not endpoint_id:
            return ""
        now = time.time()
        with self.lock, closing(self._connect()) as db:
            row = db.execute(
                "SELECT last_connected_at, last_session_seconds, stability, metadata_json FROM endpoints WHERE endpoint_id=?",
                (endpoint_id,),
            ).fetchone()
            if not row:
                return ""
            started = float(row["last_connected_at"] or 0)
            seconds = int(max(0, now - started)) if started > 0 else int(row["last_session_seconds"] or 0)
            try:
                meta = json.loads(row["metadata_json"] or "{}")
            except Exception:
                meta = {}
            if not isinstance(meta, dict):
                meta = {}
            current = str(row["stability"] or meta.get("stability") or "")
            label = self._stability_decision(meta, now, seconds, 0)
            if label == current:
                return label
            meta["stability"] = label
            db.execute(
                "UPDATE endpoints SET stability=?, metadata_json=? WHERE endpoint_id=?",
                (label, json.dumps(meta, ensure_ascii=False), endpoint_id),
            )
            db.commit()
        return label

    def invalidate_scoped_pages(self) -> None:
        self._scoped_page_cache.clear()
        self._scoped_page_stale.clear()

    def invalidate_ui_lists(self) -> None:
        """Drop every cached list, badge count, and country menu.

        Probe writes stay on the short TTL so a detection storm cannot turn
        each browser refresh into a full scan. A manual insert must show up
        on the next filter read, so that path clears these snapshots.
        """
        self.invalidate_scoped_pages()
        self._country_catalog_cache.clear()
        self._status_counts_cache.clear()
        self._ui_order_cache.clear()
        self._stats_cache = None

    def _invalidate_read_caches(self) -> None:
        # Writes do not synchronously flush every UI snapshot. Status/country
        # statistics and bounded pages are intentionally short-TTL snapshots;
        # keeping them warm prevents a probe storm from turning every browser
        # request into a SQLite scan. The data remains authoritative after the
        # cache TTL and is refreshed automatically.
        self._stats_cache = None

    def _connect(self, busy_ms: int = 8000, *, readonly: bool = False) -> sqlite3.Connection:
        timeout = max(0.05, busy_ms / 1000)
        if readonly:
            # UI pages must not wait on a writer. WAL snapshots let a read-only
            # connection proceed while probes update the same database.
            db = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=timeout)
        else:
            db = sqlite3.connect(str(self.db_path), timeout=timeout)
        db.row_factory = sqlite3.Row
        db.execute(f"PRAGMA busy_timeout={max(0, int(busy_ms))}")
        if not readonly:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            db.execute("PRAGMA foreign_keys=ON")
            # Writers are rare. 8MB of mmap is enough; 32MB on a 512MB box
            # competed with the proxy for RAM.
            db.execute("PRAGMA mmap_size=8388608")
        db.execute("PRAGMA temp_store=MEMORY")
        # Negative cache_size is KiB. 16MB per connection is larger than this
        # database and, on the 512MB Japan host, each open page pushed the
        # manager into swap. A 0.3s scan then took more than a minute. The
        # kernel already caches the file.
        db.execute("PRAGMA cache_size=-256" if readonly else "PRAGMA cache_size=-1024")
        return db

    @staticmethod
    def canonical_host(hostname: str) -> str:
        host = str(hostname or "").strip().lower().rstrip(".")
        # VPN Gate publishes the same volunteer as both vpn123 and vpn123.opengw.net.
        if host.startswith("vpn") and host[3:].isdigit():
            return host + ".opengw.net"
        return host

    @staticmethod
    def server_key(node: dict[str, Any]) -> str:
        hostname = NodePool.canonical_host(node.get("host_name") or node.get("hostname") or "")
        if hostname:
            return hostname
        ip = str(node.get("ip") or node.get("remote_host") or "").strip()
        return ip or str(node.get("id") or "").strip()

    @staticmethod
    def endpoint_id(server_key: str, protocol: str, transport: str, port: int) -> str:
        raw = f"{server_key}|{protocol}|{transport}|{port}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:32]

    def upsert_openvpn_snapshot(self, nodes: list[dict[str, Any]], source: str = "official_csv") -> None:
        """Persist OpenVPN CSV candidates into the same Master Pool used by UI and probes.
        This keeps browser refreshes completely independent from resource discovery.
        """
        servers: list[dict[str, Any]] = []
        for node in nodes or []:
            host = NodePool.canonical_host(node.get("host_name") or node.get("remote_host") or node.get("ip") or "")
            protocol = {
                "protocol": "openvpn",
                "transport": str(node.get("proto") or "tcp").strip().lower() or "tcp",
                "port": int(node.get("remote_port") or 0),
                "hostname": host,
            }
            servers.append({
                "hostname": host,
                "ip": str(node.get("ip") or node.get("remote_host") or "").strip(),
                "country": node.get("country") or "",
                "catalog_country": node.get("catalog_country") or "",
                "ping": node.get("ping") or node.get("latency_ms") or 0,
                "speed": node.get("speed") or 0,
                "sessions": node.get("sessions") or 0,
                "score": node.get("score") or 0,
                "protocols": [protocol],
                "_sources": [source],
                "owner": node.get("owner") or "",
                "asn": node.get("asn") or "",
                "as_name": node.get("as_name") or "",
                "location": node.get("location") or "",
                "ip_type": node.get("ip_type") or "",
                "quality": node.get("quality") or "",
                "geo_verified": bool(node.get("geo_verified")),
            })
            if node.get("manual_added_at"):
                servers[-1]["manual_added_at"] = float(node.get("manual_added_at") or 0)
        if servers:
            return self.upsert_discovery_snapshot(servers, source=source)
        return _empty_upsert_stats()

    def upsert_discovery_snapshot(self, servers: list[dict[str, Any]], source: str = "official_html") -> dict[str, int]:
        now = time.time()
        seen_keys: set[str] = set()
        stats = _empty_upsert_stats()
        new_ids: list[str] = []
        with self.lock, closing(self._connect()) as db:
            for server in servers:
                hostname = str(server.get("hostname") or server.get("host_name") or "").strip().lower()
                ip = str(server.get("ip") or "").strip()
                key = hostname or ip
                if not key:
                    continue
                seen_keys.add(key)
                country = canonical_country_name(server.get("country") or "")
                metadata = {
                    "source": source,
                    "ping": int(server.get("ping") or 0),
                    "speed": int(server.get("speed") or 0),
                    "sessions": int(server.get("sessions") or 0),
                    "session_grade": NodePool.session_grade(int(server.get("sessions") or 0), int(server.get("speed") or 0)),
                    "score": int(server.get("score") or 0),
                    "source_count": int(server.get("source_count") or 0),
                    "trusted_observation": bool(server.get("trusted_observation")),
                    "sources": list(server.get("_sources") or []),
                }
                if server.get("manual_added_at"):
                    metadata["manual_added_at"] = float(server.get("manual_added_at"))
                existing_server = db.execute(
                    "SELECT current_ip, country, metadata_json FROM servers WHERE server_key=?",
                    (key,),
                ).fetchone()
                old_ip = str(existing_server["current_ip"] or "").strip() if existing_server else ""
                old_country = str(existing_server["country"] or "") if existing_server else ""
                ip_changed = bool(old_ip and ip and old_ip != ip)
                if not existing_server:
                    stats["inserted_servers"] += 1
                elif ip_changed or (country and country != old_country):
                    stats["updated_servers"] += 1
                else:
                    stats["unchanged_servers"] += 1
                if existing_server:
                    try:
                        previous_meta = json.loads(existing_server["metadata_json"] or "{}")
                        if isinstance(previous_meta, dict):
                            previous_meta.update({
                                k: v for k, v in metadata.items()
                                if k in ("sessions", "session_grade") or v not in (None, "")
                            })
                            metadata = previous_meta
                    except Exception:
                        pass
                if ip_changed:
                    for field in ("owner", "asn", "as_name", "location", "ip_type", "quality"):
                        metadata.pop(field, None)
                    metadata.pop("geo_verified", None)
                for field in ("owner", "asn", "as_name", "location", "ip_type", "quality"):
                    incoming = str(server.get(field) or "").strip()
                    if incoming:
                        metadata[field] = incoming
                catalog = canonical_country_name(server.get("catalog_country") or "")
                if catalog:
                    metadata["catalog_country"] = catalog
                elif not metadata.get("catalog_country"):
                    metadata["catalog_country"] = country
                if server.get("geo_verified"):
                    metadata["geo_verified"] = True
                    located = country_from_location(metadata.get("location"))
                    if located:
                        country = located
                db.execute(
                    """
                    INSERT INTO servers(server_key, hostname, current_ip, country, first_seen, last_seen, last_source, missing_count, state, metadata_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(server_key) DO UPDATE SET
                      hostname=CASE WHEN excluded.hostname<>'' THEN excluded.hostname ELSE servers.hostname END,
                      current_ip=CASE WHEN excluded.current_ip<>'' THEN excluded.current_ip ELSE servers.current_ip END,
                      country=CASE WHEN excluded.country<>'' THEN excluded.country ELSE servers.country END,
                      last_seen=excluded.last_seen,
                      last_source=excluded.last_source,
                      missing_count=0,
                      state=CASE WHEN servers.state IN ('RETIRED','STALE') THEN 'NEW' ELSE servers.state END,
                      metadata_json=excluded.metadata_json
                    """,
                    (key, hostname, ip, country, now, now, source, 0, "NEW", json.dumps(metadata, ensure_ascii=False)),
                )

                for endpoint in server.get("protocols") or []:
                    protocol = str(endpoint.get("protocol") or "").strip().lower()
                    transport = str(endpoint.get("transport") or "unknown").strip().lower()
                    try:
                        port = int(endpoint.get("port") or 0)
                    except (TypeError, ValueError):
                        port = 0
                    if not protocol:
                        continue
                    if ip and port > 0:
                        duplicate = db.execute(
                            """
                            SELECT e.endpoint_id FROM endpoints e
                            JOIN servers s ON s.server_key=e.server_key
                            WHERE s.current_ip=? AND e.port=? AND LOWER(e.protocol)=?
                            LIMIT 1
                            """,
                            (ip, port, protocol),
                        ).fetchone()
                        if duplicate:
                            db.execute(
                                "UPDATE endpoints SET last_seen=? WHERE endpoint_id=?",
                                (now, duplicate["endpoint_id"]),
                            )
                            stats["unchanged_endpoints"] += 1
                            continue
                    eid = self.endpoint_id(key, protocol, transport, port)
                    endpoint_meta = {
                        "hostname": str(endpoint.get("hostname") or hostname or "").strip().lower(),
                        "ip": ip,
                        "source": source,
                        "source_count": int(server.get("source_count") or 0),
                        "trusted_observation": bool(server.get("trusted_observation")),
                    }
                    if server.get("manual_added_at"):
                        endpoint_meta["manual_added_at"] = float(server.get("manual_added_at"))
                    existing_endpoint = db.execute(
                        "SELECT status, metadata_json FROM endpoints WHERE endpoint_id=?",
                        (eid,),
                    ).fetchone()
                    previous_status = str(existing_endpoint["status"] or "").upper() if existing_endpoint else ""
                    if existing_endpoint:
                        try:
                            previous_endpoint_meta = json.loads(existing_endpoint["metadata_json"] or "{}")
                            if isinstance(previous_endpoint_meta, dict):
                                previous_endpoint_meta.update({k: v for k, v in endpoint_meta.items() if v not in (None, "")})
                                endpoint_meta = previous_endpoint_meta
                        except Exception:
                            pass
                    db.execute(
                        """
                        INSERT INTO endpoints(endpoint_id, server_key, protocol, transport, port, status, first_seen, last_seen, metadata_json)
                        VALUES(?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(endpoint_id) DO UPDATE SET
                          last_seen=excluded.last_seen,
                          metadata_json=excluded.metadata_json,
                          status=CASE WHEN endpoints.status IN ('RETIRED','STALE') THEN 'NEW' ELSE endpoints.status END,
                      next_test=CASE WHEN endpoints.status IN ('RETIRED','STALE') THEN 0 ELSE endpoints.next_test END
                        """,
                        (eid, key, protocol, transport, port, "NEW", now, now, json.dumps(endpoint_meta, ensure_ascii=False)),
                    )
                    if not existing_endpoint:
                        stats["inserted_endpoints"] += 1
                        new_ids.append(eid)
                    elif previous_status in ("RETIRED", "STALE"):
                        stats["recovered_endpoints"] += 1
                        new_ids.append(eid)
                    elif ip_changed and previous_status not in ("NEW",):
                        stats["ip_changed_endpoints"] += 1
                        new_ids.append(eid)
                    else:
                        stats["unchanged_endpoints"] += 1

                if ip_changed:
                    db.execute(
                        """
                        UPDATE endpoints
                        SET status='NEW', next_test=0
                        WHERE server_key=? AND UPPER(status) NOT IN ('RETIRED')
                        """,
                        (key,),
                    )

                db.execute(
                    "INSERT INTO observations(server_key, source, seen_at, ip, ping, speed, sessions, score) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        key, source, now, ip,
                        int(server.get("ping") or 0), int(server.get("speed") or 0),
                        int(server.get("sessions") or 0), int(server.get("score") or 0),
                    ),
                )

            # The HTML list is explicitly partial, so absence in this snapshot
            # must not aggressively age every historical server. Only endpoints
            # that remain unseen for long periods are naturally deprioritized by
            # next_test / last_seen scheduling.
            db.commit()
        stats["new_endpoint_ids"] = new_ids
        self.last_upsert_stats = stats
        if str(source or "").startswith("manual"):
            self.invalidate_ui_lists()
        return stats

    def upsert_shared_snapshot(self, resources: list[dict[str, Any]], peer_id: str = "", source_name: str = "shared") -> int:
        """Import peer inventory without copying that peer's latency.

        Domain, IP, protocol, port, country, availability and speed are useful.
        Latency is measured on this machine. An existing local status is never
        downgraded, and a shared row is not marked as a trusted local observation.
        """
        imported = 0
        now = time.time()
        peer_id = str(peer_id or "").strip()
        source = ("share:" + str(source_name or "shared"))[:80]
        with self.lock, closing(self._connect()) as db:
            for row in resources or []:
                if not isinstance(row, dict):
                    continue
                hostname = str(row.get("hostname") or "").strip().lower()
                ip = str(row.get("ip") or "").strip()
                key = hostname or ip
                protocol = str(row.get("protocol") or "").strip().lower()
                if not key or not protocol:
                    continue
                transport = str(row.get("transport") or "unknown").strip().lower() or "unknown"
                try:
                    port = int(row.get("port") or 0)
                except (TypeError, ValueError):
                    port = 0
                country = canonical_country_name(row.get("country") or "")
                shared_status = str(row.get("status") or "NEW").upper()
                if shared_status not in ("NEW", "AVAILABLE", "HOT", "DEGRADED", "COOLDOWN"):
                    shared_status = "NEW"
                try:
                    speed = max(0, int(row.get("speed_bps") or row.get("speed") or 0))
                except (TypeError, ValueError):
                    speed = 0
                server_row = db.execute("SELECT metadata_json, state FROM servers WHERE server_key=?", (key,)).fetchone()
                metadata: dict[str, Any] = {}
                if server_row:
                    try:
                        metadata = json.loads(server_row["metadata_json"] or "{}")
                    except Exception:
                        metadata = {}
                    if not isinstance(metadata, dict):
                        metadata = {}
                peer_ids = [str(x) for x in (metadata.get("shared_peer_ids") or []) if str(x)]
                if peer_id and peer_id not in peer_ids:
                    peer_ids.append(peer_id)
                metadata["shared_peer_ids"] = peer_ids
                metadata["shared_peer_count"] = len(peer_ids)
                metadata["shared_status"] = shared_status
                server_info = row.get("server") if isinstance(row.get("server"), dict) else {}
                for field in ("owner", "asn", "as_name", "location", "ip_type", "quality"):
                    incoming = str(server_info.get(field) or "").strip()
                    if incoming and not str(metadata.get(field) or "").strip():
                        metadata[field] = incoming
                if speed > 0:
                    metadata["shared_speed_bps"] = speed
                metadata.pop("trusted_observation", None)
                located = country_from_location(metadata.get("location"))
                metadata["catalog_country"] = country
                if located:
                    country = located
                server_state = "NEW"
                if server_row and str(server_row["state"] or "") not in ("", "STALE", "RETIRED"):
                    server_state = str(server_row["state"])
                db.execute(
                    """
                    INSERT INTO servers(server_key, hostname, current_ip, country, first_seen, last_seen, last_source, missing_count, state, metadata_json)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(server_key) DO UPDATE SET
                      hostname=CASE WHEN excluded.hostname<>'' THEN excluded.hostname ELSE servers.hostname END,
                      current_ip=CASE WHEN excluded.current_ip<>'' THEN excluded.current_ip ELSE servers.current_ip END,
                      country=CASE WHEN excluded.country<>'' THEN excluded.country ELSE servers.country END,
                      last_seen=excluded.last_seen,
                      last_source=excluded.last_source,
                      metadata_json=excluded.metadata_json,
                      state=CASE WHEN servers.state IN ('STALE','RETIRED') THEN 'NEW' ELSE servers.state END
                    """,
                    (key, hostname, ip, country, now, now, source, 0, server_state, json.dumps(metadata, ensure_ascii=False)),
                )
                if ip:
                    twins = db.execute(
                        "SELECT server_key, metadata_json FROM servers WHERE current_ip=? AND server_key<>?",
                        (ip, key),
                    ).fetchall()
                    for twin in twins:
                        try:
                            twin_meta = json.loads(twin["metadata_json"] or "{}")
                        except Exception:
                            twin_meta = {}
                        if not isinstance(twin_meta, dict):
                            twin_meta = {}
                        changed = False
                        for field in ("owner", "asn", "as_name", "location", "ip_type", "quality"):
                            incoming = str(metadata.get(field) or "").strip()
                            if incoming and not str(twin_meta.get(field) or "").strip():
                                twin_meta[field] = incoming
                                changed = True
                        if changed:
                            db.execute(
                                "UPDATE servers SET metadata_json=? WHERE server_key=?",
                                (json.dumps(twin_meta, ensure_ascii=False), twin["server_key"]),
                            )
                existing = None
                if ip and port > 0:
                    existing = db.execute(
                        """
                        SELECT e.endpoint_id, e.status, e.metadata_json FROM endpoints e
                        JOIN servers s ON s.server_key=e.server_key
                        WHERE s.current_ip=? AND e.port=? AND LOWER(e.protocol)=?
                        LIMIT 1
                        """,
                        (ip, port, protocol),
                    ).fetchone()
                eid = str(existing["endpoint_id"]) if existing else self.endpoint_id(key, protocol, transport, port)
                if existing is None:
                    existing = db.execute(
                        "SELECT endpoint_id, status, metadata_json FROM endpoints WHERE endpoint_id=?",
                        (eid,),
                    ).fetchone()
                endpoint_meta: dict[str, Any] = {}
                if existing:
                    try:
                        endpoint_meta = json.loads(existing["metadata_json"] or "{}")
                    except Exception:
                        endpoint_meta = {}
                    if not isinstance(endpoint_meta, dict):
                        endpoint_meta = {}
                endpoint_meta["hostname"] = hostname
                endpoint_meta["ip"] = ip
                endpoint_meta["source"] = source
                endpoint_meta["shared_status"] = shared_status
                if peer_id:
                    endpoint_meta["shared_peer_id"] = peer_id
                if speed > 0:
                    endpoint_meta["shared_speed_bps"] = speed
                endpoint_meta.pop("trusted_observation", None)
                if existing:
                    db.execute(
                        "UPDATE endpoints SET last_seen=?, metadata_json=? WHERE endpoint_id=?",
                        (now, json.dumps(endpoint_meta, ensure_ascii=False), eid),
                    )
                else:
                    insert_status = "AVAILABLE" if shared_status in ("AVAILABLE", "HOT") else "NEW"
                    db.execute(
                        """
                        INSERT INTO endpoints(endpoint_id, server_key, protocol, transport, port, status, first_seen, last_seen, metadata_json)
                        VALUES(?,?,?,?,?,?,?,?,?)
                        """,
                        (eid, key, protocol, transport, port, insert_status, now, now, json.dumps(endpoint_meta, ensure_ascii=False)),
                    )
                if speed > 0:
                    seen = db.execute("SELECT 1 FROM observations WHERE server_key=? LIMIT 1", (key,)).fetchone()
                    if not seen:
                        db.execute(
                            "INSERT INTO observations(server_key, source, seen_at, ip, ping, speed, sessions, score) VALUES(?,?,?,?,?,?,?,?)",
                            (key, source, now, ip, 0, speed, 0, 0),
                        )
                imported += 1
            db.commit()
        self._invalidate_read_caches()
        return imported

    def list_endpoints(self, protocol: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        # The UI is paginated; keep the backend ceiling high enough that the
        # persistent Master Pool is not accidentally truncated at 1000 endpoints.
        limit = max(1, min(int(limit), 5000))
        with closing(self._connect()) as db:
            params: list[Any] = []
            where = ""
            if protocol:
                where = "WHERE e.protocol=?"
                params.append(str(protocol).lower())
            params.append(limit)
            rows = db.execute(
                f"""
                SELECT e.*, s.hostname, s.current_ip, s.country, s.state AS server_state,
                       s.metadata_json AS server_metadata_json,
                       COALESCE((SELECT o.ping FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_ping,
                       COALESCE((SELECT o.speed FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_speed,
                       COALESCE((SELECT o.sessions FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_sessions,
                       COALESCE((SELECT o.score FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_server_score
                FROM endpoints e
                JOIN servers s ON s.server_key=e.server_key
                {where}
                ORDER BY
                  CASE e.status
                    WHEN 'HOT' THEN 0
                    WHEN 'AVAILABLE' THEN 1
                    WHEN 'NEW' THEN 2
                    WHEN 'DEGRADED' THEN 3
                    WHEN 'COOLDOWN' THEN 4
                    WHEN 'STALE' THEN 5
                    ELSE 6
                  END,
                  e.next_test ASC,
                  e.latency_ewma ASC,
                  e.last_seen DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
            result: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                try:
                    item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
                except Exception:
                    item["metadata"] = {}
                    item.pop("metadata_json", None)
                try:
                    item["server_metadata"] = json.loads(item.pop("server_metadata_json") or "{}")
                except Exception:
                    item["server_metadata"] = {}
                    item.pop("server_metadata_json", None)
                item["country"] = canonical_country_name(item.get("country") or "")
                result.append(item)
            return result

    def list_share_endpoints(self, offset: int = 0, limit: int = 2000) -> list[dict[str, Any]]:
        """One stable page of the catalog for peer sync. Not the UI hot-path query."""
        limit = max(1, min(int(limit), 2000))
        offset = max(0, int(offset))
        with closing(self._connect()) as db:
            rows = db.execute(
                """
                SELECT e.server_key, e.protocol, e.transport, e.port, e.status,
                       e.success_count, e.failure_count, e.success_streak,
                       e.first_seen, e.last_seen, e.last_success, e.metadata_json,
                       s.hostname, s.current_ip, s.country,
                       s.metadata_json AS server_metadata_json,
                       COALESCE((SELECT o.speed FROM observations o
                                 WHERE o.server_key=e.server_key
                                 ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_speed
                FROM endpoints e
                JOIN servers s ON s.server_key=e.server_key
                ORDER BY e.endpoint_id
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
            except Exception:
                item["metadata"] = {}
                item.pop("metadata_json", None)
            try:
                item["server_metadata"] = json.loads(item.pop("server_metadata_json") or "{}")
            except Exception:
                item["server_metadata"] = {}
                item.pop("server_metadata_json", None)
            item["country"] = canonical_country_name(item.get("country") or "")
            result.append(item)
        return result

    def list_routing_endpoints(self, limit: int = 400, country: str = "", protocol: str = "") -> list[dict[str, Any]]:
        """HOT/AVAILABLE rows for failover. One indexed read, not the full catalog."""
        limit = max(1, min(int(limit), 800))
        country = str(country or "").strip()
        protocol = str(protocol or "").strip().lower()
        where = "UPPER(e.status) IN ('HOT', 'AVAILABLE')"
        params: list[Any] = []
        if country:
            where += " AND s.country=?"
            params.append(country)
        if protocol:
            where += " AND LOWER(e.protocol)=?"
            params.append(protocol)
        params.append(limit)
        with closing(self._connect()) as db:
            rows = db.execute(
                f"""
                SELECT e.endpoint_id, e.server_key, e.protocol, e.transport, e.port, e.status,
                       e.latency_ewma, e.jitter_ewma, e.success_streak, e.fail_streak, e.last_success,
                       e.last_session_seconds, e.stability, e.metadata_json,
                       s.hostname, s.current_ip, s.country, s.metadata_json AS server_metadata_json,
                       COALESCE((SELECT o.speed FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_speed,
                       COALESCE((SELECT o.sessions FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_sessions
                FROM endpoints e
                JOIN servers s ON s.server_key=e.server_key
                WHERE {where}
                ORDER BY CASE UPPER(e.status) WHEN 'HOT' THEN 0 ELSE 1 END, e.latency_ewma ASC
                LIMIT ?
                """,
                params,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
            except Exception:
                item["metadata"] = {}
                item.pop("metadata_json", None)
            try:
                item["server_metadata"] = json.loads(item.pop("server_metadata_json") or "{}")
            except Exception:
                item["server_metadata"] = {}
                item.pop("server_metadata_json", None)
            item["country"] = canonical_country_name(item.get("country") or "")
            result.append(item)
        return result

    def _ui_order_index(self, country: str = "", protocol: str = "", ip_type: str = "", speed_min_bps: int = 0, latency: str = "") -> list[dict[str, Any]]:
        """One narrow read of the library. Pages and badge counts share it.

        The old query ran a window sort over every metadata blob. That was
        about a second for ten thousand rows, and the page plus the badges
        each did it again.
        """
        country = canonical_country_name(country) if country else ""
        protocol = str(protocol or "").strip().lower()
        ip_type = str(ip_type or "").strip().lower()
        speed_min_bps = int(speed_min_bps or 0)
        latency = normalize_latency_filter(latency)
        key = (country, protocol, ip_type, speed_min_bps, latency)
        now = time.monotonic()
        cached = self._ui_order_cache.get(key)
        if cached and cached[0] > now:
            return cached[1]
        # Same filter already has a snapshot and another request is scanning.
        # Return that snapshot. Waiting here is what stacked the page past
        # the browser timeout while the manager was swapped.
        if not self._ui_order_lock.acquire(blocking=False):
            if cached:
                return cached[1]
            # Another filter is already scanning. Do not pin this request
            # until that scan finishes: on a swapped host that was 15–80s
            # and every timed-out retry stacked behind it.
            if not self._ui_order_lock.acquire(timeout=2.0):
                if cached:
                    return cached[1]
                raise sqlite3.OperationalError("ui order busy")
        try:
            cached = self._ui_order_cache.get(key)
            if cached and cached[0] > time.monotonic():
                return cached[1]
            where, params = _ui_list_filters(
                country=country,
                protocol=protocol,
                ip_type=ip_type,
                speed_min_bps=speed_min_bps,
                latency=latency,
            )
            sql = (
                "SELECT e.endpoint_id AS endpoint_id, UPPER(e.status) AS status, "
                "LOWER(e.protocol) AS protocol, COALESCE(e.port,0) AS port, "
                "COALESCE(e.ui_latency_ms,0) AS lat, s.current_ip AS current_ip "
                "FROM endpoints e JOIN servers s ON s.server_key=e.server_key WHERE "
                + " AND ".join(where)
            )
            with closing(self._connect(4000, readonly=True)) as db:
                fetched = db.execute(sql, params).fetchall()
            best: dict[str, dict[str, Any]] = {}
            for row in fetched:
                eid = str(row["endpoint_id"] or "")
                if not eid:
                    continue
                port = int(row["port"] or 0)
                ip = str(row["current_ip"] or "")
                proto = str(row["protocol"] or "")
                identity = f"{proto}|{ip}|{port}" if port > 0 else f"id:{eid}"
                rank = _UI_STATUS_RANK.get(str(row["status"] or ""), 9)
                lat = int(row["lat"] or 0)
                lat_sort = lat if 1 <= lat <= 1500 else 999999
                item = {
                    "endpoint_id": eid,
                    "status": str(row["status"] or ""),
                    "protocol": proto,
                    "port": port,
                    "ip": ip,
                    "rank": rank,
                    "lat": lat,
                    "lat_sort": lat_sort,
                }
                prev = best.get(identity)
                if prev is None or (rank, lat_sort, eid) < (prev["rank"], prev["lat_sort"], prev["endpoint_id"]):
                    best[identity] = item
            ordered = sorted(best.values(), key=lambda item: (item["rank"], item["lat_sort"], item["endpoint_id"]))
            self._ui_order_cache[key] = (time.monotonic() + 60.0, ordered)
            if len(self._ui_order_cache) > 4:
                for stale in list(self._ui_order_cache):
                    if stale == key:
                        continue
                    if len(self._ui_order_cache) <= 4:
                        break
                    self._ui_order_cache.pop(stale, None)
            return ordered
        finally:
            self._ui_order_lock.release()

    def list_probe_targets(self) -> list[dict[str, Any]]:
        """Slim rows for a catalog probe. No observation lookups and no config blobs."""
        sql = (
            "SELECT e.endpoint_id AS endpoint_id, LOWER(e.protocol) AS protocol, "
            "LOWER(e.transport) AS transport, e.port AS port, e.status AS status, "
            "e.config_ref AS config_ref, s.current_ip AS current_ip, s.hostname AS hostname, "
            "s.country AS country, "
            "CASE WHEN instr(lower(COALESCE(e.metadata_json,'')), 'tls-auth')>0 "
            "OR instr(lower(COALESCE(e.metadata_json,'')), 'tls-crypt')>0 THEN 1 ELSE 0 END AS tls_auth "
            "FROM endpoints e JOIN servers s ON s.server_key=e.server_key "
            "WHERE UPPER(COALESCE(e.status,''))!='RETIRED'"
        )
        with closing(self._connect(4000, readonly=True)) as db:
            fetched = db.execute(sql).fetchall()
        rows: list[dict[str, Any]] = []
        for row in fetched:
            tls = bool(row["tls_auth"])
            rows.append({
                "endpoint_id": str(row["endpoint_id"] or ""),
                "protocol": str(row["protocol"] or ""),
                "transport": str(row["transport"] or ""),
                "port": int(row["port"] or 0),
                "status": str(row["status"] or ""),
                "config_ref": str(row["config_ref"] or ""),
                "current_ip": str(row["current_ip"] or ""),
                "hostname": str(row["hostname"] or ""),
                "country": str(row["country"] or ""),
                "metadata": {"tls_auth": True} if tls else {},
            })
        return rows

    def list_endpoints_scoped(self, country="", status="", protocol="", ip_type="", offset=0, limit=100,
                             speed_min_bps=0, active_endpoint_id="", active_ip="", active_protocol="", active_port=0,
                             latency="", standby_endpoint_id="", standby_ip="", standby_protocol="", standby_port=0):
        """Authoritative, bounded Master Pool query for the UI."""
        country = canonical_country_name(country) if country else ""
        status = str(status or "").strip().lower()
        protocol = str(protocol or "").strip().lower()
        ip_type = str(ip_type or "").strip().lower()
        speed_min_bps = int(speed_min_bps or 0)
        active_endpoint_id = str(active_endpoint_id or "").strip()
        active_ip = str(active_ip or "").strip()
        active_protocol = str(active_protocol or "").strip().lower()
        active_port = max(0, int(active_port or 0))
        standby_endpoint_id = str(standby_endpoint_id or "").strip()
        standby_ip = str(standby_ip or "").strip()
        standby_protocol = str(standby_protocol or "").strip().lower()
        standby_port = max(0, int(standby_port or 0))
        latency = normalize_latency_filter(latency)
        offset = max(0, int(offset or 0))
        # Internal callers (e.g. the country full-sweep engine) may request
        # the complete country inventory; the HTTP layer still caps browser
        # pages at 200 rows.
        limit = max(1, min(int(limit or 100), 5000))
        cache_key = (country, status, protocol, ip_type, offset, limit,
                     speed_min_bps, latency, active_endpoint_id, active_ip, active_protocol, active_port,
                     standby_endpoint_id, standby_ip, standby_protocol, standby_port)
        cached = self._scoped_page_cache.get(cache_key)
        if cached and cached[0] > time.monotonic():
            cached_rows, cached_total = cached[1]
            return [dict(x) for x in cached_rows], int(cached_total)

        with self._scoped_query_gate_guard:
            gate = self._scoped_query_gates.setdefault(cache_key, threading.Lock())
        if not gate.acquire(blocking=False):
            stale = self._scoped_page_stale.get(cache_key)
            if stale:
                cached_rows, cached_total = stale
                return [dict(x) for x in cached_rows], int(cached_total)
            if not gate.acquire(timeout=2.0):
                stale = self._scoped_page_stale.get(cache_key)
                if stale:
                    cached_rows, cached_total = stale
                    return [dict(x) for x in cached_rows], int(cached_total)
                raise sqlite3.OperationalError("ui page busy")
        try:
            cached = self._scoped_page_cache.get(cache_key)
            if cached and cached[0] > time.monotonic():
                cached_rows, cached_total = cached[1]
                return [dict(x) for x in cached_rows], int(cached_total)

            stale = self._scoped_page_stale.get(cache_key)
            try:
                ordered = list(self._ui_order_index(country, protocol, ip_type, speed_min_bps, latency))
                if status and status not in ("", "all"):
                    allowed = set(_UI_STATUS_GROUPS.get(status) or ())
                    ordered = [item for item in ordered if item["status"] in allowed]

                def _pin(item: dict[str, Any]) -> tuple:
                    eid = item["endpoint_id"]
                    ip = item["ip"]
                    proto = item["protocol"]
                    port = int(item["port"] or 0)
                    if active_endpoint_id and eid == active_endpoint_id:
                        bucket = 0
                    elif active_ip and ip == active_ip and proto == active_protocol and port == active_port:
                        bucket = 0
                    elif standby_endpoint_id and eid == standby_endpoint_id:
                        bucket = 1
                    elif standby_ip and ip == standby_ip and proto == standby_protocol and port == standby_port:
                        bucket = 1
                    else:
                        bucket = 2
                    return (bucket, item["rank"], item["lat_sort"], eid)

                ordered.sort(key=_pin)
                total = len(ordered)
                ids = [item["endpoint_id"] for item in ordered[offset:offset + limit]]
                page_rows = []
                if ids:
                    with closing(self._connect(4000, readonly=True)) as db:
                        found = db.execute(
                            "SELECT e.*, s.hostname, s.current_ip, s.country, s.state AS server_state, "
                            "s.metadata_json AS server_metadata_json "
                            "FROM endpoints e JOIN servers s ON s.server_key=e.server_key "
                            "WHERE e.endpoint_id IN (" + ",".join("?" for _ in ids) + ")",
                            ids,
                        ).fetchall()
                        by_id = {str(row["endpoint_id"]): dict(row) for row in found}
                        page_rows = [by_id[item_id] for item_id in ids if item_id in by_id]
                        _attach_latest_observations(db, page_rows)
            except sqlite3.OperationalError as exc:
                if stale and "lock" in str(exc).lower():
                    cached_rows, cached_total = stale
                    return [dict(x) for x in cached_rows], int(cached_total)
                raise

            result=[]
            for item in page_rows:
                item.pop("_ui_rn", None)
                try: item['metadata']=json.loads(item.pop('metadata_json') or '{}')
                except Exception: item['metadata']={}; item.pop('metadata_json',None)
                try: item['server_metadata']=json.loads(item.pop('server_metadata_json') or '{}')
                except Exception: item['server_metadata']={}; item.pop('server_metadata_json',None)
                item['country']=canonical_country_name(item.get('country') or '')
                item['data_integrity']={
                    'country': bool(item.get('country')),
                    'ip': bool(item.get('current_ip')),
                    'protocol': bool(item.get('protocol')),
                    'port': int(item.get('port') or 0) > 0 or item.get('protocol')=='l2tp-ipsec',
                    'speed': int(item.get('latest_speed') or 0) > 0,
                    'latency': float(item.get('latency_ewma') or item.get('latest_ping') or 0) > 0,
                }
                result.append(item)
            self._scoped_page_cache[cache_key] = (time.monotonic() + 60.0, (result, total))
            self._scoped_page_stale[cache_key] = (result, total)
            return [dict(x) for x in result], total
        finally:
            gate.release()

    def list_endpoint_ids(self, country: str = "", status: str = "", protocol: str = "", ip_type: str = "") -> list[dict[str, Any]]:
        """Ids only. Country sweeps must not run the UI page query."""
        country = canonical_country_name(country) if country else ""
        where, params = _ui_list_filters(
            country=country,
            status=status,
            protocol=protocol,
            ip_type=ip_type,
        )
        sql = (
            "SELECT endpoint_id, protocol, server_key, status, country FROM ("
            "SELECT e.endpoint_id AS endpoint_id, e.protocol AS protocol, "
            "e.server_key AS server_key, e.status AS status, s.country AS country, "
            "ROW_NUMBER() OVER (PARTITION BY " + _UI_ROW_KEY_SQL + " ORDER BY e.endpoint_id) AS _rn "
            "FROM endpoints e JOIN servers s ON s.server_key=e.server_key WHERE "
            + " AND ".join(where)
            + ") WHERE _rn=1"
        )
        with closing(self._connect(800, readonly=True)) as db:
            rows = db.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def country_catalog(self, status="", protocol="", ip_type="", connected_endpoint_id="", speed_min_bps=0, latency=""):
        """Authoritative country/IP inventory using the same Master Pool scope as the node table."""
        status = str(status or "").strip().lower()
        protocol = str(protocol or "").strip().lower()
        ip_type = str(ip_type or "").strip().lower()
        connected_endpoint_id = str(connected_endpoint_id or "").strip()
        speed_min_bps = int(speed_min_bps or 0)
        latency = normalize_latency_filter(latency)
        key = (status, protocol, ip_type, connected_endpoint_id, speed_min_bps, latency)
        now = time.monotonic()
        cached = self._country_catalog_cache.get(key)
        if cached and cached[0] > now:
            return dict(cached[1])

        # "connected" is not a stored endpoint status. Keep that menu on the
        # live endpoint itself; every other status uses the table predicate.
        where, params = _ui_list_filters(
            status="" if status == "connected" else status,
            protocol=protocol,
            ip_type=ip_type,
            speed_min_bps=speed_min_bps,
            latency=latency,
        )
        if status == "connected":
            if connected_endpoint_id:
                where.append("e.endpoint_id=?")
                params.append(connected_endpoint_id)
            else:
                where.append("1=0")

        scope = " FROM endpoints e JOIN servers s ON s.server_key=e.server_key WHERE " + " AND ".join(where)
        if not self._country_catalog_gate.acquire(blocking=False):
            if cached:
                return dict(cached[1])
            if not self._country_catalog_gate.acquire(timeout=2.0):
                if cached:
                    return dict(cached[1])
                raise sqlite3.OperationalError("country catalog busy")
        try:
            cached = self._country_catalog_cache.get(key)
            if cached and cached[0] > time.monotonic():
                return dict(cached[1])
            with closing(self._connect(4000, readonly=True)) as db:
                plain = (
                    not status
                    and not protocol
                    and not ip_type
                    and speed_min_bps == 0
                    and not latency
                )
                if plain:
                    rows = db.execute(
                        "SELECT country, current_ip, server_key FROM servers "
                        "WHERE TRIM(COALESCE(current_ip,''))<>'' "
                        "AND EXISTS (SELECT 1 FROM endpoints e WHERE e.server_key=servers.server_key "
                        "AND TRIM(COALESCE(e.protocol,''))<>'')"
                    ).fetchall()
                else:
                    rows = db.execute(
                        "SELECT s.country AS country, s.current_ip AS current_ip, s.server_key AS server_key"
                        + scope + " GROUP BY s.country, s.current_ip, s.server_key",
                        params,
                    ).fetchall()

            countries: dict[str, dict[str, int]] = {}
            country_servers: dict[str, set[str]] = {}
            country_ips: dict[str, set[str]] = {}
            all_ips: set[str] = set()
            for row in rows:
                ip = str(row["current_ip"] or "").strip()
                if not ip:
                    continue
                country = canonical_country_name(row["country"])
                if not country:
                    continue
                all_ips.add(ip)
                country_ips.setdefault(country, set()).add(ip)
                country_servers.setdefault(country, set()).add(str(row["server_key"] or ""))
            for country, ips in country_ips.items():
                countries[country] = {
                    "ip_count": len(ips),
                    "server_count": len(country_servers.get(country) or ()),
                }
            country_ip_count = sum(item["ip_count"] for item in countries.values())
            total_ip = len(all_ips)

            result = {
                "total_ip_count": total_ip,
                "country_ip_count": country_ip_count,
                "countries": countries,
                "status": status,
                "protocol": protocol,
                "ip_type": ip_type,
            }
            catalog_ttl = 5.0 if status == "connected" else 60.0
            self._country_catalog_cache[key] = (time.monotonic() + catalog_ttl, result)
            return dict(result)
        finally:
            self._country_catalog_gate.release()

    def get_endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        endpoint_id = str(endpoint_id or "").strip()
        if not endpoint_id:
            return None
        with closing(self._connect(4000, readonly=True)) as db:
            row = db.execute(
                """
                SELECT e.*, s.hostname, s.current_ip, s.country, s.state AS server_state,
                       s.metadata_json AS server_metadata_json,
                       COALESCE((SELECT o.ping FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_ping,
                       COALESCE((SELECT o.speed FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_speed,
                       COALESCE((SELECT o.sessions FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_sessions,
                       COALESCE((SELECT o.score FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_server_score
                FROM endpoints e JOIN servers s ON s.server_key=e.server_key
                WHERE e.endpoint_id=?
                """, (endpoint_id,)
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        try: item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        except Exception: item["metadata"] = {}
        try: item["server_metadata"] = json.loads(item.pop("server_metadata_json") or "{}")
        except Exception: item["server_metadata"] = {}
        item["country"] = canonical_country_name(item.get("country") or "")
        item["data_integrity"] = {
            "country": bool(item.get("country")),
            "ip": bool(item.get("current_ip")),
            "protocol": bool(item.get("protocol")),
            "port": int(item.get("port") or 0) > 0 or item.get("protocol") == "l2tp-ipsec",
            "speed": int(item.get("latest_speed") or 0) > 0,
            "latency": float(item.get("latency_ewma") or item.get("latest_ping") or 0) > 0,
        }
        return item

    def replace_hostname_ip(self, hostname: str, new_ip: str) -> int:
        """Point a hostname at its current DNS address. History stays on the same server."""
        hostname = str(hostname or "").strip().lower()
        new_ip = str(new_ip or "").strip()
        if not hostname:
            return 0
        with closing(self._connect()) as db:
            cur = db.execute(
                "UPDATE servers SET current_ip=? WHERE LOWER(hostname)=? AND COALESCE(current_ip,'')<>?",
                (new_ip, hostname, new_ip),
            )
            db.commit()
            return int(cur.rowcount or 0)

    def find_endpoint_id(self, ip: str, port: int, protocol: str) -> str:
        ip = str(ip or "").strip()
        protocol = str(protocol or "").strip().lower()
        try:
            port = int(port or 0)
        except (TypeError, ValueError):
            port = 0
        if not ip or port <= 0 or not protocol:
            return ""
        with closing(self._connect()) as db:
            row = db.execute(
                """
                SELECT e.endpoint_id
                FROM endpoints e JOIN servers s ON s.server_key=e.server_key
                WHERE s.current_ip=? AND e.port=? AND LOWER(e.protocol)=?
                ORDER BY CASE UPPER(e.status) WHEN 'HOT' THEN 0 WHEN 'AVAILABLE' THEN 1 ELSE 2 END
                LIMIT 1
                """,
                (ip, port, protocol),
            ).fetchone()
        return str(row[0]) if row else ""

    def find_endpoint_id_by_host(self, host: str, port: int, protocol: str) -> str:
        raw = str(host or "").strip()
        if raw.lower().startswith("manual_"):
            raw = raw.split("_", 1)[1]
        host = self.canonical_host(raw)
        protocol = str(protocol or "").strip().lower()
        try:
            port = int(port or 0)
        except (TypeError, ValueError):
            port = 0
        if not host or port <= 0 or not protocol:
            return ""
        with closing(self._connect()) as db:
            row = db.execute(
                """
                SELECT e.endpoint_id
                FROM endpoints e JOIN servers s ON s.server_key=e.server_key
                WHERE e.port=? AND LOWER(e.protocol)=?
                  AND (LOWER(s.hostname)=? OR LOWER(s.server_key)=? OR s.current_ip=?)
                ORDER BY CASE UPPER(e.status) WHEN 'HOT' THEN 0 WHEN 'AVAILABLE' THEN 1 ELSE 2 END
                LIMIT 1
                """,
                (port, protocol, host, host, raw),
            ).fetchone()
        return str(row[0]) if row else ""

    def find_library_matches(self, host: str, ip: str = "") -> list[dict[str, Any]]:
        """Return existing endpoints for this hostname or IP. Empty means it is not in the library."""
        host = self.canonical_host(host)
        ip = str(ip or "").strip()
        clauses: list[str] = []
        params: list[Any] = []
        if host:
            clauses.append("(LOWER(s.hostname)=? OR LOWER(s.server_key)=?)")
            params.extend([host, host])
        if ip:
            clauses.append("s.current_ip=?")
            params.append(ip)
        if not clauses:
            return []
        with closing(self._connect()) as db:
            rows = db.execute(
                f"""
                SELECT e.protocol, e.port, e.status, s.hostname, s.current_ip, s.country
                FROM endpoints e JOIN servers s ON s.server_key=e.server_key
                WHERE {' OR '.join(clauses)}
                ORDER BY e.last_seen DESC
                LIMIT 12
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def manual_endpoints_missing_speed(self, limit: int = 6) -> list[str]:
        limit = max(1, min(int(limit or 6), 12))
        with closing(self._connect()) as db:
            rows = db.execute(
                """
                SELECT e.endpoint_id
                FROM endpoints e
                JOIN servers s ON s.server_key=e.server_key
                WHERE CAST(COALESCE(json_extract(s.metadata_json, '$.manual_added_at'), '0') AS REAL) > 0
                  AND UPPER(e.status) IN ('HOT', 'AVAILABLE')
                  AND COALESCE((SELECT o.speed FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) <= 0
                  AND CAST(COALESCE(json_extract(e.metadata_json, '$.last_probe_speed_bps'), '0') AS REAL) <= 0
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [str(row[0]) for row in rows]

    @staticmethod
    def _selection_score(endpoint: dict[str, Any]) -> tuple[float, float, int]:
        status = str(endpoint.get("status") or "").upper()
        status_score = {"HOT":100.0, "AVAILABLE":80.0, "DEGRADED":30.0, "NEW":10.0, "TESTING":20.0}.get(status, 0.0)
        speed = int(endpoint.get("latest_speed") or endpoint.get("speed") or 0)
        latency = float(endpoint.get("latency_ewma") or endpoint.get("latest_ping") or 999999)
        if latency <= 0: latency = 999999
        return (status_score + min(speed / 10_000_000, 50.0), -latency, int(endpoint.get("success_streak") or 0))

    def ranked_hot_pool(self, limit: int = 10, per_server_limit: int = 2) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit or 10), 50))
        per_server_limit = max(1, min(int(per_server_limit or 2), 10))
        with closing(self._connect()) as db:
            rows = db.execute(
                """
                SELECT e.*, s.hostname, s.current_ip, s.country, s.state AS server_state,
                       s.metadata_json AS server_metadata_json,
                       COALESCE((SELECT o.ping FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_ping,
                       COALESCE((SELECT o.speed FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_speed,
                       COALESCE((SELECT o.sessions FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_sessions,
                       COALESCE((SELECT o.score FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_server_score
                FROM endpoints e JOIN servers s ON s.server_key=e.server_key
                WHERE UPPER(e.status) IN ('HOT','AVAILABLE') AND TRIM(COALESCE(s.current_ip,'')) <> ''
                ORDER BY CASE UPPER(e.status) WHEN 'HOT' THEN 0 ELSE 1 END,
                         CASE WHEN e.latency_ewma>0 THEN e.latency_ewma ELSE 999999 END,
                         e.success_streak DESC, e.last_success DESC
                LIMIT 300
                """
            ).fetchall()
        counts = {}
        out = []
        for row in rows:
            sk = str(row["server_key"])
            if counts.get(sk, 0) >= per_server_limit: continue
            item = dict(row)
            try: item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
            except Exception: item["metadata"] = {}
            if item["metadata"].get("local_forward_ok") is False:
                continue
            try: item["server_metadata"] = json.loads(item.pop("server_metadata_json") or "{}")
            except Exception: item["server_metadata"] = {}
            item["country"] = canonical_country_name(item.get("country") or "")
            counts[sk] = counts.get(sk, 0) + 1
            out.append(item)
            if len(out) >= limit: break
        return out

    def due_counts(self, protocols: tuple[str, ...] | list[str]) -> dict[str, int]:
        protocols = [str(x or "").strip().lower() for x in protocols if str(x or "").strip()]
        if not protocols:
            return {}
        placeholders = ",".join("?" for _ in protocols)
        with closing(self._connect()) as db:
            rows = db.execute(
                """
                SELECT LOWER(e.protocol) AS protocol, COUNT(*) AS n
                FROM endpoints e
                WHERE LOWER(e.protocol) IN (""" + placeholders + """)
                  AND UPPER(e.status) NOT IN ('RETIRED')
                  AND e.next_test <= ?
                GROUP BY LOWER(e.protocol)
                """,
                protocols + [time.time()],
            ).fetchall()
        return {str(row["protocol"]): int(row["n"]) for row in rows}

    def due_endpoints(self, protocols: tuple[str, ...] | list[str], limit: int = 10, country: str = "") -> list[dict[str, Any]]:
        protocols = [str(x or "").strip().lower() for x in protocols if str(x or "").strip()]
        if not protocols: return []
        limit = max(1, min(int(limit or 10), 100))
        country = canonical_country_name(country) if country else ""
        placeholders = ",".join("?" for _ in protocols)
        where_country = " AND s.country=?" if country else ""
        with closing(self._connect()) as db:
            rows = db.execute(
                """
                SELECT e.*, s.hostname, s.current_ip, s.country, s.state AS server_state,
                       s.metadata_json AS server_metadata_json,
                       COALESCE((SELECT o.ping FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_ping,
                       COALESCE((SELECT o.speed FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS latest_speed,
                       COALESCE((SELECT o.sessions FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_sessions,
                       COALESCE((SELECT o.score FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_server_score
                FROM endpoints e JOIN servers s ON s.server_key=e.server_key
                WHERE LOWER(e.protocol) IN (""" + placeholders + """)
                  AND UPPER(e.status) NOT IN ('RETIRED')
                  AND e.next_test <= ?""" + where_country + """
                ORDER BY CASE UPPER(e.status) WHEN 'NEW' THEN 0 WHEN 'AVAILABLE' THEN 1 WHEN 'HOT' THEN 2 ELSE 3 END,
                         e.next_test ASC, e.last_seen DESC
                LIMIT ?
                """,
                protocols + [time.time()] + ([country] if country else []) + [limit]
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            try: item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
            except Exception: item["metadata"] = {}
            try: item["server_metadata"] = json.loads(item.pop("server_metadata_json") or "{}")
            except Exception: item["server_metadata"] = {}
            item["country"] = canonical_country_name(item.get("country") or "")
            out.append(item)
        return out

    def queue_speed_recheck(self, endpoint_ids: list[str]) -> int:
        ids = [str(item) for item in endpoint_ids if str(item or "").strip()][:8]
        if not ids:
            return 0
        with self.lock, closing(self._connect()) as db:
            db.executemany(
                "UPDATE endpoints SET next_test=0 WHERE endpoint_id=? AND UPPER(status) IN ('HOT','AVAILABLE')",
                [(item,) for item in ids],
            )
            db.commit()
        return len(ids)

    def reset_probe_schedule(self, include_retired: bool = False) -> int:
        where = "" if include_retired else " WHERE UPPER(status) <> 'RETIRED'"
        with self.lock, closing(self._connect()) as db:
            cur = db.execute("UPDATE endpoints SET next_test=0, status=CASE WHEN UPPER(status)='STALE' THEN 'NEW' ELSE status END" + where)
            db.commit()
        self._invalidate_read_caches()
        return int(cur.rowcount or 0)

    def mark_endpoint_testing(self, endpoint_id: str, message: str = "正在检测") -> bool:
        endpoint_id = str(endpoint_id or "").strip()
        if not endpoint_id:
            return False
        meta = {}
        now = time.time()
        with self.lock, closing(self._connect()) as db:
            row = db.execute("SELECT metadata_json FROM endpoints WHERE endpoint_id=?", (endpoint_id,)).fetchone()
            if not row:
                return False
            try:
                meta = json.loads(row["metadata_json"] or "{}")
            except Exception:
                meta = {}
            if not isinstance(meta, dict):
                meta = {}
            meta["last_probe_message"] = str(message or "正在检测")[:1000]
            db.execute(
                "UPDATE endpoints SET status='TESTING', metadata_json=? WHERE endpoint_id=?",
                (json.dumps(meta, ensure_ascii=False), endpoint_id),
            )
            db.commit()
        self._invalidate_read_caches()
        return True

    def mark_endpoint_degraded(self, endpoint_id: str, message: str) -> bool:
        """Production path failed. Do not keep showing this node as available."""
        endpoint_id = str(endpoint_id or "").strip()
        if not endpoint_id:
            return False
        now = time.time()
        note = str(message or "生产代理出口不可用")[:1000]
        with self.lock, closing(self._connect()) as db:
            row = db.execute("SELECT metadata_json FROM endpoints WHERE endpoint_id=?", (endpoint_id,)).fetchone()
            if not row:
                return False
            try:
                meta = json.loads(row["metadata_json"] or "{}")
            except Exception:
                meta = {}
            if not isinstance(meta, dict):
                meta = {}
            meta["last_error"] = note
            meta["last_probe_message"] = note
            db.execute(
                """UPDATE endpoints SET status='DEGRADED', last_failure=?, failure_count=failure_count+1,
                   fail_streak=fail_streak+1, success_streak=0, next_test=?, metadata_json=?
                   WHERE endpoint_id=?""",
                (now, now + 600, json.dumps(meta, ensure_ascii=False), endpoint_id),
            )
            db.commit()
        self._invalidate_read_caches()
        return True

    def note_local_forward(self, endpoint_id: str, ok: bool, message: str = "") -> bool:
        """Record whether this server can forward into the tunnel. Does not change node availability."""
        endpoint_id = str(endpoint_id or "").strip()
        if not endpoint_id:
            return False
        note = str(message or "")[:1000]
        with self.lock, closing(self._connect()) as db:
            row = db.execute("SELECT metadata_json FROM endpoints WHERE endpoint_id=?", (endpoint_id,)).fetchone()
            if not row:
                return False
            try:
                meta = json.loads(row["metadata_json"] or "{}")
            except Exception:
                meta = {}
            if not isinstance(meta, dict):
                meta = {}
            meta["local_forward_ok"] = bool(ok)
            if ok:
                meta.pop("local_forward_error", None)
            else:
                meta["local_forward_error"] = note or "本机代理转发失败"
            db.execute(
                "UPDATE endpoints SET metadata_json=? WHERE endpoint_id=?",
                (json.dumps(meta, ensure_ascii=False), endpoint_id),
            )
            db.commit()
        self._invalidate_read_caches()
        return True

    def note_tcp_rtt(self, endpoint_id: str, latency_ms: int) -> None:
        """Store a TCP port round trip. It is a valid latency, not a tunnel dial."""
        endpoint_id = str(endpoint_id or "").strip()
        latency_ms = int(latency_ms or 0)
        if not endpoint_id or latency_ms <= 0 or latency_ms > 1500:
            return
        with self.lock, closing(self._connect()) as db:
            row = db.execute("SELECT metadata_json FROM endpoints WHERE endpoint_id=?", (endpoint_id,)).fetchone()
            if not row:
                return
            try:
                meta = json.loads(row["metadata_json"] or "{}")
            except Exception:
                meta = {}
            if not isinstance(meta, dict):
                meta = {}
            if int(meta.get("tcp_rtt_ms") or 0) == latency_ms:
                return
            meta["tcp_rtt_ms"] = latency_ms
            meta["tcp_rtt_at"] = time.time()
            db.execute(
                "UPDATE endpoints SET metadata_json=?, ui_latency_ms=? WHERE endpoint_id=?",
                (json.dumps(meta, ensure_ascii=False), latency_ms, endpoint_id),
            )
            db.commit()
        self._invalidate_read_caches()

    @staticmethod
    def _probe_failure_should_count(message: str) -> bool:
        """Foreground abort, speed tests and URL checks are not connectivity failures."""
        text = str(message or "")
        lowered = text.lower()
        for marker in (
            "让路", "跳过", "测速", "速度测试", "未测速",
            "ipify", "cloudflare", "cdn-cgi", "speed test",
            "出口检测", "网页出口", "不算不可用",
        ):
            if marker in text or marker in lowered:
                return False
        return True

    def country_probe_ids(self, per_country: int = 24) -> dict[str, list[str]]:
        """Up to N endpoint ids per country. Available rows come first. No config bodies."""
        per_country = max(1, min(40, int(per_country or 24)))
        grouped: dict[str, list[str]] = {}
        with closing(self._connect(readonly=True)) as db:
            rows = db.execute(
                """
                SELECT s.country AS country, e.endpoint_id AS endpoint_id
                FROM endpoints e
                JOIN servers s ON e.server_key = s.server_key
                WHERE COALESCE(s.country, '') != ''
                  AND COALESCE(e.status, '') != 'RETIRED'
                ORDER BY s.country,
                         CASE WHEN e.status = 'AVAILABLE' THEN 0 ELSE 1 END,
                         COALESCE(e.ui_latency_ms, 0)
                """
            ).fetchall()
        for row in rows:
            country = canonical_country_name(str(row["country"] or ""))
            endpoint_id = str(row["endpoint_id"] or "")
            if not country or not endpoint_id:
                continue
            bucket = grouped.setdefault(country, [])
            if len(bucket) < per_country:
                bucket.append(endpoint_id)
        return grouped

    def record_endpoint_probe(self, endpoint_id: str, ok: bool, latency_ms: int = 0, message: str = "", speed_bps: int | None = None) -> bool:
        endpoint_id = str(endpoint_id or "").strip()
        if not endpoint_id:
            return False
        with self.lock, closing(self._connect()) as db:
            wrote = self._apply_endpoint_probe(db, endpoint_id, ok, latency_ms, message, speed_bps)
            db.commit()
        if wrote:
            self._invalidate_read_caches()
        return wrote

    def record_light_probe_batch(self, items: list[tuple[str, bool, int, str]]) -> int:
        """Write one catalog batch in a single transaction."""
        clean: list[tuple[str, bool, int, str]] = []
        for endpoint_id, ok, latency_ms, message in items or []:
            endpoint_id = str(endpoint_id or "").strip()
            if endpoint_id:
                clean.append((endpoint_id, bool(ok), int(latency_ms or 0), str(message or "")))
        if not clean:
            return 0
        wrote = 0
        with self.lock, closing(self._connect()) as db:
            for endpoint_id, ok, latency_ms, message in clean:
                if self._apply_endpoint_probe(db, endpoint_id, ok, latency_ms, message, None):
                    wrote += 1
            db.commit()
        if wrote:
            self._invalidate_read_caches()
        return wrote

    def _write_measured_speed(self, db: sqlite3.Connection, row: sqlite3.Row, speed: int, now: float) -> None:
        """Store one real download result. The list reads the newest observation."""
        server_key = str(row["server_key"] or "")
        if not server_key or speed <= 0:
            return
        server_row = db.execute(
            "SELECT current_ip, metadata_json FROM servers WHERE server_key=?",
            (server_key,),
        ).fetchone()
        ip = ""
        if server_row is not None:
            ip = str(server_row["current_ip"] or "").strip()
            try:
                server_meta = json.loads(server_row["metadata_json"] or "{}")
            except Exception:
                server_meta = {}
            if not isinstance(server_meta, dict):
                server_meta = {}
            server_meta["last_ip_speed_bps"] = int(speed)
            server_meta["last_ip_speed_at"] = now
            server_meta["last_ip_speed_ip"] = ip
            db.execute(
                "UPDATE servers SET metadata_json=? WHERE server_key=?",
                (json.dumps(server_meta, ensure_ascii=False), server_key),
            )
        prev = db.execute(
            "SELECT ping, sessions, score, ip FROM observations WHERE server_key=? ORDER BY seen_at DESC, id DESC LIMIT 1",
            (server_key,),
        ).fetchone()
        ping = int(prev["ping"] or 0) if prev else 0
        sessions = int(prev["sessions"] or 0) if prev else 0
        score = int(prev["score"] or 0) if prev else 0
        observed_ip = str((prev["ip"] if prev else "") or ip or "")
        db.execute(
            "INSERT INTO observations(server_key, source, seen_at, ip, ping, speed, sessions, score) VALUES(?,?,?,?,?,?,?,?)",
            (server_key, "speed_test", now, observed_ip, ping, int(speed), sessions, score),
        )

    def _apply_endpoint_probe(self, db: sqlite3.Connection, endpoint_id: str, ok: bool, latency_ms: int = 0, message: str = "", speed_bps: int | None = None) -> bool:
        now = time.time()
        latency = max(0, int(latency_ms or 0))
        speed = max(0, int(speed_bps or 0)) if speed_bps is not None else 0
        msg = str(message or "")[:1000]
        row = db.execute("SELECT * FROM endpoints WHERE endpoint_id=?", (endpoint_id,)).fetchone()
        if not row:
            return False
        prev_latency = float(row["latency_ewma"] or 0)
        prev_streak = int(row["success_streak"] or 0)
        prev_fail = int(row["fail_streak"] or 0)
        try: meta = json.loads(row["metadata_json"] or "{}")
        except Exception: meta = {}
        if not isinstance(meta, dict): meta = {}
        measured = speed_bps is not None and speed > 0
        slow = measured and speed < 10_000_000
        if measured:
            meta["last_probe_speed_bps"] = speed
            meta["last_probe_speed_at"] = now
            meta["slow_until"] = (now + 1800) if slow else 0
            self._write_measured_speed(db, row, speed, now)
        if slow:
            meta["last_error"] = msg
            meta["last_probe_message"] = msg
            session_seconds = int(row["last_session_seconds"] or 0) if "last_session_seconds" in row.keys() else 0
            stability = self._stability_decision(meta, now, session_seconds, 0)
            db.execute(
                """UPDATE endpoints SET status='COOLDOWN', last_failure=?, next_test=?, stability=?, metadata_json=?
                   WHERE endpoint_id=?""",
                (now, now + 1800, stability, json.dumps(meta, ensure_ascii=False), endpoint_id),
            )
        elif ok:
            ewma = float(latency) if latency > 0 else prev_latency
            if prev_latency > 0 and latency > 0:
                ewma = 0.35 * latency + 0.65 * prev_latency
            jitter = abs(latency - prev_latency) if prev_latency > 0 and latency > 0 else 0
            new_jitter = 0.35 * jitter + 0.65 * float(row["jitter_ewma"] or 0)
            meta["last_error"] = ""
            meta["last_probe_message"] = msg
            if speed_bps is not None:
                meta["last_probe_speed_bps"] = speed
                meta["last_probe_speed_at"] = now
            server_row = db.execute(
                "SELECT current_ip, metadata_json FROM servers WHERE server_key=?",
                (row["server_key"],),
            ).fetchone()
            if server_row is not None and speed_bps is not None:
                try: server_meta = json.loads(server_row["metadata_json"] or "{}")
                except Exception: server_meta = {}
                if not isinstance(server_meta, dict): server_meta = {}
                server_meta["last_ip_speed_bps"] = speed
                server_meta["last_ip_speed_at"] = now
                server_meta["last_ip_speed_ip"] = str(server_row["current_ip"] or "").strip()
                db.execute(
                    "UPDATE servers SET metadata_json=? WHERE server_key=?",
                    (json.dumps(server_meta, ensure_ascii=False), row["server_key"]),
                )
            session_seconds = int(row["last_session_seconds"] or 0) if "last_session_seconds" in row.keys() else 0
            stability = self._stability_decision(meta, now, session_seconds, 0)
            meta["stability"] = stability
            tcp_rtt = int(meta.get("tcp_rtt_ms") or 0)
            if 1 <= tcp_rtt <= 1500:
                shown_latency = tcp_rtt
            elif 1 <= latency <= 1500:
                shown_latency = latency
            else:
                shown_latency = int(row["ui_latency_ms"] or 0) if "ui_latency_ms" in row.keys() else 0
            db.execute(
                """UPDATE endpoints SET status='AVAILABLE', last_success=?, success_count=success_count+1,
                   fail_streak=0, success_streak=?, next_test=?, latency_ewma=?, jitter_ewma=?, stability=?, metadata_json=?, ui_latency_ms=?
                   WHERE endpoint_id=?""",
                (now, prev_streak + 1, now + 4*3600, ewma, new_jitter, stability, json.dumps(meta, ensure_ascii=False), shown_latency, endpoint_id)
            )
        else:
            if not self._probe_failure_should_count(msg):
                meta["last_probe_message"] = msg
                db.execute(
                    "UPDATE endpoints SET metadata_json=? WHERE endpoint_id=?",
                    (json.dumps(meta, ensure_ascii=False), endpoint_id),
                )
            else:
                new_fail = prev_fail + 1
                meta["last_error"] = msg
                session_seconds = int(row["last_session_seconds"] or 0) if "last_session_seconds" in row.keys() else 0
                stability = self._touch_stability(meta, now, "fail", new_fail, 0, session_seconds)
                if new_fail >= 3:
                    meta["last_probe_message"] = msg
                    db.execute(
                        """UPDATE endpoints SET status='COOLDOWN', last_failure=?, failure_count=failure_count+1,
                           fail_streak=?, success_streak=0, next_test=?, stability=?, metadata_json=? WHERE endpoint_id=?""",
                        (now, new_fail, now + 300, stability, json.dumps(meta, ensure_ascii=False), endpoint_id)
                    )
                else:
                    note = f"第{new_fail}/3次连通失败，暂不标不可用。{msg}"[:1000]
                    meta["last_error"] = note
                    meta["last_probe_message"] = note
                    db.execute(
                        """UPDATE endpoints SET last_failure=?, failure_count=failure_count+1,
                           fail_streak=?, success_streak=0, next_test=?, stability=?, metadata_json=? WHERE endpoint_id=?""",
                        (now, new_fail, now + 1800, stability, json.dumps(meta, ensure_ascii=False), endpoint_id)
                    )
        return True

    def record_probe(self, node: dict[str, Any], ok: bool, latency_ms: int = 0, message: str = "", speed_bps: int | None = 0) -> bool:
        key = self.server_key(node)
        protocol = str(node.get("protocol") or "openvpn").strip().lower()
        transport = str(node.get("proto") or node.get("transport") or "tcp").strip().lower()
        port = int(node.get("remote_port") or 0)
        return self.record_endpoint_probe(self.endpoint_id(key, protocol, transport, port), ok, latency_ms, message, speed_bps=speed_bps)

    def update_server_metadata_batch(self, updates: dict[str, dict[str, Any]]) -> int:
        if not isinstance(updates, dict) or not updates: return 0
        count = 0
        with self.lock, closing(self._connect()) as db:
            for key, meta_update in updates.items():
                if not isinstance(meta_update, dict): continue
                key = str(key or "").strip().lower()
                row = db.execute("SELECT server_key, metadata_json FROM servers WHERE server_key=? OR current_ip=?", (key, key)).fetchone()
                if not row: continue
                try: meta = json.loads(row["metadata_json"] or "{}")
                except Exception: meta = {}
                if not isinstance(meta, dict): meta = {}
                for field, val in meta_update.items():
                    if val not in (None, ""): meta[field] = val
                located = country_from_location(meta.get("location"))
                if located:
                    db.execute(
                        "UPDATE servers SET metadata_json=?, country=? WHERE server_key=?",
                        (json.dumps(meta, ensure_ascii=False), located, row["server_key"]),
                    )
                else:
                    db.execute("UPDATE servers SET metadata_json=? WHERE server_key=?", (json.dumps(meta, ensure_ascii=False), row["server_key"]))
                count += 1
            db.commit()
        self._invalidate_read_caches()
        return count

    def remove_shared_peer(self, peer_id: str) -> int:
        peer_id = str(peer_id or "").strip()
        if not peer_id: return 0
        removed = 0
        with self.lock, closing(self._connect()) as db:
            rows = db.execute("SELECT server_key, metadata_json FROM servers").fetchall()
            for row in rows:
                try: meta = json.loads(row["metadata_json"] or "{}")
                except Exception: meta = {}
                peer_ids = [str(x) for x in (meta.get("shared_peer_ids") or []) if str(x) and str(x) != peer_id]
                if peer_ids:
                    meta["shared_peer_ids"] = peer_ids
                    meta["shared_peer_count"] = len(peer_ids)
                    db.execute("UPDATE servers SET metadata_json=? WHERE server_key=?", (json.dumps(meta, ensure_ascii=False), row["server_key"]))
                elif meta.get("shared_peer_ids"):
                    db.execute("UPDATE servers SET state='STALE' WHERE server_key=?", (row["server_key"],))
                    removed += 1
            db.commit()
        self._invalidate_read_caches()
        return removed

    def repair_data_integrity(self) -> dict[str, int]:
        """Normalize country/protocol/transport records without touching probe results."""
        repaired_servers = 0
        repaired_endpoints = 0
        with self.lock, closing(self._connect()) as db:
            rows = db.execute("SELECT server_key, country, metadata_json FROM servers").fetchall()
            for row in rows:
                old = str(row["country"] or "").strip()
                try:
                    meta = json.loads(row["metadata_json"] or "{}")
                except Exception:
                    meta = {}
                location = str((meta or {}).get("location") or "").strip() if isinstance(meta, dict) else ""
                located = country_from_location(location)
                new = located or canonical_country_name(old)
                if not new and location:
                    new = canonical_country_name(location.split()[0])
                if new and old != new:
                    db.execute("UPDATE servers SET country=? WHERE server_key=?", (new, row["server_key"]))
                    repaired_servers += 1
            rows = db.execute("SELECT endpoint_id, protocol, transport, port, metadata_json FROM endpoints").fetchall()
            for row in rows:
                protocol = str(row["protocol"] or "").strip().lower()
                transport = str(row["transport"] or "").strip().lower() or "unknown"
                try:
                    port = int(row["port"] or 0)
                except Exception:
                    port = 0
                updates = []
                if protocol != str(row["protocol"] or ""):
                    updates.append(("protocol", protocol))
                if transport != str(row["transport"] or ""):
                    updates.append(("transport", transport))
                if updates:
                    db.execute("UPDATE endpoints SET protocol=?, transport=? WHERE endpoint_id=?", (protocol, transport, row["endpoint_id"]))
                    repaired_endpoints += 1
                # Ensure metadata is valid JSON for every UI read.
                try:
                    meta = json.loads(row["metadata_json"] or "{}")
                    if not isinstance(meta, dict): raise ValueError
                except Exception:
                    db.execute("UPDATE endpoints SET metadata_json='{}' WHERE endpoint_id=?", (row["endpoint_id"],))
            db.commit()
        self._invalidate_read_caches()
        return {"servers": repaired_servers, "endpoints": repaired_endpoints}

    def get_cached_ip_speed(self, endpoint_id: str, max_age_seconds: int = 86400) -> dict[str, Any]:
        """Return a recent real download-speed result cached per current IP."""
        endpoint_id = str(endpoint_id or "").strip()
        if not endpoint_id:
            return {"hit": False, "speed_bps": 0, "measured_at": 0.0}
        max_age_seconds = max(3600, int(max_age_seconds or 86400))
        with closing(self._connect()) as db:
            row = db.execute(
                """SELECT e.metadata_json AS endpoint_metadata_json,
                          s.current_ip, s.metadata_json AS server_metadata_json
                   FROM endpoints e JOIN servers s ON s.server_key=e.server_key
                   WHERE e.endpoint_id=?""",
                (endpoint_id,),
            ).fetchone()
        if not row:
            return {"hit": False, "speed_bps": 0, "measured_at": 0.0}
        try: endpoint_meta = json.loads(row["endpoint_metadata_json"] or "{}")
        except Exception: endpoint_meta = {}
        try: server_meta = json.loads(row["server_metadata_json"] or "{}")
        except Exception: server_meta = {}
        current_ip = str(row["current_ip"] or "").strip()
        measured_at = float(server_meta.get("last_ip_speed_at") or endpoint_meta.get("last_probe_speed_at") or 0.0)
        cached_ip = str(server_meta.get("last_ip_speed_ip") or "").strip()
        if cached_ip and current_ip and cached_ip != current_ip:
            measured_at = 0.0
        speed_bps = int(server_meta.get("last_ip_speed_bps") if server_meta.get("last_ip_speed_bps") is not None
                        else endpoint_meta.get("last_probe_speed_bps") or 0)
        age = time.time() - measured_at if measured_at else float("inf")
        if speed_bps <= 0:
            return {"hit": bool(measured_at and age <= 1800), "speed_bps": 0, "measured_at": measured_at}
        if not measured_at or age > max_age_seconds:
            return {"hit": False, "speed_bps": max(0, speed_bps), "measured_at": measured_at}
        return {"hit": True, "speed_bps": max(0, speed_bps), "measured_at": measured_at}

    def status_counts(self, country: str = "", protocol: str = "", ip_type: str = "", speed_min_bps: int = 0, latency: str = "") -> dict[str, int]:
        """Return status counts for the same rows the node table renders."""
        country = canonical_country_name(country) if country else ""
        protocol = str(protocol or "").strip().lower()
        ip_type = str(ip_type or "").strip().lower()
        speed_min_bps = int(speed_min_bps or 0)
        latency = normalize_latency_filter(latency)
        cache_key = (country, protocol, ip_type, speed_min_bps, latency)
        cached = self._status_counts_cache.get(cache_key)
        if cached and cached[0] > time.monotonic():
            return dict(cached[1])
        if not self._status_counts_gate.acquire(blocking=False):
            if cached:
                return dict(cached[1])
            if not self._status_counts_gate.acquire(timeout=2.0):
                if cached:
                    return dict(cached[1])
                raise sqlite3.OperationalError("status counts busy")
        try:
            cached = self._status_counts_cache.get(cache_key)
            if cached and cached[0] > time.monotonic():
                return dict(cached[1])
            empty = {"usable": 0, "available": 0, "testing": 0, "not_checked": 0, "unavailable": 0, "all": 0}
            try:
                ranked = self._ui_order_index(
                    country=country,
                    protocol=protocol,
                    ip_type=ip_type,
                    speed_min_bps=speed_min_bps,
                    latency=latency,
                )
            except sqlite3.OperationalError:
                if cached:
                    return dict(cached[1])
                raise
            buckets: dict[int, int] = {}
            for item in ranked:
                rank = int(item["rank"])
                buckets[rank] = buckets.get(rank, 0) + 1
            def _take(*ranks: int) -> int:
                return sum(buckets.get(rank, 0) for rank in ranks)
            result = {
                "usable": _take(0, 1, 2, 3),
                "available": _take(0, 1),
                "testing": _take(2),
                "not_checked": _take(3),
                "unavailable": _take(4, 5, 6, 7, 8, 9),
                "all": sum(buckets.values()),
            }
            self._status_counts_cache[cache_key] = (time.monotonic() + 60.0, result)
            return dict(result)
        finally:
            self._status_counts_gate.release()

    def stats(self) -> dict[str, Any]:
        now = time.monotonic()
        cached = self._stats_cache
        if cached and cached[0] > now:
            return dict(cached[1])
        try:
            with closing(self._connect(4000, readonly=True)) as db:
                servers = int(db.execute("SELECT COUNT(*) c FROM servers").fetchone()["c"] or 0)
                endpoints = int(db.execute("SELECT COUNT(*) c FROM endpoints").fetchone()["c"] or 0)
                distinct_ips = int(db.execute("SELECT COUNT(DISTINCT current_ip) c FROM servers WHERE TRIM(COALESCE(current_ip,''))<>''").fetchone()["c"] or 0)
                country_ips = int(db.execute("SELECT COUNT(DISTINCT current_ip) c FROM servers WHERE TRIM(COALESCE(current_ip,''))<>'' AND TRIM(COALESCE(country,''))<>''").fetchone()["c"] or 0)
                states = {
                    row["state"]: row["c"]
                    for row in db.execute("SELECT state, COUNT(*) c FROM servers GROUP BY state").fetchall()
                }
            result = {"servers": servers, "endpoints": endpoints, "distinct_ips": distinct_ips, "country_ips": country_ips, "states": states}
            self._stats_cache = (now + 30.0, result)
            return dict(result)
        except sqlite3.OperationalError:
            if cached:
                return dict(cached[1])
            return {"servers": 0, "endpoints": 0, "distinct_ips": 0, "country_ips": 0, "states": {}}

    def count_by_protocol(self, exclude_retired: bool = True) -> dict[str, int]:
        sql = "SELECT LOWER(protocol) AS p, COUNT(*) AS c FROM endpoints"
        if exclude_retired:
            sql += " WHERE UPPER(COALESCE(status,''))!='RETIRED'"
        sql += " GROUP BY 1"
        try:
            with closing(self._connect(4000, readonly=True)) as db:
                rows = db.execute(sql).fetchall()
        except sqlite3.OperationalError:
            return {}
        return {str(row["p"] or ""): int(row["c"] or 0) for row in rows if str(row["p"] or "")}