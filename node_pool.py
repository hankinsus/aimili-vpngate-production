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

from vpn_utils import COUNTRY_TRANSLATIONS, canonical_country_name

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

class NodePool:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.lock = threading.RLock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._stats_cache: tuple[float, dict[str, Any]] | None = None
        self._status_counts_cache: dict[tuple[str, str, str], tuple[float, dict[str, int]]] = {}
        self._scoped_page_cache: dict[tuple, tuple[float, tuple[list[dict[str, Any]], int]]] = {}
        self._country_catalog_cache: dict[tuple[str, str, str], tuple[float, dict[str, Any]]] = {}
        self._scoped_query_gate_guard = threading.Lock()
        self._scoped_query_gates: dict[tuple, threading.Lock] = {}
        self._country_catalog_gate = threading.Lock()
        self._status_counts_gate = threading.Lock()
        with closing(self._connect()) as db:
            db.executescript(_SCHEMA)
            db.commit()

    def _invalidate_read_caches(self) -> None:
        # Writes do not synchronously flush every UI snapshot. Status/country
        # statistics and bounded pages are intentionally short-TTL snapshots;
        # keeping them warm prevents a probe storm from turning every browser
        # request into a SQLite scan. The data remains authoritative after the
        # cache TTL and is refreshed automatically.
        self._stats_cache = None

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.db_path), timeout=3)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=2500")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA temp_store=MEMORY")
        db.execute("PRAGMA cache_size=-4096")
        db.execute("PRAGMA mmap_size=67108864")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @staticmethod
    def server_key(node: dict[str, Any]) -> str:
        hostname = str(node.get("host_name") or node.get("hostname") or "").strip().lower()
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
            protocol = {
                "protocol": "openvpn",
                "transport": str(node.get("proto") or "tcp").strip().lower() or "tcp",
                "port": int(node.get("remote_port") or 0),
                "hostname": str(node.get("host_name") or node.get("remote_host") or node.get("ip") or "").strip(),
            }
            servers.append({
                "hostname": str(node.get("host_name") or node.get("remote_host") or node.get("ip") or "").strip(),
                "ip": str(node.get("ip") or node.get("remote_host") or "").strip(),
                "country": node.get("country") or "",
                "ping": node.get("ping") or node.get("latency_ms") or 0,
                "speed": node.get("speed") or 0,
                "sessions": node.get("sessions") or 0,
                "score": node.get("score") or 0,
                "protocols": [protocol],
                "_sources": [source],
            })
        if servers:
            self.upsert_discovery_snapshot(servers, source=source)

    def upsert_discovery_snapshot(self, servers: list[dict[str, Any]], source: str = "official_html") -> None:
        now = time.time()
        seen_keys: set[str] = set()
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
                    "score": int(server.get("score") or 0),
                    "source_count": int(server.get("source_count") or 0),
                    "trusted_observation": bool(server.get("trusted_observation")),
                    "sources": list(server.get("_sources") or []),
                }
                if server.get("manual_added_at"):
                    metadata["manual_added_at"] = float(server.get("manual_added_at"))
                existing_server = db.execute(
                    "SELECT metadata_json FROM servers WHERE server_key=?",
                    (key,),
                ).fetchone()
                if existing_server:
                    try:
                        previous_meta = json.loads(existing_server["metadata_json"] or "{}")
                        if isinstance(previous_meta, dict):
                            previous_meta.update({k: v for k, v in metadata.items() if v not in (None, "")})
                            metadata = previous_meta
                    except Exception:
                        pass
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
                        "SELECT metadata_json FROM endpoints WHERE endpoint_id=?",
                        (eid,),
                    ).fetchone()
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

    def list_endpoints_scoped(self, country="", status="", protocol="", ip_type="", offset=0, limit=100,
                             speed_min_bps=0, active_endpoint_id="", active_ip="", active_protocol="", active_port=0):
        """Authoritative, bounded Master Pool query for the UI."""
        country = canonical_country_name(country) if country else ""
        status = str(status or "").strip().lower()
        protocol = str(protocol or "").strip().lower()
        ip_type = str(ip_type or "").strip().lower()
        speed_min_bps = max(0, int(speed_min_bps or 0))
        active_endpoint_id = str(active_endpoint_id or "").strip()
        active_ip = str(active_ip or "").strip()
        active_protocol = str(active_protocol or "").strip().lower()
        active_port = max(0, int(active_port or 0))
        offset = max(0, int(offset or 0))
        # Internal callers (e.g. the country full-sweep engine) may request
        # the complete country inventory; the HTTP layer still caps browser
        # pages at 200 rows.
        limit = max(1, min(int(limit or 100), 5000))
        cache_key = (country, status, protocol, ip_type, offset, limit,
                     speed_min_bps, active_endpoint_id, active_ip, active_protocol, active_port)
        cached = self._scoped_page_cache.get(cache_key)
        if cached and cached[0] > time.monotonic():
            cached_rows, cached_total = cached[1]
            return [dict(x) for x in cached_rows], int(cached_total)

        with self._scoped_query_gate_guard:
            gate = self._scoped_query_gates.setdefault(cache_key, threading.Lock())
        gate.acquire()
        try:
            cached = self._scoped_page_cache.get(cache_key)
            if cached and cached[0] > time.monotonic():
                cached_rows, cached_total = cached[1]
                return [dict(x) for x in cached_rows], int(cached_total)

            where = ["TRIM(COALESCE(s.current_ip, '')) <> ''"]
            params: list[Any] = []
            if country:
                where.append("s.country=?")
                params.append(country)
            if protocol and protocol != "all":
                where.append("LOWER(e.protocol)=?")
                params.append(protocol)
            if ip_type and ip_type != "all":
                where.append("LOWER(COALESCE(json_extract(s.metadata_json, '$.ip_type'), ''))=?")
                params.append(ip_type)
            if speed_min_bps > 0:
                where.append(
                    "CAST(COALESCE(json_extract(e.metadata_json,'$.last_probe_speed_bps'), "
                    "json_extract(s.metadata_json,'$.last_ip_speed_bps'), "
                    "(SELECT o.speed * 8 FROM observations o "
                    "WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS INTEGER) >= ?"
                )
                params.append(speed_min_bps)
            if status and status != "all":
                groups = {
                    "available": ("HOT", "AVAILABLE"),
                    "testing": ("TESTING", "DEGRADED"),
                    "not_checked": ("NEW",),
                    "unavailable": ("COOLDOWN", "STALE", "RETIRED", "UNAVAILABLE"),
                }
                allowed = groups.get(status)
                if allowed:
                    placeholders=','.join('?' for _ in allowed)
                    where.append(f"UPPER(e.status) IN ({placeholders})")
                    params.extend(allowed)

            base="FROM endpoints e JOIN servers s ON s.server_key=e.server_key WHERE " + " AND ".join(where)
            with closing(self._connect()) as db:
                total=int(db.execute("SELECT COUNT(*) "+base,params).fetchone()[0] or 0)
                rows=db.execute("""
                    SELECT e.*, s.hostname, s.current_ip, s.country, s.state AS server_state,
                           s.metadata_json AS server_metadata_json,
                           COALESCE((SELECT o.ping FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_ping,
                           COALESCE(CAST(json_extract(e.metadata_json,'$.last_probe_speed_bps') AS INTEGER), CAST(json_extract(s.metadata_json,'$.last_ip_speed_bps') AS INTEGER), COALESCE((SELECT o.speed * 8 FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0), 0) AS latest_speed,
                           COALESCE((SELECT o.sessions FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_sessions,
                           COALESCE((SELECT o.score FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_server_score
                    """ + base + """
                    ORDER BY CASE
                        WHEN ?<>'' AND e.endpoint_id=? THEN 0
                        WHEN ?<>'' AND s.current_ip=? AND LOWER(e.protocol)=? AND e.port=? THEN 0
                        ELSE 1 END,
                        CASE UPPER(e.status)
                        WHEN 'HOT' THEN 0 WHEN 'AVAILABLE' THEN 1 WHEN 'NEW' THEN 2
                        WHEN 'DEGRADED' THEN 3 WHEN 'COOLDOWN' THEN 4 WHEN 'STALE' THEN 5
                        WHEN 'RETIRED' THEN 6 ELSE 7 END,
                        CASE WHEN e.latency_ewma>0 THEN e.latency_ewma ELSE 999999 END,
                        e.next_test ASC, e.last_seen DESC
                    LIMIT ? OFFSET ?""",
                    params+[active_endpoint_id, active_endpoint_id, active_ip, active_ip, active_protocol, active_port, limit, offset]).fetchall()

            result=[]
            for row in rows:
                item=dict(row)
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
            self._scoped_page_cache[cache_key] = (time.monotonic() + 1.0, (result, total))
            return [dict(x) for x in result], total
        finally:
            gate.release()

    def country_catalog(self, status="", protocol="", ip_type="", connected_endpoint_id="", speed_min_bps=0):
        """Authoritative country/IP inventory using the same Master Pool scope as the node table."""
        status = str(status or "").strip().lower()
        protocol = str(protocol or "").strip().lower()
        ip_type = str(ip_type or "").strip().lower()
        connected_endpoint_id = str(connected_endpoint_id or "").strip()
        speed_min_bps = max(0, int(speed_min_bps or 0))
        key = (status, protocol, ip_type, connected_endpoint_id, speed_min_bps)
        now = time.monotonic()
        cached = self._country_catalog_cache.get(key)
        if cached and cached[0] > now:
            return dict(cached[1])

        where = ["TRIM(COALESCE(s.current_ip,''))<>''"]
        params: list[Any] = []

        if protocol and protocol != "all":
            where.append(
                "EXISTS (SELECT 1 FROM endpoints ee WHERE ee.server_key=s.server_key AND LOWER(ee.protocol)=?)"
            )
            params.append(protocol)

        if ip_type and ip_type != "all":
            where.append(
                "LOWER(COALESCE(json_extract(s.metadata_json,'$.ip_type'),''))=?"
            )
            params.append(ip_type)

        if speed_min_bps > 0:
            where.append(
                "EXISTS (SELECT 1 FROM endpoints ee WHERE ee.server_key=s.server_key "
                "AND CAST(COALESCE(json_extract(ee.metadata_json,'$.last_probe_speed_bps'), "
                "json_extract(s.metadata_json,'$.last_ip_speed_bps'), "
                "(SELECT o.speed * 8 FROM observations o "
                "WHERE o.server_key=ee.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS INTEGER) >= ?)"
            )
            params.append(speed_min_bps)

        if status and status != "all":
            if status == "connected":
                if connected_endpoint_id:
                    where.append(
                        "EXISTS (SELECT 1 FROM endpoints ee WHERE ee.server_key=s.server_key AND ee.endpoint_id=?)"
                    )
                    params.append(connected_endpoint_id)
                else:
                    where.append("1=0")
            else:
                groups = {
                    "available": ("HOT", "AVAILABLE"),
                    "testing": ("TESTING", "DEGRADED"),
                    "not_checked": ("NEW",),
                    "unavailable": ("COOLDOWN", "STALE", "RETIRED", "UNAVAILABLE"),
                }
                allowed = groups.get(status)
                if allowed:
                    placeholders = ",".join("?" for _ in allowed)
                    where.append(
                        "EXISTS (SELECT 1 FROM endpoints ee WHERE ee.server_key=s.server_key "
                        f"AND UPPER(ee.status) IN ({placeholders}))"
                    )
                    params.extend(allowed)

        scope = " FROM servers s WHERE " + " AND ".join(where)
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT s.country, COUNT(DISTINCT s.current_ip) AS ip_count, "
                "COUNT(DISTINCT s.server_key) AS server_count" + scope + " GROUP BY s.country",
                params,
            ).fetchall()
            total = int(db.execute(
                "SELECT COUNT(DISTINCT s.current_ip)" + scope, params
            ).fetchone()[0] or 0)

        countries: dict[str, dict[str, int]] = {}
        for row in rows:
            country = canonical_country_name(row["country"])
            if not country:
                continue
            item = countries.setdefault(country, {"ip_count": 0, "server_count": 0})
            item["ip_count"] += int(row["ip_count"] or 0)
            item["server_count"] += int(row["server_count"] or 0)

        # Known-country coverage is intentionally separate from the global
        # distinct-IP total: an un-geolocated Master Pool IP must not disappear
        # from the global count or be falsely assigned to a country.
        country_total = sum(int(v.get("ip_count") or 0) for v in countries.values())
        result = {
            "total_ip_count": total,
            "country_ip_count": country_total,
            "countries": countries,
            "status": status,
            "protocol": protocol,
            "ip_type": ip_type,
        }
        self._country_catalog_cache[key] = (now + 5.0, result)
        return dict(result)

    def get_endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        endpoint_id = str(endpoint_id or "").strip()
        if not endpoint_id:
            return None
        with closing(self._connect()) as db:
            row = db.execute(
                """
                SELECT e.*, s.hostname, s.current_ip, s.country, s.state AS server_state,
                       s.metadata_json AS server_metadata_json,
                       COALESCE((SELECT o.ping FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1),0) AS latest_ping,
                       COALESCE(CAST(json_extract(e.metadata_json,'$.last_probe_speed_bps') AS INTEGER), CAST(json_extract(s.metadata_json,'$.last_ip_speed_bps') AS INTEGER), COALESCE((SELECT o.speed * 8 FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0), 0) AS latest_speed,
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
                       COALESCE(CAST(json_extract(e.metadata_json,'$.last_probe_speed_bps') AS INTEGER), CAST(json_extract(s.metadata_json,'$.last_ip_speed_bps') AS INTEGER), COALESCE((SELECT o.speed * 8 FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0), 0) AS latest_speed,
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
            try: item["server_metadata"] = json.loads(item.pop("server_metadata_json") or "{}")
            except Exception: item["server_metadata"] = {}
            item["country"] = canonical_country_name(item.get("country") or "")
            counts[sk] = counts.get(sk, 0) + 1
            out.append(item)
            if len(out) >= limit: break
        return out

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
                       COALESCE(CAST(json_extract(e.metadata_json,'$.last_probe_speed_bps') AS INTEGER), CAST(json_extract(s.metadata_json,'$.last_ip_speed_bps') AS INTEGER), COALESCE((SELECT o.speed * 8 FROM observations o WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0), 0) AS latest_speed,
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

    def record_endpoint_probe(self, endpoint_id: str, ok: bool, latency_ms: int = 0, message: str = "", speed_bps: int | None = None) -> bool:
        endpoint_id = str(endpoint_id or "").strip()
        if not endpoint_id: return False
        now = time.time()
        latency = max(0, int(latency_ms or 0))
        speed = max(0, int(speed_bps or 0)) if speed_bps is not None else 0
        msg = str(message or "")[:1000]
        with self.lock, closing(self._connect()) as db:
            row = db.execute("SELECT * FROM endpoints WHERE endpoint_id=?", (endpoint_id,)).fetchone()
            if not row: return False
            prev_latency = float(row["latency_ewma"] or 0)
            prev_streak = int(row["success_streak"] or 0)
            prev_fail = int(row["fail_streak"] or 0)
            try: meta = json.loads(row["metadata_json"] or "{}")
            except Exception: meta = {}
            if not isinstance(meta, dict): meta = {}
            if ok:
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
                db.execute(
                    """UPDATE endpoints SET status='AVAILABLE', last_success=?, success_count=success_count+1,
                       fail_streak=0, success_streak=?, next_test=?, latency_ewma=?, jitter_ewma=?, metadata_json=?
                       WHERE endpoint_id=?""",
                    (now, prev_streak + 1, now + 4*3600, ewma, new_jitter, json.dumps(meta, ensure_ascii=False), endpoint_id)
                )
            else:
                meta["last_error"] = msg
                meta["last_probe_message"] = msg
                db.execute(
                    """UPDATE endpoints SET status='COOLDOWN', last_failure=?, failure_count=failure_count+1,
                       fail_streak=?, success_streak=0, next_test=?, metadata_json=? WHERE endpoint_id=?""",
                    (now, prev_fail + 1, now + 300, json.dumps(meta, ensure_ascii=False), endpoint_id)
                )
            db.commit()
        self._invalidate_read_caches()
        return True

    def record_probe(self, node: dict[str, Any], ok: bool, latency_ms: int = 0, message: str = "", speed_bps: int = 0) -> bool:
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
                new = canonical_country_name(old)
                # Older discovery snapshots sometimes stored the country only
                # in the enriched location string (e.g. “日本 大阪府 大阪市”).
                # Recover that value before the UI builds its country/IP index.
                if not new:
                    try:
                        meta = json.loads(row["metadata_json"] or "{}")
                    except Exception:
                        meta = {}
                    location = str((meta or {}).get("location") or "").strip()
                    if location:
                        new = canonical_country_name(location.split()[0])
                if old != new:
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

    def status_counts(self, country: str = "", protocol: str = "", ip_type: str = "", speed_min_bps: int = 0) -> dict[str, int]:
        """Return authoritative endpoint status counts for the UI filters."""
        country = canonical_country_name(country) if country else ""
        protocol = str(protocol or "").strip().lower()
        ip_type = str(ip_type or "").strip().lower()
        speed_min_bps = max(0, int(speed_min_bps or 0))
        cache_key = (country, protocol, ip_type, speed_min_bps)
        cached = self._status_counts_cache.get(cache_key)
        if cached and cached[0] > time.monotonic():
            return dict(cached[1])
        with self._status_counts_gate:
            cached = self._status_counts_cache.get(cache_key)
            if cached and cached[0] > time.monotonic():
                return dict(cached[1])
            where = ["TRIM(COALESCE(s.current_ip,''))<>''"]
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
            if speed_min_bps > 0:
                where.append(
                    "CAST(COALESCE(json_extract(e.metadata_json,'$.last_probe_speed_bps'), "
                    "json_extract(s.metadata_json,'$.last_ip_speed_bps'), "
                    "(SELECT o.speed * 8 FROM observations o "
                    "WHERE o.server_key=e.server_key ORDER BY o.seen_at DESC LIMIT 1), 0) AS INTEGER) >= ?"
                )
                params.append(speed_min_bps)
            sql = """
                SELECT
                  SUM(CASE WHEN UPPER(e.status) IN ('HOT','AVAILABLE') THEN 1 ELSE 0 END) AS available,
                  SUM(CASE WHEN UPPER(e.status)='TESTING' THEN 1 ELSE 0 END) AS testing,
                  SUM(CASE WHEN UPPER(e.status)='NEW' THEN 1 ELSE 0 END) AS not_checked,
                  SUM(CASE WHEN UPPER(e.status) IN ('DEGRADED','COOLDOWN','STALE','RETIRED','UNAVAILABLE') THEN 1 ELSE 0 END) AS unavailable
                FROM endpoints e JOIN servers s ON s.server_key=e.server_key
                WHERE """ + " AND ".join(where)
            with closing(self._connect()) as db:
                row = db.execute(sql, params).fetchone()
            result = {
                "available": int(row["available"] or 0),
                "testing": int(row["testing"] or 0),
                "not_checked": int(row["not_checked"] or 0),
                "unavailable": int(row["unavailable"] or 0),
            }
            self._status_counts_cache[cache_key] = (time.monotonic() + 2.0, result)
            return dict(result)

    def stats(self) -> dict[str, Any]:
        now = time.monotonic()
        cached = self._stats_cache
        if cached and cached[0] > now:
            return dict(cached[1])
        with closing(self._connect()) as db:
            servers = int(db.execute("SELECT COUNT(*) c FROM servers").fetchone()["c"] or 0)
            endpoints = int(db.execute("SELECT COUNT(*) c FROM endpoints").fetchone()["c"] or 0)
            distinct_ips = int(db.execute("SELECT COUNT(DISTINCT current_ip) c FROM servers WHERE TRIM(COALESCE(current_ip,''))<>''").fetchone()["c"] or 0)
            country_ips = int(db.execute("SELECT COUNT(DISTINCT current_ip) c FROM servers WHERE TRIM(COALESCE(current_ip,''))<>'' AND TRIM(COALESCE(country,''))<>''").fetchone()["c"] or 0)
            states = {
                row["state"]: row["c"]
                for row in db.execute("SELECT state, COUNT(*) c FROM servers GROUP BY state").fetchall()
            }
        result = {"servers": servers, "endpoints": endpoints, "distinct_ips": distinct_ips, "country_ips": country_ips, "states": states}
        self._stats_cache = (now + 2.0, result)
        return dict(result)