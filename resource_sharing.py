from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable


def _shared_speed_bps(endpoint: dict[str, Any]) -> int:
    """Peer speed is useful. Peer latency is not: each site measures its own."""
    try:
        speed = int(endpoint.get("latest_speed") or 0)
    except (TypeError, ValueError):
        speed = 0
    if speed > 0:
        return speed
    metadata = endpoint.get("metadata") or {}
    try:
        return max(0, int(metadata.get("last_probe_speed_bps") or metadata.get("shared_speed_bps") or 0))
    except (TypeError, ValueError):
        return 0


class ResourceShareManager:
    """Peer resource sharing over the existing HTTPS management port."""

    DEFAULT_MAX_NODES = 5000
    MAX_MAX_NODES = 5000
    DEFAULT_SYNC_INTERVAL_VALUE = 6
    DEFAULT_SYNC_INTERVAL_UNIT = "hours"
    MIN_SYNC_INTERVAL_SECONDS = 3600
    MAX_SYNC_INTERVAL_SECONDS = 12 * 7 * 24 * 3600

    def __init__(self, data_file: Path, node_pool: Any, log_fn: Callable[[str], None] | None = None) -> None:
        self.data_file = Path(data_file)
        self.node_pool = node_pool
        self.lock = threading.RLock()
        self.log_fn = log_fn
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        self._ensure()
    def _log(self, message: str) -> None:
        if self.log_fn:
            try:
                self.log_fn(message)
                return
            except Exception:
                pass
        print(f"[ResourceShare] {message}", flush=True)

    def _default(self) -> dict[str, Any]:
        return {
            "schema": 2,
            "instance_id": "rs-" + secrets.token_hex(12),
            "peers": {},
            "invites": {},
        }

    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.data_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return self._default()
        except (OSError, json.JSONDecodeError):
            return self._default()

        data.setdefault("schema", 2)
        data.setdefault("instance_id", "rs-" + secrets.token_hex(12))
        data.setdefault("peers", {})
        data.setdefault("invites", {})

        # Migrate historical invite records to standing, revocable invitations.
        for invite_id, invite in list(data["invites"].items()):
            if not isinstance(invite, dict):
                data["invites"].pop(invite_id, None)
                continue
            invite.setdefault("revoked", False)
            invite["expires_at"] = 0
            invite.setdefault("legacy_code_unavailable", "code" not in invite)
        # Migrate historical peers to explicit direction semantics.
        for peer in data["peers"].values():
            if not isinstance(peer, dict):
                continue
            remote_url = str(peer.get("remote_url") or "").strip()
            peer.setdefault("direction", "outbound" if remote_url else "inbound")
            peer.setdefault("remote_instance_id", "")
            peer.setdefault("invite_id", "")
            peer.setdefault("remote_invite_id", "")
            peer.setdefault("remote_invite_code", "")
            peer.setdefault("sync_interval_value", self.DEFAULT_SYNC_INTERVAL_VALUE)
            peer.setdefault("sync_interval_unit", self.DEFAULT_SYNC_INTERVAL_UNIT)
            peer.setdefault("source_ip", "")
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.data_file.with_suffix(self.data_file.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.data_file)
        try:
            self.data_file.chmod(0o600)
        except OSError:
            pass

    def _ensure(self) -> None:
        with self.lock:
            self._write(self._read())

    @property
    def instance_id(self) -> str:
        with self.lock:
            return str(self._read().get("instance_id") or "")
    @staticmethod
    def _hash_secret(value: str) -> str:
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_url(url: str) -> str:
        raw = str(url or "").strip()
        if not raw:
            raise ValueError("资源服务器地址不能为空")
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("资源服务器地址必须使用 HTTPS")
        if parsed.username or parsed.password:
            raise ValueError("资源服务器地址不能包含账号或密码")
        port = parsed.port or 443
        path = parsed.path.rstrip("/")
        path = re.sub(r"/(?:resources|enroll|ping)$", "", path).rstrip("/")
        host = str(parsed.hostname or "")
        netloc_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        return urllib.parse.urlunsplit(("https", f"{netloc_host}:{int(port)}", path, "", "")).rstrip("/")

    @staticmethod
    def normalize_remote_input(value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            raise ValueError("对方服务器地址不能为空")
        if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
            raw = "https://" + raw
        parsed = urllib.parse.urlsplit(raw)
        if not parsed.hostname:
            raise ValueError("对方服务器地址无效")
        if parsed.port is None:
            host = parsed.hostname
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            raw = urllib.parse.urlunsplit((parsed.scheme or "https", f"{host}:8443", parsed.path or "", "", ""))
        if not urllib.parse.urlsplit(raw).path or urllib.parse.urlsplit(raw).path == "/":
            parsed = urllib.parse.urlsplit(raw)
            raw = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/resource-share", "", ""))
        return ResourceShareManager._normalize_url(raw)

    @staticmethod
    def _safe_name(value: Any, fallback: str = "共享服务器") -> str:
        value = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()
        return value[:80] or fallback
    @classmethod
    def _safe_max_nodes(cls, value: Any) -> int:
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = cls.DEFAULT_MAX_NODES
        return max(10, min(value, cls.MAX_MAX_NODES))

    @classmethod
    def normalize_sync_interval(cls, value: Any, unit: Any) -> tuple[int, str, int]:
        try:
            amount = int(value)
        except (TypeError, ValueError):
            amount = cls.DEFAULT_SYNC_INTERVAL_VALUE
        amount = max(1, amount)
        unit_key = str(unit or cls.DEFAULT_SYNC_INTERVAL_UNIT).strip().lower()
        multipliers = {"hours": 3600, "days": 86400, "weeks": 7 * 86400}
        if unit_key not in multipliers:
            unit_key = cls.DEFAULT_SYNC_INTERVAL_UNIT
        seconds = max(cls.MIN_SYNC_INTERVAL_SECONDS, min(amount * multipliers[unit_key], cls.MAX_SYNC_INTERVAL_SECONDS))
        amount = max(1, seconds // multipliers[unit_key])
        return amount, unit_key, amount * multipliers[unit_key]

    @classmethod
    def sync_interval_from_peer(cls, peer: dict[str, Any]) -> tuple[int, str, int]:
        return cls.normalize_sync_interval(
            peer.get("sync_interval_value", cls.DEFAULT_SYNC_INTERVAL_VALUE),
            peer.get("sync_interval_unit", cls.DEFAULT_SYNC_INTERVAL_UNIT),
        )

    @staticmethod
    def normalize_cidrs(values: Any) -> list[str]:
        if isinstance(values, str):
            values = re.split(r"[,\s]+", values.strip())
        if not isinstance(values, list):
            return []
        result: list[str] = []
        for raw in values:
            value = str(raw or "").strip()
            if not value:
                continue
            try:
                # A bare address is accepted as a single-host network.
                if "/" not in value:
                    addr = ipaddress.ip_address(value)
                    value = f"{addr}/128" if addr.version == 6 else f"{addr}/32"
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"无效的允许 IP/CIDR: {value}") from exc
            normalized = str(net)
            if normalized not in result:
                result.append(normalized)
        return result[:32]

    @staticmethod
    def unwrap_ip(value: Any):
        """Manual IPv4 stays IPv4. ::ffff:67.10.84.82 is that same address."""
        text = str(value or "").strip()
        if not text:
            return None
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            return addr.ipv4_mapped
        return addr

    @staticmethod
    def client_ips(headers: Any, client_address: Any) -> list[str]:
        """TCP peer first. Forwarded headers only when that peer is local nginx.

        A manually allowed address must be compared against the real peer.
        An X-Forwarded-For value must not hide it, and must not be trusted
        from a connection that did not come through the local proxy.
        """
        socket_raw = ""
        try:
            socket_raw = str(client_address[0] if client_address else "").strip()
        except Exception:
            socket_raw = ""
        socket_addr = ResourceShareManager.unwrap_ip(socket_raw)
        raw_values: list[str] = []
        if socket_raw:
            raw_values.append(socket_raw)
        if socket_addr is not None and socket_addr.is_loopback:
            try:
                real_ip = str(headers.get("X-Real-IP") or "").strip()
                if real_ip:
                    raw_values.append(real_ip)
                forwarded = str(headers.get("X-Forwarded-For") or "").strip()
                if forwarded:
                    raw_values.extend(part.strip() for part in forwarded.split(","))
            except Exception:
                pass
        found: list[str] = []
        for raw in raw_values:
            addr = ResourceShareManager.unwrap_ip(raw)
            if addr is None:
                continue
            text = str(addr)
            if text not in found:
                found.append(text)
        return found

    @staticmethod
    def client_ip(headers: Any, client_address: Any) -> str:
        ips = ResourceShareManager.client_ips(headers, client_address)
        return ips[0] if ips else ""

    @staticmethod
    def _cidr_allowed(source_ip: str, cidrs: list[str]) -> bool:
        addr = ResourceShareManager.unwrap_ip(source_ip)
        if addr is None or not cidrs:
            return False
        # A typed /32 or /128 is the operator's explicit choice. Check it
        # before a different-family network, and never let a family mismatch
        # abort the rest of the list.
        ordered = sorted(
            cidrs,
            key=lambda raw: 0 if str(raw).endswith("/32") or str(raw).endswith("/128") else 1,
        )
        for raw in ordered:
            try:
                network = ipaddress.ip_network(str(raw), strict=False)
            except ValueError:
                continue
            if network.version != addr.version:
                continue
            if addr in network:
                return True
        return False

    @classmethod
    def _sources_allowed(cls, source_ips: Any, cidrs: list[str]) -> str:
        if isinstance(source_ips, str):
            ips = [source_ips]
        else:
            ips = [str(item or "") for item in (source_ips or [])]
        for source_ip in ips:
            if cls._cidr_allowed(source_ip, cidrs):
                return str(cls.unwrap_ip(source_ip) or source_ip)
        return ""
    def create_invite(self, peer_name: str = "", allowed_cidrs: Any = None) -> dict[str, Any]:
        peer_name = self._safe_name(peer_name, "共享服务器")
        cidrs = self.normalize_cidrs(allowed_cidrs)
        if not cidrs:
            raise ValueError("请至少填写一个允许 IP/CIDR；全部 IPv4 可填写 0.0.0.0/0，IPv6 可填写 ::/0")
        code = "RS-" + "-".join(secrets.token_hex(2).upper() for _ in range(4))
        now = time.time()
        invite_id = secrets.token_hex(12)
        with self.lock:
            data = self._read()
            data["invites"][invite_id] = {
                "invite_id": invite_id,
                "code": code,
                "hash": self._hash_secret(code),
                "peer_name": peer_name,
                "allowed_cidrs": cidrs,
                "created_at": now,
                "revoked": False,
                "revoked_at": 0,
            }
            self._write(data)
        return {
            "ok": True,
            "invite_id": invite_id,
            "invite_code": code,
            "peer_name": peer_name,
            "allowed_cidrs": cidrs,
            "expires_at": 0,
            "expires_label": "永不过期",
            "created_at": now,
        }

    def list_invites(self, include_revoked: bool = False) -> list[dict[str, Any]]:
        with self.lock:
            data = self._read()
            peers = list(data["peers"].values())
            invites = list(data["invites"].values())
        counts: dict[str, int] = {}
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            invite_id = str(peer.get("invite_id") or "")
            if invite_id:
                counts[invite_id] = counts.get(invite_id, 0) + 1
        out: list[dict[str, Any]] = []
        for invite in invites:
            if not isinstance(invite, dict):
                continue
            if invite.get("revoked") and not include_revoked:
                continue
            out.append({
                "invite_id": str(invite.get("invite_id") or ""),
                "invite_code": str(invite.get("code") or ""),
                "peer_name": str(invite.get("peer_name") or "共享服务器"),
                "allowed_cidrs": list(invite.get("allowed_cidrs") or []),
                "created_at": float(invite.get("created_at") or 0),
                "revoked": bool(invite.get("revoked")),
                "revoked_at": float(invite.get("revoked_at") or 0),
                "expires_at": 0,
                "expires_label": "永不过期",
                "linked_peer_count": counts.get(str(invite.get("invite_id") or ""), 0),
                "legacy_code_unavailable": bool(invite.get("legacy_code_unavailable")),
            })
        out.sort(key=lambda x: x["created_at"], reverse=True)
        return out
    def revoke_invite(self, invite_id: str) -> dict[str, Any]:
        invite_id = str(invite_id or "").strip()
        if not invite_id:
            raise ValueError("invite_id 不能为空")
        affected: list[str] = []
        with self.lock:
            data = self._read()
            invite = data["invites"].get(invite_id)
            if not isinstance(invite, dict):
                raise KeyError("邀请码不存在")
            invite["revoked"] = True
            invite["revoked_at"] = time.time()
            for peer_id, peer in data["peers"].items():
                if isinstance(peer, dict) and str(peer.get("invite_id") or "") == invite_id:
                    peer["enabled"] = False
                    affected.append(str(peer_id))
            self._write(data)
        return {"ok": True, "invite_id": invite_id, "affected_peer_ids": affected, "message": "邀请码已撤销；关联的入站共享访问已停止。"}

    def restore_invite(self, invite_id: str) -> dict[str, Any]:
        invite_id = str(invite_id or "").strip()
        if not invite_id:
            raise ValueError("invite_id 不能为空")
        affected: list[str] = []
        with self.lock:
            data = self._read()
            invite = data["invites"].get(invite_id)
            if not isinstance(invite, dict):
                raise KeyError("邀请码不存在")
            invite["revoked"] = False
            invite["revoked_at"] = 0
            for peer_id, peer in data["peers"].items():
                if isinstance(peer, dict) and str(peer.get("invite_id") or "") == invite_id:
                    peer["enabled"] = True
                    affected.append(str(peer_id))
            self._write(data)
        return {"ok": True, "invite_id": invite_id, "affected_peer_ids": affected, "message": "邀请链接已恢复，关联入站共享访问已重新启用。"}

    def delete_invite(self, invite_id: str) -> dict[str, Any]:
        invite_id = str(invite_id or "").strip()
        if not invite_id:
            raise ValueError("invite_id 不能为空")
        with self.lock:
            data = self._read()
            invite = data["invites"].get(invite_id)
            if not isinstance(invite, dict):
                raise KeyError("邀请码不存在")
            # Destructive deletion is only allowed after an explicit revoke.
            # This prevents accidental deletion of a currently active share.
            if not invite.get("revoked"):
                raise ValueError("必须先撤销邀请链接，撤销后才能永久删除。")
            linked = [
                peer_id for peer_id, peer in data["peers"].items()
                if isinstance(peer, dict) and str(peer.get("invite_id") or "") == invite_id
            ]
            for peer_id in linked:
                data["peers"].pop(peer_id, None)
            data["invites"].pop(invite_id, None)
            self._write(data)
        for peer_id in linked:
            try:
                self.node_pool.remove_shared_peer(peer_id)
            except Exception as exc:
                self._log(f"永久删除邀请码后的共享资源清理失败: {exc}")
        return {"ok": True, "invite_id": invite_id, "deleted_peer_ids": linked}

    def _find_invite(self, code: str, source_ip: str) -> tuple[str, dict[str, Any]] | None:
        target = self._hash_secret(code)
        with self.lock:
            data = self._read()
            for invite_id, invite in data["invites"].items():
                if not isinstance(invite, dict) or bool(invite.get("revoked")):
                    continue
                stored_hash = str(invite.get("hash") or "")
                if not stored_hash or not hmac.compare_digest(stored_hash, target):
                    continue
                cidrs = list(invite.get("allowed_cidrs") or [])
                matched_ip = self._sources_allowed(source_ip, cidrs)
                if not matched_ip:
                    continue
                invite = dict(invite)
                invite["_matched_source_ip"] = matched_ip
                return str(invite_id), invite
        return None

    def _find_peer_by_token(self, token: str, source_ip: str) -> tuple[str, dict[str, Any]] | None:
        target = self._hash_secret(token)
        with self.lock:
            data = self._read()
            for peer_id, peer in data["peers"].items():
                if not isinstance(peer, dict) or not peer.get("enabled", True):
                    continue
                if not hmac.compare_digest(str(peer.get("inbound_token_hash") or ""), target):
                    continue
                matched_ip = self._sources_allowed(source_ip, list(peer.get("allowed_cidrs") or []))
                if not matched_ip:
                    continue
                peer = dict(peer)
                peer["_matched_source_ip"] = matched_ip
                return str(peer_id), peer
        return None

    def authorize(self, headers: Any, client_address: Any) -> tuple[str, dict[str, Any]]:
        token = str(headers.get("X-Aimili-Resource-Token") or "").strip()
        if len(token) < 20:
            raise PermissionError("资源共享访问令牌无效")
        source_ips = self.client_ips(headers, client_address)
        matched = self._find_peer_by_token(token, source_ips)
        if not matched:
            shown = ", ".join(source_ips) or "未知"
            raise PermissionError(f"资源共享身份验证失败，或来源 IP 未获允许（实际来源 {shown}）")
        return matched
    def enroll(self, payload: dict[str, Any], source_ip: Any) -> dict[str, Any]:
        code = str(payload.get("invite_code") or "").strip()
        if not code:
            raise PermissionError("邀请码不能为空")
        found = self._find_invite(code, source_ip)
        if not found:
            if isinstance(source_ip, str):
                shown = source_ip or "未知"
            else:
                shown = ", ".join(str(item) for item in (source_ip or [])) or "未知"
            raise PermissionError(
                "邀请码无效、已撤销，或来源 IP 不在人工允许范围内"
                f"（实际来源 {shown}）。手工填写的 IPv4 同样认可它的 ::ffff: 形式。"
            )
        invite_id, invite = found
        remote_instance_id = self._safe_name(payload.get("peer_id"), "Peer")[:128]
        remote_name = self._safe_name(invite.get("peer_name"), "共享服务器")
        existing_peer_id = self._safe_name(payload.get("existing_peer_id"), "")[:128]
        inbound_token = secrets.token_urlsafe(32)
        now = time.time()

        with self.lock:
            data = self._read()
            target_id = ""
            if existing_peer_id and isinstance(data["peers"].get(existing_peer_id), dict):
                candidate = data["peers"][existing_peer_id]
                if str(candidate.get("direction") or "") == "inbound" or not candidate.get("remote_url"):
                    if str(candidate.get("remote_peer_id") or "") == remote_instance_id:
                        target_id = existing_peer_id
            if not target_id:
                for peer_id, peer in data["peers"].items():
                    if not isinstance(peer, dict):
                        continue
                    if str(peer.get("direction") or "") != "inbound":
                        continue
                    if str(peer.get("remote_peer_id") or "") == remote_instance_id:
                        target_id = str(peer_id)
                        break
            if not target_id:
                target_id = "peer-" + secrets.token_hex(8)

            old = data["peers"].get(target_id) if target_id else None
            peer = dict(old) if isinstance(old, dict) else {}
            peer.update({
                "peer_id": target_id,
                "remote_peer_id": remote_instance_id,
                "remote_instance_id": remote_instance_id,
                "name": remote_name,
                "remote_url": "",
                "remote_port": 0,
                "allowed_cidrs": list(invite.get("allowed_cidrs") or []),
                "max_nodes": self.MAX_MAX_NODES,
                "sync_mode": "inbound",
                "direction": "inbound",
                "enabled": True,
                "created_at": float(peer.get("created_at") or now),
                "updated_at": now,
                "last_sync_at": 0,
                "last_sync_ok": None,
                "last_sync_error": "",
                "last_sync_count": 0,
                "source_ip": str(invite.get("_matched_source_ip") or (source_ip if isinstance(source_ip, str) else "")),
                "invite_id": invite_id,
                "inbound_token_hash": self._hash_secret(inbound_token),
                "outbound_token": "",
                "remote_invite_id": "",
                "remote_invite_code": "",
                "sync_interval_value": self.DEFAULT_SYNC_INTERVAL_VALUE,
                "sync_interval_unit": self.DEFAULT_SYNC_INTERVAL_UNIT,
            })
            data["peers"][target_id] = peer
            self._write(data)

        return {
            "ok": True,
            "peer_id": target_id,
            "instance_id": self.instance_id,
            "peer_name": remote_name,
            "invite_id": invite_id,
            "inbound_token": inbound_token,
            "allowed_cidrs": list(invite.get("allowed_cidrs") or []),
            "resource_url": "/resource-share",
        }

    def _normalize_remote_host_cidrs(self, remote_url: str) -> list[str]:
        parsed = urllib.parse.urlsplit(remote_url)
        host = str(parsed.hostname or "").strip()
        if not host:
            return []
        try:
            addr = ipaddress.ip_address(host)
            return [f"{addr}/128" if addr.version == 6 else f"{addr}/32"]
        except ValueError:
            pass
        out: list[str] = []
        try:
            for info in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
                try:
                    addr = ipaddress.ip_address(info[4][0])
                    cidr = f"{addr}/128" if addr.version == 6 else f"{addr}/32"
                    if cidr not in out:
                        out.append(cidr)
                except ValueError:
                    continue
        except OSError:
            pass
        return out[:16]
    def add_joined_peer(
        self,
        remote_url: str,
        remote_peer_id: str,
        remote_instance_id: str,
        name: str,
        remote_token: str,
        max_nodes: int = MAX_MAX_NODES,
        sync_interval_value: Any = DEFAULT_SYNC_INTERVAL_VALUE,
        sync_interval_unit: Any = DEFAULT_SYNC_INTERVAL_UNIT,
        remote_invite_id: str = "",
        remote_invite_code: str = "",
        auto_sync: Any = True,
        sync_schedule: str = "loop",
        sync_hour: Any = None,
    ) -> str:
        normalized = self.normalize_remote_input(remote_url)
        now = time.time()
        with self.lock:
            data = self._read()
            target_id = ""
            for peer_id, peer in data["peers"].items():
                if not isinstance(peer, dict):
                    continue
                if str(peer.get("direction") or "") != "outbound":
                    continue
                same_instance = remote_instance_id and str(peer.get("remote_instance_id") or "") == str(remote_instance_id)
                same_url = str(peer.get("remote_url") or "") == normalized
                if same_instance or same_url:
                    target_id = str(peer_id)
                    break
            if not target_id:
                target_id = "peer-" + secrets.token_hex(8)
            old = data["peers"].get(target_id)
            old_peer = dict(old) if isinstance(old, dict) else {}
            interval_value, interval_unit, _ = self.normalize_sync_interval(sync_interval_value, sync_interval_unit)
            old_peer.update({
                "peer_id": target_id,
                "remote_peer_id": str(remote_peer_id or ""),
                "remote_instance_id": str(remote_instance_id or ""),
                "name": self._safe_name(name, "共享服务器"),
                "remote_url": normalized,
                "remote_port": int(urllib.parse.urlsplit(normalized).port or 8443),
                "allowed_cidrs": [],
                "max_nodes": self.MAX_MAX_NODES,
                "sync_mode": "outbound",
                "direction": "outbound",
                "enabled": True,
                "created_at": float(old_peer.get("created_at") or now),
                "updated_at": now,
                "last_sync_at": float(old_peer.get("last_sync_at") or 0),
                "last_sync_ok": old_peer.get("last_sync_ok"),
                "last_sync_error": str(old_peer.get("last_sync_error") or ""),
                "last_sync_count": int(old_peer.get("last_sync_count") or 0),
                "source_ip": "",
                "invite_id": "",
                "inbound_token_hash": "",
                "outbound_token": str(remote_token or ""),
                "remote_invite_id": str(remote_invite_id or ""),
                "remote_invite_code": str(remote_invite_code or ""),
                "sync_interval_value": interval_value,
                "sync_interval_unit": interval_unit,
                "auto_sync": old_peer.get("auto_sync", True) is not False,
                "sync_schedule": str(old_peer.get("sync_schedule") or "loop"),
                "sync_hour": int(old_peer.get("sync_hour") or interval_value or 6),
                "syncing": False,
            })
            self.apply_sync_schedule(
                old_peer,
                auto_sync,
                sync_schedule,
                sync_hour if sync_hour is not None else interval_value,
            )
            data["peers"][target_id] = old_peer
            self._write(data)
        return target_id

    def list_peers(self, include_tokens: bool = False) -> list[dict[str, Any]]:
        with self.lock:
            peers = list(self._read()["peers"].values())
        out: list[dict[str, Any]] = []
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            item = dict(peer)
            if not include_tokens:
                item.pop("outbound_token", None)
            item.pop("inbound_token_hash", None)
            out.append(item)
        out.sort(key=lambda x: float(x.get("created_at") or 0), reverse=True)
        return out

    def get_peer(self, peer_id: str) -> dict[str, Any] | None:
        with self.lock:
            peer = self._read()["peers"].get(str(peer_id))
            return dict(peer) if isinstance(peer, dict) else None
    def update_peer(self, peer_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        peer_id = str(peer_id or "").strip()
        with self.lock:
            data = self._read()
            peer = data["peers"].get(peer_id)
            if not isinstance(peer, dict):
                raise KeyError("Peer 不存在")
            if "name" in patch:
                peer["name"] = self._safe_name(patch.get("name"))
            if "sync_interval_value" in patch or "sync_interval_unit" in patch:
                value, unit, _ = self.normalize_sync_interval(
                    patch.get("sync_interval_value", peer.get("sync_interval_value", 6)),
                    patch.get("sync_interval_unit", peer.get("sync_interval_unit", "hours")),
                )
                peer["sync_interval_value"] = value
                peer["sync_interval_unit"] = unit
            if "enabled" in patch:
                peer["enabled"] = bool(patch.get("enabled"))
            if "auto_sync" in patch or "sync_schedule" in patch or "sync_hour" in patch:
                self.apply_sync_schedule(
                    peer,
                    patch.get("auto_sync", peer.get("auto_sync", True)),
                    patch.get("sync_schedule", peer.get("sync_schedule") or "loop"),
                    patch.get("sync_hour", peer.get("sync_hour") or peer.get("sync_interval_value") or 6),
                )
            if "allowed_cidrs" in patch:
                peer["allowed_cidrs"] = self.normalize_cidrs(patch.get("allowed_cidrs"))
            peer["updated_at"] = time.time()
            self._write(data)
            return dict(peer)

    def update_invite(self, invite_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        invite_id = str(invite_id or "").strip()
        with self.lock:
            data = self._read()
            invite = data["invites"].get(invite_id)
            if not isinstance(invite, dict):
                raise KeyError("邀请码不存在")
            if "peer_name" in patch:
                invite["peer_name"] = self._safe_name(patch.get("peer_name"))
            if "allowed_cidrs" in patch:
                cidrs = self.normalize_cidrs(patch.get("allowed_cidrs"))
                if not cidrs:
                    raise ValueError("允许 IP/CIDR 不能为空")
                invite["allowed_cidrs"] = cidrs
            invite["updated_at"] = time.time()
            # Existing inbound peers follow the invitation scope immediately.
            for peer in data["peers"].values():
                if isinstance(peer, dict) and str(peer.get("invite_id") or "") == invite_id:
                    peer["name"] = invite["peer_name"]
                    peer["allowed_cidrs"] = list(invite["allowed_cidrs"])
                    if not invite.get("revoked"):
                        peer["enabled"] = True
            self._write(data)
        return {
            "ok": True,
            "invite": next(x for x in self.list_invites(include_revoked=True) if x["invite_id"] == invite_id),
        }

    def delete_peer(self, peer_id: str) -> dict[str, Any]:
        peer_id = str(peer_id or "").strip()
        with self.lock:
            data = self._read()
            peer = data["peers"].pop(peer_id, None)
            self._write(data)
        if not peer:
            raise KeyError("Peer 不存在")
        try:
            self.node_pool.remove_shared_peer(peer_id)
        except Exception as exc:
            self._log(f"删除 Peer 共享资源清理失败: {exc}")
        return {"ok": True, "peer_id": peer_id}

    def delete_relationship(self, peer_ids: list[str]) -> dict[str, Any]:
        ids = [str(x or "").strip() for x in peer_ids if str(x or "").strip()]
        deleted: list[str] = []
        for peer_id in ids:
            try:
                self.delete_peer(peer_id)
                deleted.append(peer_id)
            except KeyError:
                pass
        return {"ok": True, "peer_ids": deleted}
    def _invite_code(self, invite_id: str) -> str:
        with self.lock:
            invite = self._read()["invites"].get(str(invite_id))
            return str(invite.get("code") or "") if isinstance(invite, dict) else ""

    def relationships(self) -> list[dict[str, Any]]:
        peers = self.list_peers(include_tokens=False)
        groups: dict[str, list[dict[str, Any]]] = {}
        for peer in peers:
            remote_instance = str(peer.get("remote_instance_id") or peer.get("remote_peer_id") or "").strip()
            remote_url = str(peer.get("remote_url") or "").strip()
            source_ip = str(peer.get("source_ip") or "").strip()
            if remote_instance:
                key = "instance:" + remote_instance
            else:
                host = ""
                try:
                    host = str(urllib.parse.urlsplit(remote_url).hostname or "").strip().lower()
                except Exception:
                    pass
                key = "host:" + (host or source_ip or str(peer.get("peer_id")))
            groups.setdefault(key, []).append(peer)

        out: list[dict[str, Any]] = []
        now = time.time()
        for key, items in groups.items():
            inbound = next((p for p in items if p.get("direction") == "inbound"), None)
            outbound = next((p for p in items if p.get("direction") == "outbound"), None)
            direction = "双向共享" if inbound and outbound and inbound.get("enabled", True) and outbound.get("enabled", True) else "单向共享"
            primary = outbound or inbound or items[0]
            remote_url = str((outbound or {}).get("remote_url") or "")
            remote_ip = ""
            if remote_url:
                try:
                    remote_ip = str(urllib.parse.urlsplit(remote_url).hostname or "")
                except Exception:
                    remote_ip = ""
            remote_ip = remote_ip or str((inbound or {}).get("source_ip") or "")
            interval_value, interval_unit, interval_seconds = self.sync_interval_from_peer(outbound or primary)
            local_invite_code = self._invite_code(str((inbound or {}).get("invite_id") or ""))
            remote_invite_code = str((outbound or {}).get("remote_invite_code") or "")
            if outbound:
                if outbound.get("syncing"):
                    sync_status = "同步中"
                elif outbound.get("last_sync_ok") is True:
                    sync_status = "同步完成"
                elif outbound.get("last_sync_ok") is False:
                    sync_status = "同步失败"
                else:
                    sync_status = "待同步"
                next_sync = float(outbound.get("next_sync_at") or 0)
                if not next_sync:
                    last = float(outbound.get("last_sync_at") or 0)
                    next_sync = last + interval_seconds if last else now
            else:
                sync_status = "对方可拉取本机资源"
                next_sync = 0
            out.append({
                "relation_id": key,
                "name": str(primary.get("name") or "共享服务器"),
                "remote_ip": remote_ip,
                "remote_url": remote_url,
                "remote_instance_id": str(primary.get("remote_instance_id") or primary.get("remote_peer_id") or ""),
                "direction": direction,
                "peer_ids": [str(p.get("peer_id") or "") for p in items if p.get("peer_id")],
                "inbound_peer_id": str((inbound or {}).get("peer_id") or ""),
                "outbound_peer_id": str((outbound or {}).get("peer_id") or ""),
                "local_invite_id": str((inbound or {}).get("invite_id") or ""),
                "remote_invite_id": str((outbound or {}).get("remote_invite_id") or ""),
                "local_invite_code": local_invite_code,
                "remote_invite_code": remote_invite_code,
                "allowed_cidrs": list((inbound or {}).get("allowed_cidrs") or []),
                "sync_interval_value": interval_value,
                "sync_interval_unit": interval_unit,
                "sync_interval_seconds": interval_seconds if outbound else 0,
                "auto_sync": (outbound or primary).get("auto_sync", True) is not False,
                "sync_schedule": str((outbound or primary).get("sync_schedule") or "loop"),
                "sync_hour": int((outbound or primary).get("sync_hour") or interval_value or 6),
                "syncing": bool((outbound or {}).get("syncing")),
                "last_sync_count": int((outbound or {}).get("last_sync_count") or 0),
                "next_sync_at": next_sync,
                "sync_status": sync_status,
                "enabled": any(bool(p.get("enabled", True)) for p in items),
                "last_sync_at": float((outbound or {}).get("last_sync_at") or 0),
                "last_sync_error": str((outbound or {}).get("last_sync_error") or ""),
            })
        out.sort(key=lambda x: x["name"])
        return out

    def status(self) -> dict[str, Any]:
        invites = self.list_invites(include_revoked=True)
        peers = self.list_peers()
        return {
            "ok": True,
            "schema": 2,
            "instance_id": self.instance_id,
            "peer_count": len([p for p in peers if p.get("enabled", True)]),
            "invite_count": len([x for x in invites if not x.get("revoked")]),
            "invites": invites,
            "peers": peers,
            "relationships": self.relationships(),
        }

    @staticmethod
    def _sanitized_endpoint(endpoint: dict[str, Any]) -> dict[str, Any]:
        metadata = endpoint.get("metadata") or {}
        server_meta = endpoint.get("server_metadata") or {}
        source_ids = list(metadata.get("source_peer_ids") or [])
        if metadata.get("peer_id") and metadata.get("peer_id") not in source_ids:
            source_ids.append(str(metadata.get("peer_id")))
        return {
            "server_key": str(endpoint.get("server_key") or ""),
            "hostname": str(endpoint.get("hostname") or ""),
            "ip": str(endpoint.get("current_ip") or metadata.get("ip") or ""),
            "country": str(endpoint.get("country") or ""),
            "server": {
                "owner": str(server_meta.get("owner") or ""),
                "asn": str(server_meta.get("asn") or ""),
                "as_name": str(server_meta.get("as_name") or ""),
                "location": str(server_meta.get("location") or ""),
                "ip_type": str(server_meta.get("ip_type") or ""),
                "quality": str(server_meta.get("quality") or ""),
            },
            "protocol": str(endpoint.get("protocol") or "").lower(),
            "transport": str(endpoint.get("transport") or "").lower(),
            "port": int(endpoint.get("port") or 0),
            "status": str(endpoint.get("status") or "NEW"),
            "latency_ms": 0,
            "speed_bps": _shared_speed_bps(endpoint),
            "success_count": int(endpoint.get("success_count") or 0),
            "failure_count": int(endpoint.get("failure_count") or 0),
            "success_streak": int(endpoint.get("success_streak") or 0),
            "source_peer_ids": sorted({str(x) for x in source_ids if x}),
            "source_peer_count": max(len(source_ids), int(metadata.get("source_peer_count") or 0)),
            "first_seen": float(endpoint.get("first_seen") or 0),
            "last_seen": float(endpoint.get("last_seen") or 0),
            "last_success": float(endpoint.get("last_success") or 0),
        }

    def export_resources(self, exclude_peer_id: str = "", max_nodes: int = DEFAULT_MAX_NODES, offset: int = 0) -> dict[str, Any]:
        limit = min(2000, self._safe_max_nodes(max_nodes))
        offset = max(0, int(offset or 0))
        excluded_local_peer_ids: set[str] = set()
        if exclude_peer_id:
            with self.lock:
                for local_peer_id, peer in self._read()["peers"].items():
                    if str(local_peer_id) == str(exclude_peer_id) or str(peer.get("remote_peer_id") or "") == str(exclude_peer_id):
                        excluded_local_peer_ids.add(str(local_peer_id))
        endpoints = self.node_pool.list_share_endpoints(offset, limit)
        complete = len(endpoints) < limit
        next_offset = offset + len(endpoints)
        rows: list[dict[str, Any]] = []
        for endpoint in endpoints:
            metadata = endpoint.get("metadata") or {}
            source_ids = set(str(x) for x in (metadata.get("source_peer_ids") or []) if x)
            if metadata.get("peer_id"):
                source_ids.add(str(metadata.get("peer_id")))
            if excluded_local_peer_ids and source_ids.intersection(excluded_local_peer_ids):
                continue
            row = self._sanitized_endpoint(endpoint)
            if row["server_key"] and row["protocol"]:
                rows.append(row)
        return {
            "schema": 2,
            "instance_id": self.instance_id,
            "generated_at": time.time(),
            "count": len(rows),
            "offset": offset,
            "next_offset": next_offset,
            "complete": complete,
            "resources": rows,
        }
    def sync_peer(self, peer_id: str, timeout: int = 20, force: bool = False) -> dict[str, Any]:
        with self.lock:
            data = self._read()
            peer = data["peers"].get(str(peer_id))
            if not isinstance(peer, dict):
                raise KeyError("Peer 不存在")
            if not peer.get("enabled", True):
                raise RuntimeError("Peer 已暂停")
            remote_url = str(peer.get("remote_url") or "").strip()
            token = str(peer.get("outbound_token") or "")
            interval_value, interval_unit, interval_seconds = self.sync_interval_from_peer(peer)
            last_sync_at = float(peer.get("last_sync_at") or 0)

        if not remote_url or len(token) < 20:
            return {
                "ok": True,
                "skipped": True,
                "peer_id": str(peer_id),
                "reason": "inbound_only",
                "message": "当前关系由对方拉取本机资源，本机不需要执行拉取",
            }

        now = time.time()
        next_sync_at = (last_sync_at + interval_seconds) if last_sync_at else now
        if not force and not self.peer_sync_due(peer, now):
            return {
                "ok": True,
                "skipped": True,
                "peer_id": str(peer_id),
                "next_sync_at": now + 60,
                "sync_interval_value": interval_value,
                "sync_interval_unit": interval_unit,
            }

        query_base = {"exclude_peer_id": str(self.instance_id)}
        started = time.time()
        offset = 0
        page_size = 2000
        received = 0
        imported = 0
        remote_instance_id = ""
        try:
            while offset < 50000:
                query = dict(query_base)
                query["limit"] = str(page_size)
                query["offset"] = str(offset)
                url = remote_url + "/resources?" + urllib.parse.urlencode(query)
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "AimiliVPN-ResourceShare/2.0",
                        "Accept": "application/json",
                        "X-Aimili-Resource-Token": token,
                    },
                )
                with urllib.request.urlopen(req, timeout=max(5, min(int(timeout), 60))) as response:
                    raw = response.read()
                payload = json.loads(raw.decode("utf-8", errors="replace"))
                resources = payload.get("resources") if isinstance(payload, dict) else None
                if not isinstance(resources, list):
                    raise ValueError("远端返回的资源格式无效")
                remote_instance_id = str((payload or {}).get("instance_id") or remote_instance_id)
                resources = resources[: self.MAX_MAX_NODES]
                received += len(resources)
                imported += self.node_pool.upsert_shared_snapshot(
                    resources,
                    peer_id=str(peer_id),
                    source_name=str(peer.get("name") or "shared"),
                )
                if "complete" not in (payload or {}):
                    break
                if payload.get("complete"):
                    break
                try:
                    next_offset = int(payload.get("next_offset") or 0)
                except (TypeError, ValueError):
                    next_offset = 0
                if next_offset <= offset:
                    break
                offset = next_offset
            result = {
                "ok": True,
                "peer_id": str(peer_id),
                "remote_instance_id": remote_instance_id,
                "received": received,
                "imported": imported,
                "duration_ms": int((time.time() - started) * 1000),
                "sync_interval_value": interval_value,
                "sync_interval_unit": interval_unit,
            }
            self._mark_sync(peer_id, result, "")
            return result
        except Exception as exc:
            self._mark_sync(peer_id, {"ok": False, "imported": imported, "received": received}, str(exc))
            raise

    def _mark_sync(self, peer_id: str, result: dict[str, Any], error: str) -> None:
        with self.lock:
            data = self._read()
            peer = data["peers"].get(str(peer_id))
            if not isinstance(peer, dict):
                return
            peer["last_sync_at"] = time.time()
            peer["last_sync_ok"] = bool(result.get("ok"))
            peer["last_sync_error"] = str(error or "")
            peer["last_sync_count"] = int(result.get("imported") or result.get("received") or 0)
            peer["syncing"] = False
            self._write(data)

    def mark_syncing(self, peer_id: str, syncing: bool = True) -> None:
        with self.lock:
            data = self._read()
            peer = data["peers"].get(str(peer_id))
            if not isinstance(peer, dict):
                return
            peer["syncing"] = bool(syncing)
            self._write(data)

    @staticmethod
    def apply_sync_schedule(peer: dict[str, Any], auto_sync: Any, schedule: Any, hour: Any) -> None:
        allowed = {"loop", "daily", "mon", "tue", "wed", "thu", "fri", "sat", "sun"}
        mode = str(schedule or "loop").strip().lower()
        if mode not in allowed:
            mode = "loop"
        try:
            amount = int(hour)
        except (TypeError, ValueError):
            amount = 6
        amount = max(1, min(24, amount))
        peer["auto_sync"] = bool(auto_sync)
        peer["sync_schedule"] = mode
        peer["sync_hour"] = amount
        if mode == "loop":
            peer["sync_interval_value"] = amount
            peer["sync_interval_unit"] = "hours"
        elif mode == "daily":
            peer["sync_interval_value"] = 1
            peer["sync_interval_unit"] = "days"
        else:
            peer["sync_interval_value"] = 1
            peer["sync_interval_unit"] = "weeks"

    def peer_sync_due(self, peer: dict[str, Any], now: float | None = None) -> bool:
        now = time.time() if now is None else float(now)
        if peer.get("auto_sync") is False:
            return False
        last = float(peer.get("last_sync_at") or 0)
        schedule = str(peer.get("sync_schedule") or "")
        if not schedule:
            _, _, seconds = self.sync_interval_from_peer(peer)
            return (not last) or now >= last + seconds
        try:
            hour = int(peer.get("sync_hour") or 6)
        except (TypeError, ValueError):
            hour = 6
        hour = max(1, min(24, hour))
        if schedule == "loop":
            return (not last) or now >= last + hour * 3600
        weekdays = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
        if schedule != "daily" and schedule not in weekdays:
            return (not last) or now >= last + 6 * 3600
        current = time.localtime(now)
        if schedule in weekdays and current.tm_wday != weekdays[schedule]:
            return False
        clock = 0 if hour >= 24 else hour
        if current.tm_hour < clock:
            return False
        if not last:
            return True
        previous = time.localtime(last)
        return not (previous.tm_year == current.tm_year and previous.tm_yday == current.tm_yday)

    def sync_all(self, force: bool = False) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for peer in self.list_peers(include_tokens=True):
            if not peer.get("enabled", True):
                continue
            try:
                results.append(self.sync_peer(str(peer.get("peer_id") or ""), force=force))
            except Exception as exc:
                results.append({
                    "ok": False,
                    "peer_id": peer.get("peer_id"),
                    "error": str(exc),
                })
        return results
    def _remote_enroll(
        self,
        remote_url: str,
        invite_code: str,
        existing_peer_id: str = "",
        name: str = "",
    ) -> dict[str, Any]:
        payload = {
            "invite_code": str(invite_code or "").strip(),
            "peer_id": self.instance_id,
            "existing_peer_id": str(existing_peer_id or ""),
            "name": self._safe_name(name, "共享服务器"),
            "sync_mode": "pull",
        }
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            remote_url + "/enroll",
            data=body,
            headers={
                "User-Agent": "AimiliVPN-ResourceShare/2.0",
                "Accept": "application/json",
                "Content-Type": "application/json; charset=utf-8",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                result = json.loads(response.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            raise RuntimeError(f"连接远端资源服务器失败: {exc}") from exc
        if not isinstance(result, dict) or not result.get("ok"):
            raise RuntimeError(str(result.get("error") if isinstance(result, dict) else "远端入网失败"))
        return result

    def join_remote(
        self,
        remote_url: str,
        invite_code: str,
        name: str = "",
        sync_interval_value: Any = DEFAULT_SYNC_INTERVAL_VALUE,
        sync_interval_unit: Any = DEFAULT_SYNC_INTERVAL_UNIT,
        existing_peer_id: str = "",
        auto_sync: Any = True,
        sync_schedule: str = "loop",
        sync_hour: Any = None,
    ) -> dict[str, Any]:
        remote_url = self.normalize_remote_input(remote_url)
        invite_code = str(invite_code or "").strip()
        if not invite_code:
            raise ValueError("邀请码不能为空")
        interval_value, interval_unit, interval_seconds = self.normalize_sync_interval(
            sync_interval_value, sync_interval_unit
        )
        result = self._remote_enroll(
            remote_url=remote_url,
            invite_code=invite_code,
            existing_peer_id=existing_peer_id,
            name=name,
        )
        remote_peer_id = str(result.get("peer_id") or "")
        remote_instance_id = str(result.get("instance_id") or "")
        remote_token = str(result.get("inbound_token") or "")
        if len(remote_token) < 20 or not remote_peer_id:
            raise RuntimeError("远端返回的共享身份信息不完整")
        peer_id = self.add_joined_peer(
            remote_url=remote_url,
            remote_peer_id=remote_peer_id,
            remote_instance_id=remote_instance_id,
            name=str(result.get("peer_name") or name or "共享服务器"),
            remote_token=remote_token,
            max_nodes=self.MAX_MAX_NODES,
            sync_interval_value=interval_value,
            sync_interval_unit=interval_unit,
            remote_invite_id=str(result.get("invite_id") or ""),
            remote_invite_code=invite_code,
            auto_sync=auto_sync,
            sync_schedule=sync_schedule,
            sync_hour=sync_hour if sync_hour is not None else interval_value,
        )
        return {
            "ok": True,
            "peer_id": peer_id,
            "remote_peer_id": remote_peer_id,
            "remote_instance_id": remote_instance_id,
            "remote_url": remote_url,
            "resource_url": result.get("resource_url") or remote_url + "/resources",
            "sync_interval_value": interval_value,
            "sync_interval_unit": interval_unit,
            "sync_interval_seconds": interval_seconds,
            "peer_name": str(result.get("peer_name") or name or "共享服务器"),
            "remote_invite_id": str(result.get("invite_id") or ""),
        }

    def update_joined_peer(
        self,
        peer_id: str,
        remote_url: str,
        invite_code: str,
        name: str = "",
        sync_interval_value: Any = DEFAULT_SYNC_INTERVAL_VALUE,
        sync_interval_unit: Any = DEFAULT_SYNC_INTERVAL_UNIT,
        auto_sync: Any = None,
        sync_schedule: str = "",
        sync_hour: Any = None,
    ) -> dict[str, Any]:
        peer = self.get_peer(peer_id)
        if not peer:
            raise KeyError("Peer 不存在")
        if str(peer.get("direction") or "") != "outbound":
            # An inbound-only relation is controlled by its local invitation.
            return self.update_peer(peer_id, {
                "name": name,
                "sync_interval_value": sync_interval_value,
                "sync_interval_unit": sync_interval_unit,
                "auto_sync": peer.get("auto_sync", True) if auto_sync is None else auto_sync,
                "sync_schedule": sync_schedule or peer.get("sync_schedule") or "loop",
                "sync_hour": peer.get("sync_hour") or sync_interval_value if sync_hour is None else sync_hour,
            })
        normalized = self.normalize_remote_input(remote_url)
        invite_code = str(invite_code or "").strip()
        if not invite_code:
            raise ValueError("修改已建立共享服务器时必须填写邀请码")
        result = self._remote_enroll(
            remote_url=normalized,
            invite_code=invite_code,
            existing_peer_id=str(peer.get("remote_peer_id") or ""),
            name=name or str(peer.get("name") or "共享服务器"),
        )
        remote_token = str(result.get("inbound_token") or "")
        if len(remote_token) < 20:
            raise RuntimeError("远端没有返回新的访问令牌")
        value, unit, _ = self.normalize_sync_interval(sync_interval_value, sync_interval_unit)
        with self.lock:
            data = self._read()
            local = data["peers"].get(str(peer_id))
            if not isinstance(local, dict):
                raise KeyError("Peer 不存在")
            local.update({
                "name": self._safe_name(result.get("peer_name") or name or local.get("name")),
                "remote_url": normalized,
                "remote_port": int(urllib.parse.urlsplit(normalized).port or 8443),
                "remote_peer_id": str(result.get("peer_id") or local.get("remote_peer_id") or ""),
                "remote_instance_id": str(result.get("instance_id") or local.get("remote_instance_id") or ""),
                "outbound_token": remote_token,
                "remote_invite_id": str(result.get("invite_id") or ""),
                "remote_invite_code": invite_code,
                "sync_interval_value": value,
                "sync_interval_unit": unit,
                "updated_at": time.time(),
            })
            self.apply_sync_schedule(
                local,
                local.get("auto_sync", True) if auto_sync is None else auto_sync,
                sync_schedule or local.get("sync_schedule") or "loop",
                local.get("sync_hour") or value if sync_hour is None else sync_hour,
            )
            self._write(data)
        return {"ok": True, "peer": self.get_peer(peer_id)}

    def ping(self, headers: Any, client_address: Any) -> dict[str, Any]:
        peer_id, peer = self.authorize(headers, client_address)
        return {
            "ok": True,
            "instance_id": self.instance_id,
            "peer_id": peer_id,
            "name": peer.get("name") or "",
            "server_time": time.time(),
        }