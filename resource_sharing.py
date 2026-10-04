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
    def client_ip(headers: Any, client_address: Any) -> str:
        values: list[str] = []
        try:
            values.append(str(headers.get("X-Real-IP") or "").strip())
            forwarded = str(headers.get("X-Forwarded-For") or "").strip()
            if forwarded:
                values.extend(x.strip() for x in forwarded.split(","))
        except Exception:
            pass
        try:
            values.append(str(client_address[0] if client_address else "").strip())
        except Exception:
            pass
        for value in values:
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                continue
        return ""

    @staticmethod
    def _cidr_allowed(source_ip: str, cidrs: list[str]) -> bool:
        if not source_ip or not cidrs:
            return False
        try:
            addr = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(raw, strict=False) for raw in cidrs)
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

    def delete_invite(self, invite_id: str) -> dict[str, Any]:
        invite_id = str(invite_id or "").strip()
        if not invite_id:
            raise ValueError("invite_id 不能为空")
        with self.lock:
            data = self._read()
            invite = data["invites"].get(invite_id)
            if not isinstance(invite, dict):
                raise KeyError("邀请码不存在")
            # Permanent deletion is an explicit destructive action. If the
            # invite is still active, revoke it atomically first so the link
            # cannot authorize any new enrollment during deletion.
            if not invite.get("revoked"):
                invite["revoked"] = True
                invite["revoked_at"] = time.time()
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
                if not self._cidr_allowed(source_ip, cidrs):
                    continue
                return str(invite_id), dict(invite)
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
                if not self._cidr_allowed(source_ip, list(peer.get("allowed_cidrs") or [])):
                    continue
                return str(peer_id), dict(peer)
        return None

    def authorize(self, headers: Any, client_address: Any) -> tuple[str, dict[str, Any]]:
        token = str(headers.get("X-Aimili-Resource-Token") or "").strip()
        if len(token) < 20:
            raise PermissionError("资源共享访问令牌无效")
        source_ip = self.client_ip(headers, client_address)
        matched = self._find_peer_by_token(token, source_ip)
        if not matched:
            raise PermissionError("资源共享身份验证失败或来源 IP 未获允许")
        return matched
    def enroll(self, payload: dict[str, Any], source_ip: str) -> dict[str, Any]:
        code = str(payload.get("invite_code") or "").strip()
        if not code:
            raise PermissionError("邀请码不能为空")
        found = self._find_invite(code, source_ip)
        if not found:
            raise PermissionError("邀请码无效、已撤销，或来源 IP 不在授权范围内")
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
                "source_ip": source_ip,
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
            })
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
                sync_status = "已同步" if outbound.get("last_sync_ok") is True else ("同步失败" if outbound.get("last_sync_ok") is False else "待同步")
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
            "latency_ms": int(float(endpoint.get("latency_ewma") or endpoint.get("latest_ping") or 0)),
            "success_count": int(endpoint.get("success_count") or 0),
            "failure_count": int(endpoint.get("failure_count") or 0),
            "success_streak": int(endpoint.get("success_streak") or 0),
            "source_peer_ids": sorted({str(x) for x in source_ids if x}),
            "source_peer_count": max(len(source_ids), int(metadata.get("source_peer_count") or 0)),
            "first_seen": float(endpoint.get("first_seen") or 0),
            "last_seen": float(endpoint.get("last_seen") or 0),
            "last_success": float(endpoint.get("last_success") or 0),
        }

    def export_resources(self, exclude_peer_id: str = "", max_nodes: int = DEFAULT_MAX_NODES) -> dict[str, Any]:
        limit = self._safe_max_nodes(max_nodes)
        excluded_local_peer_ids: set[str] = set()
        if exclude_peer_id:
            with self.lock:
                for local_peer_id, peer in self._read()["peers"].items():
                    if str(local_peer_id) == str(exclude_peer_id) or str(peer.get("remote_peer_id") or "") == str(exclude_peer_id):
                        excluded_local_peer_ids.add(str(local_peer_id))
        endpoints = self.node_pool.list_endpoints(limit=min(self.MAX_MAX_NODES, limit))
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
            if len(rows) >= limit:
                break
        return {
            "schema": 2,
            "instance_id": self.instance_id,
            "generated_at": time.time(),
            "count": len(rows),
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
        if not force and last_sync_at and now < next_sync_at:
            return {
                "ok": True,
                "skipped": True,
                "peer_id": str(peer_id),
                "next_sync_at": next_sync_at,
                "sync_interval_value": interval_value,
                "sync_interval_unit": interval_unit,
            }

        query = urllib.parse.urlencode({"exclude_peer_id": str(self.instance_id)})
        url = remote_url + "/resources?" + query
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "AimiliVPN-ResourceShare/2.0",
                "Accept": "application/json",
                "X-Aimili-Resource-Token": token,
            },
        )
        started = time.time()
        try:
            with urllib.request.urlopen(req, timeout=max(5, min(int(timeout), 60))) as response:
                raw = response.read()
            payload = json.loads(raw.decode("utf-8", errors="replace"))
            resources = payload.get("resources") if isinstance(payload, dict) else None
            if not isinstance(resources, list):
                raise ValueError("远端返回的资源格式无效")
            resources = resources[: self.MAX_MAX_NODES]
            imported = self.node_pool.upsert_shared_snapshot(
                resources,
                peer_id=str(peer_id),
                source_name=str(peer.get("name") or "shared"),
            )
            result = {
                "ok": True,
                "peer_id": str(peer_id),
                "remote_instance_id": payload.get("instance_id", ""),
                "received": len(resources),
                "imported": imported,
                "duration_ms": int((time.time() - started) * 1000),
                "sync_interval_value": interval_value,
                "sync_interval_unit": interval_unit,
            }
            self._mark_sync(peer_id, result, "")
            return result
        except Exception as exc:
            self._mark_sync(peer_id, {"ok": False}, str(exc))
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
            self._write(data)

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