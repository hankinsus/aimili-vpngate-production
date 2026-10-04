[Reading 1000 lines from start (total: 14333 lines, 13333 remaining)]

#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import ipaddress
import json
import os
import queue
import re
import select
import shlex
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid
import gzip
from ui_control_plane import ui_command_plane

# Prefer IPv4 resolution to avoid slow AAAA DNS timeouts (e.g. in WSL),
# but fall back to system default (IPv6) if IPv4 resolution fails.
# This ensures pure-IPv6 VPS (with NAT64/clatd) can still function.
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        if isinstance(host, str) and ":" in host:
            return _orig_getaddrinfo(host, port, socket.AF_INET6, type, proto, flags)
        # Try IPv4 first for speed; fall back to system default (allows IPv6/NAT64)
        try:
            results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if results:
                return results
        except socket.gaierror:
            pass
        return _orig_getaddrinfo(host, port, 0, type, proto, flags)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if ":" in host or host == "":
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET

        try:
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host in ("::", "") else "127.0.0.1"
                print(f"[警告] 绑定 Web 管理后台 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 {fallback_host} ...", flush=True)
                # 关闭第一次失败时可能已创建的 socket
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.address_family = socket.AF_INET
                super().__init__((fallback_host, port), RequestHandlerClass, bind_and_activate)
            else:
                raise e

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

import vpn_utils
import proxy_server
from node_pool import NodePool
import tunnel_adapters
import vpngate_discovery
from resource_sharing import ResourceShareManager
from web_certificate import WebCertificateManager

def env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        print(f"[配置警告] 环境变量 {name}={raw!r} 不是有效整数，使用默认值 {default}", flush=True)
        value = default
    if min_value is not None and value < min_value:
        print(f"[配置警告] 环境变量 {name}={value} 小于允许值 {min_value}，使用默认值 {default}", flush=True)
        return default
    if max_value is not None and value > max_value:
        print(f"[配置警告] 环境变量 {name}={value} 大于允许值 {max_value}，使用默认值 {default}", flush=True)
        return default
    return value

def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on", "enabled")

def bounded_int(value: Any, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if min_value is not None and parsed < min_value:
        return default
    if max_value is not None and parsed > max_value:
        return default
    return parsed

API_URL = "https://www.vpngate.net/api/iphone/"
FETCH_INTERVAL_SECONDS = env_int("FETCH_INTERVAL_SECONDS", 1260, 1)
CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL_SECONDS", 1260, 1)
TARGET_VALID_NODES = env_int("TARGET_VALID_NODES", 3, 1)
MAX_SCAN_ROWS = env_int("MAX_SCAN_ROWS", 5000, 1)
OPENVPN_TEST_TIMEOUT_SECONDS = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 35, 1)
MANUAL_TEST_NODE_LIMIT = env_int("MANUAL_TEST_NODE_LIMIT", 5, 1, 20)
COUNTRY_INVENTORY_TARGET = env_int("COUNTRY_INVENTORY_TARGET", 20, 5, 100)
COUNTRY_AVAILABLE_MIN = env_int("COUNTRY_AVAILABLE_MIN", 5, 1, 10)
COUNTRY_AVAILABLE_TARGET = env_int("COUNTRY_AVAILABLE_TARGET", 10, 5, 10)
COUNTRY_PRIORITY_BATCH = env_int("COUNTRY_PRIORITY_BATCH", 5, 1, 10)
INITIAL_CONNECT_TEST_LIMIT = env_int("INITIAL_CONNECT_TEST_LIMIT", 10, 1, 50)
BACKGROUND_PROBE_BATCH = env_int("BACKGROUND_PROBE_BATCH", 24, 5, 100)
ACTIVE_BACKGROUND_PROBE_BATCH = env_int("ACTIVE_BACKGROUND_PROBE_BATCH", 6, 1, 30)
PROTOCOL_PROBE_BATCH = env_int("PROTOCOL_PROBE_BATCH", 5, 1, 20)
PROTOCOL_PROBE_INTERVAL_SECONDS = env_int("PROTOCOL_PROBE_INTERVAL_SECONDS", 300, 60, 3600)
# Scheduler tick only. Actual Peer synchronization uses each Peer’s hour/day/week interval.
RESOURCE_SHARE_SYNC_INTERVAL_SECONDS = env_int("RESOURCE_SHARE_SYNC_INTERVAL_SECONDS", 300, 60, 3600)
PROXY_HEALTH_INTERVAL_SECONDS = env_int("PROXY_HEALTH_INTERVAL_SECONDS", 15, 5, 120)
PROXY_HEALTH_CONFIRM_DELAY_SECONDS = env_int("PROXY_HEALTH_CONFIRM_DELAY_SECONDS", 2, 1, 10)
HOT_POOL_TARGET = env_int("HOT_POOL_TARGET", 8, 5, 10)
LINK_PROBE_MAX_BYTES = env_int("LINK_PROBE_MAX_BYTES", 1048576, 65536, 4194304)
LINK_PROBE_WINDOW_BYTES = env_int("LINK_PROBE_WINDOW_BYTES", 4194304, 262144, 16777216)
LINK_PROBE_WINDOW_SECONDS = env_int("LINK_PROBE_WINDOW_SECONDS", 60, 10, 300)
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
# Public ports: 8443 HTTPS management, 8500 HTTP/SOCKS5 proxy, 18443 HTTPS subscriptions.
# The manager UI itself stays on a private loopback listener and is exposed only by Nginx on 8443.
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "0.0.0.0")
LOCAL_PROXY_PORT = 8500
UI_HOST = os.environ.get("UI_HOST", "127.0.0.1")
UI_PORT = 8501
ACTIVE_ROUTE_TABLE = env_int("ACTIVE_ROUTE_TABLE", 100, 1, 252)
ISOLATED_INSTANCE = env_flag("ISOLATED_INSTANCE", False)
DISABLE_BACKGROUND_LOOPS = env_flag("DISABLE_BACKGROUND_LOOPS", False)
ENABLE_COLLECTOR_LOOP = env_flag("ENABLE_COLLECTOR_LOOP", not DISABLE_BACKGROUND_LOOPS)
ENABLE_PROXY_HEALTH_LOOP = env_flag("ENABLE_PROXY_HEALTH_LOOP", not DISABLE_BACKGROUND_LOOPS)
ENABLE_FAST_LIVENESS_LOOP = env_flag("ENABLE_FAST_LIVENESS_LOOP", not DISABLE_BACKGROUND_LOOPS)
FAST_LIVENESS_INTERVAL_SECONDS = env_int("FAST_LIVENESS_INTERVAL_SECONDS", 2, 1, 10)
ENABLE_PINGER_LOOP = env_flag("ENABLE_PINGER_LOOP", not DISABLE_BACKGROUND_LOOPS)
ENABLE_PROTOCOL_PROBE_LOOP = env_flag("ENABLE_PROTOCOL_PROBE_LOOP", not DISABLE_BACKGROUND_LOOPS)
INVALID_BACKOFF_SECONDS = env_int("INVALID_BACKOFF_SECONDS", 30 * 60, 1)

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
APP_VERSION = "V1.0.7"
GITHUB_REPOSITORY = "hankinsus/aimili-vpngate-production"
GITHUB_BRANCH = "main"
GITHUB_API_COMMIT_URL = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/commits/{GITHUB_BRANCH}"

def _version_label(commit_sha: str | None = None) -> str:
    commit = str(commit_sha or "").strip().lower()
    return f"{APP_VERSION} · {commit[:8]}" if commit else APP_VERSION
GITHUB_UPDATE_TIMEOUT_SECONDS = 8
github_update_lock = threading.Lock()
github_update_running = False
github_update_last_result: dict[str, Any] = {}

DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
BOOTSTRAP_STATE_FILE = DATA_DIR / "bootstrap_state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
SESSION_FILE = DATA_DIR / "ui_sessions.json"
SESSION_TTL_SECONDS = 30 * 24 * 3600
UPSTREAM_PROXY_AUTH_FILE = DATA_DIR / "upstream_proxy_auth.txt"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"
NODE_POOL_DB = DATA_DIR / "node_pool.sqlite3"
node_pool = NodePool(NODE_POOL_DB)
l2tp_adapter = tunnel_adapters.L2TPIPsecAdapter()

lock = threading.RLock()
maintenance_lock = threading.Lock()
active_sessions: dict[str, float] = {}
_sessions_loaded: bool = False
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
active_external_tunnel: tunnel_adapters.TunnelResult | None = None
active_pool_endpoint_id = ""
protocol_discovery_lock = threading.Lock()
protocol_probe_lock = threading.BoundedSemaphore(4)
probe_route_table_lock = threading.Lock()
probe_route_tables_free: set[int] = set(range(201,221))
country_priority_lock = threading.Lock()
global_pool_refresh_lock = threading.Lock()
global_country_coverage_lock = threading.Lock()
country_priority_request = ""
country_priority_last_discovery: dict[str, float] = {}
failover_lock = threading.Lock()
link_probe_lock = threading.Lock()
link_probe_usage: dict[str, tuple[float, int]] = {}
last_protocol_discovery_at = 0.0
global_pool_refresh_running = False
global_pool_refresh_last_at = 0.0
global_pool_refresh_status = "idle"
global_pool_refresh_message = ""
global_pool_refresh_servers = 0
global_pool_refresh_sources = 0
global_country_coverage_last_attempt: dict[str, float] = {}
is_connecting = False
# Separate manual connection ownership from background node detection.
# Manual switching is allowed while a background detection/refresh is running,
# but two manual connection operations can never overlap.
manual_connection_lock = threading.RLock()
manual_connection_active = False
manual_connection_epoch = 0
manual_connection_quiet_until = 0.0
manual_route_pin: dict[str, Any] = {}
connection_generation = 0
active_connection_generation = 0
manual_add_probe_lock = threading.Lock()
last_active_ping_time = 0.0
last_active_latency = 0

last_collector_heartbeat = 0.0
last_checker_heartbeat = 0.0
last_pinger_heartbeat = 0.0
global_country_coverage_heartbeat = 0.0
server_start_time = time.time()

def _local_git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        value = result.stdout.strip()
        return value if re.fullmatch(r"[0-9a-f]{40}", value) else ""
    except Exception:
        return ""


def _remote_git_commit() -> str:
    # Prefer the Git remote ref over the GitHub REST API. The API can be
    # temporarily stale, which could otherwise make a newer production
    # checkout look like it needs a downgrade.
    try:
        result = subprocess.run(
            ["git", "ls-remote", "origin", f"refs/heads/{GITHUB_BRANCH}"],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            timeout=GITHUB_UPDATE_TIMEOUT_SECONDS,
            check=False,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == f"refs/heads/{GITHUB_BRANCH}":
                    value = parts[0].strip().lower()
                    if re.fullmatch(r"[0-9a-f]{40}", value):
                        return value
    except Exception:
        pass

    request = urllib.request.Request(
        GITHUB_API_COMMIT_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "AimiliVPN-Updater",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=GITHUB_UPDATE_TIMEOUT_SECONDS) as response:
        data = json.loads(response.read().decode("utf-8"))
    value = str(data.get("sha") or "").strip().lower()
    return value if re.fullmatch(r"[0-9a-f]{40}", value) else ""


def current_github_version() -> dict[str, Any]:
    local = _local_git_commit()
    return {
        "ok": bool(local),
        "repository": GITHUB_REPOSITORY,
        "branch": GITHUB_BRANCH,
        "current_version": _version_label(local) if local else "未知",
        "current_commit": local,
        "source": "git",
    }


def check_github_update() -> dict[str, Any]:
    local = _local_git_commit()
    if not local:
        return {
            "ok": False,
            "error": "当前安装目录不是有效 Git 仓库，无法检查正式版更新。",
            "repository": GITHUB_REPOSITORY,
            "branch": GITHUB_BRANCH,
        }

    try:
        remote = _remote_git_commit()
    except Exception as exc:
        return {
            "ok": False,
            "error": f"无法访问 GitHub 正式版：{exc}",
            "repository": GITHUB_REPOSITORY,
            "branch": GITHUB_BRANCH,
            "current_version": _version_label(local),
        }

    if not remote:
        return {
            "ok": False,
            "error": "GitHub 未返回有效的 main 分支版本。",
            "repository": GITHUB_REPOSITORY,
            "branch": GITHUB_BRANCH,
            "current_version": _version_label(local),
        }

    local_only = 0
    remote_only = 0
    relation = "different"
    try:
        fetched = subprocess.run(
            ["git", "fetch", "--quiet", "--prune", "origin", GITHUB_BRANCH],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            timeout=GITHUB_UPDATE_TIMEOUT_SECONDS,
            check=False,
        )
        if fetched.returncode == 0:
            compare = subprocess.run(
                ["git", "rev-list", "--left-right", "--count", f"{local}...origin/{GITHUB_BRANCH}"],
                cwd=str(ROOT_DIR),
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if compare.returncode == 0:
                fields = compare.stdout.strip().split()
                if len(fields) == 2:
                    local_only, remote_only = int(fields[0]), int(fields[1])
                    if local_only == 0 and remote_only == 0:
                        relation = "same"
                    elif local_only == 0 and remote_only > 0:
                        relation = "remote_ahead"
                    elif local_only > 0 and remote_only == 0:
                        relation = "local_ahead"
                    else:
                        relation = "diverged"
    except Exception:
        pass

    has_update = relation == "remote_ahead"
    result = {
        "ok": True,
        "repository": GITHUB_REPOSITORY,
        "branch": GITHUB_BRANCH,
        "current_version": _version_label(local),
        "current_commit": local,
        "latest_version": _version_label(remote),
        "latest_commit": remote,
        "has_update": has_update,
        "relation": relation,
        "checked_at": time.time(),
    }
    if relation == "local_ahead":
        result["message"] = "当前服务器版本高于 GitHub 正式版，不执行降级更新。"
    elif relation == "diverged":
        result["ok"] = False
        result["error"] = "当前服务器与 GitHub 正式版 main 已分叉，为避免误覆盖本地版本，暂不自动更新。"
    elif relation == "different":
        result["message"] = "已获取 GitHub 远端版本，但暂时无法确认提交关系；为避免误降级，不执行自动更新。"
    return result


def start_github_update() -> dict[str, Any]:
    global github_update_running, github_update_last_result
    with github_update_lock:
        if github_update_running:
            return {"ok": False, "error": "正在更新正式版，请稍候。", "running": True}

        check = check_github_update()
        if not check.get("ok"):
            return check
        if not check.get("has_update"):
            status = str(check.get("relation") or "latest")
            message = str(check.get("message") or "当前已经是 GitHub 正式版最新版本。")
            github_update_last_result = {
                "ok": True,
                "status": status,
                "current_version": check.get("current_version"),
                "latest_version": check.get("latest_version"),
                "checked_at": time.time(),
            }
            return {
                "ok": True,
                "status": status,
                "message": message,
                "current_version": check.get("current_version"),
                "latest_version": check.get("latest_version"),
            }

        github_update_running = True
        github_update_last_result = {
            "ok": True,
            "status": "starting",
            "from_version": check.get("current_version"),
            "to_version": check.get("latest_version"),
            "started_at": time.time(),
        }

        log_path = DATA_DIR / "github_update.log"
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        log_handle = open(log_path, "a", encoding="utf-8")
        script = (
            "set -e\n"
            f"cd {shlex.quote(str(ROOT_DIR))}\n"
            f"echo '[GitHub Update] started at '$(date -Is)\n"
            f"git fetch --prune origin {shlex.quote(GITHUB_BRANCH)}\n"
            f"git checkout {shlex.quote(GITHUB_BRANCH)}\n"
            f"git reset --hard origin/{shlex.quote(GITHUB_BRANCH)}\n"
            "find . -type d -name __pycache__ -prune -exec rm -rf {} +\n"
            "python3 -m py_compile vpngate_manager.py proxy_server.py vpn_utils.py node_pool.py tunnel_adapters.py vpngate_discovery.py\n"
            "echo '[GitHub Update] build check passed at '$(date -Is)\n"
            "systemctl restart aimilivpn\n"
        )
        try:
            systemd_run = shutil.which("systemd-run")
            if systemd_run:
                unit_name = f"aimilivpn-github-update-{int(time.time())}"
                subprocess.Popen([
                    systemd_run,
                    "--quiet",
                    "--unit", unit_name,
                    "--collect",
                    "/bin/bash",
                    "-lc",
                    script,
                ], cwd=str(ROOT_DIR), stdout=log_handle, stderr=log_handle, start_new_session=True)
            else:
                subprocess.Popen(["/bin/bash", "-lc", script], cwd=str(ROOT_DIR), stdout=log_handle, stderr=log_handle, start_new_session=True)
            threading.Timer(20.0, _clear_github_update_running).start()
        except Exception:
            log_handle.close()
            github_update_running = False
            raise
        return {
            "ok": True,
            "status": "starting",
            "message": f"已发现新版本 {check.get('latest_version')}，正在从 GitHub 更新并重启服务。",
            "current_version": check.get("current_version"),
            "latest_version": check.get("latest_version"),
        }


def _clear_github_update_running() -> None:
    global github_update_running
    github_update_running = False

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def upstream_proxy_auth_file() -> str | None:
    username, password = vpn_utils.get_upstream_proxy_auth()
    if username is None:
        return None
    try:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        UPSTREAM_PROXY_AUTH_FILE.write_text(f"{username}\n{password or ''}\n", encoding="utf-8")
        try:
            UPSTREAM_PROXY_AUTH_FILE.chmod(0o600)
        except OSError:
            pass
        return str(UPSTREAM_PROXY_AUTH_FILE)
    except Exception as exc:
        print(f"[上游代理认证] 写入认证文件失败: {exc}", flush=True)
        return None

def write_json(path: Path, data: Any) -> None:
    with lock:
        # The persistent node catalog is never allowed to regress from a
        # populated snapshot to [] because a collector/probe produced a
        # transient empty result. Only the explicit first-install state may
        # create an empty node file.
        if path == NODES_FILE and isinstance(data, list) and not data and path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(existing, list) and existing:
                    log_to_json("WARNING", "Main", "拒绝用临时空节点快照覆盖已有节点库")
                    return
            except Exception:
                pass
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

import hashlib
import random

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": "127.0.0.1",
            "port": UI_PORT,
            "proxy_port": env_int("LOCAL_PROXY_PORT", 8500, 1, 65535),
            "routing_mode": "auto",
            "force_country": "",
            "routing_ip_type": "all",
            "connection_enabled": True,
            "fixed_node_id": "",
            "favorite_node_ids": [],
            "fav_fail_fallback": True,
            "web_domain": ""
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                for key in ["host", "port", "proxy_port", "routing_mode", "force_country", "routing_ip_type", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback", "web_domain"]:
                    if key not in data:
                        updated = True
            except Exception:
                pass

        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True

        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True

        if config.get("fav_fail_fallback") is not True:
            config["fav_fail_fallback"] = True
            updated = True

        if not ISOLATED_INSTANCE:
            if config.get("host") != "127.0.0.1":
                config["host"] = "127.0.0.1"
                updated = True
            if config.get("port") != 8501:
                config["port"] = 8501
                updated = True

        normalized_port = bounded_int(config.get("port"), UI_PORT, 1, 65535)
        if normalized_port != config.get("port"):
            config["port"] = normalized_port
            updated = True

        normalized_proxy_port = env_int("LOCAL_PROXY_PORT", 8500, 1, 65535)
        if normalized_proxy_port != config.get("proxy_port"):
            config["proxy_port"] = normalized_proxy_port
            updated = True

        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                write_json(auth_file, config)
            except Exception:
                pass

        return config

# 初始化时优先从 ui_auth.json 加载保存的代理出站端口和网页端口配置以覆盖环境变量
try:
    _init_cfg = load_ui_config()
    if "proxy_port" in _init_cfg:
        LOCAL_PROXY_PORT = bounded_int(_init_cfg["proxy_port"], LOCAL_PROXY_PORT, 1, 65535)
    if "port" in _init_cfg:
        UI_PORT = bounded_int(_init_cfg["port"], 8501, 1, 65535)
    if "host" in _init_cfg:
        UI_HOST = "127.0.0.1"
    if not ISOLATED_INSTANCE:
        UI_HOST = "127.0.0.1"
        UI_PORT = 8501
        LOCAL_PROXY_HOST = "0.0.0.0"
        LOCAL_PROXY_PORT = 8500
except Exception:
    pass

def _load_persisted_sessions() -> None:
    global _sessions_loaded
    with lock:
        if _sessions_loaded:
            return
        raw = read_json(SESSION_FILE, {})
        now = time.time()
        if isinstance(raw, dict):
            for token, expiry in raw.items():
                if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token):
                    continue
                try:
                    exp = float(expiry)
                except (TypeError, ValueError):
                    continue
                if exp > now:
                    active_sessions[token] = exp
        _sessions_loaded = True


def _persist_sessions() -> None:
    with lock:
        now = time.time()
        snapshot = {}
        for token, expiry in active_sessions.items():
            try:
                exp = float(expiry)
            except (TypeError, ValueError):
                continue
            if exp > now and re.fullmatch(r"[0-9a-f]{32}", str(token)):
                snapshot[str(token)] = exp
        write_json(SESSION_FILE, snapshot)
        try:
            SESSION_FILE.chmod(0o600)
        except OSError:
            pass


def _create_session() -> str:
    _load_persisted_sessions()
    token = uuid.uuid4().hex
    with lock:
        active_sessions[token] = time.time() + SESSION_TTL_SECONDS
    _persist_sessions()
    return token


def _remove_session(token: str) -> None:
    _load_persisted_sessions()
    with lock:
        active_sessions.pop(token, None)
    _persist_sessions()


def clear_persisted_sessions() -> None:
    global _sessions_loaded
    with lock:
        active_sessions.clear()
        _sessions_loaded = True
    _persist_sessions()


def get_session_token(password: str, username: str = "admin") -> str:
    salt = "aimilivpn_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

_last_cleanup_time = 0.0

def cleanup_old_logs(logs_dir: Path, force: bool = False) -> None:
    global _last_cleanup_time
    now = time.time()
    with lock:
        if not force and now - _last_cleanup_time < 3600:
            return
        _last_cleanup_time = now
    try:
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        with lock:
                            path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        with lock:
                            path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def read_recent_log_entries(log_file: Path, max_entries: int = 1200, max_bytes: int = 1048576) -> tuple[list[dict[str, Any]], bool]:
    if not log_file.exists():
        return [], False
    entries: list[dict[str, Any]] = []
    truncated = False
    try:
        with lock:
            with open(log_file, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                start = max(0, size - max_bytes)
                if start:
                    truncated = True
                    f.seek(start)
                    f.readline()
                for raw in f:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(item, dict):
                        entries.append(item)
                        if len(entries) > max_entries:
                            entries.pop(0)
                            truncated = True
    except Exception as exc:
        print(f"[API Logs] Error reading recent log entries: {exc}", flush=True)
    return entries, truncated

def clear_today_log() -> dict[str, Any]:
    logs_dir = DATA_DIR / "logs"
    logs_dir.mkdir(exist_ok=True, parents=True)
    date_str = time.strftime("%Y-%m-%d", time.localtime())
    log_file = logs_dir / f"{date_str}.json"
    with lock:
        log_file.write_text("", encoding="utf-8")
    return {"ok": True, "date": date_str}

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with lock:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

web_certificate = WebCertificateManager(
    DATA_DIR / "web_certificate.json",
    log_fn=lambda message: log_to_json("INFO", "WebSSL", message),
)

resource_share = ResourceShareManager(
    DATA_DIR / "resource_sharing.json",
    node_pool,
    log_fn=lambda message: log_to_json("INFO", "Share", message),
)

def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)

def set_manual_route_pin(*, protocol: str, endpoint_id: str = "", node_id: str = "") -> None:
    global manual_route_pin, manual_connection_quiet_until
    manual_route_pin = {
        "protocol": str(protocol or ""),
        "endpoint_id": str(endpoint_id or ""),
        "node_id": str(node_id or ""),
        "set_at": time.time(),
    }
    manual_connection_quiet_until = time.time() + 15.0

def clear_manual_route_pin() -> None:
    global manual_route_pin
    manual_route_pin = {}

def read_nodes() -> list[dict[str, Any]]:
    raw = read_json(NODES_FILE, [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, active_pool_endpoint_id, is_connecting, manual_connection_active, manual_connection_epoch
    global global_pool_refresh_running, global_pool_refresh_last_at, global_pool_refresh_status
    global global_pool_refresh_message, global_pool_refresh_servers, global_pool_refresh_sources
    state = read_json(STATE_FILE, {})
    state.pop("password", None)
    cert_state = web_certificate.snapshot()
    state["web_domain"] = str(load_ui_config().get("web_domain") or cert_state.get("domain") or "")
    state["web_certificate"] = cert_state
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["active_pool_endpoint_id"] = active_pool_endpoint_id
    state["active_pool_endpoint"] = None
    if active_pool_endpoint_id:
        try:
            endpoint = node_pool.get_endpoint(active_pool_endpoint_id)
            if endpoint:
                server_meta = endpoint.get("server_metadata") or {}
                state["active_pool_endpoint"] = {
                    "endpoint_id": endpoint.get("endpoint_id", ""),
                    "protocol": endpoint.get("protocol", ""),
                    "transport": endpoint.get("transport", ""),
                    "port": endpoint.get("port", 0),
                    "hostname": endpoint.get("hostname", ""),
                    "current_ip": endpoint.get("current_ip", ""),
                    "country": endpoint.get("country", ""),
                    "location": server_meta.get("location") or endpoint.get("country", ""),
                    "owner": server_meta.get("owner") or server_meta.get("as_name") or "",
                    "ip_type": server_meta.get("ip_type") or "",
                    "quality": server_meta.get("quality") or "",
                    "speed": endpoint.get("latest_speed", 0),
                    "latency_ms": endpoint.get("latency_ewma", 0),
                    "jitter_ms": endpoint.get("jitter_ewma", 0),
                    "selection_score": endpoint.get("selection_score", 0),
                }
        except Exception:
            pass
    state["active_tunnel_interface"] = proxy_server.get_active_interface() if active_tunnel_running() else ""
    if active_external_tunnel is not None:
        state["active_tunnel_protocol"] = active_external_tunnel.protocol
    elif active_openvpn_running():
        state["active_tunnel_protocol"] = "openvpn"
    else:
        state["active_tunnel_protocol"] = ""
    state["is_connecting"] = is_connecting
    state["manual_connection_active"] = manual_connection_active
    state["manual_connection_epoch"] = manual_connection_epoch
    state["maintenance_running"] = maintenance_lock.locked()
    state["global_pool_refresh_running"] = global_pool_refresh_running
    state["global_pool_refresh_last_at"] = global_pool_refresh_last_at
    state["global_pool_refresh_status"] = global_pool_refresh_status
    state["global_pool_refresh_message"] = global_pool_refresh_message
    state["global_pool_refresh_servers"] = global_pool_refresh_servers
    state["global_pool_refresh_sources"] = global_pool_refresh_sources
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    state["hot_pool_size"] = int(state.get("hot_pool_size") or 0)
    state["hot_pool_target"] = int(state.get("hot_pool_target") or HOT_POOL_TARGET)
    # Keep persisted UI state aligned with the current global-country coverage policy.
    state["priority_minimum"] = COUNTRY_AVAILABLE_MIN
    state["priority_target"] = COUNTRY_AVAILABLE_TARGET
    state["priority_inventory_target"] = COUNTRY_INVENTORY_TARGET
    try:
        pool_stats = node_pool.stats()
        state["pool_servers"] = int(pool_stats.get("servers") or 0)
        state["pool_endpoints"] = int(pool_stats.get("endpoints") or 0)
        state["pool_states"] = pool_stats.get("states") or {}
        state["hot_pool_size"] = int((pool_stats.get("states") or {}).get("HOT") or 0)
        state["hot_pool_target"] = HOT_POOL_TARGET
    except Exception:
        state.setdefault("pool_servers", 0)
        state.setdefault("pool_endpoints", 0)
        state.setdefault("pool_states", {})
    _proxy_display = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
    state["local_proxy"] = f"http://{_proxy_display}:8500"
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)

    # Pre-populate settings inputs in UI
    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = 8443
    state["internal_ui_port"] = ui_cfg.get("port", 8501)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    state["password_set"] = bool(ui_cfg.get("password"))
    state["proxy_port"] = 8500
    state["proxy_access"] = os.environ.get("LOCAL_PROXY_ALLOW", "127.0.0.1/32,::1/128")
    state["routing_mode"] = ui_cfg.get("routing_mode", "auto")
    state["force_country"] = ui_cfg.get("force_country", "")
    state["routing_ip_type"] = ui_cfg.get("routing_ip_type", "all")
    state["connection_enabled"] = ui_cfg.get("connection_enabled", True)
    state["fixed_node_id"] = ui_cfg.get("fixed_node_id", "")
    state["favorite_node_ids"] = ui_cfg.get("favorite_node_ids", [])
    state["fav_fail_fallback"] = bool(ui_cfg.get("fav_fail_fallback", True))
    state["manual_route_pin"] = dict(manual_route_pin)
    state["manual_connection_quiet_until"] = manual_connection_quiet_until
    state["ui_command_plane"] = ui_command_plane.ui_state()

    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def clear_active_connection_state(message: str) -> None:
    global active_openvpn_process, active_openvpn_node_id, active_external_tunnel, active_pool_endpoint_id
    stop_process(active_openvpn_process)
    active_openvpn_process = None
    active_openvpn_node_id = ""
    if active_external_tunnel is not None:
        try:
            if active_external_tunnel.protocol == "softether":
                details = active_external_tunnel.details or {}
                tunnel_adapters.SoftEtherAdapter().disconnect(
                    account=str(details.get("account") or "aimili"),
                    nic=str(details.get("nic") or "aimili"),
                    delete=True,
                    added_routes=details.get("added_host_routes") or [],
                )
            elif active_external_tunnel.protocol == "sstp":
                details = active_external_tunnel.details or {}
                tunnel_adapters.SSTPAdapter.disconnect(
                    active_external_tunnel.process,
                    added_routes=details.get("added_host_routes") or [],
                )
        except Exception:
            pass
    active_external_tunnel = None
    active_pool_endpoint_id = ""
    cleanup_policy_routing()
    with lock:
        nodes = read_nodes()
        for item in nodes:
            item["active"] = False
        write_json(NODES_FILE, nodes)
    set_state(
        active_openvpn_node_id="",
        active_pool_endpoint_id="",
        active_tunnel_protocol="",
        active_tunnel_interface="",
        is_connecting=False,
        active_node_latency="无活动连接",
        last_check_message=message,
    )

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def proxy_basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"

def recv_exact_from_socket(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Unexpected EOF while reading proxy response")

[executed on device: instance-20260601-095619 (57357237-fed5-46f5-bb41-5a6bf595b7b2)]