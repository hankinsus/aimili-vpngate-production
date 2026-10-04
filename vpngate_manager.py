
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

    # 生产服务器以 GitHub main 为唯一代码源。只要远端提交不同且不是
    # “服务器单独领先”的情形，就允许从 GitHub 正式版同步，解决服务器与
    # GitHub 历史提交号不同导致“已分叉、无法更新”的问题。
    has_update = relation in ("remote_ahead", "diverged", "different") and remote != local
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
        result["message"] = "服务器与 GitHub 正式版存在本地提交差异；更新时将以 GitHub main 为准同步。"
    elif relation == "different":
        result["message"] = "已获取 GitHub 正式版，将以 GitHub main 为准同步。"
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
    try:
        bootstrap = _read_bootstrap_state()
        state["server_country"] = str(
            bootstrap.get("local_server_country")
            or state.get("initial_bootstrap_country")
            or ""
        ).strip()
        state["server_country_code"] = str(bootstrap.get("local_server_country_code") or "").strip().upper()
        if not state["server_country"]:
            detected = _detect_local_server_country()
            if detected.get("country"):
                state["server_country"] = str(detected.get("country") or "").strip()
                state["server_country_code"] = str(detected.get("country_code") or "").strip().upper()
                _write_bootstrap_state(
                    local_server_country=state["server_country"],
                    local_server_country_code=state["server_country_code"],
                    local_server_public_ip=str(detected.get("public_ip") or ""),
                    detection_source=str(detected.get("source") or ""),
                )
    except Exception:
        state.setdefault("server_country", "")
        state.setdefault("server_country_code", "")
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
        data += chunk
    return data

def read_http_response_head(sock: socket.socket, limit: int = 65536) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise RuntimeError("Proxy response header too large")
    if b"\r\n\r\n" not in data:
        raise RuntimeError("Incomplete HTTP proxy response header")
    return data

def socks5_address_bytes(host: str) -> tuple[int, bytes]:
    try:
        return 1, socket.inet_aton(host)
    except OSError:
        pass
    try:
        return 4, socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        pass
    host_bytes = host.encode("idna")
    if len(host_bytes) > 255:
        raise RuntimeError("SOCKS5 target host name is too long")
    return 3, bytes([len(host_bytes)]) + host_bytes

def read_socks5_connect_reply(sock: socket.socket) -> None:
    header = recv_exact_from_socket(sock, 4)
    if header[0] != 5:
        raise RuntimeError("Invalid SOCKS5 reply version")
    atyp = header[3]
    if atyp == 1:
        recv_exact_from_socket(sock, 4)
    elif atyp == 3:
        domain_len = recv_exact_from_socket(sock, 1)[0]
        recv_exact_from_socket(sock, domain_len)
    elif atyp == 4:
        recv_exact_from_socket(sock, 16)
    else:
        raise RuntimeError(f"Invalid SOCKS5 reply address type: {atyp}")
    recv_exact_from_socket(sock, 2)
    if header[1] != 0:
        raise RuntimeError(f"SOCKS5 connection request rejected, code={header[1]}")

def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"

def fetch_api_text_via_proxy(url: str, ptype: str, phost: str, pport: int, use_ssl_verify: bool = True) -> str:
    import socket
    import ssl
    import urllib.parse

    parsed = urllib.parse.urlsplit(url)
    domain = parsed.hostname or "www.vpngate.net"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    is_ipv6 = ":" in phost
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(12)
        s.connect((phost, pport))
        proxy_user, proxy_pass = vpn_utils.get_upstream_proxy_auth()
        if ptype == "socks":
            # SOCKS5 Handshake
            if proxy_user is not None:
                s.sendall(b"\x05\x02\x00\x02")
            else:
                s.sendall(b"\x05\x01\x00")
            resp = recv_exact_from_socket(s, 2)
            if len(resp) < 2 or resp[0] != 5:
                raise RuntimeError("SOCKS5 authentication failed or unsupported")
            if resp[1] == 2:
                if proxy_user is None:
                    raise RuntimeError("SOCKS5 proxy requires username/password authentication")
                user_bytes = proxy_user.encode("utf-8")
                pass_bytes = (proxy_pass or "").encode("utf-8")
                if len(user_bytes) > 255 or len(pass_bytes) > 255:
                    raise RuntimeError("SOCKS5 proxy credentials are too long")
                s.sendall(b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes)
                auth_resp = recv_exact_from_socket(s, 2)
                if len(auth_resp) < 2 or auth_resp[1] != 0:
                    raise RuntimeError("SOCKS5 username/password authentication failed")
            elif resp[1] != 0:
                raise RuntimeError("SOCKS5 authentication method unsupported")
            # SOCKS5 Connect
            atyp, addr_bytes = socks5_address_bytes(domain)
            req = b"\x05\x01\x00" + bytes([atyp]) + addr_bytes + port.to_bytes(2, 'big')
            s.sendall(req)
            read_socks5_connect_reply(s)
            # If HTTPS, wrap socket with SSL
            if is_https:
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
        else: # http proxy
            if is_https:
                # HTTP CONNECT tunnel
                authority = format_host_port(domain, port)
                auth_header = proxy_basic_auth_header(proxy_user, proxy_pass or "") if proxy_user is not None else ""
                req_str = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n{auth_header}Proxy-Connection: Keep-Alive\r\n\r\n"
                s.sendall(req_str.encode('ascii'))
                resp = read_http_response_head(s)
                status_line = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                status_parts = status_line.split()
                status_code = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
                if status_code != 200:
                    raise RuntimeError(f"HTTP CONNECT tunnel failed: {status_line}")
                # Wrap socket with SSL
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
            else:
                # Direct HTTP request through proxy: request URI must be absolute
                pass

        # Send HTTP GET request
        if ptype == "http" and not is_https:
            request_uri = url
        else:
            request_uri = path

        req_headers = (
            f"GET {request_uri} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n"
            f"Accept: text/plain,*/*\r\n"
            f"{proxy_basic_auth_header(proxy_user, proxy_pass or '') if ptype == 'http' and not is_https and proxy_user is not None else ''}"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req_headers.encode('utf-8'))

        # Read response
        response_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if len(response_data) > 10 * 1024 * 1024: # max 10MB safety guard
                break
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # Parse HTTP response
    header_end = response_data.find(b"\r\n\r\n")
    if header_end == -1:
        raise RuntimeError("Invalid HTTP response format")

    headers_part = response_data[:header_end].decode('utf-8', errors='replace')
    body_part = response_data[header_end+4:]

    # Check for HTTP status code
    lines = headers_part.splitlines()
    if not lines:
        raise RuntimeError("Empty response headers")
    status_line = lines[0]
    status_parts = status_line.split()
    if len(status_parts) >= 2:
        try:
            status_code = int(status_parts[1])
            if status_code != 200:
                raise RuntimeError(f"HTTP Server returned status {status_code}: {status_line}")
        except ValueError:
            pass

    # Handle chunked transfer encoding
    is_chunked = False
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() == "transfer-encoding" and "chunked" in v.lower():
                is_chunked = True
                break

    if is_chunked:
        decoded = b""
        idx = 0
        while idx < len(body_part):
            c_end = body_part.find(b"\r\n", idx)
            if c_end == -1:
                break
            chunk_size_str = body_part[idx:c_end].split(b";")[0].strip()
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            idx = c_end + 2
            decoded += body_part[idx : idx + chunk_size]
            idx += chunk_size + 2
        body_part = decoded

    return body_part.decode('utf-8', errors='replace')

def fetch_api_text(url: str | None = None, use_ssl_verify: bool = True) -> str:
    if url is None:
        url = API_URL

    ptype, phost, pport = vpn_utils.get_upstream_proxy()
    if ptype and phost and pport:
        try:
            print(f"[fetch_api_text] 监测到上游代理 ({ptype}://{phost}:{pport})，尝试通过代理获取 API...", flush=True)
            return fetch_api_text_via_proxy(url, ptype, phost, pport, use_ssl_verify)
        except Exception as e:
            print(f"[fetch_api_text] 通过代理获取 API 失败: {e}，尝试使用直连/默认系统代理...", flush=True)
            log_to_json("WARNING", "Main", f"使用代理 {ptype}://{phost}:{pport} 获取 API 失败: {e}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 vpngate-openvpn-manager/2.0",
            "Accept": "text/plain,*/*",
        },
    )
    if url.startswith("https://") and not use_ssl_verify:
        import ssl
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=12, context=ctx) as response:
            return response.read().decode("utf-8", errors="replace")
    else:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.read().decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")

def load_blacklist() -> dict[str, dict[str, Any]]:
    now = time.time()
    raw = read_json(BLACKLIST_FILE, {})
    if not isinstance(raw, dict):
        return {}
    cleaned: dict[str, dict[str, Any]] = {}
    changed = False
    for key, entry in raw.items():
        if not isinstance(entry, dict):
            changed = True
            continue
        until = float(entry.get("until", 0) or 0)
        if until and until > now:
            cleaned[str(key)] = entry
        else:
            changed = True
    if changed:
        write_json(BLACKLIST_FILE, cleaned)
    return cleaned

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    node_id = str(node.get("id") or "").strip()
    if not node_id:
        return
    blacklist = load_blacklist()
    now = time.time()
    blacklist[node_id] = {
        "id": node_id,
        "ip": node.get("ip") or node.get("remote_host") or "",
        "country": node.get("country", ""),
        "reason": message,
        "marked_at": now,
        "until": now + INVALID_BACKOFF_SECONDS,
    }
    write_json(BLACKLIST_FILE, blacklist)

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"

    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "protocol": "openvpn",
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }


def dedupe_ui_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse visually identical protocol/IP/port rows while retaining fallback endpoints."""
    groups: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    passthrough: list[dict[str, Any]] = []

    def rank(node: dict[str, Any]) -> tuple[int, int, int, float, float]:
        status = str(node.get("probe_status") or "not_checked").lower()
        status_rank = {"available": 0, "testing": 1, "not_checked": 2, "unavailable": 3}.get(status, 4)
        active_rank = 0 if node.get("active") else 1
        trusted_rank = 0 if bool((node.get("_pool_metadata") or {}).get("trusted_observation")) else 1
        latency = float(node.get("latency_ms") or 999999)
        if latency <= 0:
            latency = 999999
        seen = float(node.get("probed_at") or node.get("fetched_at") or 0)
        return (active_rank, status_rank, trusted_rank, latency, -seen)

    for node in nodes:
        if not isinstance(node, dict):
            continue
        protocol = str(node.get("protocol") or "openvpn").strip().lower()
        ip = str(node.get("ip") or node.get("current_ip") or node.get("remote_host") or "").strip()
        try:
            port = int(node.get("remote_port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not ip or not port:
            passthrough.append(node)
            continue
        groups.setdefault((protocol, ip, port), []).append(node)

    merged: list[dict[str, Any]] = []
    for group in groups.values():
        group.sort(key=rank)
        primary = dict(group[0])
        fallback_ids: list[str] = []
        for duplicate in group:
            endpoint_id = str(duplicate.get("pool_endpoint_id") or "").strip()
            node_id = str(duplicate.get("id") or "").strip()
            if endpoint_id and endpoint_id != str(primary.get("pool_endpoint_id") or ""):
                fallback_ids.append(endpoint_id)
            elif node_id and node_id != str(primary.get("id") or "") and node_id.startswith("pool:"):
                fallback_ids.append(node_id[5:])
        if len(group) > 1:
            existing = [str(x) for x in (primary.get("pool_endpoint_ids") or []) if x]
            primary["pool_endpoint_ids"] = list(dict.fromkeys(
                [str(primary.get("pool_endpoint_id") or "")] + existing + fallback_ids
            ))
            primary["duplicate_count"] = len(group) - 1
        merged.append(primary)

    merged.extend(passthrough)
    return merged


def protocol_endpoint_to_ui_node(endpoint: dict[str, Any]) -> dict[str, Any]:
    protocol = str(endpoint.get("protocol") or "").strip().lower()
    if not protocol:
        return {}
    metadata = endpoint.get("metadata") or {}
    server_metadata = endpoint.get("server_metadata") or {}
    status = str(endpoint.get("status") or "NEW").upper()
    probe_status = {
        "HOT": "available",
        "AVAILABLE": "available",
        "NEW": "not_checked",
        "DEGRADED": "unavailable",
        "COOLDOWN": "unavailable",
        "STALE": "unavailable",
        "RETIRED": "unavailable",
    }.get(status, "not_checked")
    ip = str(endpoint.get("current_ip") or metadata.get("ip") or "").strip()
    host = str(metadata.get("hostname") or endpoint.get("hostname") or ip).strip()
    try:
        port = int(endpoint.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    return {
        "id": f"pool:{endpoint.get('endpoint_id', '')}",
        "pool_endpoint_id": str(endpoint.get("endpoint_id") or ""),
        "country": endpoint.get("country") or "",
        "country_short": "",
        "host_name": host,
        "ip": ip,
        "score": int(endpoint.get("latest_server_score") or 0),
        "ping": int(endpoint.get("latest_ping") or 0),
        "speed": int(endpoint.get("latest_speed") or 0),
        "sessions": int(endpoint.get("latest_sessions") or 0),
        "owner": str(server_metadata.get("owner") or server_metadata.get("isp") or server_metadata.get("as_name") or ""),
        "asn": str(server_metadata.get("asn") or ""),
        "as_name": str(server_metadata.get("as_name") or ""),
        "location": str(server_metadata.get("location") or endpoint.get("country") or ""),
        "ip_type": str(server_metadata.get("ip_type") or ""),
        "quality": str(server_metadata.get("quality") or ""),

        "latency_ms": int(endpoint.get("latency_ewma") or 0),
        "config_file": str(endpoint.get("config_ref") or ""),
        "proto": str(endpoint.get("transport") or ""),
        "protocol": protocol,
        "remote_host": host,
        "remote_port": port,
        "fetched_at": float(endpoint.get("last_seen") or 0),
        "manual_added_at": float(metadata.get("manual_added_at") or 0),
        "probe_status": probe_status,
        "probe_message": str(metadata.get("last_error") or ""),
        "probed_at": float(endpoint.get("last_success") or endpoint.get("last_failure") or 0),
        "active": False,
    }


def fetch_candidates() -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_ips = set()

    # 检查本地是否有节点缓存，以确定最大重试尝试次数
    has_cache = len(cached_nodes()) > 0
    max_attempts = 1 if has_cache else 2

    # 尝试 URLs 队列: 1. HTTPS(验证证书) 2. HTTPS(不验证证书) 3. HTTP
    attempts_targets = [
        (API_URL, True),
        (API_URL, False)
    ]
    if API_URL.startswith("https://"):
        attempts_targets.append((API_URL.replace("https://", "http://"), True))

    log_to_json("INFO", "Main", "开始拉取官方 API 节点列表...")

    last_err = None
    for url, verify_ssl in attempts_targets:
        for i in range(max_attempts):
            if i > 0:
                time.sleep(1.5)
            try:
                msg = f"尝试拉取 {url} (SSL验证: {verify_ssl}, 第 {i+1} 次尝试)..."
                print(f"[fetch_candidates] {msg}", flush=True)
                log_to_json("INFO", "Main", msg)
                api_text = fetch_api_text(url, verify_ssl)
                rows = parse_vpngate_rows(api_text)
                for row in rows[:MAX_SCAN_ROWS]:
                    ip = row.get("IP", "")
                    if not ip or ip in seen_ips:
                        continue
                    encoded = row.get("OpenVPN_ConfigData_Base64", "")
                    if not encoded:
                        continue
                    try:
                        config_text = decode_config(encoded)
                        node = row_to_node(row, config_text)
                    except Exception as row_exc:
                        print(f"[fetch_candidates] 跳过损坏的节点配置记录: {row_exc}", flush=True)
                        log_to_json("WARNING", "Main", f"跳过损坏的节点配置记录: {row_exc}")
                        continue
                    entry = blacklist.get(node["id"])
                    if entry and float(entry.get("until", 0) or 0) > time.time():
                        continue
                    candidates.append(node)
                    seen_ips.add(ip)
                if candidates:
                    break
            except Exception as e:
                last_err = e
                print(f"[fetch_candidates] 拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}", flush=True)
                log_to_json("WARNING", "Main", f"拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}")
        if candidates:
            break

    if not candidates:
        err_code, diag_msg = vpn_utils.diagnose_api_failure(API_URL)
        full_err_msg = f"获取官方 API 节点最终失败: {last_err} | 诊断结果: {diag_msg}"
        print(f"[错误代码 {err_code}] {full_err_msg}", flush=True)
        log_to_json("ERROR", "Main", f"[错误代码 {err_code}] {full_err_msg}")
        set_state(
            last_fetch_status="error",
            last_fetch_error_code=err_code,
            last_fetch_message=diag_msg
        )
        if last_err:
            raise RuntimeError(diag_msg) from last_err
        else:
            raise RuntimeError(diag_msg)

    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok",
        last_fetch_message=f"Fetched {len(candidates)} unique candidates across multiple attempts.",
        blacklisted_nodes=len(blacklist),
    )
    try:
        node_pool.upsert_openvpn_snapshot(candidates, source="official_csv")
    except Exception as pool_exc:
        print(f"[NodePool] 官方 CSV 快照写入失败: {pool_exc}", flush=True)
        log_to_json("WARNING", "Main", f"NodePool 快照写入失败: {pool_exc}")

    log_to_json("INFO", "Main", f"成功获取官方 API 节点，共 {len(candidates)} 个候选节点")
    return candidates

def cached_nodes() -> list[dict[str, Any]]:
    return read_nodes()

_openvpn_version = None

def split_openvpn_command() -> list[str]:
    try:
        return shlex.split(OPENVPN_CMD, posix=(os.name != "nt")) or ["openvpn"]
    except ValueError as exc:
        raise RuntimeError(f"OPENVPN_CMD 配置无法解析: {exc}") from exc

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = split_openvpn_command()
        res = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0") -> list[str]:
    command = split_openvpn_command()
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--route-delay",
            "2",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "15",
            "--auth-user-pass",
            str(AUTH_FILE),
            "--auth-nocache",
        ]
    )

    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    command.extend(["--verb", "3"])

    if os.path.exists("/etc/ssl/certs"):
        command.extend(["--capath", "/etc/ssl/certs"])

    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            auth_file = upstream_proxy_auth_file()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
    except Exception:
        pass

    if route_nopull:
        command.append("--route-nopull")
    return command

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()

def kill_existing_openvpn_processes() -> None:
    if ISOLATED_INSTANCE:
        return
    if not sys.platform.startswith("linux"):
        return
    try:
        own_markers = [
            str(DATA_DIR),
            str(CONFIG_DIR),
            str(AUTH_FILE),
            str(UPSTREAM_PROXY_AUTH_FILE),
        ]
        killed_pids: list[int] = []
        proc_root = Path("/proc")
        if not proc_root.exists():
            return
        for proc_dir in proc_root.iterdir():
            if not proc_dir.name.isdigit():
                continue
            pid = int(proc_dir.name)
            if pid == os.getpid():
                continue
            try:
                raw = (proc_dir / "cmdline").read_bytes()
            except OSError:
                continue
            if not raw:
                continue
            args = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
            if not args:
                continue
            cmdline = " ".join(args)
            executable = Path(args[0]).name.lower()
            if "openvpn" not in executable and "openvpn" not in cmdline.lower():
                continue
            if any(marker and marker in cmdline for marker in own_markers):
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed_pids.append(pid)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    print(f"[Cleanup] No permission to terminate OpenVPN PID {pid}", flush=True)
        if killed_pids:
            time.sleep(0.5)
            for pid in killed_pids:
                try:
                    raw = (proc_root / str(pid) / "cmdline").read_bytes()
                    cmdline = " ".join(part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part)
                    if any(marker and marker in cmdline for marker in own_markers):
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except (OSError, PermissionError):
                    pass
            print(f"[Cleanup] Terminated AimiliVPN OpenVPN processes: {killed_pids}", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def _openvpn_elapsed_ms(message: str) -> int:
    match = re.search(r"OpenVPN connected in (\d+) ms", str(message or ""))
    if not match:
        return 0
    try:
        return max(1, int(match.group(1)))
    except (TypeError, ValueError):
        return 0

def _prefer_openvpn_ip(config_text: str, node: dict[str, Any]) -> str:
    """Use the fresh pool IP when the stored VPNGate remote hostname is stale."""
    text_value = str(config_text or "")
    ip = str(node.get("ip") or node.get("current_ip") or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return text_value
    port = parse_int(node.get("remote_port"))
    if not ip or port <= 0:
        return text_value
    lines = text_value.splitlines()
    changed = False
    out: list[str] = []
    for line in lines:
        match = re.match(r"^(\s*remote\s+)(\S+)(\s+)(\d+)(.*)$", line, re.IGNORECASE)
        if match and parse_int(match.group(4)) == port and match.group(2) != ip:
            out.append(f"{match.group(1)}{ip}{match.group(3)}{match.group(4)}{match.group(5)}")
            changed = True
        else:
            out.append(line)
    return "\n".join(out) + ("\n" if text_value.endswith("\n") else "") if changed else text_value

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0") -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "[错误代码 2001] [ERR_OVPN_CMD_NOT_FOUND] 未找到 openvpn 命令。原因: 系统未安装 openvpn，或 PATH 环境变量不正确。", None
    except OSError as exc:
        return False, f"[错误代码 2002] [ERR_OVPN_START_FAILED] openvpn 启动失败: {exc}。原因: 系统权限不足或配置冲突。", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]
    openvpn_logs: list[str] = []

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            line_str = line.rstrip()
            if not startup_done[0]:
                openvpn_logs.append(line_str)
                lines.put(line_str)
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line_str}", flush=True)
                    level = "INFO"
                    line_lower = line_str.lower()
                    if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
                        level = "ERROR"
                    elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
                        level = "WARNING"
                    log_to_json(level, "VPN", f"[OpenVPN] {line_str}")
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-50:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            ok = True
            message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    # Bulk write accumulated startup logs
    for line_str in openvpn_logs:
        level = "INFO"
        line_lower = line_str.lower()
        if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
            level = "ERROR"
        elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
            level = "WARNING"
        log_to_json(level, "VPN", f"[OpenVPN] {line_str}")

    if not ok:
        err_code, diag_msg = vpn_utils.diagnose_openvpn_failure(tail)
        message = f"[错误代码 {err_code}] {diag_msg} (原始日志尾部: {tail[-1][-100:] if tail else '无'})"
    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    return ok, message, process


def setup_policy_routing(interface: str = "tun0", gateway: str = "") -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", str(ACTIVE_ROUTE_TABLE)], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", str(ACTIVE_ROUTE_TABLE)], capture_output=True, timeout=2)
    except Exception:
        pass

    success = False
    for attempt in range(1, 4):
        try:
            route_cmd = ["ip", "route", "add", "default"]
            if gateway:
                route_cmd.extend(["via", gateway])
            route_cmd.extend(["dev", interface])
            if gateway:
                route_cmd.append("onlink")
            route_cmd.extend(["table", str(ACTIVE_ROUTE_TABLE)])
            subprocess.run(route_cmd, check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", str(ACTIVE_ROUTE_TABLE)], check=True, timeout=2)
            # 配置反向路径过滤 rp_filter 为 loose 模式 (2)，防止回包被内核静默丢弃
            for proc_path in ["all", "default", interface]:
                try:
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{proc_path}.rp_filter=2"], capture_output=True, timeout=2)
                except Exception:
                    pass
            print(f"[policy_routing] Enabled policy routing for interface {interface} (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)

    if not success:
        print(f"[路由配置失败] [错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 {ACTIVE_ROUTE_TABLE} 添加默认路由，这可能会导致通过 VPN 接口的出站路由无法正常解析。请检查系统是否支持策略路由、iproute2 工具是否完整，以及是否具有 root 权限。", flush=True)
        log_to_json("ERROR", "Routing", f"[错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 {ACTIVE_ROUTE_TABLE} 添加默认路由")

def cleanup_policy_routing() -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", str(ACTIVE_ROUTE_TABLE)], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", str(ACTIVE_ROUTE_TABLE)], capture_output=True, timeout=2)
        print(f"[policy_routing] Cleared policy routing table {ACTIVE_ROUTE_TABLE}", flush=True)
    except Exception:
        pass

def _clear_all_node_active_flags() -> None:
    with lock:
        nodes = read_nodes()
        changed = False
        for item in nodes:
            if item.get("active"):
                item["active"] = False
                changed = True
        if changed:
            write_json(NODES_FILE, nodes)

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    with lock:
        cleanup_policy_routing()
        config_to_delete = None
        if active_openvpn_node_id:
            nodes = read_nodes()
            node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
            if node:
                config_to_delete = node.get("config_file")

        stop_process(active_openvpn_process)
        active_openvpn_process = None
        active_openvpn_node_id = ""
        if not ISOLATED_INSTANCE:
            kill_existing_openvpn_processes()

        if config_to_delete:
            try:
                path = Path(config_to_delete)
                if path.exists():
                    path.unlink()
            except Exception:
                pass
        _clear_all_node_active_flags()

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None

def active_external_tunnel_running() -> bool:
    tunnel = active_external_tunnel
    if tunnel is None or not tunnel.ok or not tunnel.interface:
        return False
    return tunnel_adapters.interface_has_ipv4(tunnel.interface)

def active_tunnel_running() -> bool:
    return active_openvpn_running() or active_external_tunnel_running()

def stop_active_external_tunnel() -> None:
    global active_external_tunnel, active_pool_endpoint_id
    tunnel = active_external_tunnel
    if tunnel is None:
        active_pool_endpoint_id = ""
        return
    try:
        if tunnel.protocol == "softether":
            details = tunnel.details or {}
            tunnel_adapters.SoftEtherAdapter().disconnect(
                account=str(details.get("account") or "aimili"),
                nic=str(details.get("nic") or "aimili"),
                delete=True,
                added_routes=details.get("added_host_routes") or [],
            )
        elif tunnel.protocol == "sstp":
            details = tunnel.details or {}
            tunnel_adapters.SSTPAdapter.disconnect(
                tunnel.process,
                added_routes=details.get("added_host_routes") or [],
            )
        elif tunnel.protocol == "l2tp-ipsec":
            l2tp_adapter.disconnect(tunnel.namespace or "aimili-l2tp-prod")
    except Exception as exc:
        log_to_json("WARNING", "VPN", f"停止 {tunnel.protocol} 隧道失败: {exc}")
    cleanup_policy_routing()
    proxy_server.clear_active_interface()
    active_external_tunnel = None
    active_pool_endpoint_id = ""
    _clear_all_node_active_flags()
    set_state(active_pool_endpoint_id="", active_tunnel_protocol="", active_tunnel_interface="")

def stop_all_tunnels() -> None:
    stop_active_external_tunnel()
    stop_active_openvpn()

def refresh_multi_protocol_catalog(force: bool = False) -> dict[str, Any]:
    global last_protocol_discovery_at
    now = time.time()
    if not force and now - last_protocol_discovery_at < 300:
        return {"ok": True, "skipped": True, "pool": node_pool.stats()}
    if not protocol_discovery_lock.acquire(blocking=False):
        return {"ok": True, "running": True, "pool": node_pool.stats()}
    try:
        servers, sources = vpngate_discovery.fetch_multi_source_tables(max_mirrors=None)
        node_pool.upsert_discovery_snapshot(servers, source="official_html_multi")
        last_protocol_discovery_at = time.time()
        stats = node_pool.stats()
        set_state(
            protocol_catalog_last_at=last_protocol_discovery_at,
            protocol_catalog_count=len(servers),
            protocol_catalog_sources=len(sources),
        )
        log_to_json("INFO", "Main", f"多协议目录刷新完成，本轮合并 {len(servers)} 台服务器，来源 {len(sources)} 个，Master Pool={stats}")
        return {"ok": True, "servers": len(servers), "sources": sources, "pool": stats}
    except Exception as exc:
        log_to_json("WARNING", "Main", f"多协议目录刷新失败: {exc}")
        return {"ok": False, "error": str(exc), "pool": node_pool.stats()}
    finally:
        protocol_discovery_lock.release()


def parse_manual_endpoint(value: str) -> tuple[str, int]:
    """Parse a manual VPN Gate target.
    
    The port is optional for VPN Gate hostnames. When it is omitted, the
    official VPN Gate endpoint page is queried and each advertised protocol
    port is tested independently. Explicit address:port input remains fully
    supported.
    """
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("节点地址不能为空")
    if raw.startswith("["):
        match = re.match(r"^\[([0-9a-fA-F:]+)\](?::(\d+))?$", raw)
        if not match:
            raise ValueError("IPv6 节点格式应为 [IPv6] 或 [IPv6]:端口")
        return match.group(1), int(match.group(2) or 0)
    match = re.match(r"^([^:]+)(?::(\d+))?$", raw)
    if not match:
        raise ValueError("节点格式应为 域名、域名:端口、IPv4 或 IPv4:端口")
    host = match.group(1).strip()
    if not host:
        raise ValueError("节点地址不能为空")
    return host, int(match.group(2) or 0)

def _manual_openvpn_template() -> str:
    """Return a current VPN Gate OpenVPN template already present on this instance."""
    try:
        for node in read_nodes():
            text = str(node.get("config_text") or "").strip()
            if text and "<ca>" in text and "<key>" in text and "remote " in text:
                return text
    except Exception:
        pass
    return ""

def _build_manual_openvpn_node(host: str, ip: str, port: int, transport: str = "tcp") -> dict[str, Any] | None:
    template = _manual_openvpn_template()
    if not template:
        try:
            fetched = fetch_candidates()
            for node in fetched:
                template = str(node.get("config_text") or "").strip()
                if template and "<ca>" in template and "<key>" in template and "remote " in template:
                    break
        except Exception:
            template = ""
    if not template:
        return None
    config_text = re.sub(r"(?m)^remote\s+\S+\s+\d+\s*$", f"remote {host} {int(port)}", template, count=1)
    transport = str(transport or "tcp").strip().lower()
    if transport not in ("tcp", "udp"):
        transport = "tcp"
    config_text = re.sub(r"(?m)^proto\s+\S+\s*$", f"proto {transport}", config_text, count=1)
    node_id = safe_name(f"MANUAL_{host}_{port}_{transport}")
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    node = {
        "id": node_id, "country": "", "country_short": "", "host_name": host, "ip": ip or host,
        "score": 0, "ping": 0, "speed": 0, "sessions": 0, "owner": "", "asn": "", "as_name": "",
        "location": "", "ip_type": "", "quality": "manual", "latency_ms": 0,
        "config_file": str(config_path), "config_text": config_text, "proto": transport, "protocol": "openvpn",
        "remote_host": host, "remote_port": int(port), "fetched_at": time.time(),
        "probe_status": "not_checked", "probe_message": "手动添加，等待本机验证", "probed_at": 0,
        "manual_added": True, "manual_source": "user_input",
    }
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        config_path.write_text(config_text, encoding="utf-8")
    except Exception:
        pass
    try:
        vpn_utils.enrich_ip_info([node])
        # Manual nodes used to keep country="" even after IP enrichment. That
        # made the UI fall back to 🌐 and made the country filter unable to
        # include the manually-added endpoint. Persist the first location token
        # as the canonical country and keep the translated Chinese label.
        if not str(node.get("country") or "").strip():
            location = str(node.get("location") or "").strip()
            country_token = location.split()[0] if location else ""
            if country_token:
                node["country"] = vpn_utils.COUNTRY_TRANSLATIONS.get(country_token, country_token)
    except Exception:
        pass
    return node

def _manual_probe_openvpn(host: str, ip: str, port: int, transport: str = "tcp", timeout: int = 9) -> dict[str, Any]:
    transport = str(transport or "tcp").strip().lower()
    if transport not in ("tcp", "udp"):
        transport = "tcp"
    started = time.perf_counter()
    template = _manual_openvpn_template()
    if not template:
        return {
            "protocol": "openvpn",
            "transport": transport,
            "port": int(port),
            "ok": False,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "message": "本机没有可复用的 VPN Gate OpenVPN 配置模板",
        }
    test_id = safe_name(f"MANUAL_TEST_{host}_{port}_{transport}")
    temp_path = test_config_path(test_id)
    idx = None
    try:
        config_text = re.sub(r"(?m)^remote\s+\S+\s+\d+\s*$", f"remote {host} {int(port)}", template, count=1)
        config_text = re.sub(r"(?m)^proto\s+\S+\s*$", f"proto {transport}", config_text, count=1)
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(config_text, encoding="utf-8")
        idx = get_free_test_index()
        ok, message, _process = run_openvpn_until_ready(
            str(temp_path), keep_alive=False, route_nopull=True, timeout=int(timeout), dev=f"tun{idx}"
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return {
            "protocol": "openvpn",
            "transport": transport,
            "port": int(port),
            "ok": bool(ok),
            "elapsed_ms": elapsed_ms,
            "message": "OpenVPN 隧道建立成功" if ok else message,
        }
    except Exception as exc:
        return {
            "protocol": "openvpn",
            "transport": transport,
            "port": int(port),
            "ok": False,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "message": str(exc),
        }
    finally:
        if idx is not None:
            release_test_index(idx)
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass


def _manual_probe_protocol(host: str, ip: str, protocol: str, port: int, transport: str = "tcp") -> dict[str, Any]:
    protocol = str(protocol or "").strip().lower()
    transport = str(transport or "tcp").strip().lower()
    started = time.perf_counter()
    token = uuid.uuid4().hex[:8]
    try:
        if protocol == "openvpn":
            return _manual_probe_openvpn(host, ip, port, transport=transport)

        if protocol == "softether":
            if not tunnel_adapters.SoftEtherAdapter.available():
                return {"protocol": protocol, "transport": transport, "port": int(port), "ok": False, "elapsed_ms": 0, "message": "SSL-VPN 组件未安装"}
            adapter = tunnel_adapters.SoftEtherAdapter()
            account = f"manual{token}"
            nic = f"m{token}"
            result = adapter.connect(host=host, port=int(port) if int(port or 0) > 0 else 443, account=account, nic=nic, username="vpn", password="vpn")
            ok = bool(result and result.ok and result.interface)
            message = result.message if result else "SSL-VPN 未建立"
            if result is not None:
                try:
                    adapter.disconnect(account=account, nic=nic, delete=True, added_routes=((result.details or {}).get("added_host_routes") if result.details else []))
                except Exception:
                    pass
            return {"protocol": protocol, "transport": transport, "port": int(port), "ok": ok, "elapsed_ms": int((time.perf_counter() - started) * 1000), "message": "SSL-VPN 隧道建立成功" if ok else message}

        if protocol == "sstp":
            if not tunnel_adapters.SSTPAdapter.available():
                return {"protocol": protocol, "transport": transport, "port": int(port), "ok": False, "elapsed_ms": 0, "message": "MS-SSTP 组件未安装"}
            adapter = tunnel_adapters.SSTPAdapter()
            target = host if int(port or 0) in (0, 443) else f"{host}:{int(port)}"
            result = adapter.connect(target, username="vpn", password="vpn", timeout=10)
            ok = bool(result and result.ok and result.interface)
            message = result.message if result else "MS-SSTP 未建立"
            if result is not None:
                try:
                    tunnel_adapters.SSTPAdapter.disconnect(result.process, added_routes=((result.details or {}).get("added_host_routes") if result.details else []))
                except Exception:
                    pass
            return {"protocol": protocol, "transport": transport, "port": int(port), "ok": ok, "elapsed_ms": int((time.perf_counter() - started) * 1000), "message": "MS-SSTP 隧道建立成功" if ok else message}

        if protocol == "l2tp-ipsec":
            if not l2tp_adapter.available():
                return {"protocol": protocol, "transport": "udp", "port": 0, "ok": False, "elapsed_ms": 0, "message": "L2TP/IPsec 组件未安装"}
            namespace = f"aimili-manual-{token}"
            result = l2tp_adapter.connect(host=host, username="vpn", password="vpn", psk="vpn", namespace=namespace, timeout=12)
            ok = bool(result and result.ok and result.interface)
            message = result.message if result else "L2TP/IPsec 未建立"
            if result is not None and result.ok:
                try:
                    l2tp_adapter.disconnect(namespace)
                except Exception:
                    pass
            return {"protocol": protocol, "transport": "udp", "port": 0, "ok": ok, "elapsed_ms": int((time.perf_counter() - started) * 1000), "message": "L2TP/IPsec 隧道建立成功" if ok else message}

        return {"protocol": protocol, "transport": transport, "port": int(port), "ok": False, "elapsed_ms": 0, "message": "不支持的手动直连协议"}
    except Exception as exc:
        return {"protocol": protocol, "transport": transport, "port": int(port), "ok": False, "elapsed_ms": int((time.perf_counter() - started) * 1000), "message": str(exc)}


def _promote_manual_endpoint(host: str, ip: str, country: str, result: dict[str, Any], source_info: dict[str, Any] | None = None) -> dict[str, Any]:
    now = time.time()
    protocol = str(result.get("protocol") or "").lower()
    transport = str(result.get("transport") or "tcp").lower()
    port = int(result.get("port") or 0)
    source_info = source_info or {}

    # Immediately enrich manually-added endpoints so the row is usable in the
    # country/location filters as soon as the user clicks “完成”. The periodic
    # metadata loop remains a fallback, not a prerequisite for first display.
    enriched: dict[str, Any] = {"ip": ip or host, "remote_host": host}
    try:
        vpn_utils.enrich_ip_info([enriched])
    except Exception as exc:
        log_to_json("WARNING", "Probe", f"手工节点 IP 信息补全失败: {exc}")
    location = str(enriched.get("location") or "").strip()
    inferred_country = str(country or "").strip()
    if not inferred_country and location:
        country_prefixes = [
            "United Arab Emirates", "United Kingdom", "United States",
            "South Africa", "New Zealand", "Saudi Arabia", "Czech Republic",
            "Costa Rica", "Dominican Republic", "Hong Kong", "Taiwan",
            "Russian Federation", "Viet Nam", "Korea Republic of",
        ]
        location_lower = location.lower()
        for prefix in sorted(country_prefixes, key=len, reverse=True):
            if location_lower == prefix.lower() or location_lower.startswith(prefix.lower() + " "):
                inferred_country = prefix
                break
        if not inferred_country:
            inferred_country = location.split(" ", 1)[0]
    metadata_updates = {
        key: enriched.get(key) or ""
        for key in ("owner", "asn", "as_name", "location", "ip_type", "quality")
    }

    if protocol == "openvpn":
        node = _build_manual_openvpn_node(host, ip or host, port, transport=transport)
        if not node:
            raise RuntimeError("OpenVPN 已建立成功，但当前实例没有可复用的配置模板，无法保存节点")
        node["country"] = inferred_country or node.get("country") or ""
        for key, value in metadata_updates.items():
            if value:
                node[key] = value
        node["manual_added_at"] = now
        node["manual_source"] = "direct_connection"
        node["probe_status"] = "available"
        node["probe_message"] = "手动直连验证通过"
        node["probed_at"] = now
        node["latency_ms"] = int(result.get("elapsed_ms") or 0)
        node_pool.upsert_openvpn_snapshot([node], source="manual_direct")
        node_pool.record_probe(node, ok=True, latency_ms=int(result.get("elapsed_ms") or 0), message="手动直连验证通过")
        with lock:
            nodes = read_nodes()
            nodes = [item for item in nodes if str(item.get("id") or "") != str(node.get("id") or "")]
            nodes.append(node)
            write_json(NODES_FILE, sort_all_nodes(nodes))
        _invalidate_ui_nodes_cache()
        return node

    server = {
        "hostname": host,
        "ip": ip or host,
        "country": inferred_country or "",
        "protocols": [{"protocol": protocol, "transport": transport, "port": port}],
        "source_count": 1 if source_info.get("found") else 0,
        "trusted_observation": True,
        "_sources": list(source_info.get("sources") or ["manual_direct"]),
        "manual_added_at": now,
    }
    node_pool.upsert_discovery_snapshot([server], source="manual_direct")
    if any(metadata_updates.values()) and (ip or host):
        node_pool.update_server_metadata_batch({str(ip or host): metadata_updates})
    endpoint_id = node_pool.endpoint_id(node_pool.server_key(server), protocol, transport, port)
    node_pool.record_endpoint_probe(endpoint_id, ok=True, latency_ms=int(result.get("elapsed_ms") or 0), message="手动直连验证通过")
    endpoint = node_pool.get_endpoint(endpoint_id)
    if not endpoint:
        raise RuntimeError("直连已通过，但写入 Master Pool 后无法读取协议端点")
    ui_node = protocol_endpoint_to_ui_node(endpoint)
    ui_node["manual_added_at"] = now
    ui_node["manual_source"] = "direct_connection"
    ui_node["probe_status"] = "available"
    ui_node["probe_message"] = "手动直连验证通过"
    ui_node["probed_at"] = now
    ui_node["latency_ms"] = int(result.get("elapsed_ms") or 0)
    with lock:
        nodes = read_nodes()
        nodes = [item for item in nodes if not (str(item.get("pool_endpoint_id") or "") == endpoint_id or str(item.get("id") or "") == "pool:" + endpoint_id)]
        nodes.append(ui_node)
        write_json(NODES_FILE, sort_all_nodes(nodes))
    _invalidate_ui_nodes_cache()
    return ui_node


def manual_direct_verify(value: str, promote: bool = True) -> dict[str, Any]:
    host, port = parse_manual_endpoint(value)
    resolved_ip = host
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", resolved_ip) and ":" not in resolved_ip:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET)
            if infos:
                resolved_ip = str(infos[0][4][0])
        except Exception:
            resolved_ip = host

    if not manual_add_probe_lock.acquire(blocking=False):
        raise RuntimeError("已有手动节点直连验证任务正在运行，请稍候")

    try:
        source_info = {"found": False, "sources": []}
        official = None
        if host.lower().endswith(".opengw.net"):
            try:
                official = vpngate_discovery.fetch_openvpn_endpoint_page(host, timeout=4)
            except Exception:
                official = None
            if official:
                source_info = {"found": True, "sources": list(official.get("_sources") or [])}

        official_protocols: dict[str, list[tuple[str, int]]] = {}
        if official:
            for item in official.get("protocols") or []:
                p = str(item.get("protocol") or "").lower()
                t = str(item.get("transport") or "tcp").lower()
                pport = int(item.get("port") or 0)
                # L2TP/IPsec is an exception: VPN Gate advertises it as a
                # supported protocol but there is no TCP/UDP service port to
                # parse from the table. The adapter handles it as IKE/UDP 500
                # + NAT-T/UDP 4500 internally, so keep a zero-port marker.
                if p and (pport > 0 or p == "l2tp-ipsec"):
                    official_protocols.setdefault(p, []).append((t if p != "l2tp-ipsec" else "udp", pport))

        attempts: list[dict[str, Any]] = []
        added_nodes: list[dict[str, Any]] = []
        successful_protocols: list[str] = []
        protocol_order = ["openvpn", "softether", "l2tp-ipsec", "sstp"]

        for protocol in protocol_order:
            offered = official_protocols.get(protocol) or []
            default_transport = "udp" if protocol == "l2tp-ipsec" else "tcp"

            # With a VPN Gate hostname and no explicit port, use every
            # advertised endpoint for that protocol until one really connects.
            # This is important because OpenVPN may advertise a TCP and a UDP
            # port, while SSL-VPN/SSTP use the published TCP port.
            if official and not offered:
                attempts.append({
                    "protocol": protocol,
                    "transport": default_transport,
                    "port": 0 if protocol == "l2tp-ipsec" else int(port),
                    "ok": False,
                    "skipped": True,
                    "message": f"当前节点未公布 {protocol} 接入方式",
                })
                continue

            if protocol == "l2tp-ipsec":
                candidates = [("udp", 0)]
            else:
                candidates = offered if official else [(default_transport, int(port))]
            protocol_passed = False
            for transport, test_port in candidates:
                result = _manual_probe_protocol(host, resolved_ip, protocol, int(test_port), transport)
                attempts.append(result)
                if not result.get("ok"):
                    continue

                protocol_passed = True
                successful_protocols.append(protocol)
                promoted = _promote_manual_endpoint(
                    host,
                    resolved_ip,
                    str((official or {}).get("country") or ""),
                    result,
                    source_info=source_info,
                ) if promote else None
                if promoted:
                    added_nodes.append(promoted)
                break

            if not protocol_passed and not official and not port:
                attempts.append({
                    "protocol": protocol,
                    "transport": default_transport,
                    "port": 0,
                    "ok": False,
                    "skipped": True,
                    "message": "未提供端口，且当前地址无法从 VPN Gate 官方页面自动获取协议端口",
                })

        if successful_protocols:
            primary = next(
                (item for item in reversed(attempts)
                 if str(item.get("protocol") or "").lower() == successful_protocols[0] and item.get("ok")),
                {}
            )
            return {
                "ok": True,
                "mode": "direct_connection",
                "passed": True,
                "input": str(value or "").strip(),
                "hostname": host,
                "ip": resolved_ip,
                "country": (official or {}).get("country") or "",
                "protocol": primary.get("protocol"),
                "transport": primary.get("transport"),
                "port": primary.get("port"),
                "protocols": successful_protocols,
                "attempts": attempts,
                "added": bool(added_nodes),
                "added_nodes": added_nodes,
                "source_count": 1 if source_info.get("found") else 0,
                "sources": source_info.get("sources") or [],
                "message": (
                    f"直连验证完成：{len(successful_protocols)} 种协议通过，"
                    f"{'已全部写入资源池并加入筛选列表。' if promote else ''}"
                ),
            }

        return {
            "ok": False,
            "mode": "direct_connection",
            "passed": False,
            "input": str(value or "").strip(),
            "hostname": host,
            "ip": resolved_ip,
            "attempts": attempts,
            "added": False,
            "added_nodes": [],
            "source_count": 1 if source_info.get("found") else 0,
            "sources": source_info.get("sources") or [],
            "error": "4 种 VPN Gate 接入方式均未建立成功，节点未加入资源池。",
        }
    finally:
        manual_add_probe_lock.release()


def _kick_manual_availability_check() -> None:
    # 新增资源立即进入持久化可用性检测引擎；若当前正处于连接/维护临界区，
    # 短暂重试而不阻塞前端“添加节点”请求。
    for _ in range(10):
        try:
            result = availability_sweep_once("")
            if not result.get("skipped") and not result.get("running"):
                return
        except Exception as exc:
            log_to_json("WARNING", "Probe", f"新增节点即时可用性检测触发失败: {exc}")
        time.sleep(2)

def add_manual_vpngate_node(value: str) -> dict[str, Any]:
    result = manual_direct_verify(value, promote=True)
    if result.get("ok"):
        set_state(
            last_check_message="新增节点已入库 · 已通知可用性检测模块，后台立即复核其余协议端点",
            availability_engine_message="新增节点已入库 · 已通知可用性检测模块，正在立即复核",
        )
        threading.Thread(target=_kick_manual_availability_check, daemon=True, name="manual-add-availability").start()
        result["detection_queued"] = True
        result["message"] = "节点已入库，并已立即通知可用性检测模块继续复核。"
    return result


def refresh_protocol_ip_metadata(max_ips: int = 100) -> int:
    """Fill ISP, ASN, location and IP-type for multi-protocol server records from the shared IP cache/query."""
    endpoints = node_pool.list_endpoints(limit=1000)
    seen: set[str] = set()
    probe_nodes: list[dict[str, Any]] = []
    for endpoint in endpoints:
        protocol = str(endpoint.get("protocol") or "").lower()
        if protocol == "openvpn":
            continue
        ip = str(endpoint.get("current_ip") or (endpoint.get("metadata") or {}).get("ip") or "").strip()
        if not ip or ip in seen:
            continue
        meta = endpoint.get("server_metadata") or {}
        if all(str(meta.get(k) or "").strip() for k in ("owner", "as_name", "ip_type", "location")):
            continue
        seen.add(ip)
        probe_nodes.append({"ip": ip, "remote_host": ip})
        if len(probe_nodes) >= max(1, int(max_ips)):
            break

    if not probe_nodes:
        return 0
    try:
        vpn_utils.enrich_ip_info(probe_nodes)
    except Exception as exc:
        log_to_json("WARNING", "Main", f"多协议 IP/ISP 信息补全失败: {exc}")
        return 0
    updates: dict[str, dict[str, Any]] = {}
    for node in probe_nodes:
        ip = str(node.get("ip") or "").strip()
        if not ip:
            continue
        updates[ip] = {
            "owner": node.get("owner") or "",
            "asn": node.get("asn") or "",
            "as_name": node.get("as_name") or "",
            "location": node.get("location") or "",
            "ip_type": node.get("ip_type") or "",
            "quality": node.get("quality") or "",
        }
    updated = node_pool.update_server_metadata_batch(updates)
    if updated:
        log_to_json("INFO", "Main", f"多协议 IP/ISP 信息补全 {updated} 台服务器")
    return updated

def protocol_catalog_loop() -> None:
    # Initial catalog refresh shortly after startup, then refresh periodically.
    time.sleep(10)
    while True:
        try:
            if ui_command_plane.is_busy() or global_pool_refresh_running:
                time.sleep(5)
                continue
            if not ISOLATED_INSTANCE:
                refresh_multi_protocol_catalog(force=True)
                refresh_protocol_ip_metadata(max_ips=100)
        except Exception as exc:
            log_to_json("WARNING", "Main", f"多协议目录后台刷新异常: {exc}")
        time.sleep(600)


def resource_share_loop() -> None:
    # The loop is only a lightweight scheduler sweep. Each Peer decides when
    # its next real sync is due according to its configured hour/day/week interval.
    time.sleep(45)
    while True:
        try:
            if ui_command_plane.is_busy() or global_pool_refresh_running:
                time.sleep(5)
                continue
            peers = resource_share.list_peers()
            if peers:
                results = resource_share.sync_all(force=False)
                actual = [item for item in results if not item.get("skipped")]
                if actual:
                    ok_count = sum(1 for item in actual if item.get("ok"))
                    log_to_json("INFO", "Share", f"资源共享周期同步完成：{ok_count}/{len(actual)} 个实际同步任务完成")
        except Exception as exc:
            log_to_json("WARNING", "Share", f"资源共享调度扫描异常: {exc}")
        time.sleep(RESOURCE_SHARE_SYNC_INTERVAL_SECONDS)


def _wait_for_automatic_connection_idle(timeout: float = 30.0) -> None:
    deadline = time.time() + float(timeout)
    warned = False
    while True:
        with lock:
            busy = bool(is_connecting)
        if not busy:
            return
        if not warned:
            warned = True
            set_state(
                last_check_message="人工操作已获得优先权，正在等待当前自动连接任务收尾；不会再启动新的自动连接。"
            )
        if time.time() >= deadline:
            raise RuntimeError("当前自动连接任务收尾超时，人工切换未强行并发执行。请稍后重试。")
        time.sleep(0.25)

def connect_pool_endpoint(endpoint_id: str, manual: bool = False) -> str:
    global active_external_tunnel, active_pool_endpoint_id, active_openvpn_node_id, is_connecting, manual_connection_active, manual_connection_epoch, connection_generation, active_connection_generation
    endpoint_id = str(endpoint_id or "").strip()
    endpoint = node_pool.get_endpoint(endpoint_id)
    if endpoint is None:
        raise ValueError("Protocol endpoint not found")
    protocol = str(endpoint.get("protocol") or "").lower()
    metadata = endpoint.get("metadata") or {}
    if protocol not in ("softether", "sstp", "l2tp-ipsec"):
        raise RuntimeError(f"协议 {protocol} 当前尚未开放生产连接")

    # Manual switching performs a real production tunnel + egress verification
    # below, so a second pre-probe is skipped. Background validation keeps the
    # original multi-source probe path. A failed validation is still recorded.
    if not metadata.get("trusted_observation") and not manual:
        probe_result = None
        for _ in range(3):
            probe_result = probe_pool_endpoint(endpoint_id)
            if probe_result.get("ok"):
                endpoint = node_pool.get_endpoint(endpoint_id) or endpoint
                metadata = endpoint.get("metadata") or {}
                break
            if probe_result.get("skipped"):
                time.sleep(1)
                continue
            break
        if not probe_result or not probe_result.get("ok"):
            reason = str((probe_result or {}).get("error") or "实时验证失败")
            raise RuntimeError(f"该端点尚未完成多源确认，已先进行实时协议验证，但验证未通过：{reason}")

        # Reload the endpoint after a successful live probe because the probe
        # updates lifecycle state and latency in Master Pool.
        endpoint = node_pool.get_endpoint(endpoint_id) or endpoint
        metadata = endpoint.get("metadata") or {}

    if protocol == "softether" and not tunnel_adapters.SoftEtherAdapter.available():
        raise RuntimeError("SoftEther 客户端组件未安装")
    if protocol == "sstp" and not tunnel_adapters.SSTPAdapter.available():
        raise RuntimeError("SSTP 客户端组件未安装")
    if protocol == "l2tp-ipsec":
        l2tp_env = tunnel_adapters.L2TPIPsecAdapter.environment_report(run_kernel_test=False)
        if not l2tp_env.get("ready"):
            raise RuntimeError(f"L2TP/IPsec 隔离环境未就绪: {l2tp_env}")

    manual_guard = False
    if manual:
        if not manual_connection_lock.acquire(blocking=False):
            raise RuntimeError("已有人工连接操作正在执行，请等待当前切换完成")
        manual_guard = True
        with lock:
            if manual_connection_active:
                manual_connection_lock.release()
                manual_guard = False
                raise RuntimeError("当前已有手动连接任务正在运行，请稍候")
            manual_connection_epoch += 1
            manual_connection_active = True
        set_state(
            manual_switch_active=True,
            manual_switch_started_at=time.time(),
            pending_connection_id=endpoint_id,
            pending_connection_pool_endpoint_id=endpoint_id,
            pending_connection_protocol=protocol,
            pending_connection_country=str(endpoint.get("country") or ""),
            pending_connection_address=(
                str(metadata.get("ip") or metadata.get("hostname") or endpoint.get("hostname") or endpoint.get("current_ip") or endpoint_id)
                + (f":{parse_int(endpoint.get('port'))}" if parse_int(endpoint.get('port')) else "")
            ),
            manual_switch_message=f"正在建立 {protocol} 安全隧道…",
            is_connecting=True,
            last_check_message=f"正在切换至 {protocol} 节点，请稍候…",
        )
    if manual and manual_guard:
        try:
            _wait_for_automatic_connection_idle()
        except Exception:
            with lock:
                manual_connection_active = False
            manual_connection_lock.release()
            manual_guard = False
            raise
    with lock:
        if is_connecting and not manual:
            if manual_guard:
                manual_connection_active = False
                manual_connection_lock.release()
                manual_guard = False
            raise RuntimeError("当前已有连接或节点检测任务正在运行，请稍后再试")
        is_connecting = True

    result: tunnel_adapters.TunnelResult | None = None
    promoted = False
    token = re.sub(r"[^a-z0-9]", "", endpoint_id.lower())[:8] or uuid.uuid4().hex[:8]

    def cleanup_new() -> None:
        if result is None:
            return
        try:
            if result.protocol == "softether":
                details = result.details or {}
                tunnel_adapters.SoftEtherAdapter().disconnect(
                    account=str(details.get("account") or f"prod{token}"),
                    nic=str(details.get("nic") or f"a{token}"),
                    delete=True,
                    added_routes=details.get("added_host_routes") or [],
                )
            elif result.protocol == "sstp":
                details = result.details or {}
                tunnel_adapters.SSTPAdapter.disconnect(
                    result.process,
                    added_routes=details.get("added_host_routes") or [],
                )
            elif result.protocol == "l2tp-ipsec":
                l2tp_adapter.disconnect(result.namespace)
        except Exception:
            pass

    try:
        set_state(is_connecting=True, last_check_message=f"正在预连接并验证 {protocol} 端点 {endpoint_id}")

        metadata = endpoint.get("metadata") or {}
        host = str(metadata.get("hostname") or endpoint.get("hostname") or endpoint.get("current_ip") or "").strip()
        if not host:
            raise RuntimeError("端点缺少可连接的 Hostname/IP")
        port = parse_int(endpoint.get("port"))

        # Make-before-break: establish a completely separate candidate tunnel
        # while the existing production 8500 path continues serving traffic.
        if manual:
            set_state(manual_switch_message=f"正在建立 {protocol} 安全隧道…")
        if protocol == "softether":
            result = tunnel_adapters.SoftEtherAdapter().connect(
                host=host,
                port=port or 443,
                account=f"prod{token}",
                nic=f"a{token}",
                username="vpn",
                password="vpn",
            )
        elif protocol == "sstp":
            result = tunnel_adapters.SSTPAdapter().connect(
                hostname=host if port in (0, 443) else f"{host}:{port}",
                username="vpn",
                password="vpn",
                timeout=20,
            )
        else:
            result = l2tp_adapter.connect(
                host=host,
                username="vpn",
                password="vpn",
                psk="vpn",
                namespace=f"aimili-l2tp-{token}",
                timeout=35,
            )

        if not result.ok or not result.interface:
            node_pool.record_endpoint_probe(endpoint_id, False, 0, result.message)
            raise RuntimeError(result.message or f"{protocol} 连接失败")

        if manual:
            set_state(manual_switch_message="目标隧道已建立，正在验证真实出口与网络质量…", last_check_message="目标节点已建立隧道，正在进行真实出口验证…")
        direct_health = (
            tunnel_adapters.L2TPIPsecAdapter.egress_check(result)
            if protocol == "l2tp-ipsec"
            else check_interface_egress(result.interface, result.gateway)
        )
        if not direct_health.get("ok"):
            message = str(direct_health.get("error") or "候选隧道出口检测失败")
            node_pool.record_endpoint_probe(endpoint_id, False, 0, message)
            raise RuntimeError(message)

        # Candidate is independently verified. Only now release the old tunnel.
        if manual:
            set_state(manual_switch_message="目标节点验证通过，正在平滑接管当前连接…", last_check_message="目标节点验证通过，正在平滑切换；原连接暂时保持。")
        if active_external_tunnel is not None:
            stop_active_external_tunnel()
        if active_openvpn_running():
            stop_active_openvpn()

        active_external_tunnel = result
        active_pool_endpoint_id = endpoint_id
        active_openvpn_node_id = ""
        proxy_server.set_active_interface(result.interface)
        setup_policy_routing(result.interface, gateway=result.gateway)
        promoted = True

        connection_generation += 1
        active_connection_generation = connection_generation

        health = check_proxy_health()
        if not health.get("ok"):
            node_pool.record_endpoint_probe(endpoint_id, False, 0, str(health.get("error") or "8500 代理出口检测失败"))
            stop_active_external_tunnel()
            raise RuntimeError(str(health.get("error") or "8500 代理出口检测失败"))

        latency = parse_int(health.get("latency_ms")) or parse_int(direct_health.get("latency_ms"))
        node_pool.record_endpoint_probe(endpoint_id, True, latency, "production connect ok")
        if manual:
            set_manual_route_pin(protocol=protocol, endpoint_id=endpoint_id)
        set_state(
            active_pool_endpoint_id=endpoint_id,
            active_tunnel_protocol=protocol,
            manual_switch_message=("切换完成，正在确认客户端状态…" if manual else ""),
            active_tunnel_interface=result.interface,
            proxy_ok=True,
            proxy_ip=health.get("ip", ""),
            proxy_latency_ms=latency,
            proxy_error="",
            is_connecting=False,
            last_check_message=f"Connected {protocol} {endpoint_id}",
        )
        log_to_json(
            "INFO",
            "VPN",
            f"{protocol} 候选隧道验证成功后接管 8500，接口 {result.interface}",
        )
        return f"Connected {protocol} endpoint {endpoint_id}"
    except Exception:
        if not promoted:
            cleanup_new()
        raise
    finally:
        is_connecting = False
        if manual_guard:
            with lock:
                manual_connection_active = False
            manual_connection_lock.release()

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    now = time.time()

    def manual_sort_key(node: dict[str, Any]) -> tuple[int, float]:
        ts = float(node.get("manual_added_at") or 0)
        recent = bool(ts and now - ts <= 3600)
        return (0 if recent else 1, -ts if recent else 0.0)

    available_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "available" or n.get("active")],
        key=lambda n: (
            0 if n.get("active") else 1,
            manual_sort_key(n),
            0 if n.get("ip_type") in ("residential", "mobile") else 1,
            parse_int(n.get("latency_ms")) or 999999,
            -parse_int(n.get("score"))
        )
    )
    untested_nodes = sorted(
        [n for n in nodes if n.get("probe_status") in ("not_checked", "testing") and not n.get("active")],
        key=lambda n: (manual_sort_key(n), -parse_int(n.get("score")), parse_int(n.get("ping")))
    )
    unavailable_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "unavailable" and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), -float(n.get("probed_at", 0)))
    )
    return available_nodes + untested_nodes + unavailable_nodes

_COUNTRY_REGION_GROUPS = {
    "east_asia": {"中国", "日本", "韩国", "台湾", "香港", "澳门", "蒙古"},
    "southeast_asia": {"新加坡", "马来西亚", "印度尼西亚", "泰国", "越南", "菲律宾", "柬埔寨"},
    "south_asia": {"印度"},
    "north_america": {"美国", "加拿大", "墨西哥"},
    "south_america": {"巴西", "阿根廷", "智利", "哥伦比亚"},
    "europe": {"英国", "爱尔兰", "法国", "德国", "荷兰", "比利时", "卢森堡", "瑞士", "奥地利", "意大利", "西班牙", "葡萄牙", "波兰", "捷克", "匈牙利", "罗马尼亚", "希腊", "瑞典", "挪威", "丹麦", "芬兰", "冰岛", "乌克兰", "土耳其", "格鲁吉亚"},
    "middle_east": {"以色列", "阿联酋", "沙特阿拉伯", "伊朗", "伊拉克"},
    "central_asia": {"哈萨克斯坦"},
    "oceania": {"澳大利亚", "新西兰"},
    "africa": {"南非", "埃及"},
}

def country_region(country: Any) -> str:
    normalized = normalized_country_name(country)
    for region, countries in _COUNTRY_REGION_GROUPS.items():
        if normalized in countries:
            return region
    return ""

def country_preference_rank(target_country: Any, candidate_country: Any) -> int:
    target = normalized_country_name(target_country)
    candidate = normalized_country_name(candidate_country)
    if not target:
        return 0
    if candidate == target:
        return 0
    target_region = country_region(target)
    candidate_region = country_region(candidate)
    if target_region and target_region == candidate_region:
        return 1
    return 2

def ip_type_preference_rank(preferred: str, actual: Any) -> int:
    preferred = str(preferred or "all").lower()
    actual = str(actual or "").lower()
    # Fixed product order: mobile -> residential -> hosting -> proxy -> other.
    ranks = {
        "all": {"mobile": 0, "residential": 1, "hosting": 2, "proxy": 3, "unknown": 4},
        "mobile": {"mobile": 0, "residential": 1, "hosting": 2, "proxy": 3, "unknown": 4},
        "residential": {"residential": 0, "mobile": 1, "hosting": 2, "proxy": 3, "unknown": 4},
        "hosting": {"hosting": 0, "mobile": 1, "residential": 2, "proxy": 3, "unknown": 4},
    }
    return ranks.get(preferred, ranks["all"]).get(actual, 4)


def endpoint_ip_type(endpoint: dict[str, Any]) -> str:
    meta = endpoint.get("server_metadata") or {}
    if meta.get("ip_type"):
        return str(meta.get("ip_type") or "")
    return str((endpoint.get("metadata") or {}).get("ip_type") or "")

ROUTING_MIN_LINE_SPEED_BPS = 50_000_000
ROUTING_HIGH_SPEED_BPS = 500_000_000

def routing_target_country(ui_cfg: dict[str, Any]) -> str:
    """Explicit country preference first; otherwise use the server's own country."""
    explicit = str(ui_cfg.get("force_country") or "").strip()
    if explicit:
        return normalized_country_name(explicit)
    try:
        bootstrap = _read_bootstrap_state()
        local = str(bootstrap.get("local_server_country") or "").strip()
        if local:
            return normalized_country_name(local)
    except Exception:
        pass
    try:
        state = get_state()
        local = str(state.get("server_country") or "").strip()
        if local:
            return normalized_country_name(local)
    except Exception:
        pass
    return ""

def routing_favorite_rank(endpoint: dict[str, Any], ui_cfg: dict[str, Any]) -> int:
    favorites = {str(x) for x in (ui_cfg.get("favorite_node_ids") or []) if str(x)}
    if not favorites:
        return 1
    endpoint_id = str(endpoint.get("endpoint_id") or "")
    metadata = endpoint.get("metadata") or {}
    variants = {endpoint_id, "pool:" + endpoint_id if endpoint_id else "", str(metadata.get("node_id") or "")}
    return 0 if favorites.intersection(variants) else 1

def routing_speed_gate(endpoint: dict[str, Any]) -> int:
    """Global speed ladder: >=500 Mbps, >=50 Mbps, then <50 Mbps fallback."""
    speed = int(endpoint.get("latest_speed") or endpoint.get("speed") or 0)
    if speed >= ROUTING_HIGH_SPEED_BPS:
        return 0
    if speed >= ROUTING_MIN_LINE_SPEED_BPS:
        return 1
    return 2

def routing_web_health_rank(endpoint: dict[str, Any]) -> int:
    status = str(endpoint.get("status") or "").upper()
    return {"HOT": 0, "AVAILABLE": 1, "DEGRADED": 2}.get(status, 3)

def routing_preference_tier(endpoint: dict[str, Any], ui_cfg: dict[str, Any]) -> int:
    if ui_cfg.get("routing_mode") == "fixed_ip":
        return 99
    target_country = routing_target_country(ui_cfg)
    country_rank = 0 if target_country and normalized_country_name(endpoint.get("country")) == target_country else 2
    favorite_rank = routing_favorite_rank(endpoint, ui_cfg)
    ip_rank = ip_type_preference_rank(ui_cfg.get("routing_ip_type", "all"), endpoint_ip_type(endpoint))
    speed_gate = routing_speed_gate(endpoint)
    return country_rank * 1000 + favorite_rank * 100 + ip_rank * 20 + speed_gate * 5

def routing_service_key(endpoint: dict[str, Any], ui_cfg: dict[str, Any]) -> tuple:
    latency = float(endpoint.get("latency_ewma") or endpoint.get("latency_ms") or 999999)
    if latency <= 0:
        latency = 999999
    speed = int(endpoint.get("latest_speed") or endpoint.get("speed") or 0)
    jitter = float(endpoint.get("jitter_ewma") or 999999)
    success_streak = int(endpoint.get("success_streak") or 0)
    return (
        routing_preference_tier(endpoint, ui_cfg),
        routing_speed_gate(endpoint),
        -speed,
        latency,
        routing_web_health_rank(endpoint),
        -float(endpoint.get("last_success") or 0),
        jitter,
        -success_streak,
    )

def openvpn_node_to_routing_endpoint(node: dict[str, Any]) -> dict[str, Any]:
    key = node_pool.server_key(node)
    eid = openvpn_pool_endpoint_id(node)
    return {
        "endpoint_id": eid,
        "server_key": key,
        "protocol": "openvpn",
        "transport": str(node.get("proto") or ""),
        "port": parse_int(node.get("remote_port")),
        "status": "HOT" if node.get("probe_status") == "available" and parse_int(node.get("latency_ms")) > 0 else "NEW",
        "first_seen": float(node.get("fetched_at") or 0),
        "last_seen": float(node.get("fetched_at") or 0),
        "last_success": float(node.get("probed_at") or 0),
        "success_streak": 1 if node.get("probe_status") == "available" else 0,
        "fail_streak": 0,
        "latency_ewma": float(node.get("latency_ms") or 0),
        "jitter_ewma": 0,
        "latest_ping": int(node.get("ping") or 0),
        "latest_speed": int(node.get("speed") or 0),
        "latest_sessions": int(node.get("sessions") or 0),
        "latest_server_score": int(node.get("score") or 0),
        "country": node.get("country") or "",
        "hostname": node.get("host_name") or node.get("remote_host") or node.get("ip") or "",
        "current_ip": node.get("ip") or node.get("remote_host") or "",
        "metadata": {
            "node_id": node.get("id") or "",
            "trusted_observation": True,
        },
        "server_metadata": {
            "owner": node.get("owner") or "",
            "asn": node.get("asn") or "",
            "as_name": node.get("as_name") or "",
            "location": node.get("location") or "",
            "ip_type": node.get("ip_type") or "",
            "quality": node.get("quality") or "",
        },
    }

def routing_node_service_key(node: dict[str, Any], ui_cfg: dict[str, Any]) -> tuple[int, int, float, int, float, int, float]:
    return routing_service_key(openvpn_node_to_routing_endpoint(node), ui_cfg)

def unified_hot_pool_candidates(ui_cfg: dict[str, Any], exclude_endpoint_id: str = "", limit: int = 100) -> list[dict[str, Any]]:
    endpoints: dict[str, dict[str, Any]] = {}

    # Routing must use the persistent Master Pool, not the small front-end
    # snapshot. The UI may show only a page of nodes; backend failover must see
    # every verified HOT/AVAILABLE endpoint.
    try:
        for endpoint in node_pool.list_endpoints(limit=5000):
            eid = str(endpoint.get("endpoint_id") or "")
            status = str(endpoint.get("status") or "").upper()
            protocol = str(endpoint.get("protocol") or "").lower()
            if (
                eid
                and status in ("HOT", "AVAILABLE")
                and protocol in ("openvpn", "softether", "sstp", "l2tp-ipsec")
                and (
                    protocol == "openvpn"
                    or bool((endpoint.get("metadata") or {}).get("trusted_observation"))
                )
            ):
                endpoints[eid] = endpoint
    except Exception as exc:
        log_to_json("WARNING", "Routing", f"Master Pool 读取失败: {exc}")

    # Keep a small secondary source from nodes.json for freshly fetched OpenVPN
    # observations that have not yet been materialized into the pool snapshot.
    for node in read_nodes():
        if node.get("probe_status") != "available" or node.get("active"):
            continue
        endpoint = openvpn_node_to_routing_endpoint(node)
        if endpoint.get("endpoint_id") and endpoint.get("endpoint_id") not in endpoints:
            endpoints[endpoint["endpoint_id"]] = endpoint
    candidates = []
    for endpoint in endpoints.values():
        eid = str(endpoint.get("endpoint_id") or "")
        if not eid or eid == exclude_endpoint_id:
            continue
        if endpoint.get("status") not in ("HOT", "AVAILABLE"):
            continue
        if str(endpoint.get("protocol") or "").lower() != "openvpn" and not bool((endpoint.get("metadata") or {}).get("trusted_observation")):
            continue
        endpoint["routing_tier"] = routing_preference_tier(endpoint, ui_cfg)
        target_country = routing_target_country(ui_cfg)
        endpoint["routing_country_rank"] = 0 if target_country and normalized_country_name(endpoint.get("country")) == target_country else 2
        endpoint["routing_favorite_rank"] = routing_favorite_rank(endpoint, ui_cfg)
        endpoint["routing_ip_rank"] = ip_type_preference_rank(ui_cfg.get("routing_ip_type", "all"), endpoint_ip_type(endpoint))
        endpoint["routing_speed_gate"] = routing_speed_gate(endpoint)
        endpoint["routing_web_health_rank"] = routing_web_health_rank(endpoint)
        candidates.append(endpoint)
    candidates.sort(key=lambda endpoint: routing_service_key(endpoint, ui_cfg))
    return candidates[:max(1, min(int(limit), 100))]

def current_active_routing_endpoint() -> dict[str, Any] | None:
    if active_pool_endpoint_id:
        return node_pool.get_endpoint(active_pool_endpoint_id)
    if active_openvpn_node_id:
        node = next((n for n in read_nodes() if n.get("id") == active_openvpn_node_id), None)
        return openvpn_node_to_routing_endpoint(node) if node else None
    return None

def maybe_recover_preferred_route(force: bool = False) -> bool:
    if manual_route_pin or ui_command_plane.is_busy():
        return False
    ui_cfg = load_ui_config()
    if ui_cfg.get("routing_mode") in ("fixed_ip", "favorites") or not bool(ui_cfg.get("connection_enabled", True)):
        return False
    has_preference = (
        bool(routing_target_country(ui_cfg))
        or str(ui_cfg.get("routing_ip_type", "all")) != "all"
        or bool(ui_cfg.get("favorite_node_ids"))
    )
    if not has_preference:
        return False
    state = get_state()
    if bool(state.get("priority_running")):
        return False
    now = time.time()
    last_check = float(state.get("last_preference_recovery_at") or 0)
    if not force and now - last_check < 60:
        return False
    set_state(last_preference_recovery_at=now)
    current = current_active_routing_endpoint()
    if not current:
        return False
    if routing_preference_tier(current, ui_cfg) == 0:
        return False
    preferred = [
        ep for ep in unified_hot_pool_candidates(ui_cfg, limit=100)
        if int(ep.get("routing_country_rank") or 99) == 0
        and str(ep.get("status") or "").upper() in ("HOT", "AVAILABLE")
    ]
    if not preferred:
        return False
    target = preferred[0]
    try:
        ok = try_unified_failover(exclude_endpoint_id=str(current.get("endpoint_id") or ""), attempts=3, preferred_only=True)
        if ok:
            set_state(preference_recovery_at=time.time(), preference_recovery_endpoint=str(target.get("endpoint_id") or ""), last_check_message="已恢复用户设定的国家/IP类型偏好")
        return ok
    except Exception as exc:
        log_to_json("WARNING", "Routing", f"偏好路由恢复失败: {exc}")
        return False

def apply_user_routing_preferences() -> None:
    try:
        ui_cfg = load_ui_config()
        if not bool(ui_cfg.get("connection_enabled", True)):
            return
        if ui_cfg.get("routing_mode") == "fixed_ip":
            return
        # Country/IP/favorites are all soft preferences. The same ranking and
        # availability fallback is used for every automatic mode.
        target_country = str(ui_cfg.get("force_country") or "").strip()
        if target_country:
            priority_result = start_country_priority(target_country)
            if priority_result.get("running"):
                return
        if active_tunnel_running():
            maybe_recover_preferred_route(force=True)
        else:
            auto_switch_node()
    except Exception as exc:
        log_to_json("WARNING", "Routing", f"应用用户路由偏好失败: {exc}")

def apply_routing_filters(
    nodes: list[dict[str, Any]],
    ui_cfg: dict[str, Any],
    include_unknown_ip_type: bool = False,
) -> list[dict[str, Any]]:
    # Automatic routing preferences are soft; availability always wins when
    # the preferred pool is empty.
    return list(nodes)

def normalized_country_name(country: Any) -> str:
    value = str(country or "").strip()
    return vpn_utils.COUNTRY_TRANSLATIONS.get(value, value)

def country_matches(node_country: Any, target_country: Any) -> bool:
    return bool(target_country) and normalized_country_name(node_country) == normalized_country_name(target_country)

def probe_priority_key(node: dict[str, Any]) -> tuple[int, int, int, int]:
    ping = parse_int(node.get("ping")) or 999999
    return (
        ping,
        -parse_int(node.get("score")),
        -parse_int(node.get("speed")),
        parse_int(node.get("sessions")),
    )

def current_fixed_node_id(ui_cfg: dict[str, Any]) -> str:
    if active_openvpn_node_id:
        return active_openvpn_node_id
    nodes = read_nodes()
    active_node = next((n for n in nodes if n.get("active") and n.get("id")), None)
    if active_node:
        return str(active_node.get("id") or "")
    return str(ui_cfg.get("fixed_node_id") or "").strip()

def validate_node_allowed_by_routing(node: dict[str, Any], ui_cfg: dict[str, Any]) -> None:
    # Country/IP/favorite rules are automatic preferences, not hard blocks.
    # Only fixed-IP mode is restricted to its explicitly selected node by its caller.
    return None

def enforce_active_node_allowed_by_routing(ui_cfg: dict[str, Any], reason: str = "路由规则已更新") -> str | None:
    active_id = active_openvpn_node_id
    if not active_id:
        return None

    nodes = read_nodes()
    active_node = next((item for item in nodes if item.get("id") == active_id), None)
    if not active_node:
        clear_active_connection_state(f"{reason}，当前活动节点已不在节点列表中，已断开连接")
        return "当前活动节点已不在节点列表中，已断开连接"

    try:
        validate_node_allowed_by_routing(active_node, ui_cfg)
        return None
    except Exception as exc:
        msg = f"{reason}，当前活动节点 {active_id} 不符合新规则，已断开连接: {exc}"
        print(f"[路由规则] {msg}", flush=True)
        log_to_json("WARNING", "Routing", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(
            active_openvpn_node_id="",
            active_node_latency="无活动连接",
            proxy_ok=False,
            proxy_ip="-",
            proxy_latency_ms=0,
            proxy_error=msg,
            last_check_message=msg,
        )

        if ui_cfg.get("connection_enabled", True) and ui_cfg.get("routing_mode") != "fixed_ip":
            threading.Thread(target=auto_switch_node, daemon=True).start()
        return msg

def reconnect_fixed_node_if_needed(ui_cfg: dict[str, Any]) -> bool:
    global is_connecting
    if ui_cfg.get("routing_mode") != "fixed_ip" or active_openvpn_running():
        return False
    target_id = current_fixed_node_id(ui_cfg)
    if not target_id:
        return False
    nodes = read_nodes()
    if not any(n.get("id") == target_id for n in nodes):
        return False

    print(f"[维护线程] 固定 IP 模式下 OpenVPN 未运行，正在重新拉起同一节点: {target_id}", flush=True)
    previous_connecting = is_connecting
    is_connecting = False
    try:
        connect_node(target_id)
        return active_openvpn_running()
    except Exception as e:
        print(f"[维护线程] 重新拉起固定节点 {target_id} 失败: {e}", flush=True)
        return False
    finally:
        is_connecting = previous_connecting

active_test_indexes = set()
test_indexes_lock = threading.Lock()

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        raise RuntimeError("没有可用的 OpenVPN 测试网卡编号，请稍后重试")

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def test_config_path(node_id: str) -> Path:
    safe_id = safe_name(node_id)
    return CONFIG_DIR / f".test_{safe_id}_{uuid.uuid4().hex}.ovpn"


def country_priority_snapshot(country: str) -> dict[str, Any]:
    target_country = str(country or "").strip()
    if not target_country:
        return {"country": "", "available": 0, "target": COUNTRY_AVAILABLE_TARGET, "minimum": COUNTRY_AVAILABLE_MIN}
    inventory_ips: set[str] = set()
    available_ips: set[str] = set()
    available_servers: set[str] = set()
    candidate_refs: list[dict[str, Any]] = []
    openvpn_nodes = read_nodes()
    for node in openvpn_nodes:
        if not country_matches(node.get("country"), target_country):
            continue
        status = str(node.get("probe_status") or "not_checked").lower()
        key = node_pool.server_key(node)
        ip = str(node.get("ip") or node.get("remote_host") or "").strip()
        if ip: inventory_ips.add(ip)
        if status == "available":
            if ip: available_ips.add(ip)
            available_servers.add(key)
        elif status in ("not_checked", "unavailable"):
            candidate_refs.append({"kind": "openvpn", "id": str(node.get("id") or ""), "server_key": key, "status": status, "probed_at": float(node.get("probed_at") or 0), "latency_ms": parse_int(node.get("latency_ms"))})
    try:
        endpoints = node_pool.list_endpoints(limit=5000)
    except Exception:
        endpoints = []
    for endpoint in endpoints:
        if str(endpoint.get("protocol") or "").lower() == "openvpn":
            continue
        if not country_matches(endpoint.get("country"), target_country):
            continue
        status = str(endpoint.get("status") or "NEW").upper()
        key = str(endpoint.get("server_key") or "")
        ip = str(endpoint.get("current_ip") or (endpoint.get("metadata") or {}).get("ip") or "").strip()
        if ip: inventory_ips.add(ip)
        if status in ("HOT", "AVAILABLE"):
            if ip: available_ips.add(ip)
            available_servers.add(key)
        elif status in ("NEW", "DEGRADED", "COOLDOWN"):
            candidate_refs.append({"kind": "pool", "id": "pool:" + str(endpoint.get("endpoint_id") or ""), "server_key": key, "status": status.lower(), "probed_at": float(endpoint.get("last_success") or endpoint.get("last_failure") or 0), "ready_at": float(endpoint.get("next_test") or 0), "latency_ms": parse_int(endpoint.get("latency_ewma"))})
    priority = {"not_checked": 0, "new": 0, "unavailable": 1, "degraded": 2, "cooldown": 3}
    now = time.time()
    candidate_refs = [
        x for x in candidate_refs
        if str(x.get("status")) in ("not_checked", "new")
        or (float(x.get("ready_at") or 0) <= now and now - float(x.get("probed_at") or 0) >= 900)
    ]
    candidate_refs.sort(key=lambda x: (priority.get(str(x.get("status")), 4), x.get("server_key") in available_servers, x.get("probed_at") or 0, x.get("latency_ms") or 999999))
    return {"country": target_country, "inventory": len(inventory_ips), "available": len(available_ips), "available_servers": len(available_servers), "target": COUNTRY_AVAILABLE_TARGET, "minimum": COUNTRY_AVAILABLE_MIN, "inventory_target": COUNTRY_INVENTORY_TARGET, "candidates": candidate_refs}

def _test_pool_reference(ref: dict[str, Any]) -> dict[str, Any]:
    kind = str(ref.get("kind") or "")
    ident = str(ref.get("id") or "")
    if kind == "openvpn":
        return {"ok": True, "kind": kind, "node": test_node_by_id(ident)}
    if kind == "pool":
        endpoint_id = ident.removeprefix("pool:")
        result = probe_pool_endpoint(endpoint_id)
        endpoint = node_pool.get_endpoint(endpoint_id)
        node = protocol_endpoint_to_ui_node(endpoint) if endpoint else {}
        return {"ok": bool(result.get("ok")), "kind": kind, "node": node, "result": result}
    return {"ok": False, "error": "未知测试类型"}

def country_priority_worker(country: str) -> None:
    global country_priority_request, is_connecting
    try:
        rounds = 0
        while rounds < 12:
            if manual_connection_active:
                time.sleep(2)
                continue
            rounds += 1
            snapshot = country_priority_snapshot(country)
            available = int(snapshot.get("available") or 0)
            inventory = int(snapshot.get("inventory") or 0)
            if rounds == 1 and inventory < COUNTRY_INVENTORY_TARGET:
                now = time.time()
                last_discovery = float(country_priority_last_discovery.get(country, 0) or 0)
                if now - last_discovery >= 600:
                    country_priority_last_discovery[country] = now
                    set_state(priority_country=country, priority_available=available, priority_inventory=inventory, priority_inventory_target=COUNTRY_INVENTORY_TARGET, priority_target=COUNTRY_AVAILABLE_TARGET, priority_minimum=COUNTRY_AVAILABLE_MIN, priority_running=True, priority_message=f"{country} 资源不足 {COUNTRY_INVENTORY_TARGET} IP，正在优先从主站和全部镜像补充资源")
                    try:
                        fetch_candidates()
                    except Exception as exc:
                        log_to_json("WARNING", "Main", f"{country} 优先补充 OpenVPN 资源失败: {exc}")
                    try:
                        refresh_multi_protocol_catalog(force=True)
                    except Exception as exc:
                        log_to_json("WARNING", "Main", f"{country} 优先补充多协议资源失败: {exc}")
                    snapshot = country_priority_snapshot(country)
                    available = int(snapshot.get("available") or 0)
                    inventory = int(snapshot.get("inventory") or 0)
            if available >= COUNTRY_AVAILABLE_TARGET:
                set_state(priority_country=country, priority_inventory=inventory, priority_inventory_target=COUNTRY_INVENTORY_TARGET, priority_available=available, priority_target=COUNTRY_AVAILABLE_TARGET, priority_minimum=COUNTRY_AVAILABLE_MIN, priority_running=False, priority_message=f"{country} 已达到 {available} 个可用节点")
                return
            candidates = snapshot.get("candidates") or []
            if not candidates:
                set_state(priority_country=country, priority_inventory=inventory, priority_inventory_target=COUNTRY_INVENTORY_TARGET, priority_available=available, priority_target=COUNTRY_AVAILABLE_TARGET, priority_minimum=COUNTRY_AVAILABLE_MIN, priority_running=False, priority_message=f"{country} 当前可检测候选不足，已得到 {available} 个可用节点")
                return
            batch: list[dict[str, Any]] = []
            seen_servers: set[str] = set()
            for ref in candidates:
                key = str(ref.get("server_key") or "")
                if key and key in seen_servers:
                    continue
                batch.append(ref)
                if key: seen_servers.add(key)
                if len(batch) >= COUNTRY_PRIORITY_BATCH:
                    break
            openvpn_refs = [x for x in batch if x.get("kind") == "openvpn"]
            pool_refs = [x for x in batch if x.get("kind") == "pool"]
            if openvpn_refs and maintenance_lock.acquire(blocking=False):
                try:
                    with lock:
                        busy = is_connecting or manual_connection_active
                    if not busy:
                        with lock:
                            is_connecting = True
                        set_state(is_connecting=True, last_check_message=f"正在优先检测 {country}，目标 {COUNTRY_AVAILABLE_MIN}-{COUNTRY_AVAILABLE_TARGET} 个可用节点")
                        test_multiple_nodes([str(x.get("id")) for x in openvpn_refs if x.get("id")])
                finally:
                    with lock:
                        is_connecting = False
                    set_state(is_connecting=False)
                    maintenance_lock.release()
            for ref in pool_refs:
                if is_connecting or manual_connection_active:
                    break
                _test_pool_reference(ref)
            snapshot = country_priority_snapshot(country)
            available = int(snapshot.get("available") or 0)
            inventory = int(snapshot.get("inventory") or 0)
            set_state(priority_country=country, priority_inventory=inventory, priority_inventory_target=COUNTRY_INVENTORY_TARGET, priority_available=available, priority_target=COUNTRY_AVAILABLE_TARGET, priority_minimum=COUNTRY_AVAILABLE_MIN, priority_running=True, priority_message=f"{country} 优先检测中：库存 {inventory}/{COUNTRY_INVENTORY_TARGET} IP，可用 {available}/{COUNTRY_AVAILABLE_TARGET}")
            if available >= COUNTRY_AVAILABLE_MIN and not (snapshot.get("candidates") or []):
                break
            if country_priority_request and country_priority_request != country:
                break
            time.sleep(1)
        final = country_priority_snapshot(country)
        available = int(final.get("available") or 0)
        inventory = int(final.get("inventory") or 0)
        set_state(priority_country=country, priority_inventory=inventory, priority_inventory_target=COUNTRY_INVENTORY_TARGET, priority_available=available, priority_target=COUNTRY_AVAILABLE_TARGET, priority_minimum=COUNTRY_AVAILABLE_MIN, priority_running=False, priority_message=f"{country} 优先检测完成：库存 {inventory} IP，可用 {available} 个节点")
    except Exception as exc:
        set_state(priority_country=country, priority_inventory=0, priority_inventory_target=COUNTRY_INVENTORY_TARGET, priority_available=0, priority_target=COUNTRY_AVAILABLE_TARGET, priority_minimum=COUNTRY_AVAILABLE_MIN, priority_running=False, priority_message=f"{country} 优先检测异常：{exc}")
    finally:
        pending = country_priority_request if country_priority_request and country_priority_request != country else ""
        country_priority_request = ""
        if country_priority_lock.locked():
            country_priority_lock.release()
        if pending:
            start_country_priority(pending)

def start_country_priority(country: str) -> dict[str, Any]:
    global country_priority_request
    target = str(country or "").strip()
    if not target:
        return {"ok": False, "error": "国家不能为空"}
    snapshot = country_priority_snapshot(target)
    country_priority_request = target
    if snapshot.get("available", 0) >= COUNTRY_AVAILABLE_TARGET:
        country_priority_request = ""
        set_state(priority_country=target, priority_inventory=int(snapshot.get("inventory") or 0), priority_inventory_target=COUNTRY_INVENTORY_TARGET, priority_available=int(snapshot.get("available") or 0), priority_target=COUNTRY_AVAILABLE_TARGET, priority_minimum=COUNTRY_AVAILABLE_MIN, priority_running=False, priority_message=f"{target} 已有 {snapshot.get('available')} 个可用节点，无需重复检测")
        return {"ok": True, "running": False, "available": snapshot.get("available"), "target": COUNTRY_AVAILABLE_TARGET}
    if not country_priority_lock.acquire(blocking=False):
        return {"ok": True, "running": True, "available": snapshot.get("available"), "target": COUNTRY_AVAILABLE_TARGET, "message": "已有国家优先检测任务运行中"}
    set_state(priority_country=target, priority_inventory=int(snapshot.get("inventory") or 0), priority_inventory_target=COUNTRY_INVENTORY_TARGET, priority_available=int(snapshot.get("available") or 0), priority_target=COUNTRY_AVAILABLE_TARGET, priority_minimum=COUNTRY_AVAILABLE_MIN, priority_running=True, priority_message=f"{target} 优先检测已启动：目标 {COUNTRY_AVAILABLE_MIN}-{COUNTRY_AVAILABLE_TARGET} 个可用节点")
    threading.Thread(target=country_priority_worker, args=(target,), daemon=True).start()
    return {"ok": True, "running": True, "available": snapshot.get("available"), "target": COUNTRY_AVAILABLE_TARGET}

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        config_text = node.get("config_text") or ""
        h = str(node.get("remote_host") or node.get("ip"))
        p = parse_int(node.get("remote_port"))
        fallback_ping = parse_int(node.get("ping"))

    temp_path = test_config_path(node_id)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        config_text = _prefer_openvpn_ip(config_text, node)
        temp_path.write_text(config_text, encoding="utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to write temp config file: {e}")

    # Final latency is measured from the real OpenVPN tunnel establishment,
    # not from VPNGate's advertised Ping value. ICMP/TCP reachability is only
    # a fast hint and is deliberately not used as the final probe metric.
    latency = 0

    idx = None
    try:
        idx = get_free_test_index()
        ok, message, _ = run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=12, dev=f"tun{idx}")
        if ok:
            latency = _openvpn_elapsed_ms(message)
    finally:
        if idx is not None:
            release_test_index(idx)
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

    temp_node = {
        "id": node_id,
        "ip": h,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node])

    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency if ok else 0
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                node["owner"] = temp_node["owner"]
                node["asn"] = temp_node["asn"]
                node["as_name"] = temp_node["as_name"]
                node["location"] = temp_node["location"]
                node["ip_type"] = temp_node["ip_type"]
                node["quality"] = temp_node["quality"]

            try:
                node_pool.record_probe(node, ok=ok, latency_ms=latency, message=message)
            except Exception as pool_exc:
                log_to_json("WARNING", "Main", f"NodePool 单节点探测结果写入失败: {pool_exc}")
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def test_multiple_nodes(node_ids: list[str]) -> list[dict[str, Any]]:
    with lock:
        nodes = read_nodes()
        to_test = [n for n in nodes if n.get("id") in node_ids]
        now = time.time()
        for n in nodes:
            if n.get("id") in node_ids and not n.get("active") and n.get("probe_status") != "unavailable":
                n["probe_status"] = "testing"
                n["probe_message"] = "正在检测节点连通性..."
                n["probed_at"] = now
        write_json(NODES_FILE, sort_all_nodes(nodes))

    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        idx, n_info = args
        node_id = n_info["id"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))
        fallback_ping = parse_int(n_info.get("ping"))

        temp_path = test_config_path(node_id)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_text = _prefer_openvpn_ip(config_text, n_info)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            return {
                "id": node_id,
                "latency_ms": 0,
                "probe_status": "unavailable",
                "probe_message": f"Failed to write configuration: {e}",
                "probed_at": time.time(),
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
            }

        # For OpenVPN, use real tunnel establishment time as the final
        # latency metric. The source-list Ping value may be stale or external.
        latency = 0
        tun_idx = None
        try:
            tun_idx = get_free_test_index()
            dev_name = f"tun{tun_idx}"
            ok, message, _ = run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=12, dev=dev_name)
            if ok:
                latency = _openvpn_elapsed_ms(message)
        finally:
            if tun_idx is not None:
                release_test_index(tun_idx)
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass

        temp_node = {
            "id": node_id,
            "ip": n_info.get("ip") or h,
            "remote_host": h,
            "remote_port": p,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
        }
        return temp_node

    updated_nodes_map = {}
    # Protect the production proxy path from CPU/TUN contention while still
    # refreshing the full candidate pool in the background.
    probe_worker_limit = 2 if active_tunnel_running() else 5
    max_workers = min(probe_worker_limit, max(1, len(to_test)))
    completed_since_flush = 0
    last_flush_at = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_worker, (idx, n)): n["id"] for idx, n in enumerate(to_test)}
        for future in concurrent.futures.as_completed(futures):
            nid = futures[future]
            try:
                res = future.result()
                updated_nodes_map[nid] = res
                try:
                    original_node = next((item for item in to_test if item.get("id") == nid), None)
                    if original_node:
                        node_pool.record_probe(
                            original_node,
                            ok=res.get("probe_status") == "available",
                            latency_ms=parse_int(res.get("latency_ms")),
                            message=str(res.get("probe_message") or ""),
                        )
                except Exception as pool_exc:
                    log_to_json("WARNING", "Main", f"NodePool 批量探测结果写入失败: {pool_exc}")
            except Exception as e:
                updated_nodes_map[nid] = {
                    "id": nid,
                    "probe_status": "unavailable",
                    "probe_message": f"Test exception: {e}",
                    "latency_ms": 0
                }
                try:
                    original_node = next((item for item in to_test if item.get("id") == nid), None)
                    if original_node:
                        node_pool.record_probe(original_node, False, 0, f"Test exception: {e}")
                except Exception as pool_exc:
                    log_to_json("WARNING", "Main", f"NodePool 异常探测结果写入失败: {pool_exc}")

            # Avoid re-reading and rewriting the entire nodes.json after every
            # single probe completion. Flush small batches so the UI remains
            # responsive without turning disk I/O into an O(n^2) bottleneck.
            completed_since_flush += 1
            now = time.time()
            if completed_since_flush >= 5 or now - last_flush_at >= 1.0:
                with lock:
                    current_nodes = read_nodes()
                    for current in current_nodes:
                        current_id = current.get("id")
                        if current_id in updated_nodes_map:
                            current.update(updated_nodes_map[current_id])
                    write_json(NODES_FILE, sort_all_nodes(current_nodes))
                completed_since_flush = 0
                last_flush_at = now

    # 批量查询并丰富可用节点的地理及 ISP 信息，防止并发时被定位 API 接口限流
    successful_nodes = [res for res in updated_nodes_map.values() if res.get("probe_status") == "available"]
    if successful_nodes:
        try:
            vpn_utils.enrich_ip_info(successful_nodes)
        except Exception as ee:
            print(f"[test_multiple_nodes] 批量富化 IP 失败: {ee}", flush=True)

    with lock:
        current_nodes = read_nodes()
        for n in current_nodes:
            nid = n.get("id")
            if nid in updated_nodes_map:
                n.update(updated_nodes_map[nid])
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)

    return list(updated_nodes_map.values())

def auto_switch_node(attempt: int = 0) -> None:
    if ui_command_plane.is_busy():
        log_to_json("INFO", "VPN", "前端人工指令进行中，自动切换暂缓")
        return
    if manual_connection_active:
        log_to_json("INFO", "VPN", "用户正在手动操作，自动切换暂缓")
        return
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，等待后台检测周期继续恢复。", flush=True)
        return
    ui_cfg = load_ui_config()
    if not bool(ui_cfg.get("connection_enabled", True)):
        print("[自动切换] 连接已禁用，不进行自动切换。", flush=True)
        return
    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = str(ui_cfg.get("force_country") or "").strip()
    if routing_mode == "fixed_ip":
        return

    current = current_active_routing_endpoint()
    exclude_endpoint_id = str(current.get("endpoint_id") or "") if current else ""
    candidates = unified_hot_pool_candidates(ui_cfg, exclude_endpoint_id=exclude_endpoint_id, limit=30)
    if candidates:
        preferred = candidates[0]
        msg = (
            f"当前连接失效，正在按偏好层级选择备用节点: "
            f"tier={preferred.get('routing_tier')} {preferred.get('protocol')} {preferred.get('endpoint_id')}"
        )
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        for endpoint in candidates[:max(1, min(5, len(candidates)))]:
            try:
                connect_ranked_endpoint(endpoint)
                return
            except Exception as exc:
                log_to_json("WARNING", "VPN", f"备用节点 {endpoint.get('endpoint_id')} 切换失败: {exc}")
        auto_switch_node(attempt + 1)
        return

    msg = "没有经过验证的备用节点，保留服务状态并进入后台补齐/重测。"
    print(f"[自动切换] {msg}", flush=True)
    log_to_json("WARNING", "VPN", msg)
    stop_all_tunnels()
    with lock:
        nodes = read_nodes()
        for item in nodes:
            item["active"] = False
        write_json(NODES_FILE, nodes)
    set_state(active_openvpn_node_id="", active_pool_endpoint_id="", active_tunnel_protocol="", last_check_message=msg, proxy_ok=False, proxy_ip="-", proxy_latency_ms=0)

    def bg_fetch_and_switch():
        try:
            if target_country:
                start_country_priority(target_country)
            time.sleep(5)
            maintain_valid_nodes(force=False)
            time.sleep(2)
            auto_switch_node(attempt + 1)
        except Exception as exc:
            print(f"[自动切换后台补齐] 获取并测试节点失败: {exc}", flush=True)
    threading.Thread(target=bg_fetch_and_switch, daemon=True).start()

def _manual_smooth_openvpn_switch(node: dict[str, Any], ui_cfg: dict[str, Any]) -> str:
    """Make-before-break manual OpenVPN switch with rollback before the new route is committed."""
    global active_openvpn_process, active_openvpn_node_id, active_external_tunnel
    global active_pool_endpoint_id, connection_generation, active_connection_generation

    node_id = str(node.get("id") or "")
    config_path = Path(node["config_file"])
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    config_text = _prefer_openvpn_ip(node.get("config_text") or "", node)
    config_path.write_text(config_text, encoding="utf-8")

    old_openvpn_process = active_openvpn_process
    old_openvpn_node_id = str(active_openvpn_node_id or "")
    old_external_tunnel = active_external_tunnel
    old_iface = str(proxy_server.get_active_interface() or "")
    old_gateway = str(getattr(old_external_tunnel, "gateway", "") or "")
    candidate_token = re.sub(r"[^a-z0-9]", "", node_id.lower())[:8] or uuid.uuid4().hex[:8]
    candidate_dev = f"tun-sw-{candidate_token}"[:15]

    set_state(
        manual_switch_active=True,
        pending_connection_id=node_id,
        pending_connection_pool_endpoint_id="",
        pending_connection_protocol="openvpn",
        pending_connection_country=str(node.get("country") or ""),
        pending_connection_address=(
            str(node.get("ip") or node.get("remote_host") or node_id)
            + (f":{parse_int(node.get('remote_port'))}" if parse_int(node.get("remote_port")) else "")
        ),
        manual_switch_message="正在建立候选 OpenVPN 隧道，当前连接保持在线…",
        last_check_message=f"正在建立候选 OpenVPN 节点 {node_id}…",
    )

    ok, message, candidate_process = run_openvpn_until_ready(
        str(config_path), keep_alive=True, route_nopull=True, dev=candidate_dev
    )
    if not ok or candidate_process is None:
        raise RuntimeError(message or "候选 OpenVPN 隧道建立失败")
    if not tunnel_adapters.interface_has_ipv4(candidate_dev):
        stop_process(candidate_process)
        raise RuntimeError("候选 OpenVPN 隧道已启动，但未获得 IPv4 地址")

    set_state(
        manual_switch_message="候选 OpenVPN 已建立，正在验证真实出口…",
        last_check_message="候选 OpenVPN 已建立，正在验证真实出口…",
    )
    candidate_egress = check_interface_egress(candidate_dev)
    if not candidate_egress.get("ok"):
        stop_process(candidate_process)
        raise RuntimeError(str(candidate_egress.get("error") or "候选 OpenVPN 真实出口验证失败"))

    set_state(
        manual_switch_message="候选节点验证通过，正在平滑接管 8500 连接…",
        last_check_message="候选节点验证通过，正在切换本地出口路由；原连接仍保留到验证完成。",
    )

    cleanup_policy_routing()
    proxy_server.set_active_interface(candidate_dev)
    setup_policy_routing(candidate_dev)
    final_health = check_proxy_health()
    if not final_health.get("ok"):
        cleanup_policy_routing()
        try:
            if old_external_tunnel is not None and old_iface:
                proxy_server.set_active_interface(old_iface)
                setup_policy_routing(old_iface, gateway=old_gateway)
            elif old_openvpn_process is not None and old_iface:
                proxy_server.set_active_interface(old_iface)
                setup_policy_routing(old_iface)
        except Exception as rollback_exc:
            log_to_json("ERROR", "VPN", f"平滑切换路由回滚失败: {rollback_exc}")
        stop_process(candidate_process)
        raise RuntimeError(str(final_health.get("error") or "新 OpenVPN 接管后 8500 出口验证失败"))

    if old_external_tunnel is not None:
        try:
            details = old_external_tunnel.details or {}
            if old_external_tunnel.protocol == "softether":
                tunnel_adapters.SoftEtherAdapter().disconnect(
                    account=str(details.get("account") or "aimili"),
                    nic=str(details.get("nic") or "aimili"),
                    delete=True,
                    added_routes=details.get("added_host_routes") or [],
                )
            elif old_external_tunnel.protocol == "sstp":
                tunnel_adapters.SSTPAdapter.disconnect(
                    old_external_tunnel.process,
                    added_routes=details.get("added_host_routes") or [],
                )
            elif old_external_tunnel.protocol == "l2tp-ipsec":
                l2tp_adapter.disconnect(old_external_tunnel.namespace or "aimili-l2tp-prod")
        except Exception as exc:
            log_to_json("WARNING", "VPN", f"旧多协议隧道清理失败（新连接已接管）: {exc}")
    elif old_openvpn_process is not None and old_openvpn_process is not candidate_process:
        stop_process(old_openvpn_process)

    if old_openvpn_node_id and old_openvpn_node_id != node_id:
        old_node = next((x for x in read_nodes() if x.get("id") == old_openvpn_node_id), None)
        if old_node:
            try:
                old_cfg = Path(old_node.get("config_file") or "")
                if old_cfg.exists() and old_cfg != config_path:
                    old_cfg.unlink()
            except Exception:
                pass

    active_external_tunnel = None
    active_pool_endpoint_id = ""
    active_openvpn_process = candidate_process
    active_openvpn_node_id = node_id
    connection_generation += 1
    active_connection_generation = connection_generation

    nodes = read_nodes()
    for item in nodes:
        item["active"] = item.get("id") == node_id
        if item["active"]:
            _ph = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
            item["probe_message"] = f"Active node. HTTP proxy: http://{_ph}:{LOCAL_PROXY_PORT}"
            item["probe_status"] = "available"
            item["latency_ms"] = int(final_health.get("latency_ms") or candidate_egress.get("latency_ms") or 0)
    write_json(NODES_FILE, nodes)

    latency = parse_int(final_health.get("latency_ms")) or parse_int(candidate_egress.get("latency_ms")) or 0
    set_state(
        active_openvpn_node_id=node_id,
        active_pool_endpoint_id="",
        active_tunnel_protocol="openvpn",
        active_tunnel_interface=candidate_dev,
        proxy_ok=True,
        proxy_ip=final_health.get("ip") or candidate_egress.get("ip") or "",
        proxy_latency_ms=latency,
        proxy_error="",
        active_node_latency=(f"{latency} ms" if latency else "出口已连接，等待延迟"),
        last_check_message=f"Connected {node_id}",
        manual_switch_message="切换完成",
    )
    set_manual_route_pin(protocol="openvpn", node_id=node_id)
    return f"Connected {node_id} (smooth switch)"

def connect_node(node_id: str, enable_connection: bool = False, manual: bool = False) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting, manual_connection_active, manual_connection_epoch, connection_generation, active_connection_generation
    node_id = str(node_id or "").strip()
    if not node_id:
        raise ValueError("Node id is required")
    stopped_existing = False
    manual_guard = False
    if manual:
        if not manual_connection_lock.acquire(blocking=False):
            raise RuntimeError("已有人工连接操作正在执行，请等待当前切换完成")
        manual_guard = True
        with lock:
            if manual_connection_active:
                manual_connection_lock.release()
                manual_guard = False
                raise RuntimeError("当前已有手动连接任务正在运行，请稍候")
            manual_connection_epoch += 1
            manual_connection_active = True
        set_state(
            manual_switch_active=True,
            manual_switch_started_at=time.time(),
            pending_connection_id=node_id,
            pending_connection_pool_endpoint_id="",
            pending_connection_protocol="openvpn",
            manual_switch_message="正在准备 OpenVPN 切换…",
            last_check_message="已开始人工切换，正在准备目标节点…",
        )
    if manual and manual_guard:
        try:
            _wait_for_automatic_connection_idle()
        except Exception:
            with lock:
                manual_connection_active = False
            manual_connection_lock.release()
            manual_guard = False
            raise
    with lock:
        if is_connecting and not manual:
            if manual_guard:
                manual_connection_active = False
                manual_connection_lock.release()
                manual_guard = False
            print("[连接] 正在建立其他连接中，跳过此请求", flush=True)
            raise RuntimeError("当前已有连接或节点检测任务正在运行，请稍后再试")
        is_connecting = True
        set_state(is_connecting=True, manual_connection_active=manual_connection_active, active_node_latency="正在连接", last_check_message=f"正在初始化连接配置: {node_id}")

    try:
        log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")

        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")

        if manual:
            set_state(
                manual_switch_active=True,
                pending_connection_id=node_id,
                pending_connection_pool_endpoint_id="",
                pending_connection_protocol="openvpn",
                pending_connection_country=str(node.get("country") or ""),
                pending_connection_address=(
                    str(node.get("ip") or node.get("remote_host") or node_id)
                    + (f":{parse_int(node.get('remote_port'))}" if parse_int(node.get('remote_port')) else "")
                ),
                manual_switch_message="正在准备 OpenVPN 安全隧道…",
                last_check_message=f"正在切换至 OpenVPN 节点 {node_id}，请稍候…",
            )

        ui_cfg = load_ui_config()
        validate_node_allowed_by_routing(node, ui_cfg)
        if not enable_connection and not ui_cfg.get("connection_enabled", True):
            raise RuntimeError("连接已被用户禁用，拒绝后台自动重连")
        if enable_connection:
            auth_file = DATA_DIR / "ui_auth.json"
            with lock:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                latest_cfg = load_ui_config()
                latest_cfg["connection_enabled"] = True
                if latest_cfg.get("routing_mode") == "fixed_ip":
                    latest_cfg["fixed_node_id"] = node_id
                ui_cfg = latest_cfg
                write_json(auth_file, ui_cfg)

        if manual and active_tunnel_running():
            return _manual_smooth_openvpn_switch(node, ui_cfg)

        if manual:
            set_state(manual_switch_message="正在建立候选连接，当前 VPN 暂不受影响…")
        set_state(active_node_latency="清理连接", last_check_message="正在准备新的 OpenVPN 连接…")
        stop_all_tunnels()
        stopped_existing = True

        set_state(active_node_latency="写入配置", last_check_message="正在写入 OpenVPN 节点配置文件...")
        config_path = Path(node["config_file"])
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_text = _prefer_openvpn_ip(node.get("config_text") or "", node)
            config_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        set_state(active_node_latency="启动核心", last_check_message="正在启动 OpenVPN Core 核心服务并建立连接...", manual_switch_message=("正在建立 OpenVPN 安全隧道…" if manual else ""))
        ok, message, process = run_openvpn_until_ready(str(node["config_file"]), keep_alive=True, route_nopull=True)
        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
            log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            print(f"[连接核心失败] 无法与 VPN 节点 {node_id} 建立隧道连接！详情: {message}", flush=True)
            set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="无活动连接", last_check_message=f"连接失败: {message}")
            with lock:
                active_openvpn_node_id = ""
            raise RuntimeError(message)

        with lock:
            active_openvpn_process = process
            active_openvpn_node_id = node_id
            connection_generation += 1
            active_connection_generation = connection_generation

        proxy_server.set_active_interface("tun0")
        set_state(active_tunnel_protocol="openvpn", active_tunnel_interface="tun0")
        if manual:
            set_state(manual_switch_message="候选 OpenVPN 已建立，正在验证真实出口…", last_check_message="候选 OpenVPN 已建立，正在验证真实出口…")
        set_state(active_node_latency="配置路由", last_check_message="正在配置策略路由规则与流量转发...")
        setup_policy_routing("tun0")

        global last_active_ping_time, last_active_latency
        last_active_ping_time = time.time()
        last_active_latency = 0

        set_state(active_node_latency="测试出口", last_check_message="正在测试本地代理出站联通性与出口 IP...")

        for item in nodes:
            item["active"] = item.get("id") == node_id
            if item["active"]:
                _ph = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
                item["probe_message"] = f"Active node. HTTP proxy: http://{_ph}:{LOCAL_PROXY_PORT}"
        write_json(NODES_FILE, nodes)

        set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if res["ok"]:
            last_active_latency = parse_int(res.get("latency_ms")) or 0
            set_state(
                proxy_ok=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=res["latency_ms"],
                active_node_latency=(f"{last_active_latency} ms" if last_active_latency > 0 else "出口已连接，等待延迟"),
                proxy_error=""
            )
        else:
            error_message = str(res.get("error") or "网页出口检测失败")
            set_state(proxy_ok=False, proxy_ip="-", proxy_latency_ms=0, proxy_error=error_message)
            node["probe_status"] = "unavailable"
            node["probe_message"] = error_message
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
            raise RuntimeError("网页出口检测失败: " + error_message)

        latency_str = f"{last_active_latency} ms" if last_active_latency > 0 else "检测超时"
        if manual:
            set_state(manual_switch_message="目标节点验证完成，正在确认客户端状态…", last_check_message="真实出口验证通过，正在完成平滑切换…")
            set_manual_route_pin(protocol="openvpn", node_id=node_id)
        set_state(active_openvpn_node_id=node_id, is_connecting=False, last_check_message=f"Connected {node_id}", active_node_latency=latency_str)
        log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功，出口网卡 tun0 已启用")
        return f"Connected {node_id}"
    except Exception as exc:
        if stopped_existing or (active_openvpn_node_id == node_id and not active_openvpn_running()):
            clear_active_connection_state(f"连接失败: {exc}")
        else:
            set_state(is_connecting=False, last_check_message=f"连接失败: {exc}")
        raise
    finally:
        with lock:
            is_connecting = False
            if manual_guard:
                manual_connection_active = False
        if manual_guard:
            manual_connection_lock.release()

PROBE_ROUTE_TABLE = 200

def cleanup_probe_policy_routing(table: int = PROBE_ROUTE_TABLE) -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", str(table)], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", str(table)], capture_output=True, timeout=2)
    except Exception:
        pass

def setup_probe_policy_routing(interface: str, gateway: str = "", table: int = PROBE_ROUTE_TABLE) -> tuple[bool, str]:
    interface = str(interface or "").strip()
    gateway = str(gateway or "").strip()
    if not interface:
        return False, "缺少测试网卡"
    cleanup_probe_policy_routing(table)
    try:
        route_cmd = ["ip", "route", "add", "default"]
        if gateway:
            route_cmd.extend(["via", gateway])
        route_cmd.extend(["dev", interface])
        if gateway:
            route_cmd.append("onlink")
        route_cmd.extend(["table", str(table)])
        subprocess.run(route_cmd, capture_output=True, text=True, check=True, timeout=3)
        subprocess.run(
            ["ip", "rule", "add", "oif", interface, "table", str(table)],
            capture_output=True, text=True, check=True, timeout=3,
        )
        return True, ""
    except Exception as exc:
        cleanup_probe_policy_routing(table)
        return False, str(exc)

def check_interface_egress(interface: str, gateway: str = "", table: int = PROBE_ROUTE_TABLE) -> dict[str, Any]:
    interface = str(interface or "").strip()
    if not interface:
        return {"ok": False, "error": "缺少测试网卡"}

    route_ok, route_error = setup_probe_policy_routing(interface, gateway, table=table)
    if not route_ok:
        return {"ok": False, "error": f"临时策略路由建立失败: {route_error}"}

    cmd = [
        "curl", "-4", "-sS",
        "--interface", f"if!{interface}",
        "-w", "\n%{time_total} %{http_code}",
        "https://api.ipify.org",
        "--connect-timeout", "4",
        "--max-time", "8",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=9)
        if res.returncode != 0:
            diagnostics: list[str] = [f"curl_exit={res.returncode}", f"gateway={gateway or '-'}"]
            if res.stderr:
                diagnostics.append(f"curl_error={res.stderr.strip()[-500:]}")
            for label, diag_cmd in [
                ("addr", ["ip", "-4", "addr", "show", "dev", interface]),
                ("probe_table", ["ip", "route", "show", "table", str(table)]),
                ("route_get", ["ip", "route", "get", "1.1.1.1", "oif", interface]),
            ]:
                try:
                    diag = subprocess.run(diag_cmd, capture_output=True, text=True, timeout=3)
                    diagnostics.append(f"{label}={(diag.stdout or diag.stderr).strip()[-700:]}")
                except Exception as exc:
                    diagnostics.append(f"{label}_error={exc}")
            return {"ok": False, "error": " | ".join(diagnostics)}
        lines = res.stdout.strip().splitlines()
        if len(lines) < 2:
            return {"ok": False, "error": "测试出口没有返回有效结果"}
        ip = lines[0].strip()
        timing = lines[-1].split()
        if len(timing) != 2 or timing[1] != "200":
            return {"ok": False, "error": f"测试出口 HTTP 异常: {lines[-1]}"}
        latency_ms = int(float(timing[0]) * 1000)
        return {"ok": True, "ip": ip, "latency_ms": latency_ms}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        cleanup_probe_policy_routing(table)

def _acquire_probe_route_table() -> int | None:
    with probe_route_table_lock:
        if not probe_route_tables_free:
            return None
        return probe_route_tables_free.pop()

def _release_probe_route_table(table: int) -> None:
    cleanup_probe_policy_routing(table)
    with probe_route_table_lock:
        probe_route_tables_free.add(int(table))

def probe_pool_endpoint(endpoint_id: str) -> dict[str, Any]:
    endpoint_id = str(endpoint_id or "").strip()
    if not endpoint_id:
        return {"ok": False, "error": "endpoint_id 为空"}
    if is_connecting or manual_connection_active:
        return {"ok": False, "skipped": True, "error": "生产连接正在切换，跳过后台探测"}
    if not protocol_probe_lock.acquire(blocking=False):
        return {"ok": False, "skipped": True, "error": "已有协议探测任务运行中"}

    endpoint = node_pool.get_endpoint(endpoint_id)
    if endpoint is None:
        protocol_probe_lock.release()
        return {"ok": False, "error": "端点不存在"}

    protocol = str(endpoint.get("protocol") or "").lower()
    metadata = endpoint.get("metadata") or {}
    host = str(metadata.get("hostname") or endpoint.get("hostname") or endpoint.get("current_ip") or "").strip()
    port = parse_int(endpoint.get("port"))
    token = re.sub(r"[^a-z0-9]", "", endpoint_id.lower())[:10] or uuid.uuid4().hex[:10]
    result: tunnel_adapters.TunnelResult | None = None
    cleanup = None
    probe_table: int | None = _acquire_probe_route_table()

    try:
        if probe_table is None:
            return {"ok": False, "skipped": True, "error": "探测临时路由表暂时已满"}
        if protocol == "softether":
            account = f"probe{token}"
            nic = f"p{token}"
            adapter = tunnel_adapters.SoftEtherAdapter()
            result = adapter.connect(
                host=host,
                port=port or 443,
                account=account,
                nic=nic,
                username="vpn",
                password="vpn",
            )
            cleanup = lambda: adapter.disconnect(
                account=account,
                nic=nic,
                delete=True,
                added_routes=((result.details or {}).get("added_host_routes") if result else []),
            )
        elif protocol == "sstp":
            adapter = tunnel_adapters.SSTPAdapter()
            target = host if port in (0, 443) else f"{host}:{port}"
            result = adapter.connect(target, username="vpn", password="vpn", timeout=20)
            cleanup = lambda: tunnel_adapters.SSTPAdapter.disconnect(
                result.process if result else None,
                added_routes=((result.details or {}).get("added_host_routes") if result else []),
            )
        elif protocol == "l2tp-ipsec":
            namespace = f"aimili-l2tp-p{token}"[:31]
            result = l2tp_adapter.connect(
                host=host,
                username="vpn",
                password="vpn",
                psk="vpn",
                namespace=namespace,
                timeout=35,
            )
            cleanup = lambda: l2tp_adapter.disconnect(namespace)
        else:
            return {"ok": False, "skipped": True, "error": f"协议 {protocol} 暂不允许后台实连测试"}

        if result is None or not result.ok or not result.interface:
            message = result.message if result else "隧道未建立"
            node_pool.record_endpoint_probe(endpoint_id, False, 0, message)
            return {"ok": False, "protocol": protocol, "error": message}

        egress = (
            tunnel_adapters.L2TPIPsecAdapter.egress_check(result)
            if protocol == "l2tp-ipsec"
            else check_interface_egress(result.interface, result.gateway, table=probe_table)
        )
        if not egress.get("ok"):
            message = str(egress.get("error") or "接口出口不可用")
            node_pool.record_endpoint_probe(endpoint_id, False, 0, message)
            return {"ok": False, "protocol": protocol, "interface": result.interface, "error": message}

        latency_ms = parse_int(egress.get("latency_ms"))
        node_pool.record_endpoint_probe(endpoint_id, True, latency_ms, "background egress probe ok")
        return {
            "ok": True,
            "protocol": protocol,
            "interface": result.interface,
            "ip": egress.get("ip", ""),
            "latency_ms": latency_ms,
        }
    except Exception as exc:
        try:
            node_pool.record_endpoint_probe(endpoint_id, False, 0, str(exc))
        except Exception:
            pass
        return {"ok": False, "protocol": protocol, "error": str(exc)}
    finally:
        if cleanup is not None:
            try:
                cleanup()
            except Exception:
                pass
        if probe_table is not None:
            _release_probe_route_table(probe_table)
        protocol_probe_lock.release()

def protocol_probe_loop() -> None:
    """Continuous availability engine for every pending endpoint.

    The previous loop only touched SoftEther/SSTP/L2TP and could leave dozens or
    hundreds of new OpenVPN endpoints permanently in NOT_CHECKED. The availability
    sweep is the single scheduler for both OpenVPN and multi-protocol resources.
    It consumes only due endpoints, prioritises NEW entries, and backs off to the
    normal recheck window after a successful probe.
    """
    time.sleep(15)
    while True:
        try:
            if ui_command_plane.is_busy() or global_pool_refresh_running or is_connecting or manual_connection_active:
                time.sleep(5)
                continue
            priority = country_priority_request if country_priority_explicit else coverage_country
            result = availability_sweep_once(priority)
            if result.get("skipped"):
                time.sleep(3)
                continue
        except Exception as exc:
            log_to_json("ERROR", "Probe", f"可用性检测循环异常: {exc}")
        time.sleep(AVAILABILITY_TICK_SECONDS)

def openvpn_pool_endpoint_id(node: dict[str, Any] | None) -> str:
    if not node:
        return ""
    try:
        key = node_pool.server_key(node)
        return node_pool.endpoint_id(
            key,
            "openvpn",
            str(node.get("proto") or "unknown").lower(),
            parse_int(node.get("remote_port")),
        )
    except Exception:
        return ""

def ensure_openvpn_node_from_pool(endpoint: dict[str, Any]) -> str:
    """Rehydrate a historical OpenVPN Master-Pool endpoint into nodes.json for connection."""
    metadata = endpoint.get("metadata") or {}
    server_meta = endpoint.get("server_metadata") or {}
    endpoint_id = str(endpoint.get("endpoint_id") or "").strip()
    node_id = str(metadata.get("node_id") or "").strip()
    if not node_id:
        transport = str(endpoint.get("transport") or "tcp").lower()
        ip = str(endpoint.get("current_ip") or "").strip()
        port = int(endpoint.get("port") or 0)
        node_id = safe_name(f"{(endpoint.get("country") or "XX")}_{ip}_{port}_{transport}")
    config_file = str(endpoint.get("config_ref") or metadata.get("config_file") or "").strip()
    config_text = ""
    if config_file:
        try:
            config_text = Path(config_file).read_text(encoding="utf-8")
        except Exception:
            config_text = ""
    host = str(endpoint.get("hostname") or endpoint.get("current_ip") or "").strip()
    port = int(endpoint.get("port") or 0)
    transport = str(endpoint.get("transport") or "tcp").lower()
    if not config_text:
        config_text = _manual_openvpn_template()
        if not config_text:
            raise RuntimeError(f"OpenVPN Pool 端点 {endpoint_id} 缺少配置文件，且当前实例没有可用模板")
        config_text = re.sub(r"(?m)^remote\s+\S+\s+\d+\s*$", f"remote {host} {port}", config_text, count=1)
        config_text = re.sub(r"(?m)^proto\s+\S+\s*$", f"proto {transport}", config_text, count=1)
        config_dir = CONFIG_DIR
        config_dir.mkdir(exist_ok=True, parents=True)
        config_file = str(config_dir / f"{node_id}.ovpn")
        try:
            Path(config_file).write_text(config_text, encoding="utf-8")
        except Exception:
            pass
    endpoint_status = str(endpoint.get("status") or "").upper()
    real_probe_at = float(endpoint.get("last_success") or 0)
    real_latency = int(endpoint.get("latency_ewma") or 0)
    is_realtime_verified = endpoint_status in ("HOT", "AVAILABLE") and real_probe_at > 0 and real_latency > 0
    node = {
        "id": node_id,
        "country": endpoint.get("country") or "",
        "country_short": "",
        "host_name": endpoint.get("hostname") or host,
        "ip": endpoint.get("current_ip") or host,
        "score": int(endpoint.get("latest_server_score") or 0),
        "ping": int(endpoint.get("latest_ping") or 0),
        "speed": int(endpoint.get("latest_speed") or 0),
        "sessions": int(endpoint.get("latest_sessions") or 0),
        "owner": str(server_meta.get("owner") or ""),
        "asn": str(server_meta.get("asn") or ""),
        "as_name": str(server_meta.get("as_name") or ""),
        "location": str(server_meta.get("location") or endpoint.get("country") or ""),
        "ip_type": str(server_meta.get("ip_type") or ""),
        "quality": str(server_meta.get("quality") or ""),
        "latency_ms": real_latency if is_realtime_verified else 0,
        "config_file": config_file,
        "config_text": config_text,
        "proto": transport,
        "protocol": "openvpn",
        "remote_host": host,
        "remote_port": port,
        "fetched_at": time.time(),
        "probe_status": "available" if is_realtime_verified else "not_checked",
        "probe_message": "已完成真实 OpenVPN 隧道测速" if is_realtime_verified else "来自 Master Pool 的资源，等待真实 OpenVPN 隧道测速",
        "probed_at": real_probe_at,
        "pool_endpoint_id": endpoint_id,
        "pool_rehydrated": True,
    }
    with lock:
        nodes = read_nodes()
        for idx, existing in enumerate(nodes):
            if existing.get("id") == node_id:
                nodes[idx].update({k: v for k, v in node.items() if v not in (None, "")})
                write_json(NODES_FILE, sort_all_nodes(nodes))
                return node_id
        nodes.append(node)
        if len(nodes) > 1000:
            active_ids = {str(active_openvpn_node_id or "")}
            kept = [n for n in nodes if n.get("id") in active_ids or n.get("probe_status") in ("available", "testing")]
            kept.extend([n for n in nodes if n not in kept][-max(0, 1000-len(kept)):])
            nodes = kept[:1000]
        write_json(NODES_FILE, sort_all_nodes(nodes))
    return node_id

def connect_pool_endpoint_with_fallback(endpoint_ids: list[str], manual: bool = False) -> str:
    ids = list(dict.fromkeys(str(x or "").strip() for x in endpoint_ids if str(x or "").strip()))
    if not ids:
        raise ValueError("没有可连接的协议端点")
    errors: list[str] = []
    for endpoint_id in ids:
        try:
            return connect_pool_endpoint(endpoint_id, manual=manual)
        except Exception as exc:
            errors.append(f"{endpoint_id[:10]}: {exc}")
            # Do not continue after a successful promotion; connect_pool_endpoint
            # only returns after the candidate has fully taken over the gateway.
            continue
    raise RuntimeError("已尝试该 IP/协议的全部候选端点，均未连接成功：" + " | ".join(errors[-4:]))

def connect_ranked_endpoint(endpoint: dict[str, Any], manual: bool = False) -> str:
    protocol = str(endpoint.get("protocol") or "").lower()
    if protocol == "openvpn":
        node_id = ensure_openvpn_node_from_pool(endpoint)
        return connect_node(node_id, manual=manual)
    return connect_pool_endpoint_with_fallback(
        [str(endpoint.get("endpoint_id") or "")],
        manual=manual,
    )

def restore_manual_previous_connection(previous_openvpn_node_id: str = "", previous_pool_endpoint_id: str = "") -> tuple[bool, str]:
    """Restore the connection that existed before a manual switch failed.
    This is deliberately a manual rollback, not an automatic failover.
    """
    try:
        previous_pool_endpoint_id = str(previous_pool_endpoint_id or "").strip()
        previous_openvpn_node_id = str(previous_openvpn_node_id or "").strip()
        if previous_pool_endpoint_id:
            if active_pool_endpoint_id == previous_pool_endpoint_id and active_tunnel_running():
                return True, "原多协议连接保持不变"
            return True, connect_pool_endpoint(previous_pool_endpoint_id, manual=True)
        if previous_openvpn_node_id:
            if active_openvpn_node_id == previous_openvpn_node_id and active_tunnel_running():
                return True, "原 OpenVPN 连接保持不变"
            return True, connect_node(previous_openvpn_node_id, manual=True)
    except Exception as exc:
        return False, str(exc)
    return False, "之前没有可恢复的活动连接"

def endpoint_allowed_by_pool_routing(endpoint: dict[str, Any], ui_cfg: dict[str, Any]) -> bool:
    # Favorites are a preference, never a hard lock.
    return ui_cfg.get("routing_mode", "auto") != "fixed_ip"

def try_unified_failover(exclude_endpoint_id: str = "", attempts: int = 4, preferred_only: bool = False, manual: bool = False) -> bool:
    if ui_command_plane.is_busy() and not manual:
        return False
    if not failover_lock.acquire(blocking=False):
        return True
    started = time.time()
    ui_cfg = load_ui_config()
    if not bool(ui_cfg.get("connection_enabled", True)):
        failover_lock.release()
        return False
    if manual_connection_active and not manual:
        failover_lock.release()
        return False
    from_protocol = ""
    from_endpoint = ""
    if active_external_tunnel is not None:
        from_protocol = str(active_external_tunnel.protocol or "")
        from_endpoint = str(active_pool_endpoint_id or "")
    elif active_openvpn_running():
        from_protocol = "openvpn"
        from_endpoint = str(active_openvpn_node_id or "")

    hot_pool = [
        ep for ep in unified_hot_pool_candidates(ui_cfg, exclude_endpoint_id=exclude_endpoint_id, limit=100)
        if endpoint_allowed_by_pool_routing(ep, ui_cfg)
    ]
    if preferred_only:
        hot_pool = [ep for ep in hot_pool if int(ep.get("routing_tier") or 99) == 0]
    set_state(
        failover_in_progress=True,
        failover_started_at=started,
        failover_from_protocol=from_protocol,
        failover_from_endpoint=from_endpoint,
        failover_candidate_count=len(hot_pool),
        failover_preferred_only=preferred_only,
    )
    last_error = ""
    for endpoint in hot_pool[:max(1, attempts)]:
        try:
            connect_ranked_endpoint(endpoint, manual=manual)
            if not bool(load_ui_config().get("connection_enabled", True)):
                stop_all_tunnels()
                set_state(failover_in_progress=False, last_failover_ok=False, last_failover_error="用户已手动断开连接")
                failover_lock.release()
                return False
            duration_ms = int((time.time() - started) * 1000)
            set_state(
                hot_pool_size=len(hot_pool),
                hot_pool_selected_score=endpoint.get("selection_score", 0),
                failover_selected_tier=int(endpoint.get("routing_tier") or 0),
                failover_in_progress=False,
                last_failover_ok=True,
                last_failover_at=time.time(),
                last_failover_duration_ms=duration_ms,
                last_failover_from_protocol=from_protocol,
                last_failover_from_endpoint=from_endpoint,
                last_failover_to_protocol=str(endpoint.get("protocol") or ""),
                last_failover_to_endpoint=str(endpoint.get("endpoint_id") or ""),
                last_failover_error="",
            )
            log_to_json("INFO", "VPN", f"统一 Hot Pool 切换成功 tier={endpoint.get('routing_tier')} {from_protocol or '-'} -> {endpoint.get('protocol')}，耗时 {duration_ms} ms")
            failover_lock.release()
            return True
        except Exception as exc:
            last_error = str(exc)
            log_to_json("WARNING", "VPN", f"统一 Hot Pool 切换失败 {endpoint.get('protocol')} {endpoint.get('endpoint_id')}: {exc}")
    duration_ms = int((time.time() - started) * 1000)
    set_state(
        failover_in_progress=False,
        last_failover_ok=False,
        last_failover_at=time.time(),
        last_failover_duration_ms=duration_ms,
        last_failover_from_protocol=from_protocol,
        last_failover_from_endpoint=from_endpoint,
        last_failover_to_protocol="",
        last_failover_to_endpoint="",
        last_failover_error=last_error or "无可用 Hot Pool 候选",
    )
    failover_lock.release()
    return False


def _global_country_pool_snapshot() -> dict[str, dict[str, set[str]]]:
    """Build one in-memory country inventory snapshot from the persistent pool."""
    result: dict[str, dict[str, set[str]]] = {}
    def add(country: Any, ip: Any, available: bool) -> None:
        name = normalized_country_name(country)
        value = str(ip or "").strip()
        if not name or not value:
            return
        bucket = result.setdefault(name, {"inventory": set(), "available": set()})
        bucket["inventory"].add(value)
        if available:
            bucket["available"].add(value)

    for node in read_nodes():
        add(
            node.get("country"),
            node.get("ip") or node.get("remote_host"),
            str(node.get("probe_status") or "").lower() == "available",
        )
    try:
        endpoints = node_pool.list_endpoints(limit=5000)
    except Exception:
        endpoints = []
    for endpoint in endpoints:
        status = str(endpoint.get("status") or "").upper()
        add(
            endpoint.get("country"),
            endpoint.get("current_ip") or (endpoint.get("metadata") or {}).get("ip"),
            status in ("HOT", "AVAILABLE"),
        )
    return result


def _pick_global_country_for_coverage() -> str:
    snapshot = _global_country_pool_snapshot()
    candidates: list[tuple[int, int, int, str]] = []
    now = time.time()
    for country, values in snapshot.items():
        inventory = len(values["inventory"])
        available = len(values["available"])
        if inventory <= 0 or available >= COUNTRY_AVAILABLE_TARGET:
            continue
        last_attempt = float(global_country_coverage_last_attempt.get(country, 0) or 0)
        # Avoid repeatedly retrying a country with no usable source every few seconds.
        if now - last_attempt < 1800 and available >= COUNTRY_AVAILABLE_MIN:
            continue
        candidates.append((available, -min(inventory, COUNTRY_INVENTORY_TARGET), int(last_attempt > 0), country))
    if not candidates:
        return ""
    candidates.sort()
    return candidates[0][3]


def schedule_global_country_coverage() -> dict[str, Any]:
    if ui_command_plane.is_busy():
        return {"ok": True, "running": True, "message": "前端人工指令进行中，暂缓国家覆盖任务"}
    if manual_connection_active:
        return {"ok": True, "running": True, "message": "手动连接正在进行，暂缓国家覆盖检测"}
    if country_priority_lock.locked() or country_priority_request:
        return {"ok": True, "running": True}
    country = _pick_global_country_for_coverage()
    if not country:
        return {"ok": True, "running": False, "message": "当前资源池已有足够覆盖或暂无可补充国家"}
    global_country_coverage_last_attempt[country] = time.time()
    return start_country_priority(country)


def global_probe_sweep_once() -> dict[str, Any]:
    """Probe due OpenVPN and non-OpenVPN resources without touching the active tunnel."""
    if ui_command_plane.is_busy():
        return {"ok": True, "skipped": True, "reason": "用户正在执行前端指令"}
    if maintenance_lock.locked() or is_connecting:
        return {"ok": True, "skipped": True, "reason": "busy"}
    openvpn_limit = 6 if active_tunnel_running() else 10
    non_openvpn_limit = 2 if active_tunnel_running() else 4
    tested_openvpn = 0
    tested_pool = 0

    openvpn_ids: list[str] = []
    try:
        due = node_pool.due_endpoints(("openvpn",), limit=openvpn_limit)
        for endpoint in due:
            node_id = str((endpoint.get("metadata") or {}).get("node_id") or "").strip()
            if node_id and node_id not in openvpn_ids:
                openvpn_ids.append(node_id)
            if len(openvpn_ids) >= openvpn_limit:
                break
    except Exception as exc:
        log_to_json("WARNING", "Probe", f"全球 OpenVPN 到期队列读取失败: {exc}")

    if openvpn_ids and maintenance_lock.acquire(blocking=False):
        try:
            if not is_connecting:
                test_multiple_nodes(openvpn_ids)
                tested_openvpn = len(openvpn_ids)
        finally:
            maintenance_lock.release()

    if not is_connecting:
        try:
            due_pool = node_pool.due_endpoints(("softether", "sstp", "l2tp-ipsec"), limit=non_openvpn_limit)
        except Exception as exc:
            due_pool = []
            log_to_json("WARNING", "Probe", f"全球多协议到期队列读取失败: {exc}")
        for endpoint in due_pool:
            if is_connecting:
                break
            endpoint_id = str(endpoint.get("endpoint_id") or "")
            if not endpoint_id:
                continue
            result = probe_pool_endpoint(endpoint_id)
            if result.get("ok") or not result.get("skipped"):
                tested_pool += 1

    return {"ok": True, "openvpn_tested": tested_openvpn, "pool_tested": tested_pool}


def refresh_global_pool_background(force: bool = True) -> dict[str, Any]:
    global global_pool_refresh_running, global_pool_refresh_last_at
    global global_pool_refresh_status, global_pool_refresh_message
    global global_pool_refresh_servers, global_pool_refresh_sources
    if not global_pool_refresh_lock.acquire(blocking=False):
        return {
            "ok": True,
            "running": True,
            "message": "全球节点库刷新正在后台进行",
        }
    with lock:
        if global_pool_refresh_running:
            global_pool_refresh_lock.release()
            return {"ok": True, "running": True, "message": "全球节点库刷新正在后台进行"}
        global_pool_refresh_running = True
        global_pool_refresh_status = "running"
        global_pool_refresh_message = "正在重新开始全球资源轮询；保留历史节点与质量数据，不断开当前 VPN。"
        global_pool_refresh_servers = 0
        global_pool_refresh_sources = 0

    set_state(
        global_pool_refresh_running=True,
        global_pool_refresh_status="running",
        global_pool_refresh_message=global_pool_refresh_message,
        global_pool_refresh_servers=0,
        global_pool_refresh_sources=0,
    )

    def worker() -> None:
        global global_pool_refresh_running, global_pool_refresh_last_at
        global global_pool_refresh_status, global_pool_refresh_message
        global global_pool_refresh_servers, global_pool_refresh_sources
        try:
            # Do not compete with the connection/maintenance critical section.
            for _ in range(120):
                if not maintenance_lock.locked() and not is_connecting:
                    break
                time.sleep(1)
            # Requeue the entire persisted pool without deleting history.
            try:
                requeued = node_pool.reset_probe_schedule(include_retired=False)
                log_to_json("INFO", "Probe", f"人工重新轮询：已重新排队 {requeued} 个非退役端点")
            except Exception as exc:
                requeued = 0
                log_to_json("WARNING", "Probe", f"人工重新轮询排队失败: {exc}")
            candidates: list[dict[str, Any]] = []
            try:
                candidates = fetch_candidates()
            except Exception as exc:
                log_to_json("WARNING", "Main", f"全球 OpenVPN 资源拉取失败: {exc}")
            catalog = refresh_multi_protocol_catalog(force=True)
            global_pool_refresh_servers = len(candidates) + int(catalog.get("servers") or 0)
            global_pool_refresh_sources = len(catalog.get("sources") or [])
            global_pool_refresh_last_at = time.time()
            global_pool_refresh_status = "ok"
            global_pool_refresh_message = (
                f"全球资源重新轮询完成：OpenVPN {len(candidates)} 个候选，多协议目录 {int(catalog.get('servers') or 0)} 台；"
                "已有资源已重新排入检测，后台会继续进行全量可用性复核与国家缺口补齐。"
            )
            log_to_json("INFO", "Main", global_pool_refresh_message)

            # Start a bounded immediate validation pass; lifecycle loops continue
            # the complete persistent-pool recheck afterwards.
            try:
                threading.Thread(target=global_probe_sweep_once, daemon=True).start()
            except Exception:
                pass
            try:
                threading.Thread(target=schedule_global_country_coverage, daemon=True).start()
            except Exception:
                pass
        except Exception as exc:
            global_pool_refresh_status = "error"
            global_pool_refresh_message = f"全球节点库刷新异常：{exc}"
            log_to_json("ERROR", "Main", global_pool_refresh_message)
        finally:
            global_pool_refresh_running = False
            set_state(
                global_pool_refresh_running=False,
                global_pool_refresh_last_at=global_pool_refresh_last_at,
                global_pool_refresh_status=global_pool_refresh_status,
                global_pool_refresh_message=global_pool_refresh_message,
                global_pool_refresh_servers=global_pool_refresh_servers,
                global_pool_refresh_sources=global_pool_refresh_sources,
            )
            global_pool_refresh_lock.release()

    threading.Thread(target=worker, daemon=True).start()
    return {"ok": True, "running": True, "message": "已启动全球节点库后台刷新"}


def global_country_coverage_loop() -> None:
    global global_country_coverage_heartbeat
    # Start after the initial catalog has had a chance to load.
    time.sleep(30)
    while True:
        try:
            global_country_coverage_heartbeat = time.time()
            if not global_pool_refresh_running and not ui_command_plane.is_busy() and not maintenance_lock.locked() and not manual_connection_active:
                schedule_global_country_coverage()
        except Exception as exc:
            log_to_json("WARNING", "Main", f"全球国家可用性补齐调度异常: {exc}")
        time.sleep(300)

def maintain_valid_nodes(force: bool = False):
    global active_openvpn_process, active_openvpn_node_id, is_connecting, manual_connection_epoch
    ensure_dirs()
    if ui_command_plane.is_busy() and not force:
        return "前端人工指令进行中，后台维护本轮暂缓"
    if global_pool_refresh_running and not force:
        return "全球资源重新轮询进行中，后台维护本轮暂缓"
    if not maintenance_lock.acquire(blocking=False):
        msg = "节点维护任务正在运行，请稍后再试"
        set_state(last_check_message=msg)
        return msg
    with lock:
        if manual_connection_active:
            maintenance_lock.release()
            msg = "用户正在手动切换节点，后台检测本轮暂缓"
            set_state(last_check_message=msg)
            return msg
        if is_connecting:
            maintenance_lock.release()
            msg = "当前已有连接或节点测试任务正在运行，请稍后再试"
            set_state(last_check_message=msg)
            return msg
        cycle_manual_epoch = manual_connection_epoch
        is_connecting = True
    try:
        if manual_connection_active or manual_connection_epoch != cycle_manual_epoch:
            return "检测周期被用户手动切换打断"
        if force:
            with lock:
                if manual_connection_active or manual_connection_epoch != cycle_manual_epoch:
                    return "检测周期被用户手动切换打断"
                stop_all_tunnels()
            reconnect_fixed_node_if_needed(load_ui_config())
        elif not active_tunnel_running():
            ui_cfg = load_ui_config()
            routing_mode = ui_cfg.get("routing_mode", "auto")
            connection_enabled = ui_cfg.get("connection_enabled", True)
            if connection_enabled:
                if routing_mode == "fixed_ip":
                    reconnect_fixed_node_if_needed(ui_cfg)
                else:
                    has_active_id = False
                    with lock:
                        if active_openvpn_node_id:
                            has_active_id = True
                            stop_all_tunnels()
                    if has_active_id:
                        print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                        is_connecting = False
                        auto_switch_node()
                        is_connecting = True
                    elif routing_mode in ("auto", "fixed_region"):
                        # Warm-start from persisted validated endpoints before
                        # doing a fresh network-wide scan.
                        is_connecting = False
                        try:
                            if try_unified_failover(attempts=3):
                                log_to_json("INFO", "VPN", "已从持久化 Hot Pool 快速恢复生产出口")
                        finally:
                            is_connecting = True

        try:
            if manual_connection_active or manual_connection_epoch != cycle_manual_epoch:
                return "检测周期被用户手动切换打断"
            set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch_candidates()
            if manual_connection_active or manual_connection_epoch != cycle_manual_epoch:
                return "检测周期被用户手动切换打断"
            threading.Thread(target=refresh_multi_protocol_catalog, args=(False,), daemon=True).start()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            diag_msg = str(exc)
            if not any(token in diag_msg for token in ["[ERR_", "错误代码"]):
                err_code, raw_diag = vpn_utils.diagnose_api_failure(API_URL)
                diag_msg = f"[错误代码 {err_code}] 获取节点失败: {exc} | 诊断结果: {raw_diag}"
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=diag_msg)
            candidates = []

        if not candidates:
            return "没有拉取到新节点"
        if manual_connection_active or manual_connection_epoch != cycle_manual_epoch:
            return "检测周期被用户手动切换打断"

        with lock:
            current_nodes = read_nodes()
            current_by_id = {
                str(n.get("id")): n
                for n in current_nodes
                if n.get("id")
            }
            active_node = None
            if active_openvpn_node_id:
                active_node = next((n for n in current_nodes if n.get("id") == active_openvpn_node_id), None)

            merged: list[dict[str, Any]] = []
            seen_ids: set[str] = set()

            if active_node:
                merged.append(active_node)
                seen_ids.add(active_node["id"])

            for cand in candidates:
                if cand["id"] not in seen_ids:
                    previous = current_by_id.get(str(cand["id"]))
                    if previous:
                        # Keep prior probe state, but prefer freshly enriched ISP/IP
                        # metadata from the latest fetch. This prevents stale cached
                        # classifications from overwriting a newly corrected result.
                        for key in [
                            "probe_status",
                            "probe_message",
                            "latency_ms",
                            "probed_at",
                        ]:
                            if previous.get(key) not in (None, ""):
                                cand[key] = previous.get(key)
                        for key in [
                            "owner",
                            "asn",
                            "as_name",
                            "location",
                            "ip_type",
                            "quality",
                        ]:
                            if cand.get(key) in (None, "") and previous.get(key) not in (None, ""):
                                cand[key] = previous.get(key)
                    merged.append(cand)
                    seen_ids.add(cand["id"])

            if len(merged) > 1000:
                merged = merged[:1000]

            for n in merged:
                config_path = Path(n["config_file"])
                if not config_path.exists():
                    try:
                        config_path.write_text(n["config_text"], encoding="utf-8")
                    except Exception:
                        pass

            write_json(NODES_FILE, merged)

        initial_tested_ids: set[str] = set()
        ui_cfg = load_ui_config()
        should_fast_connect = (
            ui_cfg.get("connection_enabled", True)
            and ui_cfg.get("routing_mode", "auto") != "fixed_ip"
            and not active_tunnel_running()
        )
        if should_fast_connect and not manual_connection_active and manual_connection_epoch == cycle_manual_epoch:
            with lock:
                current_nodes = read_nodes()
                fast_candidates = [
                    n for n in current_nodes
                    if not n.get("active") and n.get("probe_status") != "unavailable"
                ]
                fast_candidates = apply_routing_filters(fast_candidates, ui_cfg, include_unknown_ip_type=True)
                fast_candidates.sort(key=lambda n: routing_node_service_key(n, ui_cfg))
                fast_test_ids = [
                    n["id"] for n in fast_candidates
                    if n.get("id")
                ][:INITIAL_CONNECT_TEST_LIMIT]

            if fast_test_ids:
                initial_tested_ids = set(fast_test_ids)
                msg = f"首次快速连接模式：优先测试 {len(fast_test_ids)} 个高优先级节点，发现可用节点后立即连接"
                print(f"[快速首连] {msg}", flush=True)
                log_to_json("INFO", "Main", msg)
                set_state(is_connecting=True, last_check_message=msg)
                test_multiple_nodes(fast_test_ids)
                if manual_connection_active or manual_connection_epoch != cycle_manual_epoch:
                    return "检测周期被用户手动切换打断"

                with lock:
                    fast_nodes = read_nodes()
                    available_candidates = [
                        n for n in fast_nodes
                        if n.get("probe_status") == "available" and not n.get("active")
                    ]
                    available_candidates = apply_routing_filters(available_candidates, ui_cfg)

                if available_candidates:
                    is_connecting = False
                    set_state(is_connecting=False, last_check_message="快速首连已找到可用节点，正在建立连接...")
                    auto_switch_node()
                    if active_tunnel_running():
                        valid_nodes_count = len([n for n in read_nodes() if n.get("probe_status") == "available"])
                        message = f"Fetched {len(candidates)} nodes. Fast-tested {len(fast_test_ids)} nodes and connected."
                        set_state(
                            last_check_at=time.time(),
                            last_check_message=message,
                            active_openvpn_node_id=active_openvpn_node_id,
                            valid_nodes=valid_nodes_count,
                        )
                        return message
                    is_connecting = True

        # Test only OpenVPN endpoints whose lifecycle backoff has expired.
        # This prevents repeatedly reconnecting every failed node on each cycle.
        batch_limit = (
            ACTIVE_BACKGROUND_PROBE_BATCH
            if active_tunnel_running()
            else max(BACKGROUND_PROBE_BATCH, INITIAL_CONNECT_TEST_LIMIT * 2)
        )
        due_openvpn = node_pool.due_endpoints(("openvpn",), limit=batch_limit + len(initial_tested_ids))
        to_test_ids: list[str] = []
        seen_test_ids: set[str] = set()
        for endpoint in due_openvpn:
            metadata = endpoint.get("metadata") or {}
            node_id = str(metadata.get("node_id") or "").strip()
            if not node_id or node_id in initial_tested_ids or node_id in seen_test_ids:
                continue
            to_test_ids.append(node_id)
            seen_test_ids.add(node_id)
            if len(to_test_ids) >= batch_limit:
                break
        total_due = len(due_openvpn)

        msg = f"开始按退避队列低频轮询 OpenVPN，本轮检测 {len(to_test_ids)} 个到期节点（查询到 {total_due} 个候选），避免重复扫描与连接风暴"
        print(f"[周期检测] {msg}", flush=True)
        log_to_json("INFO", "Main", msg)

        if manual_connection_active or manual_connection_epoch != cycle_manual_epoch:
            return "检测周期被用户手动切换打断"
        set_state(is_connecting=True, last_check_message="正在并发检测所有节点可用性...")
        test_multiple_nodes(to_test_ids)
        is_connecting = False

        if manual_connection_active or manual_connection_epoch != cycle_manual_epoch:
            return "检测周期被用户手动切换打断"

        with lock:
            merged = read_nodes()

            # Identify available, unavailable, and active nodes
            available_nodes = [n["id"] for n in merged if n.get("probe_status") == "available"]
            unavailable_nodes = [n["id"] for n in merged if n.get("probe_status") == "unavailable"]
            active_node = next((n["id"] for n in merged if n.get("active")), "无")

            status_report = (
                f"周期节点检测完成。实时同步状态: 获取到候选节点共 {len(merged)} 个。 "
                f"其中【可用节点】{len(available_nodes)} 个: {available_nodes[:15]}...; "
                f"【不可用节点】{len(unavailable_nodes)} 个; "
                f"当前【正在正常运行的活动连接节点】为: {active_node}。"
            )
            print(f"[周期检测] {status_report}", flush=True)
            log_to_json("INFO", "Main", status_report)

            if active_node != "无" and not active_openvpn_running():
                warn_msg = f"[诊断警告] 活动节点 {active_node} 被标记为活动状态，但 OpenVPN 进程实际并未正常运行！"
                print(warn_msg, flush=True)
                log_to_json("WARNING", "Main", warn_msg)

            if not active_tunnel_running():
                ui_cfg = load_ui_config()
                connection_enabled = ui_cfg.get("connection_enabled", True)
                if connection_enabled:
                    routing_mode = ui_cfg.get("routing_mode", "auto")

                    if routing_mode != "fixed_ip":
                        available_candidates = [n for n in merged if n.get("probe_status") == "available"]
                        available_candidates = apply_routing_filters(available_candidates, ui_cfg)

                        if available_candidates and not manual_connection_active and manual_connection_epoch == cycle_manual_epoch:
                            auto_switch_node()

        valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
        message = f"Fetched {len(candidates)} nodes. Tested {len(to_test_ids)} non-active nodes."
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            active_openvpn_node_id=active_openvpn_node_id,
            valid_nodes=valid_nodes_count,
        )
        return message
    except Exception as e:
        raise e
    finally:
        is_connecting = False
        maintenance_lock.release()


def collector_loop() -> None:
    global last_collector_heartbeat
    while True:
        last_collector_heartbeat = time.time()
        success = False
        try:
            print("[守护线程] 开始执行节点拉取与可用性检测周期任务...", flush=True)
            log_to_json("INFO", "Main", "开始执行节点拉取与可用性检测周期任务...")
            res = maintain_valid_nodes(force=False)
            if "没有拉取到新节点" not in res:
                success = True
            log_to_json("INFO", "Main", f"周期同步与检测任务完成，结果: {res}")
        except Exception as exc:
            err_msg = f"周期节点同步任务执行异常: {exc}"
            print(f"[错误] {err_msg}", flush=True)
            log_to_json("ERROR", "Main", err_msg)
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")

        if not active_tunnel_running() and not success:
            sleep_time = 30
        else:
            sleep_time = CHECK_INTERVAL_SECONDS

        time.sleep(sleep_time)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AimiliVPN - 安全登录</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090d16;
      --bg-surface: rgba(15, 23, 42, 0.45);
      --border-color: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --brand: #14b8a6;
      --primary: #14b8a6;
      --primary-gradient: linear-gradient(135deg, #20c7b4 0%, #0f9f90 100%);
      --primary-hover: linear-gradient(135deg, #14b8a6 0%, #0b7f74 100%);
      --success: #10b981;
      --danger: #f43f5e;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image:
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%);
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      padding: 24px;
      box-sizing: border-box;
    }

    .login-card {
      background: var(--bg-surface);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 40px 32px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
      text-align: center;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .brand-logo {
      width: 64px;
      height: 64px;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px auto;
      color: var(--primary);
      position: relative;
    }

    .brand-logo::after {
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 16px;
      border: 1px solid var(--success);
      opacity: 0.5;
      animation: ripple 2s infinite ease-out;
    }

    @keyframes ripple {
      0% { transform: scale(1); opacity: 0.5; }
      100% { transform: scale(1.3); opacity: 0; }
    }

    .login-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 0 0 8px 0;
      letter-spacing: 0.5px;
    }

    .login-subtitle {
      font-size: 14px;
      color: var(--text-secondary);
      margin: 0 0 32px 0;
    }

    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }

    .form-label {
      display: block;
      font-size: 12.5px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }

    .input-wrapper {
      position: relative;
    }

    .input-field {
      width: 100%;
      height: 48px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 0 16px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 15px;
      outline: none;
      transition: all 0.2s ease;
    }

    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }

    .error-message {
      color: var(--danger);
      font-size: 13px;
      margin-top: 8px;
      min-height: 18px;
      text-align: left;
      margin-left: 4px;
      display: none;
    }

    .login-btn {
      width: 100%;
      height: 48px;
      background: var(--primary-gradient);
      border: none;
      border-radius: 10px;
      color: white;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
    }

    .login-btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .login-btn:active {
      transform: translateY(1px);
    }

    .login-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="brand-logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h2 class="login-title">AimiliVPN</h2>
      <p class="login-subtitle">请输入您的管理账号和安全密码以继续</p>

      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">管理账号</label>
          <div class="input-wrapper">
            <input type="text" id="username" name="username" class="input-field" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="form-label" for="password">安全密码</label>
          <div class="input-wrapper">
            <input type="password" id="password" name="password" class="input-field" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>

        <button type="submit" id="submit_btn" class="login-btn">
          <span>登录</span>
        </button>
      </form>
    </div>
  </div>

  <script>
    async function handleLogin(e) {
      e.preventDefault();
      const uname = document.getElementById("username").value.trim();
      const pwd = document.getElementById("password").value.trim();
      const errorText = document.getElementById("error_text");
      const submitBtn = document.getElementById("submit_btn");

      errorText.style.display = "none";
      submitBtn.disabled = true;
      submitBtn.querySelector("span").textContent = "正在验证...";

      try {
        const response = await fetch("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd })
        });

        const data = await response.json();
        if (response.ok && data.ok) {
          window.location.reload();
        } else {
          errorText.textContent = data.error || "账号或密码不正确，请重新输入";
          errorText.style.display = "block";
          submitBtn.disabled = false;
          submitBtn.querySelector("span").textContent = "登录";
        }
      } catch (err) {
        errorText.textContent = "连接服务器失败，请稍后重试";
        errorText.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.querySelector("span").textContent = "登录";
      }
    }
  </script>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Aimili VPN 多协议节点管理系统</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    :root {
      --bg-dark: #0b0f19;
      --bg-surface: rgba(22, 30, 49, 0.6);
      --bg-surface-hover: rgba(30, 41, 67, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-color-hover: rgba(99, 102, 241, 0.35);
      --text-primary: #f3f4f6;
      --text-secondary: #9ca3af;
      --brand: #14b8a6;
      --primary: #14b8a6;
      --primary-gradient: linear-gradient(135deg, #20c7b4 0%, #0f9f90 100%);
      --primary-hover: linear-gradient(135deg, #14b8a6 0%, #0b7f74 100%);
      --success: #10b981;
      --success-gradient: linear-gradient(135deg, #34d399 0%, #059669 100%);
      --danger: #f43f5e;
      --danger-gradient: linear-gradient(135deg, #fb7185 0%, #e11d48 100%);
      --warning: #f59e0b;
      --warning-gradient: linear-gradient(135deg, #fbbf24 0%, #d97706 100%);
      --active-row-bg: rgba(16, 185, 129, 0.06);
      --active-row-border: rgba(16, 185, 129, 0.25);
    }

    body {
      margin: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image:
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(79, 70, 229, 0.05) 0px, transparent 50%);
      background-attachment: fixed;
      color: var(--text-primary);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    header {
      padding: 10px 32px;
      background: rgba(11, 15, 25, 0.7);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      flex-direction: column;
    }

    h1 {
      font-size: 21px;
      font-weight: 700;
      margin: 0;
      background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.5px;
      display: flex;
      align-items: center;
      gap: 11px;
    }

    .header-brand-main {
      font-weight: 760;
      letter-spacing: -.45px;
      white-space: nowrap;
    }
    .header-brand-system {
      font-size: 1em;
      font-weight: 700;
      letter-spacing: -.35px;
      white-space: nowrap;
    }

    .status {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 10px var(--success);
      display: inline-block;
    }

    .btn-group {
      display: flex;
      gap: 12px;
    }

    button, .btn-telegram {
      height: 38px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-primary);
      white-space: nowrap;
      text-decoration: none;
      box-sizing: border-box;
    }

    button:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .btn-telegram {
      background: rgba(43, 162, 223, 0.15);
      border: 1px solid rgba(43, 162, 223, 0.3);
      color: #2ba2df;
    }

    .btn-telegram:hover {
      background: rgba(43, 162, 223, 0.25);
      border-color: rgba(43, 162, 223, 0.5);
      color: #2ba2df;
      transform: translateY(-1px);
    }

    .btn-primary {
      background: var(--primary-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
    }

    .btn-primary:hover {
      background: var(--primary-hover);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .btn-danger {
      background: var(--danger-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(244, 63, 94, 0.2);
    }

    .btn-danger:hover {
      opacity: 0.95;
      box-shadow: 0 6px 16px rgba(244, 63, 94, 0.35);
    }

    button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    main {
      padding: 24px 32px;
      max-width: 1400px;
      margin: 0 auto;
    }

    .active-card {
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(79, 70, 229, 0.04) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      padding: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
      box-shadow: 0 8px 32px rgba(99, 102, 241, 0.12);
      transition: all 0.3s ease;
      width: 100%;
      box-sizing: border-box;
    }

    .active-card-info {
      display: flex;
      align-items: center;
      gap: 20px;
      flex-wrap: nowrap;
      min-width: 0;
      flex: 1 1 auto;
    }

    .active-card-details {
      display: flex;
      flex-direction: column;
      gap: 6px;
      min-width: 0;
    }

    .active-card-title {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #a5b4fc;
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .active-card-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
    }

    .active-card-meta {
      display: flex;
      gap: 16px;
      font-size: 13px;
      color: var(--text-secondary);
      flex-wrap: wrap;
    }

    .active-card-meta span strong {
      color: var(--text-primary);
    }
    .active-location-with-flag,
    .node-location-cell {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      min-width: 0;
      max-width: 100%;
      vertical-align: middle;
    }
    .active-location-with-flag > span:last-child,
    .node-location-cell > .node-cell-ellipsis {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .active-hot-pool {
      display: inline-flex;
      align-items: baseline;
      gap: 5px;
      margin-left: 2px;
      white-space: nowrap;
    }
    .active-hot-pool strong {
      color: var(--text-primary);
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .stat:hover {
      background: var(--bg-surface-hover);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(99, 102, 241, 0.1);
    }

    .stat-info {
      display: flex;
      flex-direction: column;
    }

    .stat strong {
      font-size: 32px;
      font-weight: 700;
      display: block;
      margin-bottom: 4px;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .stat span {
      font-size: 13px;
      color: var(--text-secondary);
      font-weight: 500;
    }

    .stat-icon-wrapper {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.04);
      display: flex;
      align-items: center;
      justify-content: center;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }

    .stat-icon {
      width: 22px;
      height: 22px;
      color: var(--primary);
    }

    .stat:nth-child(2) .stat-icon { color: var(--warning); }
    .stat:nth-child(3) .stat-icon { color: var(--success); }

    /* New style additions */
    .header-badge-link {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      height: 24px;
      box-sizing: border-box;
    }
    .header-badge-link:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: var(--border-color-hover);
      color: var(--text-primary);
      transform: translateY(-1px);
    }
    .flex-row-container {
      display: flex;
      gap: 20px;
      flex-wrap: wrap;
      margin-bottom: 24px;
    }
    .flex-row-container > * {
      flex: 1;
      min-width: 320px;
      margin-bottom: 0 !important;
    }
    .vps-recommend-tab {
      position: fixed;
      right: 0;
      top: 50%;
      transform: translateY(-50%);
      width: 38px;
      background: var(--primary-gradient);
      border: 1px solid var(--border-color-hover);
      border-right: none;
      border-radius: 8px 0 0 8px;
      padding: 16px 6px;
      color: white;
      font-weight: 700;
      font-size: 13px;
      line-height: 1.4;
      text-align: center;
      cursor: pointer;
      z-index: 999;
      box-shadow: -4px 0 20px rgba(99, 102, 241, 0.3);
      transition: all 0.3s ease;
      writing-mode: vertical-rl;
      text-orientation: mixed;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
    }
    .vps-recommend-tab:hover {
      padding-right: 10px;
      box-shadow: -4px 0 25px rgba(99, 102, 241, 0.5);
    }
    .official-portal-intro {
      margin: -2px 0 2px;
      padding: 10px 12px;
      border: 1px solid rgba(20,184,166,.14);
      border-radius: 9px;
      background: rgba(20,184,166,.04);
      color: var(--text-secondary);
      font-size: 12px;
      line-height: 1.55;
    }
    .official-portal-tab {
      letter-spacing: .5px;
    }

    .vps-links {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 16px;
    }

    @media (max-width: 576px) {
      .vps-links {
        grid-template-columns: 1fr;
      }
    }

    .vps-item {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.04);
      border-radius: 12px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      justify-content: space-between;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
    }

    .vps-item:hover {
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(99, 102, 241, 0.3);
      transform: translateY(-2px);
      box-shadow: 0 8px 30px rgba(99, 102, 241, 0.1);
    }

    .vps-tag {
      font-size: 11px;
      font-weight: 700;
      padding: 4px 10px;
      border-radius: 6px;
      width: fit-content;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .tag-normal {
      background: rgba(99, 102, 241, 0.15);
      color: #a5b4fc;
      border: 1px solid rgba(99, 102, 241, 0.2);
    }

    .tag-premium {
      background: rgba(16, 185, 129, 0.15);
      color: #6ee7b7;
      border: 1px solid rgba(16, 185, 129, 0.2);
    }

    .vps-desc {
      font-size: 13px;
      color: var(--text-secondary);
      line-height: 1.6;
      flex: 1;
    }

    .vps-btn {
      align-self: stretch;
      text-decoration: none;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: var(--text-primary);
      font-size: 12px;
      font-weight: 600;
      padding: 8px 16px;
      border-radius: 8px;
      transition: all 0.2s ease;
      text-align: center;
    }

    .vps-item:hover .vps-btn {
      background: var(--primary-gradient);
      border-color: transparent;
      color: white;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.2);
    }

    .vps-footer {
      border-top: 1px dashed rgba(255, 255, 255, 0.08);
      padding-top: 12px;
      font-size: 13px;
      color: var(--text-secondary);
      text-align: center;
    }

    .forum-link {
      color: #818cf8;
      font-weight: 700;
      text-decoration: none;
      transition: color 0.2s ease;
    }

    .forum-link:hover {
      color: #a5b4fc;
      text-decoration: underline;
    }
    .site-footer {
      position: relative;
      margin-top: 10px;
      padding: 16px 18px 20px;
      overflow: hidden;
      background: linear-gradient(180deg, rgba(10,18,34,.05), rgba(7,12,24,.32));
      border-top: 0;
    }
    .site-footer-inner {
      position: relative;
      z-index: 1;
      width: min(1180px, 100%);
      margin: 0 auto;
      display: grid;
      gap: 14px;
      justify-items: center;
    }
    .footer-disclaimer {
      width: min(1080px, 100%);
      box-sizing: border-box;
      padding: 17px 22px 15px;
      border: 1px solid rgba(99,102,241,.15);
      border-radius: 15px;
      background: linear-gradient(135deg, rgba(14,23,42,.78), rgba(9,16,30,.66));
      box-shadow: inset 0 1px 0 rgba(255,255,255,.022), 0 8px 24px rgba(0,0,0,.14);
      text-align: left;
    }
    .footer-disclaimer-title {
      margin-bottom: 8px;
      text-align: center;
      color: var(--text-primary);
      font-size: 14.5px;
      font-weight: 720;
      letter-spacing: .1px;
    }
    .footer-disclaimer-list {
      margin: 0;
      padding-left: 20px;
      color: rgba(156,163,175,.92);
      font-size: 11.7px;
      line-height: 1.72;
    }
    .footer-disclaimer-list li {
      padding-left: 4px;
      margin: 1px 0;
    }
    .footer-brand {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 11px;
      width: 100%;
      min-width: 0;
      padding-top: 3px;
    }
    .footer-brand-link {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      min-width: 0;
      color: var(--text-primary);
      text-decoration: none;
    }
    .footer-brand-link:hover { color: #ffffff; }
    .footer-brand-logo-image {
      width: 46px;
      height: 48px;
      max-width: 46px;
      max-height: 48px;
      display: block;
      flex: 0 0 46px;
      object-fit: contain;
      object-position: center;
      background: transparent;
      filter: none;
    }
    .footer-brand-copy {
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      justify-content: center;
      gap: 7px;
      min-width: 0;
    }
    .footer-brand strong {
      color: var(--text-primary);
      font-size: 19px;
      font-weight: 760;
      line-height: 1.22;
      letter-spacing: -.25px;
    }
    .footer-brand-version {
      display: inline-flex;
      align-items: baseline;
      gap: 7px;
      color: rgba(184,191,204,.94);
      font-size: 17px;
      font-weight: 650;
      line-height: 1.3;
      letter-spacing: -.2px;
      overflow-wrap: anywhere;
    }
    .footer-brand-version-number {
      color: rgba(154,163,177,.88);
      font-size: 11.5px;
      font-weight: 520;
      letter-spacing: 0;
      white-space: nowrap;
    }
    .footer-channels {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: center;
      gap: 9px;
    }
    .footer-channel {
      width: 172px;
      min-height: 42px;
      box-sizing: border-box;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 8px 15px;
      border: 1px solid rgba(255,255,255,.095);
      border-radius: 13px;
      background: linear-gradient(180deg, rgba(18,28,49,.90), rgba(12,21,38,.82));
      box-shadow: inset 0 1px 0 rgba(255,255,255,.025), 0 6px 18px rgba(0,0,0,.15);
      color: #e8edf5;
      font-size: 12.5px;
      font-weight: 700;
      line-height: 1;
      text-decoration: none;
      white-space: nowrap;
      transition: transform .16s ease, border-color .16s ease, box-shadow .16s ease, background .16s ease, color .16s ease;
    }
    .footer-channel:hover {
      transform: translateY(-1px);
      border-color: rgba(20,184,166,.36);
      background: rgba(20,184,166,.08);
      box-shadow: 0 8px 22px rgba(0,0,0,.2), 0 0 0 1px rgba(20,184,166,.045);
      color: #fff;
    }
    .footer-channel:active { transform: translateY(0); }
    .footer-channel:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }
    .footer-channel-icon {
      width: 16px;
      height: 16px;
      display: grid;
      place-items: center;
      flex: 0 0 16px;
    }
    .footer-channel-icon svg {
      width: 16px;
      height: 16px;
      display: block;
      fill: currentColor;
    }
    .footer-channel-youtube .footer-channel-icon { color: #ff3850; }
    .footer-channel-telegram .footer-channel-icon { color: #38aeea; }
    .footer-bottom {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: center;
      gap: 9px;
      color: rgba(170,179,192,.82);
      font-size: 12px;
    }
    .footer-bottom a {
      color: inherit;
      text-decoration: none;
      padding: 2px 4px;
      transition: color .16s ease;
    }
    .footer-bottom a:hover { color: var(--text-primary); text-decoration: underline; }
    .footer-divider { opacity: .28; }
    @media (max-width:699px) {
      .site-footer { margin-top: 9px; padding: 15px 9px 18px; }
      .site-footer-inner { gap: 12px; }
      .footer-disclaimer { padding: 13px 13px 11px; border-radius: 13px; }
      .footer-disclaimer-title { font-size: 12.5px; margin-bottom: 7px; }
      .footer-disclaimer-list { font-size: 10px; line-height: 1.7; padding-left: 18px; }
      .footer-brand { align-items: center; }
      .footer-brand-logo-image { width: 44px; height: 44px; flex-basis: 44px; }
      .footer-brand-copy {
        justify-content: flex-start;
        align-items: flex-start;
        flex-direction: column;
        gap: 2px;
      }
      .footer-brand strong { font-size: 16.5px; }\n      .footer-brand-logo-image { width: 40px; max-height: 49px; }
      .footer-brand-version { font-size: 11px; }
      .footer-channels { width: 100%; gap: 7px; }
      .footer-channel { width: 100%; min-height: 44px; padding: 9px 12px; font-size: 12.5px; border-radius: 12px; }
      .footer-bottom { gap: 7px; font-size: 11px; }
    }
    @media (min-width:700px) and (max-width:1024px) {
      .site-footer { padding-left: 16px; padding-right: 16px; }
      .footer-disclaimer { width: min(920px, 100%); }
      .footer-brand strong { font-size: 17px; }
      .footer-brand-version { font-size: 11px; }
    }

    .official-links { padding: 18px 18px 16px; border: 1px solid rgba(20,184,166,.18); border-radius: 14px; background: linear-gradient(135deg,rgba(20,184,166,.08),rgba(255,255,255,.025)); }
    .official-links-title { margin-bottom: 12px; color: var(--text-primary); font-size: 14px; font-weight: 700; }
    .official-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; }
    .official-link { display:flex; align-items:center; justify-content:center; min-height:38px; padding:8px 10px; border-radius:9px; border:1px solid rgba(255,255,255,.08); background:rgba(255,255,255,.035); color:#dbe4ea; text-decoration:none; font-size:12px; font-weight:600; transition:all .2s ease; }
    .official-link:hover { transform:translateY(-1px); color:#fff; border-color:rgba(20,184,166,.4); background:rgba(20,184,166,.12); box-shadow:0 4px 14px rgba(20,184,166,.12); }
    .official-business { grid-column:1 / -1; }
    @media (max-width:576px) { .official-grid{grid-template-columns:1fr;} .official-business{grid-column:auto;} }

    .status-badge-button {
      appearance: none;
      -webkit-appearance: none;
      font-family: inherit;
      line-height: inherit;
      cursor: pointer;
      transition: transform .15s ease, filter .15s ease, box-shadow .15s ease;
    }
    .status-badge-button:hover {
      transform: translateY(-1px);
      filter: brightness(1.08);
      box-shadow: 0 4px 12px rgba(99,102,241,.18);
    }
    .status-badge-button:focus-visible {
      outline: 2px solid var(--primary);
      outline-offset: 2px;
    }
    .background-task-strip {
      min-height: 38px;
      display: flex;
      align-items: center;
      gap: 9px;
      padding: 8px 12px;
      border: 1px solid rgba(99,102,241,.16);
      border-radius: 10px;
      background: rgba(99,102,241,.045);
      color: var(--text-secondary);
      font-size: 12px;
      line-height: 1.45;
      box-sizing: border-box;
    }
    .background-task-strip.running {
      border-color: rgba(245,158,11,.22);
      background: rgba(245,158,11,.055);
    }
    .background-task-dot {
      width: 7px;
      height: 7px;
      flex: 0 0 7px;
      border-radius: 999px;
      background: var(--primary);
      box-shadow: 0 0 8px rgba(20,184,166,.4);
    }
    .background-task-strip.running .background-task-dot {
      background: var(--warning);
      box-shadow: 0 0 8px rgba(245,158,11,.45);
      animation: pulse 1.6s ease-in-out infinite;
    }

    .country-priority {
      display: flex;
      align-items: center;
      gap: 9px;
      margin: 0 0 10px;
      padding: 8px 12px;
      min-height: 34px;
      box-sizing: border-box;
      border: 1px solid rgba(20,184,166,.14);
      border-radius: 9px;
      background: rgba(20,184,166,.035);
      color: var(--text-secondary);
      font-size: 12px;
      line-height: 1.45;
    }
    .country-priority.running {
      border-color: rgba(245,158,11,.20);
      background: rgba(245,158,11,.045);
    }
    .country-priority .badge {
      flex: 0 0 auto;
      white-space: nowrap;
    }
    @media (max-width: 768px) {
      .country-priority {
        flex-wrap: wrap;
        gap: 7px;
        padding: 8px 10px;
        font-size: 11px;
      }
    }

    .toolbar {
      position: relative;
      z-index: 50;
      isolation: isolate;
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      align-items: center;
      overflow: visible;
    }

    .toolbar select {
      width: 180px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .toolbar select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: #0f172a;
    }

    .toolbar-custom-select {
      position: relative;
      width: 200px;
      height: 46px;
      flex: 0 0 auto;
      z-index: 100;
      overflow: visible !important;
    }
    .toolbar-custom-select[data-filter-id="country_filter"] {
      width: min(270px, 42vw);
    }
    .toolbar-custom-select[data-filter-id="country_filter"] {
      width: min(270px, 42vw);
    }
    .unified-select { position: relative; z-index: 100; flex: 0 0 auto; }
    .unified-select-full { width: 100%; height: 40px; }
    .unified-select-sync { width: 112px; height: 40px; flex: 0 0 112px; }
    .unified-select-log { width: 156px; height: 32px; flex: 0 0 156px; }
    .unified-select .toolbar-custom-select-button {
      height: 40px; font-size: 13px; border-radius: 8px; padding: 0 12px; font-weight: 500;
    }
    .unified-select-log .toolbar-custom-select-button {
      height: 32px; font-size: 12px; border-radius: 7px; padding: 0 10px;
    }
    .unified-select .toolbar-custom-select-menu {
      position: fixed; left: 0; right: auto; top: auto; bottom: auto;
      z-index: 120000; max-height: min(360px, calc(100vh - 24px));
    }
    .unified-select .toolbar-custom-option { min-height: 38px; font-size: 13px; }
    .unified-select-log .toolbar-custom-option { min-height: 34px; font-size: 12px; }
    .toolbar-custom-select.open {
      z-index: 10070;
    }
    .toolbar-custom-select-button {
      width: 100%;
      height: 44px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      border: 1px solid var(--border-color);
      border-radius: 9px;
      padding: 0 13px;
      background: rgba(255,255,255,.03);
      color: var(--text-primary);
      font: inherit;
      font-size: 14px;
      font-weight: 500;
      text-align: left;
      cursor: pointer;
      transition: all .2s ease;
      box-sizing: border-box;
      -webkit-font-smoothing: antialiased;
    }
    .toolbar-custom-select-button:hover,
    .toolbar-custom-select.open .toolbar-custom-select-button {
      border-color: var(--primary);
      background: #0f172a;
      box-shadow: 0 0 0 2px rgba(99,102,241,.12);
    }
    .toolbar-custom-select-button:focus-visible {
      outline: 2px solid var(--primary);
      outline-offset: 2px;
    }
    .toolbar-custom-select-label {
      min-width: 0;
      max-width: calc(100% - 24px);
      display: inline-flex;
      align-items: center;
      gap: 8px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      line-height: 1.25;
      overflow-wrap: anywhere;
    }
    .toolbar-custom-option-label {
      min-width: 0;
      flex: 1 1 auto;
      display: inline-flex;
      align-items: center;
      gap: 9px;
      overflow-wrap: anywhere;
      word-break: break-word;
      line-height: 1.35;
    }
    .toolbar-custom-option-name,
    .toolbar-custom-selected-count {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .toolbar-custom-selected-count {
      flex: 0 0 auto;
      color: var(--text-secondary);
    }
    .country-flag-img {
      width: 24px;
      height: 18px;
      min-width: 24px;
      object-fit: cover;
      object-position: center;
      display: inline-block;
      flex: 0 0 24px;
      border-radius: 3px;
      box-shadow: 0 0 0 1px rgba(255,255,255,.12), 0 2px 6px rgba(0,0,0,.22);
      background: rgba(255,255,255,.08);
      vertical-align: middle;
    }
    .country-flag-fallback {
      width: 24px;
      height: 18px;
      min-width: 24px;
      display: inline-flex;
      flex: 0 0 24px;
      align-items: center;
      justify-content: center;
      font-size: 19px;
      line-height: 1;
    }
    .toolbar-custom-select-arrow {
      color: var(--text-secondary);
      font-size: 16px;
      line-height: 1;
      flex: 0 0 auto;
      transform: translateY(-1px);
      transition: transform .18s ease;
    }
    .toolbar-custom-select.open .toolbar-custom-select-arrow {
      transform: rotate(180deg) translateY(1px);
    }
    .toolbar-custom-select-menu {
      position: absolute;
      left: 0;
      right: auto;
      top: calc(100% + 8px);
      bottom: auto;
      z-index: 10080;
      min-width: 100%;
      max-height: min(360px, calc(100vh - 40px));
      overflow-y: auto;
      overscroll-behavior: contain;
      padding: 5px;
      border: 1px solid rgba(99,102,241,.25);
      border-radius: 10px;
      background: #0b1324;
      box-shadow: 0 18px 40px rgba(0,0,0,.55), 0 4px 12px rgba(0,0,0,.28);
      backdrop-filter: none;
      -webkit-backdrop-filter: none;
      scrollbar-width: thin;
      scrollbar-color: rgba(20,184,166,.42) transparent;
      display: none;
    }
    .toolbar-custom-select.open .toolbar-custom-select-menu {
      display: block;
    }
    .toolbar-custom-select-menu::-webkit-scrollbar { width: 4px; }
    .toolbar-custom-select-menu::-webkit-scrollbar-track { background: transparent; }
    .toolbar-custom-select-menu::-webkit-scrollbar-thumb { background: rgba(20,184,166,.42); border-radius: 999px; }
    .toolbar-custom-select-menu::-webkit-scrollbar-thumb:hover { background: rgba(20,184,166,.62); }

    .toolbar-custom-option {
      width: 100%;
      min-height: 40px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 0 12px;
      border: 0;
      border-radius: 8px;
      background: transparent;
      color: var(--text-primary);
      font: inherit;
      font-size: 14px;
      font-weight: 500;
      text-align: left;
      cursor: pointer;
      -webkit-font-smoothing: antialiased;
      box-sizing: border-box;
      user-select: none;
    }
    .toolbar-custom-option:hover,
    .toolbar-custom-option:focus-visible {
      background: rgba(99,102,241,.08);
      color: var(--text-primary);
      outline: none;
    }
    .toolbar-custom-option.active {
      background: rgba(99,102,241,.12);
      color: var(--text-primary);
      outline: none;
    }
    .toolbar-custom-option-count {
      color: var(--text-secondary);
      font-size: 13px;
      font-weight: 500;
      line-height: 1;
      min-width: 58px;
      text-align: right;
      flex: 0 0 62px;
      white-space: nowrap;
    }

    .toolbar input {
      flex: 1;
      min-width: 250px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      transition: all 0.2s ease;
    }

    .toolbar input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.8);
    }

    .table-wrapper {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      position: relative;
      z-index: 1;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }

    html, body {
      max-width: 100%;
      overflow-x: hidden;
      scrollbar-width: thin;
      scrollbar-color: rgba(20,184,166,.42) rgba(15,23,42,.78);
    }

    /* Consistent slim theme scrollbar. This covers the page edge, modals,
       dropdowns and any nested scroll container instead of the browser's
       default light-gray scrollbar. */
    * {
      scrollbar-width: thin;
      scrollbar-color: rgba(20,184,166,.42) rgba(15,23,42,.78);
    }
    *::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }
    *::-webkit-scrollbar-track {
      background: rgba(15,23,42,.78);
      border-radius: 999px;
    }
    *::-webkit-scrollbar-thumb {
      background: rgba(20,184,166,.42);
      border-radius: 999px;
      border: 1px solid rgba(15,23,42,.72);
    }
    *::-webkit-scrollbar-thumb:hover {
      background: rgba(20,184,166,.60);
    }
    *::-webkit-scrollbar-corner {
      background: rgba(15,23,42,.78);
    }

    @media (max-width:1100px) {
      .toolbar { gap: 10px; padding: 12px; }
      .toolbar-custom-select {
        width: calc(25% - 8px);
        min-width: 0;
      }
      .toolbar-custom-select[data-filter-id="country_filter"] {
        width: calc(25% - 8px);
      }
      .toolbar-custom-select-button {
        padding: 0 11px;
        font-size: 13px;
      }
      .toolbar input { min-width: 0; flex: 1 1 100%; }
    }

    @media (max-width:699px) {
      .toolbar {
        display: grid;
        grid-template-columns: minmax(0,1fr) minmax(0,1fr);
        gap: 9px;
        padding: 10px;
      }
      .toolbar-custom-select,
      .toolbar-custom-select[data-filter-id="country_filter"] {
        width: 100%;
        height: 44px;
      }
      .toolbar-custom-select-button {
        height: 44px;
        padding: 0 10px;
        font-size: 13px;
      }
      .toolbar input {
        grid-column: 1 / -1;
        width: 100%;
        height: 42px;
        min-width: 0;
      }
      .toolbar-custom-select-menu {
        max-width: min(420px, calc(100vw - 20px));
        min-width: min(190px, calc(100vw - 20px));
        max-height: min(320px, calc(100vh - 120px));
      }
      .toolbar-custom-option {
        min-height: 42px;
        padding: 7px 10px;
        align-items: flex-start;
      }
      .toolbar-custom-option-count {
        min-width: 0;
        flex: 0 0 auto;
        padding-top: 2px;
      }
    }

    .table-wrapper {
      width: 100%;
      max-width: 100%;
      overflow: hidden !important;
    }
    .table-container {
      width: 100%;
      max-width: 100%;
      overflow-x: auto !important;
      overflow-y: hidden;
      -webkit-overflow-scrolling: touch;
      scrollbar-width: thin;
      scrollbar-color: rgba(20,184,166,.28) transparent;
    }

    .table-container::-webkit-scrollbar {
      height: 5px;
    }
    .table-container::-webkit-scrollbar-track { background: transparent; }
    .table-container::-webkit-scrollbar-thumb { background: rgba(20,184,166,.28); border-radius: 999px; }

    table.node-table {
      width: 100%;
      min-width: 1180px;
      max-width: none;
      border-collapse: collapse;
      text-align: left;
      table-layout: fixed;
    }

    th, td {
      padding: 11px 8px;
      border-bottom: 1px solid var(--border-color);
      font-size: 14px;
      box-sizing: border-box;
      vertical-align: middle;
      min-width: 0;
      overflow: hidden;
    }

    .node-cell-ellipsis {
      min-width: 0;
      width: 100%;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: normal;
      overflow-wrap: anywhere;
      line-height: 1.35;
      display: -webkit-box;
      -webkit-box-orient: vertical;
      -webkit-line-clamp: 2;
    }

    .node-address-cell .node-cell-ellipsis {
      white-space: nowrap;
      overflow-wrap: normal;
      display: block;
      text-overflow: ellipsis;
    }

    .node-status-cell {
      white-space: nowrap;
      text-align: center;
      overflow: visible !important;
    }

    .node-status-cell .badge,
    .node-status-cell .status-badge-button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      white-space: nowrap;
      width: auto !important;
      min-width: 72px;
      max-width: max-content;
      min-height: 30px;
      flex: 0 0 auto;
      overflow: visible;
      box-sizing: border-box;
    }

    .node-protocol-cell {
      text-align: center;
      white-space: nowrap;
    }

    .node-address-cell {
      white-space: nowrap;
    }

    .node-address-cell .mono {
      font-size: 13px;
    }

    .node-table td:nth-child(5),
    .node-table td:nth-child(6) {
      font-size: 13px;
    }

    th {
      background: rgba(17, 24, 39, 0.4);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-secondary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    tr {
      transition: background 0.2s ease;
    }

    tr:hover {
      background: rgba(255, 255, 255, 0.015);
    }

    .active-row {
      background: var(--active-row-bg) !important;
      outline: 2px solid var(--success) !important;
      outline-offset: -2px;
      position: relative;
      z-index: 5;
    }

    .active-row td {
      border-bottom: 1px solid var(--active-row-border);
      border-top: 1px solid var(--active-row-border);
    }

    .badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
    }

    .protocol-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 88px;
      max-width: 130px;
      min-height: 28px;
      box-sizing: border-box;
      padding: 4px 9px;
      border-radius: 7px;
      border: 1px solid rgba(20, 184, 166, 0.28);
      background: rgba(20, 184, 166, 0.08);
      color: var(--primary);
      font-size: 12px;
      font-weight: 700;
      text-decoration: none;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .protocol-link:hover {
      border-color: rgba(20, 184, 166, 0.55);
      background: rgba(20, 184, 166, 0.14);
      color: #5eead4;
    }

    .badge-pulse {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      animation: pulse 1.5s infinite;
      display: inline-block;
    }

    @keyframes pulse {
      0% { transform: scale(0.9); opacity: 1; }
      50% { transform: scale(1.6); opacity: 0.4; }
      100% { transform: scale(0.9); opacity: 1; }
    }

    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .available {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.2);
    }

    .unavailable {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
      border-color: rgba(244, 63, 94, 0.2);
    }

    .not_checked {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border-color: rgba(245, 158, 11, 0.2);
    }

    .testing {
      background: rgba(59, 130, 246, 0.12);
      color: #93c5fd;
      border-color: rgba(59, 130, 246, 0.24);
    }

    .current-badge {
      background: rgba(99, 102, 241, 0.15);
      color: #818cf8;
      border-color: rgba(99, 102, 241, 0.3);
    }

    .table-actions {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: nowrap;
    }

    .table-actions .connect-btn,
    .table-actions .test-btn {
      padding: 0 8px !important;
      white-space: nowrap;
      flex: 0 0 auto;
    }

    @media (max-width: 1100px) {
      .table-container {
        overflow-x: auto;
        overflow-y: hidden;
        -webkit-overflow-scrolling: touch;
        scrollbar-width: thin;
      }
      table {
        min-width: 820px;
        max-width: none;
        table-layout: auto;
      }
      th, td {
        padding: 10px 6px;
        font-size: 12px;
      }
      .node-status-cell .badge,
      .node-status-cell .status-badge-button {
        min-width: 58px;
      }
      .node-protocol-cell {
        font-size: 12px;
      }
    }

    @media (max-width: 760px) {
      .active-card {
        align-items: flex-start;
        padding: 16px;
      }
      .active-card-info {
        flex-wrap: wrap;
      }
      .active-card-meta {
        gap: 9px;
      }
      .table-actions {
        flex-wrap: wrap;
      }
      .table-actions .connect-btn,
      .table-actions .test-btn {
        padding: 0 6px !important;
        font-size: 11px;
      }
    }

    .connect-btn {
      background: transparent;
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .connect-btn:hover:not(:disabled) {
      background: var(--primary-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.3);
    }

    .connect-btn:disabled {
      opacity: 0.3;
      cursor: not-allowed;
    }

    .test-btn {
      background: transparent;
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .test-btn:hover:not(:disabled) {
      background: var(--success-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(16, 185, 129, 0.3);
    }

    .test-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .mono {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 13px;
      color: #e2e8f0;
    }

    .switching-active-card {
      border-color: rgba(245, 158, 11, .38) !important;
      background: linear-gradient(135deg, rgba(245,158,11,.09), rgba(255,255,255,.025)) !important;
      box-shadow: 0 0 20px rgba(245,158,11,.10) !important;
    }
    .switching-icon {
      background: rgba(245,158,11,.13) !important;
      border-color: rgba(245,158,11,.28) !important;
      color: #f59e0b !important;
    }
    .switch-spinner {
      width: 24px; height: 24px; animation: spin .9s linear infinite; color: #f59e0b;
    }
    .switching-badge {
      background: rgba(245,158,11,.13) !important; color: #fbbf24 !important; border-color: rgba(245,158,11,.3) !important;
    }
    .switch-elapsed { margin-left: 6px; color: var(--text-secondary); font-size: 12px; font-weight: 500; }
    .switching-target { color: var(--text-primary); opacity: .96; }
    .switching-meta { display: flex; flex-wrap: wrap; gap: 6px 14px; }
    .switching-lock-note { display:flex; align-items:center; gap:7px; color:#fbbf24; font-size:12px; white-space:nowrap; margin-left:14px; }
    .switch-spinner-dot { width:7px; height:7px; border-radius:999px; background:#f59e0b; box-shadow:0 0 8px rgba(245,158,11,.5); animation:pulse 1.2s ease-in-out infinite; }
    .switching-btn { opacity:1 !important; background:rgba(245,158,11,.12) !important; border-color:rgba(245,158,11,.34) !important; color:#fbbf24 !important; display:inline-flex; align-items:center; justify-content:center; gap:6px; }
    .switching-btn .switch-spinner { width:13px; height:13px; }
    .latency-val {
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
    }

    .latency-good {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
    }

    .latency-medium {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
    }

    .latency-poor {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
    }

    @media (max-width: 768px) {
      header {
        flex-direction: column;
        align-items: flex-start;
        padding: 16px 20px;
      }
      .btn-group {
        width: 100%;
        margin-top: 12px;
      }
      .btn-group button, .btn-group .btn-telegram {
        flex: 1;
      }
      .btn-group .dropdown {
        flex: 1;
        display: flex;
      }
      .btn-group .dropdown button {
        width: 100%;
        flex: 1;
      }
      main {
        padding: 16px 20px;
      }
      .active-card {
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
      }
      .active-card button {
        width: 100%;
      }
    }

    /* Admin dropdown styles */
    .dropdown {
      position: relative;
      display: inline-block;
    }
    .dropdown-content {
      display: none;
      position: absolute;
      right: 0;
      margin-top: 6px;
      min-width: 140px;
      background: rgba(22, 30, 49, 0.95);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 1000;
      overflow: hidden;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }
    .dropdown-content a {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      color: var(--text-primary);
      text-decoration: none;
      font-size: 13px;
      font-weight: 500;
      transition: background 0.2s;
    }
    .dropdown-content a:hover {
      background: rgba(255,255,255,0.08);
    }

    #github_dropdown {
      min-width: 300px;
      overflow: visible;
      padding: 4px;
    }

    #github_dropdown > a {
      border-radius: 7px;
      font-size: 13px;
      padding: 8px 10px;
    }

    .github-update-panel {
      border-top: 1px solid rgba(129,140,248,.16);
      margin-top: 3px;
      padding: 9px 10px 8px;
    }

    .github-update-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      min-height: 24px;
    }

    .github-update-label {
      color: var(--text-secondary);
      font-size: 12px;
      font-weight: 500;
    }

    .github-update-version {
      color: var(--text-primary);
      font-size: 12px;
      font-weight: 700;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }

    .github-update-message {
      margin-top: 4px;
      color: var(--text-secondary);
      font-size: 11px;
      line-height: 1.45;
      min-height: 16px;
    }

    .github-update-actions {
      display: flex;
      gap: 8px;
      margin-top: 8px;
    }

    .github-update-actions button {
      height: 30px;
      min-height: 30px;
      padding: 0 11px;
      font-size: 12px;
      border-radius: 7px;
      flex: 1;
    }

    /* Modal styles */
    .modal {
      display: none;
      position: fixed;
      z-index: 10000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      overflow: hidden;
      background-color: rgba(9, 13, 22, 0.7);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      align-items: center;
      justify-content: center;
    }
    .modal-content {
      background: rgba(22, 30, 49, 0.9);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      width: 90%;
      max-width: 480px;
      max-height: calc(100vh - 24px);
      padding: 32px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
      position: relative;
      box-sizing: border-box;
      overflow-y: auto;
      overflow-x: hidden;
      overscroll-behavior: contain;
      scrollbar-gutter: stable;
      scrollbar-width: thin;
      scrollbar-color: rgba(20,184,166,.30) transparent;
      animation: modalFadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .modal-content {
      scrollbar-width: thin;
      scrollbar-color: rgba(20,184,166,.30) transparent;
    }
    .modal-content::-webkit-scrollbar {
      width: 4px;
      height: 4px;
    }
    .modal-content::-webkit-scrollbar-track {
      background: transparent;
    }
    .modal-content::-webkit-scrollbar-thumb {
      background: rgba(20,184,166,.30);
      border-radius: 999px;
    }
    .modal-content::-webkit-scrollbar-thumb:hover {
      background: rgba(20,184,166,.48);
    }

    .rs-modal-content {
      width: min(1080px, 94vw);
      max-width: 1080px;
      max-height: calc(100vh - 32px);
      padding: 24px;
      overflow-y: auto;
      overflow-x: hidden;
      overscroll-behavior: contain;
      scrollbar-width: thin;
      scrollbar-color: rgba(20,184,166,.34) transparent;
    }
    .rs-modal-content::-webkit-scrollbar {
      width: 4px;
    }
    .rs-modal-content::-webkit-scrollbar-track {
      background: transparent;
    }
    .rs-modal-content::-webkit-scrollbar-thumb {
      background: rgba(20,184,166,.34);
      border-radius: 999px;
    }
    .rs-modal-content::-webkit-scrollbar-thumb:hover {
      background: rgba(20,184,166,.52);
    }
    .rs-modal-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 14px;
      margin-bottom: 16px;
    }
    .rs-close-btn {
      flex: 0 0 auto;
      width: 34px;
      height: 34px;
      border: 1px solid var(--border-color);
      background: rgba(255,255,255,.03);
      border-radius: 9px;
      color: var(--text-secondary);
      cursor: pointer;
    }
    .rs-close-btn:hover {
      color: var(--text-primary);
      background: rgba(255,255,255,.06);
    }
    .rs-local-card,
    .rs-form-card,
    .rs-list-card {
      border: 1px solid var(--border-color);
      background: rgba(255,255,255,.018);
      border-radius: 12px;
      box-sizing: border-box;
    }
    .rs-local-card {
      padding: 14px;
      margin-bottom: 14px;
    }
    .rs-card-label,
    .rs-step-title,
    .rs-list-title {
      color: var(--text-primary);
      font-weight: 700;
    }
    .rs-card-label {
      font-size: 12px;
      margin-bottom: 7px;
    }
    .rs-local-row {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .rs-local-input {
      flex: 1 1 auto;
      min-width: 0;
    }
    .rs-copy-btn {
      flex: 0 0 auto;
      height: 40px;
      padding: 0 14px;
    }
    .rs-help {
      font-size: 11px;
      color: var(--text-secondary);
      line-height: 1.55;
    }
    .rs-action-grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 14px;
      align-items: start;
    }
    .rs-form-card {
      padding: 16px;
      align-self: start;
    }
    .rs-step-title {
      display: flex;
      align-items: center;
      gap: 7px;
      font-size: 15px;
      margin-bottom: 6px;
    }
    .rs-step-title > span {
      width: 24px;
      height: 24px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 7px;
      background: rgba(20,184,166,.10);
      border: 1px solid rgba(20,184,166,.22);
      color: var(--primary);
      font-size: 12px;
    }
    .rs-form-help {
      min-height: 35px;
      margin-bottom: 11px;
    }
    .rs-form-grid {
      display: grid;
      gap: 9px;
    }
    .rs-sync-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 8px;
    }
    .rs-full-btn {
      width: 100%;
      height: 40px;
    }
    .rs-list-card {
      margin-top: 14px;
      padding: 14px 16px;
    }
    .rs-list-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 10px;
    }
    .rs-list-title {
      display: flex;
      align-items: center;
      gap: 7px;
      font-size: 14px;
    }
    .rs-count-badge {
      min-width: 22px;
      height: 21px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0 7px;
      box-sizing: border-box;
      border-radius: 999px;
      background: rgba(20,184,166,.10);
      border: 1px solid rgba(20,184,166,.24);
      color: var(--primary);
      font-size: 11px;
      font-weight: 700;
    }
    .rs-list {
      display: grid;
      gap: 8px;
    }
    .rs-empty {
      padding: 20px 12px;
      text-align: center;
      color: var(--text-secondary);
      border: 1px dashed rgba(148,163,184,.16);
      border-radius: 9px;
    }
    .rs-invite-item,
    .rs-relation-item {
      border: 1px solid rgba(148,163,184,.13);
      background: rgba(15,23,42,.28);
      border-radius: 10px;
      padding: 12px 13px;
    }
    .rs-item-head {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      flex-wrap: wrap;
    }
    .rs-item-main {
      min-width: 0;
      flex: 1 1 520px;
    }
    .rs-item-name {
      display: flex;
      align-items: center;
      gap: 7px;
      flex-wrap: wrap;
      color: var(--text-primary);
      font-size: 13px;
      font-weight: 700;
    }
    .rs-item-meta {
      margin-top: 4px;
      font-size: 11px;
      line-height: 1.55;
      color: var(--text-secondary);
      word-break: break-word;
    }
    .rs-item-code {
      display: inline-flex;
      align-items: center;
      margin-top: 7px;
      padding: 6px 9px;
      max-width: 100%;
      box-sizing: border-box;
      background: rgba(0,0,0,.18);
      border: 1px solid rgba(148,163,184,.12);
      border-radius: 7px;
      color: var(--text-primary);
      font: 700 13px/1.2 Consolas, monospace;
      letter-spacing: .45px;
      overflow-wrap: anywhere;
    }
    .rs-item-actions {
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 6px;
      flex: 0 0 auto;
      flex-wrap: wrap;
    }
    .rs-item-actions .test-btn {
      height: 30px;
      padding: 0 9px;
      white-space: nowrap;
    }
    .rs-direction {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 999px;
      background: rgba(99,102,241,.10);
      border: 1px solid rgba(99,102,241,.20);
      color: #a5b4fc;
      font-size: 10px;
      font-weight: 600;
    }
    .rs-direction.bidir {
      background: rgba(20,184,166,.10);
      border-color: rgba(20,184,166,.22);
      color: #5eead4;
    }
    .rs-security-note {
      margin-top: 12px;
      padding: 10px 12px;
      background: rgba(245,158,11,.06);
      border: 1px solid rgba(245,158,11,.16);
      border-radius: 8px;
      font-size: 11px;
      color: var(--text-secondary);
      line-height: 1.5;
    }
    .rs-footer-close {
      height: 36px;
      padding: 0 16px;
      border-radius: 8px;
      border: 1px solid var(--border-color);
      background: transparent;
      color: var(--text-secondary);
      cursor: pointer;
    }
    .rs-footer-close:hover {
      color: var(--text-primary);
      background: rgba(255,255,255,.04);
    }

    .rs-edit-modal-content {
      width: min(680px, 94vw);
      max-width: 680px;
      padding: 22px;
      max-height: min(720px, calc(100vh - 28px));
      overflow-y: auto;
      overflow-x: hidden;
      scrollbar-width: thin;
      scrollbar-color: rgba(20,184,166,.28) transparent;
    }
    .rs-edit-modal-content::-webkit-scrollbar {
      width: 3px;
    }
    .rs-edit-modal-content::-webkit-scrollbar-track {
      background: transparent;
    }
    .rs-edit-modal-content::-webkit-scrollbar-thumb {
      background: rgba(20,184,166,.28);
      border-radius: 999px;
    }
    .rs-edit-form {
      display: grid;
      gap: 14px;
    }
    .rs-edit-field {
      display: grid;
      gap: 6px;
    }
    .rs-edit-field label {
      font-size: 12px;
      color: var(--text-primary);
      font-weight: 650;
    }
    .rs-edit-field-help {
      font-size: 11px;
      color: var(--text-secondary);
      line-height: 1.5;
    }
    .rs-edit-grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 10px;
      align-items: start;
    }
    .rs-edit-sync-row {
      grid-template-columns: minmax(0, 1fr) 180px;
    }
    .rs-edit-error {
      padding: 9px 11px;
      border-radius: 8px;
      color: #fda4af;
      background: rgba(244,63,94,.07);
      border: 1px solid rgba(244,63,94,.17);
      font-size: 12px;
      line-height: 1.45;
    }
    .rs-edit-actions {
      display: flex;
      justify-content: flex-end;
      align-items: center;
      gap: 8px;
      margin-top: 2px;
    }
    .rs-edit-save {
      height: 36px;
      min-width: 112px;
      padding: 0 15px;
    }

    /* Native select popup is browser-rendered; use a dark color scheme so its
       scrollbar does not appear as a bright white/gray strip. */
    select {
      color-scheme: dark;
      scrollbar-width: thin;
      scrollbar-color: rgba(20,184,166,.30) rgba(15,23,42,.72);
    }
    select::-webkit-scrollbar {
      width: 4px;
      height: 4px;
    }
    select::-webkit-scrollbar-track {
      background: rgba(15,23,42,.72);
    }
    select::-webkit-scrollbar-thumb {
      background: rgba(20,184,166,.30);
      border-radius: 999px;
    }
    select::-webkit-scrollbar-thumb:hover {
      background: rgba(20,184,166,.48);
    }

    @media (max-width: 860px) {
      .rs-modal-content {
        width: 96vw;
        max-height: calc(100vh - 18px);
        padding: 18px;
      }
      .rs-action-grid {
        grid-template-columns: 1fr;
      }
      .rs-local-row {
        flex-direction: column;
        align-items: stretch;
      }
      .rs-copy-btn {
        width: 100%;
      }
      .rs-edit-modal-content {
        width: 96vw;
        max-height: calc(100vh - 18px);
        padding: 18px;
      }
      .rs-edit-grid {
        grid-template-columns: 1fr;
      }
      .rs-edit-sync-row {
        grid-template-columns: 1fr 1fr;
      }
      .rs-item-actions {
        width: 100%;
        justify-content: flex-start;
      }
      .toolbar-custom-select {
        width: 100%;
      }
    }

    .vps-modal-content {
      max-height: calc(100vh - 32px);
      overflow-y: auto;
      overscroll-behavior: contain;
    }
    .vps-modal-header {
      position: sticky;
      top: -32px;
      z-index: 5;
      background: rgba(22, 30, 49, 0.98);
      padding: 14px 0 16px;
      border-bottom: 1px solid rgba(20, 184, 166, 0.16);
    }

    @keyframes modalFadeIn {
      from { transform: scale(0.95); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }

    /* Inputs in settings */
    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }
    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }
    .input-field {
      width: 100%;
      height: 40px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }
    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }
    /* Long labels/placeholders and resource-sharing fields must never be clipped. */
    .form-group,
    .form-label,
    .rs-edit-field,
    .rs-edit-field label,
    .rs-card-label,
    .rs-step-title,
    .rs-list-title,
    .field-label,
    .rs-item-main {
      min-width: 0;
      max-width: 100%;
    }
    .form-label,
    .rs-edit-field label,
    .field-label,
    .rs-card-label,
    .rs-step-title,
    .rs-list-title {
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: break-word;
      line-height: 1.45;
    }
    .input-field,
    textarea,
    input[type="text"],
    input[type="password"],
    input[type="number"],
    input[type="url"],
    input[type="email"] {
      min-width: 0;
      max-width: 100%;
      text-overflow: ellipsis;
    }
    .input-field::placeholder,
    textarea::placeholder {
      color: var(--text-secondary);
      opacity: .78;
      overflow-wrap: anywhere;
    }
    .rs-sync-row,
    .rs-edit-sync-row {
      min-width: 0;
    }
    .rs-item-actions {
      min-width: 0;
      flex-wrap: wrap;
    }
    select option {
      background-color: #0f172a;
      color: #f8fafc;
    }

    /* Option Card Styles for Proxy/Routing Settings */
    .option-group {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 10px;
      margin-top: 6px;
    }

    @media (max-width: 480px) {
      .option-group {
        grid-template-columns: 1fr;
      }
    }

    .option-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 12px 14px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      user-select: none;
      position: relative;
      text-align: left;
    }

    .option-card:hover {
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(99, 102, 241, 0.25);
      transform: translateY(-1px);
    }

    .option-card.active {
      background: rgba(99, 102, 241, 0.08);
      border-color: var(--primary);
      box-shadow: 0 0 12px rgba(99, 102, 241, 0.15);
    }

    .option-card-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-primary);
      margin-bottom: 4px;
    }

    .option-card-desc {
      font-size: 11px;
      color: var(--text-secondary);
      line-height: 1.3;
    }
  </style>
</head>
<body>
<header>
  <div class="brand">
    <h1>
      <svg xmlns="http://www.w3.org/2000/svg" style="width:24px; height:24px; color:#818cf8;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
      <span class="header-brand-main">Aimili VPN</span><span class="header-brand-system">多协议节点管理系统</span>
    </h1>
    <div id="status" class="status" style="display: none;"><span class="status-dot"></span>服务加载中...</div>
  </div>
  <div class="btn-group">

    <div class="dropdown">
      <button id="github_btn" class="btn-primary" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" style="vertical-align: middle; margin-right: 4px;"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
        GITHUB
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="github_dropdown" class="dropdown-content">
        <a href="https://github.com/hankinsus/aimili-vpngate-production" target="_blank">正式版</a>
        <div class="github-update-panel" id="github_update_panel">
          <div class="github-update-row">
            <span class="github-update-label">当前正式版</span>
            <code class="github-update-version" id="github_current_version">读取中...</code>
          </div>
          <div class="github-update-message" id="github_update_message">点击“检查更新”获取 GitHub 最新版本。</div>
          <div class="github-update-actions">
            <button type="button" id="github_check_update">检查更新</button>
            <button type="button" id="github_apply_update" class="btn-primary" style="display:none;">立即更新</button>
          </div>
        </div>
      </div>
    </div>
    <a href="https://t.me/ILovestudycn" target="_blank" class="btn-telegram">
      <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" style="vertical-align: middle; margin-right: 4px;"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8.287 5.906c-.778.324-2.334.994-4.666 2.01-.378.15-.577.298-.595.442-.03.243.275.339.69.47l.175.055c.408.133.958.288 1.243.294.26.006.549-.1.868-.32 2.179-1.471 3.304-2.214 3.374-2.23.05-.012.12-.026.166.016.047.041.042.12.037.141-.03.129-1.227 1.241-1.846 1.817-.193.18-.33.307-.358.336-.063.065-.129.13-.19.193-.34.347-.597.609-.043.974.265.175.474.319.684.457.228.15.457.301.765.503.074.049.143.098.207.143.297.206.58.404.916.373.195-.018.398-.2.502-.754.25-1.332.74-4.22.842-5.281.01-.088.001-.22-.103-.312-.104-.092-.252-.09-.323-.087a1.52 1.52 0 0 0-.254.04z"/></svg>
      Telegram
    </a>
    <button id="refresh" class="btn-primary" style="background: var(--success-gradient);" title="重新开始一轮全球资源采集与可用性检测，不清空历史数据，不断开当前 VPN。">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      重新轮询全球库
    </button>
    <button id="btn_add_node" class="btn-primary" type="button" onclick="openAddNodeModal()" style="background: rgba(129,140,248,0.14); border: 1px solid rgba(129,140,248,0.35);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 5v14M5 12h14" /></svg>
      添加节点
    </button>
    <div class="dropdown">
      <button id="admin_btn" class="btn-primary" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
        管理员
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="admin_dropdown" class="dropdown-content">
        <a href="javascript:void(0)" onclick="openCredentialsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          网页安全
        </a>
        <a href="javascript:void(0)" onclick="openNetworkModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理设置
        </a>
        <a href="javascript:void(0)" onclick="openGatewayModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关设置
        </a>
        <a href="javascript:void(0)" onclick="openResourceShareModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8.5 12a3.5 3.5 0 107 0 3.5 3.5 0 00-7 0zm6.25-5.75L16 4.99M15.75 19.01L14.5 17.75M5.99 14L4.24 15.75M5.99 10L4.24 8.25M18.01 10l1.75-1.75M18.01 14l1.75 1.75" /></svg>
          资源共享
        </a>
        <a href="javascript:void(0)" onclick="openLogsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2-2z" /></svg>
          日志
        </a>
        <a href="javascript:void(0)" onclick="logoutAdmin()" style="color: var(--danger); border-top: 1px solid rgba(255,255,255,0.05);">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
          退出
        </a>
      </div>
    </div>
  </div>
</header>
<main>

    <!-- 当前连接活动节点卡片 -->
    <section class="active-node-section" id="active_node_card" style="margin-bottom: 14px;">
      <!-- Rendered dynamically by render() -->
    </section>
    <div id="background_activity_status" class="background-task-strip" style="display:none;margin-bottom:10px;">
      <span class="background-task-dot"></span>
      <span id="background_activity_text"></span>
    </div>
    <div id="country_priority_status" class="country-priority" style="display:none;"></div>

  <section class="toolbar">
    <select id="status_filter" aria-hidden="true" tabindex="-1" style="display:none;">
      <option value="all">全部节点</option>
      <option value="available">可用节点</option>
      <option value="not_checked">待检测</option>
      <option value="testing">检测中</option>
      <option value="unavailable">失效节点</option>
    </select>
    <div id="status_filter_widget" class="toolbar-custom-select" data-filter-id="status_filter" aria-label="状态筛选">
      <button id="status_filter_button" type="button" class="toolbar-custom-select-button" data-filter-toggle aria-expanded="false">
        <span id="status_filter_label" class="toolbar-custom-select-label">全部节点</span>
        <span class="toolbar-custom-select-arrow">⌄</span>
      </button>
      <div id="status_filter_menu" class="toolbar-custom-select-menu" role="listbox"></div>
    </div>

    <select id="country_filter" aria-hidden="true" tabindex="-1" style="display:none;">
      <option value="">全球国家</option>
    </select>
    <div id="country_filter_widget" class="toolbar-custom-select" data-filter-id="country_filter" aria-label="国家筛选">
      <button id="country_filter_button" type="button" class="toolbar-custom-select-button" data-filter-toggle aria-expanded="false">
        <span id="country_filter_label" class="toolbar-custom-select-label">🌐 全球国家</span>
        <span class="toolbar-custom-select-arrow">⌄</span>
      </button>
      <div id="country_filter_menu" class="toolbar-custom-select-menu" role="listbox"></div>
    </div>

    <select id="protocol_filter" aria-hidden="true" tabindex="-1" style="display:none;">
      <option value="">所有协议</option>
      <option value="openvpn">OpenVPN</option>
      <option value="softether">SSL-VPN</option>
      <option value="sstp">SSTP</option>
      <option value="l2tp-ipsec">L2TP/IPsec</option>
    </select>
    <div id="protocol_filter_widget" class="toolbar-custom-select" data-filter-id="protocol_filter" aria-label="协议筛选">
      <button id="protocol_filter_button" type="button" class="toolbar-custom-select-button" data-filter-toggle aria-expanded="false">
        <span id="protocol_filter_label" class="toolbar-custom-select-label">所有协议</span>
        <span class="toolbar-custom-select-arrow">⌄</span>
      </button>
      <div id="protocol_filter_menu" class="toolbar-custom-select-menu" role="listbox"></div>
    </div>

    <select id="ip_type_filter" aria-hidden="true" tabindex="-1" style="display:none;">
      <option value="">所有IP类型</option>
      <option value="residential">住宅IP</option>
      <option value="hosting">机房IP</option>
      <option value="mobile">移动网</option>
    </select>
    <div id="ip_type_filter_widget" class="toolbar-custom-select" data-filter-id="ip_type_filter" aria-label="IP 类型筛选">
      <button id="ip_type_filter_button" type="button" class="toolbar-custom-select-button" data-filter-toggle aria-expanded="false">
        <span id="ip_type_filter_label" class="toolbar-custom-select-label">所有IP类型</span>
        <span class="toolbar-custom-select-arrow">⌄</span>
      </button>
      <div id="ip_type_filter_menu" class="toolbar-custom-select-menu" role="listbox"></div>
    </div>

    <button id="btn_favorites" class="toolbar-btn" type="button" onclick="toggleFavoritesView()" style="margin-left: auto; height: 42px; gap: 6px;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.907c.961 0 1.371 1.24.588 1.81l-3.97 2.883a1 1 0 00-.364 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.971-2.883a1 1 0 00-1.175 0l-3.97 2.883c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.364-1.118l-3.97-2.883c-.783-.57-.372-1.81.588-1.81h4.906a1 1 0 00.951-.69l1.519-4.674z" />
      </svg>
      收藏菜单
    </button>
  </section>
  <div id="global_refresh_status" class="country-priority" style="display:none;"></div>
  <div id="favorites_panel" style="display: none; background: rgba(22, 30, 49, 0.85); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); border: 1px solid var(--border-color); border-radius: 16px; padding: 20px; margin-bottom: 20px; animation: modalFadeIn 0.25s ease-out;">
    <div style="display: flex; flex-direction: column; gap: 16px;">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
        <div style="display: flex; flex-direction: column; gap: 4px;">
          <span style="font-size: 15px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 6px;">
            ⭐ 收藏专属管理面板
          </span>
          <span style="font-size: 13px; color: var(--text-secondary);">
            在这里管理您的收藏节点过滤，以及设置出站连接漂移策略。
          </span>
        </div>
        <div style="display: flex; gap: 12px; align-items: center;">
          <button id="btn_toggle_fav_routing" type="button" class="toolbar-btn" style="height: 36px; padding: 0 14px; font-size: 13px; border-radius: 6px;" onclick="toggleFavRouting()">
            启用仅用收藏出站
          </button>
        </div>
      </div>

      <div style="border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px;">
        <div style="padding: 10px 14px; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 8px; font-size: 12px; color: var(--warning); line-height: 1.5;">
          <strong>仅用收藏是强锁定模式。</strong>开启后只会连接收藏节点；如果收藏节点全部不可用，系统不会切换到非收藏节点。
        </div>
      </div>
    </div>
  </div>

  <div class="table-wrapper">
    <div class="table-container">
      <table class="node-table">
        <thead>
          <tr>
            <th style="width: 8%;">状态</th>
            <th style="width: 10%;">协议</th>
            <th style="width: 17%;">IP 地址 : 端口</th>
            <th style="width: 7%;">延迟</th>
            <th style="width: 19%;">物理位置</th>
            <th style="width: 16%;">运营主体 / ISP</th>
            <th style="width: 10%;">IP 类型</th>
            <th style="width: 13%;">操作</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>

    <!-- 分页控制栏 -->
    <div class="pagination-container" style="padding: 14px 16px; display: flex; justify-content: flex-start; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        显示第 <span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 条，共 <span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 条节点 <span style="margin-left: 10px; color: var(--primary);">每页 100 条</span>
        <span id="pool_summary" style="margin-left: 14px; color: var(--text-secondary);">Master Pool：—</span>
        <span id="nodes_load_progress" style="margin-left: 14px; color: var(--text-secondary);">首页优先加载中...</span>
      </div>
      <div class="pagination-controls-right" style="display: flex; gap: 8px; align-items: center; margin-left: auto;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">首页</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">上一页</button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          页码 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">下一页</button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">尾页</button>
      </div>
    </div>
  </div>

  <!-- Credentials Modal (网页安全设置) -->
  <div id="credentials_modal" class="modal">
    <div class="modal-content">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          网页安全
        </h3>
        <button type="button" onclick="closeCredentialsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <div id="credentials_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="credentials_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="credentials_form" onsubmit="saveCredentials(event)">
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_username">管理账号</label>
          <input type="text" id="cred_username" class="input-field" required placeholder="请输入管理账号">
        </div>

        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_password">安全密码</label>
          <input type="password" id="cred_password" class="input-field" placeholder="留空则保留当前密码">
        </div>

        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_port">HTTPS 管理端口</label>
          <input type="number" id="cred_port" class="input-field" required value="8443" disabled title="管理端口固定为 8443">
        </div>

        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_suffix">登录安全后缀 (仅字母和数字)</label>
          <input type="text" id="cred_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY">
        </div>

        <div class="form-group" style="margin-bottom: 20px;">
          <label class="form-label" for="cred_domain">HTTPS 域名（可选）</label>
          <input type="text" id="cred_domain" class="input-field" placeholder="例如 vpn.example.com" autocomplete="url" spellcheck="false">
          <div id="cred_cert_status" style="margin-top:8px; padding:9px 11px; border:1px solid var(--border-color); border-radius:8px; color:var(--text-secondary); font-size:12px; line-height:1.55; background:rgba(15,23,42,.24);">
            填写已解析到本服务器的域名；首次绑定时自动申请 HTTPS 证书，后续同域名保存不会重复申请。
          </div>
          <div id="cred_access_url" style="margin-top:8px; padding:9px 11px; border:1px solid rgba(20,184,166,.16); border-radius:8px; color:var(--text-secondary); font-size:12px; line-height:1.55; background:rgba(20,184,166,.045); word-break:break-all;">
            当前访问地址：读取中…
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeCredentialsModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="credentials_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Network Modal (代理及网络设置，包括出站路由) -->
  <div id="network_modal" class="modal">
    <div class="modal-content" style="max-width: 480px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理设置
        </h3>
        <div id="net_upstream_proxy_state" style="font-size:11px;color:var(--text-secondary);margin-top:4px;">系统默认网络（未设置自定义上游代理）</div>
        <button type="button" onclick="closeNetworkModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <div id="network_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="network_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="network_form" onsubmit="saveNetwork(event)">
        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="net_proxy_port">HTTP/SOCKS5 代理端口</label>
          <input type="number" id="net_proxy_port" class="input-field" required min="1024" max="65535" value="8500" disabled title="代理端口固定为 8500">
        </div>

        <div style="border-top: 1px dashed rgba(255,255,255,0.08); padding-top: 16px; margin-bottom: 16px;">
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站路由模式</label>
            <input type="hidden" id="net_routing_mode" value="auto">
            <div class="option-group" id="routing_mode_group">
              <div class="option-card active" data-value="auto" onclick="setRoutingMode('auto')">
                <div class="option-card-title">自动配置</div>
                <div class="option-card-desc">智能切换，最稳定</div>
              </div>
              <div class="option-card" data-value="fixed_ip" onclick="setRoutingMode('fixed_ip')">
                <div class="option-card-title">固定 IP</div>
                <div class="option-card-desc">锁定IP，不自动切换</div>
              </div>
              <div class="option-card" data-value="fixed_region" onclick="setRoutingMode('fixed_region')">
                <div class="option-card-title">优先地区</div>
                <div class="option-card-desc">优先指定国家，失效自动回退</div>
              </div>
              <div class="option-card" data-value="favorites" onclick="setRoutingMode('favorites')">
                <div class="option-card-title">仅用收藏</div>
                <div class="option-card-desc">只在收藏节点中自动连接与切换</div>
              </div>
            </div>
          </div>

          <div id="net_force_country_group" class="form-group" style="margin-bottom: 16px; display: none;">
            <label class="form-label" for="net_force_country">优先国家地区</label>
            <select id="net_force_country" aria-hidden="true" tabindex="-1" style="display:none;">
              <option value="">正在加载节点国家...</option>
            </select>
            <div id="net_force_country_widget" class="toolbar-custom-select unified-select unified-select-full" data-unified-select-id="net_force_country" aria-label="优先国家地区">
              <button id="net_force_country_button" type="button" class="toolbar-custom-select-button" data-unified-toggle aria-expanded="false">
                <span id="net_force_country_label" class="toolbar-custom-select-label">请选择优先国家...</span>
                <span class="toolbar-custom-select-arrow">⌄</span>
              </button>
              <div id="net_force_country_menu" class="toolbar-custom-select-menu" role="listbox"></div>
            </div>
          </div>

          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站类型偏好</label>
            <input type="hidden" id="net_routing_ip_type" value="all">
            <div class="option-group" id="routing_ip_type_group">
              <div class="option-card active" data-value="all" onclick="setRoutingIpType('all')">
                <div class="option-card-title">不限类型</div>
                <div class="option-card-desc">机房 + 住宅均可</div>
              </div>
              <div class="option-card" data-value="residential" onclick="setRoutingIpType('residential')">
                <div class="option-card-title">住宅 IP</div>
                <div class="option-card-desc">优先家宽，不可用自动回退</div>
              </div>
              <div class="option-card" data-value="hosting" onclick="setRoutingIpType('hosting')">
                <div class="option-card-title">机房IP</div>
                <div class="option-card-desc">普通机房</div>
              </div>
            </div>
          </div>

          <div id="net_routing_warning" style="font-size: 12px; color: var(--text-secondary); line-height: 1.4; padding: 8px 12px; background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 6px; margin-top: 8px;">
            ℹ️ <strong>服务可用性优先</strong>：国家和 IP 类型作为偏好，不作为硬锁定。系统按“目标国家 → IP 类型 → 稳定性 → 延迟 → 带宽”选择；目标暂时不可用时自动回退到同区域或全网可用节点，目标恢复后自动切回。
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeNetworkModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="network_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>


  <!-- 我爱研究.ILovestudy 官网入口 Modal -->
  <div id="vps_recommend_modal" class="modal">
    <div class="modal-content vps-modal-content official-portal-modal" style="max-width: 640px;">
      <div class="vps-modal-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 3a9 9 0 100 18 9 9 0 000-18zm0 0c2.1 2.45 3.25 5.49 3.25 9S14.1 18.55 12 21m0-18C9.9 5.45 8.75 8.49 8.75 12S9.9 18.55 12 21M3 12h18" /></svg>
          我爱研究.ILovestudy 官网入口
        </h3>
        <button type="button" onclick="closeVpsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <div class="official-links" style="margin-top: 16px;">
        <div class="official-grid">
          <a href="https://ilovestudycn.com" target="_blank" class="official-link official-main">官网</a>
          <a href="https://ilovestudyip.com" target="_blank" class="official-link official-tool">IP节点检测</a>
          <a href="https://ilovestudyus.blogspot.com/" target="_blank" class="official-link">博客</a>
          <a href="https://www.youtube.com/@ILovestudycn" target="_blank" class="official-link official-youtube">YouTube</a>
          <a href="https://t.me/ILovestudycn" target="_blank" class="official-link official-telegram">Telegram 交流群</a>
          <a href="https://t.me/ILovestudyus" target="_blank" class="official-link official-channel">Telegram 频道</a>
          <a href="mailto:ilovestudyus@gmail.com" class="official-link official-business">商务合作</a>
        </div>
      </div>

      <div class="vps-footer" style="margin-top: 16px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 16px; text-align: left; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
        <div style="font-weight: bold; color: var(--text-primary); margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          🎁 捐赠支持项目开发：
        </div>
        <div style="font-family: monospace; background: rgba(0,0,0,0.2); padding: 8px 12px; border-radius: 6px; margin-top: 6px; word-break: break-all; select-all: true;">
          <span style="color: var(--primary); font-weight: bold;">USDT (TRON / TRC20):</span> <span style="font-family: monospace;">TPuueui5rRCL3ECV6dWmBzeDkaTV2JEyAn</span>
        </div>
      </div>
    </div>
  </div>

  <div class="vps-recommend-tab official-portal-tab" onclick="openVpsModal()">官网入口</div>

  <!-- Gateway Modal (网关自检与代理测试) -->
  <div id="gateway_modal" class="modal">
    <div class="modal-content" style="max-width: 600px; width: 90%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关设置与自检
        </h3>
        <button type="button" onclick="closeGatewayModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- 服务列表 -->
      <div id="gateway_services_list" style="display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px;">
        <div style="text-align: center; color: var(--text-secondary); padding: 20px 0;">
          <svg style="animation: spin 1s linear infinite; width: 20px; height: 20px; display: inline-block; margin-bottom: 8px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>
          <div>正在加载系统网关状态...</div>
        </div>
      </div>

      <!-- 分割线 -->
      <div style="border-top: 1px dashed rgba(255, 255, 255, 0.08); margin: 20px 0;"></div>

      <!-- 本地代理出口检测 -->
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 12px; padding: 16px;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
          <div class="stat-icon-wrapper" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.2); width: 36px; height: 36px; border-radius: 8px; flex-shrink: 0;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--primary); width: 18px; height: 18px;"><path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071a10.5 10.5 0 0114.14 0M1.414 8.05a16 16 0 0121.172 0" /></svg>
          </div>
          <div>
            <h4 style="margin: 0; font-size: 14px; font-weight: 600; color: var(--text-primary);">本地代理出口检测</h4>
            <p style="margin: 2px 0 0 0; font-size: 12px; color: var(--text-secondary);">检测 HTTP/SOCKS5 代理出站连通性与 IP</p>
          </div>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(0, 0, 0, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
          <div style="font-size: 13px; color: var(--text-secondary);">
            测试状态: <span id="proxy_status_badge" class="badge not_checked" style="margin-left: 4px;">未检测</span>
          </div>
          <div style="font-size: 13px; color: var(--text-secondary); text-align: right;">
            出口 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span>
            <span id="proxy_latency_val" style="margin-left: 6px;"></span>
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button id="btn_test_proxy" class="btn-primary" style="height: 36px; padding: 0 16px; font-size: 13px;">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            开始检测
          </button>
        </div>
      </div>

      <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
        <button type="button" onclick="closeGatewayModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>

  <!-- Add Node Modal -->
  <div id="add_node_modal" class="modal">
    <div class="modal-content" style="max-width:560px; width:94%; padding:28px;">
      <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:12px; margin-bottom:18px;">
        <div>
          <h3 style="margin:0; font-size:20px; font-weight:700; color:var(--text-primary);">添加 VPN Gate 节点</h3>
          <div style="margin-top:6px; font-size:12px; color:var(--text-secondary); line-height:1.5;">支持域名、域名:端口、IPv4、IPv4:端口，也支持 IPv6 [地址] / [地址]:端口。VPN Gate .opengw.net 域名不填写端口时，系统会自动读取官方公布的各协议端口，再逐一真实验证。</div>
        </div>
        <button type="button" onclick="closeAddNodeModal()" style="width:32px;height:32px;border:1px solid var(--border-color);background:rgba(255,255,255,.03);border-radius:8px;color:var(--text-secondary);cursor:pointer;">✕</button>
      </div>

      <label class="form-label" for="add_node_address">节点地址</label>
      <input id="add_node_address" class="input-field" autocomplete="off" spellcheck="false" placeholder="例如 vpn99990120.opengw.net（端口可省略）">

      <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:10px;">
        <button type="button" class="test-btn" onclick="fillAddNodeExample('vpn99990120.opengw.net')" style="height:30px;">示例域名</button>
        <button type="button" class="test-btn" onclick="fillAddNodeExample('203.0.113.10:1965')" style="height:30px;">示例 IPv4</button>
      </div>

      <div style="margin-top:14px; padding:12px 13px; border:1px solid rgba(99,102,241,.16); background:rgba(99,102,241,.04); border-radius:9px; font-size:11px; color:var(--text-secondary); line-height:1.55;">
        <div style="font-weight:600; color:var(--text-primary); margin-bottom:4px;">识别流程</div>
        OpenVPN → SSL-VPN → L2TP/IPsec → MS-SSTP 依次直连验证；任一方式真正建立成功即显示“通过”，只保存通过的协议端点，并将刚添加的节点置顶。
      </div>

      <div id="add_node_result" style="display:none; margin-top:14px;"></div>

      <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:20px;">
        <button type="button" onclick="closeAddNodeModal()" style="height:40px; padding:0 18px; border-radius:8px; border:1px solid var(--border-color); background:transparent; color:var(--text-secondary); cursor:pointer;">取消</button>
        <button id="add_node_submit" type="button" class="btn-primary" onclick="submitAddNode()" style="height:40px; min-width:120px;">开始识别</button>
      </div>
    </div>
  </div>

  <!-- Resource Share Modal -->
  <div id="resource_share_modal" class="modal">
    <div class="modal-content rs-modal-content">
      <div class="rs-modal-header">
        <div>
          <h3 style="margin:0;font-size:19px;font-weight:700;color:var(--text-primary);">资源共享</h3>
          <div style="margin-top:5px;font-size:12px;color:var(--text-secondary);">通过现有 8443 HTTPS 交换节点资源；邀请、加入、双向关系、周期和删除都在这里管理。</div>
        </div>
        <button type="button" onclick="closeResourceShareModal()" class="rs-close-btn">✕</button>
      </div>

      <div class="rs-local-card">
        <div class="rs-card-label">本机资源接口地址</div>
        <div class="rs-local-row">
          <input id="rs_local_url" class="input-field rs-local-input" readonly value="/resource-share">
          <button type="button" class="btn-primary rs-copy-btn" onclick="copyResourceShareUrl()">复制地址</button>
        </div>
        <div class="rs-help">对方使用“本机地址 + 邀请码”即可加入。邀请码决定谁可以访问本机资源。</div>
      </div>

      <div class="rs-action-grid">
        <section class="rs-form-card">
          <div class="rs-step-title"><span>①</span> 创建邀请码</div>
          <div class="rs-help rs-form-help">邀请码不会自动过期，可以创建多个；需要停止某台服务器访问时，直接撤销对应邀请码。</div>
          <div class="rs-form-grid">
            <input id="rs_invite_peer_name" class="input-field" placeholder="邀请服务器名称，例如 日本资源库">
            <input id="rs_invite_allowed_cidrs" class="input-field" placeholder="对方 IP/CIDR，例如 1.2.3.4/32；全部 IPv4：0.0.0.0/0">
            <div class="rs-help">单个 IP 自动转换为 /32 或 /128；全部 IPv6 可填写 ::/0。</div>
            <button id="rs_generate_btn" type="button" class="btn-primary rs-full-btn" onclick="generateResourceInvite()">生成邀请码</button>
          </div>
        </section>

        <section class="rs-form-card">
          <div class="rs-step-title"><span>②</span> 添加共享服务器</div>
          <div class="rs-help rs-form-help">这里填写对方服务器 IP/域名 + 对方给你的邀请码。系统自动判断最终是“单向共享”还是“双方双向共享”。</div>
          <div class="rs-form-grid">
            <input id="rs_remote_url" class="input-field" placeholder="对方服务器 IP 或域名，例如 203.0.113.10">
            <input id="rs_invite_input" class="input-field" placeholder="对方邀请码 RS-XXXX-XXXX-XXXX-XXXX">
            <div class="rs-sync-row">
              <input id="rs_sync_interval_value" class="input-field" type="number" min="1" max="84" value="6" placeholder="同步周期">
              <select id="rs_sync_interval_unit" aria-hidden="true" tabindex="-1" style="display:none;">
                <option value="hours">小时</option>
                <option value="days">天</option>
                <option value="weeks">周</option>
              </select>
              <div id="rs_sync_interval_unit_widget" class="toolbar-custom-select unified-select unified-select-sync" data-unified-select-id="rs_sync_interval_unit" aria-label="同步周期单位">
                <button id="rs_sync_interval_unit_button" type="button" class="toolbar-custom-select-button" data-unified-toggle aria-expanded="false">
                  <span id="rs_sync_interval_unit_label" class="toolbar-custom-select-label">小时</span>
                  <span class="toolbar-custom-select-arrow">⌄</span>
                </button>
                <div id="rs_sync_interval_unit_menu" class="toolbar-custom-select-menu" role="listbox"></div>
              </div>
            </div>
            <div class="rs-help">自动同步仅用于本机拉取对方资源；“立即同步”始终可以手动执行。</div>
            <button id="rs_join_btn" type="button" class="btn-primary rs-full-btn" onclick="joinResourcePeer()">添加并立即同步</button>
          </div>
        </section>
      </div>

      <section class="rs-list-card">
        <div class="rs-list-header">
          <div>
            <div class="rs-list-title">③ 邀请共享服务器 <span id="rs_invite_count" class="rs-count-badge">0</span></div>
            <div class="rs-help">已发出的长期邀请码。撤销=立即停止访问；删除=永久删除这条邀请码记录。</div>
          </div>
        </div>
        <div id="rs_invite_list" class="rs-list">
          <div class="rs-empty">暂无邀请码</div>
        </div>
      </section>

      <section class="rs-list-card" style="margin-top:14px;">
        <div class="rs-list-header">
          <div>
            <div class="rs-list-title">④ 已建立共享服务器 <span id="rs_peer_count" class="rs-count-badge">0</span></div>
            <div class="rs-help">同一服务器只有一张关系卡：双方都有邀请并互相加入时显示“双方双向共享”，只有一侧时显示“单向共享”。</div>
          </div>
          <button type="button" class="btn-primary" onclick="syncAllResourcePeers()" style="height:36px;padding:0 13px;">立即同步全部</button>
        </div>
        <div id="rs_peer_list" class="rs-list">
          <div class="rs-empty">暂无共享服务器</div>
        </div>
      </section>

      <div class="rs-security-note">安全边界：共享接口只返回 Host/IP、国家、协议、端口、健康摘要等公开资源信息；不返回管理员密码、SOCKS5 密码、OpenVPN 配置正文或本机文件路径。删除关系时只清理其独占且尚未被本机验证的共享资源。</div>

      <div style="display:flex;justify-content:flex-end;margin-top:14px;">
        <button type="button" onclick="closeResourceShareModal()" class="rs-footer-close">关闭</button>
      </div>
    </div>
  </div>

  <!-- Resource Share Edit Modal -->
  <div id="resource_share_edit_modal" class="modal" style="z-index: 10020;">
    <div class="modal-content rs-edit-modal-content">
      <div class="rs-modal-header">
        <div>
          <h3 id="rs_edit_title" style="margin:0;font-size:19px;font-weight:700;color:var(--text-primary);">修改资源共享</h3>
          <div id="rs_edit_help" style="margin-top:5px;font-size:12px;color:var(--text-secondary);">修改后立即生效。</div>
        </div>
        <button type="button" onclick="closeResourceShareEditModal()" class="rs-close-btn">✕</button>
      </div>

      <form id="rs_edit_form" class="rs-edit-form" onsubmit="submitResourceShareEdit(event)">
        <input type="hidden" id="rs_edit_type" value="">
        <input type="hidden" id="rs_edit_id" value="">

        <div class="rs-edit-field">
          <label for="rs_edit_name">服务器名称</label>
          <input id="rs_edit_name" class="input-field" placeholder="共享服务器">
        </div>

        <div id="rs_edit_local_scope_row" class="rs-edit-field">
          <label for="rs_edit_local_scope">允许对方访问本机的 IP/CIDR</label>
          <input id="rs_edit_local_scope" class="input-field" placeholder="例如 1.2.3.4/32；全部 IPv4：0.0.0.0/0">
          <div class="rs-edit-field-help">这是本机入站白名单。留空会拒绝所有来源。</div>
        </div>

        <div id="rs_edit_remote_row" class="rs-edit-grid">
          <div class="rs-edit-field">
            <label for="rs_edit_remote_url">对方服务器 IP / 域名</label>
            <input id="rs_edit_remote_url" class="input-field" placeholder="例如 203.0.113.10">
          </div>
          <div class="rs-edit-field">
            <label for="rs_edit_remote_invite">对方邀请码</label>
            <input id="rs_edit_remote_invite" class="input-field" placeholder="RS-XXXX-XXXX-XXXX-XXXX">
          </div>
        </div>

        <div id="rs_edit_sync_row" class="rs-edit-field">
          <label>自动同步周期</label>
          <div class="rs-sync-row rs-edit-sync-row">
            <input id="rs_edit_sync_value" class="input-field" type="number" min="1" max="84" value="6" placeholder="周期">
            <select id="rs_edit_sync_unit" aria-hidden="true" tabindex="-1" style="display:none;">
              <option value="hours">小时</option>
              <option value="days">天</option>
              <option value="weeks">周</option>
            </select>
            <div id="rs_edit_sync_unit_widget" class="toolbar-custom-select unified-select unified-select-sync" data-unified-select-id="rs_edit_sync_unit" aria-label="同步周期单位">
              <button id="rs_edit_sync_unit_button" type="button" class="toolbar-custom-select-button" data-unified-toggle aria-expanded="false">
                <span id="rs_edit_sync_unit_label" class="toolbar-custom-select-label">小时</span>
                <span class="toolbar-custom-select-arrow">⌄</span>
              </button>
              <div id="rs_edit_sync_unit_menu" class="toolbar-custom-select-menu" role="listbox"></div>
            </div>
          </div>
          <div class="rs-edit-field-help">修改后下一个周期按新配置重新计算；也可以随时手动同步。</div>
        </div>

        <div id="rs_edit_error" class="rs-edit-error" style="display:none;"></div>

        <div class="rs-edit-actions">
          <button type="button" class="rs-footer-close" onclick="closeResourceShareEditModal()">取消</button>
          <button type="submit" id="rs_edit_submit" class="btn-primary rs-edit-save">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Logs Modal (日志监控与分类筛选) -->
  <div id="logs_modal" class="modal">
    <div class="modal-content" style="max-width: 800px; width: 95%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          今日运行日志
        </h3>

        <div style="display: flex; align-items: center; gap: 10px; margin-left: auto;">
          <label class="form-label" for="log_filter_select" style="margin: 0; font-size: 13px; color: var(--text-secondary);">日志筛选:</label>
          <select id="log_filter_select" aria-hidden="true" tabindex="-1" style="display:none;">
            <option value="all">全部日志</option>
            <option value="proxy">代理相关 (Proxy)</option>
            <option value="vpn">VPN 连接 (VPN)</option>
            <option value="system">系统运行 (Main/Route)</option>
          </select>
          <div id="log_filter_select_widget" class="toolbar-custom-select unified-select unified-select-log" data-unified-select-id="log_filter_select" aria-label="日志筛选">
            <button id="log_filter_select_button" type="button" class="toolbar-custom-select-button" data-unified-toggle aria-expanded="false">
              <span id="log_filter_select_label" class="toolbar-custom-select-label">全部日志</span>
              <span class="toolbar-custom-select-arrow">⌄</span>
            </button>
            <div id="log_filter_select_menu" class="toolbar-custom-select-menu" role="listbox"></div>
          </div>
        </div>

        <button type="button" onclick="closeLogsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- Terminal Log Container -->
      <div id="log_terminal_container" style="background: #050811; border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 10px; height: 400px; padding: 16px; overflow-y: auto; font-family: 'JetBrains Mono', Consolas, Courier, monospace; font-size: 12px; line-height: 1.5; text-align: left; white-space: pre-wrap; word-break: break-all; color: #a5b4fc; box-shadow: inset 0 4px 20px rgba(0,0,0,0.8); position: relative; margin-bottom: 20px;">
        <div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">
          暂无今日运行日志记录。
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; gap: 8px;">
          <button type="button" onclick="copyLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
            一键复制
          </button>
          <button type="button" onclick="exportLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: rgba(255,255,255,0.05); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            导出日志
          </button>
          <button type="button" onclick="clearTodayLogs()" class="btn-primary" style="height: 38px; padding: 0 12px; background: rgba(244,63,94,0.08); color: var(--danger); border: 1px solid rgba(244,63,94,0.25);">
            清空今日
          </button>
          <button type="button" onclick="cleanupOldLogs()" class="btn-primary" style="height: 38px; padding: 0 12px; background: rgba(245,158,11,0.08); color: var(--warning); border: 1px solid rgba(245,158,11,0.25);">
            清理旧日志
          </button>
        </div>
        <button type="button" onclick="closeLogsModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>
  <footer class="site-footer" aria-label="Aimili VPN 官方入口">
    <div class="site-footer-inner">
      <section class="footer-disclaimer" aria-labelledby="footer-disclaimer-title">
        <div id="footer-disclaimer-title" class="footer-disclaimer-title">隐私免责声明</div>
        <ol class="footer-disclaimer-list">
          <li>本节点管理系统仅用于整理订阅和检测你拥有或获授权使用的节点，不提供、出售或分发节点资源。请自行确认使用权限，并遵守适用法律、网络服务条款及相关规则。</li>
          <li>检测结果仅反映执行时的网络状态和当次可取得的信息，可能受网络、设备及数据可用性影响；结果仅供参考，不构成安全、信誉、可用性、合规性或任何第三方平台判断的保证。</li>
          <li>“IP属地”“原生 / 广播”网络类型等为技术分类，不属于官方认证，IPv4 与 IPv6 独立检测，结果可能不同。未执行、未知或直接生成的结果不代表已经通过全部检测。</li>
          <li>订阅输入、节点列表、筛选状态和已完成的节点检测结果默认在当前设备本机处理和保存。仅在完成当前操作确有必要时进行网络通信或一次性临时读取；公开页面和错误提示不会展示原始凭据、访问令牌、完整请求地址或原始服务响应。</li>
          <li>只有你主动生成在线订阅时，最终选中的节点连接信息才会进入临时订阅存储，并在 30 分钟后自动失效。订阅链接和二维码具有访问能力，请按敏感信息管理，不要公开分享。</li>
          <li>清除本机节点订阅不会立即撤销已经发布的临时链接；已发布链接按照到期时间自动失效。使用共享设备后请清理本机记录、截图、复制内容和导出文件，也请谨慎保存和分享。</li>
        </ol>
      </section>

      <div class="footer-brand">
        <div class="footer-brand-link" aria-label="我爱研究.ILovestudy 品牌标志">
          <svg class="footer-brand-logo-image footer-brand-logo-svg" viewBox="0 0 96 96" role="img" aria-label="我爱研究.ILovestudy 标志">
            <defs>
              <linearGradient id="brandShield" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0" stop-color="#e0f2fe"/>
                <stop offset=".36" stop-color="#60a5fa"/>
                <stop offset=".72" stop-color="#2563eb"/>
                <stop offset="1" stop-color="#0f172a"/>
              </linearGradient>
              <linearGradient id="brandInner" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0" stop-color="#0ea5e9"/>
                <stop offset=".52" stop-color="#1d4ed8"/>
                <stop offset="1" stop-color="#0b1738"/>
              </linearGradient>
              <linearGradient id="brandMetal" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0" stop-color="#ffffff"/>
                <stop offset=".42" stop-color="#cbd5e1"/>
                <stop offset="1" stop-color="#64748b"/>
              </linearGradient>
              <linearGradient id="brandChip" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0" stop-color="#fef3c7"/>
                <stop offset=".48" stop-color="#fbbf24"/>
                <stop offset="1" stop-color="#b45309"/>
              </linearGradient>
            </defs>
            <!-- Clean native shield: no decorative top/bottom lines, no external background. -->
            <path d="M48 4 82 18v25c0 23-13 38-34 49C27 81 14 66 14 43V18L48 4Z"
                  fill="url(#brandShield)" stroke="#e0f2fe" stroke-width="2.5" stroke-linejoin="round"/>
            <path d="M48 13 73 23v20c0 17-9 29-25 39-16-10-25-22-25-39V23l25-10Z"
                  fill="url(#brandInner)" stroke="#22d3ee" stroke-width="1.5" opacity=".98"/>
            <!-- Centered chip, aligned to the shield's visual center. -->
            <g transform="translate(48 49)">
              <rect x="-19" y="-19" width="38" height="38" rx="8" fill="url(#brandMetal)" stroke="#f8fafc" stroke-width="1.5"/>
              <rect x="-11" y="-11" width="22" height="22" rx="4" fill="url(#brandChip)" stroke="#fef3c7" stroke-width="1"/>
              <path d="M-6 -5h12M-6 0h12M-6 5h12" stroke="#78350f" stroke-width="1.6" stroke-linecap="round"/>
            </g>
          </svg>
          <span class="footer-brand-copy">
            <strong>我爱研究.ILovestudy</strong>
            <span class="footer-brand-version"><span class="footer-brand-system">多协议节点管理系统</span><span class="footer-brand-version-number">· V1.0.8</span></span>
          </span>
        </div>
      </div>

      <div class="footer-channels" aria-label="官方频道入口">
        <a class="footer-channel footer-channel-youtube" href="https://www.youtube.com/@ILovestudycn" target="_blank" rel="noopener noreferrer" aria-label="打开 YouTube 频道">
          <span class="footer-channel-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24"><path d="M23.5 6.2a3 3 0 0 0-2.1-2.1C19.5 3.6 12 3.6 12 3.6s-7.5 0-9.4.5A3 3 0 0 0 .5 6.2 31 31 0 0 0 0 12a31 31 0 0 0 .5 5.8 3 3 0 0 0 2.1 2.1c1.9.5 9.4.5 9.4.5s7.5 0 9.4-.5a3 3 0 0 0 2.1-2.1A31 31 0 0 0 24 12a31 31 0 0 0-.5-5.8ZM9.6 15.6V8.4l6.2 3.6-6.2 3.6Z"/></svg>
          </span>
          <span class="footer-channel-label">YouTube 频道</span>
        </a>
        <a class="footer-channel footer-channel-telegram" href="https://t.me/ILovestudyus" target="_blank" rel="noopener noreferrer" aria-label="打开 Telegram 频道">
          <span class="footer-channel-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24"><path d="M21.6 3.4 2.9 10.6c-1.3.5-1.3 1.2-.2 1.5l4.8 1.5 1.8 5.5c.2.6.1.8.7.8.5 0 .7-.2 1-.5l2.3-2.2 4.8 3.6c.9.5 1.5.3 1.7-.8l3.1-14.7c.4-1.4-.5-2-1.5-1.4ZM9.1 13.3l10.5-6.6c.5-.3 1-.1.6.2l-8.8 7.9-.3 3.2-1.4-.7-.6-.2Z"/></svg>
          </span>
          <span class="footer-channel-label">Telegram 频道</span>
        </a>
      </div>

      <nav class="footer-bottom" aria-label="底部官方入口">
        <a href="https://ilovestudycn.com" target="_blank" rel="noopener noreferrer">官网</a>
        <span class="footer-divider">|</span>
        <a href="https://ilovestudyip.com/" target="_blank" rel="noopener noreferrer">IP 节点检测</a>
      </nav>
    </div>
  </footer>
</main>
<script>
let nodes=[], state={}, testingNodeIds = new Set();
let currentPage = 1;
const pageSize = 100;
let currentPageNodes = [];

const translateProtocol = p => {
  const key = String(p || "").trim().toLowerCase();
  const dict = {
    "openvpn": "OpenVPN",
    "softether": "SSL-VPN",
    "sstp": "SSTP",
    "l2tp-ipsec": "L2TP/IPsec",
    "l2tp_ipsec": "L2TP/IPsec",
    "l2tp": "L2TP/IPsec"
  };
  return dict[key] || (key ? key.toUpperCase() : "OpenVPN");
};

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const base=p=>(p||"").split(/[\\/]/).pop();

function getProtocolUrl(n) {
  const protocol = String(n && n.protocol || "openvpn").trim().toLowerCase();
  if (protocol === "softether") return "https://www.vpngate.net/cn/howto_softether.aspx";
  if (protocol === "sstp") return "https://www.vpngate.net/cn/howto_sstp.aspx";
  if (protocol === "l2tp-ipsec" || protocol === "l2tp_ipsec" || protocol === "l2tp") return "https://www.vpngate.net/cn/howto_l2tp.aspx";
  if (protocol !== "openvpn") return "";
  const params = new URLSearchParams();
  const host = String(n && (n.host_name || n.remote_host) || "").trim();
  const ip = String(n && n.ip || "").trim();
  if (host && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) params.set("fqdn", host);
  if (ip) params.set("ip", ip);
  const port = Number(n && n.remote_port || 0);
  const transport = String(n && (n.proto || n.transport) || "tcp").trim().toLowerCase();
  if (port > 0) params.set(transport === "udp" ? "udp" : "tcp", String(port));
  return "https://www.vpngate.net/cn/do_openvpn.aspx" + (params.toString() ? "?" + params.toString() : "");
}

function formatNodeLocation(n) {
  const country = getNodeCountry(n);
  let location = String(n && n.location || "").trim().replace(/\s+/g, " ");
  if (!country) return location || "—";
  if (!location || location === "-" || location === "—") return country;
  const knownCountryLabels = [
    "美国","加拿大","德国","英国","法国","日本","韩国","新加坡","澳大利亚","新西兰","俄罗斯",
    "中国","台湾","香港","澳门","荷兰","瑞典","挪威","西班牙","意大利","瑞士","奥地利","比利时",
    "丹麦","芬兰","葡萄牙","爱尔兰","波兰","捷克","匈牙利","土耳其","印度","泰国","越南","马来西亚",
    "印度尼西亚","菲律宾","墨西哥","巴西","阿根廷","智利","南非","以色列","阿联酋"
  ];
  const englishCountryPrefix = /^(United States|Canada|Germany|United Kingdom|France|Japan|Korea Republic of|Republic of Korea|Singapore|Australia|New Zealand|Russian Federation|China|Taiwan|Hong Kong|Macao|Macau|Netherlands|Sweden|Norway|Spain|Italy|Switzerland|Austria|Belgium|Denmark|Finland|Portugal|Ireland|Poland|Czech Republic|Hungary|Turkey|India|Thailand|Viet Nam|Vietnam|Malaysia|Indonesia|Philippines|Mexico|Brazil|Argentina|Chile|South Africa|Israel|United Arab Emirates)\b/i;
  const cnMatch = location.match(new RegExp("^(" + knownCountryLabels.join("|") + ")\s*"));
  const enMatch = location.match(englishCountryPrefix);
  if (cnMatch) {
    if (cnMatch[1] !== country) return country;
    location = location.slice(cnMatch[0].length).trim();
  } else if (enMatch) {
    const prefixCountry = translateCountry(enMatch[1]);
    if (prefixCountry && prefixCountry !== country) return country;
    location = location.slice(enMatch[0].length).trim();
  }
  return location ? (location === country || location.startsWith(country + " ") ? location : country + " " + location) : country;
}

function renderProtocolCell(n) {
  const label = translateProtocol(n && n.protocol || "openvpn");
  const href = getProtocolUrl(n);
  if (!href) return `<span class="protocol-badge">${esc(label)}</span>`;
  return `<a class="protocol-badge protocol-link" href="${esc(href)}" target="_blank" rel="noopener noreferrer" title="打开 VPN Gate ${esc(label)} 官方连接页面">${esc(label)}</a>`;
}
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "proxy": "代理 IP"};
  const key = String(t || "").trim().toLowerCase();
  if (!key || ["unknown","unclassified","unavailable","n/a","na","null","undefined","-","—"].includes(key)) return "—";
  return dict[key] || key;
};

const translateCountry = c => {
  const raw = String(c || "").trim();
  const normalized = raw.replace(/\s*\([^)]*\)\s*$/g, "").trim();
  const dict = {
    "Croatia": "克罗地亚",
    "Hrvatska": "克罗地亚",
    "Yemen": "也门",
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "China": "中国",
    "Taiwan": "台湾",
    "Taiwan Province of China": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚",
    "India": "印度",
    "Philippines": "菲律宾",
    "Australia": "澳大利亚",
    "New Zealand": "新西兰",
    "Canada": "加拿大",
    "Ukraine": "乌克兰",
    "France": "法国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "Sweden": "瑞典",
    "Norway": "挪威",
    "Spain": "西班牙",
    "Turkey": "土耳其",
    "South Africa": "南非",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Chile": "智利",
    "Mexico": "墨西哥",
    "Egypt": "埃及",
    "Romania": "罗马尼亚",
    "Poland": "波兰",
    "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚",
    "Mongolia": "蒙古",
    "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Colombia": "哥伦比亚",
    "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰",
    "Italy": "意大利",
    "Switzerland": "瑞士",
    "Belgium": "比利时",
    "Austria": "奥地利",
    "Denmark": "丹麦",
    "Finland": "芬兰",
    "Portugal": "葡萄牙",
    "Greece": "希腊",
    "Czech Republic": "捷克",
    "Hungary": "匈牙利",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "UAE": "阿联酋",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡"
  };
  const extra = {
    "Albania":"阿尔巴尼亚","Algeria":"阿尔及利亚","Angola":"安哥拉","Armenia":"亚美尼亚",
    "Azerbaijan":"阿塞拜疆","Bahrain":"巴林","Bangladesh":"孟加拉国","Barbados":"巴巴多斯",
    "Belarus":"白俄罗斯","Bosnia and Herzegovina":"波斯尼亚和黑塞哥维那","Botswana":"博茨瓦纳",
    "Brunei":"文莱","Bulgaria":"保加利亚","Cameroon":"喀麦隆","Costa Rica":"哥斯达黎加",
    "Cyprus":"塞浦路斯","Ecuador":"厄瓜多尔","El Salvador":"萨尔瓦多","Estonia":"爱沙尼亚",
    "Ethiopia":"埃塞俄比亚","Fiji":"斐济","Guatemala":"危地马拉","Haiti":"海地",
    "Jamaica":"牙买加","Jordan":"约旦","Kenya":"肯尼亚","Kuwait":"科威特",
    "Kyrgyzstan":"吉尔吉斯斯坦","Latvia":"拉脱维亚","Lebanon":"黎巴嫩","Libya":"利比亚",
    "Liechtenstein":"列支敦士登","Lithuania":"立陶宛","Malta":"马耳他","Mauritius":"毛里求斯",
    "Moldova":"摩尔多瓦","Montenegro":"黑山","Morocco":"摩洛哥","Myanmar":"缅甸",
    "Nepal":"尼泊尔","Nigeria":"尼日利亚","North Macedonia":"北马其顿","Pakistan":"巴基斯坦",
    "Panama":"巴拿马","Paraguay":"巴拉圭","Peru":"秘鲁","Slovakia":"斯洛伐克",
    "Slovenia":"斯洛文尼亚","Serbia":"塞尔维亚","Sri Lanka":"斯里兰卡","Tunisia":"突尼斯",
    "Uganda":"乌干达","Uruguay":"乌拉圭","Uzbekistan":"乌兹别克斯坦","Venezuela":"委内瑞拉",
    "Zimbabwe":"津巴布韦","Bahamas":"巴哈马","Bolivia":"玻利维亚","Curaçao":"库拉索",
    "Dominican Republic":"多米尼加共和国","Honduras":"洪都拉斯","Nicaragua":"尼加拉瓜",
    "Trinidad and Tobago":"特立尼达和多巴哥","Guyana":"圭亚那","Suriname":"苏里南",
    "Maldives":"马尔代夫","Oman":"阿曼","Qatar":"卡塔尔","Palestine":"巴勒斯坦",
    "Bermuda":"百慕大","Gibraltar":"直布罗陀","Isle of Man":"马恩岛","Jersey":"泽西岛",
    "Guernsey":"根西岛","New Caledonia":"新喀里多尼亚","Puerto Rico":"波多黎各"
  };
  return dict[raw] || dict[normalized] || extra[raw] || extra[normalized] || normalized || "—";
};

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "testing": "检测中", "not_checked": "待检测"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  const value = Number(ms);
  if (!value || value < 0) return '';
  if (value <= 400) return 'latency-good';
  if (value <= 800) return 'latency-medium';
  return 'latency-poor';
}

function matchesNodeFilters(n, ignoreCountry = false) {
  if (!n) return false;
  const selectedCountry = $("country_filter")?.value || "";
  const selectedProtocol = $("protocol_filter")?.value || "";
  const selectedIpType = $("ip_type_filter")?.value || "";
  const selectedStatus = $("status_filter")?.value || "";

  if (!ignoreCountry && selectedCountry && getNodeCountry(n) !== selectedCountry) return false;
  if (selectedProtocol && String(n.protocol || "openvpn").toLowerCase() !== selectedProtocol) return false;

  const ipType = String(n.ip_type || "").toLowerCase();
  if (selectedIpType === "residential" && ipType !== "residential") return false;
  if (selectedIpType === "hosting" && ipType !== "hosting") return false;
  if (selectedIpType === "mobile" && ipType !== "mobile") return false;

  if (selectedStatus === "available" && n.probe_status !== "available" && !n.active) return false;
  if (selectedStatus === "not_checked" && (n.probe_status !== "not_checked" || n.active)) return false;
  if (selectedStatus === "testing" && n.probe_status !== "testing") return false;
  if (selectedStatus === "unavailable" && (n.probe_status !== "unavailable" || n.active)) return false;

  const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
  if (showFavoritesOnly && !favoriteIds.includes(n.id)) return false;
  return true;
}

const CUSTOM_FILTER_CONFIG = {
  status_filter: {widget:"status_filter_widget", button:"status_filter_button", label:"status_filter_label", menu:"status_filter_menu"},
  country_filter: {widget:"country_filter_widget", button:"country_filter_button", label:"country_filter_label", menu:"country_filter_menu"},
  protocol_filter: {widget:"protocol_filter_widget", button:"protocol_filter_button", label:"protocol_filter_label", menu:"protocol_filter_menu"},
  ip_type_filter: {widget:"ip_type_filter_widget", button:"ip_type_filter_button", label:"ip_type_filter_label", menu:"ip_type_filter_menu"}
};


const UNIFIED_SELECT_CONFIG = {
  net_force_country: {widget:"net_force_country_widget", button:"net_force_country_button", label:"net_force_country_label", menu:"net_force_country_menu"},
  rs_sync_interval_unit: {widget:"rs_sync_interval_unit_widget", button:"rs_sync_interval_unit_button", label:"rs_sync_interval_unit_label", menu:"rs_sync_interval_unit_menu"},
  rs_edit_sync_unit: {widget:"rs_edit_sync_unit_widget", button:"rs_edit_sync_unit_button", label:"rs_edit_sync_unit_label", menu:"rs_edit_sync_unit_menu"},
  log_filter_select: {widget:"log_filter_select_widget", button:"log_filter_select_button", label:"log_filter_select_label", menu:"log_filter_select_menu"}
};

function renderUnifiedSelect(selectId) {
  const cfg = UNIFIED_SELECT_CONFIG[selectId];
  const select = cfg ? $(selectId) : null;
  const label = cfg ? $(cfg.label) : null;
  const menu = cfg ? $(cfg.menu) : null;
  if (!cfg || !select || !label || !menu) return;
  const selected = select.options[select.selectedIndex];
  label.textContent = selected ? selected.textContent : "";
  const html = Array.from(select.options).map(option => {
    const value = String(option.value || "");
    const textValue = String(option.textContent || "");
    const active = value === String(select.value || "");
    const disabled = !!option.disabled;
    return '<button type="button" class="toolbar-custom-option ' + (active ? 'active' : '') + '"' +
      (disabled ? ' disabled style="opacity:.45;cursor:not-allowed;"' : '') +
      ' role="option" aria-selected="' + (active ? 'true' : 'false') + '"' +
      ' onclick="event.preventDefault();event.stopPropagation();chooseUnifiedSelect(' + JSON.stringify(selectId) + ',' + JSON.stringify(value) + ')">' +
      '<span>' + esc(textValue) + '</span></button>';
  }).join("");
  if (menu.innerHTML !== html) menu.innerHTML = html;
}

function renderAllUnifiedSelects() {
  Object.keys(UNIFIED_SELECT_CONFIG).forEach(renderUnifiedSelect);
}

function closeUnifiedSelects(exceptId = "") {
  Object.keys(UNIFIED_SELECT_CONFIG).forEach(id => {
    if (id === exceptId) return;
    const cfg = UNIFIED_SELECT_CONFIG[id];
    const widget = $(cfg.widget);
    const button = $(cfg.button);
    const menu = $(cfg.menu);
    if (widget) widget.classList.remove("open");
    if (button) button.setAttribute("aria-expanded", "false");
    if (menu) { menu.style.top=""; menu.style.left=""; menu.style.bottom=""; }
  });
}

function toggleUnifiedSelect(selectId, event) {
  if (event) { event.preventDefault(); event.stopPropagation(); }
  const cfg = UNIFIED_SELECT_CONFIG[selectId];
  const widget = cfg ? $(cfg.widget) : null;
  const button = cfg ? $(cfg.button) : null;
  const menu = cfg ? $(cfg.menu) : null;
  if (!cfg || !widget || !menu) return;
  const opening = !widget.classList.contains("open");
  closeCustomFilters("");
  closeUnifiedSelects(selectId);
  renderUnifiedSelect(selectId);
  widget.classList.toggle("open", opening);
  if (button) button.setAttribute("aria-expanded", opening ? "true" : "false");
  if (opening) {
    requestAnimationFrame(() => {
      const rect = widget.getBoundingClientRect();
      const menuHeight = Math.min(menu.scrollHeight || 280, Math.min(360, window.innerHeight - 24));
      const spaceBelow = window.innerHeight - rect.bottom - 10;
      const spaceAbove = rect.top - 10;
      const openUp = menuHeight > spaceBelow && spaceAbove >= menuHeight;
      const top = openUp ? Math.max(8, rect.top - menuHeight - 8) : Math.min(window.innerHeight - menuHeight - 8, rect.bottom + 8);
      const left = Math.min(Math.max(8, rect.left), Math.max(8, window.innerWidth - rect.width - 8));
      menu.style.left = left + "px";
      menu.style.width = rect.width + "px";
      menu.style.top = top + "px";
      menu.style.bottom = "auto";
    });
  }
}

function chooseUnifiedSelect(selectId, value) {
  const cfg = UNIFIED_SELECT_CONFIG[selectId];
  const select = cfg ? $(selectId) : null;
  const option = select ? Array.from(select.options).find(x => String(x.value) === String(value)) : null;
  if (!select || !option || option.disabled) return;
  select.value = value;
  select.dispatchEvent(new Event("change", {bubbles:true}));
  if (selectId === "log_filter_select") filterAndRenderLogs();
  renderUnifiedSelect(selectId);
  closeUnifiedSelects("");
}

function bindUnifiedSelectEvents() {
  document.querySelectorAll("[data-unified-toggle]").forEach(button => {
    button.addEventListener("click", event => {
      const widget = button.closest(".unified-select");
      const selectId = widget?.getAttribute("data-unified-select-id");
      if (selectId) toggleUnifiedSelect(selectId, event);
    });
  });
  document.addEventListener("click", event => {
    if (!event.target?.closest?.(".unified-select")) closeUnifiedSelects("");
  });
  window.addEventListener("resize", () => closeUnifiedSelects(""));
}

function syncUnifiedSelect(selectId) { renderUnifiedSelect(selectId); }

const COUNTRY_FLAG_CODES = {
  "日本":"JP","韩国":"KR","美国":"US","俄罗斯":"RU","中国":"CN","台湾":"TW","香港":"HK","澳门":"MO",
  "新加坡":"SG","马来西亚":"MY","印度尼西亚":"ID","印度":"IN","菲律宾":"PH","泰国":"TH","越南":"VN",
  "澳大利亚":"AU","新西兰":"NZ","加拿大":"CA","英国":"GB","法国":"FR","德国":"DE","荷兰":"NL","瑞典":"SE",
  "挪威":"NO","芬兰":"FI","丹麦":"DK","冰岛":"IS","爱尔兰":"IE","西班牙":"ES","葡萄牙":"PT","意大利":"IT",
  "瑞士":"CH","比利时":"BE","奥地利":"AT","希腊":"GR","土耳其":"TR","波兰":"PL","捷克":"CZ","斯洛伐克":"SK",
  "匈牙利":"HU","罗马尼亚":"RO","保加利亚":"BG","克罗地亚":"HR","塞尔维亚":"RS","斯洛文尼亚":"SI","爱沙尼亚":"EE",
  "拉脱维亚":"LV","立陶宛":"LT","乌克兰":"UA","格鲁吉亚":"GE","哈萨克斯坦":"KZ","亚美尼亚":"AM","阿塞拜疆":"AZ",
  "吉尔吉斯斯坦":"KG","蒙古":"MN","以色列":"IL","阿联酋":"AE","沙特阿拉伯":"SA","伊朗":"IR","伊拉克":"IQ","卡塔尔":"QA","阿曼":"OM",
  "埃及":"EG","南非":"ZA","尼日利亚":"NG","肯尼亚":"KE","摩洛哥":"MA","突尼斯":"TN","巴西":"BR","阿根廷":"AR","智利":"CL",
  "墨西哥":"MX","哥伦比亚":"CO","秘鲁":"PE","厄瓜多尔":"EC","乌拉圭":"UY","巴拿马":"PA","哥斯达黎加":"CR","多米尼加共和国":"DO",
  "波多黎各":"PR","阿尔巴尼亚":"AL","阿尔及利亚":"DZ","安哥拉":"AO","白俄罗斯":"BY","波斯尼亚和黑塞哥维那":"BA","博茨瓦纳":"BW",
  "文莱":"BN","喀麦隆":"CM","塞浦路斯":"CY","萨尔瓦多":"SV","埃塞俄比亚":"ET","斐济":"FJ","危地马拉":"GT","海地":"HT","牙买加":"JM",
  "约旦":"JO","科威特":"KW","黎巴嫩":"LB","利比亚":"LY","列支敦士登":"LI","马耳他":"MT","毛里求斯":"MU","摩尔多瓦":"MD","黑山":"ME",
  "缅甸":"MM","尼泊尔":"NP","巴基斯坦":"PK","巴拉圭":"PY","马达加斯加":"MG","斯里兰卡":"LK","乌干达":"UG","乌兹别克斯坦":"UZ","津巴布韦":"ZW",
  "巴哈马":"BS","玻利维亚":"BO","洪都拉斯":"HN","尼加拉瓜":"NI","特立尼达和多巴哥":"TT","圭亚那":"GY","苏里南":"SR","马尔代夫":"MV",
  "巴勒斯坦":"PS","百慕大":"BM","直布罗陀":"GI","马恩岛":"IM","泽西岛":"JE","根西岛":"GG","新喀里多尼亚":"NC","塞舌尔":"SC",
  "卢森堡":"LU","毛里塔尼亚":"MR","纳米比亚":"NA","刚果共和国":"CG","刚果民主共和国":"CD","加纳":"GH","坦桑尼亚":"TZ","赞比亚":"ZM",
  "塞内加尔":"SN","科特迪瓦":"CI","佛得角":"CV","莫桑比克":"MZ","马拉维":"MW","科索沃":"XK"
};

const COUNTRY_FLAG_ALIASES = {
  "Korea Republic of":"KR","Republic of Korea":"KR","Korea":"KR","Russian Federation":"RU","Russian":"RU",
  "Viet Nam":"VN","Vietnam":"VN","United States":"US","United States of America":"US","USA":"US","United Kingdom":"GB","UK":"GB",
  "Taiwan Province of China":"TW","Czech Republic":"CZ","Czechia":"CZ","Türkiye":"TR","Turkey":"TR","Brunei Darussalam":"BN",
  "Lao People's Democratic Republic":"LA","Laos":"LA","Côte d'Ivoire":"CI","Ivory Coast":"CI","Eswatini":"SZ","Swaziland":"SZ",
  "Moldova, Republic of":"MD","Palestine, State of":"PS","Syrian Arab Republic":"SY","Tanzania, United Republic of":"TZ",
  "Bolivia, Plurinational State of":"BO","Venezuela, Bolivarian Republic of":"VE","Cabo Verde":"CV","Cape Verde":"CV",
  "Curacao":"CW","Curaçao":"CW","Micronesia, Federated States of":"FM","Micronesia":"FM","Macedonia":"MK"
};

function countryFlagCode(country) {
  const raw = String(country || "").trim();
  const name = translateCountry(raw);
  if (/^[A-Za-z]{2}$/.test(raw)) return raw.toUpperCase();
  return COUNTRY_FLAG_CODES[name] || COUNTRY_FLAG_ALIASES[raw] || COUNTRY_FLAG_ALIASES[name] || "";
}

function countryFlagEmoji(code) {
  const value = String(code || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(value)) return "🌐";
  return String.fromCodePoint(...value.split("").map(ch => 0x1F1E6 + ch.charCodeAt(0) - 65));
}

function countryFlag(country, title = "", loading = "lazy") {
  const code = countryFlagCode(country).toLowerCase();
  const label = esc(title || translateCountry(country) || country || "");
  if (!code) {
    return '<span class="country-flag-fallback" role="img" aria-label="' + label + '" title="' + label + '">🌐</span>';
  }
  const eager = loading === "eager" ? ' fetchpriority="high"' : ' loading="lazy"';
  return '<img class="country-flag-img" src="https://flagcdn.com/w40/' + code + '.png" alt="" aria-hidden="true"' + eager +
    ' referrerpolicy="no-referrer" onerror="this.style.display=\'none\';this.nextElementSibling.style.display=\'inline-flex\';" title="' + label + '">' +
    '<span class="country-flag-fallback" role="img" aria-label="' + label + '" title="' + label + '" style="display:none;">🌐</span>';
}
function renderCustomFilter(selectId, withCount = false) {
  const cfg = CUSTOM_FILTER_CONFIG[selectId];
  const select = cfg ? $(selectId) : null;
  const label = cfg ? $(cfg.label) : null;
  const menu = cfg ? $(cfg.menu) : null;
  const widget = cfg ? $(cfg.widget) : null;
  if (!cfg || !select || !label || !menu) return;

  // Background polling repaints the page every 1.5–2s. Never replace the
  // live option DOM while the dropdown is open, otherwise a click can land
  // on an element that was just destroyed/recreated.
  if (widget?.classList.contains("open")) return;

  const selected = select.options[select.selectedIndex];
  const nextRawLabel = selected ? selected.textContent : "";
  const selectedParts = withCount ? String(nextRawLabel).split(" · ") : [String(nextRawLabel)];
  const selectedName = selectedParts.shift() || nextRawLabel;
  const selectedCount = selectedParts.join(" · ");
  const selectedFlag = withCount
    ? (String(select.value || "") ? countryFlag(select.value, selectedName, "eager") : countryFlag(""))
    : "";
  const selectedDisplay = withCount
    ? selectedFlag + '<span class="toolbar-custom-option-name">' + esc(selectedName) + '</span>' + (selectedCount ? '<span class="toolbar-custom-selected-count">· ' + esc(selectedCount) + '</span>' : '')
    : esc(nextRawLabel);
  if (label.innerHTML !== selectedDisplay) label.innerHTML = selectedDisplay;

  const html = Array.from(select.options).map(option => {
    const value = String(option.value || "");
    const textValue = String(option.textContent || "");
    const active = value === String(select.value || "");
    const parts = withCount ? textValue.split(" · ") : [textValue];
    const name = parts.shift() || textValue;
    const count = parts.join(" · ");
    const flagMarkup = withCount ? (value ? countryFlag(value, name, "lazy") : countryFlag("")) : "";
    return '<button type="button" class="toolbar-custom-option ' + (active ? 'active' : '') +
      '" role="option" aria-selected="' + (active ? 'true' : 'false') +
      '" data-filter-option="1" data-filter-value="' + esc(value) + '"' +
      ' onclick="event.preventDefault();event.stopPropagation();chooseCustomFilter(' + JSON.stringify(selectId) + ',' + JSON.stringify(value) + ')">' +
      '<span class="toolbar-custom-option-label">' +
      flagMarkup + '<span class="toolbar-custom-option-name">' + esc(name) + '</span>' +
      '</span>' +
      (count ? '<span class="toolbar-custom-option-count">' + esc(count) + '</span>' : '') +
      '</button>';
  }).join("");

  // Background refreshes run every 1.5–2s. Do not replace an unchanged open menu.
  if (menu.innerHTML !== html) menu.innerHTML = html;
}

function renderCustomCountryFilter() {
  renderCustomFilter("country_filter", true);
}

function renderAllCustomFilters() {
  renderCustomFilter("status_filter");
  renderCustomCountryFilter();
  renderCustomFilter("protocol_filter");
  renderCustomFilter("ip_type_filter");
}

function closeCustomFilters(exceptId = "") {
  Object.keys(CUSTOM_FILTER_CONFIG).forEach(id => {
    if (id === exceptId) return;
    const cfg = CUSTOM_FILTER_CONFIG[id];
    const widget = $(cfg.widget);
    const button = $(cfg.button);
    if (widget) widget.classList.remove("open");
    if (button) button.setAttribute("aria-expanded", "false");
  });
}

function toggleCustomFilter(selectId, event) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  const cfg = CUSTOM_FILTER_CONFIG[selectId];
  const widget = cfg ? $(cfg.widget) : null;
  const button = cfg ? $(cfg.button) : null;
  if (!cfg || !widget) return;
  const opening = !widget.classList.contains("open");
  closeCustomFilters(selectId);
  closeUnifiedSelects("");
  if (opening) renderCustomFilter(selectId, selectId === "country_filter");
  widget.classList.toggle("open", opening);
  if (button) button.setAttribute("aria-expanded", opening ? "true" : "false");
  if (opening) {
    const menu = $(cfg.menu);
    if (menu) {
      /* Toolbar menus are positioned relative to their trigger. This avoids
         viewport/fixed-position calculations and keeps the menu attached to
         the correct filter while the page is scrolling. */
      menu.style.left = "";
      menu.style.top = "";
      menu.style.bottom = "";
      menu.style.width = "";
    }
    const active = $(cfg.menu)?.querySelector(".toolbar-custom-option.active");
    if (active) active.scrollIntoView({block:"nearest"});
  }
}

function chooseCustomFilter(selectId, value) {
  const cfg = CUSTOM_FILTER_CONFIG[selectId];
  const select = $(selectId);
  if (!cfg || !select) return;
  const nextValue = String(value ?? "");
  select.value = Array.from(select.options).some(option => String(option.value) === nextValue) ? nextValue : "";
  closeCustomFilters();
  renderCustomFilter(selectId, selectId === "country_filter");
  select.dispatchEvent(new Event("change", {bubbles:true}));
}

function closeCustomCountryFilter() {
  closeCustomFilters();
}
function toggleCustomCountryFilter(event) {
  toggleCustomFilter("country_filter", event);
}
function chooseCountryFilter(value) {
  chooseCustomFilter("country_filter", value);
}

function bindCustomFilterEvents() {
  if (document.body?.dataset.customFilterEventsBound === "1") return;
  document.body.dataset.customFilterEventsBound = "1";

  document.addEventListener("click", event => {
    const option = event.target?.closest?.(".toolbar-custom-option[data-filter-option]");
    if (option) {
      const widget = option.closest(".toolbar-custom-select");
      const selectId = widget?.dataset?.filterId || "";
      if (selectId) {
        event.preventDefault();
        chooseCustomFilter(selectId, option.dataset.filterValue || "");
      }
      return;
    }

    const toggle = event.target?.closest?.("[data-filter-toggle]");
    if (toggle) {
      const widget = toggle.closest(".toolbar-custom-select");
      const selectId = widget?.dataset?.filterId || "";
      if (selectId) toggleCustomFilter(selectId, event);
      return;
    }

    if (!event.target?.closest?.(".toolbar-custom-select")) closeCustomFilters();
  });

  document.addEventListener("keydown", event => {
    const toggle = event.target?.closest?.("[data-filter-toggle]");
    if (!toggle) return;
    const widget = toggle.closest(".toolbar-custom-select");
    const selectId = widget?.dataset?.filterId || "";
    if (!selectId) return;
    if (event.key === "Enter" || event.key === " ") {
      toggleCustomFilter(selectId, event);
    } else if (event.key === "Escape") {
      closeCustomFilters();
    }
  });
}

function getNodeCountry(n) {
  const explicit = translateCountry(n && n.country);
  if (explicit && explicit !== "—" && explicit !== "-") return explicit;
  const location = String(n && n.location || "").trim().replace(/\s+/g, " ");
  if (!location) return "";
  const prefixes = [
    "United Arab Emirates","United Kingdom","United States","South Africa","New Zealand",
    "Saudi Arabia","Czech Republic","Costa Rica","Dominican Republic","Russian Federation",
    "Korea Republic of","Viet Nam","Vietnam","Hong Kong","Taiwan","Macao","Macau",
    "Croatia","Yemen","Japan","Korea","Thailand","Singapore","Malaysia","Indonesia","India",
    "Philippines","Australia","Canada","Ukraine","France","Germany","Netherlands","Sweden",
    "Norway","Spain","Turkey","Brazil","Argentina","Chile","Mexico","Egypt","Romania",
    "Poland","Kazakhstan","Georgia","Mongolia","Iran","Iraq","Colombia","Cambodia","Ireland",
    "Italy","Switzerland","Belgium","Austria","Denmark","Finland","Portugal","Greece",
    "Hungary","Israel","Iceland","Luxembourg","美国","加拿大","德国","英国","法国","日本",
    "韩国","新加坡","澳大利亚","新西兰","俄罗斯","中国","台湾","香港","澳门","荷兰","瑞典",
    "挪威","西班牙","意大利","瑞士","奥地利","比利时","丹麦","芬兰","葡萄牙","爱尔兰",
    "波兰","捷克","匈牙利","土耳其","印度","泰国","越南","马来西亚","印度尼西亚","菲律宾",
    "墨西哥","巴西","阿根廷","智利","南非","以色列","阿联酋"
  ];
  const lower = location.toLowerCase();
  for (const prefix of prefixes) {
    if (lower === prefix.toLowerCase() || lower.startsWith(prefix.toLowerCase() + " ")) {
      return translateCountry(prefix);
    }
  }
  return "";
}

let countryCatalogData = null;
let countryCatalogKey = "";
let countryCatalogPromise = null;
let activeCountryScope = "";
let scopeLoadGeneration = 0;

function currentFilterKey() {
  return [
    $("status_filter")?.value || "",
    $("protocol_filter")?.value || "",
    $("ip_type_filter")?.value || ""
  ].join("|");
}

async function refreshCountryCatalog(force = false) {
  const key = currentFilterKey();
  if (!force && countryCatalogData && countryCatalogKey === key) {
    updateCountryFilter();
    return countryCatalogData;
  }
  if (countryCatalogPromise) return countryCatalogPromise;
  const [status, protocol, ipType] = key.split("|");
  const params = new URLSearchParams();
  if (status) params.set("status", status);
  if (protocol) params.set("protocol", protocol);
  if (ipType) params.set("ip_type", ipType);

  countryCatalogPromise = fetchJsonWithTimeout("./api/ui/country_catalog" + (params.toString() ? "?" + params.toString() : ""), {}, 8000)
    .then(data => {
      countryCatalogData = data || {countries:{}, total_ip_count:0, server_country:""};
      countryCatalogKey = key;
      if (countryCatalogData.server_country && !state.server_country) {
        state.server_country = countryCatalogData.server_country;
      }
      updateCountryFilter();
      return countryCatalogData;
    })
    .finally(() => { countryCatalogPromise = null; });
  return countryCatalogPromise;
}

function updateCountryFilter() {
  const select = $("country_filter");
  if (!select) return;
  const selectedValue = String(select.value || "");
  const catalog = countryCatalogData || {countries:{}, total_ip_count:0};
  const merged = new Map();

  Object.entries(catalog.countries || {}).forEach(([rawCountry, item]) => {
    const country = translateCountry(rawCountry) || rawCountry;
    const current = merged.get(country) || {ip_count:0, server_count:0};
    current.ip_count += Number(item?.ip_count || 0);
    current.server_count += Number(item?.server_count || 0);
    merged.set(country, current);
  });

  const countries = Array.from(merged.entries()).sort((a,b) => {
    const diff = Number(b[1]?.ip_count || 0) - Number(a[1]?.ip_count || 0);
    return diff || a[0].localeCompare(b[0], "zh-CN");
  });

  const total = Number(catalog.total_ip_count || 0);
  const globalLabel = "全球国家 · " + total + " IP";
  const options = countries.map(([country, item]) => {
    const count = Number(item?.ip_count || 0);
    return '<option value="' + esc(country) + '">' + esc(country) + ' · ' + count + ' IP</option>';
  }).join("");

  select.innerHTML = '<option value="">' + globalLabel + '</option>' + options;
  // The native <select> is hidden; the visible country dropdown is a custom
  // widget. Keep both in sync whenever the catalog arrives or changes.
  renderCustomCountryFilter();
  const normalizedSelected = translateCountry(selectedValue);
  const selectedCountry = countries.find(([country]) =>
    country === selectedValue || country === normalizedSelected
  );
  if (selectedCountry) {
    select.value = selectedCountry[0];
  } else if (activeCountryScope) {
    const scopeLabel = translateCountry(activeCountryScope);
    const scopeCountry = countries.find(([country]) => country === scopeLabel);
    select.value = scopeCountry ? scopeCountry[0] : "";
  } else {
    select.value = "";
  }
  renderCustomCountryFilter();
}


function getFilteredNodes() {
  return nodes.filter(n => matchesNodeFilters(n, false));
}

function stableSortNodes() {
  const statusRank = { available: 0, testing: 1, not_checked: 2, unavailable: 3 };
  const protocolRank = { softether: 0, sstp: 1, "l2tp-ipsec": 2, openvpn: 3 };
  const latencyValue = n => {
    const value = Number(n?.latency_ms || 0);
    return value > 0 ? value : Number.MAX_SAFE_INTEGER;
  };
  const nowSeconds = Date.now() / 1000;
  const manualRank = n => {
    const ts = Number(n?.manual_added_at || 0);
    const recent = ts > 0 && (nowSeconds - ts) <= 3600;
    return [recent ? 0 : 1, recent ? -ts : 0];
  };
  nodes.sort((a, b) => {
    if (!a || !b) return 0;

    const aActive = !!((a.pool_endpoint_id && state.active_pool_endpoint_id === a.pool_endpoint_id) || (!state.active_pool_endpoint_id && a.active && a.id === state.active_openvpn_node_id));
    const bActive = !!((b.pool_endpoint_id && state.active_pool_endpoint_id === b.pool_endpoint_id) || (!state.active_pool_endpoint_id && b.active && b.id === state.active_openvpn_node_id));
    if (aActive !== bActive) return aActive ? -1 : 1;

    const aRank = statusRank[a.probe_status || "not_checked"] ?? 2;
    const bRank = statusRank[b.probe_status || "not_checked"] ?? 2;
    if (aRank !== bRank) return aRank - bRank;

    const am = manualRank(a);
    const bm = manualRank(b);
    if (am[0] !== bm[0]) return am[0] - bm[0];
    if (am[1] !== bm[1]) return am[1] - bm[1];

    // Default display order: lowest measured latency first within the same
    // availability state, regardless of protocol.
    const aLatency = latencyValue(a);
    const bLatency = latencyValue(b);
    if (aLatency !== bLatency) return aLatency - bLatency;

    const aProtocol = String(a.protocol || "openvpn").toLowerCase();
    const bProtocol = String(b.protocol || "openvpn").toLowerCase();
    const ap = protocolRank[aProtocol] ?? 9;
    const bp = protocolRank[bProtocol] ?? 9;
    if (ap !== bp) return ap - bp;

    const aScore = Number(a.score || 0);
    const bScore = Number(b.score || 0);
    if (bScore !== aScore) return bScore - aScore;

    return String(a.id || "").localeCompare(String(b.id || ""));
  });
}

function render(){
  const activeNodeId = state.active_openvpn_node_id;
  const activeNode = state.active_pool_endpoint_id
    ? null
    : nodes.find(n => n && (n.active && (!activeNodeId || n.id === activeNodeId) || n.id === activeNodeId));

  // Render separated Active Node Card
  const activeCardContainer = $("active_node_card");
  const switching = !!state.manual_switch_active || (!!state.is_connecting && !!state.pending_connection_id);
  if (switching) {
    const pendingCountry = translateCountry(state.pending_connection_country || "-");
    const pendingProtocol = translateProtocol(state.pending_connection_protocol || "-");
    const pendingAddress = state.pending_connection_address || state.pending_connection_id || "目标节点";
    const startedAt = Number(state.manual_switch_started_at || 0);
    const elapsed = startedAt ? Math.max(0, Math.floor(Date.now() / 1000 - startedAt)) : 0;
    const currentEp = state.active_pool_endpoint;
    const currentNode = activeNode;
    const currentLabel = currentEp
      ? `${translateProtocol(currentEp.protocol || state.active_tunnel_protocol || "")} · ${translateCountry(currentEp.country || "-")}`
      : currentNode
        ? `${translateProtocol(currentNode.protocol || "openvpn")} · ${translateCountry(currentNode.country || "-")}`
        : "当前连接";
    const switchMessage = state.manual_switch_message || state.last_check_message || "正在建立新连接…";
    activeCardContainer.innerHTML = `
      <div class="active-card switching-active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper switching-icon">
            <svg xmlns="http://www.w3.org/2000/svg" class="switch-spinner" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 0121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title switching-title">
              <span class="badge switching-badge"><span class="badge-pulse"></span>切换中</span>
              <strong>正在切换至 ${esc(pendingProtocol)} · ${esc(pendingCountry)}</strong>
              <span class="switch-elapsed">${elapsed}s</span>
            </div>
            <div class="active-card-value mono switching-target">${esc(pendingAddress)}</div>
            <div class="active-card-meta switching-meta">
              <span>当前连接：<strong>${esc(currentLabel)}</strong>，验证完成前保持在线</span>
              <span>阶段：<strong>${esc(switchMessage)}</strong></span>
            </div>
          </div>
        </div>
        <div class="switching-lock-note"><span class="switch-spinner-dot"></span>正在平滑建立并验证新隧道</div>
      </div>
    `;
  } else if (!activeNode && !state.active_pool_endpoint && state.connection_status === "connecting") {
    const busyTitle = state.maintenance_running ? "正在更新节点" : "正在连接";
    const busyLatency = state.maintenance_running ? "节点检测中" : (state.active_node_latency || "正在连接...");
    const busyMessage = state.last_check_message || (state.maintenance_running ? "正在后台拉取并检测节点，已完成的结果会实时显示在下方列表。" : "正在与 VPN 节点建立加密隧道，请稍候...");
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #f59e0b; width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>${esc(busyTitle)}</span>
              <strong>${esc(busyLatency)}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(busyMessage)}
            </div>
          </div>
        </div>
      </div>
    `;
  } else if (state.active_pool_endpoint) {
    const ep = state.active_pool_endpoint;
    const latencyValue = Number(state.proxy_latency_ms || 0);
    const latencyClass = getLatencyClass(latencyValue);
    const latencyText = latencyValue ? `<span class="latency-val ${latencyClass}">${latencyValue} ms</span>` : "-";
    const protocolName = translateProtocol(ep.protocol || state.active_tunnel_protocol || "openvpn");
    const activeDisplayLocation = formatNodeLocation({country: ep.country || "", location: ep.location || ""});
    const endpointAddress = ep.hostname || ep.current_ip || ep.endpoint_id || "-";
    const clientBadge = state.client_status === "usable" ? "客户端可用" : (state.client_status === "degraded" ? "客户端不可用" : "已连接 · 等待验证");
    const clientBadgeClass = state.client_status === "usable" ? "available" : (state.client_status === "degraded" ? "unavailable" : "not_checked");
    activeCardContainer.innerHTML = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge ${clientBadgeClass}"><span class="badge-pulse"></span>${esc(clientBadge)}</span>
              <strong>${esc(protocolName)} · ${esc(translateCountry(ep.country || "-"))}</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(endpointAddress)}${ep.port ? ":" + esc(String(ep.port)) : ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>协议: <strong>${esc(protocolName)}</strong></span>
              <span class="active-location-meta">物理位置: <strong><span class="active-location-with-flag">${countryFlag(ep.country || activeDisplayLocation, translateCountry(ep.country) || activeDisplayLocation, "eager")}<span>${esc(activeDisplayLocation)}</span></span></strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(ep.owner || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 类型: <strong>${esc(translateIpType(ep.ip_type))}</strong></span>
              <span style="margin-left: 12px;">带宽: <strong>${esc(speed(ep.speed))}</strong></span>
              <span class="active-hot-pool" title="当前处于 HOT 状态的节点数量；系统目标为最低热备数量"><span>热备池</span><strong>${esc(String(state.hot_pool_size || 0))} 个</strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">断开连接</button>
      </div>
    `;
  } else if (activeNode) {
    const activeLatencyValue = Number(state.proxy_latency_ms || 0);
    const latencyClass = getLatencyClass(activeLatencyValue);
    const latencyText = activeLatencyValue ? `<span class="latency-val ${latencyClass}">${activeLatencyValue} ms</span>` : "-";
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    const displayLocationFlag = countryFlag(activeNode.country || displayLocation, displayLocation, "eager");
    const clientBadge = state.client_status === "usable" ? "客户端可用" : (state.client_status === "degraded" ? "客户端不可用" : "已连接 · 等待验证");
    const clientBadgeClass = state.client_status === "usable" ? "available" : (state.client_status === "degraded" ? "unavailable" : "not_checked");
    activeCardContainer.innerHTML = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge ${clientBadgeClass}"><span class="badge-pulse"></span>${esc(clientBadge)}</span>
              <strong>${esc(translateCountry(activeNode.country))} · ${esc(translateProtocol(activeNode.protocol || "openvpn"))}</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>协议: <strong>${esc(translateProtocol(activeNode.protocol || "openvpn"))}</strong></span>
              <span class="active-location-meta">物理位置: <strong><span class="active-location-with-flag">${displayLocationFlag}<span>${esc(displayLocation)}</span></span></strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 类型: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          断开连接
        </button>
      </div>
    `;
  } else {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--border-color); box-shadow: none;">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge unavailable" style="padding: 2px 8px;">未连接</span> 当前未连接 VPN 节点
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              在下方列表中选择一个可用备用节点并点击 “切换” 按钮开始连接。
            </div>
          </div>
        </div>
      </div>
    `;
  }

  const bgActivityEl = $("background_activity_status");
  const bgActivityTextEl = $("background_activity_text");
  if (bgActivityEl && bgActivityTextEl) {
    const collecting = !!state.resource_engine_running;
    const probing = !!state.availability_engine_running;
    const priorityRunning = !!state.priority_running;
    const bootstrapRunning = !!state.initial_bootstrap_running;
    const manualSwitchRunning = !!state.manual_switch_active;
    const tested = Number(state.availability_tested_total || 0);
    const queue = Number(state.availability_queue || 0);
    let bgText = "资源守护正常运行 · 新资源进入后立即检测 · 后台检测不影响当前 VPN 连接";
    if (manualSwitchRunning) bgText = "人工切换中 · " + String(state.manual_switch_message || state.last_check_message || "正在平滑建立并验证新隧道") + " · 当前连接保持在线";
    else if (bootstrapRunning) bgText = "首次安装初始化中 · 先获取资源，再检测本机国家并自动连接最低延迟节点";
    else if (state.failover_in_progress) bgText = "主备切换中 · 正在验证备用节点，当前连接状态单独显示";
    else if (collecting) bgText = "资源收集中 · 正在从主站、镜像和多协议目录补充 Master Pool";
    else if (probing) bgText = String(state.availability_engine_message || "可用性检测中 · 新资源优先 · 全球资源最长 4 小时滚动复检");
    else if (priorityRunning) bgText = translateCountry(state.priority_country || "") + " 优先检测中 · 可用 " + Number(state.priority_available || 0) + "/" + Number(state.priority_target || 10);
    const detail = (tested > 0 || queue > 0) ? " · 已检测 " + tested + " · 待检测 " + queue : "";
    bgActivityEl.style.display = "flex";
    bgActivityEl.className = "background-task-strip " + ((manualSwitchRunning || collecting || probing || priorityRunning || bootstrapRunning || state.failover_in_progress) ? "running" : "");
    bgActivityTextEl.textContent = bgText + detail;
  }

  const globalRefreshEl = $("global_refresh_status");
  if (globalRefreshEl) {
    const running = !!state.global_pool_refresh_running;
    const status = String(state.global_pool_refresh_status || "idle");
    const message = String(state.global_pool_refresh_message || "");
    const servers = Number(state.global_pool_refresh_servers || 0);
    const sources = Number(state.global_pool_refresh_sources || 0);
    if (running || status === "error" || status === "ok") {
      globalRefreshEl.style.display = "flex";
      globalRefreshEl.className = "country-priority " + (running ? "running" : "");
      if (running) {
        globalRefreshEl.innerHTML = `<span class="badge not_checked"><span class="badge-pulse"></span>全球资源轮询中</span><span>${esc(message || "正在重新开始全球资源采集与可用性检测；当前 VPN 连接不会被断开。")}</span>`;
      } else {
        const detail = status === "error"
          ? message
          : (message || `全球库刷新完成 · 本次拉取 ${servers} 个服务器资源 · ${sources} 个镜像来源`);
        globalRefreshEl.innerHTML = `<span class="badge available">全球节点库已更新</span><span>${esc(detail)}</span>`;
      }
    } else {
      globalRefreshEl.style.display = "none";
    }
  }

  const priorityStatusEl = $("country_priority_status");
  if (priorityStatusEl) {
    const pcRaw = String(state.priority_country || "");
    const pc = translateCountry(pcRaw);
    if (pc) {
      const av = Number(state.priority_available || 0);
      const target = Number(state.priority_target || 10);
      const min = Number(state.priority_minimum || 5);
      const inventory = Number(state.priority_inventory || 0);
      const inventoryTarget = Number(state.priority_inventory_target || 20);
      const rawPriorityMessage = String(state.priority_message || (av + " 个可用节点"));
      const priorityMessage = /unauthorized|http\\s*401/i.test(rawPriorityMessage)
        ? "管理员会话已失效，请刷新页面并重新登录"
        : (pcRaw && rawPriorityMessage.startsWith(pcRaw)
          ? rawPriorityMessage.replace(pcRaw, pc)
          : rawPriorityMessage);
      priorityStatusEl.style.display = "flex";
      priorityStatusEl.className = state.priority_running ? "country-priority running" : "country-priority";
      priorityStatusEl.innerHTML = state.priority_running
        ? `<span class="badge not_checked"><span class="badge-pulse"></span>${esc(pc)} 优先检测中</span><span>库存 ${inventory}/${inventoryTarget} IP · 可用 ${av}/${target} · 目标 ${min}-${target}</span>`
        : `<span class="badge available">${esc(pc)} 优先检测完成</span><span>库存 ${inventory}/${inventoryTarget} IP · ${esc(priorityMessage)}</span>`;
    } else {
      priorityStatusEl.style.display = "none";
    }
  }

  const shown = getFilteredNodes();

  if ($("total")) $("total").textContent = totalNodeCount || nodes.length;
  if ($("target")) $("target").textContent = state.target_valid_nodes || 3;
  if ($("active")) $("active").textContent = activeNode ? 1 : 0;

  const statusMessage = state.last_check_message || "";
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">无</span>`;
  const localProxy = state.local_proxy || `http://127.0.0.1:${state.proxy_port || 8500}`;
  if ($("status")) { $("status").innerHTML=`<span class="status-dot"></span>HTTP 代理本地接口：${localProxy} | 活动节点：${activeNodeInfo} | 状态：${statusMessage}`; }

  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");

  if (state.is_connecting) {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "#f59e0b";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px; max-width: 450px; display: inline-block; white-space: normal; line-height: 1.4; text-align: left;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  updateFavPanelUI();

  // Pagination is server-side; the Master Pool total is authoritative.
  const totalPages = Math.ceil(Number(totalNodeCount || 0) / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;

  const startIndex = totalNodeCount > 0 ? (currentPage - 1) * pageSize : 0;
  const endIndex = Math.min(startIndex + shown.length, Number(totalNodeCount || 0));
  currentPageNodes = shown;

  // Render table rows
  if (currentPageNodes.length === 0) {
    $("rows").innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      if (!n) return '';
      const isCurrentlyActive = (n.pool_endpoint_id && state.active_pool_endpoint_id === n.pool_endpoint_id) || (!state.active_pool_endpoint_id && !!activeNode && n.id === activeNode.id);
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      const isTesting = testingNodeIds.has(n.id) || n.probe_status === "testing";
      const displayProbeStatus = isTesting ? "testing" : (n.probe_status || "not_checked");

      const badgeClass = isCurrentlyActive ? 'available' : displayProbeStatus;
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(displayProbeStatus);
      const rowLatencyValue = isCurrentlyActive
        ? Number(state.proxy_latency_ms || 0)
        : (n.probe_status === "available" ? Number(n.latency_ms || 0) : 0);
      const latencyClass = getLatencyClass(rowLatencyValue);
      const latencyText = rowLatencyValue ? `<span class="latency-val ${latencyClass}">${rowLatencyValue} ms</span>` : "-";
      const displayLocation = formatNodeLocation(n);
      const displayLocationFlag = countryFlag(n.country || displayLocation, translateCountry(n.country) || displayLocation, "lazy");
      const protocolName = translateProtocol(n.protocol || "openvpn");
      const nodeHost = n.ip || n.remote_host || "-";
      const nodePort = Number(n.remote_port || 0) > 0 ? ":" + String(n.remote_port) : "";
      const nodeAddress = nodeHost + nodePort;

      const canRetest = !isCurrentlyActive && !isTesting && ["not_checked", "unavailable"].includes(n.probe_status || "not_checked");
      const statusCell = isCurrentlyActive
        ? `<span class="badge available"><span class="badge-pulse"></span>已连接</span>`
        : canRetest
          ? `<button type="button" class="badge status-badge-button ${badgeClass}" title="点击立即检测此节点" onclick="testNode(this, '${esc(n.id)}', event)">${badgeText}</button>`
          : `<span class="badge ${badgeClass}">${badgeText}</span>`;

      // Background detection is allowed to continue while the user manually
      // switches nodes. Only an actual manual connection operation remains
      // mutually exclusive. A node currently being tested is still unavailable.
      const isUnavailable = n.probe_status === "unavailable";
      const backgroundDetectionRunning = !!(
        state.maintenance_running ||
        state.priority_running ||
        state.global_pool_refresh_running
      );
      const manualConnectBusy = manualConnectionUiBusy || !!state.manual_connection_active ||
        (!!state.is_connecting && !backgroundDetectionRunning);
      const switchRunning = !!state.manual_switch_active || manualConnectionUiBusy || !!state.manual_connection_active;
      const isPendingSwitch = switchRunning && (
        (state.pending_connection_pool_endpoint_id && n.pool_endpoint_id === state.pending_connection_pool_endpoint_id) ||
        (!state.pending_connection_pool_endpoint_id && state.pending_connection_id && n.id === state.pending_connection_id)
      );
      const connectBtn = isCurrentlyActive
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : isPendingSwitch
          ? `<button class="connect-btn switching-btn" disabled><span class="switch-spinner"></span>切换中</button>`
          : `<button class="connect-btn" ${(isUnavailable || isTesting || manualConnectBusy || switchRunning) ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : ''} onclick="connectNode('${esc(n.id)}')">切换</button>`;

      const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
      const isFav = favoriteIds.includes(n.id);
      const favBtn = isFav
        ? `<button class="test-btn" style="color: var(--warning); border-color: rgba(245, 158, 11, 0.4); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">★ 已收藏</button>`
        : `<button class="test-btn" style="color: var(--text-secondary); border-color: var(--border-color); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">☆ 收藏</button>`;

      return `<tr ${rowClass}>
        <td class="node-status-cell">${statusCell}</td>
        <td class="node-protocol-cell">${renderProtocolCell(n)}</td>
        <td class="node-address-cell" title="${esc(nodeAddress)}"><div class="node-cell-ellipsis mono">${esc(nodeAddress)}</div></td>
        <td style="white-space:nowrap;text-align:center;">${latencyText}</td>
        <td title="${esc(displayLocation)}"><div class="node-location-cell">${displayLocationFlag}<span class="node-cell-ellipsis">${esc(displayLocation)}</span></div></td>
        <td title="${esc(n.owner||n.as_name||"-")}"><div class="node-cell-ellipsis">${esc(n.owner||n.as_name||"-")}</div></td>
        <td title="${esc(translateIpType(n.ip_type))}"><div class="node-cell-ellipsis">${esc(translateIpType(n.ip_type))}</div></td>
        <td>
          <div class="table-actions">
            ${favBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Render pagination controls
  $("page_start").textContent = totalNodeCount > 0 && shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = totalNodeCount;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;
  const poolSummary = $("pool_summary");
  if (poolSummary) {
    const poolServers = Number(state.pool_servers || 0);
    const poolEndpoints = Number(state.pool_endpoints || 0);
    poolSummary.textContent = poolServers
      ? `Master Pool：${poolServers} 台服务器 · ${poolEndpoints} 个协议端点`
      : "Master Pool：—";
  }

  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;
}

// Hook up page buttons events
$("btn_first_page").onclick = () => loadServerPage(1);
$("btn_prev_page").onclick = () => loadServerPage(currentPage - 1);
$("btn_next_page").onclick = () => loadServerPage(currentPage + 1);
$("btn_last_page").onclick = () => {
  const totalPages = Math.max(1, Math.ceil(Number(totalNodeCount || 0) / pageSize));
  loadServerPage(totalPages);
};

async function prioritizeCountry(country){
  const selected = String(country || "").trim();
  countryPriorityRequestSeq += 1;
  const requestSeq = countryPriorityRequestSeq;
  if (countryPriorityPollInterval) {
    clearInterval(countryPriorityPollInterval);
    countryPriorityPollInterval = null;
  }
  if (!selected) {
    state.priority_country = "";
    state.priority_running = false;
    render();
    return;
  }
  state.priority_country = selected;
  state.priority_running = true;
  state.priority_available = 0;
  state.priority_target = 10;
  state.priority_minimum = 5;
  state.priority_message = `${selected} 优先检测已启动`;
  render();
  try {
    const response = await fetch("./api/prioritize_country", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ country: selected })
    });
    const result = await response.json().catch(() => ({}));
    if (requestSeq !== countryPriorityRequestSeq) return;
    if (!response.ok || !result.ok) {
      state.priority_running = false;
      state.priority_message = response.status === 401 || /unauthorized/i.test(String(result.error || ""))
        ? "管理员会话已失效，请刷新页面并重新登录"
        : (result.error || "国家优先检测启动失败");
      render();
      return;
    }
    const poll = async () => {
      if (requestSeq !== countryPriorityRequestSeq || countryPriorityPollBusy) return;
      countryPriorityPollBusy = true;
      try {
        const d = await fetchNodesState(8000);
        if (requestSeq !== countryPriorityRequestSeq) return;
        if (Array.isArray(d.nodes) && d.nodes.length > 0) mergeLoadedNodePage(d.nodes);
        if (d.state) state = d.state;
        stableSortNodes();
        updateCountryFilter();
        render();
        if (!state.priority_running || String(state.priority_country || "") !== selected) {
          if (countryPriorityPollInterval) { clearInterval(countryPriorityPollInterval); countryPriorityPollInterval = null; }
        }
      } catch (e) {
        if (requestSeq === countryPriorityRequestSeq && e?.name !== "AbortError") {
          console.warn("国家优先检测轮询暂时失败，保留当前结果", e);
        }
      } finally {
        countryPriorityPollBusy = false;
      }
    };
    await poll();
    countryPriorityPollInterval = setInterval(poll, 1500);
  } catch (e) {
    if (requestSeq === countryPriorityRequestSeq) {
      state.priority_running = false;
      state.priority_message = "国家优先检测请求失败";
      render();
    }
  }
}

async function testNode(btn, id, event){
  if (event) event.stopPropagation();
  testingNodeIds.add(id);
  render();

  try {
    const result = await fetchJsonWithTimeout("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    }, 30000);
    if (result.node) {
      const idx = nodes.findIndex(n => n && n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
      }
    }
  } catch (e) {
    const idx = nodes.findIndex(n => n && n.id === id);
    if (idx !== -1) {
      nodes[idx] = Object.assign({}, nodes[idx], {
        probe_status: "unavailable",
        probe_message: "手动检测失败：" + (e?.message || "请求超时"),
        probed_at: Date.now() / 1000
      });
    }
  } finally {
    testingNodeIds.delete(id);
    render();
  }
}

async function toggleFavorite(id, event) {
  if (event) event.stopPropagation();
  try {
    const response = await fetch("./api/toggle_favorite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok) {
      state.favorite_node_ids = Array.isArray(result.favorite_node_ids) ? result.favorite_node_ids : [];
      render();
    }
  } catch (e) {
    console.error("切换收藏失败", e);
  }
}

let pollInterval = null;
let refreshPollInterval = null;
let countryPriorityPollInterval = null;
let countryPriorityRequestSeq = 0;
let connectionPollBusy = false;
let refreshPollBusy = false;
let countryPriorityPollBusy = false;
let manualConnectionUiBusy = false;

async function fetchJsonWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(1000, Number(timeoutMs) || 10000));
  try {
    const requestOptions = Object.assign({
      credentials: "same-origin",
      cache: "no-store",
      headers: {"Accept": "application/json"}
    }, options || {});
    requestOptions.credentials = "same-origin";
    requestOptions.cache = "no-store";
    requestOptions.signal = controller.signal;
    requestOptions.headers = Object.assign({"Accept": "application/json"}, options && options.headers ? options.headers : {});
    const response = await fetch(url, requestOptions);
    let data = {};
    try { data = await response.json(); } catch (_) {}
    if (response.status === 401) throw new Error("登录状态已失效，请重新登录");
    if (!response.ok) throw new Error(data && data.error ? data.error : ("HTTP " + response.status));
    return data;
  } catch (err) {
    if (err && err.name === "AbortError") throw new Error("请求超时，请稍后重试");
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

let nodesFetchPromise = null;
let lastGoodNodesState = null;
let totalNodeCount = 0;
let nodeCacheBuilding = false;

async function fetchUiStateOnly(timeoutMs = 5000) {
  return fetchJsonWithTimeout("./api/ui/state", {}, timeoutMs);
}

async function fetchScopedNodePage(offset, limit = 100, timeoutMs = 12000) {
  const params = new URLSearchParams();
  params.set("offset", String(Math.max(0, Number(offset) || 0)));
  params.set("limit", String(Math.max(1, Math.min(200, Number(limit) || 100))));
  if (activeCountryScope) params.set("country", activeCountryScope);
  const status = $("status_filter")?.value || "";
  const protocol = $("protocol_filter")?.value || "";
  const ipType = $("ip_type_filter")?.value || "";
  if (status) params.set("status", status);
  if (protocol) params.set("protocol", protocol);
  if (ipType) params.set("ip_type", ipType);
  return fetchJsonWithTimeout("./api/ui/nodes?" + params.toString(), {}, timeoutMs);
}

async function fetchNodesState(timeoutMs = 8000) {
  const [nodeData, stateData] = await Promise.all([
    fetchScopedNodePage(0, 100, timeoutMs),
    fetchUiStateOnly(Math.min(timeoutMs, 4000))
  ]);
  return {
    nodes: Array.isArray(nodeData?.nodes) ? nodeData.nodes : [],
    state: stateData?.state || {},
    total: Number(nodeData?.total || 0),
    cache_building: !!nodeData?.cache_building
  };
}

function nodeLoadYield() {
  return new Promise(resolve => {
    if (typeof window.requestIdleCallback === "function") {
      window.requestIdleCallback(() => resolve(), {timeout: 150});
    } else {
      setTimeout(resolve, 20);
    }
  });
}

function mergeLoadedNodePage(pageNodes) {
  if (!Array.isArray(pageNodes) || !pageNodes.length) return;
  const incoming = new Map(pageNodes.map((n, idx) => [
    String(n?.id || n?.pool_endpoint_id || "__page_" + idx), n
  ]));
  nodes = nodes.filter(n => !incoming.has(String(n?.id || n?.pool_endpoint_id || "")));
  nodes.push(...pageNodes);
  stableSortNodes();
}

function updateNodeLoadProgress(done, total, finished = false) {
  const el = $("nodes_load_progress");
  if (!el) return;
  const scopeName = activeCountryScope ? translateCountry(activeCountryScope) : "全球节点";
  if (!total) {
    el.textContent = scopeName + "暂无可加载节点";
    return;
  }
  if (done >= total) {
    el.textContent = activeCountryScope
      ? scopeName + "节点已全部加载 · 共 " + total + " 条"
      : "全球节点已全部加载 · 共 " + total + " 条";
    return;
  }
  el.textContent = finished
    ? "已加载 " + done + "/" + total + " 条"
    : scopeName + "首页已就绪 · 后台继续加载 " + Math.max(0, total - done) + " 条";
}

async function loadScopedNodes(country, generation) {
  const myGeneration = generation;
  nodes = [];
  currentPage = 1;
  totalNodeCount = 0;
  nodeCacheBuilding = false;
  activeCountryScope = String(country || "").trim();

  // First-screen rule: one authoritative Master Pool page only.
  const first = await fetchScopedNodePage(0, pageSize, 12000);
  if (myGeneration !== scopeLoadGeneration) return;

  totalNodeCount = Number(first?.total || 0);
  nodeCacheBuilding = !!first?.cache_building;
  const firstNodes = Array.isArray(first?.nodes) ? first.nodes : [];
  if (firstNodes.length) mergeLoadedNodePage(firstNodes);

  updateCountryFilter();
  updateNodeLoadProgress(firstNodes.length, totalNodeCount, true);
  render();
}

let pageLoadBusy = false;
async function loadServerPage(page) {
  if (pageLoadBusy) return;
  const totalPages = Math.max(1, Math.ceil(Number(totalNodeCount || 0) / pageSize));
  const targetPage = Math.max(1, Math.min(totalPages, Number(page) || 1));
  if (targetPage === currentPage && nodes.length) return;

  const generation = ++scopeLoadGeneration;
  pageLoadBusy = true;
  currentPage = targetPage;
  nodes = [];
  render();
  updateNodeLoadProgress(0, totalNodeCount);

  try {
    const offset = (targetPage - 1) * pageSize;
    const data = await fetchScopedNodePage(offset, pageSize, 12000);
    if (generation !== scopeLoadGeneration) return;
    totalNodeCount = Number(data?.total || totalNodeCount || 0);
    nodeCacheBuilding = !!data?.cache_building;
    const pageNodes = Array.isArray(data?.nodes) ? data.nodes : [];
    mergeLoadedNodePage(pageNodes);
    updateNodeLoadProgress(pageNodes.length, totalNodeCount, true);
    render();
  } catch (e) {
    if (generation !== scopeLoadGeneration) return;
    console.warn("分页节点读取失败", e);
    updateNodeLoadProgress(0, totalNodeCount, true);
    render();
  } finally {
    pageLoadBusy = false;
  }
}

async function loadScope(country, {preserveState = true} = {}) {
  const generation = ++scopeLoadGeneration;
  const scope = String(country || "").trim();
  activeCountryScope = scope;
  nodes = [];
  totalNodeCount = 0;
  currentPage = 1;

  if (!preserveState) {
    try {
      const stateData = await fetchUiStateOnly(5000);
      if (stateData?.state) state = stateData.state;
    } catch (_) {}
  }

  render();
  try {
    await loadScopedNodes(scope, generation);
  } catch (e) {
    if (generation !== scopeLoadGeneration) return;
    console.warn("按范围加载节点失败", e);
    updateNodeLoadProgress(nodes.length, totalNodeCount, true);
    render();
  }
}

async function load(){
  const generation = ++scopeLoadGeneration;

  // Phase 1: current connection/status MUST render first.
  try {
    const stateData = await fetchUiStateOnly(5000);
    if (stateData?.state) state = stateData.state;
  } catch (e) {
    console.warn("状态读取失败，继续尝试读取节点范围", e);
  }
  if (generation !== scopeLoadGeneration) return;
  render();

  // Phase 2: country catalog is independent and must never block the first page.
  const catalogPromise = refreshCountryCatalog(true).catch(e => {
    console.warn("国家目录读取失败", e);
    return countryCatalogData || {server_country:"", countries:{}, total_ip_count:0};
  });

  let serverCountry = String(
    state.server_country ||
    state.initial_bootstrap_country ||
    countryCatalogData?.server_country ||
    ""
  ).trim();

  if (!serverCountry) {
    const catalog = await catalogPromise;
    if (generation !== scopeLoadGeneration) return;
    serverCountry = String(catalog?.server_country || "").trim();
  }

  if (generation !== scopeLoadGeneration) return;
  activeCountryScope = serverCountry;
  const select = $("country_filter");
  if (select && serverCountry) select.value = serverCountry;

  // Phase 3: one scoped page only. Subsequent pages are fetched on demand.
  try {
    await loadScopedNodes(serverCountry, generation);
  } catch (e) {
    if (generation !== scopeLoadGeneration) return;
    console.warn("首屏节点范围读取失败", e);
    updateNodeLoadProgress(nodes.length, totalNodeCount, true);
    render();
  }

  if (state.global_pool_refresh_running || state.maintenance_running) {
    startRefreshPolling();
  } else if (state.is_connecting || state.manual_switch_active) {
    startConnectionPolling();
  }
}

function refreshButtonBusy(message = "正在后台更新...") {
  const btn = $("refresh");
  if (!btn) return;
  btn.disabled = true;
  btn.innerHTML = `<svg style="animation: spin 1s linear infinite; width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>${esc(message)}`;
}

function refreshButtonIdle() {
  const btn = $("refresh");
  if (!btn) return;
  btn.disabled = false;
  btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>重新轮询全球库`;
}

function startRefreshPolling() {
  if (refreshPollInterval) clearInterval(refreshPollInterval);
  refreshButtonBusy("正在重新轮询全球库...");
  refreshPollInterval = setInterval(async () => {
    if (refreshPollBusy) return;
    refreshPollBusy = true;
    try {
      const data = await fetchNodesState(8000);
      if (Array.isArray(data.nodes) && data.nodes.length > 0) mergeLoadedNodePage(data.nodes);
      if (data.state) state = data.state;
      stableSortNodes();
      updateCountryFilter();
      render();

      if (!state.global_pool_refresh_running) {
        clearInterval(refreshPollInterval);
        refreshPollInterval = null;
        refreshButtonIdle();
        // Rebuild the browser snapshot from the first page, then lazily load
        // the remaining global nodes in the background.
        load();
      }
    } catch (pe) {
      if (pe?.name === "AbortError") return;
      clearInterval(refreshPollInterval);
      refreshPollInterval = null;
      refreshButtonIdle();
    } finally {
      refreshPollBusy = false;
    }
  }, 1500);
}

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    if (connectionPollBusy) return;
    connectionPollBusy = true;
    try {
      // Connection progress is state-only. Avoid re-downloading the full ~1.5MB
      // node list every 500ms; refresh the node list once the switch completes.
      const data = await fetchJsonWithTimeout("./api/ui/state", {}, 2500);
      if (data.state) state = data.state;
      render();

      if (!state.is_connecting && !state.manual_switch_active && !state.maintenance_running && !state.failover_in_progress) {
        clearInterval(pollInterval);
        pollInterval = null;
        manualConnectionUiBusy = false;
        await load();
        fetchJsonWithTimeout("./api/test_proxy", { method: "POST" }, 8000).catch(() => {});
        render();
      }
    } catch(pe) {
      if (pe?.name !== "AbortError") console.warn("切换状态读取失败，继续等待下一次状态更新", pe);
    } finally {
      connectionPollBusy = false;
    }
  }, 500);
}

async function connectNode(id){
  if (manualConnectionUiBusy || state.manual_connection_active || state.manual_switch_active || state.failover_in_progress) return;
  if (state.ui_command_plane?.active?.kind === "manual_connect") return;
  manualConnectionUiBusy = true;
  const selectedNode = nodes.find(n => n && n.id === id);
  const poolEndpointId = selectedNode && selectedNode.pool_endpoint_id ? selectedNode.pool_endpoint_id : "";
  state.is_connecting = true;
  state.manual_connection_active = true;
  state.manual_switch_active = true;
  state.manual_switch_started_at = Date.now() / 1000;
  state.pending_connection_id = id;
  state.pending_connection_protocol = selectedNode?.protocol || "";
  state.pending_connection_country = selectedNode?.country || "";
  state.active_node_latency = "正在切换";
  state.manual_switch_message = "正在发送连接请求…";
  state.last_check_message = "正在切换，当前连接在目标节点验证通过前保持不变…";
  render();

  startConnectionPolling();

  try {
    const fallbackEndpointIds = selectedNode && Array.isArray(selectedNode.pool_endpoint_ids)
      ? selectedNode.pool_endpoint_ids
      : (poolEndpointId ? [poolEndpointId] : []);
    const result = await fetchJsonWithTimeout(
      poolEndpointId ? "./api/connect_pool_endpoint" : "./api/connect",
      {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: poolEndpointId
          ? JSON.stringify({endpoint_id: poolEndpointId, endpoint_ids: fallbackEndpointIds})
          : JSON.stringify({id})
      },
      600000
    );
    if (result.ok && result.auto_fallback) {
      state.last_check_message = result.message || "当前节点失败，正在自动切换备用节点...";
      state.active_node_latency = "自动切换";
      render();
    }
    if (result.ok) {
      if (result.state) state = result.state;
      state.pending_connection_id = "";
      state.pending_connection_protocol = "";
      state.pending_connection_country = "";
      manualConnectionUiBusy = false;
      load();
    }
    if (!result.ok) {
      if (result.state) state = result.state;
      manualConnectionUiBusy = false;
      state.is_connecting = false;
      state.manual_connection_active = false;
      state.manual_switch_active = false;
      state.pending_connection_id = "";
      state.pending_connection_pool_endpoint_id = "";
      state.pending_connection_protocol = "";
      state.pending_connection_country = "";
      state.pending_connection_address = "";
      state.last_check_message = result.error || "人工切换失败，服务器未完成目标节点验证。";
      state.manual_switch_message = result.restored_previous
        ? "切换失败，已保留/恢复原连接。"
        : "切换失败，请检查节点状态或稍后重试。";
      await load();
      render();
      return;
    }
  } catch(e) {
    // The reverse proxy may time out before the backend finishes a long,
    // make-before-break switch. Do not fabricate a failure or clear the server
    // state; keep polling until the backend reports the final result.
    state.last_check_message = "连接请求暂时中断，服务器仍可能正在验证新节点；请勿重复点击，正在继续读取切换状态…";
    state.manual_switch_message = "正在等待服务器最终切换结果…";
    state.is_connecting = true;
    state.manual_connection_active = true;
    state.manual_switch_active = true;
    manualConnectionUiBusy = true;
    render();
    startConnectionPolling();
  }
}

async function disconnectNode(){
  if (!confirm("确定要断开当前的 VPN 连接吗？")) return;
  try {
    const result = await fetchJsonWithTimeout("./api/disconnect", { method: "POST" }, 15000);
    if (result.ok) {
      try {
        await fetch("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
    } else {
      alert("断开连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("请求断开连接失败");
  }
}





function openAddNodeModal(){
  const modal = $("add_node_modal");
  const input = $("add_node_address");
  const result = $("add_node_result");
  if (modal) modal.style.display = "flex";
  if (result) result.style.display = "none";
  const submit = $("add_node_submit");
  if (submit) {
    submit.disabled = false;
    submit.textContent = "开始识别";
    submit.onclick = submitAddNode;
  }
  if (input) {
    input.value = "";
    setTimeout(() => input.focus(), 80);
  }
  if (modal && !modal.dataset.bound) {
    modal.addEventListener("click", (event) => {
      if (event.target === modal) closeAddNodeModal();
    });
    input?.addEventListener("keydown", (event) => {
      if (event.key === "Enter") submitAddNode();
      if (event.key === "Escape") closeAddNodeModal();
    });
    modal.dataset.bound = "1";
  }
}

function closeAddNodeModal(){
  const modal = $("add_node_modal");
  if (modal) modal.style.display = "none";
}

function fillAddNodeExample(value){
  const input = $("add_node_address");
  if (!input) return;
  input.value = value;
  input.focus();
}

function renderManualAddAttempts(data, success) {
  const rawAttempts = Array.isArray(data && data.attempts) ? data.attempts : [];
  const names = {openvpn:"OpenVPN",softether:"SSL-VPN","l2tp-ipsec":"L2TP/IPsec",sstp:"MS-SSTP"};
  const order = ["openvpn","softether","l2tp-ipsec","sstp"];
  const seen = {};
  rawAttempts.forEach(function(item) {
    seen[String(item.protocol || "").toLowerCase()] = item;
  });
  const attempts = order.map(function(protocol) {
    return seen[protocol] || {
      protocol: protocol,
      transport: protocol === "l2tp-ipsec" ? "udp" : "tcp",
      port: 0,
      ok: false,
      skipped: true,
      message: "未返回该协议检测结果"
    };
  });

  const passedCount = attempts.filter(function(item) { return !!item.ok; }).length;
  const rows = attempts.map(function(item) {
    const protocol = String(item.protocol || "").toLowerCase();
    const name = names[protocol] || String(item.protocol || "未知协议");
    const transport = item.transport ? " " + String(item.transport).toUpperCase() : "";
    const port = Number(item.port || 0) ? " :" + String(item.port) : "";
    let icon = "•", stateText = "未检测", cls = "color:var(--text-secondary);";
    if (item.skipped) { icon = "—"; stateText = "未公布 / 未检测"; }
    else if (item.ok) { icon = "✓"; stateText = "通过"; cls = "color:var(--success);"; }
    else { icon = "×"; stateText = "未通过"; cls = "color:var(--danger);"; }
    const detail = item.message ? String(item.message).slice(0, 180) : "";
    return '<div style="display:flex;align-items:flex-start;gap:8px;padding:7px 0;border-bottom:1px solid rgba(255,255,255,.05);">' +
      '<span style="width:18px;flex:0 0 18px;font-weight:600;' + cls + '">' + icon + '</span>' +
      '<span style="flex:1;color:var(--text-primary);">' + esc(name + transport + port) +
      '<span style="margin-left:8px;' + cls + '">' + stateText + '</span>' +
      (detail ? '<span style="display:block;margin-top:2px;font-size:11px;color:var(--text-secondary);">' + esc(detail) + '</span>' : '') +
      '</span></div>';
  }).join("");

  const title = success
    ? "✓ 直连验证完成 · " + passedCount + "/4 协议通过，节点已加入资源池"
    : "4 种 VPN Gate 接入方式均未建立成功，节点未加入资源池";
  const color = success ? "var(--success)" : "var(--danger)";
  const border = success ? "rgba(34,197,94,.22)" : "rgba(244,63,94,.20)";
  const bg = success ? "rgba(34,197,94,.07)" : "rgba(244,63,94,.07)";
  const address = data && (data.hostname || data.ip)
    ? String(data.hostname || data.ip) + (data.port ? ":" + String(data.port) : "")
    : "";
  const message = success
    ? (data.message || "直连验证完成，所有可用协议结果均已写入资源池。")
    : (data.error || "节点未通过直连验证。");

  return '<div style="padding:13px 14px;background:' + bg + ';border:1px solid ' + border + ';border-radius:9px;">' +
    '<div style="font-size:13px;font-weight:600;color:' + color + ';">' + title + '</div>' +
    (address ? '<div style="margin-top:5px;font-size:12px;color:var(--text-secondary);">节点地址：<span class="mono" style="color:var(--text-primary);">' + esc(address) + '</span></div>' : '') +
    '<div style="margin-top:6px;font-size:12px;color:var(--text-secondary);">' + esc(message) + '</div>' +
    '<div style="margin-top:8px;border-top:1px solid rgba(255,255,255,.05);">' + rows + '</div>' +
    '</div>';
}

async function submitAddNode(){
  const input = $("add_node_address");
  const submit = $("add_node_submit");
  const resultBox = $("add_node_result");
  const address = String(input && input.value || "").trim();
  if (!address) { if (input) input.focus(); return; }
  const validAddress =
    /^[^:\s]+(?::\d{1,5})?$/.test(address) ||
    /^\[[0-9a-fA-F:]+\](?::\d{1,5})?$/.test(address);
  if (!validAddress) {
    if (resultBox) {
      resultBox.style.display = "block";
      resultBox.innerHTML = '<div style="padding:11px 12px;color:var(--warning);background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.2);border-radius:8px;">请输入“域名 / 域名:端口 / IPv4 / IPv4:端口”；VPN Gate .opengw.net 域名可不填写端口，系统会自动读取官方公布端口。</div>';
    }
    return;
  }
  try {
    if (submit) { submit.disabled = true; submit.textContent = "正在直连..."; }
    if (resultBox) {
      resultBox.style.display = "block";
      resultBox.innerHTML = '<div style="padding:12px;color:var(--text-secondary);border:1px solid var(--border-color);border-radius:8px;">正在读取 VPN Gate 官方端口并直连验证 4 种接入方式；已公布的协议会逐一测试，所有通过的协议都会写入资源池...</div>';
    }
    const data = await fetchJsonWithTimeout("./api/add_node", {
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({address: address})
    }, 60000);

    if (resultBox) resultBox.innerHTML = renderManualAddAttempts(data, !!data.ok);
    if (data.ok) {
      const addedNodes = Array.isArray(data.added_nodes) ? data.added_nodes.filter(Boolean) : [];
      if (addedNodes.length) {
        mergeLoadedNodePage(addedNodes);
        currentPage = 1;
        totalNodeCount = Math.max(totalNodeCount, nodes.length);
        updateCountryFilter();
      }
      state.last_check_message = data.message || "新增节点已入库 · 已通知可用性检测模块";
      state.availability_engine_message = "新增节点已入库 · 已通知可用性检测模块，正在立即复核";
      state.availability_engine_running = true;
      render();
    }
    if (submit) {
      submit.disabled = false;
      submit.textContent = data.ok ? "完成" : "重新识别";
      submit.onclick = data.ok ? closeAddNodeModal : submitAddNode;
    }
  } catch (err) {
    if (resultBox) {
      resultBox.style.display = "block";
      resultBox.innerHTML = '<div style="padding:12px;color:var(--danger);background:rgba(244,63,94,.07);border:1px solid rgba(244,63,94,.2);border-radius:8px;">添加失败：' + esc(err.message || err) + '</div>';
    }
    if (submit) { submit.textContent = "重新识别"; submit.disabled = false; }
  }
}

let initialNodeLoadRetryCount = 0;
async function loadLegacy(){
  const generation = ++nodeLoadGeneration;
  // A fresh page load starts with the first 100 rows only. Any previous
  // progressive loader sees the generation change and exits without touching
  // the new snapshot.
  nodes = [];
  totalNodeCount = 0;
  nodeCacheBuilding = false;
  nodeProgressivePromise = null;

  try {
    const d = await fetchNodesState(8000);
    const incomingNodes = Array.isArray(d.nodes) ? d.nodes : [];
    totalNodeCount = Math.max(
      Number(d.total || 0),
      Number(d?.state?.pool_endpoints || 0),
      incomingNodes.length
    );
    nodeCacheBuilding = !!d.cache_building;

    if (incomingNodes.length > 0) {
      nodes = incomingNodes;
      initialNodeLoadRetryCount = 0;
    } else {
      let restored = false;
      try {
        const cached = JSON.parse(sessionStorage.getItem("aimili_last_nodes_snapshot") || "null");
        if (cached && Array.isArray(cached.nodes) && cached.nodes.length) {
          nodes = cached.nodes.slice(0, 100);
          restored = true;
        }
      } catch (_) {}
      const poolEndpoints = Number(d?.state?.pool_endpoints || 0);
      if (!restored && poolEndpoints > 0 && initialNodeLoadRetryCount < 12) {
        initialNodeLoadRetryCount += 1;
        state = d.state || state || {};
        state.last_check_message = "节点资源正在恢复；首页先显示可用数据，后台继续读取其余节点...";
        render();
        setTimeout(() => load(), 600);
        return;
      }
    }
    if (d.state) state = d.state;
  } catch (e) {
    console.warn("节点首屏读取暂时失败，尝试使用本地缓存", e);
    try {
      const cached = JSON.parse(sessionStorage.getItem("aimili_last_nodes_snapshot") || "null");
      if (cached && Array.isArray(cached.nodes) && cached.nodes.length) {
        nodes = cached.nodes.slice(0, 100);
        totalNodeCount = Math.max(totalNodeCount, nodes.length);
      }
    } catch (_) {}
  }

  stableSortNodes();
  updateCountryFilter();
  updateNodeLoadProgress(nodes.length, totalNodeCount);
  render();

  if (totalNodeCount > nodes.length) {
    progressivelyLoadNodes(totalNodeCount, generation);
  }

  if (state.global_pool_refresh_running) {
    startRefreshPolling();
  } else if (state.maintenance_running) {
    startRefreshPolling();
  } else if (state.is_connecting) {
    startConnectionPolling();
  }
}
async function applyNodeFilterChange() {
  currentPage = 1;
  try {
    await refreshCountryCatalog(true);
  } catch (_) {}
  const country = activeCountryScope;
  await loadScope(country, {preserveState:true});
}

$("country_filter").onchange=async()=>{
  const country = String($("country_filter").value || "").trim();
  activeCountryScope = country;
  currentPage = 1;

  // Empty country is the explicit “全球国家” action and is the only path
  // allowed to request the complete global node list.
  if (!country) {
    await loadScope("", {preserveState:true});
    return;
  }

  // Country selection loads that country only; priority probing is started
  // after its rows are visible instead of blocking the dropdown itself.
  await loadScope(country, {preserveState:true});
  prioritizeCountry(country);
};
$("protocol_filter").onchange=applyNodeFilterChange;
$("ip_type_filter").onchange=applyNodeFilterChange;
$("status_filter").onchange=applyNodeFilterChange;
renderAllCustomFilters();
bindCustomFilterEvents();
renderAllUnifiedSelects();
bindUnifiedSelectEvents();

$("refresh").onclick=async()=>{
  if (manualConnectionUiBusy || state.manual_connection_active) return;
  refreshButtonBusy("正在重新轮询全球库...");
  try{
    const data = await fetchJsonWithTimeout("./api/refresh_global_pool",{method:"POST"}, 10000);
    if (data.ok === false) throw new Error(data.error || "全球库刷新启动失败");
    state = Object.assign({}, state, {
      global_pool_refresh_running: true,
      global_pool_refresh_status: "running",
      global_pool_refresh_message: data.message || "正在重新开始全球资源轮询"
    });
    render();
    startRefreshPolling();
  }
  catch(e){
    refreshButtonIdle();
    alert("更新节点失败：\n" + (e.message || e));
  }
};
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");

  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";

  try {
    const result = await fetchJsonWithTimeout("./api/test_proxy", { method: "POST" }, 10000);
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";

      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

// GitHub production version / update
let githubUpdateBusy = false;

function setGithubUpdateMessage(message, type = "normal") {
  const el = $("github_update_message");
  if (!el) return;
  el.textContent = message || "";
  el.style.color = type === "success" ? "var(--success)" : (type === "error" ? "var(--danger)" : "var(--text-secondary)");
}

function setGithubUpdateButtonBusy(busy, label) {
  const btn = $("github_check_update");
  if (!btn) return;
  btn.disabled = !!busy;
  btn.textContent = label || (busy ? "检查中..." : "检查更新");
}

async function loadGithubCurrentVersion() {
  try {
    const result = await fetchJsonWithTimeout("./api/github_version", {}, 4000);
    const versionLabel = String(result.current_version || "未知");
    const el = $("github_current_version");
    if (el) el.textContent = versionLabel;
  } catch (e) {
    const el = $("github_current_version");
    if (el) el.textContent = "未知";
  }
}

async function checkGithubUpdate() {
  if (githubUpdateBusy) return;
  githubUpdateBusy = true;
  setGithubUpdateButtonBusy(true, "检查中...");
  const applyBtn = $("github_apply_update");
  if (applyBtn) applyBtn.style.display = "none";
  setGithubUpdateMessage("正在检查 GitHub 正式版...");
  try {
    const result = await fetchJsonWithTimeout("./api/github_update/check", {}, 10000);
    const current = result.current_version || "未知";
    const latest = result.latest_version || current;
    const currentEl = $("github_current_version");
    if (currentEl) currentEl.textContent = current;
    if (result.ok && result.has_update) {
      setGithubUpdateMessage("发现新版本 " + latest + "，当前 " + current + "。", "success");
      if (applyBtn) { applyBtn.style.display = "inline-flex"; applyBtn.disabled = false; }
    } else if (result.ok) {
      const messageType = result.relation === "local_ahead" ? "normal" : "success";
      setGithubUpdateMessage(result.message || ("当前已经是最新正式版（" + current + "）。"), messageType);
    } else {
      setGithubUpdateMessage(result.error || "检查更新失败。", "error");
    }
  } catch (e) {
    setGithubUpdateMessage("检查更新失败：" + (e.message || "网络错误"), "error");
  } finally {
    githubUpdateBusy = false;
    setGithubUpdateButtonBusy(false);
  }
}

async function applyGithubUpdate() {
  if (githubUpdateBusy) return;
  const btn = $("github_apply_update");
  if (!btn) return;
  githubUpdateBusy = true;
  btn.disabled = true;
  setGithubUpdateButtonBusy(true, "更新中...");
  setGithubUpdateMessage("正在拉取 GitHub 正式版，更新完成后服务会自动重启...");
  try {
    const result = await fetchJsonWithTimeout("./api/github_update", { method: "POST" }, 10000);
    if (!result.ok) {
      setGithubUpdateMessage(result.error || "更新启动失败。", "error");
      btn.disabled = false;
      setGithubUpdateButtonBusy(false);
      githubUpdateBusy = false;
      return;
    }
    if (result.status === "latest") {
      setGithubUpdateMessage(result.message || "当前已经是最新版本。", "success");
      btn.style.display = "none";
      setGithubUpdateButtonBusy(false);
      githubUpdateBusy = false;
      return;
    }
    setGithubUpdateMessage(result.message || "更新已启动，服务即将重启。", "success");
    setTimeout(() => window.location.reload(), 7000);
  } catch (e) {
    setGithubUpdateMessage("更新请求已发出；如果服务正在重启，请稍候刷新页面。", "success");
    setTimeout(() => window.location.reload(), 7000);
  }
}

// Admin dropdown toggle & GitHub dropdown toggle
const adminBtn = $("admin_btn");
const adminDropdown = $("admin_dropdown");
const githubBtn = $("github_btn");
const githubDropdown = $("github_dropdown");

if (adminBtn && adminDropdown) {
  adminBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = adminDropdown.style.display === "block";
    adminDropdown.style.display = isShow ? "none" : "block";
    if (githubDropdown) githubDropdown.style.display = "none";
  };
}

if (githubBtn && githubDropdown) {
  githubBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = githubDropdown.style.display === "block";
    githubDropdown.style.display = isShow ? "none" : "block";
    if (adminDropdown) adminDropdown.style.display = "none";
    if (!isShow) loadGithubCurrentVersion();
  };
}

if ($("github_check_update")) {
  $("github_check_update").onclick = (e) => {
    e.stopPropagation();
    checkGithubUpdate();
  };
}

if ($("github_apply_update")) {
  $("github_apply_update").onclick = (e) => {
    e.stopPropagation();
    applyGithubUpdate();
  };
}

document.addEventListener("click", () => {
  if (adminDropdown) adminDropdown.style.display = "none";
  if (githubDropdown) githubDropdown.style.display = "none";
});

let showFavoritesOnly = false;

function toggleFavoritesView() {
  showFavoritesOnly = !showFavoritesOnly;
  currentPage = 1;
  render();
}

function updateFavPanelUI() {
  const panel = $("favorites_panel");
  if (!panel) return;
  panel.style.display = showFavoritesOnly ? "block" : "none";

  const btn = $("btn_favorites");
  if (btn) {
    if (showFavoritesOnly) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  }

  if (showFavoritesOnly && state) {
    const favRoutingBtn = $("btn_toggle_fav_routing");
    if (favRoutingBtn) {
      if (state.routing_mode === "favorites") {
        favRoutingBtn.textContent = "禁用仅用收藏出站";
        favRoutingBtn.style.background = "var(--danger-gradient)";
        favRoutingBtn.style.borderColor = "transparent";
        favRoutingBtn.style.color = "#ffffff";
        favRoutingBtn.style.boxShadow = "0 0 12px rgba(244, 63, 94, 0.3)";
      } else {
        favRoutingBtn.textContent = "启用仅用收藏出站";
        favRoutingBtn.style.background = "rgba(255,255,255,0.03)";
        favRoutingBtn.style.borderColor = "var(--border-color)";
        favRoutingBtn.style.color = "var(--text-primary)";
        favRoutingBtn.style.boxShadow = "none";
      }
    }
  }
}

async function toggleFavRouting() {
  if (!state) return;
  const newMode = state.routing_mode === "favorites" ? "auto" : "favorites";

  state.routing_mode = newMode;
  updateFavPanelUI();

  try {
    const res = await fetch("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: newMode,
        force_country: state.force_country || "",
        routing_ip_type: state.routing_ip_type || "all"
      })
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      load();
    } else {
      alert("更新出站路由设置失败: " + (data.error || "未知错误"));
      load();
    }
  } catch (err) {
    alert("连接服务器失败，请稍后重试");
    load();
  }
}

function selectOptionCard(groupName, value) {
  if (groupName === 'routing_mode') {
    const input = $("net_routing_mode");
    if (input) input.value = value;

    const cards = document.querySelectorAll("#routing_mode_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });

    handleRoutingModeChange(value);
  } else if (groupName === 'routing_ip_type') {
    const input = $("net_routing_ip_type");
    if (input) input.value = value;

    const cards = document.querySelectorAll("#routing_ip_type_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
  }
}

function setRoutingMode(value) {
  selectOptionCard('routing_mode', value);
}

function setRoutingIpType(value) {
  selectOptionCard('routing_ip_type', value);
}

function handleRoutingModeChange(mode) {
  const countryGroup = $("net_force_country_group");
  const warningDiv = $("net_routing_warning");

  if (mode === "fixed_region") {
    countryGroup.style.display = "block";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `ℹ️ <strong>优先地区</strong>：优先选择您指定的国家；若目标国家暂时没有可用节点，系统会自动放宽国家/IP 类型限制，按稳定性、延迟和带宽选择可用出口；目标恢复后自动切回。`;
  } else if (mode === "favorites") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `ℹ️ <strong>仅用收藏</strong>：优先使用您收藏的节点；如果全部收藏节点暂时不可用，系统默认自动回退到全局可用节点，避免代理中断。收藏节点恢复后会自动优先切回。`;
  } else if (mode === "fixed_ip") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定IP</strong>：锁定当前连接的节点。不管该节点是否失效，系统都绝不自动切换至其他IP；如果节点由于网络故障失效，会造成代理中断（但如果OpenVPN连接意外退出，脚本将尝试为您在后台重新拉起连接同一IP）。<br><strong>提示</strong>：您可以在主页 of 节点列表中直接点击“连接”按钮来选择并锁定不同的IP节点。`;
  } else {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--text-secondary)";
    warningDiv.style.background = "rgba(255, 255, 255, 0.02)";
    warningDiv.style.border = "1px solid rgba(255, 255, 255, 0.05)";
    warningDiv.innerHTML = `ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。`;
  }
}

function populateRoutingCountries() {
  const select = $("net_force_country");
  if (!select) return;
  // Country options come from the server-computed Master Pool catalog.
  // Never derive them from the currently loaded/paginated node rows.
  const catalog = countryCatalogData || { countries: {} };
  const countMap = {};
  Object.entries(catalog.countries || {}).forEach(([rawCountry, item]) => {
    const country = translateCountry(rawCountry) || rawCountry;
    const count = Number(item?.ip_count || 0);
    if (country) countMap[country] = Math.max(Number(countMap[country] || 0), count);
  });
  const countries = Object.keys(countMap).sort((a,b) => {
    const diff = countMap[b] - countMap[a];
    return diff !== 0 ? diff : a.localeCompare(b, "zh-CN");
  });
  let html = '<option value="">请选择优先国家...</option>';
  countries.forEach(c => {
    html += `<option value="${esc(c)}">${esc(c)} ${countMap[c]}</option>`;
  });
  select.innerHTML = html;
  if (state) {
    select.value = state.force_country ? translateCountry(state.force_country) : "";
  }
  syncUnifiedSelect("net_force_country");
}


let certificatePollInterval = null;
let redirectToConfiguredDomainAfterCert = false;

function redirectToConfiguredDomain() {
  const domain = String(state?.web_domain || state?.web_certificate?.domain || "").trim();
  if (!domain) return false;
  const currentHost = String(window.location.hostname || "").trim().toLowerCase();
  if (currentHost === domain.toLowerCase()) return false;
  const suffix = String(state?.secret_path || "Admin").replace(/^\/+|\/+$/g, "");
  const target = `https://${domain}:8443/${suffix}/`;
  window.location.replace(target);
  return true;
}

function renderCertificateStatus(certState) {
  const el = $("cred_cert_status");
  const accessEl = $("cred_access_url");
  if (!el) return;
  const cert = certState || state?.web_certificate || {};
  const status = String(cert.status || "not_configured");
  const domain = String(cert.domain || state?.web_domain || "");
  const message = String(cert.message || "");
  const error = String(cert.last_error || "");
  const expiresAt = Number(cert.expires_at || 0);

  let badgeText = "未启用";
  let badgeBg = "rgba(148,163,184,.12)";
  let badgeColor = "var(--text-secondary)";
  let detail = message || "填写域名后自动申请 HTTPS 证书。";

  if (status === "issuing" || status === "installing" || status === "running") {
    badgeText = status === "installing" ? "安装中" : "申请中";
    badgeBg = "rgba(245,158,11,.14)";
    badgeColor = "#f59e0b";
    detail = message || "正在申请 HTTPS 证书，请稍候…";
  } else if (status === "active") {
    badgeText = "已启用";
    badgeBg = "rgba(16,185,129,.14)";
    badgeColor = "var(--success)";
    const expiryText = expiresAt ? new Date(expiresAt * 1000).toLocaleString() : "读取中";
    detail = domain
      ? `HTTPS 已启用：${esc(domain)} · 证书到期：${esc(expiryText)} · 自动续期已开启`
      : "HTTPS 证书已启用。";
  } else if (status === "error" || status === "interrupted") {
    badgeText = status === "interrupted" ? "任务中断" : "申请失败";
    badgeBg = "rgba(244,63,94,.12)";
    badgeColor = "var(--danger)";
    detail = error || message || "HTTPS 证书申请失败，请检查域名解析及 80 端口。";
  }

  el.innerHTML = `<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
    <span style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;background:${badgeBg};color:${badgeColor};font-weight:600;">${esc(badgeText)}</span>
    <span>${esc(detail)}</span>
  </div>`;

  if (accessEl) {
    const secretPath = String(state?.secret_path || "Admin").replace(/^\/+|\/+$/g, "");
    const preferredHost = domain || String(window.location.hostname || "").trim() || "服务器IP";
    const preferredUrl = `https://${preferredHost}:8443/${secretPath}/`;
    accessEl.innerHTML = `<div style="display:flex;flex-direction:column;gap:4px;">
      <span style="color:var(--text-secondary);">推荐访问地址</span>
      <a href="${esc(preferredUrl)}" target="_blank" rel="noopener noreferrer" style="color:var(--primary);font-weight:650;text-decoration:none;overflow-wrap:anywhere;">${esc(preferredUrl)}</a>
      <span style="font-size:11px;">${domain ? "已绑定域名，优先使用域名访问；IP 仍可作为回退入口。" : "未绑定域名，使用服务器 IP 通过 HTTPS:8443 访问。"}</span>
    </div>`;
  }
}

async function startCertificatePolling() {
  if (certificatePollInterval) clearInterval(certificatePollInterval);
  const poll = async () => {
    try {
      const data = await fetchJsonWithTimeout("./api/certificate_status", {}, 5000);
      if (data.certificate) {
        state.web_certificate = data.certificate;
        state.web_domain = data.certificate.domain || state.web_domain || "";
        renderCertificateStatus(data.certificate);
        if (
          redirectToConfiguredDomainAfterCert &&
          String(data.certificate.status || "") === "active"
        ) {
          redirectToConfiguredDomainAfterCert = false;
          if (redirectToConfiguredDomain()) return;
        }
        const done = !data.certificate.running && ["active", "error", "not_configured", "interrupted"].includes(String(data.certificate.status || ""));
        if (done && certificatePollInterval) {
          clearInterval(certificatePollInterval);
          certificatePollInterval = null;
        }
      }
    } catch (err) {
      console.warn("HTTPS 证书状态读取失败，继续等待下一次状态更新", err);
    }
  };
  await poll();
  certificatePollInterval = setInterval(poll, 1500);
}

function openCredentialsModal() {
  $("credentials_error").style.display = "none";
  $("credentials_success").style.display = "none";
  $("credentials_form").reset();
  if (state) {
    $("cred_username").value = state.username || "";
    $("cred_password").value = "";
    $("cred_port").value = 8443;
    $("cred_suffix").value = state.secret_path || "";
    $("cred_domain").value = state.web_domain || state.web_certificate?.domain || "";
  }
  renderCertificateStatus(state?.web_certificate || {});
  $("credentials_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeCredentialsModal() {
  $("credentials_modal").style.display = "none";
}

async function saveCredentials(e) {
  e.preventDefault();
  const errorDivEl = $("credentials_error");
  const successDiv = $("credentials_success");
  const submitBtn = $("credentials_submit_btn");

  errorDivEl.style.display = "none";
  successDiv.style.display = "none";

  const username = $("cred_username").value.trim();
  const password = $("cred_password").value.trim();
  const port = parseInt($("cred_port").value);
  const suffix = $("cred_suffix").value.trim();
  const domain = $("cred_domain").value.trim();

  if (!username || (!password && !(state && state.password_set))) {
    errorDivEl.textContent = "用户名不能为空；首次设置时密码不能为空";
    errorDivEl.style.display = "block";
    return;
  }

  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "网页管理端口范围必须在 1 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }

  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "登录安全后缀仅能由英文字母和数字组成";
    errorDivEl.style.display = "block";
    return;
  }

  if (domain && !/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(domain.replace(/\.$/, ""))) {
    errorDivEl.textContent = "域名格式不正确，请填写完整域名，例如 vpn.example.com";
    errorDivEl.style.display = "block";
    return;
  }

  if (state && port === state.proxy_port) {
    errorDivEl.textContent = "网页管理端口不能与代理出站端口相同";
    errorDivEl.style.display = "block";
    return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";

  try {
    const res = await fetch("./api/update_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: username,
        password: password,
        port: port,
        secret_path: suffix,
        domain: domain
      })
    });

    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.certificate) {
        state.web_certificate = data.certificate;
        state.web_domain = data.certificate.domain || domain;
        renderCertificateStatus(data.certificate);
      }
      if (data.restart_needed) {
        successDiv.textContent = data.certificate?.status === "issuing"
          ? "保存成功，网页安全配置将在 4 秒内重启；证书申请会在重启后继续。"
          : "保存成功！网页管理端口或路径已变更，页面将在 4 秒内自动跳转...";
        successDiv.style.display = "block";

        const inputs = $("credentials_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);

        setTimeout(() => {
          const protocol = "https:";
          const currentHost = window.location.hostname;
          const preferredHost = domain || currentHost;
          window.location.href = `${protocol}//${preferredHost}:${port}/${suffix}/`;
        }, 4000);
      } else {
        const certStatus = String(data.certificate?.status || "");
        const configuredDomain = String(domain || data.certificate?.domain || "").trim();
        const onConfiguredDomain = configuredDomain && String(window.location.hostname || "").trim().toLowerCase() === configuredDomain.toLowerCase();
        if (configuredDomain && !onConfiguredDomain && certStatus === "active") {
          successDiv.textContent = "HTTPS 证书已启用，正在切换到域名访问…";
          successDiv.style.display = "block";
          setTimeout(() => redirectToConfiguredDomain(), 500);
          return;
        }
        const certBusy = ["issuing", "installing"].includes(certStatus);
        if (certBusy) {
          redirectToConfiguredDomainAfterCert = !!configuredDomain && !onConfiguredDomain;
          successDiv.textContent = data.reauth_required
            ? "账号密码保存成功，HTTPS 证书正在后台申请；完成后会自动更新状态。"
            : "保存成功，HTTPS 证书正在后台申请；完成后会自动更新状态。";
          successDiv.style.display = "block";
          submitBtn.disabled = false;
          submitBtn.textContent = "保存修改";
          startCertificatePolling();
        } else {
          successDiv.textContent = data.reauth_required ? "账号密码保存成功，请重新登录..." : "账号密码保存成功，已即时生效！";
          successDiv.style.display = "block";
          setTimeout(() => {
            if (data.reauth_required) {
              window.location.reload();
            } else {
              closeCredentialsModal();
              load();
            }
          }, 1500);
        }
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}

function openNetworkModal() {
  $("network_error").style.display = "none";
  $("network_success").style.display = "none";
  $("network_form").reset();

  if (state) {
    $("net_proxy_port").value = 8500;
    const mode = state.routing_mode || "auto";
    const ipType = state.routing_ip_type || "all";

    selectOptionCard('routing_mode', mode);
    selectOptionCard('routing_ip_type', ipType);
    const upstreamEl = $("net_upstream_proxy_state");
    if (upstreamEl) upstreamEl.textContent = state.upstream_proxy_label || "系统默认网络（未设置自定义上游代理）";
  }

  populateRoutingCountries();
  syncUnifiedSelect("net_force_country");
  $("network_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeNetworkModal() {
  $("network_modal").style.display = "none";
}

async function saveNetwork(e) {
  e.preventDefault();
  const errorDivEl = $("network_error");
  const successDiv = $("network_success");
  const submitBtn = $("network_submit_btn");

  errorDivEl.style.display = "none";
  successDiv.style.display = "none";

  const proxyPort = parseInt($("net_proxy_port").value);
  const routingMode = $("net_routing_mode").value;
  const forceCountry = $("net_force_country").value;
  const routingIpType = $("net_routing_ip_type").value;

  if (isNaN(proxyPort) || proxyPort < 1024 || proxyPort > 65535) {
    errorDivEl.textContent = "代理出站端口范围必须在 1024 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }

  if (state && proxyPort === state.port) {
    errorDivEl.textContent = "代理出站端口不能与网页管理端口相同";
    errorDivEl.style.display = "block";
    return;
  }

  if (routingMode === "fixed_region" && !forceCountry) {
    errorDivEl.textContent = "请选择一个要锁定的目标国家";
    errorDivEl.style.display = "block";
    return;
  }
  if (routingMode === "fixed_ip" && !(state && (state.active_openvpn_node_id || state.fixed_node_id))) {
    errorDivEl.textContent = "启用固定 IP 前，请先连接一个要锁定的节点";
    errorDivEl.style.display = "block";
    return;
  }

  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";

  try {
    const res = await fetch("./api/update_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        proxy_port: proxyPort,
        routing_mode: routingMode,
        force_country: forceCountry,
        routing_ip_type: routingIpType
      })
    });

    const data = await res.json();
    if (res.ok && data.ok) {
      if (data.restart_needed) {
        successDiv.textContent = "保存成功！代理出站端口已变更，页面将在 4 秒内自动刷新...";
        successDiv.style.display = "block";

        const inputs = $("network_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);

        setTimeout(() => {
          window.location.reload();
        }, 4000);
      } else {
        successDiv.textContent = "配置保存成功，已即时生效！";
        successDiv.style.display = "block";
        setTimeout(() => {
          closeNetworkModal();
          load();
        }, 1500);
      }
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}



function openVpsModal() {
  $("vps_recommend_modal").style.display = "flex";
}

function closeVpsModal() {
  $("vps_recommend_modal").style.display = "none";
}

$("vps_recommend_modal").addEventListener("click", (event) => {
  if (event.target === event.currentTarget) closeVpsModal();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeVpsModal();
});

async function logoutAdmin() {
  try {
    const res = await fetch("./api/logout", { method: "POST" });
    if (res.ok) {
      window.location.reload();
    }
  } catch (err) {
    console.error("退出登录失败", err);
    window.location.reload();
  }
}

// 先把页面骨架、筛选栏和状态区域立即渲染出来；节点数据随后异步读取，
// 避免首页被数千条节点数据阻塞在白屏/半屏状态。
render();
load();

// 每 10 秒在前台空闲时自动更新节点与状态，无需手动刷新页面
setInterval(async () => {
  if (typeof state !== "undefined" && !state.is_connecting && (!testingNodeIds || !testingNodeIds.size) && document.visibilityState === "visible") {
    try {
      const pageOffset = Math.max(0, (currentPage - 1) * pageSize);
      const [d, stateData] = await Promise.all([
        fetchScopedNodePage(pageOffset, pageSize, 8000),
        fetchUiStateOnly(4000)
      ]);
      if (Array.isArray(d?.nodes)) {
        nodes = [];
        mergeLoadedNodePage(d.nodes);
      }
      if (d?.total != null) totalNodeCount = Number(d.total || 0);
      if (d?.cache_building != null) nodeCacheBuilding = !!d.cache_building;
      if (stateData?.state) state = stateData.state;
      stableSortNodes();
      updateCountryFilter();
      render();
    } catch(e) {}
  }
}, 10000);
let gatewayPollInterval = null;

function openGatewayModal() {
  $("admin_dropdown").style.display = "none";
  $("gateway_modal").style.display = "flex";
  loadGatewayStatus();
  if (gatewayPollInterval) clearInterval(gatewayPollInterval);
  gatewayPollInterval = setInterval(loadGatewayStatus, 3000);
}

function closeGatewayModal() {
  $("gateway_modal").style.display = "none";
  if (gatewayPollInterval) {
    clearInterval(gatewayPollInterval);
    gatewayPollInterval = null;
  }
}

async function loadGatewayStatus() {
  try {
    const res = await fetch("./api/gateway_status");
    const data = await res.json();
    if (data.ok && data.services) {
      renderGatewayServices(data.services);
    }
  } catch (e) {
    console.error("加载网关状态失败", e);
  }
}

function renderGatewayServices(services) {
  const container = $("gateway_services_list");
  if (!container) return;

  let html = "";
  services.forEach(s => {
    const statusText = s.status === "running" ? "正在运行" : "已停止";
    const badgeClass = s.status === "running" ? "available" : "unavailable";
    const statusPulse = s.status === "running" ? '<span class="badge-pulse"></span>' : '';

    html += `
      <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 10px; padding: 12px 16px; display: flex; flex-direction: column; gap: 6px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="font-size: 14px; color: var(--text-primary);">${esc(s.name)}</strong>
          <span class="badge ${badgeClass}">${statusPulse}${statusText}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-secondary);">${esc(s.details || "-")}</div>
        ${s.error ? `
          <div style="font-size: 12px; color: var(--danger); background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.15); border-radius: 6px; padding: 6px 10px; margin-top: 4px; line-height: 1.4;">
            ⚠️ 诊断原因: ${esc(s.error)}
          </div>
        ` : ''}
      </div>
    `;
  });
  container.innerHTML = html;
}

async function resourceShareAdminPost(action, payload={}) {
  return fetchJsonWithTimeout("./api/resource_share/" + action, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify(payload)
  }, 15000);
}

function resourceShareTime(ts) {
  if (!ts) return "从未";
  try { return new Date(Number(ts) * 1000).toLocaleString(); } catch (_) { return "—"; }
}

function resourceShareStatusText(peer) {
  if (!peer.enabled) return "已暂停";
  if (peer.last_sync_ok === true) return "正常";
  if (peer.last_sync_ok === false) return "同步失败";
  return "待同步";
}

function refreshResourceShareModeUI() {
  const mode = $("rs_sync_mode")?.value || "pull";
  const modeHint = $("rs_mode_hint");
  if (modeHint) modeHint.textContent = mode === "bidirectional"
    ? "双向共享：对方会拉取本机资源，本机也会拉取对方资源。邀请码中的允许 IP 控制谁能访问本机。"
    : "仅拉取：本机只从对方资源库获取节点，不开放本机资源给对方拉取，因此不需要填写允许 IP。";
}

function openResourceShareModal() {
  const dropdown = $("admin_dropdown");
  if (dropdown) dropdown.style.display = "none";
  const modal = $("resource_share_modal");
  if (modal) modal.style.display = "flex";
  syncUnifiedSelect("rs_sync_interval_unit");
  loadResourceShareStatus();
}

function closeResourceShareModal() {
  const modal = $("resource_share_modal");
  if (modal) modal.style.display = "none";
}

async function loadResourceShareStatus() {
  try {
    const data = await fetchJsonWithTimeout("./api/resource_share/status", {}, 10000);
    if (!data.ok) throw new Error(data.error || "加载失败");
    if ($("rs_local_url")) {
      $("rs_local_url").value = data.local_url || (window.location.origin + "/resource-share");
    }
    renderResourceShareInvites(data.invites || []);
    renderResourceShareRelationships(data.relationships || []);
  } catch (err) {
    const inviteBox = $("rs_invite_list");
    const peerBox = $("rs_peer_list");
    const html = '<div class="rs-empty" style="color:var(--danger);">资源共享状态加载失败：' + esc(err.message || err) + '</div>';
    if (inviteBox) inviteBox.innerHTML = html;
    if (peerBox) peerBox.innerHTML = html;
  }
}

function renderResourceShareInvites(invites) {
  const box = $("rs_invite_list");
  const count = $("rs_invite_count");
  if (count) count.textContent = invites.length;
  if (!box) return;
  if (!invites.length) {
    box.innerHTML = '<div class="rs-empty">暂无邀请码。创建第一个长期邀请码后，会一直显示在这里。</div>';
    return;
  }
  box.innerHTML = invites.map(function(invite) {
    const code = String(invite.invite_code || "");
    const linked = Number(invite.linked_peer_count || 0);
    const scope = Array.isArray(invite.allowed_cidrs) ? invite.allowed_cidrs.join(", ") : "—";
    const legacy = invite.legacy_code_unavailable || !code;
    return '<div class="rs-invite-item">' +
      '<div class="rs-item-head">' +
        '<div class="rs-item-main">' +
          '<div class="rs-item-name">' +
            esc(invite.peer_name || "共享服务器") +
            '<span class="rs-direction">长期邀请码</span>' +
            (linked ? '<span class="rs-direction bidir">已关联 ' + linked + ' 台</span>' : '') +
          '</div>' +
          (legacy
            ? '<div class="rs-item-meta" style="color:var(--warning);">历史邀请码未保存明文，不能在页面恢复显示；可以重新创建一个长期邀请码。</div>'
            : '<div class="rs-item-code">' + esc(code) + '</div>') +
          '<div class="rs-item-meta">允许来源：' + esc(scope) + ' · 创建时间：' + esc(resourceShareTime(invite.created_at)) + ' · 有效期：永不过期' + (invite.revoked ? ' · <span style="color:var(--danger);">已撤销</span>' : '') + '</div>' +
          (invite.revoked ? '<div class="rs-item-meta" style="color:var(--text-secondary);">此邀请码已停止授权。删除后将不再保留该邀请码记录。</div>' : '') +
        '</div>' +
        '<div class="rs-item-actions">' +
          (!legacy ? '<button class="test-btn" onclick="copyResourceShareCode(\'' + esc(code) + '\')">复制</button>' : '') +
          (!invite.revoked ? '<button class="test-btn" onclick="editResourceInvite(\'' + esc(invite.invite_id) + '\')">修改</button>' : '') +
          (!invite.revoked ? '<button class="test-btn" style="color:var(--danger);border-color:rgba(244,63,94,.3);" onclick="revokeResourceInvite(\'' + esc(invite.invite_id) + '\')">撤销</button>' : '<button class="test-btn" disabled>已撤销</button>') +
          (invite.revoked ? '<button class="test-btn" style="color:var(--danger);border-color:rgba(244,63,94,.3);" onclick="deleteResourceInvite(\'' + esc(invite.invite_id) + '\')">删除</button>' : '') +
        '</div>' +
      '</div>' +
    '</div>';
  }).join("");
}

function renderResourceShareRelationships(relations) {
  const box = $("rs_peer_list");
  const count = $("rs_peer_count");
  if (count) count.textContent = relations.length;
  if (!box) return;
  if (!relations.length) {
    box.innerHTML = '<div class="rs-empty">暂无已建立共享服务器。给对方邀请码，或填写对方给你的邀请码后，这里会自动形成关系卡。</div>';
    return;
  }
  box.innerHTML = relations.map(function(relation) {
    const bidir = relation.direction === "双向共享";
    const status = relation.sync_status || "未建立主动拉取";
    const statusColor = relation.last_sync_error ? "var(--danger)" : (relation.last_sync_at ? "var(--success)" : "var(--warning)");
    const intervalText = relation.sync_interval_seconds
      ? ((relation.sync_interval_value || 6) + " " + (relation.sync_interval_unit === "days" ? "天" : relation.sync_interval_unit === "weeks" ? "周" : "小时"))
      : "—";
    const allowed = Array.isArray(relation.allowed_cidrs) && relation.allowed_cidrs.length ? relation.allowed_cidrs.join(", ") : "本机未开放白名单";
    const nextText = relation.next_sync_at ? resourceShareTime(relation.next_sync_at) : (relation.outbound_peer_id ? "待同步" : "无本机主动拉取");
    const localInvite = relation.local_invite_code || "—";
    const remoteInvite = relation.remote_invite_code || "—";
    const syncBtn = relation.outbound_peer_id
      ? '<button class="test-btn" onclick="syncResourcePeer(\'' + esc(relation.outbound_peer_id) + '\')">同步</button>'
      : '';
    return '<div class="rs-relation-item">' +
      '<div class="rs-item-head">' +
        '<div class="rs-item-main">' +
          '<div class="rs-item-name">' +
            esc(relation.name || "共享服务器") +
            '<span class="rs-direction ' + (bidir ? 'bidir' : '') + '">' + esc(relation.direction || "单向共享") + '</span>' +
            '<span style="font-size:11px;color:' + statusColor + ';">' + esc(status) + '</span>' +
          '</div>' +
          '<div class="rs-item-meta">服务器 IP：<strong>' + esc(relation.remote_ip || "—") + '</strong>' +
            (relation.remote_url ? ' · 地址：' + esc(relation.remote_url) : '') +
          '</div>' +
          '<div class="rs-item-meta">本机邀请码：' + esc(localInvite) + ' · 对方邀请码：' + esc(remoteInvite) + '</div>' +
          '<div class="rs-item-meta">本机允许来源：' + esc(allowed) + ' · 自动同步：' + esc(intervalText) + ' · 下次同步：' + esc(nextText) + '</div>' +
          (relation.last_sync_error ? '<div class="rs-item-meta" style="color:var(--danger);">最近错误：' + esc(relation.last_sync_error) + '</div>' : '') +
        '</div>' +
        '<div class="rs-item-actions">' +
          syncBtn +
          '<button class="test-btn" onclick="editResourceRelationship(\'' + esc(relation.relation_id) + '\')">修改</button>' +
          '<button class="test-btn" style="color:var(--danger);border-color:rgba(244,63,94,.3);" onclick="deleteResourceRelationship(' + JSON.stringify(relation.peer_ids || []) + ')">删除</button>' +
        '</div>' +
      '</div>' +
    '</div>';
  }).join("");
}

let currentResourceInviteId = "";


function copyResourceShareCode(code) {
  const value = String(code || "");
  if (!value) return;
  navigator.clipboard?.writeText(value).then(
    () => alert("邀请码已复制。"),
    () => alert("复制失败，请手动复制邀请码。")
  );
}

async function generateResourceInvite() {
  const btn = $("rs_generate_btn");
  const peerName = ($("rs_invite_peer_name")?.value || "").trim();
  const cidrs = ($("rs_invite_allowed_cidrs")?.value || "").trim();
  if (!cidrs) {
    alert("请填写允许 IP/CIDR，例如 1.2.3.4/32；全部 IPv4 可填写 0.0.0.0/0。");
    return;
  }
  try {
    if (btn) { btn.disabled = true; btn.textContent = "正在创建..."; }
    const data = await resourceShareAdminPost("invite", {
      peer_name: peerName,
      allowed_cidrs: cidrs
    });
    if ($("rs_invite_peer_name")) $("rs_invite_peer_name").value = "";
    if ($("rs_invite_allowed_cidrs")) $("rs_invite_allowed_cidrs").value = "";
    await loadResourceShareStatus();
    alert("邀请码已创建并保存为长期邀请码：\n\n" + (data.invite_code || "—"));
  } catch (err) {
    alert("创建邀请码失败：\n" + (err.message || err));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "生成邀请码"; }
  }
}

let resourceShareEditContext = null;

async function openResourceShareEditModal(type, id) {
  try {
    const res = await fetch("./api/resource_share/status", {
      credentials: "same-origin",
      cache: "no-store"
    });
    const data = await res.json();
    if (!res.ok || data.ok === false) throw new Error(data.error || "加载共享配置失败");

    let payload = null;
    if (type === "invite") {
      payload = (data.invites || []).find(item => item.invite_id === id);
      if (!payload) throw new Error("邀请码不存在");
      if (payload.legacy_code_unavailable) {
        throw new Error("这个历史邀请码没有保存明文，请创建一个新的长期邀请码。");
      }
    } else {
      payload = (data.relationships || []).find(item => item.relation_id === id);
      if (!payload) throw new Error("共享关系不存在");
    }

    resourceShareEditContext = { type, id, payload };

    $("rs_edit_type").value = type;
    $("rs_edit_id").value = id;
    $("rs_edit_title").textContent = type === "invite" ? "修改邀请码" : "修改共享服务器";
    $("rs_edit_help").textContent = type === "invite"
      ? "修改服务器名称或允许来源 IP/CIDR。修改后立即生效。"
      : "一次修改对方地址、邀请码、同步周期和本机允许来源。保存后立即生效。";

    $("rs_edit_name").value = payload.peer_name || payload.name || "共享服务器";
    $("rs_edit_local_scope").value = Array.isArray(payload.allowed_cidrs) ? payload.allowed_cidrs.join(", ") : "";
    $("rs_edit_remote_url").value = payload.remote_ip || payload.remote_url || "";
    $("rs_edit_remote_invite").value = payload.remote_invite_code || "";
    $("rs_edit_sync_value").value = Number(payload.sync_interval_value || 6);
    $("rs_edit_sync_unit").value = payload.sync_interval_unit || "hours";
    syncUnifiedSelect("rs_edit_sync_unit");

    const isInvite = type === "invite";
    const hasOutbound = !isInvite && !!payload.outbound_peer_id;
    $("rs_edit_local_scope_row").style.display = (isInvite || !!payload.inbound_peer_id) ? "grid" : "none";
    $("rs_edit_remote_row").style.display = hasOutbound ? "grid" : "none";
    $("rs_edit_sync_row").style.display = hasOutbound ? "grid" : "none";
    $("rs_edit_local_scope").disabled = false;
    $("rs_edit_remote_url").disabled = false;
    $("rs_edit_remote_invite").disabled = false;
    $("rs_edit_sync_value").disabled = false;
    $("rs_edit_sync_unit").disabled = false;

    $("rs_edit_error").style.display = "none";
    $("rs_edit_error").textContent = "";
    $("rs_edit_submit").disabled = false;
    $("rs_edit_submit").textContent = "保存修改";
    $("resource_share_edit_modal").style.display = "flex";
  } catch (err) {
    alert("打开修改界面失败：\n" + (err.message || err));
  }
}

function closeResourceShareEditModal() {
  $("resource_share_edit_modal").style.display = "none";
  resourceShareEditContext = null;
}

async function submitResourceShareEdit(event) {
  event.preventDefault();
  const context = resourceShareEditContext;
  const submit = $("rs_edit_submit");
  const errorBox = $("rs_edit_error");
  if (!context) return;

  const name = ($("rs_edit_name").value || "").trim();
  const localScope = ($("rs_edit_local_scope").value || "").trim();
  const remoteUrl = normalizeResourceRemoteInput($("rs_edit_remote_url").value);
  const remoteInvite = ($("rs_edit_remote_invite").value || "").trim();
  const syncValue = Math.max(1, Number($("rs_edit_sync_value").value || 6));
  const syncUnit = $("rs_edit_sync_unit").value || "hours";

  errorBox.style.display = "none";
  submit.disabled = true;
  submit.textContent = "正在保存...";

  try {
    if (context.type === "invite") {
      await resourceShareAdminPost("update_invite", {
        invite_id: context.id,
        peer_name: name,
        allowed_cidrs: localScope
      });
    } else {
      const relation = context.payload;
      if (relation.outbound_peer_id) {
        if (!remoteUrl || !remoteInvite) {
          throw new Error("双向/主动拉取关系必须填写对方服务器地址和邀请码。");
        }
        await resourceShareAdminPost("rebind", {
          peer_id: relation.outbound_peer_id,
          remote_url: remoteUrl,
          invite_code: remoteInvite,
          name: name,
          sync_interval_value: syncValue,
          sync_interval_unit: syncUnit
        });
      }
      if (relation.local_invite_id) {
        if (!localScope) throw new Error("本机允许来源 IP/CIDR 不能为空。");
        await resourceShareAdminPost("update_invite", {
          invite_id: relation.local_invite_id,
          peer_name: name,
          allowed_cidrs: localScope
        });
      } else if (!relation.outbound_peer_id) {
        await resourceShareAdminPost("update", {
          peer_id: relation.inbound_peer_id,
          name: name
        });
      }
    }

    closeResourceShareEditModal();
    await loadResourceShareStatus();
  } catch (err) {
    errorBox.textContent = err.message || String(err);
    errorBox.style.display = "block";
    submit.disabled = false;
    submit.textContent = "保存修改";
  }
}

function editResourceInvite(inviteId) {
  openResourceShareEditModal("invite", inviteId);
}

async function revokeResourceInvite(inviteId) {
  if (!inviteId) return;
  if (!confirm("确定撤销这个长期邀请码？撤销后关联服务器将不能继续拉取本机资源，但记录会保留，可稍后永久删除。")) return;
  try {
    await resourceShareAdminPost("revoke_invite", { invite_id: inviteId });
    await loadResourceShareStatus();
  } catch (err) {
    if (String(err.message || "").toLowerCase().includes("unauthorized")) {
      alert("管理员会话已失效，请刷新页面后重新登录，再执行撤销。");
    } else {
      alert("撤销邀请码失败：\n" + (err.message || err));
    }
  }
}

async function deleteResourceInvite(inviteId) {
  if (!inviteId) return;
  if (!confirm("确定永久删除这个已撤销的邀请码？删除后邀请码记录和对应入站共享记录都将消失，无法恢复。")) return;
  try {
    await resourceShareAdminPost("delete_invite", { invite_id: inviteId });
    await loadResourceShareStatus();
  } catch (err) {
    alert("永久删除邀请码失败：\n" + (err.message || err));
  }
}

function normalizeResourceRemoteInput(value) {
  let raw = String(value || "").trim();
  if (!raw) return "";
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = "https://" + raw;
  try {
    const parsed = new URL(raw);
    if (!parsed.port) parsed.port = "8443";
    if (!parsed.pathname || parsed.pathname === "/") parsed.pathname = "/resource-share";
    return parsed.toString().replace(/\/$/, "");
  } catch (_) {
    return raw;
  }
}

async function joinResourcePeer() {
  const btn = $("rs_join_btn");
  const remoteUrl = normalizeResourceRemoteInput($("rs_remote_url")?.value);
  const invite = ($("rs_invite_input")?.value || "").trim();
  const intervalValue = Math.max(1, Number($("rs_sync_interval_value")?.value || 6));
  const intervalUnit = $("rs_sync_interval_unit")?.value || "hours";
  if (!remoteUrl || !invite) {
    alert("请填写对方服务器 IP/域名和邀请码。");
    return;
  }
  try {
    if (btn) { btn.disabled = true; btn.textContent = "正在添加..."; }
    const data = await resourceShareAdminPost("join", {
      remote_url: remoteUrl,
      invite_code: invite,
      sync_interval_value: intervalValue,
      sync_interval_unit: intervalUnit
    });
    const first = data.first_sync || {};
    if ($("rs_remote_url")) $("rs_remote_url").value = "";
    if ($("rs_invite_input")) $("rs_invite_input").value = "";
    await loadResourceShareStatus();
    await load();
    if (first.ok) {
      alert("共享服务器已添加，首次同步成功，导入 " + Number(first.imported || first.received || 0) + " 条资源。");
    } else {
      alert("共享服务器已建立，但首次同步失败：\n" + (first.error || "远端暂不可用") + "\n稍后可在“已建立共享服务器”中重新同步。");
    }
  } catch (err) {
    alert("添加共享服务器失败：\n" + (err.message || err));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "添加并立即同步"; }
  }
}

function editResourceRelationship(relationId) {
  openResourceShareEditModal("relationship", relationId);
}

async function deleteResourceRelationship(peerIds) {
  const ids = Array.isArray(peerIds) ? peerIds.filter(Boolean) : [String(peerIds || "")].filter(Boolean);
  if (!ids.length) return;
  if (!confirm("确定删除这个共享服务器关系？\n删除后不会删除已经由本机验证通过的节点。")) return;
  try {
    await resourceShareAdminPost("delete_relationship", { peer_ids: ids });
    await loadResourceShareStatus();
    await load();
  } catch (err) {
    alert("删除共享关系失败：\n" + (err.message || err));
  }
}

async function generateResourceInviteLegacy() {
  const btn = $("rs_generate_btn");
  const peerName = ($("rs_invite_peer_name").value || "").trim();
  const cidrs = ($("rs_invite_allowed_cidrs").value || "").trim();
  if (!cidrs) {
    alert("请填写允许 IP/CIDR。单个 IPv4 地址建议写成 1.2.3.4/32；全部 IPv4 可写 0.0.0.0/0。");
    return;
  }
  try {
    if (btn) { btn.disabled = true; btn.textContent = "正在生成..."; }
    const data = await resourceShareAdminPost("invite", {
      ttl_seconds: 1800,
      peer_name: peerName,
      allowed_cidrs: cidrs
    });
    currentResourceInviteId = data.invite_id || "";
    $("rs_invite_code").textContent = data.invite_code || "";
    $("rs_invite_scope").textContent = "服务器：" + (data.peer_name || peerName || "共享服务器") + " · 允许来源：" + (data.allowed_cidrs || []).join(", ");
    $("rs_invite_expiry").textContent = "有效期至：" + resourceShareTime(data.expires_at);
    $("rs_invite_box").style.display = "block";
  } catch (err) {
    alert("生成邀请码失败：\n" + (err.message || err));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "生成邀请码"; }
  }
}

async function revokeCurrentResourceInviteLegacy() {
  if (!currentResourceInviteId) {
    alert("当前没有可撤销的邀请码。");
    return;
  }
  if (!confirm("确定撤销当前邀请码？撤销后即使仍在有效期内也不能再使用。")) return;
  try {
    await resourceShareAdminPost("revoke_invite", {invite_id: currentResourceInviteId});
    currentResourceInviteId = "";
    $("rs_invite_box").style.display = "none";
    alert("邀请码已撤销。");
  } catch (err) {
    alert("撤销邀请码失败：\n" + (err.message || err));
  }
}

function normalizeResourceRemoteInput(value) {
  let raw = String(value || "").trim();
  if (!raw) return "";
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = "https://" + raw;
  try {
    const parsed = new URL(raw);
    if (!parsed.port) parsed.port = "8443";
    if (!parsed.pathname || parsed.pathname === "/") parsed.pathname = "/resource-share";
    return parsed.toString().replace(/\/$/, "");
  } catch (_) {
    return raw;
  }
}

async function joinResourcePeerLegacy() {
  const btn = $("rs_join_btn");
  const remoteUrl = normalizeResourceRemoteInput($("rs_remote_url").value);
  const invite = ($("rs_invite_input").value || "").trim();
  const syncMode = $("rs_sync_mode").value || "pull";
  const intervalValue = Number($("rs_sync_interval_value").value || 6);
  const intervalUnit = $("rs_sync_interval_unit").value || "hours";
  if (!remoteUrl || !invite) {
    alert("请填写对方服务器 IP/域名和邀请码。");
    return;
  }
  try {
    if (btn) { btn.disabled = true; btn.textContent = "正在加入并同步..."; }
    const data = await resourceShareAdminPost("join", {
      remote_url: remoteUrl,
      invite_code: invite,
      sync_mode: syncMode,
      sync_interval_value: intervalValue,
      sync_interval_unit: intervalUnit
    });
    const first = data.first_sync || {};
    alert(first.ok
      ? "资源共享已建立，首次同步成功，共导入 " + (first.imported || first.received || 0) + " 条资源。"
      : "资源共享已建立，但首次同步失败：\n" + (first.error || "远端暂不可用") + "\n可以点击“同步”重新尝试。");
    $("rs_invite_input").value = "";
    await loadResourceShareStatus();
    await load();
  } catch (err) {
    alert("加入共享失败：\n" + (err.message || err));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "加入并立即同步"; }
  }
}

async function syncResourcePeer(peerId) {
  try {
    const data = await resourceShareAdminPost("sync", {peer_id: peerId});
    const result = data.result || {};
    alert(result.ok === false ? "同步失败：\n" + (result.error || "未知错误") : "同步完成，导入 " + (result.imported || result.received || 0) + " 条资源。");
    await loadResourceShareStatus();
    await load();
  } catch (err) {
    alert("同步失败：\n" + (err.message || err));
  }
}

async function syncAllResourcePeers() {
  try {
    const data = await resourceShareAdminPost("sync", {});
    const results = Array.isArray(data.result) ? data.result : [];
    const ok = results.filter(function(item) { return item && item.ok; }).length;
    alert("同步完成：成功 " + ok + " / " + results.length + " 个 Peer。");
    await loadResourceShareStatus();
    await load();
  } catch (err) {
    alert("同步失败：\n" + (err.message || err));
  }
}

async function toggleResourcePeer(peerId, enabled) {
  try {
    await resourceShareAdminPost("toggle", {peer_id: peerId, enabled: !!enabled});
    await loadResourceShareStatus();
  } catch (err) {
    alert("修改共享状态失败：\n" + (err.message || err));
  }
}

async function editResourcePeerLegacy(peerId) {
  try {
    const data = await fetchJsonWithTimeout("./api/resource_share/status", {}, 10000);
    const peer = (data.peers || []).find(function(item) { return item.peer_id === peerId; });
    if (!peer) throw new Error("Peer 不存在");
    const name = window.prompt("共享服务器名称", peer.name || "");
    if (name === null) return;
    const cidrs = window.prompt(
      "本机允许对方访问的 IP/CIDR（仅双向共享需要）",
      (peer.allowed_cidrs || []).join(", ")
    );
    if (cidrs === null) return;
    const intervalValue = window.prompt(
      "自动同步周期数值（例如 6 / 1 / 2）",
      String(peer.sync_interval_value || 6)
    );
    if (intervalValue === null) return;
    const intervalUnit = window.prompt(
      "自动同步周期单位：hours / days / weeks",
      String(peer.sync_interval_unit || "hours")
    );
    if (intervalUnit === null) return;
    await resourceShareAdminPost("update", {
      peer_id: peerId,
      name: name,
      allowed_cidrs: cidrs,
      sync_interval_value: Number(intervalValue),
      sync_interval_unit: String(intervalUnit).toLowerCase()
    });
    await loadResourceShareStatus();
  } catch (err) {
    alert("更新 Peer 失败：\n" + (err.message || err));
  }
}

async function deleteResourcePeer(peerId) {
  if (!confirm("确定删除这个资源共享 Peer？\n仅会清理该 Peer 独占且未本地验证的共享资源。")) return;
  try {
    await resourceShareAdminPost("delete", {peer_id: peerId});
    await loadResourceShareStatus();
    await load();
  } catch (err) {
    alert("删除 Peer 失败：\n" + (err.message || err));
  }
}

function copyResourceShareUrl() {
  const value = $("rs_local_url")?.value || "";
  if (!value) return;
  navigator.clipboard?.writeText(value).then(
    ()=>alert("资源接口地址已复制。"),
    ()=>alert("复制失败，请手动复制。")
  );
}

async function clearTodayLogs() {
  if (!confirm("确定清空今天的运行日志？历史节点数据库和共享资源不会受到影响。")) return;
  try {
    const response = await fetch("./api/logs/manage", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({action:"clear_today"})
    });
    const data = await response.json();
    if (!response.ok || data.ok === false) throw new Error(data.error || "清空失败");
    await loadLogs();
    alert("今日运行日志已清空。");
  } catch (err) {
    alert("清空日志失败：\n" + (err.message || err));
  }
}

async function cleanupOldLogs() {
  if (!confirm("确定清理旧日志？仅清理 3 天前的日志文件。")) return;
  try {
    const response = await fetch("./api/logs/manage", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({action:"cleanup_old"})
    });
    const data = await response.json();
    if (!response.ok || data.ok === false) throw new Error(data.error || "清理失败");
    await loadLogs();
    alert(data.message || "旧日志清理完成。");
  } catch (err) {
    alert("清理旧日志失败：\n" + (err.message || err));
  }
}

let logsPollInterval = null;
let rawLogsCache = [];

function openLogsModal() {
  $("admin_dropdown").style.display = "none";
  syncUnifiedSelect("log_filter_select");
  $("logs_modal").style.display = "flex";
  loadLogs();
  if (logsPollInterval) clearInterval(logsPollInterval);
  logsPollInterval = setInterval(loadLogs, 5000);
}

function closeLogsModal() {
  $("logs_modal").style.display = "none";
  if (logsPollInterval) {
    clearInterval(logsPollInterval);
    logsPollInterval = null;
  }
}

async function loadLogs() {
  try {
    const res = await fetch("./api/logs");
    const data = await res.json();
    if (data.logs) {
      rawLogsCache = data.logs;
      filterAndRenderLogs();
    }
  } catch (e) {
    console.error("加载日志失败", e);
  }
}

function filterAndRenderLogs() {
  const filterVal = $("log_filter_select").value;
  const term = $("log_terminal_container");
  if (!term) return;

  let filtered = rawLogsCache;
  if (filterVal === "proxy") {
    filtered = rawLogsCache.filter(l => l.module === "Proxy");
  } else if (filterVal === "vpn") {
    filtered = rawLogsCache.filter(l => l.module === "VPN");
  } else if (filterVal === "system") {
    filtered = rawLogsCache.filter(l => !["Proxy", "VPN"].includes(l.module));
  }

  if (filtered.length === 0) {
    term.innerHTML = `<div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">暂无该类型日志。</div>`;
    return;
  }

  const linesHtml = filtered.map(l => {
    let color = "#a5b4fc";
    if (l.module === "Proxy") color = "#38bdf8";
    if (l.module === "VPN") color = "#34d399";
    if (l.level === "WARNING") color = "#fbbf24";
    if (l.level === "ERROR") color = "#f43f5e";

    return `<div style="color: ${color}; margin-bottom: 4px;">[${esc(l.timestamp)}] [${esc(l.level)}] [${esc(l.module)}] ${esc(l.message)}</div>`;
  }).join("");

  const isAtBottom = term.scrollHeight - term.clientHeight <= term.scrollTop + 50;

  term.innerHTML = linesHtml;

  if (isAtBottom) {
    term.scrollTop = term.scrollHeight;
  }
}

function copyLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;

  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供复制的日志。");
    return;
  }

  navigator.clipboard.writeText(text).then(() => {
    alert("日志内容已成功复制到剪贴板！");
  }).catch(err => {
    console.error("复制失败", err);
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert("日志内容已复制到剪贴板！");
  });
}

function exportLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;

  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供导出的日志。");
    return;
  }

  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const dateStr = new Date().toISOString().slice(0, 10);
  const filterVal = $("log_filter_select").value;
  a.download = `vpngate_log_${filterVal}_${dateStr}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
</script>
</body></html>"""

def local_proxy_port_reachable(timeout: float = 0.4) -> bool:
    host = LOCAL_PROXY_HOST
    candidates: list[tuple[int, str]] = []
    if host in ("::", ""):
        candidates = [(socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")]
    elif host == "0.0.0.0":
        candidates = [(socket.AF_INET, "127.0.0.1")]
    elif ":" in host:
        candidates = [(socket.AF_INET6, host), (socket.AF_INET, "127.0.0.1")]
    else:
        candidates = [(socket.AF_INET, host)]
    for af, target in candidates:
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, LOCAL_PROXY_PORT))
            return True
        except Exception:
            pass
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
    return False

def reserve_link_probe_bytes(client_ip: str, requested: int) -> tuple[bool, int]:
    now = time.time()
    requested = max(0, int(requested))
    with link_probe_lock:
        started, used = link_probe_usage.get(client_ip, (now, 0))
        if now - started >= LINK_PROBE_WINDOW_SECONDS:
            started, used = now, 0
        if used + requested > LINK_PROBE_WINDOW_BYTES:
            retry_after = max(1, int(LINK_PROBE_WINDOW_SECONDS - (now - started)))
            link_probe_usage[client_ip] = (started, used)
            return False, retry_after
        link_probe_usage[client_ip] = (started, used + requested)
        # Opportunistic cleanup so the dict cannot grow forever.
        if len(link_probe_usage) > 2048:
            stale = [ip for ip, (ts, _) in link_probe_usage.items() if now - ts > LINK_PROBE_WINDOW_SECONDS * 2]
            for ip in stale[:1024]:
                link_probe_usage.pop(ip, None)
        return True, 0

def check_proxy_health() -> dict[str, Any]:
    # 1. 检测代理服务端口是否在监听
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(1.5)
        connect_host = LOCAL_PROXY_HOST
        if connect_host in ("::", "0.0.0.0", ""):
            connect_host = "::1" if is_ipv6 else "127.0.0.1"
        try:
            s.connect((connect_host, LOCAL_PROXY_PORT))
        except Exception as e:
            if connect_host == "::1":
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
            else:
                raise e
    except Exception as e:
        diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
        diag_msg = diag[1] if diag else f"端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e}"
        return {
            "ok": False,
            "error": f"代理服务未运行 ({diag_msg})"
        }
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # 2. 检测当前活动 VPN 网卡是否存在，不再写死 tun0。
    active_iface = proxy_server.get_active_interface()
    iface_path = Path("/sys/class/net") / active_iface
    if sys.platform.startswith("linux") and not iface_path.exists():
        return {
            "ok": False,
            "error": f"[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] 当前 VPN 网卡 ({active_iface}) 不存在，请确保隧道已成功建立"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        proxy_hosts = []
        if LOCAL_PROXY_HOST == "::":
            proxy_hosts = ["[::1]", "127.0.0.1"]
        elif LOCAL_PROXY_HOST == "0.0.0.0":
            proxy_hosts = ["127.0.0.1"]
        elif ":" in LOCAL_PROXY_HOST:
            proxy_hosts = [f"[{LOCAL_PROXY_HOST}]", "127.0.0.1"]
        else:
            proxy_hosts = [LOCAL_PROXY_HOST]

        for p_host in proxy_hosts:
            proxy_url = f"socks5h://{p_host}:{LOCAL_PROXY_PORT}"
            proxy_user, proxy_pass = proxy_server.get_proxy_credentials()
            cmd = [
                "curl", "-s",
                "-w", "\n%{time_total} %{http_code}",
                "-x", proxy_url,
                url,
                "--max-time", "5"
            ]
            if proxy_user is not None and proxy_pass is not None:
                cmd.extend(["--proxy-user", f"{proxy_user}:{proxy_pass}"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    lines = res.stdout.strip().splitlines()
                    if len(lines) >= 2:
                        ip = lines[0].strip()
                        time_info = lines[1].strip().split()
                        if len(time_info) == 2:
                            total_time_str, http_code = time_info
                            if http_code == "200" and ip:
                                latency_ms = int(float(total_time_str) * 1000)
                                return {"ok": True, "ip": ip, "latency_ms": latency_ms}
            except Exception:
                pass
        return None

    try:
        result = _curl_check_ip("http://ip.sb")
        if result:
            return result
        result = _curl_check_ip("http://api.ipify.org")
        if result:
            return result

        # 此时外网测试失败，检测本地代理端口是否依然能连通。若仍能连通，直接抛出出口测试失败，不调用占用诊断
        port_still_listening = False
        test_sock = None
        try:
            test_sock = socket.socket(af, socket.SOCK_STREAM)
            test_sock.settimeout(1.0)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                test_sock.connect((connect_host, LOCAL_PROXY_PORT))
                port_still_listening = True
            except Exception:
                if connect_host == "::1":
                    test_sock.close()
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(1.0)
                    test_sock.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                    port_still_listening = True
        except Exception:
            pass
        finally:
            if test_sock is not None:
                try:
                    test_sock.close()
                except Exception:
                    pass

        if not port_still_listening:
            diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
            if diag:
                return {"ok": False, "error": f"出口连接测试失败 | 本机诊断结果: {diag[1]}"}

        return {"ok": False, "error": "出口连接测试失败 (ip.sb 和 api.ipify.org 均无法连通，可能是节点已失效或 VPS 防火墙限制了 UDP/TCP 出站端口)"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}

def handle_confirmed_tunnel_failure(error_msg: str, expected_target: str = "") -> None:
    global is_connecting
    if expected_target:
        current_target = str(active_pool_endpoint_id or active_openvpn_node_id or "")
        if current_target != str(expected_target):
            log_to_json("INFO", "Proxy", f"忽略旧连接迟到故障事件: expected={expected_target}, current={current_target}")
            return
    if manual_connection_active:
        log_to_json("INFO", "VPN", "人工连接操作进行中，忽略自动故障接管")
        return
    if time.time() < manual_connection_quiet_until:
        log_to_json("INFO", "VPN", "人工连接刚完成，忽略本轮可能来自旧连接的陈旧故障结果")
        return
    if not bool(load_ui_config().get("connection_enabled", True)):
        return
    if active_pool_endpoint_id:
        failed_endpoint = active_pool_endpoint_id
        clear_manual_route_pin()
        try:
            node_pool.record_endpoint_probe(failed_endpoint, False, 0, error_msg)
        except Exception:
            pass
        if not try_unified_failover(exclude_endpoint_id=failed_endpoint, attempts=3):
            stop_active_external_tunnel()
            auto_switch_node()
        return

    if active_openvpn_node_id:
        clear_manual_route_pin()
        ui_cfg = load_ui_config()
        routing_mode = ui_cfg.get("routing_mode", "auto")
        if routing_mode != "fixed_ip":
            failed_endpoint = ""
            with lock:
                nodes = read_nodes()
                active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if active_node:
                    failed_endpoint = openvpn_pool_endpoint_id(active_node)
                    mark_blacklisted(active_node, f"代理连续连通性检测失败: {error_msg}")
                    active_node["probe_status"] = "unavailable"
                    write_json(NODES_FILE, nodes)
                    try:
                        node_pool.record_probe(active_node, False, 0, error_msg)
                    except Exception:
                        pass
            if not try_unified_failover(exclude_endpoint_id=failed_endpoint, attempts=4):
                auto_switch_node()
        else:
            print(f"[代理守护线程] 固定 IP 模式下代理连续不可用，正在尝试重启连接同一节点: {active_openvpn_node_id}", flush=True)
            is_connecting = False
            try:
                connect_node(active_openvpn_node_id)
            except Exception as exc:
                print(f"[代理守护线程] 重启固定节点失败: {exc}", flush=True)


def owned_tunnel_local_liveness() -> tuple[bool, str]:
    if active_pool_endpoint_id:
        tunnel = active_external_tunnel
        if tunnel is None:
            return False, "活动多协议 TunnelResult 已丢失"
        protocol = str(tunnel.protocol or "")
        if protocol == "softether":
            details = tunnel.details or {}
            account = str(details.get("account") or "aimili")
            ok, output = tunnel_adapters.SoftEtherAdapter().account_connected(account)
            if not ok:
                return False, f"SoftEther Session 已断开: {output[-500:]}"
            if not tunnel_adapters.interface_has_ipv4(tunnel.interface):
                return False, f"SoftEther 网卡 {tunnel.interface} 没有 IPv4"
            return True, ""
        if protocol == "sstp":
            if tunnel.process is None or tunnel.process.poll() is not None:
                return False, "SSTP/pppd 进程已退出"
            if not tunnel_adapters.interface_has_ipv4(tunnel.interface):
                return False, f"SSTP 网卡 {tunnel.interface} 没有 IPv4"
            return True, ""
        if protocol == "l2tp-ipsec":
            if tunnel.process is None or tunnel.process.poll() is not None:
                return False, "L2TP/IPsec helper 进程已退出"
            if not tunnel.interface or not (Path("/sys/class/net") / tunnel.interface).exists():
                return False, f"L2TP veth {tunnel.interface} 已消失"
            return True, ""
        return False, f"未知活动协议 {protocol}"

    if active_openvpn_node_id:
        if not active_openvpn_running():
            return False, "OpenVPN 进程已退出"
        active_iface = str(proxy_server.get_active_interface() or "tun0")
        if sys.platform.startswith("linux") and not Path("/sys/class/net").joinpath(active_iface).exists():
            return False, f"OpenVPN 活动网卡 {active_iface} 已消失"
        if not tunnel_adapters.interface_has_ipv4(active_iface):
            return False, f"OpenVPN 活动网卡 {active_iface} 没有 IPv4"
        return True, ""

    return True, "idle"


def fast_tunnel_liveness_loop() -> None:
    liveness_failures = 0
    last_target = ""
    time.sleep(3)
    while True:
        try:
            if ui_command_plane.is_busy() or global_pool_refresh_running or is_connecting or manual_connection_active or failover_lock.locked():
                time.sleep(FAST_LIVENESS_INTERVAL_SECONDS)
                continue
            if not active_pool_endpoint_id and not active_openvpn_node_id:
                time.sleep(FAST_LIVENESS_INTERVAL_SECONDS)
                continue
            target = active_pool_endpoint_id or active_openvpn_node_id
            if target != last_target:
                liveness_failures = 0
                last_target = target
            ok, reason = owned_tunnel_local_liveness()
            if not ok:
                liveness_failures += 1
                if liveness_failures < 3:
                    time.sleep(FAST_LIVENESS_INTERVAL_SECONDS)
                    continue
                error_msg = f"本地快速存活检测连续 {liveness_failures} 次失败: {reason}"
                liveness_failures = 0
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=error_msg,
                )
                log_to_json("WARNING", "Proxy", error_msg)
                handle_confirmed_tunnel_failure(error_msg)
        except Exception as exc:
            log_to_json("ERROR", "Proxy", f"快速存活守护异常: {exc}")
        time.sleep(FAST_LIVENESS_INTERVAL_SECONDS)


def background_proxy_checker() -> None:
    global last_checker_heartbeat, is_connecting
    time.sleep(PROXY_HEALTH_INTERVAL_SECONDS)
    while True:
        last_checker_heartbeat = time.time()
        try:
            if is_connecting:
                time.sleep(5)
                continue

            # Never infer ownership from an existing host tun/ppp interface.
            # If this manager has no intended active endpoint, it is idle.
            # If an endpoint ID still exists but the process/interface vanished,
            # that is a real tunnel failure and must enter failover handling.
            check_target = str(active_pool_endpoint_id or active_openvpn_node_id or "")
            if not active_tunnel_running():
                if not check_target:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error="当前实例没有活动 VPN 隧道",
                    )
                    time.sleep(PROXY_HEALTH_INTERVAL_SECONDS)
                    continue
                res = {
                    "ok": False,
                    "error": "活动 VPN 隧道进程或网卡已消失",
                }
            else:
                res = check_proxy_health()
            if res["ok"]:
                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error=""
                )
                maybe_recover_preferred_route()
                log_to_json("INFO", "Proxy", f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
            else:
                first_error = res.get("error", "未知错误")
                # A single public endpoint hiccup must not flap the production
                # tunnel. Confirm once more before blacklisting or switching.
                time.sleep(PROXY_HEALTH_CONFIRM_DELAY_SECONDS)
                confirm = check_proxy_health()
                if confirm.get("ok"):
                    set_state(
                        proxy_ok=True,
                        proxy_ip=confirm["ip"],
                        proxy_latency_ms=confirm["latency_ms"],
                        proxy_error=""
                    )
                    maybe_recover_preferred_route()
                    log_to_json("WARNING", "Proxy", f"首次健康检查失败但复检恢复，保持当前节点: {first_error}")
                    continue

                error_msg = confirm.get("error") or first_error
                if active_openvpn_node_id:
                    print(f"[警告] {LOCAL_PROXY_PORT} 端口本地代理连续检测失败！原因: {error_msg}", flush=True)
                    log_to_json("WARNING", "Proxy", f"代理连续检测失败: {error_msg}")
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=error_msg
                )

                # Only confirmed failures can trigger production failover.
                handle_confirmed_tunnel_failure(error_msg, expected_target=check_target)
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(PROXY_HEALTH_INTERVAL_SECONDS)

def active_node_pinger() -> None:
    # Heartbeat only. Real client health and latency are maintained by the
    # background proxy health loop, avoiding duplicate ICMP/TCP probes.
    global last_pinger_heartbeat
    while True:
        last_pinger_heartbeat = time.time()
        try:
            if active_tunnel_running():
                current = int(read_json(STATE_FILE, {}).get("proxy_latency_ms") or 0)
                if current > 0:
                    set_state(active_node_latency=f"{current} ms")
                else:
                    set_state(active_node_latency="出口已连接，等待检测")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        ui_cfg = load_ui_config()
        return ui_cfg.get("secret_path", "EJsW2EeBo9lY")

    def is_authorized(self) -> bool:
        ui_cfg = load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            print("[Auth] 管理后台密码为空，已拒绝访问。请检查 ui_auth.json。", flush=True)
            return False

        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()

        session_token = cookies.get("session")
        if not session_token:
            return False

        _load_persisted_sessions()
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        request_path = urllib.parse.urlsplit(self.path).path
        if not secret_path:
            return request_path
        if request_path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if request_path.startswith(prefix):
            return "/" + request_path[len(prefix):]
        # Resource-sharing endpoints use a separate bearer token and an IP/CIDR
        # allow-list, so peers never need the admin secret path.
        if request_path == "/resource-share" or request_path.startswith("/resource-share/"):
            return request_path
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        if hasattr(self, "_ui_command_token") and int(status) >= 400:
            self._ui_command_ok = False
        body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(body) >= 16384 and "gzip" in str(self.headers.get("Accept-Encoding") or "").lower():
            body = gzip.compress(body, compresslevel=5)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_bytes(body, "application/json; charset=utf-8", status)

    def read_request_body(self, max_bytes: int = 65536) -> bytes:
        length = parse_int(self.headers.get("Content-Length"))
        if length < 0:
            raise ValueError("Content-Length 无效")
        if length > max_bytes:
            raise ValueError(f"请求体过大，最大允许 {max_bytes} 字节")
        return self.rfile.read(length) if length > 0 else b""

    def read_json_body(self, max_bytes: int = 65536) -> dict[str, Any]:
        body = self.read_request_body(max_bytes)
        if not body:
            return {}
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("请求 JSON 必须是对象")
        return data

    def resource_share_local_url(self) -> str:
        scheme = str(self.headers.get("X-Forwarded-Proto") or "https").split(",")[0].strip() or "https"
        host = str(self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "").strip()
        forwarded_port = str(self.headers.get("X-Forwarded-Port") or "").split(",")[0].strip()
        if host and forwarded_port and ":" not in host:
            default_port = "443" if scheme == "https" else "80"
            if forwarded_port != default_port:
                host = f"{host}:{forwarded_port}"
        return f"{scheme}://{host}/resource-share" if host else "/resource-share"

    def handle_resource_share_get(self, effective_path: str) -> bool:
        try:
            if effective_path in ("/resource-share", "/resource-share/"):
                self.send_json({
                    "ok": True,
                    "service": "AimiliVPN Resource Share",
                    "version": 1,
                    "server_url": self.resource_share_local_url(),
                    "message": "资源共享接口已启用。访问 resources 需要有效的资源访问令牌；加入服务器请使用长期邀请码。",
                    "endpoints": {
                        "ping": "/resource-share/ping",
                        "resources": "/resource-share/resources",
                        "enroll": "/resource-share/enroll"
                    }
                })
                return True
            if effective_path == "/resource-share/ping":
                self.send_json(resource_share.ping(self.headers, self.client_address))
                return True
            if effective_path == "/resource-share/resources":
                peer_id, peer = resource_share.authorize(self.headers, self.client_address)
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                exclude_id = str((query.get("exclude_peer_id") or [""])[0]).strip()
                requested = bounded_int(
                    (query.get("limit") or [str(resource_share.DEFAULT_MAX_NODES)])[0],
                    resource_share.DEFAULT_MAX_NODES,
                    10,
                    min(resource_share.MAX_MAX_NODES, int(peer.get("max_nodes") or resource_share.DEFAULT_MAX_NODES)),
                )
                payload = resource_share.export_resources(exclude_peer_id=exclude_id, max_nodes=requested)
                payload["authorized_peer_id"] = peer_id
                self.send_json(payload)
                return True
            self.send_json({"ok": False, "error": "resource share endpoint not found"}, HTTPStatus.NOT_FOUND)
            return True
        except PermissionError as exc:
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.FORBIDDEN)
            return True
        except Exception as exc:
            log_to_json("WARNING", "Share", f"资源共享 GET 失败: {exc}")
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_GATEWAY)
            return True

    def handle_resource_share_post(self, effective_path: str) -> bool:
        try:
            if effective_path == "/resource-share/enroll":
                payload = self.read_json_body(max_bytes=32768)
                source_ip = resource_share.client_ip(self.headers, self.client_address)
                if not source_ip:
                    raise ValueError("无法识别对端 IP")
                result = resource_share.enroll(payload, source_ip)
                result["resource_url"] = self.resource_share_local_url() + "/resources"
                log_to_json("INFO", "Share", f"资源共享新 Peer 已加入: {result.get('peer_id')}，来源 {source_ip}")
                self.send_json(result)
                return True
            self.send_json({"ok": False, "error": "resource share endpoint not found"}, HTTPStatus.NOT_FOUND)
            return True
        except PermissionError as exc:
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.FORBIDDEN)
            return True
        except ValueError as exc:
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return True
        except Exception as exc:
            log_to_json("WARNING", "Share", f"资源共享 POST 失败: {exc}")
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_GATEWAY)
            return True

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        if effective_path in ("/resource-share", "/resource-share/") or effective_path.startswith("/resource-share/"):
            self.handle_resource_share_get(effective_path)
            return

        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return

        if effective_path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path in ("/footer-logo-clean.webp", "/footer-logo-clean.png"):
            try:
                if effective_path.endswith(".webp"):
                    self.send_bytes((ROOT_DIR / "footer-logo-clean.webp").read_bytes(), "image/webp")
                else:
                    self.send_bytes((ROOT_DIR / "footer-logo-clean.png").read_bytes(), "image/png")
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/link-test":
            try:
                link_test_path = ROOT_DIR / "client_link_test.html"
                self.send_bytes(link_test_path.read_bytes(), "text/html; charset=utf-8")
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path in ("/api/github_version", "/api/github_update/check"):
            self.send_json(check_github_update() if effective_path.endswith("/check") else current_github_version())
        elif effective_path == "/api/certificate_status":
            self.send_json({"ok": True, "certificate": web_certificate.snapshot()})
        elif effective_path == "/api/github_update/status":
            self.send_json({
                "ok": True,
                "running": github_update_running,
                "last_result": github_update_last_result,
            })
        elif effective_path == "/api/nodes":
            global active_openvpn_node_id
            nodes = _get_ui_nodes_snapshot()
            active_node = next((n for n in nodes if active_openvpn_node_id and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                n["active"] = bool(active_openvpn_node_id and n.get("id") == active_openvpn_node_id)
            if active_node and last_active_latency > 0:
                active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped.pop("_pool_metadata", None)
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": _get_fast_nodes_state()})
        elif effective_path == "/api/ui/state":
            self.send_json({"ok": True, "state": _get_fast_nodes_state(), "ui_command": ui_command_plane.ui_state()})
        elif effective_path == "/api/ui/nodes":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            offset = bounded_int((query.get("offset") or ["0"])[0], 0, 0, 200000)
            limit = bounded_int((query.get("limit") or ["100"])[0], 100, 1, 200)
            country = str((query.get("country") or [""])[0]).strip()
            status = str((query.get("status") or [""])[0]).strip().lower()
            protocol = str((query.get("protocol") or [""])[0]).strip().lower()
            ip_type = str((query.get("ip_type") or [""])[0]).strip().lower()
            page_nodes, total_nodes, cache_building = _get_ui_nodes_page(
                offset, limit, country, status, protocol, ip_type
            )
            self.send_json({
                "ok": True,
                "nodes": page_nodes,
                "offset": offset,
                "limit": limit,
                "total": total_nodes,
                "has_more": offset + len(page_nodes) < total_nodes,
                "cache_building": cache_building,
                "scope": {"country": country, "status": status, "protocol": protocol, "ip_type": ip_type},
                "generated_at": time.time(),
            })
        elif effective_path == "/api/ui/country_catalog":
            try:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                status = str((query.get("status") or [""])[0]).strip().lower()
                protocol = str((query.get("protocol") or [""])[0]).strip().lower()
                ip_type = str((query.get("ip_type") or [""])[0]).strip().lower()
                self.send_json({"ok": True, **_get_ui_country_catalog(status, protocol, ip_type)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/protocol_capabilities":
            self.send_json({"ok": True, "protocols": tunnel_adapters.capability_report()})
        elif effective_path == "/api/node_pool_stats":
            try:
                self.send_json({"ok": True, "pool": node_pool.stats()})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/pool_endpoints":
            try:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                protocol = str((query.get("protocol") or [""])[0]).strip().lower() or None
                limit = bounded_int((query.get("limit") or ["500"])[0], 500, 1, 5000)
                self.send_json({"ok": True, "endpoints": node_pool.list_endpoints(protocol=protocol, limit=limit)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/hot_pool":
            try:
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                limit = bounded_int((query.get("limit") or ["10"])[0], 10, 1, 20)
                pool = node_pool.ranked_hot_pool(limit=limit, per_server_limit=2)
                self.send_json({
                    "ok": True,
                    "hot_pool": pool,
                    "count": len(pool),
                    "target": HOT_POOL_TARGET,
                    "deficit": max(0, HOT_POOL_TARGET - len(pool)),
                })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/link_probe":
            # Client measures HTTP RTT externally. The response separates that
            # client-to-server metric from local 8500 and VPN egress health.
            state = get_state()
            self.send_json({
                "ok": True,
                "server_time": time.time(),
                "proxy_host": LOCAL_PROXY_HOST,
                "proxy_port": LOCAL_PROXY_PORT,
                "proxy_port_reachable": local_proxy_port_reachable(),
                "proxy_ok": bool(state.get("proxy_ok")),
                "proxy_latency_ms": parse_int(state.get("proxy_latency_ms")),
                "active_tunnel_protocol": state.get("active_tunnel_protocol", ""),
                "active_tunnel_interface": proxy_server.get_active_interface() if active_tunnel_running() else "",
                "active_node_id": active_openvpn_node_id,
                "active_pool_endpoint_id": active_pool_endpoint_id,
                "pool": node_pool.stats(),
                "hot_pool_size": state.get("hot_pool_size", 0),
                "hot_pool_target": state.get("hot_pool_target", HOT_POOL_TARGET),
                "last_failover_ok": state.get("last_failover_ok"),
                "last_failover_duration_ms": state.get("last_failover_duration_ms", 0),
                "last_failover_from_protocol": state.get("last_failover_from_protocol", ""),
                "last_failover_to_protocol": state.get("last_failover_to_protocol", ""),
            })
        elif effective_path == "/api/link_probe_payload":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            requested = bounded_int(
                (query.get("bytes") or ["262144"])[0],
                262144,
                1024,
                LINK_PROBE_MAX_BYTES,
            )
            client_ip = str(self.client_address[0] if self.client_address else "unknown")
            allowed, retry_after = reserve_link_probe_bytes(client_ip, requested)
            if not allowed:
                self.send_json(
                    {"ok": False, "error": "测速请求过于频繁", "retry_after_seconds": retry_after},
                    HTTPStatus.TOO_MANY_REQUESTS,
                )
                return
            self.send_bytes(b"0" * requested, "application/octet-stream")
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_nodes()
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        elif effective_path == "/api/gateway_status":
            web_ui_status = {
                "name": "Web 管理服务",
                "status": "running",
                "details": f"监听地址: {load_ui_config().get('host', UI_HOST)}:{load_ui_config().get('port', UI_PORT)}",
                "error": ""
            }
            proxy_ok = False
            proxy_err = ""
            is_ipv6 = ":" in LOCAL_PROXY_HOST
            af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(0.5)
                connect_host = LOCAL_PROXY_HOST
                if connect_host in ("::", "0.0.0.0", ""):
                    connect_host = "::1" if is_ipv6 else "127.0.0.1"
                try:
                    s.connect((connect_host, LOCAL_PROXY_PORT))
                    proxy_ok = True
                except Exception:
                    if connect_host == "::1":
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        proxy_ok = True
                    else:
                        raise
            except Exception as e:
                diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
                proxy_err = diag[1] if diag else f"本地代理网关无法连通: {e}"
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
            proxy_gateway_status = {
                "name": "本地代理网关",
                "status": "running" if proxy_ok else "stopped",
                "details": f"监听地址: {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
                "error": proxy_err
            }
            tunnel_ok = active_tunnel_running()
            tunnel_state = get_state()
            tunnel_protocol = str(tunnel_state.get("active_tunnel_protocol") or "")
            tunnel_iface = str(tunnel_state.get("active_tunnel_interface") or "")
            tunnel_id = active_pool_endpoint_id or active_openvpn_node_id
            tunnel_err = ""
            tunnel_details = "未连接"
            if tunnel_ok:
                tunnel_details = f"协议: {tunnel_protocol or 'unknown'}; 接口: {tunnel_iface or '-'}; 端点: {tunnel_id or '-'}"
                if sys.platform.startswith("linux") and tunnel_iface:
                    if not (Path("/sys/class/net") / tunnel_iface).exists():
                        tunnel_err = f"[警告] 活动 VPN 网卡 ({tunnel_iface}) 不存在，可能存在隧道或策略路由问题。"
            elif tunnel_id:
                tunnel_err = "活动 VPN 隧道已中断或核心进程异常退出。"
                tunnel_details = f"最近活动端点: {tunnel_id}"
            tunnel_status = {
                "name": "活动 VPN 隧道",
                "status": "running" if tunnel_ok else "stopped",
                "details": tunnel_details,
                "error": tunnel_err
            }
            now = time.time()
            server_uptime = now - server_start_time
            collector_ok = (last_collector_heartbeat > 0.0 and now - last_collector_heartbeat < (CHECK_INTERVAL_SECONDS * 1.5)) or (server_uptime < 15.0)
            collector_status = {
                "name": "节点同步守护线程",
                "status": "running" if collector_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_collector_heartbeat)) if last_collector_heartbeat > 0 else '等待启动'}",
                "error": "" if collector_ok else "线程可能已异常终止，导致无法在后台拉取和测速新节点。"
            }
            checker_ok = (last_checker_heartbeat > 0.0 and now - last_checker_heartbeat < 90.0) or (server_uptime < 35.0)
            checker_status = {
                "name": "出口检测守护线程",
                "status": "running" if checker_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_checker_heartbeat)) if last_checker_heartbeat > 0 else '等待启动'}",
                "error": "" if checker_ok else "线程可能已挂起或终止，导致无法实时获取代理出口状态。"
            }
            pinger_ok = (last_pinger_heartbeat > 0.0 and now - last_pinger_heartbeat < 30.0) or (server_uptime < 15.0)
            pinger_status = {
                "name": "延迟测速守护线程",
                "status": "running" if pinger_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pinger_heartbeat)) if last_pinger_heartbeat > 0 else '等待启动'}",
                "error": "" if pinger_ok else "线程可能已中止，无法实时刷新活动节点的 Ping 延迟。"
            }
            self.send_json({
                "ok": True,
                "services": [
                    web_ui_status,
                    proxy_gateway_status,
                    tunnel_status,
                    collector_status,
                    checker_status,
                    pinger_status
                ]
            })
        elif effective_path == "/api/resource_share/status":
            try:
                status = resource_share.status()
                status["local_url"] = self.resource_share_local_url()
                status["pool"] = node_pool.stats()
                self.send_json(status)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/logs":
            logs_dir = DATA_DIR / "logs"
            date_str = time.strftime("%Y-%m-%d", time.localtime())
            log_file = logs_dir / f"{date_str}.json"
            entries, truncated = read_recent_log_entries(log_file, max_entries=1200, max_bytes=1048576)
            self.send_json({"logs": entries, "truncated": truncated, "max_entries": 1200, "max_bytes": 1048576})
        elif effective_path == "/api/logs/size":
            logs_dir = DATA_DIR / "logs"
            date_str = time.strftime("%Y-%m-%d", time.localtime())
            log_file = logs_dir / f"{date_str}.json"
            try:
                size = log_file.stat().st_size if log_file.exists() else 0
            except OSError:
                size = 0
            self.send_json({"ok": True, "date": date_str, "bytes": size})
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "":
            return
        if effective_path in ("/api/login", "/api/logout"):
            return self._do_POST_impl()
        if not self.is_authorized():
            return self._do_POST_impl()

        # All authenticated UI write operations pass through one command gate.
        # Connection endpoints retain their dedicated connection lock below.
        command_bypass = {"/api/connect", "/api/connect_pool_endpoint"}
        if effective_path in command_bypass:
            return self._do_POST_impl()

        command = ui_command_plane.begin("ui_command", effective_path)
        if command is None:
            self.send_json(
                {"ok": False, "busy": True, "error": "已有前端操作正在执行，请等待当前操作完成"},
                HTTPStatus.CONFLICT,
            )
            return

        self._ui_command_token = command["token"]
        self._ui_command_ok = True
        try:
            return self._do_POST_impl()
        except Exception:
            self._ui_command_ok = False
            raise
        finally:
            ui_command_plane.finish(
                command["token"],
                ok=bool(getattr(self, "_ui_command_ok", False)),
                message=effective_path,
            )
            self._ui_command_token = ""
            self._ui_command_ok = True

    def _do_POST_impl(self) -> None:
        global is_connecting
        effective_path = self.validate_path()
        if effective_path == "": return
        if effective_path.startswith("/resource-share/"):
            self.handle_resource_share_post(effective_path)
            return

        if effective_path == "/api/login":
            try:
                payload = self.read_json_body()
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")

                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")

                if expected_pwd and input_pwd == expected_pwd and input_uname == expected_uname:
                    token = _create_session()
                    body = json.dumps({"ok": True}).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    # Use a host-wide HttpOnly session cookie so admin API calls remain
                    # authenticated even when the browser changes between the secret
                    # path, relative API paths, and modal views. The secret URL is
                    # still enforced independently by validate_path().
                    secret_path = self.get_secret_path()
                    self.send_header("Set-Cookie", f"session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    # Clear legacy secret-path scoped session cookies to prevent
                    # duplicate session= cookies from being parsed ambiguously.
                    if secret_path:
                        self.send_header("Set-Cookie", f"session=; Path=/{secret_path}/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    _remove_session(session_token)
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                secret_path = self.get_secret_path()
                if secret_path:
                    self.send_header("Set-Cookie", f"session=; Path=/{secret_path}/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path == "/api/github_update/check":
            try:
                self.send_json(check_github_update())
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_GATEWAY)
            return

        if effective_path == "/api/github_update":
            try:
                result = start_github_update()
                self.send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.CONFLICT)
            except Exception as exc:
                log_to_json("WARNING", "Main", f"GitHub 正式版更新启动失败: {exc}")
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logs/manage":
            try:
                payload = self.read_json_body(max_bytes=4096)
                action = str(payload.get("action") or "").strip().lower()
                if action == "clear_today":
                    result = clear_today_log()
                    log_to_json("INFO", "Main", "管理员已清空今日运行日志")
                    self.send_json(result)
                elif action == "cleanup_old":
                    logs_dir = DATA_DIR / "logs"
                    cleanup_old_logs(logs_dir, force=True)
                    self.send_json({"ok": True, "message": "已执行旧日志清理（保留最近 3 天）"})
                else:
                    self.send_json({"ok": False, "error": "未知日志管理操作"}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/resource_share/invite":
            try:
                payload = self.read_json_body(max_bytes=8192)
                result = resource_share.create_invite(
                    peer_name=str(payload.get("peer_name") or "").strip(),
                    allowed_cidrs=payload.get("allowed_cidrs", ""),
                )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/resource_share/join":
            try:
                payload = self.read_json_body(max_bytes=16384)
                result = resource_share.join_remote(
                    remote_url=str(payload.get("remote_url") or "").strip(),
                    invite_code=str(payload.get("invite_code") or "").strip(),
                    name=str(payload.get("name") or "").strip(),
                    sync_interval_value=payload.get("sync_interval_value", resource_share.DEFAULT_SYNC_INTERVAL_VALUE),
                    sync_interval_unit=str(payload.get("sync_interval_unit") or resource_share.DEFAULT_SYNC_INTERVAL_UNIT),
                    existing_peer_id=str(payload.get("peer_id") or ""),
                )
                sync_result = None
                try:
                    sync_result = resource_share.sync_peer(str(result.get("peer_id") or ""), force=True)
                except Exception as sync_exc:
                    sync_result = {"ok": False, "error": str(sync_exc)}
                    log_to_json("WARNING", "Share", f"新共享服务器首次同步失败: {result.get('peer_id')}")
                result["first_sync"] = sync_result
                log_to_json("INFO", "Share", f"已建立资源共享关系: {result.get('peer_id')}")
                self.send_json(result)
            except (ValueError, RuntimeError) as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/resource_share/sync":
            try:
                payload = self.read_json_body(max_bytes=8192)
                peer_id = str(payload.get("peer_id") or "").strip()
                if peer_id:
                    result = resource_share.sync_peer(peer_id, force=True)
                else:
                    result = resource_share.sync_all(force=True)
                self.send_json({"ok": True, "result": result})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_GATEWAY)
            return

        if effective_path == "/api/resource_share/update":
            try:
                payload = self.read_json_body(max_bytes=16384)
                peer_id = str(payload.get("peer_id") or "").strip()
                if not peer_id:
                    raise ValueError("peer_id 不能为空")
                patch = {
                    key: payload[key]
                    for key in ("name", "allowed_cidrs", "enabled", "sync_interval_value", "sync_interval_unit")
                    if key in payload
                }
                if "allowed_cidrs" in patch:
                    patch["allowed_cidrs"] = resource_share.normalize_cidrs(patch["allowed_cidrs"])
                peer = resource_share.update_peer(peer_id, patch)
                self.send_json({"ok": True, "peer": peer})
            except KeyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.NOT_FOUND)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/resource_share/rebind":
            try:
                payload = self.read_json_body(max_bytes=16384)
                peer_id = str(payload.get("peer_id") or "").strip()
                if not peer_id:
                    raise ValueError("peer_id 不能为空")
                result = resource_share.update_joined_peer(
                    peer_id=peer_id,
                    remote_url=str(payload.get("remote_url") or "").strip(),
                    invite_code=str(payload.get("invite_code") or "").strip(),
                    name=str(payload.get("name") or "").strip(),
                    sync_interval_value=payload.get("sync_interval_value", resource_share.DEFAULT_SYNC_INTERVAL_VALUE),
                    sync_interval_unit=str(payload.get("sync_interval_unit") or resource_share.DEFAULT_SYNC_INTERVAL_UNIT),
                )
                self.send_json(result)
            except KeyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.NOT_FOUND)
            except (ValueError, RuntimeError) as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/resource_share/update_invite":
            try:
                payload = self.read_json_body(max_bytes=8192)
                invite_id = str(payload.get("invite_id") or "").strip()
                if not invite_id:
                    raise ValueError("invite_id 不能为空")
                result = resource_share.update_invite(invite_id, {
                    key: payload[key]
                    for key in ("peer_name", "allowed_cidrs")
                    if key in payload
                })
                if isinstance(result.get("invite"), dict) and "allowed_cidrs" in result["invite"]:
                    result["invite"]["allowed_cidrs"] = resource_share.normalize_cidrs(result["invite"]["allowed_cidrs"])
                self.send_json(result)
            except KeyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.NOT_FOUND)
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/resource_share/revoke_invite":
            try:
                payload = self.read_json_body(max_bytes=8192)
                invite_id = str(payload.get("invite_id") or "").strip()
                if not invite_id:
                    raise ValueError("invite_id 不能为空")
                result = resource_share.revoke_invite(invite_id)
                log_to_json("INFO", "Share", f"已撤销资源共享邀请码: {invite_id}")
                self.send_json(result)
            except KeyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.NOT_FOUND)
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/resource_share/delete_invite":
            try:
                payload = self.read_json_body(max_bytes=8192)
                invite_id = str(payload.get("invite_id") or "").strip()
                if not invite_id:
                    raise ValueError("invite_id 不能为空")
                result = resource_share.delete_invite(invite_id)
                log_to_json("INFO", "Share", f"已永久删除资源共享邀请码: {invite_id}")
                self.send_json(result)
            except KeyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.NOT_FOUND)
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/resource_share/toggle":
            try:
                payload = self.read_json_body(max_bytes=8192)
                peer_id = str(payload.get("peer_id") or "").strip()
                peer = resource_share.update_peer(peer_id, {"enabled": bool(payload.get("enabled"))})
                self.send_json({"ok": True, "peer": peer})
            except KeyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.NOT_FOUND)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/resource_share/delete":
            try:
                payload = self.read_json_body(max_bytes=8192)
                peer_id = str(payload.get("peer_id") or "").strip()
                result = resource_share.delete_peer(peer_id)
                log_to_json("INFO", "Share", f"已删除资源共享 Peer: {peer_id}")
                self.send_json(result)
            except KeyError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.NOT_FOUND)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/resource_share/delete_relationship":
            try:
                payload = self.read_json_body(max_bytes=8192)
                peer_ids = payload.get("peer_ids", [])
                if not isinstance(peer_ids, list):
                    peer_ids = [peer_ids]
                result = resource_share.delete_relationship([str(x or "") for x in peer_ids])
                log_to_json("INFO", "Share", f"已删除资源共享关系: {result.get('peer_ids')}")
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        if effective_path == "/api/update_credentials":
            try:
                payload = self.read_json_body()
                new_username = str(payload.get("username") or "").strip()
                new_password = str(payload.get("password") or "").strip()
                new_suffix = str(payload.get("secret_path") or "").strip()
                raw_domain = str(payload.get("domain") or "").strip()
                new_port_int = 8501

                ui_cfg = load_ui_config()
                try:
                    new_domain = web_certificate.normalize_domain(raw_domain)
                except ValueError as exc:
                    self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                    return

                if not new_username or (not new_password and not ui_cfg.get("password")):
                    self.send_json({"ok": False, "error": "用户名不能为空；首次设置时密码不能为空"}, HTTPStatus.BAD_REQUEST)
                    return

                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return

                expected_username = ui_cfg.get("username", "")
                expected_password = ui_cfg.get("password", "")
                expected_suffix = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
                old_domain = str(ui_cfg.get("web_domain") or "").strip()
                cert_before = web_certificate.snapshot()

                # Do not let a different domain overwrite an in-flight ACME order.
                # Saving the same domain is allowed and remains idempotent.
                cert_running_domain = str(cert_before.get("domain") or "").strip()
                if cert_before.get("running") and new_domain != cert_running_domain:
                    self.send_json(
                        {"ok": False, "error": f"HTTPS 证书正在申请 {cert_running_domain or '当前域名'}，请等待当前任务完成后再修改域名。"},
                        HTTPStatus.CONFLICT,
                    )
                    return

                ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                ui_cfg["port"] = 8501
                ui_cfg["host"] = "127.0.0.1"
                ui_cfg["secret_path"] = new_suffix
                ui_cfg["web_domain"] = new_domain

                auth_file = DATA_DIR / "ui_auth.json"
                reauth_required = new_username != expected_username or (new_password and new_password != expected_password)
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                    if reauth_required:
                        active_sessions.clear()

                restart_needed = (new_suffix != expected_suffix)
                certificate_result = web_certificate.snapshot()
                domain_changed = new_domain != old_domain

                if new_domain:
                    if domain_changed and not restart_needed:
                        # A changed hostname is the only normal settings action
                        # that is allowed to start a fresh ACME issuance.
                        certificate_result = web_certificate.start(new_domain)
                    elif restart_needed:
                        # Persist a resumable state marker without starting the
                        # ACME child process inside a process that is about to exit.
                        web_certificate._write_state(
                            status="issuing",
                            domain=new_domain,
                            message="网页安全配置正在重启，重启后将自动继续申请 HTTPS 证书。",
                            last_error="",
                        )
                        certificate_result = web_certificate.snapshot()
                    else:
                        certificate_result = web_certificate.snapshot()
                elif old_domain:
                    certificate_result = web_certificate.disable()
                    if not certificate_result.get("ok"):
                        self.send_json(
                            {"ok": False, "error": certificate_result.get("error") or certificate_result.get("last_error") or "清除 HTTPS 域名失败"},
                            HTTPStatus.BAD_GATEWAY,
                        )
                        return

                if restart_needed:
                    self.send_json({
                        "ok": True,
                        "restart_needed": True,
                        "reauth_required": reauth_required,
                        "certificate": certificate_result,
                        "message": "配置更新成功，网页安全后缀已变更；服务将在约 2 秒后重启，HTTPS 证书任务会在重启后自动继续。",
                    })

                    def restart_server():
                        time.sleep(2)
                        print("[系统] 管理后台安全配置更新，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)

                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    message = "账号密码配置保存成功。"
                    if certificate_result.get("status") in ("issuing", "installing") and certificate_result.get("running"):
                        message += " HTTPS 证书正在后台申请。"
                    elif certificate_result.get("status") == "active":
                        message += " HTTPS 证书已启用。"
                    elif new_domain and certificate_result.get("status") == "error":
                        message += " HTTPS 证书申请失败，请检查域名解析、80 端口及防火墙设置。"
                    elif not new_domain:
                        message += " HTTPS 域名已清除。"
                    self.send_json({
                        "ok": True,
                        "restart_needed": False,
                        "reauth_required": reauth_required,
                        "certificate": certificate_result,
                        "message": message,
                    })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_settings":
            try:
                payload = self.read_json_body()

                new_proxy_port = payload.get("proxy_port")
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()

                try:
                    new_proxy_port_int = int(new_proxy_port)
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "HTTP/SOCKS5 代理端口固定为 8500"}, HTTPStatus.BAD_REQUEST)
                    return
                if new_proxy_port_int != 8500:
                    self.send_json({"ok": False, "error": "HTTP/SOCKS5 代理端口固定为 8500"}, HTTPStatus.BAD_REQUEST)
                    return

                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_mode == "fixed_region" and not force_country:
                    self.send_json({"ok": False, "error": "启用优先地区前，请先选择一个目标国家"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting", "mobile"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg = load_ui_config()
                expected_proxy_port = 8500
                fixed_node_id = current_fixed_node_id(ui_cfg) if routing_mode == "fixed_ip" else ""

                if new_proxy_port_int != 8500:
                    self.send_json({"ok": False, "error": "HTTP/SOCKS5 代理端口固定为 8500"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_mode == "fixed_ip" and not fixed_node_id:
                    self.send_json({"ok": False, "error": "启用固定 IP 前，请先连接一个要锁定的节点"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg["proxy_port"] = 8500
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                if routing_mode == "favorites":
                    ui_cfg["fav_fail_fallback"] = True
                if routing_mode == "fixed_ip":
                    ui_cfg["fixed_node_id"] = fixed_node_id

                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)

                clear_manual_route_pin()
                policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "路由设置已更新")
                if routing_mode == "fixed_region" or routing_ip_type != "all":
                    threading.Thread(target=apply_user_routing_preferences, daemon=True).start()

                restart_needed = (new_proxy_port_int != expected_proxy_port)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "message": "配置更新成功，代理出站端口变更，将在 2 秒内重启..."})

                    def restart_server():
                        time.sleep(2)
                        print("[系统] 代理出站端口变更，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)

                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    message = policy_message or "配置更新成功，已即时生效！"
                    self.send_json({"ok": True, "restart_needed": False, "message": message})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_routing":
            try:
                payload = self.read_json_body()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                ui_cfg = load_ui_config()
                fav_fail_fallback = bool(payload.get("fav_fail_fallback", ui_cfg.get("fav_fail_fallback", True)))

                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_mode == "fixed_region" and not force_country:
                    self.send_json({"ok": False, "error": "启用优先地区前，请先选择一个目标国家"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting", "mobile"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg = load_ui_config()
                fixed_node_id = current_fixed_node_id(ui_cfg) if routing_mode == "fixed_ip" else ""
                if routing_mode == "fixed_ip" and not fixed_node_id:
                    self.send_json({"ok": False, "error": "启用固定 IP 前，请先连接一个要锁定的节点"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                ui_cfg["fav_fail_fallback"] = fav_fail_fallback
                if routing_mode == "fixed_ip":
                    ui_cfg["fixed_node_id"] = fixed_node_id
                ui_cfg.pop("enable_force_country", None)

                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)

                clear_manual_route_pin()
                policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "出站路由配置已更新")
                if routing_mode == "fixed_region" or routing_ip_type != "all":
                    threading.Thread(target=apply_user_routing_preferences, daemon=True).start()

                self.send_json({"ok": True, "message": policy_message or "出站路由配置更新成功，偏好已即时应用，目标恢复后会自动切回！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/toggle_favorite":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "").strip()
                if not node_id:
                    self.send_json({"ok": False, "error": "节点 ID 不能为空"}, HTTPStatus.BAD_REQUEST)
                    return

                ui_cfg = load_ui_config()
                fav_ids = ui_cfg.get("favorite_node_ids", [])
                if not isinstance(fav_ids, list):
                    fav_ids = []

                if node_id in fav_ids:
                    fav_ids.remove(node_id)
                else:
                    fav_ids.append(node_id)

                ui_cfg["favorite_node_ids"] = fav_ids
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)

                policy_message = None
                if ui_cfg.get("routing_mode") == "favorites":
                    policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "收藏列表已更新")

                self.send_json({"ok": True, "favorite_node_ids": fav_ids, "message": policy_message or ""})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                self.send_json({"ok": True, "message": maintain_valid_nodes(force=True)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_global_pool":
            try:
                if manual_connection_active or manual_connection_lock.locked():
                    self.send_json({"ok": False, "busy": True, "error": "当前正在执行人工切换，请完成后再重新轮询全球库"}, HTTPStatus.CONFLICT)
                    return
                result = refresh_global_pool_background(force=True)
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                if maintenance_lock.locked():
                    self.send_json({"ok": True, "message": "节点维护任务正在运行，请稍后再试", "running": True})
                else:
                    threading.Thread(target=maintain_valid_nodes, args=(False,), daemon=True).start()
                    self.send_json({"ok": True, "message": "已在后台启动节点更新流程", "running": False})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/add_node":
            try:
                payload = self.read_json_body(max_bytes=8192)
                value = str(payload.get("address") or payload.get("node") or "").strip()
                result = add_manual_vpngate_node(value)
                self.send_json(result)
            except ValueError as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                payload = self.read_json_body(max_bytes=262144)
                node_ids = payload.get("ids", [])
                if not isinstance(node_ids, list):
                    self.send_json({"ok": False, "error": "节点 ID 列表无效"}, HTTPStatus.BAD_REQUEST)
                    return
                node_ids = [str(node_id or "").strip() for node_id in node_ids]
                node_ids = [node_id for node_id in node_ids if node_id]
                if len(node_ids) > MANUAL_TEST_NODE_LIMIT:
                    self.send_json({"ok": False, "error": f"单次最多测试 {MANUAL_TEST_NODE_LIMIT} 个节点"}, HTTPStatus.BAD_REQUEST)
                    return
                if not maintenance_lock.acquire(blocking=False):
                    self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                    return
                with lock:
                    if is_connecting:
                        maintenance_lock.release()
                        self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                        return
                    is_connecting = True
                try:
                    set_state(is_connecting=True, last_check_message="正在手动测试节点可用性...")
                    tested_nodes = test_multiple_nodes(node_ids)
                    self.send_json({"ok": True, "nodes": tested_nodes})
                finally:
                    with lock:
                        is_connecting = False
                    set_state(is_connecting=False)
                    maintenance_lock.release()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                ui_cfg = load_ui_config()
                clear_manual_route_pin()
                ui_cfg["connection_enabled"] = False
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)

                # Serialize manual disconnect with an in-flight failover. The
                # failover either observes connection_enabled=false and aborts,
                # or completes first; in both cases disconnect then owns the
                # final cleanup and cannot be overwritten by the old failover.
                failover_lock.acquire()
                try:
                    stop_all_tunnels()
                    with lock:
                        nodes = read_nodes()
                        for item in nodes:
                            item["active"] = False
                        write_json(NODES_FILE, nodes)
                    global last_active_ping_time, last_active_latency
                    last_active_ping_time = 0.0
                    last_active_latency = 0
                    proxy_server.clear_active_interface()
                    set_state(
                        active_openvpn_node_id="",
                        active_pool_endpoint_id="",
                        active_pool_endpoint=None,
                        active_tunnel_protocol="",
                        active_tunnel_interface="",
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error="",
                        last_check_message="手动断开连接",
                        active_node_latency="无活动连接",
                    )
                    self.send_json({"ok": True})
                finally:
                    failover_lock.release()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/simulate_tunnel_failure":
            try:
                self.read_request_body()
                if not ISOLATED_INSTANCE:
                    self.send_json(
                        {"ok": False, "error": "该测试接口仅允许隔离实例使用"},
                        HTTPStatus.FORBIDDEN,
                    )
                    return

                protocol = ""
                endpoint_id = ""
                if active_external_tunnel is not None:
                    protocol = str(active_external_tunnel.protocol or "")
                    endpoint_id = str(active_pool_endpoint_id or "")
                    if protocol == "softether":
                        details = active_external_tunnel.details or {}
                        tunnel_adapters.SoftEtherAdapter().disconnect(
                            account=str(details.get("account") or "aimili"),
                            nic=str(details.get("nic") or "aimili"),
                            delete=False,
                        )
                    elif protocol == "sstp":
                        tunnel_adapters.SSTPAdapter.disconnect(active_external_tunnel.process)
                    elif protocol == "l2tp-ipsec":
                        l2tp_adapter.disconnect(active_external_tunnel.namespace)
                    else:
                        raise RuntimeError(f"不支持模拟故障的协议: {protocol}")
                elif active_openvpn_running():
                    protocol = "openvpn"
                    endpoint_id = str(active_openvpn_node_id or "")
                    stop_process(active_openvpn_process)
                else:
                    self.send_json({"ok": False, "error": "当前没有活动隧道"}, HTTPStatus.CONFLICT)
                    return

                set_state(
                    simulated_failure_at=time.time(),
                    simulated_failure_protocol=protocol,
                    simulated_failure_endpoint=endpoint_id,
                )
                self.send_json({
                    "ok": True,
                    "protocol": protocol,
                    "endpoint_id": endpoint_id,
                    "message": "已模拟底层隧道故障，等待健康守护自动切换",
                })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/protocol_selftest":
            try:
                self.read_request_body()
                l2tp = tunnel_adapters.L2TPIPsecAdapter.environment_report(run_kernel_test=True)
                self.send_json({
                    "ok": bool(l2tp.get("ready")),
                    "l2tp_ipsec": l2tp,
                    "protocols": tunnel_adapters.capability_report(),
                }, HTTPStatus.OK if l2tp.get("ready") else HTTPStatus.SERVICE_UNAVAILABLE)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/link_probe_upload":
            try:
                requested = parse_int(self.headers.get("Content-Length"))
                if requested <= 0 or requested > LINK_PROBE_MAX_BYTES:
                    self.send_json(
                        {"ok": False, "error": f"上传测速大小必须在 1 到 {LINK_PROBE_MAX_BYTES} 字节之间"},
                        HTTPStatus.BAD_REQUEST,
                    )
                    return
                client_ip = str(self.client_address[0] if self.client_address else "unknown")
                allowed, retry_after = reserve_link_probe_bytes(client_ip, requested)
                if not allowed:
                    self.send_json(
                        {"ok": False, "error": "测速请求过于频繁", "retry_after_seconds": retry_after},
                        HTTPStatus.TOO_MANY_REQUESTS,
                    )
                    return
                body = self.read_request_body(LINK_PROBE_MAX_BYTES)
                self.send_json({
                    "ok": True,
                    "received_bytes": len(body),
                    "server_time": time.time(),
                })
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_protocol_catalog":
            try:
                self.read_request_body()
                result = refresh_multi_protocol_catalog(force=True)
                self.send_json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_GATEWAY)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect_pool_endpoint":
            try:
                if manual_connection_active or manual_connection_lock.locked():
                    self.send_json({"ok": False, "busy": True, "error": "已有人工切换正在执行，请等待当前切换完成"}, HTTPStatus.CONFLICT)
                    return
                payload = self.read_json_body()
                endpoint_id = str(payload.get("endpoint_id") or "").strip()
                endpoint_ids = payload.get("endpoint_ids", [])
                if not isinstance(endpoint_ids, list):
                    endpoint_ids = [endpoint_ids]
                endpoint_ids = [str(x or "").strip() for x in endpoint_ids if str(x or "").strip()]
                if endpoint_id and endpoint_id not in endpoint_ids:
                    endpoint_ids.insert(0, endpoint_id)
                if not endpoint_ids:
                    self.send_json({"ok": False, "error": "endpoint_id 不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                ui_cmd = ui_command_plane.begin("manual_connect", endpoint_ids[0])
                if ui_cmd is None:
                    self.send_json({"ok": False, "busy": True, "error": "已有前端人工操作正在执行，请等待当前操作完成"}, HTTPStatus.CONFLICT)
                    return
                previous_openvpn_node_id = str(active_openvpn_node_id or "")
                previous_pool_endpoint_id = str(active_pool_endpoint_id or "")
                ui_cfg = load_ui_config()
                ui_cfg["connection_enabled"] = True
                write_json(DATA_DIR / "ui_auth.json", ui_cfg)
                try:
                    message = connect_pool_endpoint_with_fallback(endpoint_ids, manual=True)
                    set_state(manual_switch_active=False, pending_connection_id="", pending_connection_pool_endpoint_id="", pending_connection_protocol="", pending_connection_country="", pending_connection_address="", manual_switch_message="切换完成", last_check_message="人工切换完成，当前节点可用。")
                    ui_command_plane.finish(ui_cmd["token"], ok=True, message=message)
                    self.send_json({"ok": True, "message": message, "state": get_state()})
                except Exception as primary_exc:
                    restored, restore_msg = restore_manual_previous_connection(
                        previous_openvpn_node_id,
                        previous_pool_endpoint_id,
                    )
                    if restored:
                        message = "人工切换失败，已保留/恢复原连接：" + str(restore_msg)
                    else:
                        message = "人工切换失败，原连接恢复失败：" + str(restore_msg)
                    set_state(manual_switch_active=False, pending_connection_id="", pending_connection_pool_endpoint_id="", pending_connection_protocol="", pending_connection_country="", pending_connection_address="", manual_switch_message=message)
                    ui_command_plane.finish(ui_cmd["token"], ok=False, message=message)
                    self.send_json({
                        "ok": False,
                        "auto_fallback": False,
                        "restored_previous": restored,
                        "error": message,
                        "state": get_state(),
                    }, HTTPStatus.BAD_GATEWAY)
            except Exception as exc:
                if "ui_cmd" in locals():
                    ui_command_plane.finish(ui_cmd["token"], ok=False, message=str(exc))
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            try:
                if manual_connection_active or manual_connection_lock.locked():
                    self.send_json({"ok": False, "busy": True, "error": "已有人工切换正在执行，请等待当前切换完成"}, HTTPStatus.CONFLICT)
                    return
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "").strip()
                if not node_id:
                    self.send_json({"ok": False, "error": "节点 ID 不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                ui_cmd = ui_command_plane.begin("manual_connect", node_id)
                if ui_cmd is None:
                    self.send_json({"ok": False, "busy": True, "error": "已有前端人工操作正在执行，请等待当前操作完成"}, HTTPStatus.CONFLICT)
                    return
                previous_openvpn_node_id = str(active_openvpn_node_id or "")
                previous_pool_endpoint_id = str(active_pool_endpoint_id or "")
                try:
                    message = connect_node(node_id, enable_connection=True, manual=True)
                    set_state(manual_switch_active=False, pending_connection_id="", pending_connection_pool_endpoint_id="", pending_connection_protocol="", pending_connection_country="", pending_connection_address="", manual_switch_message="切换完成", last_check_message="人工切换完成，当前节点可用。")
                    ui_command_plane.finish(ui_cmd["token"], ok=True, message=message)
                    self.send_json({"ok": True, "message": message, "state": get_state()})
                except Exception as primary_exc:
                    restored, restore_msg = restore_manual_previous_connection(
                        previous_openvpn_node_id,
                        previous_pool_endpoint_id,
                    )
                    if restored:
                        message = "人工切换失败，已保留/恢复原连接：" + str(restore_msg)
                    else:
                        message = "人工切换失败，原连接恢复失败：" + str(restore_msg)
                    set_state(manual_switch_active=False, pending_connection_id="", pending_connection_pool_endpoint_id="", pending_connection_protocol="", pending_connection_country="", pending_connection_address="", manual_switch_message=message)
                    ui_command_plane.finish(ui_cmd["token"], ok=False, message=message)
                    self.send_json({
                        "ok": False,
                        "auto_fallback": False,
                        "restored_previous": restored,
                        "error": message,
                        "state": get_state(),
                    }, HTTPStatus.BAD_GATEWAY)
            except Exception as exc:
                if "ui_cmd" in locals():
                    ui_command_plane.finish(ui_cmd["token"], ok=False, message=str(exc))
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/prioritize_country":
            try:
                payload = self.read_json_body()
                country = str(payload.get("country") or "").strip()
                if not country:
                    self.send_json({"ok": False, "error": "国家不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                self.send_json(start_country_priority(country))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

        elif effective_path == "/api/test_node":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "")
                if not node_id.strip():
                    self.send_json({"ok": False, "error": "节点 ID 不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                if node_id.startswith("pool:"):
                    endpoint_id = node_id.removeprefix("pool:")
                    result = probe_pool_endpoint(endpoint_id)
                    endpoint = node_pool.get_endpoint(endpoint_id)
                    node = protocol_endpoint_to_ui_node(endpoint) if endpoint else {}
                    self.send_json({"ok": bool(result.get("ok")), "node": node, "result": result}, HTTPStatus.OK)
                    return
                if not maintenance_lock.acquire(blocking=False):
                    self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                    return
                with lock:
                    if is_connecting:
                        maintenance_lock.release()
                        self.send_json({"ok": False, "error": "当前已有连接或节点维护任务正在运行，请稍后再试"}, HTTPStatus.CONFLICT)
                        return
                    is_connecting = True
                try:
                    set_state(is_connecting=True, last_check_message="正在手动测试节点可用性...")
                    updated_node = test_node_by_id(node_id)
                    self.send_json({"ok": True, "node": updated_node})
                finally:
                    with lock:
                        is_connecting = False
                    set_state(is_connecting=False)
                    maintenance_lock.release()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                self.read_request_body()
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def isatty(self) -> bool:
        return self.stdout.isatty()

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.stdout, attr)


# ========================= AimiliVPN V2 Runtime =========================
RESOURCE_COLLECTION_INTERVAL_SECONDS = 600
AVAILABILITY_TICK_SECONDS = 5
AVAILABILITY_OPENVPN_IDLE_BATCH = 10
AVAILABILITY_OPENVPN_ACTIVE_BATCH = 5
AVAILABILITY_PROTOCOL_IDLE_BATCH = 4
AVAILABILITY_PROTOCOL_ACTIVE_BATCH = 2
COUNTRY_RESERVE_TARGET = 60
COUNTRY_RESERVE_PER_BUCKET = 5
COUNTRY_PRIORITY_AVAILABLE_TARGET = 10
COUNTRY_COVERAGE_ROTATION_SECONDS = 600

resource_engine_lock = threading.Lock()
availability_engine_lock = threading.Lock()
ui_nodes_cache_lock = threading.Lock()
ui_nodes_cache = []
ui_nodes_cache_at = 0.0
ui_nodes_cache_building = False
UI_NODES_CACHE_TTL_SECONDS = 3.0
bootstrap_connection_lock = threading.Lock()
resource_engine_running = False
resource_engine_message = ""
resource_engine_last_at = 0.0
availability_engine_running = False
availability_engine_message = ""
availability_tested_total = 0
availability_queue = 0
availability_new_pending = 0
coverage_country = ""
coverage_inventory = 0
coverage_available = 0
coverage_selected = 0
coverage_target = COUNTRY_RESERVE_TARGET
coverage_last_at = 0.0
country_priority_explicit = False
initial_bootstrap_active = False

_legacy_get_state_v2 = get_state
_legacy_unified_hot_pool_candidates_v2 = unified_hot_pool_candidates

def _sanitize_ui_nodes(nodes):
    cleaned = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        item = dict(node)
        item.pop("config_text", None)
        item.pop("_pool_metadata", None)
        cleaned.append(item)
    return dedupe_ui_nodes(cleaned)

def _build_ui_nodes_cache():
    global ui_nodes_cache, ui_nodes_cache_at, ui_nodes_cache_building
    try:
        nodes = read_nodes()
        try:
            # OpenVPN is already represented by read_nodes(); Master Pool
            # contributes the additional protocols. Pull the full pool so the
            # UI cache is no longer capped at the old 5,000-endpoint window.
            for endpoint in node_pool.list_endpoints(limit=10000):
                if str(endpoint.get("protocol") or "").lower() == "openvpn":
                    continue
                pool_node = protocol_endpoint_to_ui_node(endpoint)
                if pool_node:
                    nodes.append(pool_node)
        except Exception as exc:
            log_to_json("WARNING", "Main", f"后台多协议节点快照合并失败: {exc}")
        snapshot = _sanitize_ui_nodes(nodes)
        with ui_nodes_cache_lock:
            ui_nodes_cache = snapshot
            ui_nodes_cache_at = time.time()
    except Exception as exc:
        log_to_json("WARNING", "Main", f"后台节点列表快照构建失败: {exc}")
    finally:
        ui_nodes_cache_building = False

def _detect_local_server_country():
    """Detect this server's public egress country once during first-install bootstrap."""
    urls = (
        "http://ip-api.com/json/?lang=zh-CN&fields=status,query,country,countryCode",
        "https://ipapi.co/json/",
    )
    for url in urls:
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "aimilivpn/bootstrap"})
            with urllib.request.urlopen(request, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
            if not isinstance(data, dict):
                continue
            country = str(data.get("country") or data.get("country_name") or "").strip()
            if country:
                try:
                    country = normalized_country_name(country)
                except Exception:
                    pass
                return {
                    "country": country,
                    "country_code": str(data.get("countryCode") or data.get("country_code") or "").strip().upper(),
                    "public_ip": str(data.get("query") or data.get("ip") or "").strip(),
                    "source": url,
                }
        except Exception as exc:
            log_to_json("WARNING", "Bootstrap", f"本机服务器国家探测失败: {exc}")
    return {"country": "", "country_code": "", "public_ip": "", "source": ""}

def _read_bootstrap_state():
    try:
        data = read_json(BOOTSTRAP_STATE_FILE, {})
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def _write_bootstrap_state(**updates):
    state = _read_bootstrap_state()
    state.update(updates)
    write_json(BOOTSTRAP_STATE_FILE, state)
    return state

def _first_install_bootstrap_needed():
    state = _read_bootstrap_state()
    if state.get("completed"):
        return False
    try:
        stats = node_pool.stats()
        return int(stats.get("endpoints") or 0) == 0
    except Exception:
        return not BOOTSTRAP_STATE_FILE.exists()

def _refresh_ui_nodes_cache_async(force=False):
    global ui_nodes_cache_building
    with ui_nodes_cache_lock:
        fresh = bool(ui_nodes_cache) and (time.time() - ui_nodes_cache_at) < UI_NODES_CACHE_TTL_SECONDS
        if ui_nodes_cache_building or (not force and fresh):
            return
        ui_nodes_cache_building = True
    threading.Thread(target=_build_ui_nodes_cache, daemon=True, name="ui-node-cache").start()

def _invalidate_ui_nodes_cache() -> None:
    global ui_nodes_cache, ui_nodes_cache_at, ui_nodes_cache_building
    with ui_nodes_cache_lock:
        ui_nodes_cache = []
        ui_nodes_cache_at = 0.0
        ui_nodes_cache_building = False
    _refresh_ui_nodes_cache_async(force=True)

def _sort_ui_nodes_for_page(nodes):
    """Return the same stable ranking used by the browser, but server-side.

    This lets the first 100 rows be the true first page instead of an arbitrary
    slice of a multi-thousand-node snapshot.
    """
    status_rank = {"available": 0, "testing": 1, "not_checked": 2, "unavailable": 3}
    protocol_rank = {"softether": 0, "sstp": 1, "l2tp-ipsec": 2, "openvpn": 3}
    now = time.time()

    def key(n):
        active = 0
        if active_pool_endpoint_id and n.get("pool_endpoint_id") == active_pool_endpoint_id:
            active = 0
        elif (not active_pool_endpoint_id and n.get("id") == active_openvpn_node_id):
            active = 0
        else:
            active = 1
        status = str(n.get("probe_status") or "not_checked").lower()
        manual_ts = float(n.get("manual_added_at") or 0)
        recent = 0 if manual_ts > 0 and (now - manual_ts) <= 3600 else 1
        recent_ts = -manual_ts if recent == 0 else 0
        latency = float(n.get("latency_ms") or 0)
        latency_key = latency if latency > 0 else float("inf")
        protocol = str(n.get("protocol") or "openvpn").lower()
        score = -float(n.get("score") or 0)
        return (
            active,
            status_rank.get(status, 2),
            recent,
            recent_ts,
            latency_key,
            protocol_rank.get(protocol, 9),
            score,
            str(n.get("id") or ""),
        )

    return sorted(_sanitize_ui_nodes(nodes), key=key)


def _get_ui_nodes_snapshot():
    _refresh_ui_nodes_cache_async()
    with ui_nodes_cache_lock:
        if ui_nodes_cache:
            return [dict(x) for x in ui_nodes_cache]
    return _sanitize_ui_nodes(read_nodes())


def _node_matches_ui_scope(node: dict[str, Any], country: str = "", status: str = "", protocol: str = "", ip_type: str = "") -> bool:
    country = str(country or "").strip()
    status = str(status or "").strip().lower()
    protocol = str(protocol or "").strip().lower()
    ip_type = str(ip_type or "").strip().lower()

    if country and not country_matches(node.get("country"), country):
        # A populated canonical country is authoritative. Only fall back to
        # location when the source did not provide a country at all; otherwise
        # stale/mismatched IP geolocation must never leak another country's row
        # into a scoped result.
        node_country = str(node.get("country") or "").strip()
        if node_country:
            return False
        location = str(node.get("location") or "").strip()
        if not location or not country_matches(location.split()[0], country):
            return False

    node_protocol = str(node.get("protocol") or "openvpn").strip().lower()
    if protocol and node_protocol != protocol:
        return False

    node_ip_type = str(node.get("ip_type") or "").strip().lower()
    if ip_type and node_ip_type != ip_type:
        return False

    if status == "available":
        return str(node.get("probe_status") or "").lower() == "available" or bool(node.get("active"))
    if status == "testing":
        return str(node.get("probe_status") or "").lower() == "testing"
    if status == "unavailable":
        return str(node.get("probe_status") or "").lower() == "unavailable" and not bool(node.get("active"))
    return True


def _get_ui_nodes_page(offset=0, limit=100, country="", status="", protocol="", ip_type=""):
    """Return a bounded page for the requested scope.

    The browser should never download the global pool merely to populate a
    dropdown. Country/status/protocol/IP-type selection is a server-side query;
    only the selected scope is transferred to the browser.
    """
    offset = max(0, int(offset or 0))
    limit = max(1, min(200, int(limit or 100)))

    # Do not start/build the heavyweight global UI snapshot here. The Master
    # Pool is the normal source for this endpoint, so a country/filter request
    # must remain fast and independent of global cache construction.
    with ui_nodes_cache_lock:
        building = bool(ui_nodes_cache_building)

    # Master Pool is authoritative for every UI node read, including the
    # explicit “全球国家” scope. The browser must never depend on the
    # heavyweight global snapshot being complete before filters or pages work.
    # SQLite performs the scope/count query and HTTP returns only one page.
    try:
        scoped_endpoints, endpoint_total = node_pool.list_endpoints_scoped(
            country=country,
            status=status,
            protocol=protocol,
            ip_type=ip_type,
            offset=offset,
            limit=limit,
        )
        scoped_nodes = [
            protocol_endpoint_to_ui_node(endpoint)
            for endpoint in scoped_endpoints
        ]
        scoped_nodes = _sanitize_ui_nodes([node for node in scoped_nodes if node])
        # Keep the browser-facing ranking deterministic inside the returned
        # page. The SQL query already applies the same primary status/latency
        # ordering, so we do not materialize thousands of rows in Python.
        ordered = _sort_ui_nodes_for_page(scoped_nodes)
        return ordered, endpoint_total, building
    except Exception as exc:
        log_to_json("WARNING", "Main", f"按范围读取 Master Pool UI 页面失败，回退 UI 快照: {exc}")

    # Emergency compatibility fallback for an unavailable/locked Master Pool.
    # This path is never the normal source of country/filter data.
    _refresh_ui_nodes_cache_async()
    with ui_nodes_cache_lock:
        snapshot = [dict(x) for x in ui_nodes_cache] if ui_nodes_cache else []
    if not snapshot:
        snapshot = _sanitize_ui_nodes(read_nodes())
    filtered = [n for n in snapshot if _node_matches_ui_scope(n, country, status, protocol, ip_type)]
    ordered = _sort_ui_nodes_for_page(filtered)
    total = len(ordered)
    return ordered[offset:offset + limit], total, building


def _get_ui_country_catalog(status="", protocol="", ip_type=""):
    """Return global country/IP totals without transferring global node rows."""
    status = str(status or "").strip().lower()
    protocol = str(protocol or "").strip().lower()
    ip_type = str(ip_type or "").strip().lower()
    try:
        catalog = node_pool.country_catalog(status=status, protocol=protocol, ip_type=ip_type)
    except Exception:
        catalog = {"total_ip_count": 0, "countries": {}}

    # Country/IP inventory is authoritative in Master Pool. Manual nodes are
    # promoted into the same SQLite pool when added, so the UI never has to
    # scan nodes.json or compute a second country inventory on the frontend.
    countries = dict(catalog.get("countries") or {})

    bootstrap = _read_bootstrap_state()
    server_country = str(
        bootstrap.get("local_server_country")
        or read_json(STATE_FILE, {}).get("initial_bootstrap_country")
        or ""
    ).strip()
    return {
        "total_ip_count": int(catalog.get("total_ip_count") or 0),
        "countries": countries,
        "server_country": server_country,
        "status": status,
        "protocol": protocol,
        "ip_type": ip_type,
    }


def _get_fast_nodes_state():
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
                meta = endpoint.get("server_metadata") or {}
                state["active_pool_endpoint"] = {
                    "endpoint_id": endpoint.get("endpoint_id", ""),
                    "protocol": endpoint.get("protocol", ""),
                    "transport": endpoint.get("transport", ""),
                    "port": endpoint.get("port", 0),
                    "hostname": endpoint.get("hostname", ""),
                    "current_ip": (endpoint.get("metadata") or {}).get("ip") or "",
                    "country": endpoint.get("country", ""),
                    "location": meta.get("location") or endpoint.get("country", ""),
                    "owner": meta.get("owner") or meta.get("as_name") or "",
                    "ip_type": meta.get("ip_type") or "",
                    "quality": meta.get("quality") or "",
                    "speed": endpoint.get("latest_speed", 0),
                    "latency_ms": endpoint.get("latency_ewma", 0),
                }
        except Exception:
            state["active_pool_endpoint"] = None

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
    state["is_connecting"] = is_connecting
    state["manual_connection_active"] = manual_connection_active
    state["connection_generation"] = connection_generation
    state["active_connection_generation"] = active_connection_generation
    state["manual_route_pin"] = dict(manual_route_pin)
    state["manual_connection_quiet_until"] = manual_connection_quiet_until
    state["ui_command_plane"] = ui_command_plane.ui_state()
    state["maintenance_running"] = maintenance_lock.locked()
    state["global_pool_refresh_running"] = global_pool_refresh_running
    state["global_pool_refresh_last_at"] = global_pool_refresh_last_at
    state["global_pool_refresh_status"] = global_pool_refresh_status
    state["global_pool_refresh_message"] = global_pool_refresh_message
    state["global_pool_refresh_servers"] = global_pool_refresh_servers
    state["global_pool_refresh_sources"] = global_pool_refresh_sources

    try:
        active = active_tunnel_running()
    except Exception:
        active = False
    if active:
        state["connection_status"] = "connected"
        state["connection_message"] = "当前 VPN 隧道正常运行"
        if state.get("proxy_ok") is True:
            state["client_status"] = "usable"
        elif state.get("proxy_ok") is False:
            state["client_status"] = "degraded"
        else:
            state["client_status"] = "validating"
    elif manual_connection_active or failover_lock.locked() or is_connecting:
        state["connection_status"] = "connecting"
        state["connection_message"] = "正在建立或切换 VPN 隧道"
        state["client_status"] = "validating"
    else:
        state["connection_status"] = "disconnected"
        state["connection_message"] = "当前没有活动 VPN 隧道"
        state["client_status"] = "not_connected"
    state["client_usable"] = state["client_status"] == "usable"

    state["resource_engine_running"] = bool(resource_engine_running)
    state["resource_engine_message"] = resource_engine_message
    state["resource_engine_last_at"] = resource_engine_last_at
    state["availability_engine_running"] = bool(availability_engine_running)
    state["availability_engine_message"] = availability_engine_message
    state["availability_tested_total"] = int(availability_tested_total)
    state["availability_queue"] = int(availability_queue)
    state["availability_new_pending"] = int(availability_new_pending)
    state["availability_recheck_seconds"] = 4 * 3600
    state["coverage_country"] = coverage_country
    state["coverage_inventory"] = int(coverage_inventory)
    state["coverage_available"] = int(coverage_available)
    state["coverage_selected"] = int(coverage_selected)
    state["coverage_target"] = int(coverage_target)
    state["coverage_last_at"] = coverage_last_at
    proxy_state = _upstream_proxy_state()
    state["upstream_proxy_mode"] = proxy_state["mode"]
    state["upstream_proxy_type"] = proxy_state["type"]
    state["upstream_proxy_host"] = proxy_state["host"]
    state["upstream_proxy_port"] = proxy_state["port"]
    state["upstream_proxy_label"] = proxy_state["label"]
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("favorite_node_ids", [])
    return state

def _runtime_connection_status():
    if active_tunnel_running():
        return "connected", "当前 VPN 隧道正常运行"
    if manual_connection_active or failover_lock.locked():
        return "connecting", "正在建立或切换 VPN 隧道"
    return "disconnected", "当前没有活动 VPN 隧道"

def _runtime_client_status():
    if not active_tunnel_running():
        return "not_connected"
    state = _legacy_get_state_v2()
    if state.get("proxy_ok") is True:
        return "usable"
    if state.get("proxy_ok") is False:
        return "degraded"
    return "validating"

def _upstream_proxy_state():
    try:
        ptype, host, port = vpn_utils.get_upstream_proxy()
    except Exception:
        ptype = host = port = None
    if host and port:
        return {"mode":"custom_upstream","type":str(ptype or ""), "host":str(host), "port":int(port),
                "label":f"自定义上游代理 · {ptype or 'proxy'}://{host}:{port}"}
    return {"mode":"system_default","type":"","host":"","port":0,"label":"系统默认网络（未设置自定义上游代理）"}


def _endpoint_country(endpoint):
    return normalized_country_name(endpoint.get("country") or "")

def _endpoint_ip(endpoint):
    return str(endpoint.get("current_ip") or (endpoint.get("metadata") or {}).get("ip") or "").strip()

def _endpoint_ip_type(endpoint):
    m=endpoint.get("server_metadata") or {}
    value=str(m.get("ip_type") or (endpoint.get("metadata") or {}).get("ip_type") or "").lower()
    return value if value in ("residential","mobile","hosting") else "unknown"

def country_reserve_snapshot(country, target=COUNTRY_RESERVE_TARGET):
    target_country=normalized_country_name(country)
    if not target_country:
        return {"country":"","inventory":0,"available":0,"selected":0,"target":0,"selected_endpoints":[]}
    all_items=[]
    available_items=[]
    for ep in node_pool.list_endpoints(limit=5000):
        if _endpoint_country(ep)!=target_country:
            continue
        if not _endpoint_ip(ep):
            continue
        status=str(ep.get("status") or "").upper()
        if status in ("RETIRED","STALE"):
            continue
        all_items.append(ep)
        if status in ("HOT","AVAILABLE"):
            ep["selection_score"]=node_pool._selection_score(ep)[0]
            available_items.append(ep)

    inventory={_endpoint_ip(x) for x in all_items if _endpoint_ip(x)}
    available_ips={_endpoint_ip(x) for x in available_items if _endpoint_ip(x)}
    selected=[]; used=set()
    for protocol in ("openvpn","softether","sstp","l2tp-ipsec"):
        for ip_type in ("residential","mobile","hosting"):
            bucket=[x for x in available_items if str(x.get("protocol") or "").lower()==protocol and _endpoint_ip_type(x)==ip_type and _endpoint_ip(x) not in used]
            bucket.sort(key=lambda x:(-float(x.get("selection_score") or 0),float(x.get("latency_ewma") or 999999),-int(x.get("success_streak") or 0)))
            taken=0
            for ep in bucket:
                ip=_endpoint_ip(ep)
                if not ip or ip in used:
                    continue
                selected.append(ep); used.add(ip); taken+=1
                if taken>=COUNTRY_RESERVE_PER_BUCKET or len(selected)>=target:
                    break
            if len(selected)>=target:
                break
        if len(selected)>=target:
            break
    if len(selected)<target:
        rest=[x for x in available_items if _endpoint_ip(x) not in used]
        rest.sort(key=lambda x:(-float(x.get("selection_score") or 0),float(x.get("latency_ewma") or 999999),-int(x.get("success_streak") or 0)))
        for ep in rest:
            ip=_endpoint_ip(ep)
            if not ip or ip in used:
                continue
            selected.append(ep); used.add(ip)
            if len(selected)>=target:
                break
    return {"country":target_country,"inventory":len(inventory),"available":len(available_ips),"selected":len(selected),
            "target":min(int(target),max(1,len(inventory))) if inventory else 0,"selected_endpoints":selected[:int(target)]}

def _pick_global_country_for_coverage_v2():
    snapshot=_global_country_pool_snapshot(); now=time.time(); ranked=[]
    for country,values in snapshot.items():
        inventory=len(values.get("inventory") or set()); available=len(values.get("available") or set())
        if inventory<=0: continue
        target=min(COUNTRY_RESERVE_TARGET,inventory)
        if available>=target: continue
        last=float(global_country_coverage_last_attempt.get(country,0) or 0)
        if now-last<COUNTRY_COVERAGE_ROTATION_SECONDS: continue
        ranked.append((-(target-available)/max(1,target),-inventory,last,country))
    ranked.sort()
    return ranked[0][3] if ranked else ""



def _due_endpoints(country="", protocols=("openvpn","softether","sstp","l2tp-ipsec"), limit=10):
    now=time.time(); target=normalized_country_name(country); wanted={str(x).lower() for x in protocols}; rows=[]
    for ep in node_pool.list_endpoints(limit=5000):
        protocol=str(ep.get("protocol") or "").lower(); status=str(ep.get("status") or "").upper()
        if protocol not in wanted or status in ("RETIRED","STALE"): continue
        if target and _endpoint_country(ep)!=target: continue
        if float(ep.get("next_test") or 0)>now: continue
        rows.append(ep)
    rows.sort(key=lambda x:(0 if str(x.get("status") or "").upper()=="NEW" else 1,float(x.get("next_test") or 0),float(x.get("last_success") or 0)))
    return rows[:max(1,min(int(limit),5000))]

def _due_counts():
    rows=_due_endpoints("",("openvpn","softether","sstp","l2tp-ipsec"),5000)
    return sum(1 for x in rows if str(x.get("protocol") or "").lower()=="openvpn"),sum(1 for x in rows if str(x.get("protocol") or "").lower()!="openvpn")

def _finish_priority_if_ready(country):
    global country_priority_request,country_priority_explicit
    if not country_priority_explicit or not country: return
    snap=country_reserve_snapshot(country); available=int(snap.get("available") or 0); inventory=int(snap.get("inventory") or 0)
    if available>=COUNTRY_PRIORITY_AVAILABLE_TARGET:
        set_state(priority_country=country,priority_inventory=inventory,priority_inventory_target=min(60,max(1,inventory)),priority_available=COUNTRY_PRIORITY_AVAILABLE_TARGET,
                  priority_target=COUNTRY_PRIORITY_AVAILABLE_TARGET,priority_minimum=5,priority_running=False,priority_message=f"{country} 已达到 {COUNTRY_PRIORITY_AVAILABLE_TARGET} 个可用节点")
        country_priority_request=""; country_priority_explicit=False
    elif not _due_endpoints(country,("openvpn","softether","sstp","l2tp-ipsec"),1):
        set_state(priority_country=country,priority_inventory=inventory,priority_inventory_target=min(60,max(1,inventory)) if inventory else 60,
                  priority_available=min(COUNTRY_PRIORITY_AVAILABLE_TARGET,available),priority_target=COUNTRY_PRIORITY_AVAILABLE_TARGET,
                  priority_minimum=5,priority_running=False,priority_message=f"{country} 当前资源已完成检测，可用 {available}；等待新资源自动进入")
        country_priority_request=""; country_priority_explicit=False

def availability_sweep_once(priority_country=""):
    global availability_engine_running,availability_engine_message,availability_tested_total,availability_queue,availability_new_pending
    if manual_connection_active or failover_lock.locked() or is_connecting: return {"ok":True,"skipped":True,"reason":"用户连接或主备切换进行中"}
    if not availability_engine_lock.acquire(blocking=False): return {"ok":True,"running":True}
    availability_engine_running=True
    try:
        active=active_tunnel_running()
        ov_limit=AVAILABILITY_OPENVPN_ACTIVE_BATCH if active else AVAILABILITY_OPENVPN_IDLE_BATCH
        pool_limit=AVAILABILITY_PROTOCOL_ACTIVE_BATCH if active else AVAILABILITY_PROTOCOL_IDLE_BATCH
        priority=normalized_country_name(priority_country)
        priority_ov=_due_endpoints(priority,("openvpn",),min(5,ov_limit)) if priority else []
        priority_pool=_due_endpoints(priority,("softether","sstp","l2tp-ipsec"),min(3,pool_limit)) if priority else []
        selected_ov=[]; selected_pool=[]; seen=set()
        for ep in priority_ov+_due_endpoints("",("openvpn",),ov_limit):
            eid=str(ep.get("endpoint_id") or "")
            if not eid or eid in seen: continue
            seen.add(eid); selected_ov.append(ep)
            if len(selected_ov)>=ov_limit: break
        seen=set()
        for ep in priority_pool+_due_endpoints("",("softether","sstp","l2tp-ipsec"),pool_limit):
            eid=str(ep.get("endpoint_id") or "")
            if not eid or eid in seen: continue
            seen.add(eid); selected_pool.append(ep)
            if len(selected_pool)>=pool_limit: break
        availability_queue=len(selected_ov)+len(selected_pool)
        availability_new_pending=sum(1 for ep in selected_ov+selected_pool if str(ep.get("status") or "").upper()=="NEW")
        availability_engine_message=f"可用性检测中 · 新资源优先 · OpenVPN {len(selected_ov)} · 多协议 {len(selected_pool)} · 全球资源最长 4 小时复检"
        set_state(availability_engine_running=True,availability_engine_message=availability_engine_message,availability_queue=availability_queue,availability_new_pending=availability_new_pending)
        tested=0
        ids=[str((ep.get("metadata") or {}).get("node_id") or "") for ep in selected_ov]
        ids=[x for x in ids if x]
        if ids:
            try: tested+=len(test_multiple_nodes(ids))
            except Exception as exc: log_to_json("WARNING","Probe",f"V2 OpenVPN 批量检测失败: {exc}")
        if selected_pool:
            workers=min(4 if not active else 2,len(selected_pool))
            def one(ep):
                eid=str(ep.get("endpoint_id") or "")
                return probe_pool_endpoint(eid) if eid else {"skipped":True}
            with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,workers)) as ex:
                futs=[ex.submit(one,ep) for ep in selected_pool]
                for fut in concurrent.futures.as_completed(futs):
                    try:
                        if not fut.result().get("skipped"): tested+=1
                    except Exception as exc: log_to_json("WARNING","Probe",f"V2 多协议探测异常: {exc}")
        availability_tested_total+=tested
        if (not initial_bootstrap_active and not active_tunnel_running()
                and not manual_connection_active and bool(load_ui_config().get("connection_enabled", True))):
            threading.Thread(target=_ensure_active_client_v2, daemon=True).start()
        ov_due,pool_due=_due_counts()
        set_state(availability_engine_running=False,
                  availability_engine_message=f"本轮已检测 {tested} 个 · 待检测 OpenVPN {ov_due} / 多协议 {pool_due} · 后台继续运行",
                  availability_tested_total=availability_tested_total,availability_queue=ov_due+pool_due,availability_new_pending=0)
        if priority: _finish_priority_if_ready(priority)
        return {"ok":True,"tested":tested,"openvpn_due":ov_due,"protocol_due":pool_due}
    except Exception as exc:
        set_state(availability_engine_running=False,availability_engine_message=f"可用性检测异常：{exc}",availability_queue=0)
        log_to_json("ERROR","Probe",f"V2 可用性检测异常: {exc}")
        return {"ok":False,"error":str(exc)}
    finally:
        availability_engine_running=False
        availability_engine_lock.release()


def resource_collect_once(force=False):
    global resource_engine_running,resource_engine_message,resource_engine_last_at
    if ui_command_plane.is_busy() and not force:
        return {"ok": True, "skipped": True, "reason": "用户正在执行前端指令"}
    if manual_connection_active and not force:
        return {"ok":True,"skipped":True,"reason":"用户正在手动切换节点"}
    if not resource_engine_lock.acquire(blocking=False): return {"ok":True,"running":True}
    resource_engine_running=True
    resource_engine_message="正在采集资源，不影响当前 VPN 连接"
    set_state(resource_engine_running=True,resource_engine_message=resource_engine_message)
    try:
        before=int(node_pool.stats().get("endpoints") or 0)
        try: candidates=fetch_candidates()
        except Exception as exc:
            candidates=[]; log_to_json("WARNING","Main",f"V2 OpenVPN 资源采集失败: {exc}")
        catalog=refresh_multi_protocol_catalog(force=True)
        after=int(node_pool.stats().get("endpoints") or 0)
        resource_engine_last_at=time.time(); added=max(0,after-before)
        resource_engine_message=f"资源采集完成 · OpenVPN {len(candidates)} · 多协议服务器 {int(catalog.get('servers') or 0)} · 新增/恢复约 {added} 个端点，立即进入检测"
        _refresh_ui_nodes_cache_async(force=True)
        set_state(resource_engine_running=False,resource_engine_message=resource_engine_message,resource_engine_last_at=resource_engine_last_at,
                  last_fetch_at=resource_engine_last_at,last_fetch_status="ok",last_fetch_message=resource_engine_message)
        return {"ok":True,"endpoints":after,"added":added}
    except Exception as exc:
        resource_engine_message=f"资源采集异常：{exc}"
        set_state(resource_engine_running=False,resource_engine_message=resource_engine_message)
        log_to_json("ERROR","Main",resource_engine_message)
        return {"ok":False,"error":str(exc)}
    finally:
        resource_engine_running=False
        resource_engine_lock.release()





def _switch_candidates_with_favorites_fallback(ui_cfg,exclude_endpoint_id="",limit=30):
    candidates=_legacy_unified_hot_pool_candidates_v2(ui_cfg,exclude_endpoint_id=exclude_endpoint_id,limit=limit)
    if candidates: return candidates,False
    if ui_cfg.get("routing_mode")=="favorites" and bool(ui_cfg.get("fav_fail_fallback",True)):
        fallback=dict(ui_cfg); fallback["routing_mode"]="auto"; fallback["favorite_node_ids"]=[]
        return _legacy_unified_hot_pool_candidates_v2(fallback,exclude_endpoint_id=exclude_endpoint_id,limit=limit),True
    return [],False


def _ensure_active_client_v2():
    if active_tunnel_running() or manual_connection_active or failover_lock.locked() or is_connecting:
        return
    ui_cfg=load_ui_config()
    if not bool(ui_cfg.get("connection_enabled",True)):
        return
    if not bootstrap_connection_lock.acquire(blocking=False):
        return
    try:
        if ui_cfg.get("routing_mode") == "fixed_ip":
            reconnect_fixed_node_if_needed(ui_cfg)
        else:
            auto_switch_node()
    except Exception as exc:
        log_to_json("WARNING","VPN",f"启动/恢复活动 VPN 失败: {exc}")
    finally:
        bootstrap_connection_lock.release()

def startup_recovery_loop():
    """Independent boot/restart recovery; never depends on resource collection."""
    time.sleep(5)
    while True:
        try:
            if (
                not initial_bootstrap_active
                and not global_pool_refresh_running
                and not ui_command_plane.is_busy()
                and not manual_connection_active
                and not is_connecting
                and bool(load_ui_config().get("connection_enabled", True))
                and not active_tunnel_running()
            ):
                set_state(last_check_message="启动恢复：正在从已验证节点中选择最佳备用节点...")
                _ensure_active_client_v2()
        except Exception as exc:
            log_to_json("WARNING", "VPN", f"启动恢复守护异常: {exc}")
        time.sleep(15)



def _initial_bootstrap_candidate(local_country):
    temp_cfg = {
        "routing_mode": "fixed_region",
        "force_country": str(local_country or "").strip(),
        "routing_ip_type": "all",
        "connection_enabled": True,
    }
    candidates = unified_hot_pool_candidates(temp_cfg, limit=100)
    target = normalized_country_name(local_country)
    if target:
        local = [x for x in candidates if normalized_country_name(x.get("country")) == target]
        if local:
            return local[0], "local_country"
    return (candidates[0], "global_fallback") if candidates else (None, "")

def initial_install_bootstrap_loop():
    global initial_bootstrap_active
    if not _first_install_bootstrap_needed():
        if not _read_bootstrap_state().get("completed"):
            _write_bootstrap_state(completed=True, completed_at=time.time(), mode="existing_install_detected")
        return
    initial_bootstrap_active = True
    detected = _detect_local_server_country()
    local_country = str(detected.get("country") or "").strip()
    _write_bootstrap_state(
        started_at=time.time(),
        completed=False,
        local_server_country=local_country,
        local_server_country_code=str(detected.get("country_code") or ""),
        local_server_public_ip=str(detected.get("public_ip") or ""),
        detection_source=str(detected.get("source") or ""),
    )
    set_state(
        initial_bootstrap_running=True,
        initial_bootstrap_country=local_country,
        initial_bootstrap_public_ip=str(detected.get("public_ip") or ""),
        last_check_message=(
            f"首次安装初始化：正在获取资源并检测"
            + (f"，本机服务器位于 {local_country}" if local_country else "")
        ),
    )
    try:
        try:
            resource_collect_once(force=True)
        except Exception as exc:
            log_to_json("WARNING", "Bootstrap", f"首次安装资源获取启动失败: {exc}")
        try:
            if local_country:
                availability_sweep_once(local_country)
            else:
                availability_sweep_once("")
        except Exception as exc:
            log_to_json("WARNING", "Bootstrap", f"首次安装初始可用性检测失败: {exc}")

        deadline = time.time() + 15 * 60
        while time.time() < deadline and not active_tunnel_running():
            if not bool(load_ui_config().get("connection_enabled", True)):
                break
            candidate, reason = (None, "")
            try:
                candidate, reason = _initial_bootstrap_candidate(local_country)
            except Exception as exc:
                log_to_json("WARNING", "Bootstrap", f"首次安装候选节点选择失败: {exc}")
            if candidate:
                try:
                    set_state(
                        initial_bootstrap_running=True,
                        initial_bootstrap_country=local_country,
                        last_check_message=(
                            f"首次安装自动连接：优先 {local_country or '本机国家'}，"
                            f"正在连接最低延迟节点 {candidate.get('protocol','')} "
                            f"{candidate.get('current_ip') or candidate.get('hostname') or candidate.get('endpoint_id')}"
                        ),
                    )
                    connect_ranked_endpoint(candidate, manual=False)
                    _write_bootstrap_state(
                        completed=True,
                        completed_at=time.time(),
                        selected_endpoint=str(candidate.get("endpoint_id") or ""),
                        selected_country=str(candidate.get("country") or ""),
                        selection_reason=reason,
                    )
                    set_state(
                        initial_bootstrap_running=False,
                        initial_bootstrap_completed=True,
                        initial_bootstrap_country=local_country,
                        last_check_message=(
                            f"首次安装初始化完成：已自动连接 "
                            f"{candidate.get('country') or local_country or '最佳节点'}，"
                            "现在进入资源采集、可用性检测与 4 小时复检维护。"
                        ),
                    )
                    return
                except Exception as exc:
                    log_to_json("WARNING", "Bootstrap", f"首次安装自动连接失败: {candidate.get('endpoint_id')}: {exc}")
            time.sleep(5)

        _write_bootstrap_state(
            completed=True,
            completed_at=time.time(),
            selection_reason="no_verified_local_candidate",
        )
        set_state(
            initial_bootstrap_running=False,
            initial_bootstrap_completed=True,
            initial_bootstrap_country=local_country,
            last_check_message=(
                "首次安装初始化完成，但暂时没有经过验证的本国节点；"
                "后台资源与可用性检测将继续运行，获得可用节点后自动连接。"
            ),
        )
    except Exception as exc:
        log_to_json("ERROR", "Bootstrap", f"首次安装初始化异常: {exc}")
        _write_bootstrap_state(completed=True, completed_at=time.time(), selection_reason="bootstrap_exception")
        set_state(initial_bootstrap_running=False, initial_bootstrap_completed=True, last_check_message=f"首次安装初始化异常：{exc}")
    finally:
        initial_bootstrap_active = False



OPENVPN_LATENCY_MIGRATION_MARKER = DATA_DIR / "openvpn_latency_metrics_v2.json"


def migrate_openvpn_latency_metrics() -> None:
    """Remove persisted OpenVPN latency values that were not proven by a live tunnel."""
    try:
        marker = read_json(OPENVPN_LATENCY_MIGRATION_MARKER, {})
        marker_version = int(marker.get("version") or 0) if isinstance(marker, dict) else 0
        if marker_version >= 3:
            return

        reset_count = 0
        if marker_version < 2:
            reset_count = node_pool.reset_openvpn_latency_metrics()

        nodes = read_nodes()
        changed = 0
        for node in nodes:
            if str(node.get("protocol") or "openvpn").lower() != "openvpn":
                continue

            status = str(node.get("probe_status") or "not_checked").lower()
            # Any non-available OpenVPN row must never display or retain a latency.
            # In particular, failed AUTH/TLS attempts can have an elapsed duration,
            # but that duration is not a usable latency metric.
            if status != "available" and parse_int(node.get("latency_ms")) != 0:
                node["latency_ms"] = 0
                changed += 1

            # pool_rehydrated rows can carry the old Master-Pool latency into the UI.
            if node.get("pool_rehydrated") and status != "available":
                node["latency_ms"] = 0
                node["probe_message"] = "历史资源已重置，等待真实 OpenVPN 隧道测速"
                node["probed_at"] = 0

        if changed:
            write_json(NODES_FILE, sort_all_nodes(nodes))

        write_json(
            OPENVPN_LATENCY_MIGRATION_MARKER,
            {
                "version": 3,
                "completed_at": time.time(),
                "db_rows_reset": reset_count,
                "nodes_reset": changed,
            },
        )
        log_to_json(
            "INFO",
            "Main",
            f"已完成 OpenVPN 延迟可信度迁移：重置 {reset_count} 个 Master Pool 端点、清理 {changed} 个非可用节点的延迟值；后续延迟只采用真实隧道测速。",
        )
    except Exception as exc:
        log_to_json("ERROR", "Main", f"OpenVPN 延迟可信度迁移失败：{exc}")


def resume_web_certificate_if_needed() -> None:
    try:
        cfg = load_ui_config()
        domain = str(cfg.get("web_domain") or "").strip()
        if not domain:
            return
        cert = web_certificate.snapshot()
        status = str(cert.get("status") or "")
        cert_domain = str(cert.get("domain") or "").strip()
        should_resume = (
            status in ("issuing", "installing", "interrupted")
            or (status == "not_configured" and cert_domain != domain)
        )
        if not should_resume:
            return

        def resume() -> None:
            try:
                web_certificate.start(domain, resume=True)
            except Exception as exc:
                log_to_json("ERROR", "WebSSL", f"HTTPS 证书任务自动恢复失败：{domain} · {exc}")

        threading.Timer(1.5, resume).start()
        log_to_json("INFO", "WebSSL", f"已检测到 HTTPS 证书任务需要恢复：{domain}")
    except Exception as exc:
        log_to_json("ERROR", "WebSSL", f"HTTPS 证书启动检查失败：{exc}")


def main() -> None:
    ensure_dirs()
    migrate_openvpn_latency_metrics()
    if not ISOLATED_INSTANCE:
        kill_existing_openvpn_processes()

    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{'[' + LOCAL_PROXY_HOST + ']' if ':' in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": True,
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
            "isolated_instance": ISOLATED_INSTANCE,
            "background_loops_disabled": DISABLE_BACKGROUND_LOOPS,
            "collector_loop_enabled": ENABLE_COLLECTOR_LOOP,
            "proxy_health_loop_enabled": ENABLE_PROXY_HEALTH_LOOP,
            "fast_liveness_loop_enabled": ENABLE_FAST_LIVENESS_LOOP,
            "fast_liveness_interval_seconds": FAST_LIVENESS_INTERVAL_SECONDS,
            "pinger_loop_enabled": ENABLE_PINGER_LOOP,
            "protocol_probe_loop_enabled": ENABLE_PROTOCOL_PROBE_LOOP,
            "active_route_table": ACTIVE_ROUTE_TABLE,
            "proxy_health_interval_seconds": PROXY_HEALTH_INTERVAL_SECONDS,
            "proxy_health_confirm_delay_seconds": PROXY_HEALTH_CONFIRM_DELAY_SECONDS,
            "failover_in_progress": False,
            "last_failover_ok": None,
            "last_failover_duration_ms": 0,
            "priority_country": "",
            "priority_inventory": 0,
            "priority_inventory_target": COUNTRY_INVENTORY_TARGET,
            "priority_available": 0,
            "priority_target": COUNTRY_AVAILABLE_TARGET,
            "priority_minimum": COUNTRY_AVAILABLE_MIN,
            "priority_running": False,
            "priority_message": "",
        },
    )
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()

    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    for _ in range(30):
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(0.5)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                s.connect((connect_host, LOCAL_PROXY_PORT))
                gateway_ready = True
                break
            except Exception:
                if connect_host == "::1":
                    try:
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        gateway_ready = True
                        break
                    except Exception:
                        pass
                raise
        except Exception:
            time.sleep(0.5)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)

    enabled_loops: list[str] = []
    if ENABLE_COLLECTOR_LOOP:
        threading.Thread(target=collector_loop, daemon=True).start()
        enabled_loops.append("collector")
    if ENABLE_PROXY_HEALTH_LOOP:
        threading.Thread(target=background_proxy_checker, daemon=True).start()
        enabled_loops.append("proxy-health")
    if ENABLE_FAST_LIVENESS_LOOP:
        threading.Thread(target=fast_tunnel_liveness_loop, daemon=True).start()
        enabled_loops.append("fast-liveness")
    if ENABLE_PINGER_LOOP:
        threading.Thread(target=active_node_pinger, daemon=True).start()
        enabled_loops.append("pinger")
    if not ISOLATED_INSTANCE:
        threading.Thread(target=protocol_catalog_loop, daemon=True).start()
        enabled_loops.append("protocol-catalog")
        threading.Thread(target=resource_share_loop, daemon=True).start()
        enabled_loops.append("resource-share")
        threading.Thread(target=global_country_coverage_loop, daemon=True).start()
        enabled_loops.append("country-coverage")
    if ENABLE_PROTOCOL_PROBE_LOOP:
        threading.Thread(target=protocol_probe_loop, daemon=True).start()
        enabled_loops.append("protocol-probe")

    threading.Thread(target=startup_recovery_loop, daemon=True, name="startup-recovery").start()
    enabled_loops.append("startup-recovery")

    # First installation is a one-time bootstrap only when the persistent pool
    # is empty. Existing installations keep their saved routing preferences.
    if _first_install_bootstrap_needed():
        threading.Thread(target=initial_install_bootstrap_loop, daemon=True, name="initial-bootstrap").start()
        enabled_loops.append("initial-bootstrap")
    elif not _read_bootstrap_state().get("completed"):
        _write_bootstrap_state(completed=True, completed_at=time.time(), mode="existing_install_detected")

    if ISOLATED_INSTANCE:
        print(f"[隔离实例] 已启用后台循环: {', '.join(enabled_loops) if enabled_loops else '无'}", flush=True)

    ui_cfg = load_ui_config()
    resume_web_certificate_if_needed()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = bounded_int(ui_cfg.get("port"), UI_PORT, 1, 65535)

    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    DualStackHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()