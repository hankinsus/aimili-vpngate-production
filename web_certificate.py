from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable


class WebCertificateManager:
    """Manage an optional Let's Encrypt certificate for the public 8443 UI."""

    def __init__(
        self,
        state_file: Path,
        tls_dir: Path = Path("/etc/aimilivpn/tls"),
        nginx_conf: Path = Path("/etc/nginx/conf.d/aimilivpn-production.conf"),
        log_fn: Callable[[str], None] | None = None,
    ) -> None:
        self.state_file = Path(state_file)
        self.tls_dir = Path(tls_dir)
        self.nginx_conf = Path(nginx_conf)
        self.fullchain = self.tls_dir / "fullchain.pem"
        self.privkey = self.tls_dir / "privkey.pem"
        self.selfsigned_fullchain = self.tls_dir / "selfsigned-fullchain.pem"
        self.selfsigned_privkey = self.tls_dir / "selfsigned-privkey.pem"
        self.lock = threading.Lock()
        self.running = False
        self.log_fn = log_fn or (lambda _message: None)

    @staticmethod
    def normalize_domain(value: Any) -> str:
        domain = str(value or "").strip().rstrip(".").lower()
        if not domain:
            return ""
        if len(domain) > 253 or "." not in domain:
            raise ValueError("域名必须是公网可解析的完整域名，例如 vpn.example.com")
        if domain.startswith("*.") or "*" in domain:
            raise ValueError("暂不支持通配符域名，请填写具体子域名")
        labels = domain.split(".")
        if len(labels) < 2:
            raise ValueError("域名格式无效")
        for label in labels:
            if not label or len(label) > 63:
                raise ValueError("域名格式无效")
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
                raise ValueError("域名只能包含英文字母、数字和连字符")
        return domain

    def _log(self, message: str) -> None:
        try:
            self.log_fn(message)
        except Exception:
            pass

    def _read_state(self) -> dict[str, Any]:
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {
            "status": "not_configured",
            "domain": "",
            "message": "尚未配置 HTTPS 域名",
            "expires_at": 0,
            "issuer": "",
            "updated_at": 0,
            "last_error": "",
        }

    def _write_state(self, **updates: Any) -> dict[str, Any]:
        state = self._read_state()
        state.update(updates)
        state["updated_at"] = time.time()
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        temp = self.state_file.with_suffix(".tmp")
        temp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temp, self.state_file)
        return state

    def snapshot(self) -> dict[str, Any]:
        state = self._read_state()
        state["running"] = bool(self.running)
        if state.get("status") == "issuing" and not self.running:
            state["status"] = "interrupted"
            state["message"] = "上一次证书申请任务在服务重启时中断，请重新保存域名。"
        if not state.get("domain"):
            state["status"] = "not_configured"
        return state

    def _acme_bin(self) -> str:
        candidates = [
            os.environ.get("ACME_SH", ""),
            "/root/.acme.sh/acme.sh",
            shutil.which("acme.sh") or "",
        ]
        for candidate in candidates:
            if candidate and Path(candidate).exists() and os.access(candidate, os.X_OK):
                return candidate
        raise RuntimeError("服务器未找到 acme.sh，无法自动申请 Let's Encrypt 证书")

    @staticmethod
    def _run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    @staticmethod
    def _tail_output(result: subprocess.CompletedProcess[str], limit: int = 1200) -> str:
        text = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        return text[-limit:] if text else "命令无输出"

    @staticmethod
    def _port_available(port: int) -> bool:
        checks = [
            (socket.AF_INET, ("0.0.0.0", port)),
            (socket.AF_INET6, ("::", port)),
        ]
        for family, address in checks:
            sock = socket.socket(family, socket.SOCK_STREAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(address)
            except OSError:
                return False
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        return True

    def _cert_meta(self) -> dict[str, Any]:
        if not self.fullchain.exists():
            return {"expires_at": 0, "issuer": "", "subject": ""}
        try:
            result = self._run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(self.fullchain),
                    "-noout",
                    "-enddate",
                    "-issuer",
                    "-subject",
                ],
                5,
            )
            if result.returncode != 0:
                return {"expires_at": 0, "issuer": "", "subject": ""}
            values: dict[str, str] = {}
            for line in (result.stdout or "").splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip()
            expires_at = 0
            raw_expiry = values.get("notAfter", "")
            if raw_expiry:
                try:
                    expires_at = int(
                        subprocess.check_output(
                            ["date", "-d", raw_expiry, "+%s"],
                            text=True,
                            timeout=3,
                        ).strip()
                    )
                except Exception:
                    expires_at = 0
            return {
                "expires_at": expires_at,
                "issuer": values.get("issuer", ""),
                "subject": values.get("subject", ""),
            }
        except Exception:
            return {"expires_at": 0, "issuer": "", "subject": ""}

    def _ensure_selfsigned_backup(self) -> None:
        self.tls_dir.mkdir(parents=True, exist_ok=True)
        if self.fullchain.exists() and self.privkey.exists():
            if not self.selfsigned_fullchain.exists():
                shutil.copy2(self.fullchain, self.selfsigned_fullchain)
            if not self.selfsigned_privkey.exists():
                shutil.copy2(self.privkey, self.selfsigned_privkey)

    def _write_nginx_config(self, domain: str) -> None:
        server_name = domain or "_"
        config = f"""# AimiliVPN public HTTPS management gateway
# 8443: HTTPS management UI -> 127.0.0.1:8501
#
# When web_domain is configured, the same certificate is served on 8443 and the
# browser can validate the certificate for that hostname. The IP address is
# intentionally still accepted as a fallback, but browsers will warn on IP use.

server {{
    listen 8443 ssl;
    server_name {server_name};

    ssl_certificate     {self.fullchain};
    ssl_certificate_key {self.privkey};
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 100m;

    # Manual node switching is make-before-break and may take several checks
    # when a candidate needs a fallback. Keep the reverse proxy connection alive
    # long enough for the backend to return its final JSON state.
    proxy_connect_timeout 15s;
    proxy_send_timeout 900s;
    proxy_read_timeout 900s;

    location / {{
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Port 8443;
        proxy_read_timeout 900s;
        proxy_send_timeout 900s;
    }}
}}
"""
        self.nginx_conf.parent.mkdir(parents=True, exist_ok=True)
        temp = self.nginx_conf.with_suffix(".tmp")
        temp.write_text(config, encoding="utf-8")
        os.replace(temp, self.nginx_conf)

    def _reload_nginx(self) -> None:
        test = self._run(["nginx", "-t"], 10)
        if test.returncode != 0:
            raise RuntimeError(f"Nginx 配置检测失败：{self._tail_output(test)}")
        reload_result = self._run(["systemctl", "reload", "nginx"], 20)
        if reload_result.returncode != 0:
            reload_result = self._run(["nginx", "-s", "reload"], 20)
        if reload_result.returncode != 0:
            raise RuntimeError(f"Nginx 重载失败：{self._tail_output(reload_result)}")

    def _ensure_acme_cron(self, acme: str) -> None:
        result = self._run([acme, "--install-cronjob"], 15)
        if result.returncode != 0:
            self._log(f"acme.sh 自动续期任务安装失败：{self._tail_output(result, 700)}")

    def start(self, domain: str) -> dict[str, Any]:
        domain = self.normalize_domain(domain)
        if not domain:
            return self.disable()

        with self.lock:
            if self.running:
                current = self.snapshot()
                current.update({"ok": True, "status": "running", "message": "已有 HTTPS 证书申请任务正在执行"})
                return current
            self.running = True
            self._write_state(
                status="issuing",
                domain=domain,
                message="正在校验域名并准备申请 90 天 HTTPS 证书…",
                last_error="",
            )
        thread = threading.Thread(
            target=self._worker,
            args=(domain,),
            daemon=True,
            name="web-certificate",
        )
        thread.start()
        result = self.snapshot()
        result.update({
            "ok": True,
            "status": "issuing",
            "message": "证书申请已启动：正在验证域名、申请 Let's Encrypt 证书并更新 Nginx。",
        })
        return result

    def disable(self) -> dict[str, Any]:
        with self.lock:
            self.running = False
        try:
            self._ensure_selfsigned_backup()
            if self.selfsigned_fullchain.exists() and self.selfsigned_privkey.exists():
                shutil.copy2(self.selfsigned_fullchain, self.fullchain)
                shutil.copy2(self.selfsigned_privkey, self.privkey)
            self._write_nginx_config("")
            self._reload_nginx()
            state = self._write_state(
                status="not_configured",
                domain="",
                message="HTTPS 域名证书未启用，当前使用服务器自带证书。",
                expires_at=0,
                issuer="",
                last_error="",
            )
            return {"ok": True, **state, "running": False}
        except Exception as exc:
            state = self._write_state(
                status="error",
                domain="",
                message="清除 HTTPS 域名配置失败",
                last_error=str(exc),
            )
            return {"ok": False, **state, "running": False, "error": str(exc)}

    def _worker(self, domain: str) -> None:
        try:
            self._write_state(
                status="issuing",
                domain=domain,
                message="正在检查服务器 ACME 环境与 80 端口…",
                last_error="",
            )
            result = self._provision(domain)
            self._write_state(
                status="active",
                domain=domain,
                message=result["message"],
                expires_at=result["expires_at"],
                issuer=result["issuer"],
                last_error="",
            )
            self._log(f"HTTPS 证书配置成功：{domain}，到期时间 {result['expires_at'] or '未知'}")
        except Exception as exc:
            self._write_state(
                status="error",
                domain=domain,
                message="HTTPS 证书申请失败",
                last_error=str(exc),
            )
            self._log(f"HTTPS 证书申请失败：{domain} · {exc}")
        finally:
            with self.lock:
                self.running = False

    def _provision(self, domain: str) -> dict[str, Any]:
        acme = self._acme_bin()
        self._ensure_selfsigned_backup()

        current = self._read_state()
        meta = self._cert_meta()
        # Reuse a still-valid certificate for the same domain instead of
        # needlessly consuming an ACME issuance.
        if (
            str(current.get("domain") or "") == domain
            and meta.get("expires_at", 0) > int(time.time()) + 14 * 24 * 3600
            and meta.get("issuer")
            and "Let's Encrypt" in meta.get("issuer", "")
        ):
            self._write_nginx_config(domain)
            self._reload_nginx()
            self._ensure_acme_cron(acme)
            return {
                "message": f"域名证书已存在并仍然有效：{domain}，已重新绑定 Nginx。",
                "expires_at": int(meta.get("expires_at") or 0),
                "issuer": str(meta.get("issuer") or ""),
            }

        if not self._port_available(80):
            raise RuntimeError("80 端口当前被其他服务占用，Let's Encrypt HTTP-01 无法验证。请先释放 80 端口。")

        self._write_state(status="issuing", domain=domain, message="正在向 Let's Encrypt 申请证书（HTTP-01）…")
        issue = self._run(
            [
                acme,
                "--issue",
                "-d",
                domain,
                "--standalone",
                "--httpport",
                "80",
                "--server",
                "letsencrypt",
                "--keylength",
                "ec-256",
            ],
            240,
        )
        if issue.returncode != 0:
            raise RuntimeError(f"Let's Encrypt 申请失败：{self._tail_output(issue)}")

        self._write_state(status="installing", domain=domain, message="证书申请成功，正在安装证书并重新加载 Nginx…")
        install = self._run(
            [
                acme,
                "--install-cert",
                "-d",
                domain,
                "--ecc",
                "--key-file",
                str(self.privkey),
                "--fullchain-file",
                str(self.fullchain),
                "--reloadcmd",
                "nginx -t && systemctl reload nginx",
            ],
            120,
        )
        if install.returncode != 0:
            raise RuntimeError(f"证书安装失败：{self._tail_output(install)}")

        self._write_nginx_config(domain)
        self._reload_nginx()
        self._ensure_acme_cron(acme)

        meta = self._cert_meta()
        if not meta.get("expires_at"):
            raise RuntimeError("证书已安装，但无法读取证书到期时间。")
        return {
            "message": f"HTTPS 已启用：{domain}，证书默认约 90 天有效，acme.sh 已配置自动续期。",
            "expires_at": int(meta.get("expires_at") or 0),
            "issuer": str(meta.get("issuer") or ""),
        }
