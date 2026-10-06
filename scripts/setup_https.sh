#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TLS_DIR="/etc/aimilivpn/tls"
CERT_FILE="$TLS_DIR/fullchain.pem"
KEY_FILE="$TLS_DIR/privkey.pem"
NGINX_CONF="/etc/nginx/conf.d/aimilivpn-production.conf"
ACME_CONF="/etc/nginx/conf.d/aimilivpn-acme.conf"
ACME_ROOT="/var/www/aimilivpn-acme"
SUB_DIR="/var/lib/aimilivpn/subscriptions"
ENABLE_IP_ACME="${AIMILIVPN_ENABLE_ACME_IP_CERT:-0}"
ACME_AVAILABLE=0
ACME_ISSUED=0

if [ "$(id -u)" != "0" ]; then echo "错误: 需要 root 权限。" >&2; exit 1; fi

service_enable() {
  if command -v systemctl >/dev/null 2>&1; then systemctl enable nginx >/dev/null 2>&1 || true
  elif command -v rc-update >/dev/null 2>&1; then rc-update add nginx default >/dev/null 2>&1 || true
  fi
}
service_restart() {
  if command -v systemctl >/dev/null 2>&1; then systemctl restart nginx
  else rc-service nginx restart
  fi
}
service_reload() {
  if command -v systemctl >/dev/null 2>&1; then systemctl reload nginx
  else rc-service nginx reload || rc-service nginx restart
  fi
}

OS_TYPE=""
[ -f /etc/os-release ] && . /etc/os-release && OS_TYPE="$ID"
case "$OS_TYPE" in
  ubuntu|debian) export DEBIAN_FRONTEND=noninteractive; apt-get update -q; apt-get install -y nginx openssl curl ca-certificates certbot ;;
  alpine) apk add --no-cache nginx openssl curl ca-certificates certbot ;;
  centos|rhel|rocky|almalinux|fedora|ol|amzn) (command -v dnf >/dev/null 2>&1 && dnf install -y nginx openssl curl ca-certificates certbot) || yum install -y nginx openssl curl ca-certificates certbot ;;
  *) echo "不支持的系统: $OS_TYPE" >&2; exit 1 ;;
esac

mkdir -p "$TLS_DIR" "$ACME_ROOT/.well-known/acme-challenge" "$SUB_DIR"
chmod 700 "$TLS_DIR"
PUBLIC_IP="${PUBLIC_IP:-$(curl -4fsS --max-time 5 https://api.ipify.org || true)}"
[ -z "$PUBLIC_IP" ] && PUBLIC_IP="127.0.0.1"

# 先生成可用的后备证书，保证 Nginx 即使 ACME 失败也能启动。
# 无域名时由联合安装设置 AIMILIVPN_IP_CERT_FOREVER=1。
# 公网 CA 不能签发永不过期的 IP 证书；这里改为 100 年自签 IP 证书，并关闭 Let's Encrypt 短效 IP 证书。
CERT_DAYS=3650
if [ "${AIMILIVPN_IP_CERT_FOREVER:-0}" = "1" ]; then
  CERT_DAYS=36500
  ENABLE_IP_ACME=0
fi
if ! openssl req -x509 -nodes -newkey rsa:2048 -days "$CERT_DAYS" -keyout "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=$PUBLIC_IP" -addext "subjectAltName=IP:$PUBLIC_IP" >/dev/null 2>&1; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -keyout "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=$PUBLIC_IP" -addext "subjectAltName=IP:$PUBLIC_IP" >/dev/null 2>&1
fi
chmod 600 "$KEY_FILE"; chmod 644 "$CERT_FILE"

install -m 0644 "$ROOT_DIR/scripts/nginx/aimilivpn-production.conf" "$NGINX_CONF"
rm -f "$ACME_CONF"

# 只有 80 端口空闲时才启用 HTTP-01，避免抢占用户已有网站。
if [ "$ENABLE_IP_ACME" = "1" ] && ! ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq '(^|:)80$'; then
  install -m 0644 "$ROOT_DIR/scripts/nginx/aimilivpn-acme.conf" "$ACME_CONF"
  ACME_AVAILABLE=1
else
  ACME_AVAILABLE=0
fi

service_enable
nginx -t
service_restart

if [ "$ACME_AVAILABLE" = "1" ] && command -v certbot >/dev/null 2>&1; then
  if certbot certonly --webroot -w "$ACME_ROOT" --preferred-profile shortlived --ip-address "$PUBLIC_IP" --cert-name aimilivpn-ip --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring; then
    LE_DIR="/etc/letsencrypt/live/aimilivpn-ip"
    if [ -s "$LE_DIR/fullchain.pem" ] && [ -s "$LE_DIR/privkey.pem" ]; then
      install -m 0644 "$LE_DIR/fullchain.pem" "$CERT_FILE"
      install -m 0600 "$LE_DIR/privkey.pem" "$KEY_FILE"
      mkdir -p /etc/letsencrypt/renewal-hooks/deploy
      cat > /etc/letsencrypt/renewal-hooks/deploy/aimilivpn-nginx <<'HOOK'
#!/bin/sh
set -eu
install -m 0644 /etc/letsencrypt/live/aimilivpn-ip/fullchain.pem /etc/aimilivpn/tls/fullchain.pem
install -m 0600 /etc/letsencrypt/live/aimilivpn-ip/privkey.pem /etc/aimilivpn/tls/privkey.pem
if command -v systemctl >/dev/null 2>&1; then systemctl reload nginx; else rc-service nginx reload || rc-service nginx restart; fi
HOOK
      chmod 755 /etc/letsencrypt/renewal-hooks/deploy/aimilivpn-nginx
      echo "已获得 Let's Encrypt 公网可信 IP 证书。"
    fi
  else
    echo "Let's Encrypt IP 证书申请失败，继续使用自签名证书。"
  fi
fi

# In the default three-port mode, never leave ACME port 80 enabled after a failed/disabled attempt.
if [ "$ACME_AVAILABLE" = "1" ] && [ "$ACME_ISSUED" != "1" ]; then
  rm -f "$ACME_CONF"
  service_reload
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw delete allow 80/tcp >/dev/null 2>&1 || true
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port=80/tcp >/dev/null || true
    firewall-cmd --reload >/dev/null || true
  fi
fi

nginx -t && service_reload

if [ "$ACME_ISSUED" = "1" ] && command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^certbot.timer'; then
  systemctl enable --now certbot.timer >/dev/null 2>&1 || true
elif [ "$ACME_ISSUED" = "1" ] && [ -d /etc/cron.daily ]; then
  cat > /etc/cron.daily/aimilivpn-certbot-renew <<'EOF'
#!/bin/sh
certbot renew --quiet
EOF
  chmod 755 /etc/cron.daily/aimilivpn-certbot-renew
elif [ "$ACME_ISSUED" = "1" ] && [ -d /etc/periodic/daily ]; then
  cat > /etc/periodic/daily/aimilivpn-certbot-renew <<'EOF'
#!/bin/sh
certbot renew --quiet
EOF
  chmod 755 /etc/periodic/daily/aimilivpn-certbot-renew
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 8443/tcp >/dev/null; ufw allow 8500/tcp >/dev/null; ufw allow 18443/tcp >/dev/null
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port=8443/tcp >/dev/null || true
  firewall-cmd --permanent --add-port=8500/tcp >/dev/null || true
  firewall-cmd --permanent --add-port=18443/tcp >/dev/null || true
  firewall-cmd --reload >/dev/null || true
fi

echo "HTTPS 管理后台: https://${PUBLIC_IP}:8443/"
echo "HTTPS 订阅入口: https://${PUBLIC_IP}:18443/"
echo "内部管理服务:   http://127.0.0.1:8501/"