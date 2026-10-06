#!/usr/bin/env bash
# 九合一 + AimiliVPN 联合安装。V1.0.1
# 署名: 我爱研究.ilovestudy
# 不要在已经上线的生产机上执行。新机器：
#   bash <(curl -Ls https://raw.githubusercontent.com/hankinsus/aimili-vpngate-production/main/install-suite.sh)
set -euo pipefail

if [ "$(id -u)" != "0" ]; then
    echo "错误: 请用 root 运行。"
    exit 1
fi

if [ -f /opt/aimilivpn/vpngate_data/state.json ] && [ -d /etc/v2ray-agent ] && [ "${AIMILI_ALLOW_EXISTING:-}" != "1" ]; then
    echo "检测到本机已经同时有 AimiliVPN 和九合一目录。"
    echo "联合安装不会在已上线机器上重跑。请换一台新服务器。"
    echo "确认是误报时才设置 AIMILI_ALLOW_EXISTING=1。"
    exit 1
fi

echo "=========================================================="
echo "  九合一 + AimiliVPN 联合安装"
echo "  署名: 我爱研究.ilovestudy    版本: V1.0.1"
echo "=========================================================="
echo
echo "有域名就输入域名（九合一走 TLS，AimiliVPN 申请 Let's Encrypt，约 90 天并自动续期）。"
echo "没有域名直接回车：九合一无域名 Reality，AimiliVPN 使用 100 年自签 IP 证书。"
echo "公网 CA 不能签发永不过期的 IP 证书，所以无域名不走 Let's Encrypt 短效 IP 证书。"
echo

DOMAIN="${AIMILI_DOMAIN-}"
if [ -z "${AIMILI_DOMAIN+x}" ]; then
    read -r -p "域名（没有就回车）: " DOMAIN
fi
DOMAIN="${DOMAIN#"${DOMAIN%%[![:space:]]*}"}"
DOMAIN="${DOMAIN%"${DOMAIN##*[![:space:]]}"}"

REPO_INSTALL_URL="${AIMILI_INSTALL_URL:-https://raw.githubusercontent.com/hankinsus/aimili-vpngate-production/main/install.sh}"

if [ -z "$DOMAIN" ]; then
    export AIMILIVPN_IP_CERT_FOREVER=1
    export AIMILIVPN_ENABLE_ACME_IP_CERT=0
    echo "未填写域名：九合一无域名安装，AimiliVPN 使用 100 年自签 IP 证书。"
else
    unset AIMILIVPN_IP_CERT_FOREVER || true
    export AIMILIVPN_ENABLE_ACME_IP_CERT=0
    echo "使用域名: ${DOMAIN}"
fi

echo
echo "[1/3] 安装 AimiliVPN ..."
bash <(curl -fsSL "$REPO_INSTALL_URL")

if [ -n "$DOMAIN" ]; then
    echo
    echo "[1b] 为 AimiliVPN 申请域名证书 ${DOMAIN} ..."
    if ! python3 - "$DOMAIN" <<'PY'
import sys
sys.path.insert(0, "/opt/aimilivpn")
from pathlib import Path
from web_certificate import WebCertificateManager

domain = sys.argv[1]
mgr = WebCertificateManager(Path("/opt/aimilivpn/vpngate_data/web_certificate.json"))
mgr._worker(domain)
print("域名证书已安装:", domain)
PY
    then
        echo "域名证书申请失败。管理页暂时仍使用自签证书，可用 https://IP:8443 打开后再在页面里重试。"
    fi
fi

if [ ! -s /opt/aimilivpn/jiuheyi/install.sh ]; then
    echo "错误: 仓库里没有 jiuheyi/install.sh，AimiliVPN 安装没有拿到九合一脚本。"
    exit 1
fi

echo
echo "[2/3] 安装九合一 ..."
mkdir -p /etc/v2ray-agent
cp /opt/aimilivpn/jiuheyi/install.sh /etc/v2ray-agent/install.sh
chmod 700 /etc/v2ray-agent/install.sh
export AIMILI_SUITE=1
if [ -z "$DOMAIN" ]; then
    export AIMILI_SUITE_ACTION=domainless
    unset domain || true
else
    export AIMILI_SUITE_ACTION=with-domain
    export domain="$DOMAIN"
fi
bash /etc/v2ray-agent/install.sh

echo
echo "[3/3] 检查 Nginx ..."
if command -v nginx >/dev/null 2>&1; then
    nginx -t
    if command -v systemctl >/dev/null 2>&1; then
        systemctl reload nginx || systemctl restart nginx || true
    fi
fi

echo
echo "=========================================================="
echo "安装完成。"
echo "九合一默认出站: 127.0.0.1:8500"
echo "用户名: socks5"
echo "密码: ilovestudy"
if [ -z "$DOMAIN" ]; then
    echo "AimiliVPN 证书: 自签 IP 证书，100 年。浏览器首次访问需要手动信任。"
else
    echo "AimiliVPN 证书: Let's Encrypt 域名证书，约 90 天，acme.sh 自动续期。"
fi
echo "九合一菜单: vasma"
echo "=========================================================="
