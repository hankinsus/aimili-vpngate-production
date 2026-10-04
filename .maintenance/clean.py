from pathlib import Path
import base64
import re

root = Path(".")
logo_b64 = (root / ".maintenance/logo.b64").read_text(encoding="utf-8").strip()
logo = base64.b64decode(logo_b64, validate=True)
(root / "footer-logo-clean.png").write_bytes(logo)

replacements = {
    "README.md": [
        ("### ⭐ 我的邀请入口\n", ""),
        ("### ⭐ My invitation links\n", ""),
        ("HTTP/SOCKS5 八合一代理", "HTTP/SOCKS5 代理"),
        ("HTTP/SOCKS5 八合一", "HTTP/SOCKS5 代理"),
        ("HTTP/SOCKS5 eight-in-one proxy", "HTTP/SOCKS5 proxy"),
        ("# Aimili VPN｜多协议节点管理系统 🌐", "# Aimili VPN 多协议节点管理系统 🌐"),
        ("**ILovestudy｜Multi-Protocol Node Management System**", "**Aimili VPN Multi-Protocol Node Management System**"),
        ("**Version: V1.0.6**", "**Version: V1.0.7**"),
    ],
    "install.sh": [
        ("# 4.5 Public HTTP/SOCKS5 eight-in-one gateway settings", "# 4.5 Public HTTP/SOCKS5 proxy settings"),
        ('print("  八合一代理:   服务器IP:8500")', 'print("  HTTP/SOCKS5代理: 服务器IP:8500")'),
        ('print("2) HTTP/SOCKS5 八合一: 8500 (固定)")', 'print("2) HTTP/SOCKS5 代理: 8500 (固定)")'),
        ('print("HTTP/SOCKS5 八合一固定为 8500。")', 'print("HTTP/SOCKS5 代理固定为 8500。")'),
        ("HTTP/SOCKS5 八合一", "HTTP/SOCKS5 代理"),
    ],
    "vpngate_manager.py": [
        ("HTTP/SOCKS5 八合一端口", "HTTP/SOCKS5 代理端口"),
        ("八合一端口固定为 8500", "代理端口固定为 8500"),
        ("HTTP/SOCKS5 八合一端口固定为 8500", "HTTP/SOCKS5 代理端口固定为 8500"),
    ],
}
for rel, pairs in replacements.items():
    p = root / rel
    text = p.read_text(encoding="utf-8")
    for old, new in pairs:
        text = text.replace(old, new)
    p.write_text(text, encoding="utf-8")

(root / "VERSION").write_text("V1.0.7\n", encoding="utf-8")

leftovers = []
for p in [root/"README.md", root/"install.sh", root/"vpngate_manager.py"]:
    t = p.read_text(encoding="utf-8", errors="ignore")
    if re.search(r"八合一|我的邀请入口|My invitation links|referral code|referral links", t, re.I):
        leftovers.append(str(p))
if leftovers:
    raise SystemExit("forbidden terms remain: " + ", ".join(leftovers))

print("maintenance cleanup complete")
