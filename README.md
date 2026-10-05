
# Aimili VPN 多协议节点管理系统 🌐

Bilingual: [中文](#中文) | [English](#english)

本项目用于在 Linux VPS 上统一管理 OpenVPN、SoftEther、SSTP、L2TP/IPsec 等多协议节点，提供节点资源采集、持续可用性检测、真实连接延迟、自动故障切换、HTTP/SOCKS5 出站代理与 Web 管理。


[🎁 专线流媒体｜顶级三网优化](https://yiy.one/register?codes=98BA33)
[📢 无限流量住宅 IP](https://www.miyaip.com/?invitecode=2955039)
<a name="中文"></a>

## 中文

### 1. 系统名称与定位

**Aimili VPN｜多协议节点管理系统**

系统以后台持续任务为核心。新资源进入 Master Pool 后进入待检测队列；后台检测会持续消费待检测节点，并在后续周期复检已经验证过的资源。当前连接存在时，后台检测不会主动断开当前 VPN。

### 2. 端口架构

| 用途 | 端口 | 监听方式 |
| --- | ---: | --- |
| HTTPS 管理后台 | `8443/tcp` | 公网，通过 Nginx 代理到 `127.0.0.1:8501` |
| HTTP/SOCKS5 代理 | `8500/tcp` | 公网，由账号密码与 IP/CIDR 白名单控制 |
| HTTPS 订阅入口 | `18443/tcp` | 公网，由现有订阅服务提供 |
| 管理后台内部服务 | `8501/tcp` | 仅本机 `127.0.0.1` |

### 3. HTTPS 访问规则

网页管理后台固定使用 **HTTPS + 8443**。

- **没有绑定域名**：使用 `https://服务器IP:8443/安全后缀/`，安装器提供自签名 HTTPS 证书，浏览器可能提示证书不受信任。
- **绑定域名后**：使用 `https://你的域名:8443/安全后缀/`。首次绑定该域名时自动申请并安装证书，后台自动续期。
- **同一个域名正在申请/安装证书时**，再次点击“保存修改”只保存账号、安全后缀等配置，不会重复创建新的证书申请。
- **只有更换域名**时，系统才会启动新的域名证书申请流程。

使用域名申请证书时，请先将域名 A/AAAA 解析到这台服务器，并确保公网 TCP 80 可用于 ACME 验证。

### 4. 节点检测

状态筛选包括：

| 状态 | 含义 |
| --- | --- |
| 全部节点 | 显示全部节点 |
| 待检测 | 尚未完成当前可用性验证，继续进入后台检测队列 |
| 检测中 | 当前正在执行可用性检测 |
| 可用节点 | 已经完成真实可用性验证 |
| 失效节点 | 当前验证失败或不可用 |

OpenVPN 的节点延迟只使用真实 OpenVPN 隧道建立后的实际检测结果，不使用 VPNGate 页面提供的 Ping 值，也不会把认证失败、TLS 失败等连接尝试耗时当作可用延迟。

### 5. 官方入口与项目支持

| 入口 | 地址 | 用途 |
| --- | --- | --- |
| 官网 | [ilovestudycn.com](https://ilovestudycn.com) | 项目主页与产品信息 |
| IP 节点检测 | [ilovestudyip.com](https://ilovestudyip.com/) | IP 与节点检测工具 |
| 博客 | [ilovestudyus.blogspot.com](https://ilovestudyus.blogspot.com/) | 教程与技术文章 |
| YouTube | [我爱研究 YouTube 频道](https://www.youtube.com/@ILovestudycn) | 视频教程 |
| Telegram 交流群 | [ILovestudy Telegram 交流群](https://t.me/ILovestudycn) | 用户交流与反馈 |
| Telegram 频道 | [ILovestudy Telegram 频道](https://t.me/ILovestudyus) | 项目公告与更新 |
| 商务合作 | [ilovestudyus@gmail.com](mailto:ilovestudyus@gmail.com) | 商务与合作联系 |

协议说明页使用 [VPN Gate 官方网站](https://www.vpngate.net/) 的公开技术资料。

### 6. 一键部署

正式版仓库：[hankinsus/aimili-vpngate-production](https://github.com/hankinsus/aimili-vpngate-production)

安装脚本：[install.sh](https://raw.githubusercontent.com/hankinsus/aimili-vpngate-production/refs/heads/main/install.sh)

以 root 用户执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/hankinsus/aimili-vpngate-production/refs/heads/main/install.sh)
```

安装完成后，终端会输出当前可用的 HTTPS 管理地址。网页中也会显示当前推荐访问地址。

### 7. 快速使用

1. 打开安装器输出的 HTTPS 管理地址并登录。
2. 等待后台资源采集与可用性检测；新资源会进入“待检测”并继续自动检测。
3. 在节点列表中按国家、协议、IP 类型和状态筛选。
4. 点击“切换”时，系统会先建立并验证新隧道，再完成切换；切换期间顶部和活动节点卡片都会显示“切换中”。
5. 连接建立后，8500 端口的 HTTP/SOCKS5 流量通过当前活动 VPN 隧道出站。

### 8. HTTP/SOCKS5 代理

代理固定使用 `8500/tcp`。访问来源由 `LOCAL_PROXY_ALLOW` 控制，并可配合 `LOCAL_PROXY_USER` / `LOCAL_PROXY_PASS` 使用账号密码认证。

Python 示例：

```python
import requests

proxies = {
    "http": "http://服务器IP:8500",
    "https": "http://服务器IP:8500",
}
response = requests.get("https://www.google.com", proxies=proxies)
print(response.status_code)
```

Shell 示例：

```bash
export http_proxy="http://服务器IP:8500"
export https_proxy="http://服务器IP:8500"
```

不要将内部管理端口 `8501` 暴露到公网。

### 9. 常见问题

**网页出现 502 Bad Gateway**

通常表示 Nginx 可以工作，但管理服务 `127.0.0.1:8501` 正在重启、暂时退出或尚未完成启动。确认 `aimilivpn.service` 为 active/running 后再刷新。

**待检测节点长期不变化**

检查后台状态是否显示“可用性检测中”。“待检测”节点由后台队列持续消费；用户手动切换、资源总刷新等高优先级操作执行时，后台检测会暂时让路，操作完成后继续。

**证书申请失败**

确认域名 DNS 已经指向本服务器，并确保公网 TCP 80 可以访问。申请中的同域名再次保存不会重新申请；需要重新申请时更换域名，或先清除域名后再重新绑定。

### 10. 项目链接清理

仓库文档中的项目入口统一使用可点击 Markdown 链接。已移除与系统功能无关的第三方 VPS/代理购买推广链接，不再保留对应的推荐码、邀请链接和相关商务文案。

系统运行所需的官方技术资料、开源许可证链接、GitHub 自身链接以及必要的检测服务地址保留不变。

### 11. 开源协议

项目代码遵循仓库中的 [GNU GPL v3](LICENSE)。

### 12. 开发支持

感谢使用与反馈。项目官方入口统一从 [我爱研究.ILovestudy](https://ilovestudyip.com/) 访问。

---

<a name="english"></a>

## English

### 1. System name and scope

**Aimili VPN Multi-Protocol Node Management System**

The system is designed for Linux VPS deployments and manages OpenVPN, SoftEther, SSTP, and L2TP/IPsec resources from one web console. It provides resource collection, continuous availability testing, real connection latency, automatic failover, an HTTP/SOCKS5 egress proxy, and web administration.


[🎁 Dedicated Streaming Media｜Top 3-Network Optimization](https://yiy.one/register?codes=98BA33)
[📢 Unlimited Traffic Residential IP](https://www.miyaip.com/?invitecode=2955039)
### 2. Port architecture

| Purpose | Port | Binding |
| --- | ---: | --- |
| HTTPS management | `8443/tcp` | Public, proxied by Nginx to `127.0.0.1:8501` |
| HTTP/SOCKS5 proxy | `8500/tcp` | Public, protected by credentials and IP/CIDR allowlist |
| HTTPS subscriptions | `18443/tcp` | Public, provided by the existing subscription service |
| Internal management service | `8501/tcp` | Local only: `127.0.0.1` |

### 3. HTTPS access rules

The web management console always uses **HTTPS on port 8443**.

- **No domain configured**: use `https://SERVER-IP:8443/SECURITY-SUFFIX/`. The installer provides a self-signed HTTPS certificate, so the browser may show a certificate warning.
- **A domain is configured**: use `https://YOUR-DOMAIN:8443/SECURITY-SUFFIX/`. The first binding automatically requests and installs a certificate, with automatic renewal enabled.
- **Saving the same domain while a certificate request/install is running** only saves account/security settings and never starts a second certificate order.
- **Changing the domain** is the normal action that starts a new domain certificate issuance flow.

For domain issuance, point the domain A/AAAA records to this server and keep public TCP port 80 available for ACME validation.

### 4. Node detection

The status filter includes:

| Status | Meaning |
| --- | --- |
| All nodes | Show the complete node list |
| Pending | Not yet verified by the current availability cycle; remains in the background testing queue |
| Testing | Currently being tested |
| Available | Successfully verified by the real availability test |
| Failed | The latest verification failed or the resource is unavailable |

OpenVPN latency is based only on real OpenVPN tunnel establishment/verification. The system does not use the Ping value advertised by VPN Gate and does not treat authentication, TLS, or other failed connection-attempt durations as usable latency.

### 5. Official resources and support

| Resource | Address | Purpose |
| --- | --- | --- |
| Website | [ilovestudycn.com](https://ilovestudycn.com) | Project homepage and product information |
| IP Node Checker | [ilovestudyip.com](https://ilovestudyip.com/) | IP and node inspection |
| Blog | [ilovestudyus.blogspot.com](https://ilovestudyus.blogspot.com/) | Tutorials and technical articles |
| YouTube | [ILovestudy YouTube Channel](https://www.youtube.com/@ILovestudycn) | Video tutorials |
| Telegram Group | [ILovestudy Telegram Group](https://t.me/ILovestudycn) | User discussion and feedback |
| Telegram Channel | [ILovestudy Telegram Channel](https://t.me/ILovestudyus) | Project announcements and updates |
| Business cooperation | [ilovestudyus@gmail.com](mailto:ilovestudyus@gmail.com) | Business and partnership inquiries |

Protocol help pages use public technical information from the [official VPN Gate website](https://www.vpngate.net/).

### 6. One-click installation

Official repository: [hankinsus/aimili-vpngate-production](https://github.com/hankinsus/aimili-vpngate-production)

Installer: [install.sh](https://raw.githubusercontent.com/hankinsus/aimili-vpngate-production/refs/heads/main/install.sh)

Run as root:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/hankinsus/aimili-vpngate-production/refs/heads/main/install.sh)
```

After installation, the terminal prints the current HTTPS management address. The web console also displays the recommended address.

### 7. Quick start

1. Open the HTTPS management address printed by the installer and sign in.
2. Wait for background resource collection and availability testing. New resources enter the Pending queue and continue to be tested automatically.
3. Filter nodes by country, protocol, IP type, and status.
4. When you click Switch, the system establishes and validates the new tunnel before completing the switch. The top status area and active-node card both show the live “Switching” state.
5. Once connected, HTTP/SOCKS5 traffic on port `8500` exits through the active VPN tunnel.

### 8. HTTP/SOCKS5 proxy

The proxy uses fixed TCP port `8500`. Source access is controlled by `LOCAL_PROXY_ALLOW`, with optional username/password authentication through `LOCAL_PROXY_USER` and `LOCAL_PROXY_PASS`.

Python example:

```python
import requests

proxies = {
    "http": "http://SERVER-IP:8500",
    "https": "http://SERVER-IP:8500",
}
response = requests.get("https://www.google.com", proxies=proxies)
print(response.status_code)
```

Shell example:

```bash
export http_proxy="http://SERVER-IP:8500"
```

Do not expose internal management port `8501` to the public internet.

### 9. Common issues

**502 Bad Gateway**

This normally means Nginx is reachable but the management service on `127.0.0.1:8501` is restarting, temporarily stopped, or has not finished starting. Check that `aimilivpn.service` is active/running and refresh.

**Pending nodes do not change**

Check the background status strip and confirm that availability testing is active. Pending nodes are consumed by the background queue. Higher-priority actions such as manual switching or a global resource refresh can temporarily yield the testing slot; testing resumes afterward.

**Certificate issuance fails**

Confirm that the domain DNS records point to this server and that public TCP port 80 is reachable. Saving the same domain during issuance never starts another order. To intentionally request a different certificate binding, change the domain or clear the domain and bind it again.

### 10. Repository link cleanup

Project documentation now uses clickable Markdown links for project entry points. Unrelated third-party VPS/proxy promotion links, associated promotional copy has been removed.

Official technical references, open-source license links, required GitHub links, and required network-diagnostic service endpoints remain because they are part of the system or its legal/technical dependencies.

### 11. License

The project is released under the [GNU GPL v3](LICENSE).

### 12. Project support

Thank you for using and reporting issues. The official project entry point is [ILovestudy](https://ilovestudyip.com/).

---

**Version: V1.0.7**
