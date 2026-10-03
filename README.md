# AimiliVPN 多协议节点管理系统 🌐

Bilingual: [中文](#中文) | [English](#english)

---

<a name="中文"></a>
## 中文 (Chinese)

AimiliVPN 多协议节点管理系统是一款面向 Linux VPS 的自动化 VPN 节点管理与代理网关。它以 Python 为核心，支持 OpenVPN、SoftEther、SSTP、L2TP/IPsec 等多协议节点池，并提供自动故障切换、节点探测、出站代理与 Web 管理。

### 端口架构

| 用途 | 端口 | 监听方式 |
| --- | ---: | --- |
| HTTPS 管理后台 | `8443/tcp` | 公网，通过 Nginx 代理到 `127.0.0.1:8501` |
| HTTPS 订阅入口 | `18443/tcp` | 公网，由现有订阅服务独立提供；安装器不接管 |
| HTTP/SOCKS5 八合一 | `8500/tcp` | 公网，账号密码 + IP/CIDR 白名单 |
| 管理后台内部服务 | `8501/tcp` | 仅 `127.0.0.1` |

不要求域名即可使用 HTTPS：安装器会优先尝试为公网 IP 申请 Let's Encrypt IP 证书；IP 证书属于短期证书，需要自动续期。若 ACME 条件不满足，会自动使用自签名证书，浏览器会提示证书不受信任。

---

### 🌟 优选推荐：无需动手更省心
[🎁[专线流媒体 顶级三网优化](https://yiy.one/register?codes=98BA33)]
[📢[无限流量住宅IP](https://www.miyaip.com/?invitecode=2955039)]

| 推荐 | 适合谁 | 亮点 | 入口 |
| --- | --- | --- | --- |
| **专线稳定流媒体** | 更看重国内访问质量、延迟和线路上限的用户 | **顶级三网优化线路**，解锁Open AI/Chat GPT、YouTube、Netflix、Disney+等适合对网络体验、跨境访问质量和长期稳定性要求更高的场景 | [立即查看](https://yiy.one/register?codes=98BA33)|
| **静态机房住宅IP** | 想低成本跨境电商、流媒体解锁、直播等住宅IP需求的用户 | **不限流量**，价格实惠、经过1个月测试，有需求可入手测试 | [立即查看](https://www.miyaip.com/?invitecode=2955039) |

---

### 📢 ILovestudy 官方入口与支持

| 入口 | 地址 | 用途 |
| --- | --- | --- |
| 官网 | https://ilovestudycn.com | 项目主页与产品信息 |
| IP节点检测查询 | https://ilovestudyip.com | IP / 节点检测工具 |
| 博客 | https://ilovestudyus.blogspot.com/ | 教程与技术文章 |
| YouTube | https://www.youtube.com/@ILovestudycn | 视频教程 |
| Telegram 交流群 | https://t.me/ILovestudycn | 用户交流与反馈 |
| Telegram 频道 | https://t.me/ILovestudyus | 项目公告与更新 |
| 商务合作 | ilovestudyus@gmail.com | 商务与合作联系 |

---

### 🚀 一键极速部署 (支持 Debian/Ubuntu/CentOS/Alpine 等 Linux 系统)

在您的 Linux VPS 上以 root 用户执行以下对应命令：

#### 🌟 正式稳定版本 (main 分支)
```bash
bash <(curl -Ls https://raw.githubusercontent.com/hankinsus/aimili-vpngate-production/refs/heads/main/install.sh)
```
> 💡 **小贴士**：部署完成后，终端会输出管理网页的专属链接（含随机安全后缀，如 `https://your_vps_ip:8443/u71e9IXp4TPx`）。在终端中输入 `ml` 命令可以随时调出交互式命令行管理菜单。

---

### 💡 快速使用指南 (小白必看)

部署成功后，如何使用它进行科学上网？

#### 第一步：登录 Web 管理后台
打开浏览器，访问部署完成时提示的专属后台地址（含安全后缀），即可进入精美的暗黑玻璃拟物风管理界面。

#### 第二步：获取并连接节点
1. 首次进入后台，节点列表可能正在进行首次自动测速与拉取。
2. 点击 **“更新节点”** 按钮（或通过网页下方的网关/日志进行状态检查），程序会在后台通过多线程并发测速，自动筛选出延迟最低、可连接的 VPNGate 节点。
3. 选择您喜欢的出站路由模式：
   - **智能自动配置**（推荐）：如果当前连接的节点失效，系统会在数秒内自动漂移连接至其他备用健康节点，无需手动干预。
   - **固定国家地区**：只选择指定国家（如日本 JP、韩国 KR、美国 US）的最佳节点。
   - **固定 IP 节点**：始终锁定连接到这一个特定节点。

#### 第三步：使用 8500 八合一代理 (核心步骤)
AimiliVPN 的八合一代理固定使用 **`8500/tcp`**，支持 HTTP、HTTPS CONNECT 与 SOCKS5，流量经当前活动 VPN 隧道出站。8500 的来源限制由 `LOCAL_PROXY_ALLOW` 控制，并使用 `LOCAL_PROXY_USER` / `LOCAL_PROXY_PASS` 做账号密码认证。

* **🐍 Python 脚本中使用代理**:
  ```python
  import requests
  proxies = {
      "http": "http://服务器IP:8500",
      "https": "http://服务器IP:8500",
  }
  response = requests.get("https://www.google.com", proxies=proxies)
  ```
* **🐚 Shell 终端环境中使用代理**:
  在命令行执行以下命令，可以让当前终端的后续命令（如 `curl`、`wget` 等）走代理出口：
  ```bash
  export http_proxy="http://服务器IP:8500"
  export https_proxy="http://服务器IP:8500"
  ```
* **⚙️ 本地其他服务配置**:
  将本机的其他代理工具、爬虫框架或服务的出战代理设置为 `服务器IP:8500`。

> 💡 **小贴士**：8500 已由安装器绑定到公网接口；请使用 `LOCAL_PROXY_ALLOW` 限制允许访问的 IP/CIDR，并保留用户名密码认证。

#### 8500 八合一代理账号与访问控制

安装器会创建 `/etc/default/aimilivpn`，用户可以自行设置 SOCKS5/HTTP 代理用户名、密码和允许访问 8500 的来源地址：

```bash
sudo vim /etc/default/aimilivpn

LOCAL_PROXY_USER="socks5"
LOCAL_PROXY_PASS="ilovestudy"
LOCAL_PROXY_ALLOW="你的公网IP/32"

sudo chmod 600 /etc/default/aimilivpn
sudo ml restart
```

多个来源使用逗号或分号分隔；默认仅允许本机 `127.0.0.1/32,::1/128`。如需远程访问，请明确填写自己的公网 IP/CIDR；使用 `0.0.0.0/0,::/0` 表示允许所有来源。默认密码为 `ilovestudy`，公网部署后建议立即修改。

---

### 🛠️ 核心功能与操作说明

* **合并操作面板**：将“更新节点”与“立即检测补齐”合并，一键触发多线程拉取与测速。
* **网关状态面板**：
  - **系统诊断**：检测网关心跳及后台各个子守护线程（网页服务、VPN连接管理、出站网关服务）是否正常运行。若有脚本未运行，会提示具体的异常原因。
  - **本地代理出口检测**：在网页端直接一键检测 VPS 后台对海外的实际连通状况，并回显真实的代理出站 IP 和所在地理位置。
* **日志追踪面板**：
  - **分类过滤**：可精准筛选查看特定功能的日志（如 VPN 连接日志、API 请求日志、系统异常等）。
  - **实时滚动与管理**：日志实时滚动加载，支持一键复制代码、一键导出 `.log` 日志文件到本地。

---

### ⚠️ 小白安装与运行常见问题 (FAQ)

#### 1. 提示 `Cannot allocate tun` 或 `Cannot open tun/tap dev`
* **原因**：VPS 宿主机未启用虚拟网卡（TUN/TAP 设备）。这种情况常见于 LXC 或 OpenVZ 架构的轻量 VPS。
* **解决办法**：请登录您的 VPS 服务商控制面板（如 SolusVM/Proxmox），找到 **Enable TUN/TAP** / **开启 TUN** 选项并启用，然后重启 VPS。如无此选项，请工单联系客服开启。

#### 2. 网页管理后台无法打开（链接超时或拒绝连接）
* **原因 1**：VPS 本身自带防火墙（如 UFW、firewalld 或 iptables）阻断了 HTTPS 端口。
* **解决办法 1**：公网放行三个端口：`8443/tcp`（HTTPS 管理）、`8500/tcp`（HTTP/SOCKS5 八合一）和 `18443/tcp`（HTTPS 订阅）。内部管理监听 `127.0.0.1:8501` 不对公网开放。
  * **UFW (Ubuntu/Debian)**: `ufw allow 8443/tcp && ufw allow 8500/tcp && ufw allow 18443/tcp`
  * **Firewalld (CentOS/RHEL)**: `firewall-cmd --zone=public --add-port=8443/tcp --permanent && firewall-cmd --zone=public --add-port=8500/tcp --permanent && firewall-cmd --zone=public --add-port=18443/tcp --permanent && firewall-cmd --reload`
* **原因 2**：云服务商的“安全组”或“网络访问控制列表 (ACL)”未放行 HTTPS 端口。
* **解决办法 2**：登录云服务商控制台，在入站规则中放行 TCP `8443`、`8500` 和 `18443`。不要把 `8501` 暴露到公网；8500 的访问通过 `LOCAL_PROXY_ALLOW` 与代理账号密码控制。

#### 3. 页面提示 `API Domain Blocked` 且备选节点显示为 0
* **原因**：您的 VPS DNS 解析异常，或者官方 VPNGate 域名遭防火墙拦截污染，导致无法下载节点列表。
* **解决办法**：
  * **设置上游代理**：如果您有其他可用的代理服务，可在网页管理面板中打开“管理员 -> 代理及网络设置”，配置有效的 HTTP/SOCKS5 上游代理，后台会自动通过该代理拉取更新。
  * **修改 DNS 解析器**：在终端修改 `/etc/resolv.conf`，将域名服务器替换为公共 DNS（如 `nameserver 8.8.8.8` 和 `nameserver 1.1.1.1`）。

#### 4. VPN 已成功连接，但客户端设置代理后无法上网 (无流量)
* **原因**：部分系统启用了严格的反向路径过滤（`rp_filter`），导致策略路由的入站/出站数据包被系统误判丢弃。
* **解决办法**：在终端输入 `ml` 命令打开交互菜单，工具会自动检测并提示您将 `rp_filter` 修复为宽松模式（值为 `2`）。

---

### 🎁 捐赠支持项目开发

如果您觉得这个项目对您有所帮助，欢迎捐赠支持我们的后续开发与维护：

* **USDT (TRON / TRC20)**: `TPuueui5rRCL3ECV6dWmBzeDkaTV2JEyAn`

感谢您的慷慨与支持！❤️

---

<a name="english"></a>
## English

AimiliVPN Multi-Protocol Node Management System is a Linux VPS gateway for managing and automatically switching between OpenVPN, SoftEther, SSTP, and L2TP/IPsec endpoints. It provides protocol discovery, health checks, failover, and a local HTTP/SOCKS5 egress proxy.

### Port architecture

| Purpose | Port | Binding |
| --- | ---: | --- |
| HTTPS management | `8443/tcp` | Public, proxied to `127.0.0.1:8501` |
| HTTP/SOCKS5 eight-in-one | `8500/tcp` | Public, protected by credentials + IP/CIDR allowlist |
| HTTPS subscriptions | `18443/tcp` | Public, provided by the external subscription service; installer does not replace it |

A domain is not required. The default deployment keeps exactly three public ports (8443/8500/18443) and uses HTTPS with a local self-signed certificate, so browsers may show a certificate warning. Optional trusted IP-certificate mode can be enabled with `AIMILIVPN_ENABLE_ACME_IP_CERT=1`; that mode requires public TCP/80 for ACME validation and ongoing renewal. Let's Encrypt IP certificates are short-lived.

### 8500 HTTP/SOCKS5 eight-in-one

The public proxy uses fixed TCP port `8500`. Configure username, password, and source IP/CIDR access in `/etc/default/aimilivpn`:

### 🌟 Recommended VPS Deals: Simple and Convenient
[![Dedicated Streaming Media - Top 3-Network Optimization](https://img.shields.io/badge/Dedicated%20Streaming%20Media-Top%203--Network%20Optimization-red?style=for-the-badge)](https://yiy.one/register?codes=98BA33)
[![Unlimited Traffic - Residential IP](https://img.shields.io/badge/Unlimited%20Traffic-Residential%20IP-blue?style=for-the-badge)](https://www.miyaip.com/?invitecode=2955039)

| Recommendation | Suitable for | Highlights | Entry |
| --- | --- | --- | --- |
| **Stable Streaming Media** | Users who care more about access quality, latency, and route limits for cross-border use | **Top-tier three-network optimized routes**, with access to OpenAI/ChatGPT, YouTube, Netflix, Disney+, and other services; suitable for demanding network-experience and long-term stability needs | [View now](https://yiy.one/register?codes=98BA33) |
| **Static Residential IP** | Users looking for low-cost cross-border e-commerce, streaming, live-streaming, or residential-IP use cases | **Unlimited traffic**, affordable pricing, and one month of testing; suitable for users who want to test before long-term use | [View now](https://www.miyaip.com/?invitecode=2955039) |


### 📢 ILovestudy Official Resources & Support

| Resource | Address | Purpose |
| --- | --- | --- |
| Website | https://ilovestudycn.com | Project homepage and product information |
| IP Node Checker | https://ilovestudyip.com | IP and node inspection tools |
| Blog | https://ilovestudyus.blogspot.com/ | Tutorials and technical articles |
| YouTube | https://www.youtube.com/@ILovestudycn | Video tutorials |
| Telegram Group | https://t.me/ILovestudycn | User discussion and feedback |
| Telegram Channel | https://t.me/ILovestudyus | Project announcements and updates |
| Business Cooperation | ilovestudyus@gmail.com | Business and partnership inquiries |

---

### 🚀 One-Click Installation

Run the corresponding command on your Linux VPS as root:

#### 🌟 Stable Release (main branch)
```bash
bash <(curl -Ls https://raw.githubusercontent.com/hankinsus/aimili-vpngate-production/refs/heads/main/install.sh)
```

> 💡 **Quick Note**: Once installed, copy the printed URL from the terminal to access the Web UI. Type the `ml` command in the terminal to summon the interactive CLI management console.

---

### 💡 Quick Start Guide

#### Step 1: Access the Web UI
Open your browser and navigate to the printed URL (e.g. `https://your_vps_ip:8443/u71e9IXp4TPx`).

#### Step 2: Select Node and Mode
1. Wait for the program to complete its first automatic node speed benchmarks.
2. Under "Admin", you can trigger node fetching. The backend concurrently tests official VPNGate nodes and ranks them by latency.
3. Switch routes mode (Smart Auto, Specific Region, or Specific Server Node) according to your needs.

#### Step 3: Use 8500 HTTP/SOCKS5 Eight-in-One Proxy (Core Step)
The HTTP/SOCKS5 eight-in-one proxy uses fixed TCP port **`8500`** and routes traffic through the active VPN tunnel. The installer default username is `socks5` and the default password is `ilovestudy`; change it after deployment when the proxy is reachable from the public internet. The secure default allowlist permits only `127.0.0.1/32,::1/128`; add your public IP/CIDR for remote access. Access is controlled by `LOCAL_PROXY_ALLOW`, with `LOCAL_PROXY_USER` / `LOCAL_PROXY_PASS` authentication.

* **🐍 Proxy in Python**:
  ```python
  import requests
  proxies = {
      "http": "http://服务器IP:8500",
      "https": "http://服务器IP:8500",
  }
  response = requests.get("https://www.google.com", proxies=proxies)
  ```
* **🐚 Proxy in Shell terminal**:
  ```bash
  export http_proxy="http://服务器IP:8500"
  export https_proxy="http://服务器IP:8500"
  ```
* **⚙️ Other local services**:
  Configure your scrapers, frameworks, or utility tools on this VPS to send traffic via `服务器IP:8500`.

> 💡 **Quick Note**: 8500 is the public proxy endpoint. Restrict source IPs/CIDRs with `LOCAL_PROXY_ALLOW` and keep username/password authentication enabled.

---

### ⚠️ Common Troubleshooting (FAQ)

#### 1. Error: `Cannot allocate tun` or `Cannot open tun/tap dev`
* **Reason**: Virtual network adapter (TUN/TAP device) is disabled. This is common in OpenVZ/LXC VPS instances.
* **Solution**: Enable **TUN/TAP** in your VPS SolusVM/KiwiVM control panel, or submit a support ticket to your hosting provider.

#### 2. Cannot open the Web UI in the browser
* **Reason 1**: The built-in firewall (UFW or firewalld) is blocking the public HTTPS and proxy endpoints.
* **Solution 1**: Allow TCP `8443` for management, `8500` for the HTTP/SOCKS5 gateway, and `18443` for subscriptions. Keep `127.0.0.1:8501` private.
  * **UFW**: `ufw allow 8443/tcp && ufw allow 8500/tcp && ufw allow 18443/tcp`
  * **Firewalld**: `firewall-cmd --add-port=8443/tcp --permanent && firewall-cmd --add-port=8500/tcp --permanent && firewall-cmd --add-port=18443/tcp --permanent && firewall-cmd --reload`
* **Reason 2**: Your cloud provider security group or network ACL is blocking the public HTTPS ports.
* **Solution 2**: Allow inbound TCP `8443`, `8500`, and `18443` in the VPS provider console. Keep `8501` private.

#### 3. "API Domain Blocked" / Candidate nodes pool is empty (0 nodes)
* **Reason**: The official VPNGate domain is blocked or DNS resolution failed on your VPS.
* **Solution**: Add an HTTP/SOCKS5 upstream proxy in the settings panel (Admin -> Proxy Settings), or configure public DNS in `/etc/resolv.conf` (e.g., `nameserver 8.8.8.8`).

---

### 🎁 Donation Support

If you find this project helpful, you can support its development and maintenance via donation:

* **USDT (TRON / TRC20)**: `TPuueui5rRCL3ECV6dWmBzeDkaTV2JEyAn`

Thank you for your generosity and support! ❤️