# AimiliVPN 低资源服务器架构基线

## 目标

正式支持 1 vCPU / 1 GB RAM 的基础服务器。该规格上的 Python 管理进程只承担控制面，不承担高吞吐业务数据面的长期转发。

## 生命周期原则

前端是无状态控制台。打开、刷新、关闭浏览器都只能读取后端状态，不得建立或销毁 VPN 隧道。

后端 aimilivpn.service 是连接生命周期的唯一拥有者：

- 持续维护当前 VPN 隧道、活动出口、代理和资源池。
- 节点故障由后台故障恢复逻辑处理。
- 只有用户主动切换或断开才执行对应连接写操作。
- /api/ui/state、/api/ui/nodes、/api/ui/country_catalog 是读取接口，不负责连接动作。

## 控制面优化

1. 管理后台使用 HTTP/1.1 keep-alive，避免 Nginx 到 Python 的重复 TCP 建连。
2. UI state 使用短 TTL 内存缓存，多个页面读取同一状态时避免重复磁盘/数据库读取。
3. Dashboard HTML 使用 ETag；静态 Logo 长缓存。
4. 默认关闭逐请求访问日志，避免低资源磁盘 I/O。
5. Master Pool 使用 SQLite WAL、NORMAL 同步、短 busy timeout 和内存 page cache。
6. 国家库存和 Pool stats 使用短 TTL 缓存；节点列表查询在 SQL 端分页，不向前端发送整个池。
7. 后台探测批次默认降低到适合 1C1G 的规模，避免探测线程压垮管理进程。

## 数据面原则

对于 VMess、VLESS、业务转发和大流量场景，不建议把 Python HTTP/SOCKS5 relay 作为最终数据面。

推荐：

`aimilivpn-manager`（控制面）
→ 生成/维护配置
→ `xray-core` 或 `sing-box`（数据面）
→ 承担 TCP/UDP/TUN/VMess/VLESS/业务转发

Python 只负责选择、健康检查、配置编排、状态和运维；高吞吐连接交给专门的数据面实现。

## 资源建议

### 1C1G

- Python Manager：常驻控制面
- SQLite：本地 Master Pool
- Nginx：HTTPS 入口
- SOCKS5：低并发本地/管理用途
- Xray/sing-box：业务转发
- 后台探测：小批次、低频、分协议公平调度

### 2C2G+

可以逐步提高探测批次、代理并发和数据面连接数，但所有参数都通过环境变量覆盖，不把高负载参数写死。

## 验收指标

后续压测应分别统计：

- API 首字节时间（TTFB）
- /api/ui/state P50/P95/P99
- /api/ui/nodes P50/P95/P99
- Dashboard 首次加载大小
- TCP CONNECT 延迟
- SOCKS5 CONNECT 建连成功率
- UDP ASSOCIATE 成功率
- 业务转发吞吐与 CPU
- 24h/72h 长连接稳定性
- 内存常驻与峰值

