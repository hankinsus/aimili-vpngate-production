# Wi-Fi Calling / UDP 支持基线

## 关键结论

“SOCKS5 支持 UDP”与“手机 Wi-Fi Calling 一定可用”不是同一件事。

Wi-Fi Calling 通常涉及运营商 IMS/ePDG 的 IPsec 路径。Apple 公布的端口信息包含 UDP 4500 用于 Wi-Fi Calling；Android 网络建议也明确涉及 IPsec NAT-T，常见为 UDP 4500，并要求网络允许相关 IPsec 流量。

因此需要验证的是整条链路：

手机
→ 全局 VPN/TUN 或系统路由
→ UDP 500 / UDP 4500（以及必要时 ESP）
→ 运营商 ePDG/IMS
→ Wi-Fi Calling 建立

## 本项目当前状态

### 已增加

本项目 SOCKS5 已实现 RFC 1928 UDP ASSOCIATE：

- UDP framing
- IPv4 / IPv6 地址类型
- 上游 UDP socket
- 与活动 VPN 网卡绑定
- UDP 关联空闲回收

这解决的是“应用通过 SOCKS5 使用 UDP”的能力。

### 尚未等同于

它仍不等于系统级 Wi-Fi Calling 透传。

如果手机的 Wi-Fi Calling 流量没有经过 SOCKS5，而是由系统直接产生 IPsec/NAT-T 流量，那么必须保证承载该流量的 VPN 数据面能够透明携带 UDP 4500；仅提供应用层 SOCKS5 无法替代系统级 VPN/TUN。

## 推荐的数据面

Wi-Fi Calling 优先级：

1. WireGuard / IKEv2 / OpenVPN-UDP / 具备 TUN 的数据面
2. Xray/sing-box TUN + UDP 能力
3. SOCKS5 UDP 只作为应用层能力

对于 VMess/VLESS 业务转发，优先把 Xray-core 或 sing-box 与管理面分离。管理面负责路由选择和配置，数据面负责长期 TCP/UDP 流量。

## 诊断顺序

1. 检查服务器公网出站 UDP 是否可用。
2. 检查防火墙和云厂商安全组是否允许出站 UDP 500/4500。
3. 检查所选 VPN 数据面是否支持 UDP。
4. 检查 NAT 是否保持 UDP 4500 映射足够长。
5. 检查手机侧运营商是否允许当前漫游/网络条件下的 Wi-Fi Calling。
6. 使用抓包或连接日志确认 IKE/IPsec/ePDG 阶段卡在哪一步。

## 结论

后续验收不能只写“SOCKS5 UDP 测试通过”。

必须分别验收：

- SOCKS5 UDP
- VPN 隧道 UDP
- UDP 4500 出站
- 全局 TUN/系统流量透传
- 最终 Wi-Fi Calling 实机注册与通话

