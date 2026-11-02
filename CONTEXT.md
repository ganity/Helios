# Helios

Helios 管理本机应用流量，根据规则选择直连、拒绝或经加密节点转发，并确保系统网络设置可以安全恢复。

## 配置与身份

**Node（节点）**：
一个可连接的 Helios 服务端及其地址、身份校验和传输偏好。节点不包含运行时健康状态。
_Avoid_: Server、Endpoint

**Profile（配置档）**：
一组可激活的节点选择、运行模式、DNS 设置和规则引用。首版只提供一个默认配置档。
_Avoid_: Subscription、Account

**Credential（凭据）**：
客户端访问节点所需的秘密身份材料，例如随机 token。节点只保存凭据引用，不保存明文凭据。
_Avoid_: Password、Secret Key

## 流量与策略

**Inbound（入口）**：
流量进入 Helios 的方式，限定为 SOCKS5、HTTP CONNECT 或 TUN。
_Avoid_: Listener、Input

**Flow（流）**：
一次需要独立路由决策的 TCP 连接或 UDP 会话。
_Avoid_: Request、Connection

**Target（目标）**：
流希望访问的域名或 IP、端口及网络协议。
_Avoid_: Destination、Address

**Rule（规则）**：
对 Flow 上下文进行匹配并产生 Route Decision 的有序声明。
_Avoid_: ACL、Filter

**Route Decision（路由决定）**：
规则计算出的 Direct、Proxy 或 Reject 结果；Proxy 结果必须确定一个 Node。
_Avoid_: Policy Result、Action

**Mode（模式）**：
覆盖常规规则计算的用户选择，限定为 Rule、Global 和 Direct。
_Avoid_: Profile、Strategy

## 传输与协议

**Session（会话）**：
客户端与单个节点建立的、经过认证的 Helios 协议关系。一个 Session 可以承载多个 Flow。
_Avoid_: Tunnel、Connection

**Transport（传输）**：
承载 Helios 协议的 QUIC 或 TCP/TLS 机制。Transport 不决定业务路由。
_Avoid_: Protocol、Channel

**Helios Protocol（Helios 协议）**：
在加密 Transport 内表达认证、建流、UDP 数据和控制消息的版本化应用层协议。
_Avoid_: Encryption Protocol、Obfuscation Protocol

**Fallback（回退）**：
QUIC 不可用时让新 Flow 改用 TCP/TLS 的过程。它不迁移已建立的 Flow。
_Avoid_: Seamless Migration、Failover

## 系统状态

**System Proxy Lease（系统代理租约）**：
Helios 对系统代理设置的有期限所有权记录，包含原设置、Helios 设置和恢复状态。
_Avoid_: Backup、Proxy Toggle

**Tunnel Lease（隧道租约）**：
Helios 对 TUN、路由和 DNS 系统改动的有期限所有权记录，用于幂等停止和异常恢复。
_Avoid_: TUN State、Route Backup

**Health Sample（健康样本）**：
对节点在特定时间、特定 Transport 下的握手或应用层往返测量。
_Avoid_: Ping

**Metric Snapshot（指标快照）**：
某一时刻客户端速率、累计字节、Flow 数和 Transport 状态的只读视图。
_Avoid_: Telemetry、Analytics
