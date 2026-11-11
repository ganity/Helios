# 路由、DNS 与 TUN

## 1. 统一决策模型

所有 Inbound 构造同一个 `FlowContext`：

```rust
pub struct FlowContext {
    pub inbound: InboundKind,
    pub network: Network,
    pub source: SocketAddr,
    pub domain: Option<NormalizedDomain>,
    pub destination_ip: Option<IpAddr>,
    pub destination_port: u16,
    pub process: Option<ProcessIdentity>,
}

pub enum RouteDecision {
    Direct,
    Proxy(NodeId),
    Reject,
}
```

Mode 在规则前生效：

- Direct：除 Helios 自身控制流量外均 Direct。
- Global：本地保留地址和明确保护目标 Direct，其余 Proxy。
- Rule：按有序 Rule 计算。

系统安全规则优先于用户规则，例如服务端地址、loopback 和 TUN 自身流量不得再次进入代理。

## 2. 规则语义

v1 支持：

```text
DOMAIN
DOMAIN-SUFFIX
IP-CIDR
IP-CIDR6
DST-PORT
NETWORK
FINAL
```

后续按真实需求增加 `PROCESS-NAME` 和 `PROCESS-PATH`。仅增加内置 CN IP 快照；其他 GEO 国家、脚本和远程订阅不在本次范围。

当前阶段已实现 TCP Target 和 SOCKS5 UDP Target 的 `DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`、`IP-CIDR6`、`DST-PORT`、`NETWORK` 和 `FINAL`，以及 Direct、Proxy、Reject 三种动作。`NETWORK` 的值严格为 `tcp` 或 `udp`，与其他规则一样按顺序匹配；HTTP/SOCKS CONNECT 使用 TCP，SOCKS UDP 使用 UDP。SOCKS5、HTTP CONNECT 与 SOCKS5 UDP 共用可热更新的规则决策；新规则完整验证后原子替换。TUN 平台支持范围见实施状态。

桌面文本规则示例：`network,udp,reject`。规则测试器可选择 TCP/UDP，使用与实际转发相同的决策入口。旧版 `decide(Target)` API 默认 TCP。

规则从上到下匹配，第一个命中生效。新增 `geoip,cn,direct`（可加 `no-resolve`）、`ip-cidr,...,direct,resolve` 和 `ip-cidr6,...,direct,resolve`。原有三字段 CIDR 不主动解析域名。遇到允许解析的 IP 规则时，daemon 按需解析并从原规则位置继续，后续 IP 规则可使用结果。规则引擎本身不执行网络 I/O；同步旧 API 只做无解析匹配。运行时测试与实际转发使用同一异步入口。具体语义、缓存和启用步骤见 [域名与国内 IP 分流](16-domain-ip-routing.md)。

当前域名执行去尾点、ASCII 小写；IDNA 规范化尚未实现。`DOMAIN-SUFFIX,example.com` 匹配 `example.com` 和 `a.example.com`，但不匹配 `badexample.com`。

示例：

```yaml
rules:
  - type: domain-suffix
    value: example.cn
    action: direct
  - type: ip-cidr
    value: 192.168.0.0/16
    action: direct
  - type: network
    value: udp
    action: proxy
  - type: final
    action: proxy
```

个人规则量在数千条内时使用简单有序结构。只有 profile 证明匹配成为热点后再增加域名后缀索引，并保证顺序语义不变。

## 3. DNS 模式

### System

Direct Flow 使用系统解析；Proxy 域名由服务端解析。适用于 System Proxy 模式。

### Real-IP

Helios DNS 返回真实 IP，同时记录短期 `domain → IP` 观察映射。TUN Flow 可能因共享 IP 或缓存而无法可靠恢复域名，因此域名规则只是尽力而为。

### Fake-IP

Helios DNS 为域名分配保留地址，TUN Flow 用该地址查回域名，再由服务端解析真实地址。默认池：

```text
IPv4: 198.18.0.0/15
IPv6: fdfe:dcba:9876::/96
```

Fake-IP 映射只在内存保存，重启后重新分配。当前实现使用 198.18.0.0/15 与 fdfe:dcba:9876::/96，共享稳定的域名映射、容量上限、TTL 清理与最旧项驱逐；默认容量 4096、TTL 60 秒。daemon 的可选 UDP DNS responder 同时回答 A 与 AAAA，IPv4/IPv6 Fake-IP 均可反查回原域名；其他类型返回 NotImplemented。

## 4. DNS 查询路由

```text
Application DNS query
        │
        ▼
Helios DNS
  ├─ local/system zone → local resolver
  ├─ Direct rule       → configured local upstream
  └─ Proxy/unknown     → Fake-IP or remote resolver
```

TUN + Fake-IP 下，未知域名先返回 Fake-IP，真正的 Proxy/Direct 决定在 Flow 出现时计算。这避免 DNS 查询阶段缺少端口和进程上下文。

当前 responder 和目标反查数据面已经实现，但不会主动修改系统 DNS；正式系统 DNS 接管、精确恢复与崩溃恢复仍由后续特权 helper 完成。

要求：

- 缓存 key 包含 qname、qtype 和 DNS 模式。
- 尊重 TTL，但设置合理最小/最大值。
- negative response 有短 TTL。
- 有界缓存和并发查询合并。
- DNS 超时不能无限阻塞 Flow。
- 默认不记录完整 qname。

应用自带 DoH、直接 IP 和缓存结果可能绕过域名上下文，UI 和文档必须明确该限制。

## 5. TUN 数据路径

第一实现采用：

```text
TUN device
   ↓ IP packets
tun2proxy/netstack
   ↓ logical TCP/UDP Flow
Policy
   ├─ Direct socket
   ├─ Proxy Transport
   └─ Reject
```

如果 tun2proxy 无法满足性能、IPv6 或生命周期需求，再直接集成 smoltcp；在有测量证据前不自建 netstack。

## 6. Windows

- Wintun 提供 Layer 3 adapter。
- helper 创建 adapter、分配地址、设置 MTU、路由和 DNS。
- 服务端 IP、loopback、局域网和 helper/daemon 控制流量加入 bypass。
- 使用 Windows IP Helper API 或经过审核的 route_manager Adapter。
- helper 以 Windows Service 或一次性提权进程运行；优先选择可验证调用方的最小常驻服务。

## 7. macOS

正式发布使用 Network Extension `NEPacketTunnelProvider`。最小 Swift/Objective-C glue 负责 Apple 生命周期和 entitlement，Rust 负责可移植的协议、规则与 Transport。

需要验证两种集成方案：

1. Rust 静态库嵌入 extension，低延迟但 FFI 和生命周期复杂。
2. extension 与 daemon 通过受控 IPC 交换 packet，隔离好但复制和吞吐成本更高。

阶段 6 原型用基准选择，不预先承诺。开发环境中可用普通 TUN 做算法验证，但不能把它当成正式分发方案。

## 8. Tunnel Lease

租约持久化字段：

```text
lease_id
owner_instance_id
phase: acquiring | active | releasing
adapter identity
original routes/DNS needed for restoration
applied routes/DNS
server bypass route
created_at
```

获取顺序：

1. 写 `acquiring` 租约。
2. 创建 TUN。
3. 写入服务端 bypass。
4. 写入 TUN 路由。
5. 设置 DNS。
6. 自检服务端可达和无路由环路。
7. 标记 `active`。

释放顺序相反。任何阶段失败都执行补偿；补偿失败保留租约供下次恢复。

恢复只撤销与记录值一致的 Helios 改动。若用户或系统已修改同一项，标记冲突并使用平台安全默认值，不盲目覆盖。

## 9. MTU、IPv6 与 UDP

- 初始 TUN MTU 取保守值 1280，实测后按平台调整。
- 不依赖 IP 分片；过大 UDP 在进入 Transport 前按能力拒绝或由上层降低大小。
- 桌面默认让 TUN 同时接管 IPv4/IPv6；高级设置可显式关闭 IPv6 接管。helper 会同步配置 IPv6 默认路由，SOCKS/HTTP、协议 Target、TLS/QUIC 与服务端拨号均保留 IPv6 地址族。
- UDP association 默认空闲超时 60 秒，可配置 30–300 秒。
- Direct UDP 和 Proxy UDP 使用相同规则结果，但不同 socket Adapter。

## 10. 同时启用 System Proxy 与 TUN

默认互斥。TUN 已能接管大部分系统流量，再启用 System Proxy 可能让支持代理的应用经过两次入口。桌面请求停止 TUN 后不会立即启用系统代理；helper 确认离线后用户重试。若 helper 心跳已陈旧，则先请求授权恢复路由，恢复完成后用户再启用系统代理。

高级模式允许同时启用时，必须确保：

- 本地 SOCKS/HTTP 监听地址绕过 TUN。
- daemon 出站 socket 绕过 TUN。
- UI 明确显示双接管状态。
- 测试覆盖浏览器不会形成环路。
