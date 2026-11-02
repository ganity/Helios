# 产品与总体架构

## 1. 产品边界

Helios 为一个用户管理若干海外 Linux 节点。桌面客户端负责本地流量入口、规则、DNS、节点选择、系统集成和可视化；服务端负责认证、远端解析和受控出站。

完整产品由以下可执行程序组成：

| 程序 | 平台 | 权限 | 职责 |
|---|---|---|---|
| `helios-server` | Linux | 普通用户；绑定 443 时授予单项 capability | QUIC/TLS 接入、认证、DNS、TCP/UDP 出站 |
| `helios-daemon` | Windows/macOS | 普通用户 | Inbound、规则、Transport、配置、指标、IPC |
| `helios-desktop` | Windows/macOS | 普通用户 | 窗口、托盘、用户操作，不持有网络状态机 |
| `helios-helper` | Windows/macOS | 最小特权 | TUN、路由、DNS 和恢复；不处理代理 payload |

## 2. 运行时拓扑

```text
Browser/App ─┬─ System proxy ─ SOCKS5/HTTP ─┐
             └─ TUN ─ privileged helper ────┤
                                             ▼
                                      helios-daemon
                                      ├─ Policy
                                      ├─ DNS
                                      ├─ Node health
                                      └─ AutoTransport
                                          ├─ QUIC/UDP 443
                                          └─ TLS/TCP 443
                                             │
                                      helios-server
                                      ├─ Authentication
                                      ├─ Remote DNS
                                      └─ TCP/UDP outbound
```

`helios-desktop` 只通过本地 IPC 操作 daemon。窗口退出不终止 daemon；显式“退出 Helios”才停止入口并释放系统租约。

## 3. 深模块与 seam

### Policy

小接口：输入 Flow 上下文，返回 Route Decision。实现隐藏模式覆盖、规则顺序、域名规范化、CIDR 与节点选择。

```rust
pub trait Policy: Send + Sync {
    fn decide(&self, flow: &FlowContext) -> RouteDecision;
}
```

### Transport

小接口：建立 TCP Flow、UDP 会话并报告状态。实现隐藏 QUIC、TLS、连接缓存、回退与健康状态。

```rust
pub trait Transport: Send + Sync {
    async fn connect_tcp(&self, target: Target) -> Result<ProxyStream>;
    async fn associate_udp(&self, target: Option<Target>) -> Result<DatagramSession>;
    fn status(&self) -> TransportStatus;
}
```

首版仅有 `QuicTransport` 和 `TlsTransport` 两个真实 Adapter，因此 seam 有现实意义。`AutoTransport` 组合二者，但不泄露内部选择给调用者。

### Platform control

系统代理和 TUN 是两个独立 seam：前者可由 daemon 的普通权限 Adapter 完成；后者通过认证 IPC 调用 helper。两者不应共享一个含糊的 `PlatformManager`。

```rust
pub trait SystemProxyControl {
    fn acquire(&self, desired: ProxySettings) -> Result<SystemProxyLease>;
    fn release(&self, lease: &SystemProxyLease) -> Result<()>;
    fn recover(&self) -> Result<RecoveryReport>;
}

pub trait TunnelControl {
    async fn acquire(&self, desired: TunnelSettings) -> Result<TunnelLease>;
    async fn release(&self, lease: &TunnelLease) -> Result<()>;
    async fn recover(&self) -> Result<RecoveryReport>;
}
```

`helios-system-proxy` 当前提供平台无关的 lease 状态机：平台 Adapter 负责读取和应用完整原始 Snapshot，lease 负责原子记录、崩溃恢复、验证和 drift 检测。Windows/macOS 的具体 Adapter 必须接入官方系统接口后才能启用。

## 4. 建议工作区演进

第一阶段：

```text
crates/helios-protocol
apps/helios-client
apps/helios-server
```

需要桌面和 TUN 时再拆成：

```text
crates/helios-transport
crates/helios-routing
crates/helios-ipc
crates/helios-system-proxy
apps/helios-daemon
apps/helios-desktop
apps/helios-helper
```

不预建只有类型转发的空 crate。只有当逻辑具有两个调用者、两个 Adapter 或独立测试价值时才形成模块。

## 5. 关键数据流

### SOCKS5/HTTP Proxy Flow

1. Inbound 读取有上限且有超时的请求头。
2. 保留原始 Target 域名，不进行不必要的本地解析。
3. Policy 计算 Route Decision。
4. Direct 使用本地 socket；Reject 返回协议对应错误；Proxy 交给所选 Node 的 Transport。
5. 建流成功后进行双向复制，传播半关闭和取消。
6. 指标只记录聚合字节数和错误类别。

### TUN Flow

1. helper 创建 TUN、写入路由和 DNS，返回 Tunnel Lease。
2. TUN 数据交给 netstack；Fake-IP 映射补充域名上下文。
3. Policy 计算 Route Decision。
4. Flow 经本地直连或 Node Transport 转发。
5. helper 在停止、异常恢复或下次启动时释放租约。

## 6. 生命周期

daemon 启动顺序：

1. 读取并验证配置。
2. 恢复遗留 System Proxy Lease 和 Tunnel Lease。
3. 初始化凭据和节点，但不自动修改系统设置。
4. 启动本地 IPC。
5. 启动 Inbound。
6. 按用户配置选择是否获取新租约。
7. 发布 Ready 状态，允许 UI 操作。

daemon 和 server 都响应 Ctrl-C：先停止三个本地入口/两个公网监听器接受新连接，再等待 2 秒让已建立 Flow 完成或被上层关闭。超出宽限期后进程退出；桌面端的显式关闭命令将在认证 control 接口具备平台身份校验后复用同一生命周期路径。

关闭顺序相反：先停止接收新 Flow，再等待有界宽限期，释放系统租约，最后关闭 IPC。任何一步失败均记录可供下次启动恢复的状态。

## 7. 稳定性约束

- daemon 不因单个 Flow、节点或 UI 失败退出。
- helper 请求必须幂等；重复 acquire/release 不破坏系统状态。
- 配置无效时保留最后一个有效运行配置。
- QUIC 失败不会关闭已有 TCP/TLS Flow。
- 节点切换只影响新 Flow。
- 系统代理与 TUN 可分别使用，但默认互斥；TUN 运行时切换到系统代理会先请求停止，helper 确认离线后用户重试；陈旧状态下先请求授权恢复路由，再允许代理接管。
- 所有后台任务必须有 owner、取消信号和有界关闭时间。

## 8. 性能目标

这些是验收目标，不是接口保证：

- 代理关闭时不改变系统网络。
- 空闲 daemon + desktop 的目标常驻内存小于 60 MiB；15 MiB 不作为硬指标。
- 个人使用下支持至少 1,000 个并发 TCP Flow。
- 在正常网络中，转发吞吐不低于 VPS 单核和链路瓶颈的较小者的 80%。
- UI 指标刷新频率 1 Hz，不因图表高频重绘影响转发。
