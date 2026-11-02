# 客户端、桌面界面与 IPC

> 本文包含目标设计。当前正式 egui 实现和待完成项以 [功能补全清单](11-feature-completion.md) 为准；不要把下列目标命令、事件及平台能力都视为已实现。

## 1. 进程职责

### helios-daemon

- 持有当前有效配置、Node、Session、Flow 和指标。
- 提供 SOCKS5、HTTP CONNECT 和 TUN 数据入口。
- 执行规则、DNS 和 Transport 选择。
- 管理 System Proxy Lease。
- 通过受认证 IPC 请求 helper 管理 Tunnel Lease。
- 对 UI 提供命令和只读事件。

### helios-desktop

- 展示 daemon 的状态，不缓存第二份权威状态。
- `crates/helios-client-model` 独立承载节点/桌面配置、规则解析与匹配测试、导入校验和平台默认路径，不依赖具体 UI 框架；当前 egui 前端与 `experiments/helios-client-gpui` 必须复用该模型，禁止各自实现第二套配置语义。
- `crates/helios-client-control` 封装认证 IPC、端点连接、超时、状态查询、规则更新、优雅关闭及 TLS/QUIC 节点认证延迟探测；UI 前端只处理结果和交互，不得自行序列化 control 消息、复制占用检测或握手探测逻辑。
- 本地保存节点列表、活动节点和编辑中的路由规则；旧单节点 profile 首次读取时迁移为单元素节点列表。
- 支持新增、删除、切换节点，并对活动节点或全部节点执行真实 TLS/QUIC 认证 RTT 探测，逐传输显示握手、延迟、时间与失败原因。桌面保存配置后重启受管理 daemon 来应用节点和监听变更；新窗口可在认证后重新控制标记为桌面管理的 daemon，普通 CLI daemon 不自动接管。节点切换会中断旧连接。
- Node 页支持通过可复制 JSON 导出活动节点或导入为新节点。交换格式只包含节点字段和凭据文件路径，不读取或嵌入 token、CA 证书内容；导入时严格拒绝未知字段和非法地址、名称或凭据 ID。
- GPUI 实验使用原生文件选择器导入相同 Node JSON，文件最大 64 KiB；活动节点不可删除。切换节点时仅重启当前窗口拥有的 daemon；外部 daemon 保持运行并提示由所有者重启。
- 路由页使用与 daemon 相同的 `RuleSet`，可以针对域名、IPv4、IPv6 和目标端口即时预览当前未保存规则的 Proxy、Direct 或 Reject 结果，并显示命中的规则序号和原始内容。
- 提交完整且带 revision 的修改命令。
- 关闭窗口默认隐藏到托盘。
- 无 daemon 时展示启动/恢复错误，不自行接管网络。

### helios-helper

- 校验调用方身份和请求 schema。
- 只执行允许列表中的 TUN、路由、DNS 操作。
- 持久化 Tunnel Lease，支持恢复。
- 不读取 Node Credential，不连接服务端，不解析代理数据。

## 2. 本地 Inbound

默认监听：

```text
127.0.0.1:1080   SOCKS5
127.0.0.1:8080   HTTP CONNECT
```

IPv6 loopback 可配置为 `[::1]`。默认禁止绑定非 loopback；允许局域网访问属于未来功能，必须额外提供本地认证和防火墙提示。

SOCKS5 v1：

- 无认证方法。
- 支持 CONNECT 与 UDP ASSOCIATE。
- 保留域名，不提前解析 Proxy Flow。
- 不支持 BIND。
- UDP 优先使用独立 QUIC connection 和 QUIC datagram；QUIC association 不可用时，Proxy 规则使用独立 TLS framed stream，Direct 规则仍本地转发，绝不静默回退为直连。

HTTP v1：

- 支持 CONNECT authority-form 和常用方法的 HTTP/1.0/1.1 absolute-form forward proxy。
- Header 总长度最大 16 KiB，数量最大 64。
- Header 读取超时默认 5 秒。
- forward 请求改写为 origin-form，并移除 `Proxy-Connection`；不缓存或解析 body。

Windows 桌面可启用当前用户的 HTTP/HTTPS 系统代理，将普通 HTTP 和 HTTPS CONNECT 流量指向本地 HTTP proxy listener。Adapter 精确保存 `ProxyEnable`、`ProxyServer`、`ProxyOverride` 的值和缺失状态，写入后广播 WinINet 设置变更；关闭、退出或下次启动恢复 Lease。

桌面 Settings 可逐行配置系统代理 bypass。默认绕过 localhost、loopback、RFC1918、link-local 和 `.local`，启用时还会自动加入当前节点 IP，避免系统代理捕获节点连接形成环路。空行会忽略，重复项会去重，包含平台分隔符的条目会拒绝保存。

macOS 桌面使用系统自带 `networksetup` 枚举所有启用的网络服务，逐服务保存和恢复 Web Proxy、Secure Web Proxy 与 bypass domains。已启用的认证代理无法读取原密码，因此 Helios 会拒绝接管而不是生成不可恢复的 Lease。

## 3. IPC

当前阶段在 macOS/Linux 使用权限为 `0600` 的 Unix Domain Socket，在 Windows 使用拒绝远程客户端、仅允许对象所有者和 SYSTEM 访问的 Named Pipe；旧配置仍可显式使用 loopback TCP control Adapter。`heliosctl` 和桌面可读取聚合指标及内存中的当前连接详情，桌面可原子更新路由规则和取消列出的单条连接。停止后台使用认证 Shutdown：停止接收新 Flow，活跃 Flow 归零立即退出，最多等待 2 秒；桌面等待超时后仅可强制终止持有子进程句柄的 daemon，对重新连接的后台不会猜测 PID 强杀。请求使用 64 KiB 有界长度帧、版本化 JSON 和现有节点 32 字节 token 认证，每个 connection 只处理一个请求。daemon 使用常量时间比较校验 token，不返回凭据或访问历史；系统代理、TUN 和节点凭据变更尚未通过此 control Adapter 开放。

两类本地 IPC 复用同一个 `helios-control` schema。Unix socket 由当前用户私有目录和 `0600` 权限约束；Windows Named Pipe 使用保护 DACL，并继续要求 token 认证。helper 使用平台提供的授权边界。系统代理、TUN 和节点凭据变更不得通过 control Adapter 开放。

消息格式：

```text
Length: u32 (max 1 MiB)
Version: u16
Request ID: u64
Kind: u16
Payload: postcard/CBOR bytes
```

当前使用 `serde_json`，control schema version 为 4，单条消息最大 64 KiB。支持 `GetStatus`、`UpdateRules`、`CloseFlow`、`SetSystemProxy`、带 revision 的 `ApplyConfig`、过期 DNS 映射清理及 `Shutdown`。IPC 与公网 Helios Protocol 完全分离。

### 命令

```text
GetSnapshot
ApplyConfig(expected_revision, config)
ListNodes
UpsertNode(expected_revision, node)
DeleteNode(expected_revision, node_id)
SetActiveNode(node_id)
TestNode(node_id, transports)
SetMode(mode)
SetSystemProxy(enabled)
SetTunnel(enabled)
MatchRule(sample)
ListFlows(filter, cursor)
CloseFlow(flow_id)
ExportDiagnostics(options)
Shutdown
```

### 事件

```text
SnapshotChanged
MetricSnapshot
NodeHealthChanged
FlowOpened
FlowUpdated
FlowClosed
LogEvent
RecoveryRequired
```

慢 UI 不得阻塞 daemon。事件队列有界；指标和 Flow update 允许合并或丢弃，状态变化不允许静默丢失，队列溢出时要求 UI 重新获取 snapshot。

## 4. UI 信息架构

左侧导航：

```text
状态
节点
规则
DNS
连接
日志
设置
```

### 状态

- 运行状态和最近错误。
- 当前 Node、Mode 和 Transport。
- System Proxy、TUN 两个独立开关。
- 实时上下行、累计流量、活跃 Flow。
- 每 2 秒从 daemon 累计计数计算实时上下行速率；高级连接页最多保留 60 次采样的流量图，正常轮询约 2 分钟。daemon 重启导致计数归零时速率按 0 处理。
- QUIC 降级时显示原因和下次探测时间。

### 节点

字段：名称、主机、端口、凭据引用、证书模式、首选 Transport、TCP fallback、连接超时。

节点行展示：

- 最近 QUIC 和 TCP/TLS 应用层 RTT。
- 最近 TCP/TLS 应用层 RTT。
- Available、Degraded、Unavailable 或 Unknown。
- 最近检查时间和失败类别。

“延迟”定义为已完成协议握手后的 Helios PING/PONG；同时在详情中展示握手耗时。禁止把 ICMP ping 混称为节点延迟。

### 规则

- 支持 Rule、Global Proxy、Global Direct 三种模式；模式切换复用规则热更新接口，无需重启 daemon。
- Global 模式只向 daemon 下发单条 Final 规则，用户编辑的 Rule 规则原样保留，切回 Rule 后继续使用。
- 有序规则列表、启用、添加、编辑、删除、排序。
- 输入域名/IP/端口/协议进行匹配预览。
- 导入前展示验证错误和变更摘要。
- v1 不提供在线规则订阅。

### DNS

- 当前独立 DNS 页支持启停 Fake-IP、本地监听地址、缓存容量与响应 TTL。
- Fake-IP 使用 `198.18.0.0/15`，进入 TCP/UDP 数据面后恢复原始域名再执行路由。
- 明确提示应用自带 DoH 可能绕过本地 DNS 与域名规则。
- Real-IP 上游选择、缓存命中率和清空缓存尚未实现。

### 连接

- 当前 Connections 页通过认证 IPC 展示活跃 Flow 的 ID、Inbound、Target、路由决策、实际传输、持续时间与独立上下行字节。
- daemon 最多返回 256 条明细，但活跃总数始终准确，避免突破 64 KiB IPC 消息上限。
- Flow 结束即从内存注册表移除，不落盘、不保留访问历史；历史只保留聚合流量指标。
- UDP association 可能同时承载 Direct 与 Proxy 数据包，因此决策显示为 `mixed`，传输显示 association 建立时可用的 QUIC、TLS 或 Direct。
- 节点名称和绝对开始时间尚未实现。

### 日志

- 等级、模块、时间和错误类别筛选。
- 默认脱敏。
- 诊断模式有时限，到期自动恢复普通日志等级。
- 桌面启动 daemon 时将 JSON stderr 写入状态目录的 `daemon.log`；达到 5 MiB 时启动前轮换为 `daemon.log.1`，最多保留当前文件和一份历史文件。Unix 日志权限为 `0600`。Logs 页每 2 秒读取文件末尾最多 128 KiB、展示最多 200 条结构化事件，只显示时间、等级和脱敏事件名，不展示 DEBUG 错误详情；Settings 页显示路径并可打开日志目录。
- 导出前提示可能包含网络元数据。

### 设置

- 开机启动、启动时连接、关闭窗口行为。
- IPv6、局域网绕过、超时。
- 配置目录、版本、许可证。
- 恢复系统网络、导出诊断、退出并恢复。

## 5. 托盘

```text
Helios · Connected
US VPS · QUIC · 82 ms
────────────
✓ System Proxy
  TUN
────────────
✓ Rule
  Global
  Direct
────────────
Nodes >
Open Helios
Quit and restore network
```

托盘操作调用相同 IPC 命令，不包含第二套业务逻辑。

当前实现提供最小生命周期菜单：显示主窗口、启停由桌面启动的 daemon、退出 Helios。Windows/macOS 关闭主窗口时应用继续驻留托盘；显式退出会停止桌面自有 daemon，并由 Drop 路径恢复系统代理租约。

## 6. 状态一致性

- daemon 是唯一权威状态源。
- 配置带单调递增 `revision`。
- UI 修改必须携带读取时的 revision；冲突时重新加载而不是覆盖。
- UI 的开关先显示 Pending，收到 daemon 确认后才显示 On/Off。
- 失败时保留原值并展示可操作错误。
- 系统设置的实际值与租约不一致时显示 Drifted，不假装已启用。

## 7. Node 健康与选择

检测步骤：DNS → Transport handshake → AUTH → PING/PONG。QUIC 使用长期控制流；TLS 使用独立短连接，服务端按首帧区分健康探测和 CONNECT。分别记录耗时和错误。

默认策略：

- 手动选择 Node 为主。
- 当前 Node 连续 3 次新建 Flow 失败后标记 Degraded。
- 配置了备用 Node 时，新 Flow 才切换。
- 原 Node 恢复后不自动抢回。
- 后台检测最短间隔 30 秒，并加入随机抖动。
- UI 手动检测不改变当前 Node。

首版不实现自动最低延迟负载均衡。

## 8. 资源与隐私

- UI 指标刷新 1 Hz，图表最多保留 10 分钟内存数据。
- Flow 列表分页，daemon 不向 UI 推送每个数据包。
- 默认不落盘访问历史、目标域名或进程路径。
- 日志文件滚动并有总大小上限。
- desktop 崩溃不影响 daemon；daemon 崩溃后 helper 和下次启动负责恢复租约。
