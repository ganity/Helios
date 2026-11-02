# 测试、里程碑与验收

## 1. 测试层次

### 单元测试

- 协议编解码、所有长度边界和错误类别。
- 域名规范化、后缀边界、CIDR 和规则顺序。
- AutoTransport 状态转换和冷却。
- Fake-IP 分配、TTL、回收和容量限制。
- 配置交叉验证和 schema 迁移。
- System Proxy Lease、Tunnel Lease 的幂等恢复。
- 指标计算不溢出。

### 属性测试与 fuzz

目标：协议帧、SOCKS5、HTTP CONNECT、DNS、配置导入和 IPC。

关键性质：

```text
decode(encode(x)) == x
任意输入不 panic
声明长度超过上限时不做等量分配
规则结果确定且顺序稳定
重复 release 租约不破坏用户设置
```

### 集成测试

- SOCKS5 → QUIC → server → TCP echo。
- HTTP CONNECT → QUIC → HTTP origin。
- QUIC 被丢弃 → 新 Flow TCP/TLS 回退。
- 远端域名解析，不触发客户端 DNS。
- UDP association → QUIC datagram → DNS echo。
- server 重启、证书错误、token 错误、超时。
- desktop 重启而 daemon 持续工作。
- System Proxy 强杀后恢复。
- TUN 强杀后恢复和无环路。

### 网络仿真

Linux 使用 netem 模拟：

- 50–500 ms 延迟和抖动。
- 1%、5%、10% 丢包。
- UDP 全丢弃。
- 带宽和队列限制。
- DNS 超时和错误响应。
- 中途断开、地址变化、服务端 GOAWAY。

### 平台验收

Windows/macOS 真机或 VM：

- 睡眠/唤醒。
- Wi-Fi、以太网和热点切换。
- 强杀 desktop、daemon、helper。
- 注销、重启、升级和卸载。
- 原有代理/PAC 配置恢复。
- 普通用户与管理员账户。
- IPv4-only、IPv6-only 和双栈网络。

## 2. CI 阶段

仓库的 `.github/workflows/ci.yml` 使用固定 Rust 1.95.0：Linux 执行完整格式、测试、Clippy 和 Release 构建；Windows/macOS 原生 runner 检查并 Clippy 桌面、daemon、helper 与诊断 CLI。平台真机网络、提权和签名测试仍属于发布门禁，不能由编译 CI 替代。

每个 PR：

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check
cargo audit
```

夜间：

- Windows/macOS/Linux 完整矩阵。
- 协议和解析器 fuzz 时间预算。
- netem 集成测试。
- release 构建和安装 smoke test。
- 依赖 SBOM 和可复现性比较。

涉及平台网络设置的测试必须在隔离 VM 中执行，不在普通共享 CI runner 修改宿主路由。

## 3. 阶段 0：协议验证

时间：1–2 周。

交付：

- `helios-protocol` 编解码与 fuzz target。
- Quinn/rustls 客户端和服务端 echo。
- TCP/TLS echo。
- 威胁模型和基准记录。

验收：

- 两种 Transport 各稳定传输 1 GiB。
- 错误证书和错误 credential 被拒绝。
- 非法帧不 panic、不超限分配。

## 4. 阶段 1：CLI 代理 MVP

时间：3–5 周；依赖阶段 0。

交付：

- SOCKS5 CONNECT、HTTP CONNECT。
- QUIC、TCP/TLS 新 Flow 回退。
- Linux 服务端、远端 DNS、systemd。
- 单 Node、Direct/Proxy、结构化日志。

验收：

- 浏览器和命令行工具稳定访问。
- Proxy 域名不在客户端解析。
- UDP/443 被阻断时 3 秒内让新 Flow 使用 TCP。
- 连续运行 72 小时，无持续内存增长和任务泄漏。

## 5. 阶段 2：规则与系统代理

时间：3–4 周；依赖阶段 1。

交付：

- Rule/Global/Direct。
- DOMAIN、DOMAIN-SUFFIX、IP-CIDR、FINAL。
- Windows/macOS System Proxy Lease。
- 原子配置和恢复 CLI。

验收：

- 匹配预览与真实 Flow 结果一致。
- 正常退出、强杀、重启均能恢复 Helios 设置。
- 用户在运行中改变的代理设置不会被盲目覆盖。

## 6. 阶段 3：桌面产品

时间：4–6 周；依赖阶段 2。

交付：

- daemon/desktop 分离和 IPC。
- 节点 CRUD、健康检测、状态页、规则页、日志页。
- 托盘、流量图、活跃 Flow。
- Windows/macOS 安装包。

验收：

- desktop 关闭/崩溃不影响代理。
- 重启 desktop 后状态与 daemon 一致。
- Node 检测分别展示 QUIC/TCP 结果。
- 配置 revision 冲突不会丢失修改。

## 7. 阶段 4：Windows TUN

时间：4–8 周；依赖阶段 3。

交付：

- helper、Wintun、tun2proxy、Tunnel Lease。
- TCP/UDP、局域网和服务端绕过。
- TUN UI、恢复工具。

验收：

- 忽略系统代理的应用也能经 TUN 工作。
- 不发生 daemon 出站回环。
- 强杀任一进程并重启后可恢复网络。
- TUN 关闭后系统路由和 DNS 与启用前一致或明确报告冲突。

## 8. 阶段 5：Fake-IP DNS

时间：4–6 周；依赖阶段 4。

交付：

- Helios DNS、Fake-IP 池、缓存。
- TUN 域名规则、Real-IP 兼容模式。
- DNS 页面和诊断。

验收：

- 域名规则能从 DNS 到 Flow 保持一致。
- Fake-IP 池达到容量时有界回收。
- DNS 上游失败不导致无限等待。
- DoH 和直接 IP 限制在 UI 中可见。

## 9. 阶段 6：macOS TUN

时间：6–10 周；依赖阶段 5。

交付：

- Network Extension、最小原生 glue。
- 签名、公证、授权和卸载流程。
- 睡眠和网络变化处理。

验收：

- 公证安装包可在干净 macOS 上安装。
- 系统 VPN 授权、启停、升级、卸载行为正确。
- 睡眠/唤醒和网卡切换后不形成路由环路。

## 10. 阶段 7：1.0 稳定化

时间：1–3 月。

1.0 门槛：

- Protocol v1 冻结并有兼容性测试。
- Windows/macOS 配置迁移、升级和卸载通过。
- 核心解析器持续 fuzz，无已知 crash。
- QUIC/TCP 故障矩阵通过。
- 系统代理和 TUN 不存在已知断网遗留。
- 依赖、许可证、SBOM 和发布签名完成。
- 至少一个月个人真实网络 dogfood。

## 11. 发布退出条件

任何里程碑出现以下问题不得进入下一阶段：

- 已知可导致断网且不能自动恢复。
- 凭据或 payload 进入默认日志。
- 未认证输入可触发无界内存、任务或文件增长。
- 测试依赖人工修改生产机器网络设置。
- 关键平台只能以关闭 TLS 验证或长期管理员权限运行。

## 12. 粗略工作量

一名熟悉 Rust async 和平台网络的开发者：8–12 个月。两名开发者分别负责网络核心、桌面/平台：5–8 个月。估算包含测试、签名、安装和真实网络稳定化，不只计算功能编码。
