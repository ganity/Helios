# Helios

Helios 是面向个人使用的跨平台加密网络工具，由 Windows/macOS/Linux 桌面客户端和 Linux 服务端组成。项目自主定义应用层协议、路由策略和产品行为；密码学、TLS、QUIC 与平台虚拟网卡能力使用可审计的成熟实现。

## 设计目标

- 单用户、少量桌面终端，优先保证稳定性和可恢复性。
- 同时支持系统代理和 TUN 模式。
- 代理目标域名默认由服务端解析。
- QUIC 优先，TCP/TLS 为新连接自动回退。
- 客户端具有节点、规则、DNS、连接和监控界面。
- 核心、UI 与特权操作分离，最小化高权限代码。
- 依赖版本固定、源码可审计、构建过程可追踪。

## 非目标

- 不自研密码算法或 QUIC/TLS。
- 不提供多用户、计费、订阅市场或 Web 管理面板。
- 不兼容公开代理协议，也不承诺协议“不可识别”。
- 首版不迁移已经建立的会话；传输回退只影响新连接。
- 首版不追求复杂规则订阅、脚本规则或移动端。

## 文档索引

- [实施状态](docs/00-implementation-status.md)
- [功能补全、验证与升级清单](docs/11-feature-completion.md)
- [统一术语](CONTEXT.md)
- [产品与总体架构](docs/01-architecture.md)
- [Helios 协议](docs/02-protocol.md)
- [客户端、桌面界面与 IPC](docs/03-client.md)
- [Linux 客户端安装与支持范围](docs/09-linux-client.md)
- [路由、DNS 与 TUN](docs/04-routing-dns-tun.md)
- [配置与状态模型](docs/05-configuration.md)
- [安全、部署与运维](docs/06-security-operations.md)
- [Linux systemd unit](deploy/helios-server.service)
- [Linux server installer](deploy/install-server.sh)
- [测试、里程碑与验收](docs/07-testing-roadmap.md)
- [阶段 0 诊断 CLI](docs/08-stage0-cli.md)
- [架构决策记录](docs/adr/)

## 推荐技术栈

| 领域 | 选择 |
|---|---|
| 异步运行时 | Tokio |
| QUIC | Quinn |
| TLS | rustls / tokio-rustls |
| 桌面 UI | egui/eframe |
| 托盘 | tray-icon |
| 序列化 | Serde；配置 TOML，规则 YAML |
| 日志 | tracing |
| Windows TUN | Wintun |
| TUN 转代理原型 | tun2proxy |
| 路由 | route_manager 或平台原生接口 |
| 系统代理 | sysproxy，加 Helios 恢复层 |
| 密钥存储 | Windows Credential Manager / macOS Keychain |

## 交付顺序

1. 命令行 SOCKS5，经 QUIC 和 TCP/TLS 连通 Linux 服务端。
2. HTTP CONNECT、规则、系统代理和崩溃恢复。
3. daemon、桌面 UI、托盘、节点检测和监控。
4. Windows TUN 与 UDP。
5. Fake-IP DNS 与 TUN 域名规则。
6. macOS Network Extension、签名与公证。

在前一阶段通过验收前，不并行扩展下一阶段的产品范围。

## 当前状态

当前已有 Rust 核心、配置化 daemon/server、SOCKS5 CONNECT/UDP ASSOCIATE、HTTP CONNECT、规则分流、QUIC/TLS 回退、Fake-IP DNS、状态/流量监控、系统代理与托盘生命周期，以及基于 tun2proxy 的独立特权 TUN helper。真实 Windows/macOS 授权、路由恢复和安装包仍需真机验证；具体证据见[实施状态](docs/00-implementation-status.md)。
