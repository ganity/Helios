# TUIC 实现与 Helios QUIC 吞吐下降对照

## 范围与结论

核对日期：2026-11-03。用户给出的 `tuic-protocol/tuic` 当前保存协议规范，
README 明确说明仓库不提供官方实现，并列出 Itsusinn/tuic、Mihomo、sing-box 等实现。
因此不能把某一个实现的默认参数称为“TUIC 协议的默认参数”。
[官方 README，固定提交 8e118f2](https://github.com/tuic-protocol/tuic/blob/8e118f242f24a17a9f487dc344cc50d7e63e557e/README.md#L16-L50)。

本文深入核对 Rust 实现 `Itsusinn/tuic` 的提交
`50ee37bf31d79e409acab00891590a0c737686d6`（workspace 版本 `2.0.0-dev10`）。
其 Quinn 路径默认使用 BBR，显式设置传输窗口，并把连接替换与业务开流分开。
这些是实现层面的工程选择，不是 TUIC 协议自动消除丢包、限速或播放器问题。

实际传输代码已委托给 `wind-tuic`，固定提交
`5e8096f852d069bfa96e2a2f95412246b2035ad9`。
以下依赖版本以顶层 TUIC 的 Cargo.lock 为准，不使用 Wind 自己的锁文件：
Quinn fork 为 `01b8848dcb321eb17ad4d88dd6f84f28f45a0d6a`，
quinn-congestions 为 `83052f7da6f59d70792f9abb7b62b171cdc0d443`。
[依赖声明](https://github.com/Itsusinn/tuic/blob/50ee37bf31d79e409acab00891590a0c737686d6/crates/tuic-server/Cargo.toml#L33)、
[顶层锁文件](https://github.com/Itsusinn/tuic/blob/50ee37bf31d79e409acab00891590a0c737686d6/Cargo.lock#L3664-L3700)。

## 1. 拥塞控制：直接对应本次持续降速

服务端配置的 `CongestionController` 是 Wind 枚举别名，其默认变体为 `Bbr`；
客户端配置也明确默认 `Bbr`。这是构造默认值，不是从示例配置推测。
[服务端别名](https://github.com/Itsusinn/tuic/blob/50ee37bf31d79e409acab00891590a0c737686d6/crates/tuic-server/src/utils.rs#L2)、
[枚举默认值](https://github.com/rust-proxy/wind/blob/5e8096f852d069bfa96e2a2f95412246b2035ad9/crates/wind-tuic/src/quinn/utils.rs#L15-L24)、
[客户端默认值](https://github.com/Itsusinn/tuic/blob/50ee37bf31d79e409acab00891590a0c737686d6/crates/tuic-client/src/config.rs#L208-L214)。

此版本的 `bbr` 和 `bbr3` 名称都映射到同一个
`quinn_congestions::bbr::BbrConfig`；另可选 Quinn 的 CUBIC、NewReno。
不能把这两个 BBR 名称描述成两套已独立验证的算法，也不能称为直接使用 Helios
当前版本中的 Quinn 内置 BBR。
[客户端工厂](https://github.com/rust-proxy/wind/blob/5e8096f852d069bfa96e2a2f95412246b2035ad9/crates/wind-tuic/src/quinn/utils.rs#L69-L80)、
[服务端工厂](https://github.com/rust-proxy/wind/blob/5e8096f852d069bfa96e2a2f95412246b2035ad9/crates/wind-tuic/src/quinn/inbound.rs#L297-L320)。

服务端初始拥塞窗口默认 1 MiB，明确传给选定算法；客户端不覆盖算法初始窗口，
当前 BBR 依赖默认为 `200 × 1200 = 240,000` 字节。
[服务端初始值](https://github.com/Itsusinn/tuic/blob/50ee37bf31d79e409acab00891590a0c737686d6/crates/tuic-server/src/config.rs#L522-L528)、
[BBR 默认计算](https://github.com/proxy-rs/quinn-congestions/blob/83052f7da6f59d70792f9abb7b62b171cdc0d443/src/bbr/mod.rs#L524-L528)、
[200 包常量](https://github.com/proxy-rs/quinn-congestions/blob/83052f7da6f59d70792f9abb7b62b171cdc0d443/src/bbr/mod.rs#L635)、
[1200 字节常量](https://github.com/proxy-rs/quinn-congestions/blob/83052f7da6f59d70792f9abb7b62b171cdc0d443/src/lib.rs#L3)。

Helios 生产基点 `682766c` 使用 crates.io Quinn 0.11.12 / quinn-proto 0.11.19。
本轮 Helios 诊断没有替换 QUIC 库，仅切换服务端拥塞算法，即得到可逆改善：
服务端默认 CUBIC 在当前链路持续收到丢包判定，活跃窗口约 11～30 KB；
约 179 ms RTT、17,924 字节窗口对应约 0.80 Mbps 的量级。
同一连接连续下载九个 1 MiB 文件时：

| Helios 服务端实验参数 | 九次结果 |
| --- | --- |
| 默认 CUBIC | 两次 10 秒超时，其余约 3.46～10.00 秒 |
| CUBIC，初始窗口增至 240,000 字节 | 从 1.223 秒逐步恶化，后续多次 5～9 秒 |
| BBR，初始窗口降至与原 CUBIC 相同的 12,000 字节 | 全部成功，0.256～0.619 秒 |

这排除了“只因为 BBR 默认初始窗口更大”的解释。不能将它写成 TUIC 已经通过
同线路对照测试；实际测试的是 Helios 的算法切换。
详细原始证据及实验边界保存在本机诊断目录
`/tmp/helios-quic-code-diagnosis.d5d05r/REPORT.md` 及其日志；该临时目录不随 Git 分发。

## 2. 流控窗口和并发额度：不要与拥塞窗口混淆

| 参数 | Itsusinn/tuic 当前 Quinn 路径 |
| --- | --- |
| 服务端、客户端发送数据窗口 | 16 MiB |
| 服务端、客户端单流接收窗口 | 8 MiB |
| 连接级接收窗口 | 默认应用路径未覆盖，继承该 Quinn fork 的 `VarInt::MAX` |
| 服务端允许对端并发双向/单向流 | 分别 512 |
| 客户端允许对端并发双向/单向流 | 未覆盖，继承 Quinn 各 100 |
| `send_fairness` | 未覆盖，继承 `true` |

来源：
[服务端应用默认值](https://github.com/Itsusinn/tuic/blob/50ee37bf31d79e409acab00891590a0c737686d6/crates/tuic-server/src/config.rs#L381-L408)、
[服务端参数传递](https://github.com/Itsusinn/tuic/blob/50ee37bf31d79e409acab00891590a0c737686d6/crates/tuic-server/src/plugin.rs#L209-L227)、
[服务端参数落点](https://github.com/rust-proxy/wind/blob/5e8096f852d069bfa96e2a2f95412246b2035ad9/crates/wind-tuic/src/quinn/inbound.rs#L260-L287)、
[客户端默认值](https://github.com/Itsusinn/tuic/blob/50ee37bf31d79e409acab00891590a0c737686d6/crates/tuic-client/src/config.rs#L152-L174)、
[客户端参数传递](https://github.com/Itsusinn/tuic/blob/50ee37bf31d79e409acab00891590a0c737686d6/crates/tuic-client/src/plugin.rs#L181-L186)、
[Quinn 锁定版本默认值](https://github.com/Tipuch/quinn/blob/01b8848dcb321eb17ad4d88dd6f84f28f45a0d6a/quinn-proto/src/config/transport.rs#L382-L389)。

注意配置名 `receive_window` 在这条应用路径实际设置的是 **单流** 窗口。
发送窗口、接收流控窗口、初始拥塞窗口是不同限制；调大前两者无法保证受拥塞窗口
限制的链路恢复。本轮 Helios 慢速实验没有流控阻塞，不能把这些 TUIC 参数当作已证实修复。

## 3. 连接替换、开流和保活

客户端用 `ArcSwap` 保存当前连接。`connect_tcp` 先 `load_full()` 获取连接引用，
再异步开流；重连成功后 `store()` 替换连接。因此该路径没有 Helios 当前
`RwLock` 读锁跨网络等待、失败分支再申请同一写锁的结构。
[开流入口](https://github.com/rust-proxy/wind/blob/5e8096f852d069bfa96e2a2f95412246b2035ad9/crates/wind-tuic/src/quinn/outbound.rs#L380-L390)、
[重连替换](https://github.com/rust-proxy/wind/blob/5e8096f852d069bfa96e2a2f95412246b2035ad9/crates/wind-tuic/src/quinn/outbound.rs#L349-L368)。

但其共享 `open_connect_stream` 仍直接等待 `open_bi().await`，这一函数本身
没有超时。不能声称 TUIC 所有调用者都不存在流额度等待问题。Helios 仍需自行保证
建流总期限、失败不误伤其他活跃流。
[共享开流函数](https://github.com/rust-proxy/wind/blob/5e8096f852d069bfa96e2a2f95412246b2035ad9/crates/wind-tuic/src/proto/client_proto.rs#L68-L84)。

客户端默认每 3 秒发送 TUIC Heartbeat datagram，并将 Quinn 的 keep-alive
设为 `None`。心跳不等 PONG；监督任务同时观察连接关闭，连续三次心跳发送错误才
将会话标为丢失。因此没有 Helios 当前“取消有序控制流读取，再重发并消费迟到 PONG”
的相同错位路径。心跳成功入队不等于已测得对端活性或 RTT，不能直接替代认证探测。
[间隔默认值](https://github.com/Itsusinn/tuic/blob/50ee37bf31d79e409acab00891590a0c737686d6/crates/tuic-client/src/config.rs#L81-L83)、
[禁用 Quinn 定时保活](https://github.com/rust-proxy/wind/blob/5e8096f852d069bfa96e2a2f95412246b2035ad9/crates/wind-tuic/src/quinn/outbound.rs#L229-L233)、
[心跳发送](https://github.com/rust-proxy/wind/blob/5e8096f852d069bfa96e2a2f95412246b2035ad9/crates/wind-tuic/src/proto/client_proto.rs#L205-L210)、
[监督任务](https://github.com/rust-proxy/wind/blob/5e8096f852d069bfa96e2a2f95412246b2035ad9/crates/wind-tuic/src/quinn/outbound.rs#L586-L612)。

## 4. UDP socket 缓冲与平台边界

核对到的默认监听、拨号路径没有在应用层统一设置“大 UDP 接收缓冲”。
服务端直接绑定 socket，客户端可使用调用者 socket factory 或普通 UDP bind。
因此不能将 TUIC 表现归因于一个未找到的固定 16 MiB `SO_RCVBUF`。
[服务端 bind](https://github.com/rust-proxy/wind/blob/5e8096f852d069bfa96e2a2f95412246b2035ad9/crates/wind-tuic/src/quinn/inbound.rs#L420-L427)、
[客户端 bind](https://github.com/rust-proxy/wind/blob/5e8096f852d069bfa96e2a2f95412246b2035ad9/crates/wind-tuic/src/quinn/outbound.rs#L405-L420)。

其锁定 Quinn fork 底层在 Apple 平台会尝试将过小 `SO_SNDBUF` 提到
`65535 + cmsg::LEN` 的安全下限。这属于依赖的特定平台行为，不是跨平台任意放大
接收缓冲，也不是本轮已经证明的 macOS 根因。
[Apple 发送缓冲处理](https://github.com/Tipuch/quinn/blob/01b8848dcb321eb17ad4d88dd6f84f28f45a0d6a/quinn-udp/src/unix.rs#L189-L195)、
[下限常量](https://github.com/Tipuch/quinn/blob/01b8848dcb321eb17ad4d88dd6f84f28f45a0d6a/quinn-udp/src/unix.rs#L486)。

## 对 Helios 的实施含义与验证缺口

最小方向是保留现有 Quinn 与私有协议，显式配置经过当前链路对照验证的拥塞控制，
并修复已复现的连接锁、开流期限及健康检查缺陷。没有证据要求整套迁移到 TUIC、
采用其开发版 fork，或盲目照搬 1 MiB 初始拥塞窗口。

本文仅新增研究文档，未修改 Helios 生产源码。已逐项沿固定版本源码核查参数传递；
未编译或部署 TUIC，未做 TUIC/Helios 同版本同线路浏览器对照，也未完成修复后 macOS
首页自动播放和长时稳定性验收。BBR 无法保证绕过 UDP 限速、阻断或所有网络问题。

后续实施：用户确认后，Helios 已在现有 Quinn 上启用两端 BBR（12,000 字节初始窗口），
并修复上述锁、开流期限与控制流取消问题。生产代码回归和 VPS 部署结果见
[QUIC 修复验证记录](10-vps-testing.md#quic-拥塞控制与会话管理修复2026-11-03)。
本节前面的“未修改/未部署”描述研究阶段，不代表后续实施状态。
