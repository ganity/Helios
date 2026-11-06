# 实施状态

本文只记录已经存在并经过验证的实现，不以设计意图代替完成状态。

2026-11-02 功能补全：已新增 TCP/UDP NETWORK 规则、运行时随机 Padding、QUIC/TLS 双传输测速、
桌面单实例锁、后台认证重连与退出代理恢复，以及高级连接监控、单连接关闭、日志筛选、脱敏诊断导出。
本地 control schema 已升到 4；客户端、daemon 和 heliosctl 必须配套升级。
实现范围、检查结果和仍缺少的功能统一见 [功能补全清单](11-feature-completion.md)。
下文保留早期阶段记录，其中测试计数和产品描述不代表本次最新验收。

## 当前阶段

Linux TUN 的桌面开关、提权、出口/DNS 同步、运行监视、异常恢复与系统组件分发已接通；真实 TUN、真实 pkexec/polkit 和桌面状态机在隔离容器通过，详见 [Linux TUN 实现与进度](15-linux-tun-implementation.md)。跨发行版与物理桌面环境验证继续进行。

2026-11-02：已修复真实 VPS 链路在 TCP 半关闭后出现的 TLS `close_notify` 截断故障，
更新服务端并验证 SOCKS5/HTTP CONNECT 的公网 HTTPS 请求。复现证据、修复边界与当前机器使用方法见
[VPS 真机测试与使用](10-vps-testing.md)。此结果不代替 TUN、QUIC 或跨平台真机验收。

桌面易用性补充：正式 egui 客户端支持中文/English 即时切换与保存，默认精简首页，
系统代理、虚拟网卡开关直接可见。节点可用与系统代理启用分开显示；系统代理只在节点认证可用、
系统写入及回读验证成功后显示开启，并定期检查外部改动，失败后保留恢复责任。
Linux 真实 GNOME Lease + 全新 Chrome 配置已验证无浏览器代理参数的 Google HTTP 200、
页面标题与原设置精确恢复；浏览器测试显式选择运行，普通测试默认忽略。中英文、较小窗口的
Xvfb 截图检查和默认测试通过；后续 Linux TUN 已开放桌面开关并补齐授权接口、真实数据面与恢复检查。见
[Linux 客户端日常使用](09-linux-client.md)。

## 已完成

| 项目 | 实现证据 | 验证证据 |
|---|---|---|
| Rust workspace 与固定工具链 | `Cargo.toml`、`rust-toolchain.toml` | Rust/Cargo 1.95.0 成功构建 |
| Helios v1 控制帧基础格式 | `crates/helios-protocol/src/frame.rs` | round-trip、超限、未知字段和短输入测试 |
| IPv4/IPv6/域名 Target 编码 | `crates/helios-protocol/src/address.rs` | 三种地址 round-trip 和非法边界测试 |
| CONNECT_TCP payload | `crates/helios-protocol/src/message.rs` | round-trip、超时、Padding 上限、截断和尾随测试 |
| Hello/Auth payload 与 proof | `crates/helios-protocol/src/handshake.rs` | round-trip、token/transcript 绑定、非法 credential 测试 |
| 解析长度上限 | `MAX_CONTROL_PAYLOAD`、`MAX_DOMAIN_LEN` | 超限 payload 在读取 payload 前拒绝 |
| 有界异步帧 I/O | `crates/helios-transport/src/framed.rs` | 碎片化流、超限 header、完整写入测试 |
| TCP/TLS 基础链路 | `crates/helios-transport/src/tls.rs` | 真实 TCP PING/PONG、不受信证书拒绝测试 |
| TLS 版本约束 | `crates/helios-transport/src/crypto.rs` | 客户端与服务端的 TCP/QUIC 配置显式限定 TLS 1.3，不依赖默认协议版本；新增双方 TLS 1.3 与 `helios/1` ALPN 握手断言，transport 14 项测试和 Clippy 通过 |
| QUIC 基础链路 | `crates/helios-transport/src/quic.rs` | 真实 UDP/QUIC 双向 stream PING/PONG 和 datagram 端到端转发测试 |
| 认证状态机 | `crates/helios-transport/src/handshake.rs` | 成功、错误 token、未知 credential 统一失败测试 |
| TCP 建流与 raw relay | `crates/helios-transport/src/proxy.rs` | 认证、真实目标建连、双向 raw bytes、连接拒绝测试 |
| 双传输诊断服务端 | `apps/helios-server` | debug/release 构建、TLS/QUIC 进程级 smoke test；支持兼容旧参数的 `run`、不绑定端口的完整 `check`、版本输出和不可覆盖的 `0600` CSPRNG token 生成；默认 INFO 单行 JSON 日志，客户端地址和错误详情默认脱敏，`RUST_LOG` 可限时启用 DEBUG |
| Linux 服务端安装 | `deploy/install-server.sh`、`deploy/helios-server.service` | 安装专用用户、二进制、严格权限配置、证书、私钥和 32 字节随机 token；重复安装保留既有 token/服务配置内容并重新校正权限；支持 `DESTDIR` staging 验证；systemd 使用最小 capability 与 hardened sandbox |
| 单 Flow 诊断客户端 | `apps/helios-client` | TLS/QUIC stdin/stdout 双向 smoke test；token 从文件读取 |
| SOCKS5 CONNECT 入口 | `crates/helios-proxy`、`apps/helios-daemon` | 协议边界测试；curl 经 QUIC/TLS 的进程级 HTTP smoke test |
| daemon 运维 CLI | `apps/helios-daemon` | 保留旧配置路径启动方式；支持显式 run、无监听的完整配置/CA/token/规则/Fake-IP check、版本输出，以及 Windows/macOS System Proxy Lease drift-safe 恢复；TUN 恢复继续隔离在特权 helper |
| HTTP proxy 入口 | `crates/helios-proxy`、`apps/helios-daemon` | CONNECT 和 HTTP/1.0/1.1 absolute-form 有界解析；请求行改写、hop-by-hop proxy header 移除、body 保留测试；Direct 真实 TCP origin 集成测试；curl `--proxytunnel` 经 QUIC smoke test |
| 严格 TOML 配置 | `crates/helios-config`、`config/*.example.toml` | schema、未知字段、范围和相对路径验证测试；配置化进程 smoke test |
| 服务端资源边界 | `apps/helios-server` | 握手超时、共享 session 上限、单 QUIC session flow 上限通过构建与进程验证 |
| QUIC 到 TLS 自动回退 | `apps/helios-daemon` | TCP-only Helios 测试服务下完成 QUIC 超时、TLS 认证、建流和双向数据测试 |
| 基础路由与 Direct | `crates/helios-routing`、`apps/helios-daemon` | 全规则类型顺序测试；无 Helios 服务端的 SOCKS5 Direct 进程 smoke test |
| 规则热更新与运行模式 | `helios-control`、daemon、桌面 Routing 页 | 新规则完整验证后原子替换；Rule、Global Proxy、Global Direct 模式均复用同一规则引擎并可热切换；Global 模式不覆盖已编辑规则；新 TCP/UDP Flow 立即生效，已有 Flow 不变；无效更新保留旧规则测试 |
| Fake-IP DNS 数据面 | `crates/helios-dns`、daemon、桌面 DNS 页 | 198.18.0.0/15 有界分配、稳定正反向映射、TTL 清理、容量驱逐、A 查询回答、AAAA 空回答防泄漏；TCP/UDP Fake-IP 目标恢复为原域名后进入规则；独立 DNS 页配置启停、监听、容量和 TTL，并提示应用内 DoH 绕过风险 |
| QUIC/TLS 健康与恢复 | `crates/helios-transport`、server/daemon | 控制流 RTT 状态测试；TLS 探测首帧与 CONNECT 分流测试；双 RTT 进程 smoke test；QUIC 连续超时阈值和 server 重启恢复进程测试；daemon 默认 INFO JSON 日志仅记录状态事件，底层错误仅 DEBUG |
| 认证控制接口与 CLI | `crates/helios-control`、`apps/heliosctl` | v2 有界 framing；复用节点 32 字节 token 并常量时间校验；macOS/Linux 使用 `0600` Unix Domain Socket，旧配置保留 loopback TCP；CLI 同时支持两类端点；状态响应含最多 256 条仅驻内存的活跃 Flow 明细；真实 QUIC RTT、Flow 和流量计量进程 smoke test |
| System Proxy Lease 状态机 | `crates/helios-system-proxy` | 原子记录、未完成 acquire 回滚、精确恢复和用户 drift 保护测试 |
| Windows HTTPS 系统代理 Adapter | `crates/helios-system-proxy/src/windows.rs`、桌面 Settings | HKCU 原值存在性与内容完整快照、WinINet 变更广播、Lease 精确恢复；可配置 bypass，默认绕过本地/局域网并自动加入节点 IP 防环路；Windows GNU 目标 `cargo check`/Clippy 通过；完整客户端 Windows 链接仍需 MinGW/CI |
| macOS 系统代理 Adapter | `crates/helios-system-proxy/src/macos.rs`、桌面 Settings | `networksetup` 逐启用服务保存/恢复 HTTP、HTTPS 和 bypass；可配置 bypass，默认绕过本地/局域网并自动加入节点 IP防环路；认证代理拒绝接管；输出解析测试及 macOS 目标 `cargo check`/Clippy 通过 |
| 有界优雅关闭 | `apps/helios-daemon`、`apps/helios-server`、桌面 | SIGINT、Unix SIGTERM 或认证 Shutdown 停止新连接；daemon 按活跃 Flow、server 按活跃 Session 提前退出，最多等待 2 秒；桌面 3 秒未退出才强杀 |
| SOCKS5 UDP 双传输 | `crates/helios-proxy`、daemon、server | 端到端测试覆盖 UDP ASSOCIATE、QUIC datagram 优先、TLS framed stream fallback、服务端 UDP echo、30–300 秒可配置空闲回收、丢弃计量及上下行监控；Direct/Proxy/Reject 规则均接入 |
| 原生桌面控制台骨架 | `apps/helios-client/src/desktop.rs`、`crates/helios-client-model` | eframe/egui 原生窗口在 Xvfb 启动；节点/桌面配置、规则解析与测试、导入校验和平台默认路径已抽成不依赖 UI 框架的共享 crate；概览展示状态、累计流量、实时上下行速率与 60 秒趋势，多节点支持增删切换、并行认证探测和不包含凭据内容的严格 JSON 导入导出；提供路由编辑和域名/IP/端口即时匹配测试（含命中规则序号与内容）、配置生成，以及对桌面自有 daemon 的启停和配置应用重启；macOS/Linux 默认认证探测 Unix socket，仅在端点不可达时自动启动，端点占用或认证异常时拒绝双开；daemon JSON 日志写入私有文件，5 MiB 单次轮换；Logs 页有界读取末尾 128 KiB、最多展示 200 条脱敏事件，Settings 可打开目录；旧单节点 JSON 自动迁移，CLI 参数模式保留 |
| 共享桌面控制客户端 | `crates/helios-client-control` | 封装认证状态查询、daemon 占用检测、规则热更新、优雅关闭、TLS/QUIC 节点认证延迟探测及 Unix Socket/TCP/Windows Pipe 连接；egui 与 GPUI 不再各自实现握手；真实 TLS 认证和 PING/PONG、状态交换及 Offline/Occupied 分类测试通过 |
| GPUI 桌面实验 | `experiments/helios-client-gpui` | 独立 workspace 和锁文件，不污染正式 egui 客户端依赖；精确锁定 Zed/GPUI 提交，复用 `helios-client-model` 与 `helios-client-control`；状态每 2 秒在后台刷新并支持防重复手动刷新；Rule、Global Proxy、Global Direct 可原子保存 desktop/daemon 配置并通过认证 IPC 热更新；节点可从本地 JSON 导入（64 KiB 上限）、认证延迟探测、切换及删除（保护活动节点）；支持自动启动与本窗口拥有 daemon 的启停，切换时用旧节点凭据关停后再应用新配置，外部 daemon 仅提示重启；停止失败保留子进程句柄并展示错误；Xvfb 实际点击验证节点切换及真实 daemon 启停，认证 `heliosctl status` 与 UI 周期状态一致，停止后进程退出且 Unix socket 清除 |
| 活跃连接监控 | daemon、`helios-control`、桌面 Connections 页 | TCP Flow 注册目标、入口、Direct/Proxy 决策和实际 Direct/QUIC/TLS 传输；UDP 注册 mixed association；独立计算持续时间和上下行字节；Flow 生命周期结束立即删除，不写日志或历史文件；桌面每 2 秒通过认证状态请求展示，明细硬限制 256 条 |
| Windows/macOS 托盘生命周期 | `apps/helios-client/src/desktop.rs` | 托盘创建成功时关闭窗口隐藏到托盘；托盘可恢复窗口、启停桌面自有 daemon、退出并触发系统代理租约恢复；托盘创建失败则正常关闭窗口，避免隐藏后无法找回；RGBA 图标边界自检。关闭分支修改已通过 Linux client 测试/Clippy，但 Windows/macOS 真机行为仍待验证 |
| 独立 TUN 特权 helper 与桌面控制 | `apps/helios-helper`、`apps/helios-client/src/desktop.rs`、`vendor/tproxy-config`、`config/helper.example.toml` | 嵌入精确锁定的 tun2proxy 0.8.3，将 TUN TCP/UDP 转入 Helios loopback SOCKS5；严格配置、回环入口校验、节点 IP 自动绕过防路由环、MTU/MSS 边界、状态心跳与停止请求测试通过；桌面可通过 Windows UAC/macOS 系统授权启停；系统代理切换要求 TUN 离线后重试，陈旧 TUN 状态先请求授权恢复路由；daemon stop/restart 失败会保留子进程句柄；私有化 tproxy-config 增加受保护、原子写入的系统级路由恢复记录 |
| 基础质量门禁 | workspace、`.github/workflows/ci.yml` | 最新 Linux workspace 格式检查、112 项测试及全目标 Clippy 通过（2 项 GNOME/托盘隔离集成测试默认跳过，另在隔离会话执行通过）；Linux client、daemon、ctl 的 Release 构建和分发包解包安装验证通过；CI 定义 Linux 完整门禁及 Windows/macOS 原生 check+Clippy，等待首次远端运行证据 |

当前正式 workspace 测试：112 passed，0 failed，2 ignored（GNOME 与托盘集成测试另在独立 D-Bus 会话运行通过，托盘测试含三个菜单项的真实 D-Bus 点击事件）；GPUI 独立 workspace 此前另有 2 项测试通过。Windows Named Pipe 源码已接入，Windows 目标检查仍被本机缺少 `x86_64-w64-mingw32-gcc` 阻断。另已完成 TLS 与 QUIC 的独立进程级双向字节 smoke test、server/daemon CLI 配置与密码材料 smoke test、`heliosctl` 状态/计量、egui 与 GPUI 原生窗口 Xvfb smoke test，以及 curl 经配置化 SOCKS5/HTTP proxy→QUIC/TLS/Direct→域名目标的进程级 smoke test。

## 下一步

Linux 存储接口接通：受保护记录的路径配置、写入、读取与移除接口已支持 Linux，复用 4 MiB 上限与原子文件 I/O；临时目录测试验证路由/网关/转发状态完整落盘往返、0600 文件/0700 目录、损坏记录拒绝且保留。vendor 10 项测试及 vendor/helper Clippy 通过。尚未从 Linux 路由变更调用存储接口，helper `--recover` 仍明确拒绝；主机/命名空间绑定、写前日志、幂等恢复与路径权限加固未完成，不能视为持久路由恢复。

恢复记录写入失败处理：抽出受限原子写入函数，普通错误时仅清理本次成功创建的 `.new` 文件，已有临时文件保持原样并拒绝覆盖；Unix rename 后同步父目录。测试覆盖正常替换、既有临时文件保护、超限不覆盖旧记录、rename 失败清理临时文件；vendor 9 项测试及 vendor/helper Clippy 通过，原生 CI 扩大为读写测试。目录同步失败可能已提交新记录但返回错误；强杀残留 `.new` 与路径/权限竞态仍待恢复策略，Linux 路由日志尚未接入。

受保护恢复文件 I/O 上限：现有 Windows/macOS 记录入口写入前拒绝超过 4 MiB 的序列化内容，读取使用 4 MiB+1 有界读取并检查普通文件，拒绝静态符号链接、目录及超限文件。Linux 临时文件测试覆盖正常内容、恰好上限、上限+1、目录与符号链接拒绝；vendor 8 项测试及 vendor/helper Clippy 通过，原生 CI 加入该测试。Unix 路径竞态、所有权与父目录验证仍需加固，不能将此边界检查视为完整可信存储；Linux 尚未接通磁盘恢复。

恢复解码内存边界：Linux 路由序列改为 serde visitor 逐项限量读取，不再先构造任意大小的 `Vec<Vec<u8>>` 后检查；内外层分别限制 65536 字节与 4096 路由，不信任反序列化器的长度提示预分配。新增精确上限、零上限、嵌套内外层超限测试；vendor 7 项测试及 Clippy 通过。仅约束路由字段，整个文件与其他恢复字段的总大小仍需在磁盘读取层限制；持久恢复尚未接入。

Linux 恢复记录格式前置：`TproxyStateInner` 支持 Linux serde，路由用本机 netlink 字节保存以保留属性，fwmark 的 IP 版本严格编码为 4/6；限制单路由 64 KiB、每列表 4096 项，编码与解码均检查。新增真实 IPv4/IPv6 RouteMessage、大小表号和 fwmark 状态往返、短输入/非法版本/超限拒绝测试；vendor 6 项测试与 Clippy 通过。字节格式仅同主机/架构使用，尚未接入受保护磁盘日志；读取总文件大小边界、主机绑定、变更前日志提交与恢复命令仍需实施，Linux TUN 继续禁用。

Linux 网关模式部分失败回滚：iptables 每条添加成功后立即写入内存删除待办，不再等三条命令及转发开启全部成功后才记录。故障注入测试验证首条成功立即可见、后续执行失败不丢记录、不记录失败规则、非法动作在执行前拒绝；vendor 5 项测试通过。转发原值已有条件记录，本轮未改系统转发设置。网关模式不由当前 Helios helper 默认启用；记录尚未持久化，真实 iptables 与强杀恢复未验收。

fwmark 初始化与表保护：删除“初始化清空指定表、再读取该空表复制路由”的无效破坏性逻辑，改为 IPv4/IPv6 表均为空才添加规则；每添加成功一条立即追加内存回滚项，防止第二条添加失败丢失第一条记录。清理不再 flush 整张表，只删除保存的匹配规则，避免清除后来出现的第三方路由。新增非空 v4/v6 拒绝测试；vendor 4 项测试和 helper Clippy 通过。预检不是跨软件原子锁，规则身份、持久日志与实际 fwmark 转发功能仍需集成验证；Helios helper 默认未启用 fwmark。

fwmark 匹配范围修复：策略规则删除从仅匹配 mark 改为同时匹配 mark、表号、完整掩码与 `ToTable` 动作；支持小表号 header 和大表号 `Table` 属性（后者优先），拒绝不同表、部分掩码、其他动作及缺失 mark。新增构造规则测试，不访问内核；vendor 3 项测试通过。相同字段的第三方规则仍不可区分，精确规则租约、共享表保护与持久恢复尚未完成，此变更不等于所有权证明。

Linux 其余清理错误补充：防火墙、fwmark、转发开关、链路删除、resolv.conf 卸载/写回结果均向上传递；各阶段尽量继续执行，任一失败不标完成。防火墙/fwmark 成功项从待办移除，转发恢复成功清旗标；已不存在链路按幂等成功处理，其他链路错误返回；卸载失败时不写回仍被挂载的 resolv.conf。复用待办故障测试，并断言空待办不再执行操作；vendor 2 项测试与 helper Clippy 通过。未运行真实 netlink/iptables/DNS 操作，fwmark 的规则所有权精确匹配、路由租约持久化及真实失败重试仍待验证，不能据此开放 Linux TUN。

Linux 路由列表清理补充：恢复与删除路由均逐项尝试，成功项移出内存待办，失败项保留并向上传递，列表失败时不标完成且暂不删除 TUN 链路；已成功的 resolv.conf 卸载/内容恢复不在重试中重复执行。故障注入测试验证所有项均获尝试、只保留并重试失败项；vendor 2 项测试通过，Linux CI 已改为执行完整 vendor 测试。此测试不运行 netlink；防火墙/fwmark/链路删除仍存在仅记录错误的路径，真实网络及强杀后持久恢复尚未验证。

Linux 路由清理重试补充：`_tproxy_remove` 不再一进入就设置 `tproxy_removed_done`，仅在函数成功走到末尾后设置。新增无网络单元测试，验证非法状态连续两次清理均报错、不误标完成，以及已完成状态的幂等返回；单独执行通过并加入 CI（vendor 非 workspace 默认测试成员）。helper Clippy 通过。仍有路由操作错误被底层仅记录而未返回，尚不能据此宣称完整恢复。

helper 失败状态保留：移除无条件删除状态的 Drop guard；TUN 运行、取消等待或监听错误均保留状态供恢复，只有成功返回才删除，删除失败会报错。参数转换移到状态创建前，信号监听错误也先取消并等待任务。新增失败保留、成功删除及删除失败回归测试；helper 12 项测试和 Clippy 通过。底层 Linux 恢复仍会吞掉部分路由错误，成功返回尚不能作为真实网络恢复的充分证据；Linux TUN 不开放。

helper 心跳文件加固：状态以 `create_new` 独占创建（Unix 0600），心跳仅通过已打开句柄更新时间，不再按可替换路径反复写入。Unix 回归测试覆盖初始符号链接拒绝、已有状态拒绝、运行中路径被换成符号链接后目标内容与时间均保持不变，以及停止请求消费。心跳/停止监听失败先取消并等待 TUN 任务，再报告错误；不代表底层路由恢复已获验证。helper 11 项测试、Clippy 通过；Windows/macOS 原生结果待 CI，Linux TUN 仍未开放。

Unix helper 实例锁：启动和 `--recover` 在任何路由操作前共用固定文件锁，持有至操作返回。Linux 使用 `/run/helios-helper.lock`，macOS 使用 `/private/var/run/helios-helper.lock`；校验 root 所有权与禁止其他用户写入，拒绝符号链接，不删除锁文件。Linux 测试覆盖跨进程排他、句柄释放后重新获取、符号链接拒绝及目标内容保留；helper 10 项测试与 Clippy 通过。Windows 尚未接入此锁，旧版 helper 也不遵循新锁；升级须先停止旧进程。macOS 固定路径/授权真机验证与 Linux 路由持久恢复仍待完成。

helper 恢复冲突保护：`--recover` 先检查状态心跳，仍活跃时拒绝执行路由恢复，保留状态与停止请求；Linux 不支持恢复的失败路径也通过保留文件测试。helper 9 项测试与 Clippy 通过。心跳检查不是原子跨进程锁，无法证明暂停超过 2 秒的进程已经退出；全局实例锁与持久路由恢复仍需补齐，不能据此开放 Linux TUN。

helper 退出补充：Unix SIGTERM 与 SIGINT 均触发取消并等待 `general_run_async` 返回，不再由默认 SIGTERM 直接终止进程。7 项 helper 测试及 Clippy 通过，其中信号测试在独立测试子进程中安装真实处理器并分别接收 SIGTERM/SIGINT，不创建 TUN、不修改网络；Windows/macOS CI 已加入 helper 测试。此证据只覆盖信号处理，不证明真实路由恢复成功。

TUN 恢复安全补充：受保护记录读取失败不再被共享 `tproxy_remove(None)` 吞掉，helper 会保留状态并报告恢复失败。新增缺失/损坏记录回归测试，测试不修改路由，已加入 Windows/macOS CI；本机 Linux 无法执行该平台分支，首次原生 CI 结果待确认。helper 另拒绝零端口 SOCKS 目标，6 项 Linux 测试和 Clippy 通过。Linux 持久路由恢复仍未实现，TUN 开关继续禁用。

Linux 托盘补充：已接入 `ksni` StatusNotifierItem，菜单复用窗口显示、daemon 启停和退出；无宿主不隐藏窗口，宿主消失时请求恢复窗口。新增菜单/ARGB 图标单元测试与独立 D-Bus 注册、激活、菜单点击、宿主退出、服务关闭测试，后者单独执行通过并加入 Linux CI。client 构建与 Clippy 通过；真实 GNOME/KDE 托盘显示和 Wayland 聚焦尚未验收。包含此变更的 Release 包位于 `target/linux-package-tray/helios-linux-x86_64.tar.gz`，已完成解包校验、空格前缀安装及 desktop 入口验证；旧 `target/linux-package` 保留不变。SHA256 为 `6db7e5185359ff00d15ab86fa01235608a99d6d55f39f0c690aa45b004f970d7`，不是签名。

Linux 客户端已加入正式 egui 构建：共用节点、规则和监控，新增 GNOME GSettings 系统代理 Adapter（复用租约恢复）、Linux `recover-network` 和 desktop 启动入口。24 项相关单元测试、Linux build/Clippy、desktop 文件校验通过；GNOME 真实会话启停/恢复仍未验收。Linux TUN 与 KDE 自动代理暂未接入，安装说明见 `09-linux-client.md`。

1. 在 Windows CI/真机验证 Named Pipe DACL、并发实例和桌面启停。
2. 完成 Windows/macOS 真机 TUN 授权、强杀恢复，以及真实公网 UDP MTU、丢包与跨网络切换测试。

## 尚未实现

- 完整生产运维与真实跨网络恢复验收（QUIC 周期恢复探测已有实现）。
- SOCKS5 BIND 和系统 DNS 租约/恢复。
- UDP 跨平台、跨网络真实链路实测。
- macOS 认证代理凭据无法由 `networksetup` 读取，因此发现已启用认证代理时拒绝接管。
- Windows Named Pipe 尚缺 Windows 编译与真机 ACL 验证；本机交叉检查在 `ring` 构建脚本阶段停止。
- TUN helper 的 Windows/macOS 真机授权、真实流量与强杀恢复验证；当前已具备受保护路由租约与陈旧心跳恢复命令，但尚未在真实平台证明所有系统版本的路由/DNS恢复行为。Windows GNU 交叉检查还受本机缺少 `x86_64-w64-mingw32-gcc` 阻塞。

以上项目未完成前，Helios 不能作为完整桌面 VPN/TUN 产品使用。SOCKS5 UDP 已支持 QUIC datagram 和 TLS framed stream 回退；QUIC datagram 单包仍受路径 MTU 限制。Linux TUN 已接通，范围见当前阶段；KDE 自动系统代理尚未实现。
