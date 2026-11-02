# 功能补全与验收清单

更新日期：2026-11-02。范围为正式 egui 客户端及 workspace；GPUI 仍是独立实验。

## 本次已补全

| 功能 | 实际行为 | 主要实现 |
|---|---|---|
| 后台存活时重新打开界面 | 先验证本地 IPC；不因打开窗口就撤销代理租约。认证通过且标记为桌面管理的后台可以重新控制 | `helios-client/desktop.rs`、`helios-client-control` |
| UI 与代理生命周期 | 关闭 UI 或 UI 崩溃不主动撤销仍在使用的代理；桌面管理的后台正常退出会尝试恢复租约。确认后台离线后 UI 才执行恢复；连接超时、认证失败不视为离线 | client、daemon、system-proxy |
| 单实例界面 | 使用操作系统文件锁；句柄随进程退出释放，锁文件不删除，避免同时运行的新窗口争用租约 | client |
| 配置切换 | 保存新配置后，用运行中旧节点的控制凭据关闭旧后台；确认停止后才启动新后台。原先开启系统代理时，等新后台就绪再恢复连接 | client |
| TCP/UDP 规则 | `network,tcp,...` / `network,udp,...`；实际转发与规则测试使用同一决策。支持有序 Direct/Proxy/Reject | routing、client-model、daemon |
| 随机控制帧填充 | HELLO、AUTH、CONNECT 接入操作系统随机源和长度档位，按能力协商；QUIC 新建 stream 继承协商状态 | transport、daemon、client CLI |
| 双传输节点测试 | 每次并行测试 QUIC 与 TLS；分别显示认证握手耗时、PING RTT、错误及测试时间。一种传输失败不掩盖另一种成功 | client-control、client |
| 高级监控 | 最多保留 60 个速率采样；累计上下行、UDP 丢弃计数；按目标、入口、传输、决策筛选当前连接 | client |
| 单连接关闭 | 通过认证 `CloseFlow` 取消真实 TCP relay / UDP association；结束后释放流与计量。UDP 关闭单位是整个 association | control、daemon、client-control、client |
| 日志与诊断 | 按日志级别/事件筛选；导出受限的汇总 JSON。诊断文件不包含 token、证书、节点配置路径、连接目标或原始错误。Unix 文件权限 0600，已存在文件拒绝覆盖 | client |
| 中文 / English | 新增控制项随现有语言设置切换；复杂诊断留在高级页面 | client |
| daemon-owned proxy lifecycle | 独立 256-bit 本地控制 token、单写者 lease lock、后台设置/验证/恢复；daemon 退出后 watchdog 等待 lease lock 并恢复原代理 | config、control、daemon、client |
| live node switching | 新节点 TLS/QUIC 认证成功后切换新连接；旧 flows 保留原 transport；错误凭据和过期 revision 拒绝提交 | daemon、control、client |
| backup failover | 可选备用节点；健康连续 3 次失败后顺序认证切换，60 秒冷却且不自动切回 | config、daemon、model、client |
| Fake-IP DNS | A/AAAA 都生成可反向映射的 Fake-IP；展示缓存统计，只清理过期条目 | DNS、control、client |
| runtime config | ApplyConfig/UpdateRules 原子保存 daemon 配置；监听、DNS、超时变化明确要求重启 | config、control、daemon、client |

这些变更没有新增运行时依赖。Padding 不改变 TLS/QUIC 本身，也不保证不可识别。

## 升级与试用

本批 Linux 包：[`helios-linux-x86_64.tar.gz`](../target/linux-package-core-20261102/helios-linux-x86_64.tar.gz)。Release 编译通过；已完成包内 SHA256 校验、临时目录解包及 daemon version 检查。

归档 SHA256：`c965cef8720f0dfa2e81e885b31ef0e2aebc330eb211c8493b89e72435a05bd7`。此值用于校验文件一致性，不是发布签名。

本地控制协议从 3 升到 **4**，公网 Helios Protocol 仍是 v1。客户端、daemon、heliosctl 必须一起升级；不要让旧 UI 控制新后台。

1. 从旧版托盘选择“退出 Helios”，等系统代理关闭；不要直接强杀正在使用的后台。
2. 安装同一个新包中的三个程序。原有配置和凭据文件保留；自定义过 daemon 路径时在高级设置中确认路径。
3. 打开客户端，选择节点并测试；节点页应分别显示 QUIC/TLS 结果。节点列表摘要显示已成功传输中的最低 RTT，不表示首选传输一定可用。
4. 开启系统代理，访问网页；到“高级设置 → 连接记录”观察曲线、计量并筛选目标，关闭一条测试连接。浏览器可能自动重建连接，新的 flow ID 属于正常行为。
5. 在“高级设置 → 日志”筛选级别、导出诊断。导出提示会给出文件位置。
6. 关闭窗口后重新打开，应能认证并读取桌面管理后台。再从托盘退出，确认恢复原系统代理。

规则示例（从上到下首次命中）：

```text
domain-suffix,example.cn,direct
network,udp,reject
final,proxy
```

此示例禁止所有其余 UDP，仅用于验证规则，不建议未经确认直接覆盖日常规则。

## 验证范围

- 工作区格式、单元/集成测试、全目标 Clippy 作为本批门禁。
- 本批 workspace 测试全部通过；有 5 项 ignored 测试默认不运行。全目标 Clippy 和格式检查通过；Linux TUN SIGKILL 恢复测试及 GNOME 代理恢复测试另行隔离执行通过。
- 真实回环 TCP relay 验证错误 token 无法关闭连接，正确 token 可取消转发、产生 EOF，并移除活跃计量；再次关闭已结束连接返回错误。
- 双传输测试使用本地真实 TLS 服务：UDP 不可用时仍保留成功的 TLS 认证和 PING 结果。沉默 TLS 对端受 10 秒总期限约束。
- 模拟旧端握手覆盖新客户端/旧服务端、新服务端/旧客户端，检查能力交集、认证证明与 Padding；另检查真实 CONNECT 帧档位及显式 Padding 保留。
- 桌面测试覆盖单实例锁释放、旧状态事件隔离、运行中控制凭据保留、脱敏导出、中文控件和小窗口布局。
- 新增受保护的 GNOME 代理恢复测试，需显式 opt-in，在私有 D-Bus、临时 `XDG_CONFIG_HOME` 下执行；已独立通过，并加入 Linux CI。此测试验证租约 guard 和启动恢复，不是整个 GUI 强杀后的进程级验收。
- 未在本轮替换运行中的用户程序、修改当前代理、重新部署 VPS 或重跑真实 Chrome 上网测试。
- 新增本地 TLS 双节点真实集成测试，覆盖新旧 flow、认证失败、版本冲突、自动回切备用节点与配置持久化；增加 proxy watchdog 强杀恢复测试及 DNS AAAA/cache tests。
- 在无外网、独立 Docker network/mount namespace（hostname 校验 `helios-tun-test`）执行 dummy uplink/TUN 路由与 DNS 故障测试：SIGKILL 中断后拒绝外部 namespace，恢复后 IPv4/IPv6 路由与 DNS 回到原值，重复恢复幂等。不是宿主桌面/真实上网验收。

隔离测试示例：

```sh
task_proxy_dir=$(mktemp -d /tmp/helios-managed-proxy.XXXXXX)
env XDG_CONFIG_HOME="$task_proxy_dir" \
  HELIOS_ISOLATED_GSETTINGS_DIR="$task_proxy_dir" HELIOS_ISOLATED_PROXY_TEST=1 \
  dbus-run-session -- cargo test -p helios-daemon \
  managed_guard_restores_lease_on_exit_and_on_startup_recovery -- --ignored
```

## 仍未完成，不计为已实现

| 优先级 | 缺口 | 完成条件 |
|---|---|---|
| P0 | Linux TUN 产品化 | journal/recovery 基础和隔离容器 SIGKILL 测试已通过，但 helper 未接入客户端/提权流程，UI 开关仍禁用；只支持桌面模式，不开放 gateway/fwmark。需宿主桌面、DNS 管理器和真实流量验收 |
| P1 | DNS 完整产品能力 | 已有 IPv4/IPv6 Fake-IP 和过期项清理；Real-IP 上游策略、系统 DNS lease/桌面 DNS 接管仍未实现 |
| P1 | 凭据与证书管理 | 原生凭据库、双 token 轮换窗口、SPKI pin、证书到期提示、按来源认证限速及日志限流 |
| P1 | 平台真机验收 | Windows/macOS TUN 授权、睡眠/切网、强杀恢复；macOS NetworkExtension 正式方案；Linux KDE 自动代理 |
| P2 | 配置和交互完善 | 事件推送、规则图形化排序/编辑、IDNA、登录自启/自动连接和关闭行为设置；监听/DNS/timeout 仍需重启 |
| P2 | 协议完整性 | 版本集合协商及完整 GOAWAY；当前能力协商和固定 v1 帧不等于完整版本协商 |
| P2 | 发布与长期稳定性 | Win/macOS 签名安装包、更新验证、fuzz/netem/72 小时压力与资源占用验收。Linux 校验和包不是签名发布 |

本机 `unshare -Urn true` 返回 `Operation not permitted`；改在无外网、受限 Docker network/mount namespace 做 journal/recovery 故障测试。此结果不替代宿主桌面提权与真实流量验收，Linux TUN 开关继续禁用。

签名发布、长期稳定性和 iPhone/iOS 客户端按用户要求暂缓。
