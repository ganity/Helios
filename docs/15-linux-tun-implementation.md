# Linux TUN 实现与进度

Linux TUN 桌面开关已接通。桌面自动获取物理出口与真实 DNS，重启源地址绑定的 daemon，经 pkexec/polkit 启动固定的特权 helper，真实 TUN 自检通过后显示开启。路由、静态 DNS、systemd-resolved、桌面状态机及真实授权接口已通过隔离验证。

## 方案

复用现有 tun2proxy、daemon SOCKS5、TCP/UDP 规则与传输。普通用户运行 daemon，root helper 只管理 TUN 和系统网络设置。无需自建网络协议栈，也不赋予 daemon `CAP_NET_ADMIN`。

Linux 采用源地址绑定与策略路由：

```text
应用的未绑定公网连接 → 独立表 20220 → TUN → tun2proxy → daemon SOCKS5
绑定物理出口地址的 daemon 连接 → main 表 → 原物理网络
局域网、节点 IP 的明确路由 → main 表
```

daemon 必须在创建 TCP/UDP socket 时绑定 helper 校验过的物理出口地址，包括 Direct、节点连接、探测及真实 DNS 查询。仅增加服务器 IP 的目标绕过路由不能解决 Direct 回流。

这是路由选择机制，不是按进程隔离：其他显式绑定同一物理地址的应用也会绕过 TUN。不承诺与其他 VPN、VRF 或自定义策略路由共存；首版检测到非标准规则或已占用的表时拒绝启动。一个地址族只支持一个出口地址；切网后需要停止、恢复并重新获取出口，后续再考虑自动重建。

## 本轮已实现：路由后端

- `TproxyArgs.source_bypass` 为显式可选项；空列表保留旧调用行为，旧恢复记录可继续读取。
- 启用此选项时，在修改路由/DNS 前校验源地址属于本机非 TUN 接口、IPv4/IPv6 每类最多一个地址、策略规则为标准规则、表 20220 未占用。要求启用受保护恢复日志。
- 保留 main 表，新增 TUN 默认路由到表 20220。TUN 具有独立的 IPv4/IPv6 源地址，防止未绑定应用自动选择物理源地址后匹配 bypass。
- 优先级 20220 让绑定出口地址的连接查 main；20221 在该查找失败后返回 unreachable，避免出口默认路由消失后 daemon 回流；20222 查 main 的非默认明确路由；20223 接管其余流量。未启用接管的地址族在最后一步返回 unreachable。
- 新增策略规则在写入内核前记录到原有受保护 journal。恢复时按逆序删除精确匹配的自有规则，冲突时保留外部设置与记录供重试。
- 日志增加有界的原始 netlink RuleMessage 编解码；路由恢复按记录中的表号查询。规范化内核补全的默认属性，仍检查实际网关、接口、metric、协议和表号。
- 修正路由 dump 未可靠过滤表的问题，以及 IPv4 default-route setter 错写 IPv6 字段的问题。路由候选按最长前缀、再按 metric 排序。

## 已实现：daemon 出站与真实 DNS

- 可选 `[outbound]` 配置复用 `source_bypass` 名称，每个地址族最多一个物理源地址；显式指定 1–4 个真实 `dns_servers`。源地址必须与 helper 使用的策略规则一致。普通配置不启用此节，继续使用系统路由和系统解析。
- Direct TCP、Direct UDP、TLS 节点连接、TLS UDP 关联、TLS 健康探测、QUIC 连接和重连都使用同一份不可变的出站策略。TCP 复用现有的双栈地址竞争逻辑；缺少源地址族时过滤该族，绑定失败则报错，不创建未绑定 socket。
- 绑定模式的 Direct 域名解析只查询显式上游，通过绑定源地址的 UDP socket 发出 A/AAAA 请求。只请求已启用的地址族，校验响应来源、事务 ID、问题和记录所属名称；支持有界 CNAME 链及 UDP 截断后的绑定 TCP 重试。上游失败不会回退系统 DNS。
- 两个 Fake-IP 地址池以及 IPv4-mapped Fake-IP 均禁止作为真实解析结果/Direct 目标；缺失或过期的映射拒绝连接，不再按普通 IP 拨号。Direct 解析后还检查是否命中本进程的受保护入口。
- UDP 的 IPv4/IPv6 出站 socket 独立可用；缺少某族不影响另一族或代理转发。出站绑定和真实 DNS 配置属于网络租约的一部分，修改需要重启；节点切换和规则更新保留当前绑定。
- 当前按 Flow/UDP 包解析，不缓存真实 DNS 结果；只有实际查询开销成为瓶颈时再增加受容量和 TTL 限制的缓存。

配置示例、限制见 [配置模型](05-configuration.md)。该配置仅控制 daemon socket，不创建 TUN 或自动配置 helper。

## 已实现：helper 与静态 DNS 数据面

- Linux helper 必须显式配置 `source_bypass`，与 daemon 完全一致；无源地址配置的旧文件只允许 `--recover`，不再启动可能回流的旧路由模式。Windows/macOS 不受影响。
- 直接复用已安装的 `tun` 库创建设备，将源地址显式传入 `TproxyArgs`，再调用 tun2proxy 的设备级 API。正常退出、SIGTERM 和数据面报错都等待显式 journal 清理；清理失败保留租约与状态。
- 启动前通过 loopback SOCKS 探测保留的 `198.18.0.0:53` DNS 网关。此网关只由配置了出站绑定和 DNS 的 daemon 在 SOCKS TCP 入口处理，不按规则代理到远端。TUN 的 UDP DNS 经 tun2proxy 转为 TCP；原生 TCP DNS 走同一入口，直接复用 daemon 双栈 Fake-IP 缓存，TTL 不超出缓存有效期。不会启用 tun2proxy 的第二套 VirtualDns。
- 静态后端要求 `/etc/resolv.conf` 为 root 所有、不被其他用户写入的普通文件；拒绝已知 DNS 管理器生成标记、loopback/stub/Fake-IP nameserver 和未知指令。标准 resolved stub symlink 走下述独立后端；其他 symlink 拒绝。变更与恢复继续使用已有 inode/内容冲突保护。该检测不能证明没有隐藏的外部写入者，手工启用仅适用于明确不受管理的静态文件。
- 本地 vendoring tun2proxy 0.8.3，仅修复 DNS-over-TCP 读取半帧时丢包的问题；增加分段长度、分段内容及合并帧回归检查，见 `vendor/tun2proxy/HELIOS.md`。
- 管理员 CLI 仍可手工运行配置文件；此入口不通过 polkit 委托。桌面仅使用下述固定路径和管道接口。

## 已实现：systemd-resolved 按接口 DNS 租约

- 自动识别指向 `/run/systemd/resolve/stub-resolv.conf` 的标准 symlink，检查文件所有者为 root 或当前 resolved 服务用户、不可被其他用户写入，并通过 D-Bus 确认 stub 已启用。指向 uplink `resolv.conf` 的 symlink 不走 stub，继续拒绝。
- 复用仓库中的 zbus，通过固定 `/run/dbus/system_bus_socket` 调用真实 `org.freedesktop.resolve1`；不使用调用者的总线地址环境变量。只配置新 TUN 的 DNS `198.18.0.0`、默认 DNS 路由和 `~.`，并仅在该接口关闭 DNSSEC/DoT 以承载合成 Fake-IP；不修改物理接口或 `/etc/resolv.conf`。
- 若其他接口或全局已设置搜索域/路由域，启动前拒绝，避免更长域名后缀优先于 `~.` 或与另一个 `~.` 并行查询。本阶段不支持 split DNS。LLMNR、mDNS、单标签名称和 resolved 的本地合成记录仍遵循系统语义，不宣称这些都进入 Fake-IP。
- 恢复日志保存总线 ID、服务唯一名称、原始/已应用/待确认的接口快照；每步变更前 checkpoint，回复丢失后允许恢复到原始状态。恢复前比较 DNSEx（含端口和服务名）、域、默认路由、DNSSEC/DoT、LLMNR/mDNS 与信任锚，冲突时保留外部配置和日志。
- 正常清理使用自有 TUN 的 Revert；非持久 TUN 在退出或强杀后已消失时，不再通过旧 ifindex 修改任何接口。进入与退出均刷新 resolved 缓存，避免真实 IP/Fake-IP 跨租约残留。若 resolved 不可用，保留日志；服务恢复且旧 TUN 已消失后可重试清理。若服务重启而 TUN 仍存在，则保留日志并拒绝自动覆盖。
- 活跃租约定期核对 resolved 的服务身份、接口快照与其他接口域；异常会停止接管并进入恢复。

## 已实现：桌面授权、生命周期与分发

- 桌面固定调用 `/usr/bin/pkexec /usr/libexec/helios-helper --desktop`，校验 helper 及目录为 root 所有且其他用户不可写。不运行用户配置的特权程序，不以 root 运行桌面或 daemon。
- 使用已有路由查询自动选取物理源地址；UDP connect 只查询内核，不发送探测包。真实 DNS 从静态 resolver 或 resolved 的上游列表获取，未配置公共 DNS 后备。开启 TUN 时自动配置 daemon 的 Fake-IP，不要求用户另开 DNS 开关。源地址配置只保存在当前会话，不持久化到桌面 JSON。
- helper 从 stdin 接收不超过 64 KiB、禁止未知字段的 JSON；请求没有文件路径，只含网络参数与桌面/daemon PID。root 侧固定使用 `/run/helios` 和 `/var/lib/helios`，按 `PKEXEC_UID` 验证进程所属用户、网络 namespace 及启动时间。通过保留的 SOCKS `198.18.0.0:54` 对照 daemon PID、源地址和真实 DNS。旧的任意路径 CLI 在 pkexec 环境下拒绝。
- 桌面用普通用户权限重建绑定出口的 daemon，再等待 helper 创建 TUN、配置网络并通过真实 TCP DNS 自检；收到 `ready` 后才显示开启。授权拒绝、准备阶段取消和自检失败会关闭本次 daemon、恢复普通配置并显示错误。
- stdin 管道同时是本窗口的停止权限和存活证明。关闭开关、退出或进程崩溃导致 EOF 后，helper 等待路由/DNS 清理。源地址绑定的 desktop-managed daemon 也持有桌面管道，窗口退出后自行结束，避免留下旧出口绑定。
- 每 500 ms 检查物理源地址/链路、main 表、策略规则、TUN 路由、静态 DNS 或 resolved 租约，以及 daemon 配置握手。物理网络、DNS 管理器或进程变化时停止并恢复；切网后重新开启会重新获取出口。不自动修改其他 VPN 或重建外部配置。
- 在动网络前启动独立 root watchdog，并等待其确认就绪。它核对 helper PID/启动时间和受保护的会话所有者记录，SIGKILL 后等待实例锁释放并恢复；DNS 服务暂时不可用时保留租约，最多重试约 10 秒。冲突或持续故障保留状态，界面可请求授权恢复。其他用户的活动租约不被新会话接管。
- 重启恢复绑定 machine-id；只恢复 inode 与应用内容仍匹配的静态 DNS，不操作上次启动的路由、规则或 ifindex。缺少主机身份的旧记录或外部修改保留供管理员处理。安装的 `helios-tun-recover.service` 在网络启动前执行此恢复。
- Debian 包包含固定 helper、polkit action、恢复服务及依赖；卸载前恢复残留租约，活动实例未停止时拒绝移除恢复程序。便携包包含 helper 和 `install-linux-tun.sh`，普通应用仍按用户安装，系统组件另行安装一次。

Debian 安装后直接使用桌面开关。源码/便携包先构建配套程序并安装系统组件：

```sh
cargo build -p helios-client -p helios-daemon -p helios-helper -p heliosctl
sudo sh deploy/install-linux-tun.sh target/debug
./target/debug/helios-client
```

该安装操作需要管理员授权；上述验证仅在一次性容器中安装测试组件，没有修改日常宿主网络或安装策略。

## 验证

普通检查：

```sh
cargo test -p tun2proxy --lib dns_tcp_retains
cargo test -p tproxy-config --features secure-state-file
cargo test -p helios-helper -p helios-daemon -p helios-config -p helios-transport -p helios-dns
cargo clippy -p tproxy-config --features secure-state-file --all-targets -- -D warnings
```

真实内核路由测试仅在无外网的独立 Docker network/mount namespace 运行。默认镜像为 ubuntu:24.04，也可以传入已存在的镜像；测试只读挂载本机运行库和测试二进制，容器仅授予 NET_ADMIN，不使用宿主网络，不挂载项目或 Docker socket。需要 Linux、Docker、Python 3、iproute2；脚本已接入 Linux CI。

```sh
sh deploy/test-linux-tun-routing.sh [DOCKER_IMAGE]
```

两项测试分别验证旧路由路径和新 source-policy 路径。新路径检查 IPv4/IPv6 应用路由到 TUN、实际 UDP socket 的自动/显式源地址选择、绑定出口地址的连接走 uplink、出口默认路由丢失时拒绝回流、同优先级外部规则冲突保护、跨 namespace 记录拒绝、SIGKILL 后路由/规则/DNS 恢复及重复恢复。

daemon 的本地 TCP/UDP/TLS/QUIC 测试检查服务端实际观察到的来源地址；真实 DNS 测试覆盖响应校验、CNAME、IPv6、TCP 重试、Fake-IP 拒绝和无系统解析回退。Linux 使用独立 loopback 地址区分是否确实绑定，无需修改主机网络。

上述路由测试使用 dummy 接口。另外新增真实数据面测试：

```sh
sh deploy/test-linux-tun-dataplane.sh [DOCKER_IMAGE]
```

两个 `--network none` 容器仅通过临时 veth 相连；一个运行真实 server 与本地 DNS/echo，另一个以 UID 65534、无 capability 运行真实 daemon，root helper 使用 `/dev/net/tun`。测试真实双栈 Fake-IP、Direct/Proxy TCP/UDP（含原生 IPv6 目标）、域名 Reject、DNS 管理器拒绝、停止文件、SIGTERM 和 SIGKILL 后恢复，比较路由/规则/DNS 与初始状态一致。该测试需要 Docker、Python 3、iproute2、OpenSSL 和 `/dev/net/tun`；不使用宿主网络、不挂载 Docker socket 或项目，只读挂载运行库、必要二进制和测试文件。

启用真实 resolved 测试（需要宿主提供 `systemd-resolved`、`dbus-daemon`、`busctl`、`setpriv`、`pkexec` 和 `polkitd` 二进制）：

```sh
HELIOS_TEST_RESOLVED=1 sh deploy/test-linux-tun-dataplane.sh [DOCKER_IMAGE]
```

该模式在容器中启动私有 system bus 和真实 resolved（已验证 systemd 255），通过 `127.0.0.53` 查询双栈 Fake-IP 后运行相同流量测试，验证物理接口 DNS 快照不变、缓存恢复成真实地址、split DNS 启动拒绝，以及服务停机时保留日志、服务重启后恢复。另一个隔离内核用例检查活跃接口的外部修改保护、服务身份冲突、变更已应用但尚未确认及 Revert 后尚未 checkpoint 的恢复。还在容器内启动真实 polkitd，使用仅针对测试用户的批准/拒绝规则与最小 PAM 会话配置；以普通用户执行正式桌面状态机，通过真实 pkexec 验证授权拒绝、准备阶段取消、开启、关闭和桌面对象退出。该测试不自动输入密码，不验证日常桌面认证代理的弹窗外观。额外只读挂载测试二进制，挂载一个任务临时 `/etc` 目录，增加 CHOWN/SETPCAP/NET_RAW/SYS_PTRACE 以启动具有实际服务能力的 resolved；无需 SYS_ADMIN 或宿主 D-Bus。Docker 生成的 DNS bind 占据 stub 文件，测试就地提供 stub 内容，因此不验证 resolved 对 stub 文件的原子替换。

另外验证桌面接口拒绝未知路径字段和 daemon 配置不一致，真实 TUN 上的 EOF、helper SIGKILL、daemon 退出、路由变化、外部 DNS 改动、竞争域和 resolved 服务停机/恢复。每次对照路由/规则/DNS 快照与租约状态。模拟旧 boot-id 的恢复用例验证持久 DNS 的内容冲突保护及新接口不被旧 ifindex 删除。

这些一次性容器不代表每个发行版、桌面认证弹窗、物理 Wi-Fi 切换或公网链路都已验收。测试没有修改宿主机网络。
