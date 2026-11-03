# VPS 真机测试与使用

## 2026-11-03：吞吐与会话稳定性

- 同一 10 MiB 下载：公网 QUIC 一次 48.5 秒、一次 60 秒超时；强制 TLS 两次约 4.3 秒。50 MiB 下载：Helios TLS 8.25 秒，本机 7890 代理 13.67 秒。公网测量随时间和路径变化，不是带宽上限保证。
- 本机服务端回环测试：QUIC 32 MiB 约 0.19–0.25 秒；100 个并发请求通过。将应用健康探测延至 60 秒后，旧客户端在空闲约 35 秒后无法继续建流；客户端 QUIC 每 10 秒保活修复后，同一测试通过。
- Alpine 模板原设 `max_sessions = 8`。本机复现旧版行为：并发超过上限即丢弃新 TCP 连接，表现为 TLS 握手 EOF/HTTP 502；服务端现在在 accept 循环中等待会话许可，避免无限创建等待任务并让内核 backlog 提供有界排队。保留上限 8、24 路并发下 TLS 与 QUIC 分别完成 100 个请求，闲置恢复测试也通过。模板上限仍提升到 32，减少排队延迟；高于配置上限的突发连接仍可能在内核 backlog 满时被拒绝。
- 本机节点配置 `~/.helios/desktop.json` 与 `daemon.toml` 已改为 TLS 优先。VPS 的实际 `max_sessions` 尚未确认或修改：现有 SSH 公钥未获授权。需在 VPS 检查实际服务端配置，若仍为 8，则改为至少 32 并重启服务，再重测网页并发。
- 可重复本机测试：先构建 Release 的 `helios-server`、`helios-daemon`、`heliosctl`，再运行 `bash scripts/local-transport-smoke.sh`；低会话上限回归可用 `SMOKE_TRANSPORT=tls SMOKE_MAX_SESSIONS=8 SOAK_PARALLEL=24 SOAK_REQUESTS=100 bash scripts/local-transport-smoke.sh`。脚本只绑定本机端口，使用临时证书与凭据，不修改系统代理。
- 无头 Chrome 在 Helios 和本机 7890 代理下都超时，不能据此判定 Helios 浏览器兼容性；macOS 真机浏览器与连续 72 小时运行仍需验收。

## 2026-11-02：TLS 半关闭故障修复

原故障不是“探测成功即可使用”：客户端输入结束后，真实隧道会报
`peer closed connection without sending TLS close_notify`。SSH banner 可能已经收到，
但后续响应仍可能丢失，不能视为正常链路。

定位证据：旧客户端连接当前 VPS 可复现；仅更新客户端、服务端仍为旧版时，
同一命令恢复正常。测试中用“遇到第一个 TCP FIN 就关闭双向连接”的转发器，
也能稳定重现旧实现的错误。因此故障与路径上的 TCP 半关闭处理相符；
未取得运营商转发器日志，不能断言是哪一层 NAT 的具体实现。

修复在共享 TLS 传输层：仍发送 TLS `close_notify`，但延后底层 TCP FIN，
直到双向 TLS 流结束并释放连接。客户端、daemon 和服务端统一使用此实现。
不忽略 `UnexpectedEof`，不关闭证书验证，不修改协议或凭据。

已验证：

- 更新前的失败用例：客户端 stdin 立即 EOF，隧道连接 VPS 本机 SSH，收到 banner 后正常退出，退出码 0。
- HTTP 请求写完即 EOF：收到完整 HTTP 200、响应正文及 chunked 结束标记，退出码 0。
- 本地 SOCKS5（远端解析）和 HTTP CONNECT 经 VPS 访问 `https://example.com`：均为 HTTP 200，正文 577 字节。
- daemon 认证状态为 `connected`、传输为 `tls`，一次探测 RTT 约 154 ms；请求结束后活跃 Flow 归零，未出现原来的转发警告。
- VPS 已安装更新后的 musl Release 服务端，OpenRC 状态为 started；本地 Release 客户端和 daemon 同步更新。
- 回归测试覆盖正常直连、遇 FIN 断开的转发器、256 KiB 完整响应、目标先关闭发送方向后仍可上传、真实 TLS 截断仍拒绝。
- `cargo test --workspace --locked`、Clippy（全部 target、拒绝 warning）和格式检查通过；transport 共 18 项测试通过。依赖真实桌面环境的默认忽略测试不包含在此结论内。
- Release 桌面程序在 Xvfb 下自动启动同目录新版 daemon，再经 SOCKS5 完成 HTTPS 200；限时测试结束后本地进程均退出。VPS 服务继续运行，RSS 约 4 MiB，没有 OOM 事件。

更新后的 Linux 包：`target/linux-package-20261102-tls-close/helios-linux-x86_64.tar.gz`，
已解包并验证包内 `SHA256SUMS` 全部通过。不含节点凭据；旧包保留，不能继续用旧包验证本次修复。
包的 SHA256 为 `4f4efb60feafdec2c63de2eed769e8b9e87b59482c1728c998a09820adc4ca41`；校验和不是签名。

## 在当前机器使用

当前节点、受信证书和凭据已配置在 `~/.helios/`，无需重新输入。不要把该目录或
`vps真机.md` 放进分发包或公开仓库。服务端凭据未更换，既有其他服务未修改。

在真实图形桌面的终端运行（不要 sudo）：

```sh
cd /home/jhz/tmp/Helios
./target/release/helios-client
```

确认概览为已连接，节点使用 **TLS**；当前 VPS 禁止 UDP，不要强制 QUIC。
若未自动启动，在客户端启动 daemon。节点延迟是 Helios 认证探测耗时，不代表所有站点延迟。

先单独验证代理，不必修改系统网络设置：

```sh
curl --noproxy '' --proxy socks5h://127.0.0.1:1080 https://example.com
curl --noproxy '' --proxy http://127.0.0.1:8080 https://example.com
```

`socks5h` 让目标域名在服务端解析。`--noproxy ''` 避免终端已有 NO_PROXY 绕过测试。
这两个测试请求只能在 daemon 正在运行时使用。

确认后可在客户端开启系统代理。Linux 自动系统代理面向 GNOME；其他桌面可在浏览器中
手动设置 HTTP `127.0.0.1:8080` 或 SOCKS5 `127.0.0.1:1080`（启用远端 DNS）。
系统代理不会接管忽略代理设置的应用。不要同时让其他代理软件占用这两个端口。

本轮不修改用户的系统代理或路由。运行环境没有真实图形会话，原生桌面、系统代理和
TUN 的真机验收仍需分别进行；本次 TLS 修复不代表 TUN 已通过验收。
公网 QUIC、UDP、长期运行和跨网络切换亦未由本轮测试证明。

### 2026-11-03 VPS 更新验证

- 使用 `.vps真机.md` 中的 root 账号及 SSH 端口 41237 登录成功。
- 已部署提交 `ab1c3de` 的 musl release 服务端，OpenRC `helios-server` 重启成功。
- 保留原证书和凭据，将 `max_sessions` 从 8 调整为 32。
- 旧程序和配置分别备份为 `/usr/local/bin/helios-server.before-ab1c3de`
  和 `/etc/helios/server.toml.before-ab1c3de`。
- 部署文件 SHA-256：`89427146e6256052892690620e639ee56f97838d13ad20a57457632b12d124b3`。
- 本地 daemon 经 VPS TLS：Google 返回 200，耗时 1.79 秒；GitHub robots.txt
  12 并发共 48 次全部返回 200；OVH 10 MiB 下载耗时 5.00 秒，约 2.10 MB/s。
- 上述为短时公网冒烟测试，未证明长期稳定性或 macOS 图形客户端表现。

### 复杂网页复现（同日后续）

使用全新 Chrome headless 配置、禁用缓存，访问 `https://doodles.google/`，
每 5 秒向下滚动，观察 30 秒：

- Helios TLS：31 个请求，7 个完成，22 个隧道连接失败，2 个未完成；
  18 张图片仅 1 张加载成功，DOMContentLoaded 约 24.38 秒。
- 本机 7890 代理：57 个请求，53 个完成，18 张图片全部加载成功；
  DOMContentLoaded 约 3.69 秒，load 约 23.18 秒。失败项为统计或验证码请求取消。
- Helios 单独请求 gstatic 资源可复现 10 秒后返回 HTTP 502；debug 日志为
  `remote transport failed: deadline has elapsed`。
- VPS 直接请求 Doodles 首页约 0.17 秒；当时 SSH 可用。之后本机连接
  VPS 24443、41237 出现 `No route to host` 或超时，经 7890 连接 SSH 也超时。
  尚不能确定失联原因，不能将全部失败归因于应用会话上限。

上述结果推翻了“小文件并发通过即可代表复杂网页可用”的判断。
需恢复 VPS 网络访问后继续检查会话占用和握手阶段；尚未修复复杂网页问题。

### VPS 恢复后的 TCP 分段兼容修复

- 恢复后第一轮 Doodles 成功，但第二轮再次出现 10 秒隧道超时，30 秒内
  18 张图片全部未加载。SSH 同时卡在密钥交换；TCP 状态显示大量重传、
  拥塞窗口降至 1。采样时服务端连接数未达 32，不能用会话额度解释全部故障。
- 临时中转仅将节点 TCP MSS 限制为 1000 后，两轮均加载全部 18 张图片，
  没有隧道错误；使用相同分段措施的 SSH 也恢复可用。这支持大包传输／PMTU
  路径异常的判断，但尚无链路抓包证据确定具体是哪一层丢包。
- 正式代码通过 `helios_transport::connect_node_tcp` 统一代理流量、TLS UDP
  关联、健康探测和桌面节点测试。Unix 在连接前设置 MSS 1000，并启用
  TCP_NODELAY；Windows 当前仅启用 TCP_NODELAY，尚无对应分段兼容措施。
  此措施降低单包载荷以换取兼容性，不改变 TLS、安全校验或协议帧。
- 移除临时中转、使用原节点地址直接连接后，连续三轮 Doodles 均加载全部
  18 张图片，无隧道错误；load 分别为 13.48、12.41、14.20 秒。统计／验证码
  `ERR_ABORTED` 与隧道失败分开计算。10 MiB 下载 4.39 秒，约 2.39 MB/s。
- 相关 transport、client-control、daemon 测试通过（48 项，另有 1 项需隔离
  桌面环境的既有测试跳过）；TLS 和 QUIC 各 100 次、24 并发本地请求通过，
  服务端额度为 8。增加了验证实际 MSS、TCP_NODELAY 和 64 KiB 传输的测试。
- 本机缺少 macOS C 交叉编译器和 Windows MinGW 编译器，跨平台 check
  在 ring 构建阶段受阻。macOS 真机效果、Windows 同类线路兼容和长期稳定性
  仍需验证。本次修复位于客户端；VPS 程序无需更换。

### 借鉴成熟内核的连接基础优化

此次为独立 Rust 实现，未复制 Mihomo 的 GPL 源码，未修改私有协议。

- 服务端目标域名：最多缓存 256 个域名，合并同域名的并发成功查询，失败不缓存；
  使用系统解析器，无法获取权威 TTL，故采用 30 秒固定缓存上限，过期后重新解析，
  不返回过期地址。不在客户端解析海外域名。
- 服务端目标拨号：IPv4/IPv6 交错排列，每隔 250 ms 启动下一地址，失败时可提前
  尝试；第一个连接成功后取消剩余尝试，仍受协议请求的整体目标连接期限约束。
- 节点 TCP、服务端接受的 TLS TCP 和服务端目标 TCP：启用 TCP_NODELAY 与
  TCP keepalive（空闲 60 秒、探测间隔 10 秒）。保活不等于应用层健康或 MTU 修复。
- 认证后首帧等待受握手期限约束；客户端等待建流回应最长为请求目标连接期限
  加 1 秒。保留现有 TLS 半关闭实现及对应测试，不添加会中断长下载的硬性流期限。
- debug 日志分别记录节点 TCP、TLS、认证以及服务端 DNS 和目标 TCP 阶段，
  不记录 token、认证内容、URL 查询串。可设置
  `RUST_LOG=helios_daemon=debug,helios_transport=debug` 检查。

新增的浏览器测试使用全新 Chrome 配置、禁用缓存，30 秒内断言所有图片加载，
排除 `ERR_ABORTED`，其他网络错误使测试失败。以下命令同时覆盖新客户端和服务端：

```sh
SMOKE_TRANSPORT=tls SOAK_PARALLEL=24 SOAK_REQUESTS=100 SMOKE_MAX_SESSIONS=8 \
  IDLE_SECONDS=3 BROWSER_SMOKE_URL=local bash scripts/local-transport-smoke.sh
SMOKE_TRANSPORT=quic SOAK_PARALLEL=24 SOAK_REQUESTS=100 SMOKE_MAX_SESSIONS=8 \
  IDLE_SECONDS=3 BROWSER_SMOKE_URL=local bash scripts/local-transport-smoke.sh
# VPS 代理需先启动；此命令使用当前运行的程序，不会自动更换服务端。
node scripts/browser-smoke.mjs 8080 https://doodles.google/
```

本地图片页面发出 48 个独立图片请求；Chrome 显式关闭 loopback 代理绕过，确保
这些请求经过 Helios。浏览器脚本当前依赖 Linux `/usr/bin/google-chrome` 和
支持内置 WebSocket 的 Node。测试脚本为临时服务生成证书与 token，退出时清理。

新版 57 项基础测试通过（另有 1 项需隔离桌面环境的既有测试跳过），Clippy 和
release 编译通过。TLS/QUIC 各 100 次、24 并发转发通过，且各自浏览器验收均为
48/48 图片成功、无网络错误。旧 VPS 服务端的 Doodles 复验得到
18/18 图片、无资源网络错误；此结果不能证明新版服务端的公网性能。新服务端在
本机直连 Google 资源存在超时，故不将其作为速度结论。此次尚未部署 VPS 或推送。

仍待后续测量：节点级 MSS 策略（当前保留上轮 Unix 固定 1000 的兼容行为）、
Windows 分段兼容、TLS 恢复／预连接及长期运行。没有依据本轮结果引入 TCP 多路复用。

### Mihomo 固定版本深入对照后的第二轮调整

详见 [源码分析](12-mihomo-comparison.md)。新增 TLS 认证与建流流水发送，服务端仍先
认证；补齐建流写入背压超时和 DNS 失败的 1 秒共享窗口。真实 TLS 测试确认现有
配置已经支持会话恢复，不额外实现 ticket 或启用 0-RTT。

TLS/QUIC 本地各 100 次、24 并发及各自 48 张图片验收通过。新版 daemon 直接连接
既有 VPS，Doodles 30 秒内 18/18 图片成功，54 个完成事件，10,718,450 字节，
无非取消类资源错误。没有做同线路 Mihomo A/B，不据此报告相对加速百分比。
VPS 仍是旧服务端，服务端 DNS 优化尚未部署；本轮仅更新本地 daemon 并保留运行。
