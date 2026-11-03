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

### 多个 X 视频的后续诊断

用户报告多条视频同时加载后停止自动播放，点击并等待数秒仍可播放，普通页面正常。
未登录 Chrome 直接访问第一条帖子时，Helios 和 7890 均收到 X 的 HTTP 403，
不能用帖子页面的无视频结果判断代理失效。

从 X 公开 syndication 接口取得用户给出的五条帖子的真实 HLS 和 MP4 地址。
Helios 两轮、每轮五条视频并发：播放列表全部 HTTP 200，MP4 首 1 MiB Range 全部
HTTP 206，无超时；视频平均首字节 1.165 秒，首 1 MiB 完成 2.127 秒。7890 一轮
对应均值为 0.410 和 0.802 秒。两条代理不保证同线路，因此不把差距全部归因于内核。

全新 Chrome 中，同时创建五个 muted、autoplay、playsInline 视频元素并显式调用
play()，使用五条帖子的最高分辨率 MP4。Helios 五条均触发 playing，分别为
4.933、6.408、5.600、8.242、7.721 秒；30 秒内无媒体错误，短视频正常结束，
其余继续播放。7890 同测亦均播放，分别为 3.936、2.331、7.898、25.188、21.437 秒。
加载过程中 Chrome 的 ERR_ABORTED 单独记录，不等同于视频失败。

该测试未复现 X 登录页面的自动播放停止，也不覆盖 HLS/MSE 播放器或 X 的可见性、
预加载策略；不能宣称已经修好。CDN 根路径的 HTTP 400 也不能代表媒体不可用。

独立容量测试发现：TLS 额度为 8 时，保留 8 条空闲 CONNECT 后第 9 条请求等待
超过 3 秒；保留连接占用额度符合现有设计，但可造成多标签页等待。VPS 采样为
11 条已建立连接，额度 32，未证实本次用户现象发生时饱和。可用以下诊断命令复测：

```sh
SMOKE_TRANSPORT=tls SOAK_REQUESTS=10 SMOKE_MAX_SESSIONS=8 IDLE_SECONDS=1 \
  CAPACITY_CONNECTIONS=8 bash scripts/local-transport-smoke.sh
```

当前饱和诊断预期失败；它使用本地临时服务，不会占用 VPS。不要把增大额度、强制
关闭空闲连接或修改浏览器自动播放权限当成已证实的修复。仍需用户浏览器种类、
客户端版本及同浏览器 Clash 对照；若仅 X 页面停止发起媒体请求，应检查实际登录
页面的播放器状态和网络记录，而不是更改加密或忽略 TLS 错误。

#### Chrome 双代理交替复测

用户补充 Mac Chrome 使用 Clash 可自动播放。本机确认 7890 为运行中的 Mihomo，
8080 为 Helios。全新无登录 Chrome 同时打开五条原始帖子，两套代理全部返回
HTTP 403，均无视频元素或媒体请求，因此未获得帖子播放器的启动耗时。

改用上述五条真实 MP4，在每轮新建且禁用缓存的 Chrome 中同时加载，按
Clash → Helios → Helios → Clash 顺序测量从创建媒体元素到首次 playing 的秒数。
仍显式调用 play()，不将结果解释为 X 页面的自动播放策略。

| 帖子 ID | Clash 第 1 轮 | Helios 第 1 轮 | Helios 第 2 轮 | Clash 第 2 轮 |
| --- | ---: | ---: | ---: | ---: |
| 2117463721757012466 | 3.842 | 6.214 | 5.730 | 6.528 |
| 2117176877177778425 | 2.066 | 5.499 | 5.133 | 7.851 |
| 2117461320845152627 | 4.463 | 4.052 | 5.376 | 9.203 |
| 2117180664432996505 | 9.165 | 12.008 | 8.318 | 21.923 |
| 2117213787694698736 | 8.291 | 7.483 | 5.360 | 13.407 |

每套代理 10 次媒体启动全部成功，无媒体错误。Clash 第二轮明显变慢，说明该组
公网样本有较大波动；不能据两轮均值判断 Helios 更快，也不能证明用户问题消失。
原始诊断数据位于本机 `/tmp/helios-x-ab-{7890,8080}.json` 和
`/tmp/helios-video-ab-repeat.jsonl`，属于临时文件。未修改生产代码或部署。

#### 有头 Chrome 原始帖子验证

在本机 X11 `:0` 启动独立配置的可见 Chrome 后，五条原始帖子均能返回 200，
不再受无头测试的 403 限制。用户肉眼确认第一轮 Clash 窗口的原始视频自动播放；
该轮自动化未捕获 playing，不能据缺失事件否定用户观察。

之后逐个创建并切前台，等待 12 秒再尝试鼠标点击，另等 12 秒；启动参数补充
`--no-first-run --no-default-browser-check`，避免新配置的首次启动流程干扰。
Helios 五条在点击前均已触发 playing，导航至首次 playing 分别为
10.642、5.748、5.972、9.573、8.900 秒，且点击前 currentTime 已推进、readyState=4。
捕获到真实 X 播放列表／分片请求。这是原始页面的自动播放验证，不是独立 MP4。

后续 Clash 同脚本复测未得到五条一致的点击前 playing：第 3、4 条在观察窗口内
播放，其余尚在等待。该样本与用户观察不同，也包含自动化鼠标操作，不能用于
宣布 Clash 不支持自动播放或 Helios 更快；尚无稳定的自动播放失败重现环路。
页面切前台不等同于保证操作系统焦点与用户交互条件完全相同；本轮逐个加载，
不等同于同时打开五条再来回切换。原始记录在 `/tmp/helios-x-headed-helios.jsonl`
和 `/tmp/helios-x-headed-clash.jsonl`。未修改生产代码或部署。

#### 已登录、同一有头 Chrome 的正式对照

用户在专用 Chrome 配置中登录后，通过既有 CDP 接口连接同一窗口，全程不关闭
浏览器、不导出 Cookie、不点击播放按钮。为覆盖启动时固定的 Clash 代理，仅在
该测试配置加载本地临时 MV3 扩展（仅 `proxy` 权限）；确认代理设置及 Chrome 到
8080 的实际 socket。完成后清除扩展代理设置、卸载临时扩展，恢复启动参数的
7890 Clash，并将首页带回前台。登录配置和所有标签页保持不变。

顺序为 Helios → Clash，两轮都禁用 HTTP 缓存并绕过 service worker；测试结束
恢复上述 CDP 设置。每轮先首页滚动 40 秒（8 次采样），再同时导航五条原始帖子，
逐个切前台停留 14 秒，记录自动触发的 playing。切前台前后都采样
performance.now()；以下耗时为首次 playing 减去切前台后立即采样的时间，不是
单独视频下载时间，也不是每条都从冷启动开始计时。

| 视频（用户提供顺序） | Helios 切前台至播放 | Clash 切前台至播放 |
| --- | ---: | ---: |
| 1 | 8.256 秒 | 7.382 秒 |
| 2 | 1.534 秒 | 0.441 秒 |
| 3 | 1.427 秒 | 0.842 秒 |
| 4 | 1.616 秒 | 0.491 秒 |
| 5 | 1.563 秒 | 0.488 秒 |

两套代理五条均自动播放，采样时可见视频 currentTime 已推进、readyState=4。
首条包含更多页面冷启动工作；后四条切前台前已后台预加载，不可直接混算均值。
首页 Helios 捕获 4 次 playing、115 个媒体请求，Clash 5 次 playing、149 个媒体
请求；首页内容动态变化，请求数和事件数不作为速度排名。两轮只见 ERR_ABORTED
类网络取消，没有其它网络错误或视频 error 事件。

本轮支持“Helios 在这些帖子切前台后的启动等待更长”，但只是单轮、不同出站
线路对照，不能把差距直接归因于某段内核代码；仍未复现连锁停止自动播放。
脱敏记录（仅域名、计时、状态，不含请求头和 Cookie）保存在
`/tmp/helios-logged-in-comparison.json`；执行脚本为
`/tmp/helios-live-compare.mjs`，均是本机临时诊断文件。未修改生产代码或部署。

#### 首页长滚动与 QUIC 补测

**结论更正：本节旧脚本只统计 `<video>`，漏掉了仅显示播放按钮、尚未创建播放器的
卡片。以下成功计数仅代表被观察到的播放器，不代表首页全部视频正常；不得用来
否定用户“前几个能播放、后续不自动预览”的反馈。有效复现见下一节。**

用户明确问题在首页可视视频预览，而非帖子详情。继续连接原登录窗口，保留正常
缓存和 service worker，使用真实滚轮事件而不调用 play()。仅将高度超过 100px、
纵向可见比例至少 60% 的候选视频纳入观察；确认 document.hasFocus() 和
visibilityState，观察 currentTime 是否推进。暂停超过 10 秒仅作告警，不自动判为
网络故障：X 可能选择同屏另一条视频播放，或者主动暂停刚开始的预览。

TLS 与 Clash 各滚动 60 次、每次 450px：分别观察到 20/20、23/23 个候选视频
自动播放并推进；无失焦样本，媒体请求分别为 354、388，无非 ERR_ABORTED 错误。
快速滚动各 40 组、每组 5 次 450px：TLS 23 个候选中 20 个推进，2 个因布局变化
移出视野而排除，1 个在 playing 约 9ms 后 pause；Clash 26 个候选中 23 个推进，
3 个短暂 playing 后 pause。其中一个告警时同屏另一视频正在播放。因此这些告警
不等价于用户截图中的持续黑屏缓冲，不能据此认定代理传输失败。

用户补充 Mac 为最新构建、首选 QUIC。本机此前固定 TLS，不能当作相同条件。
另起同节点 QUIC 实例（仅临时端口 8081/1081 和私有控制 socket），没有更改现有
daemon 配置。控制状态确认 transport=quic，采样活跃流全部为 quic，RTT 约
165～223ms，并非回退 TLS。QUIC 快速滚动 40 组只遇到 5 个可观察候选，3 个推进，
1 个旁边另一视频正在播放，1 个约 29ms 后 pause；再逐屏滚动 60 次，5/5 个候选
推进，无媒体网络错误。后半段列表没有视频，不能将全部滚动次数算成视频成功数。

本轮仍未建立“缓冲不足且后续视频连锁不播放”的稳定重现。Linux 浏览器临时
代理扩展也未覆盖 macOS networksetup 系统代理接入路径。测试结束恢复 Clash、
卸载临时扩展、保留浏览器窗口和登录配置。数据在本机
`/tmp/helios-home-{soak,fast,quic,quic-normal}-results.json`，仅含媒体状态、
域名及计时，无 Cookie 或请求头。未修改生产代码或部署。

#### 首页停播有效复现与 X 带宽门槛

用户肉眼指出后续卡片不播放。对同一屏幕检查，PlayStation 帖子
`2117270756476309666` 显示 playButton，但当时整个首页没有 `<video>` 元素；此前
“无视频可检查”实际是漏检。该卡片后来恢复，不能据此否定先前的停播。

重新沿当前首页持续滚动，不刷新，不调用 play()。采样同时覆盖视频元素和
playButton 占位卡片，并记录解码帧数、paused、currentTime。QUIC 实例控制状态
及流列表确认真实 QUIC。前几个可见视频正常推进，随后多张卡片保持播放按钮，
6 秒多次采样不创建播放器；保留页面切到 Clash 后，旧卡片仍未立即恢复。
`node /tmp/helios-preview-stall.mjs` 在该现场运行，8 次采样后明确失败：
`Visible video card stayed a play-button placeholder without an automatic preview`。
两次均取得该失败信号，不再以短暂 playing 事件当成整体成功。

读取 X 当前已加载的前端代码和组件状态，发现：

- 账号自动播放选项为 Always，dataSaverMode=false，preventPlayback 未启用，
  无 SoftIntervention；页面启用了自动播放带宽门槛。
- 自动播放判断模块 411278 在估计带宽低于 1,000,000 bps 时拒绝自动预览，改为
  仅渲染播放按钮；估计缓存模块 18158 按网络签名保存，最多有效 300,000ms。
- 在第二轮真实 QUIC 连续滚动中，同步读取该页面自己的估计：约 35.7 Mbps →
  2.92 Mbps → 1.29 Mbps → 0.657/0.676/0.557 Mbps。最后一组可见卡片没有
  播放器，与失败画面一致；Chrome effectiveType 此时仍是 4g，不能把 3g 当作
  必要条件。
- 紧随其后的只读函数检查得到：开启带宽门槛时 false，不计带宽门槛时 true；
  当时缓存约 893,184 bps，网络签名 4g:unknown。此检查没有修改门槛或缓存值。

以上定位了该次“后续不自动预览”的直接页面机制。尚未确定带宽估计下降源于
Helios 实际传输瓶颈、短时请求等待还是播放器估计方法，不能宣称代理内核已修复。
之前在 Clash 下缓存恢复至约 30.8 Mbps 的现场，诊断性调用单张卡片的 forceUpdate()
后记录到视频持续推进和解码帧增加；此操作只用于检验重新渲染，不是修复，也不
纳入“未经干预自动播放成功”的验收。未修改账号设置或关闭浏览器。

一手代码来自当时页面实际加载的 X 资源：
[自动播放判断及组件](https://abs.twimg.com/responsive-web/client-web/shared~bundle.AudioSpaceAnalytics~bundle.AudioSpacePeek~bundle.AudioSpaceReport~bundle.AudioSpaceStart~bundle.8bab2b46a97b3bffa.js)、
[带宽缓存与门槛模块](https://abs.twimg.com/responsive-web/client-web/shared~loader.inlineTombstoneHandler~loader.tweetHandler.466361b7583a225ea.js)。
模块号与资源版本仅用于本次证据，不应写死进 Helios。

现场数据：`/tmp/helios-home-continuous-results.json`、
`/tmp/helios-home-bandwidth-results.json`、`/tmp/helios-preview-stall-reproduced.jsonl`，
以及 `/tmp/helios-home-stalled-*.png`；均为本机临时诊断文件，不含 Cookie 或请求头。
测试完成恢复 Clash、卸载临时扩展，窗口及登录配置保留。未修改生产代码或部署。

#### QUIC 拥塞控制与会话管理修复（2026-11-03）

随后进行了真正的传输层对照，修复范围包括客户端和服务端，不改私有协议：

- 继续使用官方 Quinn 0.11.12；两端显式采用内置 BBR，初始拥塞窗口 12,000 字节。
  VPS 同连接连续下载的 CUBIC 基线为 3.458～9.996 秒/1 MiB，并有两次 10 秒超时；
  单纯将 CUBIC 初始窗口提高到 240,000 字节仍会逐次变慢，不能替代拥塞控制修复。
- 开流前克隆会话并释放 RwLock，避免网络等待持有读锁、错误路径申请写锁而死锁。
  单个流失败不再移除存活会话，旧连接失败也不能清掉新连接。
- 将等待 QUIC stream credit 纳入连接总期限，避免并发请求无限等待。
- 心跳保留完整读写 future，5 秒软超时后继续等待同一次 PING/PONG；15 秒硬期限后
  才关闭会话。避免取消半帧读取、重发请求、迟到 PONG 导致控制流错位。
  恢复连接与认证也设置 10 秒期限。

针对锁、stream credit 和旧会话替换的四项回归先在旧代码失败，再在修复后通过。
新增测试还覆盖延迟/分段 PONG、阻塞 PING 写入和心跳最终期限。

验证命令：

```sh
cargo test --offline -p helios-transport -p helios-daemon -p helios-server
cargo test --offline -p helios-transport --test quic_loss -- --ignored --nocapture
cargo clippy --offline -p helios-daemon -p helios-server -p helios-transport --all-targets -- -D warnings
cargo build --offline --release -p helios-daemon -p helios-server -p heliosctl
SMOKE_TRANSPORT=quic SOAK_REQUESTS=120 SOAK_PARALLEL=24 IDLE_SECONDS=65 bash scripts/local-transport-smoke.sh
```

结果：常规测试 65 项通过；一个隔离 D-Bus 测试未运行，弱网测试另行显式执行。
弱网测试用用户态 UDP 中继加入 160ms RTT、每 100 个下行数据报丢弃一个，读取并
校验完整 1 MiB：CUBIC 4.959 秒，正式 BBR 配置 2.046 秒。该计时测试默认 ignored，
需单独执行以免并行测试负载影响结果。Clippy 无警告，原生 release 与 musl 服务端
构建成功。局域网 32 MiB 下载 0.349 秒，120 次下载/24 路并发全部完成，空闲 65 秒
后继续下载成功，无 QUIC Flow 回退。

修复版 musl 服务端已实际部署，配置校验、OpenRC 状态和文件 SHA-256 均检查通过；
原二进制备份为 `/usr/local/bin/helios-server.before-bbr-1793698426480`。
新二进制 SHA-256：`2a888ed1977d78604c5b4098a8cd56ba7f69a6c4da7a4ab2415a0fb1ba15470d`。
客户端只重启独立 QUIC 测试实例（HTTP 8081），未修改桌面主实例配置。

正式部署后，同一 QUIC 连接从 VPS 临时 loopback 源连续下载 9 次 1 MiB，含建流的
耗时依次为 2.334、0.587、0.312、0.524、0.310、0.407、0.271、0.333、0.329 秒。
没有超时、接收 socket 丢包或连接关闭，测试直接使用 QUIC、不允许 TLS 掩盖失败。
这是当前线路的实测改善，不代表所有网络必然满速；BBR 也无法解决 UDP 阻断/限速。

使用原来已登录的有头 Chrome 首页，通过临时代理扩展指向新版客户端 8081，连续
滚动 55 次（450px/次），有效观察约 362 秒。每屏采样至少 6 秒，未播放时延长到
10 秒；同时统计真实 video 与 playButton 占位卡片，不调用 play()，不修改播放器
设置、带宽缓存或自动播放门槛。控制面多次采样均为 QUIC，活跃流也全部为 QUIC。

- 21 张进入有效视野的视频卡片中，20 张在对应停留窗口内有解码帧推进；另 1 张
  暂停在约 0.158 秒、readyState=4，继续滚动后自行播放，后续采样帧数达到 328。
  所以最终 21 张均观察到播放，但不能记作“21/21 首次进入视野立即播放”。
- 没有只剩 playButton 的卡片，也未出现先前的后续连锁停播；457 次视频资源响应，
  均为 200，无非 ERR_ABORTED 网络错误，无失焦样本。HTTP 成功仅作辅助证据，
  播放判据是 paused 状态与实际解码帧推进。
- 期间发生一次 QUIC 5 秒软超时，后续心跳恢复；未记录 quic_health_failed、
  quic_flow_failed 或重建事件，末次 RTT 约 174ms。后台 TLS 探测也有一次超时，
  说明本次链路仍有短时波动，不能把 BBR 当作消除全部网络波动的保证。
- 结束后恢复原 Clash 浏览器代理并卸载临时扩展，保留所有窗口和登录状态。

现场数据：`/tmp/helios-bbr-browser-8081.json`、
`/tmp/helios-bbr-browser-8081-{2,54}.png`、`/tmp/helios-bbr-daemon.log`。
最终 VPS 服务仍为 started，二进制哈希与部署值一致。本轮未重新运行 macOS 真机、
未进行数小时/数日稳定性验收，也未推送 Git 或触发新的客户端安装包构建。

#### macOS TLS 节点测试 EINVAL 修复

用户在 macOS 测试节点时，QUIC 正常，TLS 返回 `Invalid argument (os error 22)`。
在 GitHub macOS 原生运行器执行：

```sh
cargo test -p helios-transport tls::tests:: -- --nocapture
```

[修复前回归运行](https://github.com/ganity/Helios/actions/runs/41616018197)
的 TCP 连接测试实际返回 `Os { code: 22, kind: InvalidInput, message: "Invalid argument" }`，
其余 6 项 TLS 测试通过。测试由原来的 join 改为有 5 秒期限的 try_join，使连接准备
失败能立即报错，不会一直等待从未到达的 accept。

根因是 `connect_node_tcp` 在所有 Unix 平台连接前设置 `TCP_MAXSEG=1000`。
[Apple 内核](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp_usrreq.c)
只允许将 MSS 设置为不大于当前值；未连接 IPv4 socket 使用默认 MSS，
[默认值为 512](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp.h)，
因此强设 1000 会在 connect/TLS 握手之前失败。这与证书路径或 token 无关。

修复在 Apple 平台连接成功后读取协商 MSS，再设置 `min(当前 MSS, 1000)`；
其他 Unix 保留原有连接前设置，Windows 保留 OS PMTU 处理。连接后的 Apple 设置
约束本机发送分段，不应等同于 Linux 在 SYN 前配置的对端 MSS 协商行为。
共享拨号入口同时覆盖桌面节点测试、daemon TLS 代理与 QUIC 回退；不改节点配置
或服务端。真实 TLS 分帧测试也改走该入口，macOS CI 新增运行 TCP/TLS 原生测试，
避免仅凭跨平台编译成功判定运行时可用。
