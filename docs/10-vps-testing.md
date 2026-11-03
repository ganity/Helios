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
