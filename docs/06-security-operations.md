# 安全、部署与运维

## 1. 信任边界

以下输入均不可信：

- 本地 SOCKS5/HTTP 请求，即使来自 loopback。
- TUN packet 和 DNS 消息。
- 公网协议帧和 TLS peer。
- 导入的配置与规则。
- desktop IPC 和 helper IPC。
- 服务端 DNS 响应和目标网络行为。

所有解析器必须先验证长度再分配，所有网络操作必须有超时，所有队列和缓存必须有界。

## 2. 威胁与控制

| 威胁 | 控制 |
|---|---|
| 中间人 | TLS 证书与 server name 验证；可选 SPKI pin |
| Credential 泄漏 | OS secret store；应用层 HMAC proof；日志脱敏 |
| 未授权公共代理 | 认证前限制；失败限速；只开放 Helios 加密端口 |
| 内存耗尽 | 帧、队列、Flow、DNS、UDP association 硬上限 |
| CPU 耗尽 | 握手超时、来源限速、认证失败退避 |
| DNS 泄漏 | Proxy 域名远端解析；TUN Fake-IP；明确 DoH 限制 |
| 路由环路 | 服务端和 daemon socket bypass；启用后自检 |
| 崩溃断网 | System Proxy Lease、Tunnel Lease、启动恢复 |
| helper 被滥用 | 当前用户/签名验证；命令允许列表；最小参数 |
| 日志泄漏 | 默认不记录完整域名、进程路径、token、payload |
| 供应链变更 | 锁版本、vendor、审查 build.rs/proc macro、SBOM |

## 3. Credential 生命周期

- 初次部署由 CLI 使用操作系统 CSPRNG 生成 32 bytes token。
- token 只在受控终端输出一次，分别写入服务端权限文件和客户端 secret store。
- Node 配置引用 credential ID。
- 支持添加新 token、双 token 过渡、禁用旧 token。
- 不在日志、诊断包、二维码或普通配置导出中包含 token。
- Credential 比较使用常量时间实现。

## 4. TLS

- 最低 TLS 1.3。
- 使用 rustls 默认安全 cipher suites，除非安全评审要求修改。
- 正常验证证书链、有效期和 server name。
- 自签名部署使用显式 SPKI pin，不提供“跳过验证”。
- 证书即将过期在 UI 和服务端日志中预警。
- QUIC 和 TCP/TLS 使用同一服务端身份，但可有不同 ALPN。

## 5. 依赖治理

- 提交 `Cargo.lock` 和 `rust-toolchain.toml`。
- 发布构建使用 `cargo vendor` 的固定依赖。
- 禁止浮动 Git branch 依赖。
- 启用最少 Cargo feature。
- CI 执行 `cargo audit`、`cargo deny check` 和许可证检查。
- 人工审查依赖中的 `build.rs`、proc macro、native library 和 `unsafe`。
- 生成 SBOM，并记录二进制、源码和依赖归档的 hash。
- Dependabot 类更新只开 PR，不自动合并。

依赖源码可见不等于安全；目标是版本固定、变更可追溯、构建可重复。

## 6. Linux 服务端部署

建议目录：

```text
/usr/local/bin/helios-server
/etc/helios/server.toml
/etc/helios/credentials.toml
/etc/helios/tls/
/var/lib/helios/
```

systemd 要求：

- 专用 `helios` 用户。
- 配置和凭据只允许该用户读取。
- 绑定 443 使用 `CAP_NET_BIND_SERVICE`，不以 root 常驻。
- `NoNewPrivileges=true`、`PrivateTmp=true`、`ProtectSystem=strict`。
- 只开放必须的写目录。
- 合理的文件描述符上限。
- SIGTERM 或 Ctrl-C 时停止接收新 Session/Flow，活跃项归零后提前退出，最长等待 2 秒。

仓库提供 `deploy/helios-server.service`。安装二进制和配置后执行：

```sh
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin helios
sudo install -o root -g root -m 0755 target/release/helios-server /usr/local/bin/helios-server
sudo install -d -o root -g helios -m 0750 /etc/helios
sudo install -o root -g helios -m 0640 server.toml /etc/helios/server.toml
sudo install -o root -g root -m 0644 deploy/helios-server.service /etc/systemd/system/helios-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now helios-server
```

也可使用仓库提供的最小安装脚本。它创建专用用户、安装二进制与 hardened systemd unit、生成权限为 `0600` 的 32 字节随机 token，并安装证书和私钥；重复运行会保留现有 token 和 `server.toml` 配置内容，同时重新收紧 token、私钥和配置文件权限：

```sh
sudo deploy/install-server.sh target/release/helios-server cert.pem key.pem
sudo cat /etc/helios/token.hex
```

第二条命令的输出必须通过安全通道写入客户端 token 文件，随后清理终端滚屏和任何临时副本。测试打包时可设置 `DESTDIR=/tmp/stage`，此时脚本不会创建用户或调用 systemd。

证书、私钥和 token 路径必须对 `helios` 用户可读；私钥与 token 不应授予 group/other 权限。

防火墙只需允许 UDP/443 和 TCP/443。管理操作通过 SSH 完成，不新增公网管理端口。

## 7. Windows 发布

- 构建签名的 x64/arm64 二进制和安装包。
- Wintun DLL 固定版本并校验签名/hash。
- helper/service 安装和卸载必须幂等。
- 卸载前停止 daemon、释放租约、移除 adapter 和启动项。
- 强制卸载失败时保留恢复工具，而不是直接删除状态。
- 系统代理使用 HKCU Internet Settings Lease，保存值是否存在与原始类型/内容；发现用户漂移时不覆盖外部修改。设置 `http=` 和 `https=` 到本地有界 HTTP proxy listener。

## 8. macOS 发布

- App Bundle 包含 desktop、daemon/helper 和 Network Extension。
- 使用 Developer ID 签名并 notarize。
- entitlement 最小化，正式验证 Packet Tunnel 权限。
- 使用 SMAppService 等受支持机制启动后台程序。
- 卸载指引先停用 VPN configuration，再删除应用。
- 系统代理 Lease 逐网络服务保存 HTTP、HTTPS 和 bypass domains；发现认证代理时拒绝启用，避免覆盖不可恢复的密码状态。

## 9. 日志和诊断

日志分级：ERROR、WARN、INFO、DEBUG、TRACE。默认 INFO，生产日志字段化。

`helios-server` 与 `helios-daemon` 默认向 stderr 输出单行 JSON，便于 journald 或日志采集器处理。通过 `RUST_LOG` 临时调整级别，例如 `RUST_LOG=helios_server=debug` 或 `RUST_LOG=helios_daemon=debug`；DEBUG 可能包含底层错误文本，只应在限时诊断期间启用。默认 INFO/WARN 只记录事件类别，不记录客户端地址、目标地址、token、proof 或 payload。

默认允许记录：

- 时间、模块、事件、匿名 Flow/Session ID。
- Transport、错误类别、耗时、聚合字节数。

默认禁止记录：

- token、proof、私钥、payload。
- 完整目标域名/IP。
- 用户名和完整进程路径。

诊断包包括版本、平台、脱敏配置、租约状态、最近错误和依赖清单。生成前再次执行脱敏扫描。

## 10. 运维命令

服务端 CLI 最小集合：

```text
helios-server check --config PATH
helios-server run --config PATH
helios-server credential generate --output TOKEN_FILE
helios-server identity generate --output DIRECTORY
helios-server client-link --config PATH --address IP:PORT --server-name NAME --name DISPLAY_NAME
helios-server version
```

为兼容已有 systemd unit，`helios-server PATH` 仍等价于 `run --config PATH`。`check` 会解析严格 TOML、读取并验证 token、证书和私钥，并构建 TLS/QUIC crypto 配置，但不会绑定端口。`credential generate` 使用操作系统 CSPRNG 创建恰好 32 字节的 token，以 64 位十六进制写入新文件；目标已存在时拒绝覆盖，Unix 权限为 `0600`。

`identity generate` 创建独立私钥及绑定随机 `node-<128-bit>.helios.invalid` 名称的五年期终端证书；该名称只用于 TLS 身份校验，不参与 DNS 解析，因此公网 IP 变化不要求换证书。`client-link` 在输出链接前使用实际私钥、证书和给定名称完成一次内存 TLS 握手；名称不匹配时拒绝生成。`helios://` 链接内含 token，必须按密码处理，不能记录到日志或诊断包。每台 VPS 使用独立私钥，不能跨节点共享 `key.pem`。

客户端恢复命令：

```text
helios-daemon check --config PATH
helios-daemon recover-network
helios-daemon version
```

为兼容现有桌面启动方式，`helios-daemon PATH` 仍等价于 `run --config PATH`。`check` 验证严格 TOML、CA、server name、token、规则和 Fake-IP 参数，但不绑定任何端口。`recover-network` 仅在 Windows/macOS 恢复 Helios 自己持有的 System Proxy Lease；发现用户或其他软件修改过代理时保持现状并返回错误。TUN 恢复仍由需要系统授权的 `helios-helper --recover` 执行。

不实现常驻 Web 管理面板。

## 11. 升级与协议兼容

- 客户端升级前保存配置快照。
- 服务端先升级，保持支持当前和前一个稳定协议版本。
- 客户端确认服务端支持后再启用新能力。
- 破坏性协议变化增加主版本，不根据 User-Agent 猜测。
- 回滚不能覆盖更新版本配置；未来 schema 以只读方式保护。
