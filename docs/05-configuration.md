# 配置模型

当前阶段实现服务端和 SOCKS5 daemon 两类严格 TOML 配置。未知字段、非法范围和不支持的 schema 会在启动时拒绝；相对文件路径以配置文件所在目录为基准。

## 服务端

参考 `config/server.example.toml`：

```toml
schema_version = 1
listen = "0.0.0.0:443"

[tls]
certificate = "cert.pem"
private_key = "key.pem"

[auth]
id = "desktop-main"
token_file = "token.hex"

[limits]
handshake_timeout_seconds = 10
max_sessions = 64
max_flows_per_session = 1024
```

同一个 `listen` 地址同时绑定 TCP/TLS 和 UDP/QUIC。`max_sessions` 是两种传输共享的已接受会话上限；`max_flows_per_session` 限制单个 QUIC connection 的并发数据流。TLS 每个连接只承载一个 Flow。

## SOCKS5 daemon

参考 `config/daemon.example.toml`：

```toml
schema_version = 1
listen = "127.0.0.1:1080"
http_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:9080"
# macOS/Linux 可选；桌面客户端默认使用 ~/.helios/control.sock
# control_socket = "/Users/you/.helios/control.sock"
# Windows 可选；桌面客户端默认使用当前用户私有 Named Pipe
# control_pipe = "\\.\pipe\helios-control"

[dns]
listen = "127.0.0.1:1053"
fake_ip_capacity = 4096
fake_ip_ttl_seconds = 60

[node]
server = "203.0.113.10:443"
server_name = "vpn.example.com"
ca_certificate = "ca.pem"
credential_id = "desktop-main"
token_file = "token.hex"
preferred_transport = "quic"

[timeouts]
socks_handshake_seconds = 5
http_handshake_seconds = 5
connect_milliseconds = 10000
health_probe_seconds = 30
udp_idle_seconds = 60

[[rules]]
type = "domain-suffix"
value = "example.cn"
action = "direct"

[[rules]]
type = "ip-cidr"
value = "192.168.0.0/16"
action = "direct"

[[rules]]
type = "final"
action = "proxy"
```

`listen`（SOCKS5）、`http_listen`（HTTP proxy）和 `control_listen`（只读状态）必须是三个不同的 loopback 地址。HTTP 入口支持 CONNECT 和 HTTP/1.0/1.1 absolute-form forward proxy。control Adapter 只提供聚合状态与规则热更新，不允许系统网络或凭据变更，并使用 `[node].token_file` 中的 32 字节 token 验证本地请求。`udp_idle_seconds` 限制在 30–300 秒，默认 60 秒；有效 UDP 活动会续期关联。`preferred_transport` 取 `quic` 时，认证后立即执行一次应用层 PING/PONG，此后按 `health_probe_seconds` 周期测量 RTT；连续 3 次探测超时才标记 QUIC 降级，协议错误或 Flow 建立传输错误立即让新 Flow 改走 TLS。降级后 daemon 按同一间隔重新建立和认证 QUIC，恢复成功后只让新 Flow 使用 QUIC，已有 TLS Flow 不迁移。服务端明确返回目标连接错误时不会重试。取 `tls` 时只使用 TLS。`server` 当前必须是 IP socket address；`server_name` 用于证书校验。

`[dns]` 为可选配置。启用后 daemon 在指定 loopback UDP 地址运行 Fake-IP responder；容量限制为 1–65536，TTL 限制为 30–3600 秒。该配置不修改系统 DNS。

规则按配置顺序匹配，第一个命中即停止。支持 `domain`、`domain-suffix`、`ip-cidr`、`ip-cidr6`、`dst-port` 和 `final`；动作支持 `direct`、`proxy`、`reject`。非空规则必须以唯一且位于末尾的 `final` 结束。规则为空时等价于 `FINAL,proxy`。域名规则大小写不敏感，后缀规则匹配根域及其子域，不匹配仅有字符串后缀的无关域名。Direct 域名使用本机 DNS；Proxy 域名仍由服务端解析。daemon 自身两个入口始终优先拒绝，不能被用户 Direct 规则覆盖。

macOS/Linux 设置 `control_socket` 后，daemon 使用权限为 `0600` 的 Unix Domain Socket。Windows 设置 `control_pipe` 后，daemon 使用拒绝远程客户端、仅允许对象所有者与 SYSTEM 访问的 Named Pipe。`control_listen` 仅保留为旧配置兼容入口。

## 凭据与证书

token 文件必须包含恰好 64 个十六进制字符。Unix 上程序要求 token 是普通文件，且 group/other 没有任何权限；建议执行：

```sh
chmod 600 token.hex
```

服务端证书必须可用于 `serverAuth`。daemon 的 `ca_certificate` 应包含签发服务端证书的 CA；测试环境也可填入受信任的自签终端证书。

部署前可在不启动监听的情况下验证配置及所有引用文件：

```sh
helios-server check --config /etc/helios/server.toml
```

## 验证范围

- `schema_version` 必须为 1。
- 监听端口和服务端端口不能为 0。
- handshake/SOCKS/HTTP Header 超时范围为 1 到 60 秒。
- connect timeout 范围为 1000 到 30000 毫秒。
- QUIC 健康探测间隔范围为 5 到 300 秒，单次响应超时为 5 秒。
- session 和 flow 上限范围为 1 到 10000。
- credential ID 必须满足协议编码约束。
- `server_name` 必须是 rustls 接受的 DNS 名或 IP。
- CIDR 地址族必须与规则类型一致；端口不能为 0；FINAL 必须位于末尾。

桌面当前管理节点列表、路由规则和 daemon 配置，并通过 control 通道原子热更新规则。系统凭据库尚未接入，token 仍使用权限受限的文件。

桌面生成配置后，也可在不启动本地监听或连接服务端的情况下进行完整检查：

```sh
helios-daemon check --config ~/.helios/daemon.toml
```
