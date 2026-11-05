# 阶段 0 诊断 CLI

当前二进制用于验证 Helios Protocol、TLS/QUIC、认证、TCP relay 与本地 SOCKS5 CONNECT；它们还不是桌面客户端。

## 服务端

复制并修改 `config/server.example.toml`，将证书、私钥和 token 放在配置文件同目录，或使用绝对路径：

```sh
helios-server ./server.toml
```

没有域名时，可生成一个不绑定 VPS IP 的稳定 TLS 身份。命令拒绝覆盖已有目录，
输出的名称同时写入 `server-name.txt`：

```sh
helios-server identity generate --output ./identity
```

将 `identity/cert.pem` 和 `identity/key.pem` 配置到服务端。迁移 VPS 或更换公网 IP
时保留这些文件及 `server-name.txt`，只更新公开连接地址，无需重新签发证书。

服务端配置完成后生成秘密连接链接：

```sh
helios-server client-link \
  --config /etc/helios/server.toml \
  --address 203.0.113.10:4800 \
  --server-name "$(cat ./identity/server-name.txt)" \
  --name "Personal VPS"
```

客户端在节点页粘贴输出的 `helios://v1/...` 链接即可。链接包含节点 token，等同于
密码；不要放入聊天记录、公开日志、命令参数或普通节点导出。客户端会自动保存证书与
token，用户无需填写证书、凭据文件或 TLS 名称路径。

程序在配置的同一地址同时监听 TCP/TLS 和 UDP/QUIC。TCP/TLS 每条连接执行一次认证并承载一个 `CONNECT_TCP`；QUIC connection 的第一个双向 stream 完成认证，后续双向 stream 各承载一个 TCP Flow。

## SOCKS5 daemon

复制并修改 `config/daemon.example.toml` 后启动：

```sh
helios-daemon ./daemon.toml
```

当前支持 SOCKS5 无认证协商、`CONNECT` 和 `UDP ASSOCIATE`。UDP ASSOCIATE 优先使用独立认证 QUIC 连接及 QUIC datagram；QUIC 不可用时 Proxy 规则改走独立 TLS framed stream，Direct 规则仍本地转发，不会静默直连。`BIND` 不支持。使用 `socks5h` 或 `--socks5-hostname` 可保留域名并交给 Helios 服务端解析：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

HTTP 入口只支持 CONNECT authority-form，域名同样交给服务端解析。可用以下命令验证隧道；普通 HTTP forward-proxy 请求会返回 405：

```sh
curl --proxytunnel --proxy http://127.0.0.1:8080 https://example.com/
```

TLS 模式为每个 SOCKS Flow 建立独立 TLS 连接并认证。QUIC 模式在 daemon 启动时建立并认证一个 connection，每个 SOCKS Flow 使用独立双向 stream；启动连接失败或运行中出现传输错误时，新 Flow 自动回退到 TLS。降级后 daemon 会按健康探测间隔重新连接 QUIC，恢复后仅新 Flow 使用 QUIC。

## 状态查询

`heliosctl` 通过配置的 control 端点查询 daemon；token 仍由调用者显式提供：

```sh
heliosctl status 127.0.0.1:9080 token.hex
# macOS/Linux 桌面默认端点
heliosctl status ~/.helios/control.sock token.hex
# Windows 桌面默认端点
heliosctl status '\\.\pipe\helios-control' token.hex
```

结果为版本化 JSON，包含 `unknown/connected/degraded/unavailable` 状态、当前 QUIC/TLS 传输、最近 QUIC 应用层 RTT、活跃 Flow 和进程生命周期内累计上下行字节。

## 单 Flow 诊断客户端

`helios-client` 暂时保留位置参数，只用于 stdin/stdout 链路诊断：

```text
helios-client TRANSPORT SERVER_ADDR SERVER_NAME CA_PEM CREDENTIAL_ID TOKEN_FILE TARGET_HOST TARGET_PORT
```

示例：

```sh
printf 'GET / HTTP/1.0\r\n\r\n' | helios-client \
  quic 203.0.113.10:443 vpn.example.com ./ca.pem \
  desktop-main ./token.hex example.com 80
```

## 当前限制

- 没有 SOCKS5 BIND；每个新 UDP association 都会重新优先尝试 QUIC，再按需回退 TLS。
- macOS/Linux 支持 Unix Domain Socket，Windows 支持当前用户私有 Named Pipe，旧配置继续支持 loopback TCP。
- 服务端和 daemon 支持 Ctrl-C 有界关闭；桌面停止其自有 daemon 时使用认证 Shutdown，并在超时后才强杀。
- `helios://` 是传递完整节点配置的秘密链接，不是自动刷新的订阅地址；IP 改变后需要生成并重新导入包含新地址的链接，稳定 TLS 身份和证书可以继续使用。
- 当前 CLI 只查询状态；规则、系统代理和 TUN 由桌面界面控制。
- `helios-server` 与 daemon 使用默认 INFO 的结构化 JSON 日志；helper 和桌面日志仍需统一到同一策略。
- UDP datagram 会受路径 MTU 与丢包影响；当前单包 payload 上限 1200 bytes，服务端每关联最多并行处理 64 个 UDP 请求，单请求等待响应最多 5 秒。

在上述生产能力完成前，只应在受控环境验证，不应直接作为长期公网服务部署。
