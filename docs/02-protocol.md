# Helios Protocol v1 设计

## 1. 目标与威胁边界

Helios Protocol 是运行在 TLS 1.3 或 QUIC 加密层内的应用协议。它负责版本协商、认证、建流、UDP 关联、错误和保活，不负责自定义加密。

协议不承诺隐藏 QUIC/TLS，也不以更改字段顺序作为安全机制。Padding 只用于降低固定应用帧长度，不保证抵抗流量分析。

## 2. Transport 映射

### QUIC

- 一个节点通常维持一个 QUIC connection。
- 每个 TCP Flow 打开一个双向 QUIC stream。
- stream 以 `CONNECT_TCP` 开始，收到成功结果后余下字节均为业务数据，不再逐块封装 DATA 帧。
- 控制使用一个长期双向 stream。
- UDP 优先使用 QUIC datagram，控制和重绑定仍走可靠 stream。

### TCP/TLS

- v1 每个 TCP Flow 建立一个独立 TLS/TCP 连接。
- TLS 完成后发送 `CLIENT_HELLO`、`AUTH` 和 `CONNECT_TCP`。
- 收到成功结果后余下字节均为业务数据。
- UDP 在 TCP 回退下采用长度前缀消息；不承诺实时性等同 QUIC。
- 不实现应用层多路复用，避免共享 TCP 队头阻塞和自研复杂 mux。

## 3. 基础编码

所有整数为网络字节序。控制帧格式：

```text
0               1               2               3
+---------------+---------------+---------------+---------------+
| Magic: 0x48 0x53              | Version       | Type          |
+---------------+---------------+---------------+---------------+
| Flags         | Reserved      | Request ID                    |
+---------------+---------------+---------------+---------------+
| Payload Length                                                |
+---------------+---------------+---------------+---------------+
| Payload ...                                                   |
+---------------------------------------------------------------+
```

| 字段 | 长度 | 约束 |
|---|---:|---|
| Magic | 2 | 固定 `HS`，只用于误配置检测，不是安全特征 |
| Version | 1 | v1 为 `1` |
| Type | 1 | 未知关键类型关闭协议关系 |
| Flags | 1 | 未知 flag 必须拒绝 |
| Reserved | 1 | 必须为零 |
| Request ID | 4 | 请求与结果关联，零保留给单向事件 |
| Payload Length | 4 | 控制帧最大 16 KiB |

地址编码：

```text
Address Type: 1 byte  (1=IPv4, 2=IPv6, 3=Domain)
Address Length: 1 byte
Address: N bytes
Port: 2 bytes
```

域名按 UTF-8 输入，经 IDNA 转为 ASCII 后发送；编码后不超过 253 bytes，单标签不超过 63 bytes。IP 地址必须使用固定 4/16 bytes。

## 4. 消息类型

| 类型 | 方向 | 用途 |
|---|---|---|
| `CLIENT_HELLO` | C→S | 版本、能力、随机数 |
| `SERVER_HELLO` | S→C | 选定版本、能力、限制 |
| `AUTH` | C→S | credential ID 与证明 |
| `AUTH_OK` | S→C | 认证完成、Session ID |
| `AUTH_ERROR` | S→C | 通用认证失败，不泄露具体原因 |
| `CONNECT_TCP` | C→S | 请求 TCP Target |
| `CONNECT_OK` | S→C | 出站已建立 |
| `CONNECT_ERROR` | S→C | 规范化错误类别 |
| `UDP_ASSOCIATE` | C→S | 建立 UDP 会话 |
| `UDP_ASSOCIATE_OK` | S→C | 返回 Association ID |
| `UDP_PACKET` | 双向 | TCP fallback 下的 UDP 消息 |
| `PING` / `PONG` | 双向 | 应用层健康测量 |
| `GOAWAY` | 双向 | 不再接受新 Flow |
| `CLOSE` | 双向 | 关闭 UDP 关联或控制关系 |

认证完成后的 QUIC 控制 stream 持续存活。客户端发送带非零 Request ID 的 `PING`，服务端用相同 Request ID 和原样 payload 返回 `PONG`；不匹配的响应视为控制协议错误。控制 stream 关闭或收到非控制消息时，服务端结束整个 QUIC session，防止失去认证控制关系后继续接收新 Flow。

## 5. 握手与认证

```text
Client                    Server
  |--- TLS/QUIC handshake -->|
  |--- CLIENT_HELLO -------->|
  |<-- SERVER_HELLO ---------|
  |--- AUTH ---------------->|
  |<-- AUTH_OK / ERROR -------|
```

TLS 必须正常验证服务端证书和 server name。AUTH 使用 256-bit 随机 token 派生的证明，而不是明文 token：

```text
proof = HMAC-SHA256(token,
    "helios-auth-v1\\0" ||
    u32(client_hello_payload.length) || client_hello_payload ||
    u32(server_hello_payload.length) || server_hello_payload)
```

服务端通过 credential ID 找到 token，常量时间比较 proof。认证失败响应内容一致，并限制同一来源的失败速率。

长度使用网络字节序，payload 是控制帧中的完整 payload，包括 nonce、能力、服务端限制和 Padding。域分离字符串和显式长度避免跨协议使用与字段拼接歧义。TLS 已提供加密与完整性；HMAC 的作用是避免在应用 payload 中直接发送长期 token，并把认证绑定到本次握手。该定义在 Protocol v1 冻结前仍需独立安全评审。

## 6. TCP Flow

`CONNECT_TCP` payload：

```text
Target
Connect Timeout Milliseconds: u32
Metadata Length: u16
Metadata: bytes
Padding Length: u16
Padding: bytes
```

v1 Metadata 必须为空，字段仅保留为零长度，避免以后无法区分旧解析器。Timeout 服务端限制在 1–30 秒范围内。

结果错误类别：

```text
GENERAL_FAILURE
NOT_ALLOWED
NETWORK_UNREACHABLE
HOST_UNREACHABLE
CONNECTION_REFUSED
TIMEOUT
ADDRESS_UNSUPPORTED
RATE_LIMITED
```

成功后协议切换为 raw byte stream。双方必须传播半关闭；空闲超时默认 5 分钟，可由服务端限制。一个方向 EOF 不立即丢弃另一个方向尚未发送的数据。

## 7. UDP

当前实现把以下 Helios 消息编码后放入一个 QUIC datagram：

```text
Association ID: u32
Packet ID: u32
Target
Payload Length: u16
Payload
```

当前 wire 编码为 `Association ID:u32 | Packet ID:u32 | Target | Payload Length:u16 | Payload`。协议 payload 上限为 1200 bytes；编码后的完整 datagram 还必须不超过 Quinn 当前路径 MTU，超限时客户端丢弃。v1 不分片。

SOCKS UDP 来源固定为该关联首个有效数据报的来源地址。服务端为单个请求使用独立 UDP socket，避免不同目标的响应串线；每个关联最多并行处理 64 个请求，每个请求最多等待 5 秒。关联通过 TCP 控制连接/QUIC association stream 生命周期关闭，也会在 30–300 秒可配置空闲时间后自动释放，默认 60 秒。

UDP 优先使用 QUIC datagram；QUIC association 无法建立时，客户端新建独立 TLS 连接并协商 `CAP_UDP_OVER_STREAM`，随后使用 `UDP_PACKET` 有界帧顺序收发。TLS fallback 存在队头阻塞，仅作为 UDP/443 不可用时的可靠兜底。规则 `direct` 在客户端解析域名并本地发 UDP，`proxy` 由服务端解析并转发，`reject` 丢弃。

## 8. Padding

v1 只允许握手和建流控制帧 Padding：

- 随机选择总帧长档位：256、512、1024 或 2048 bytes。
- 总帧不得超过 4 KiB。
- 数据 stream 不逐包 Padding。
- 接收方忽略 Padding 内容，但严格验证长度。
- 随机数来自操作系统 CSPRNG。

当前实现：`CLIENT_HELLO` 使用随机档位填充；对端确认 `PADDING_TIERS` 后，`SERVER_HELLO`、`AUTH`、`CONNECT_TCP` 接入填充。总帧长指 Helios 明文帧头加 payload，不是 TLS record 或 QUIC 网络包长度。随机档位选自能够容纳原始帧的档位；超过最大档位不再补齐。CONNECT 的显式 Padding 保留。

Padding 内容及档位均来自操作系统随机源；协议安全不依赖它。旧端不声明能力时，后续 AUTH/CONNECT 不启用填充；已有旧格式仍可解码 CLIENT_HELLO 的 Padding。新旧客户端/服务端组合有回归测试。当前尚未提供用户级关闭选项。

## 9. 版本与能力

`CLIENT_HELLO` 提交支持版本集合和能力位；服务端选择共同最高版本。没有共同版本则发送 `GOAWAY(UNSUPPORTED_VERSION)`。

v1 能力：

```text
TCP_CONNECT
UDP_DATAGRAM
UDP_OVER_STREAM
PADDING_TIERS
```

客户端不得仅凭自己支持某能力就使用它，必须等待服务端确认。

## 10. 0-RTT、重放与恢复

v1 不在 QUIC 0-RTT 中发送 AUTH、CONNECT 或 UDP。可以恢复 QUIC session ticket，但应用消息必须等待握手确认。

Transport 断开后：

- 已建立 Flow 失败并通知对应 Inbound。
- 新 Flow 可以选择其他 Transport 或 Node。
- 不重放 CONNECT，不迁移 TCP 字节流。
- UDP association 可重新建立，但会获得新的 Association ID。

当前已测试 SOCKS5 UDP → `UDP_ASSOCIATE` → QUIC datagram/TLS framed stream → 服务端 UDP → 返回 SOCKS datagram 的本机端到端路径。每个 SOCKS UDP association 使用独立 QUIC connection 或 TLS connection，避免关联间相互消费数据。客户端计量解析失败、规则拒绝、无代理通道、超 MTU 与发送失败等丢弃，并将累计值暴露到桌面状态。尚未完成真实公网 MTU/丢包验证。

## 11. 解析器要求

- 读取 payload 前先验证长度上限。
- 不为未认证连接分配与声明长度等量的大缓冲区。
- 未知版本、未知关键 flag、非零 reserved 均明确拒绝。
- 解析失败只关闭关联 stream；认证/控制 stream 失败关闭整个 Session。
- 任意输入不得 panic。
- 编解码必须有 round-trip、边界、属性测试和 fuzz target。
