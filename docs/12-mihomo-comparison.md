# Mihomo 源码对照与 Helios 第二轮调整

## 核对范围

用户指定仓库为 https://github.com/MetaCubeX/mihomo 。本轮固定实际代码分支 Meta 的
提交 `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`，避免把默认分支的元数据、旧注释
代码或其他版本混为一谈。实际分支为 GPLv3；Helios 只借鉴设计，独立使用 Rust 实现。

本报告区分代码事实、Helios 的对应改动和未验证判断，不以更换语言或增加参数推断速度。

## 1. 拨号和失败路径

[dialer.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/component/dialer/dialer.go)
的 `DialContext` 选择串行或可选并发拨号。双栈分支同时协调两个地址族，偏好族有
300 ms 回退门限，落败的成功连接会被关闭。`tcp-concurrent` 默认关闭，因此不能
把它描述成“总是同时连接所有 IP”。

Helios 已有 IPv4/IPv6 交错、250 ms 错峰尝试及整体目标连接期限。`JoinSet` 丢弃时
取消剩余任务，落败连接随任务结果释放。当前没有额外添加 IP 探测服务或无限重试。
地址缓存命中并不保证该地址可达；目前会尝试全部缓存地址，但不会在失败后突破总期限重试。

## 2. DNS：成功缓存不等于失败合并

[resolver.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/dns/resolver.go)
结合查询合并与带过期时间的 DNS 消息缓存，过期命中还可以触发后台刷新。
Helios 使用系统解析器，拿不到消息 TTL，不能照搬其 TTL 和过期返回策略。

上一轮 Helios 虽用同域名锁合并成功结果，但失败不留下共享结果，等待者拿锁后
会再次解析，造成失败请求串行重放。本轮改为成功结果最多保留 30 秒，失败结果只保留
1 秒，等待者共用错误，之后允许恢复重试。仍最多缓存 256 个域名；繁忙时不驱逐正在
使用的条目。取消持锁查询会释放锁，不留下永久 in-flight 状态。

新增测试验证短时错误共享及过期恢复。这里的 1 秒是本地失败抑制窗口，不是权威
NXDOMAIN TTL，也不只针对 NXDOMAIN。容量达到上限且全部条目繁忙时，新域名不缓存，
该场景不保证查询合并。没有在客户端解析海外目标。

## 3. 握手往返：减少串行等待，保留认证

[Trojan 出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/trojan.go)
在 TLS 后调用
[WriteHeader](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/trojan/trojan.go)，
将认证材料和目标地址组成请求头。普通 TCP 分支不是全局多路复用。

Helios 的 challenge-response 认证有自己的重放防护，不能直接改为同样的密码头。
但原流程在 `AuthOk` 返回之后才发送 `ConnectTcp`，这个客户端等待可以省去：

```text
之前：Auth → 等 AuthOk → ConnectTcp → 等 ConnectOk
现在：Auth + ConnectTcp → 等 AuthOk → 等 ConnectOk
```

本轮增加认证后建流流水发送，仅用于 TLS TCP Flow；QUIC 已在会话中认证，不需要
每个流重做这一步。帧内容和序号不变，服务端仍严格先认证再处理建流，没有启用 TLS
early data、跳过证书校验、在认证前拨号目标或提前发送浏览器业务数据。

测试包含：对端故意延迟 AuthOk 直到收到 ConnectTcp（旧串行实现会停住）、错误凭据
必须拒绝、现有 authenticate_server/accept_tcp 与 Padding 协商兼容。流程上少一次
串行往返；不能直接把它等同于整个网页加速一个 RTT，收益取决于连接复用和资源依赖。

## 4. TLS 恢复：先验证默认行为

检查本地 rustls 构造器发现其 std 默认已有服务端内存会话存储并发送 TLS 1.3 ticket。
无需再添加一套 ticket 管理。新增真实 TLS 测试复用同一 ClientCrypto/ServerCrypto，
确认第一次为 `Full`、第二次为 `Resumed`，且两次均执行 Helios 应用层认证。
TLS 1.3 恢复可减少证书和密码运算开销，不应声称它自动变成 0-RTT。

## 5. 转发、半关闭和缓冲

实际转发入口是
[common/net/sing.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/common/net/sing.go)，
而不是整段被注释的 `relay.go`。两方向复制，正常结束尝试 CloseWrite，错误关闭，
等待另一方向退出并最终关闭两端。依赖在
[go.mod](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/go.mod)
固定 `github.com/metacubex/sing v0.5.8`。

继续追踪
[sing Copy](https://github.com/MetaCubeX/sing/blob/v0.5.8/common/bufio/copy.go)
可以看到缓存数据处理、计数包装拆解、syscall 连接的 copyDirect 和 Extended/ReadWait
路径；[Buffer](https://github.com/MetaCubeX/sing/blob/v0.5.8/common/buf/buffer.go)
也有受管理的池化存储。不能简化成“把缓冲改大就能一样快”。

Helios 的 TLS 解密流无法直接使用裸 TCP 到 TCP 的零拷贝。本轮保留 Tokio 双向复制
及已有半关闭兼容测试，不引入第二套转发循环或无证据的缓冲池。

确实修复的超时缺口：之前 open_tcp 只给读回应设置期限，写请求背压可以无限等待。
现在同一超时覆盖写请求、flush 和读回应；流水发送位于已有节点握手期限内，后续
建流回应另有目标期限。新增 duplex(1) 不读取对端的测试，验证写阻塞也能退出。

## 6. 保活、QUIC 和 MSS 的界限

[keepalive](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/component/keepalive/tcp_keepalive_go123.go)
集中处理拨号器、监听器和连接的选项，且考虑平台差异。Helios 上轮的保活措施保留，
但 TCP keepalive 不替代应用认证探测或路径 MTU 修复。

[TUIC 出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/tuic.go)
使用连接池及流数留量，还配置 QUIC 窗口和心跳。它属于协议专用路径，不能据此认定
所有 Mihomo 协议都复用。当前 VPS 不适合 UDP，对 QUIC 堆参数无法修复其 TCP 链路。
本轮不加入 QUIC 池或 TCP 全局复用，避免扩大无测量支持的改动。

固定 Unix MSS 1000 仍是上一轮链路兼容行为，不是 Mihomo 源码推导出的通用配置。
尚待节点级策略与 Windows 验证；本轮不移除已在用户线路验证有效的行为。

## 验收和边界

新增回归覆盖流水发送时序、错误认证、原服务端兼容、完整建流超时、DNS 失败共享与
恢复、TLS 会话恢复。63 项相关测试通过（另有 1 项既有隔离桌面测试跳过），Clippy、release server/daemon 编译及 TLS/QUIC
本地 100 次、24 并发测试通过；两种传输各自加载全部 48 张图片，无资源错误。

本轮未修改 VPS、GitHub 或系统代理。新版客户端直连既有 VPS 的 Doodles 结果另见
测试记录；它可验证新客户端兼容，但不能代表新版服务端的 DNS 优化已在公网生效。
Mac/Windows 真机、长时间运行和公平的同线路 Mihomo 对照仍未完成。
