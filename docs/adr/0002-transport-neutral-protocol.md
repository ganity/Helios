# Keep the application protocol transport-neutral

Helios Protocol 的建流、认证和错误语义不依赖 QUIC 或 TCP/TLS，由 Transport Adapter 映射到各自连接模型。QUIC 为首选，TCP/TLS 只为新 Flow 回退且 v1 每个 TCP Flow 使用独立 TLS 连接；这避免自研多路复用与共享 TCP 队头阻塞，代价是更多握手。
