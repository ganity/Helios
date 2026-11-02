# Build Helios as a thin core

Helios 使用 Tokio、Quinn、rustls 等底层库自建协议、策略和生命周期，不 Fork TUIC、Leaf 或其他完整代理框架。这样牺牲首版速度，换取长期较小的审计面、当前依赖版本和对协议/回退语义的直接控制；这些完整项目只作为实现参考和对照测试工具。
