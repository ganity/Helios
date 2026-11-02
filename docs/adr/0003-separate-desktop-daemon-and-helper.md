# Separate desktop, daemon, and privileged helper

桌面界面、网络核心和特权系统操作使用独立进程：desktop 只呈现状态，daemon 持有网络状态机，helper 只管理 TUN、路由和 DNS。该结构增加 IPC 和打包成本，但防止 UI 崩溃中断流量，并把长期高权限代码缩到可审核的最小范围。
