# Deliver system proxy before TUN

Helios 先完成 SOCKS5/HTTP、规则、系统代理和桌面产品，再依次实现 Windows TUN、Fake-IP DNS 和 macOS Network Extension。TUN 的路由恢复、DNS、UDP、权限和签名风险显著高于用户态代理；分阶段可以先验证协议和 Transport，同时避免多个高风险变量一起进入调试范围。
