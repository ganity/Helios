# Linux 桌面客户端

正式 egui/eframe 客户端支持 X11/Wayland；节点、延迟探测、规则、DNS、连接列表和流量监控与其他平台共用实现。

## 日常使用

### 首次配置节点

从 VPS 的实际服务配置中确认 TLS 证书路径、`auth.id` 和 `auth.token_file`。使用项目安装脚本时默认是 `/etc/helios/cert.pem`、`desktop-main` 和 `/etc/helios/token.hex`；自行部署可能不同。通过 SSH/SFTP 安全传输证书和 token 文件到客户端电脑，**不要下载或分享服务端私钥 `key.pem`**，也不要把 token 发到日志或截图里。

把文件放在当前用户可读、长期保留的位置。节点的“受信证书文件”和“凭据文件”分别填写这两个**本机文件的完整路径**，不要填写 VPS 路径、证书正文或 token 正文。例如 Linux 为 `/home/你的用户名/.helios/cert.pem` 和 `/home/你的用户名/.helios/token.hex`；Windows 可使用 `C:\Users\你的用户名\.helios\cert.pem` 和相应的 `token.hex` 路径。token 应仅允许当前用户读取；Linux/macOS 可执行 `chmod 600 token.hex`。

服务器地址填写实际 IP 和端口；“证书对应域名 / IP”必须与证书中的身份匹配，不能随意改成其他 IP。凭据标识填写服务端的 `auth.id`。完成后点击“测试延迟”，成功后“应用配置”，最后开启系统代理。输入框支持 Ctrl+C / Ctrl+V，macOS 使用 Command+C / Command+V。旧安装包缺少剪贴板功能，需要升级到包含此修复的构建。

界面顶部可以随时切换 **中文 / English**，选择会保存在 `desktop.json`；旧配置无需迁移。
首页集中显示连接状态、“系统代理”“虚拟网卡”开关、节点选择、延迟、速度和代理模式；详细规则、DNS、日志和程序路径收在高级设置中。
首页和节点页选择节点的行为一致：本窗口管理的后台正在运行时自动应用切换，离线时保存供下次连接使用。
修改节点参数后点击节点页的“应用配置”；删除节点需要再次确认。操作结果固定显示在页面顶部，可手动关闭；
长错误消息在提示区内滚动，不会挤走整个页面。各页面分别记住滚动位置。
中文使用操作系统现有字体，Linux 推荐安装 Noto CJK 或 Droid 中文字体；没有新增字体下载或第三方 UI 依赖。

打开“系统代理”时，软件会启动自己管理的后台，等待节点认证可用，再把 GNOME HTTP/HTTPS
代理设置为本机 HTTP 监听地址，并读回确认。后台在线或节点可用不再等同于系统代理开启。
关闭开关恢复原设置；后台异常退出时尝试恢复，检测到其他软件改动时保留其设置并报告冲突。
如果旧版仍在托盘运行，请先从托盘退出旧版，再启动新版；新版不会接管另一个窗口的后台。

2026-11-02 实测：系统代理关闭时直连 Google 超时；手动指定 Helios HTTP 代理可返回 200。
随后通过相同 Lease 接口开启真实 GNOME 系统代理，使用全新 Chrome 测试配置，未传入
`--proxy-server`，通过浏览器调试接口确认 Google 主文档 HTTP 200、页面标题 Google；测试后
所有代理快照字段精确恢复。测试不使用日常浏览器的用户数据，不关闭浏览器证书校验。

这项测试会短暂修改当前 GNOME 代理，必须明确选择运行，且本机 8080 端口已有可用代理。
需要 `/opt/google/chrome/chrome`、Node.js（内置 WebSocket）、timeout、gsettings 和用户 D-Bus：

```sh
HELIOS_REAL_BROWSER_TEST=1 cargo test -p helios-system-proxy \
  real_browser_uses_gnome_system_proxy -- --ignored --nocapture
```

实现参考了 Clash Verge Rev 的 [Linux 系统代理适配](https://github.com/clash-verge-rev/sysproxy-rs/blob/main/src/linux.rs)
和[根据系统实际状态显示开关](https://github.com/clash-verge-rev/clash-verge-rev/blob/dev/src/hooks/use-system-proxy-state.ts)的做法；
未引入 Clash 内核。系统代理和 TUN 是不同的接管方式，不需要同时开启。

**Linux 虚拟网卡尚未完成**：现有 helper 未接入 Linux 持久恢复，界面明确禁用该开关。
这不是可用的 TUN 实现，不能把此次系统代理验收当成 TUN 验收；不应为了点亮开关绕过路由/DNS 恢复保护。

## 构建运行

```sh
cargo build --release -p helios-client -p helios-daemon -p heliosctl
./target/release/helios-client
```

开发时可使用隔离 UI 预览检查布局（不读取个人配置、不恢复代理租约、不启动后台或托盘）：

```sh
cargo run -p helios-client --example ui-preview
```

预览使用临时配置和不存在的后台路径，不能用于上网；窗口两分钟后自动关闭。

需要图形桌面、OpenGL/EGL、字体和 X11/Wayland 运行库。配置位于 `$HOME/.helios/desktop.json`；daemon 使用私有 Unix socket。客户端和 daemon 放在同一目录，或在 Settings 填 daemon 绝对路径。不要 sudo 启动 UI。

可选安装到当前用户：

```sh
sh deploy/install-linux-client.sh target/release
```

安装器默认写入 `$HOME/.local`，desktop 使用绝对路径（支持空格），无需依赖桌面会话 PATH；可用第二个参数指定绝对安装前缀。它先检查三个二进制、逐文件原子替换，不修改 `~/.helios`。请先退出客户端再升级；多文件更新不提供事务回滚。若已有配置指定旧 daemon 路径，需在 Settings 中调整。

## 便携分发包

```sh
sh deploy/package-linux-client.sh target/release target/linux-package
```

输出 `helios-linux-<架构>.tar.gz`，含三个二进制、安装脚本、说明和包内校验清单；已有同名包时拒绝覆盖。解包后先 `sha256sum -c SHA256SUMS`，再执行 `sh install-linux-client.sh .`。该包依赖构建机兼容的 glibc/图形运行库，不是跨发行版静态包；校验和不是签名，尚未提供正式签名发行。

## 系统代理与边界

首批支持 GNOME `org.gnome.system.proxy` GSettings，需要 gsettings、对应 schema、可写 dconf 和用户 D-Bus 会话。HTTP/HTTPS、bypass 和认证开关使用现有 System Proxy Lease 快照、验证和恢复；检测到外部修改时不覆盖用户设置。启动时尝试恢复遗留租约。

UI 运行期间每两秒检查自有 daemon；确认 daemon 退出且系统代理仍开启时，尝试释放代理租约。恢复失败会报错并保留租约供重试。此机制不是独立 watchdog，UI 与 daemon 同时被强杀仍需要下次启动或 `recover-network` 恢复。

系统代理只影响遵循 GNOME 配置的应用，不是透明接管所有网络。KDE、独立窗口管理器和忽略系统设置的应用可手工使用默认 `127.0.0.1:1080` SOCKS5 或 `127.0.0.1:8080` HTTP 代理。SOCKS 应选择远端解析（例如 curl `--socks5-hostname`）。

启用 Helios 时将 GNOME 模式改为 manual；关闭后恢复先前模式（包括 PAC/auto）及 HTTP 认证开关。PAC URL 和既有 SOCKS 端点不被改写，因此非 HTTP/HTTPS 应用仍可能使用既有 SOCKS；此开关不承诺接管它们。

可在同一桌面用户会话运行 `helios-daemon recover-network` 恢复 Helios 持有的系统代理租约。Linux TUN 的授权、路由租约与恢复暂未接入桌面。GNOME 适配有单元检查，真实桌面应用与崩溃恢复仍需真机验证。

## 系统托盘

Linux 使用 `ksni` 通过用户 D-Bus 提供 StatusNotifierItem，不需要 GTK/AppIndicator 开发库。托盘菜单可显示窗口、启停本窗口拥有的 daemon 和退出；仅在托盘宿主可用时关闭窗口隐藏到托盘。宿主消失时请求恢复窗口；无 D-Bus 或无宿主时保留普通窗口关闭行为。KDE 等需要启用托盘宿主，GNOME 通常需要 AppIndicator 扩展；不自动安装扩展。Wayland 下窗口显示可用，但强制聚焦可能受合成器策略限制。

隔离协议测试覆盖无宿主、注册、激活、三个菜单项的 D-Bus 点击、宿主退出及服务关闭；真实桌面托盘显示/点击仍需验收：

```sh
env HELIOS_ISOLATED_TRAY_TEST=1 dbus-run-session -- \
  cargo test -p helios-client isolated_sni_registration_activation_and_host_loss -- --ignored
```

注意：`helios-helper --recover` 在 Linux 明确返回不支持并保留状态文件；上游 Linux 路由状态目前只驻内存，不能把该命令当作强杀后的恢复工具。桌面 TUN 开关在持久恢复能力补齐前保持禁用。

## 隔离代理集成测试

已验证真实 GSettings 写入、读回校验、普通/空 bypass 的租约恢复及外部修改保护。此测试默认忽略，必须使用临时配置目录和独立 D-Bus，不要直接在日常会话运行：

Linux CI 显式安装 GSettings schema、dconf 和 D-Bus 依赖，运行此隔离测试及 desktop 文件校验；首次远端执行结果仍待确认。

```sh
task_gsettings_dir=$(mktemp -d /tmp/helios-lease-test.XXXXXX)
env XDG_CONFIG_HOME="$task_gsettings_dir" HELIOS_ISOLATED_GSETTINGS_DIR="$task_gsettings_dir" \
  dbus-run-session -- cargo test -p helios-system-proxy isolated_gsettings_lease_round_trip -- --ignored
```
