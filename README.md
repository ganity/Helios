# Helios

[![CI](https://github.com/ganity/Helios/actions/workflows/ci.yml/badge.svg)](https://github.com/ganity/Helios/actions/workflows/ci.yml)

Helios 是面向个人 VPS 和少量桌面终端的加密网络工具，提供 Windows、macOS、Linux 桌面客户端和 Linux 服务端。客户端按规则将应用流量直连、拒绝或经节点转发，支持系统代理和 TUN 虚拟网卡两种接入方式。

项目使用 Rust 开发，采用自定义的 Helios 应用层协议，通过 QUIC 或 TCP/TLS 1.3 传输；TLS 与 QUIC 分别基于 rustls 和 Quinn。桌面界面、转发进程和特权网络操作独立运行。

**当前处于持续开发和验证阶段。** Linux TUN 已接通桌面授权、运行监视与异常恢复，并通过隔离环境中的真实数据面测试；Windows/macOS TUN 的完整真机验收、正式签名发行与长期稳定性验证仍在推进。具体范围见[功能与验收清单](docs/11-feature-completion.md)。

## 功能

- **桌面客户端**：中文 / English 界面、节点管理、`helios://` 链接导入、系统托盘、QUIC/TLS 独立延迟测试。
- **流量接入**：本地 SOCKS5 TCP/UDP、HTTP CONNECT 与 HTTP 转发代理，以及独立 helper 提供的 TUN。
- **路由分流**：按规则、全局代理和直连模式；规则支持域名、域名后缀、IPv4/IPv6 CIDR、目标端口和 TCP/UDP，动作包括 Direct、Proxy、Reject。
- **双传输**：支持优先 QUIC，新连接在传输不可用时回退 TCP/TLS；也可固定使用 TLS。已有连接不会迁移传输。
- **DNS**：双栈 Fake-IP 与域名映射；Proxy 域名由服务端解析，Direct 使用本地解析或 Linux TUN 会话指定的真实上游。
- **节点切换**：运行时切换新连接使用的节点，支持可选备用节点故障转移。
- **连接与监控**：流量曲线、活动连接筛选、单连接关闭、日志筛选与脱敏诊断导出。
- **网络恢复**：系统代理与 TUN 的变更记录、恢复重试和外部修改保护；Linux TUN 另有独立 watchdog 处理 helper 被强杀的情况。

规则从上到下首次命中，示例：

```text
domain-suffix,example.cn,direct
ip-cidr,192.168.0.0/16,direct
network,udp,reject
final,proxy
```

这个示例会拒绝此前未命中的 UDP，仅用于说明语法。国内直连规则及其适用范围见[分流配置指南](docs/14-china-direct-routing.md)。

## 平台支持

| 平台 | 桌面与系统代理 | TUN | 构建产物 |
| --- | --- | --- | --- |
| Windows x64 | 桌面、托盘与系统代理已接入 | 独立提权 helper；完整授权及网络恢复仍需真机验收 | `.exe` 安装包 |
| macOS Apple Silicon / Intel | 桌面、托盘与按网络服务设置的系统代理已接入 | 独立提权 helper；完整真机验收及 NetworkExtension 方案待完善 | 分架构 `.dmg` |
| Linux x86_64 | X11/Wayland 桌面；自动系统代理支持 GNOME | 桌面开关、pkexec/polkit 授权、DNS 接管及恢复已接入 | `.deb`；可自行打包 `.tar.gz` |
| Linux 服务端 | 无图形界面，提供 CLI 与 systemd 部署脚本 | 服务端不需要 TUN | `helios-server` 二进制 |

Linux KDE 等桌面可使用手工代理或满足条件的 TUN；GNOME 托盘通常需要提供 StatusNotifierItem 宿主的扩展。Linux 包依赖兼容的 glibc 和图形运行库，具体要求见[Linux 客户端指南](docs/09-linux-client.md)。

## 安装客户端

从 [GitHub Actions](https://github.com/ganity/Helios/actions/workflows/ci.yml) 中选择成功的构建，在 **Artifacts** 下载对应平台的安装包；下载 Actions 产物通常需要登录 GitHub。

- **Windows**：解压产物后运行 `Helios-Setup-x64.exe`。
- **macOS**：选择 `arm64` 或 `x86_64` 产物，打开 DMG，将 `Helios.app` 拖入 Applications。当前打包使用 ad-hoc 签名，尚未提供 Developer ID 签名和公证。
- **Debian / Ubuntu**：解压产物，在安装包所在目录执行：

  ```sh
  sudo apt install ./helios_amd64.deb
  ```

Debian 包包含 Linux TUN 所需的固定 helper、polkit 授权策略和开机恢复服务。桌面客户端以普通用户运行，开启 TUN 时再请求管理员授权。

升级前先在旧客户端关闭网络接管并退出；客户端、daemon、helper 和 CLI 使用同一构建中的配套版本。用户配置默认保存在 `~/.helios/`，安装器不附带节点凭据。

### 首次连接

1. 部署下文的 Helios 服务端，生成节点链接。
2. 打开客户端，在节点导入窗口粘贴 `helios://` 链接；证书与凭据会写入当前用户的本地文件。
3. 选择节点并测试延迟，确认认证和至少一种传输可用，再应用或切换节点。
4. 在首页按需开启“系统代理”或“虚拟网卡”。遵循系统代理设置的应用可先使用系统代理；需要接管其他应用流量时使用 TUN，无需同时开启两种模式。
5. 在高级设置中调整规则、DNS、连接监控和日志。

也可手动填写节点的 IP:端口、证书对应名称、受信证书文件、凭据 ID 和 token 文件。文件路径应指向**客户端电脑上的文件**；证书对应名称必须匹配证书身份。详细步骤见[首次配置节点](docs/09-linux-client.md#首次配置节点)。

`helios://` 链接包含认证 token，应按密码保管。手动传输文件时，只向客户端提供证书与 token，服务端私钥 `key.pem` 留在服务端。

### Linux TUN 使用条件

Linux TUN 支持不受管理的静态 `/etc/resolv.conf`，或使用标准 stub 的 systemd-resolved；已有搜索域、路由域等冲突配置时会拒绝启用。NetworkManager 使用兼容的 resolved stub 时可走 resolved 后端，直接管理 resolver 文件的模式暂不支持。

当前每个地址族使用一个物理出口，不承诺与其他 VPN、VRF 或自定义策略路由共存。检测到网络或 DNS 状态变化时会停止接管并尝试恢复；切网后重新开启即可重新获取出口。恢复遇到外部修改时保留记录并报告冲突。

源码或便携包安装需要先安装一次系统组件。源码目录中执行：

```sh
sudo sh deploy/install-linux-tun.sh target/release
```

便携包解压后执行 `sudo sh install-linux-tun.sh .`。运行这些命令前需准备好配套二进制；构建方法见下文。支持条件、恢复机制和隔离测试见 [Linux TUN 文档](docs/15-linux-tun-implementation.md)。

## 部署 Linux 服务端

以下步骤适用于使用 systemd 的 Linux 主机，在仓库根目录执行；需要 Rust 工具链，以及可供客户端访问的 TCP 和 UDP 端口。默认端口均为 **443**，需在主机防火墙及云安全组放行。

### 1. 构建并生成节点身份

```sh
cargo build --release --locked -p helios-server
./target/release/helios-server identity generate --output helios-identity
```

身份目录包含 `cert.pem`、`key.pem` 和 `server-name.txt`。生成的 `node-….helios.invalid` 名称只用于 TLS 身份校验，不需要配置 DNS；实际连接地址使用 VPS 的公网 IP。每个节点应使用独立私钥。

### 2. 安装并启动服务

```sh
sudo sh deploy/install-server.sh \
  target/release/helios-server \
  helios-identity/cert.pem \
  helios-identity/key.pem
```

脚本创建专用 `helios` 用户，安装 systemd 服务、证书和私钥，并生成随机 token。配置位于 `/etc/helios/server.toml`；重复安装保留已有配置和 token。服务以普通用户运行，通过受限 capability 绑定低端口。

默认同时监听 IPv4 和 IPv6；主机禁用 IPv6 时，移除配置中的 `listen_ipv6` 后重新启动服务。配置检查与运行状态：

```sh
sudo -u helios /usr/local/bin/helios-server check --config /etc/helios/server.toml
sudo systemctl status helios-server
sudo journalctl -u helios-server -n 50 --no-pager
```

### 3. 生成客户端导入链接

将示例地址 `203.0.113.10:443` 替换为 VPS 的实际公网 IP 和端口；IPv6 地址使用 `[地址]:端口` 格式。

```sh
sudo /usr/local/bin/helios-server client-link \
  --config /etc/helios/server.toml \
  --address 203.0.113.10:443 \
  --server-name "$(cat helios-identity/server-name.txt)" \
  --name "My VPS"
```

命令验证证书身份后输出包含连接信息、受信证书和 token 的链接，将其通过安全通道导入客户端。不要把链接粘贴到公开 issue、日志或截图中。

已有证书也可直接用于安装；生成链接时使用该证书实际包含的名称。更多配置和运维命令见[配置模型](docs/05-configuration.md)、[安全与部署](docs/06-security-operations.md)，Alpine/OpenRC 可参考[配置示例](config/server.alpine.example.toml)与 [OpenRC 服务脚本](deploy/helios-server.openrc)。

## 从源码构建客户端

仓库通过 [`rust-toolchain.toml`](rust-toolchain.toml) 固定 Rust **1.95.0**。安装 rustup 后，在目标平台构建；Windows 需要相应的 C/C++ 构建工具，macOS 需要 Xcode Command Line Tools，Linux 需要图形运行库。

```sh
git clone https://github.com/ganity/Helios.git
cd Helios
cargo build --release --locked \
  -p helios-client -p helios-daemon -p helios-helper -p heliosctl
```

Linux/macOS 使用 `./target/release/helios-client` 启动；Windows 使用 `target\release\helios-client.exe`。程序应保留在同一目录；macOS 正常使用建议先构建 App 包。

Linux 可安装到当前用户目录，默认前缀为 `~/.local`：

```sh
sh deploy/install-linux-client.sh target/release
```

打包脚本：

| 目标 | 命令 |
| --- | --- |
| Linux Debian 包 | `sh deploy/package-linux-deb.sh target/release target/installers` |
| Linux 便携包 | `sh deploy/package-linux-client.sh target/release target/installers` |
| macOS DMG | `sh deploy/package-macos-app.sh target/release target/installers 0.1.0` |
| Windows 安装包 | 使用 Inno Setup 编译 `deploy/helios-windows.iss`，完整步骤见 CI |

## 项目结构与开发检查

| 组件 | 职责 |
| --- | --- |
| `apps/helios-client` | egui 桌面界面、托盘与用户操作 |
| `apps/helios-daemon` | 本地代理入口、路由、节点连接与监控 |
| `apps/helios-helper` | 需要系统授权的 TUN、路由与 DNS 操作 |
| `apps/helios-server` | Linux 节点认证、TCP/UDP 转发 |
| `apps/heliosctl` | 本地控制 CLI |
| `crates/` | 协议、传输、配置、DNS、路由和系统代理等共享模块 |
| `vendor/` | 包含本项目补丁的 TUN 与路由依赖 |

常规开发检查：

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Linux CI 还会在一次性 Docker 网络命名空间中检查真实 TUN、双栈 TCP/UDP、systemd-resolved、pkexec/polkit 及正常退出和强杀恢复。需要自行运行时，依赖和命令见 [Linux TUN 验证说明](docs/15-linux-tun-implementation.md#验证)。普通 `cargo test` 不会执行这些需显式启用的隔离测试。

## 当前边界

Helios 专注个人节点与桌面客户端，当前没有多用户计费、订阅市场、Web 管理面板或移动客户端。公网链路使用 Helios 自定义协议；本地 SOCKS5/HTTP 接口供应用接入，客户端不能直接连接其他代理协议的节点。

原生凭据库、SPKI pin、正式签名与更新验证、macOS NetworkExtension 以及长期压力验收尚未完成。配置中的 token 目前保存在权限受限的文件里。QUIC/TLS 加密和控制帧填充不构成“协议不可识别”的保证。

## 文档

- **使用与配置**：[Linux 客户端](docs/09-linux-client.md) · [配置参考](docs/05-configuration.md) · [国内直连规则](docs/14-china-direct-routing.md) · [服务端部署与运维](docs/06-security-operations.md)
- **网络实现**：[Linux TUN](docs/15-linux-tun-implementation.md) · [路由、DNS 与 TUN](docs/04-routing-dns-tun.md) · [协议](docs/02-protocol.md)
- **架构与开发**：[总体架构](docs/01-architecture.md) · [客户端与 IPC](docs/03-client.md) · [术语](CONTEXT.md) · [架构决策](docs/adr/)
- **进度与验证**：[功能与验收清单](docs/11-feature-completion.md) · [实施记录](docs/00-implementation-status.md) · [测试路线](docs/07-testing-roadmap.md)

部分架构与安全文档同时记录了目标设计；判断功能是否已交付时，请结合实现记录和对应验证范围。
