# 国内直连、其余代理：本机规则审计与配置

核查日期：2026-11-04。只读取本机 Clash Party 和 Helios 代码；未改变运行中的代理、DNS、节点或桌面配置。

## 1. 推荐的实际策略

使用「按规则」模式，按以下顺序首次命中生效：

| 目标 | 动作 | 理由 |
| --- | --- | --- |
| 明确需要代理的例外，如 X、Google、YouTube、GitHub、OpenAI | 代理 | 优先于国内列表，避免 Google.cn 等被宽规则直连 |
| 局域网域名、路由器、回环和私网地址 | 直连 | NAS、打印机、本机和内网服务不应绕海外 |
| 国内域名白名单，包括国内服务的 `.com` 和 CDN | 直连 | 只写 `.cn` 不够 |
| 应用提供的数字目标 IP：大陆 IPv4 / IPv6 | 直连 | 适用于请求里没有域名的情形 |
| 其他数字公网 IP、未知域名 | 代理 | 保留海外服务可用性，避免未知域名为分类而先在本地解析 |

这里的“国内域名”是适合国内直连的维护名单，不是对服务器实际地理位置的保证。静态规则不能保证零漏收或永远正确；漏收的国内网站会走代理，可以增加域名例外。

不要把所有数字 IP 都设为直连：国外视频/CDN 也可能以 IP 为目标。也不要把国内 IP 段填入操作系统的「代理绕过列表」来代替 Helios 路由；不同系统/浏览器的绕过语义不同，应由 Helios 统一决定。

## 2. 本机 Clash Party 实际配置

读取 `~/.config/mihomo-party/work/config.yaml`，只提取规则和规则集元数据：

- 共 20 条顶层规则、18 个内嵌规则集。
- 有国外域名名单、YouTube / Google / Telegram / 游戏等服务分类、私有域名及私有 IP、大陆 IP 名单，最后走兜底组。
- 大陆 IP 集共 9,651 个 CIDR：6,223 个 IPv4、3,428 个 IPv6。
- 没有完整的国内域名规则集；当前模板主要依靠国外域名名单与大陆 IP 兜底。
- 直连组与兜底组是可选策略组；仅凭静态 YAML，不能断言运行中最终选择的是哪一个节点或 DIRECT。

没有复制订阅地址、节点凭据、订阅 API 的专用直连规则，也没有照搬游戏、Apple、Microsoft 等可选策略组。它们与“国内直连、海外代理”的目标不完全相同。

### 为什么不能直接复制 Clash YAML

Helios 目前接受 `domain`、`domain-suffix`、`ip-cidr`、`ip-cidr6` 等具体规则，不接受 `GEOSITE`、`GEOIP`、`RULE-SET` 和 Clash 策略组。必须展开规则数据，并把动作映射为 `direct` / `proxy`。

另一个关键区别：[Mihomo 的 IP 规则可能触发域名解析](https://wiki.metacubex.one/config/rules/)，`no-resolve` 可以限制主动解析。Helios 的 CIDR 规则仅匹配 `Address::Ip`，不会为了判断地域去解析域名。因此，一个未入名单的国内 `.com` 域名，在这里仍走代理，即使它解析到大陆 IP。这是有意保留的当前语义。

## 3. 已生成的两个配置

| 文件 | 内容 | 当前使用条件 |
| --- | --- | --- |
| [china-direct.rules](../config/china-direct.rules) | 334 条；163 条国内域名后缀，另有代理例外、私有域名/地址、6 个常见国内 DNS IP | 推荐先使用；能通过现有热更新接口 |
| [china-direct-full.rules](../config/china-direct-full.rules) | 119,261 条；109,445 条国内域名后缀及全部 9,651 个大陆 CIDR | 更符合完整需求；只能离线保存后启动，暂不推荐直接在运行中粘贴应用 |

精简版包含腾讯、阿里、百度、京东、哔哩哔哩、抖音、小红书、网易、美团等常用服务及 CDN；`.cn`、`.中国`（Punycode）也直连。它**不是完整的国内域名/IP 库**：未收录的国内域名和大多数国内数字公网 IP 仍走代理。不要将其当作全部国内 IP 均直连的实现。

完整版在精简版的策略顺序上补齐公开国内域名库和本机大陆 IP 库。国内域名来源选择 [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list) 的 `accelerated-domains.china.conf`；仅提取域名，不导入文件中的 DNS 服务器设置。没有合并其独立 Google / Apple 加速名单。移除了 `.top`、`.wang`、`.公司`、`.网络` 等过宽的顶级域直连规则，保留 `.cn` 和 `.中国`；去掉被父后缀覆盖的冗余项。

### 在客户端使用精简版

1. 保留原规则备份，打开「高级设置 → 路由规则」。
2. 选择「按规则」，将 `china-direct.rules` 全文复制到规则编辑框，替换原规则并保存/应用。
3. 首页保持「按规则」，打开系统代理或虚拟网卡中需要的一种模式。
4. 用规则测试器检查 `www.baidu.com`、`video.twimg.com`、`192.168.1.1`、`8.8.8.8`，预期依次为直连、代理、直连、代理。浏览器重新建立连接后使用新规则；已有连接不会被迁移。

自定义规则加在最终 `final,proxy` 前；需要覆盖现有白名单的代理例外应放在白名单之前。不要同时在 Clash 与 Helios 打开系统代理。

### 完整版的当前限制

控制接口 `MAX_CONTROL_MESSAGE` 为 65,536 字节。精简版实际 `UpdateRules` JSON 为 22,497 字节；完整版为 7,806,712 字节，运行中热更新会被拒绝，涉及完整规则的其他控制请求也有相同限制。

代码允许后台停止时保存桌面配置与 daemon 配置，再从磁盘启动加载大规则库；但本次没有在桌面 UI 中试贴约 4 MB 文本，不保证编辑体验。不要在后台运行中尝试完整版，也不要以“文件已保存”当作热更新成功。需要把完整版作为默认体验时，应先完善规则文件加载/控制传输与大列表编辑体验，而非仅调大一个消息上限。

路由引擎仍是按序线性匹配。本次本机 release 单线程微测试中，未知目标的首次决策：精简版约 2 微秒，完整版约 800 微秒；这是每条新流的匹配开销，不是每个视频数据包都遍历，亦不是网页吞吐或 macOS 性能测试。后续适合增加保持顺序语义的域名/CIDR 索引。

## 4. 数据快照与验证

- 域名原文件：`https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf`。
- 获取时 4,011,515 字节；SHA-256：`3780aa1aa97dffae010998ce0f320351c4646a4bd4a66327f6f99393f1ae7e22`。
- 大陆 CIDR：本机 Clash Party 的内嵌 `geoip-cn.payload`；逐项以换行连接、不加末尾换行后的 SHA-256：`2bc01bbaf32f235597d0edf035466735bc4867b9b65ad75b034779368ddf53a4`。这只是本机快照，不声称它是最新全国分配数据。
- 域名来源版权：Copyright © 2015 Felix Yan <felixonmars@archlinux.org>；按上游 WTFPL Version 2 使用与再分发，见[上游许可](https://github.com/felixonmars/dnsmasq-china-list/blob/master/LICENSE)。私有域名与大陆 IP 来源为本机 Clash Party 规则数据，保留其精确域名/后缀区别，不含节点信息。

用当前仓库实际 `parse_rules`、`render_rules`、`RuleSet` 与 `ControlRequest` 做了离线验证：两个文件均可解析、往返序列化一致；国内域名、海外视频域名、域名后缀边界、私网 IPv4/IPv6、国内公网 IP、海外公网 IP 和 Fake-IP 保留地址的 89 项决策断言通过。未知地址 `198.18.0.1` 不被当成局域网直连；实际 Fake-IP 流应先恢复域名再决策。

没有验证真实浏览器请求的完整覆盖率、macOS/TUN 下是否始终保留域名，或所有名单条目的现实可达性。系统代理也无法接管不遵守系统代理的应用。名单是静态快照，不会自动更新；后续更新需要重新验证再替换。

公开来源的更多比较见 [规则来源研究](research-routing-sources.md)。
