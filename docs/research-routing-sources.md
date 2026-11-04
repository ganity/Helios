# 国内直连规则来源与转换研究

核查日期：2026-11-04。本文只研究公开规则语义和数据源；本机 Clash Party 的实际启用配置需另行核查。

## 推荐策略

按顺序配置：用户明确指定的代理/直连例外 → 局域网域名与地址直连 → 国内域名白名单直连 → 中国大陆数字 IP 直连 → `FINAL,PROXY`。

“国内域名”应理解为维护列表认定适合在国内直连的域名，不等于仅以 `.cn` 结尾，也不意味着所有境内企业的海外服务都适合直连。未知域名默认代理，让代理服务端解析，不为判定地域而预先在本地解析。纯 IP 请求中，私网和中国大陆 IP 直连，其余代理；不要把所有 IP 一律直连。

这是一项面向可用性的选择：名单漏收的国内域名暂时走代理，可以加例外；误收的海外域名则可能直连失败。没有静态列表能保证所有目标地理位置和可达性永远正确。

## Mihomo 和 Helios 的差异

[Mihomo 官方路由文档](https://wiki.metacubex.one/config/rules/)规定规则从上到下匹配；`GEOSITE` 查询域名集合，`GEOIP` 查询地址国家代码，`MATCH` 是兜底。目标 IP 规则默认可能触发域名 DNS 解析，`no-resolve` 禁止这次主动解析，但不排除使用此前已取得的 IP。

本仓库 `crates/helios-routing/src/lib.rs` 当前仅支持 `DOMAIN`、`DOMAIN-SUFFIX`、IPv4/IPv6 CIDR、端口、网络类型和 `FINAL`。CIDR 规则只匹配 `Address::Ip`，不会解析 `Address::Domain`。因此将 CN CIDR 转为 Helios 规则后，其含义是“数字目标中的 CN IP 直连”，并非 Mihomo 默认 `GEOIP,CN,DIRECT` 对所有域名再查 IP 的行为。

| 上游格式 | 可转换方式 |
| --- | --- |
| 完整域名 | `domain,<域名>,direct` |
| `+.example.com` 或明确的域名后缀 | `domain-suffix,example.com,direct` |
| IPv4 / IPv6 CIDR | `ip-cidr` / `ip-cidr6`，动作 `direct` |
| `MATCH,PROXY` | `final,proxy` |
| GEOSITE / GEOIP / RULE-SET | 先读取和展开具体文本数据，不能直接粘贴 |
| 正则、关键字、通配符、进程、逻辑规则 | 当前不可等价转换；不能静默当成后缀 |

## 数据源选择

- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 提供与 Mihomo 生态接近的公开规则。其 [README](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/master/README.md)明确 `geosite:cn` 使用 ChinaMax_Domain；[cn 域名文本](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.list)可展开为精确/后缀匹配，[CN IP 文本](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.list)可展开为 CIDR。核查时域名文本约 11 万行，包含 `+.ms` 等较宽泛顶级域；适合兼容现有配置时使用，但不应宣称它严格等价于域名服务器位于大陆。
- [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)提供每日构建的 [direct.txt](https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt)。它还包含 Apple、Google 等适合国内直连的特定服务，不等于仅中国企业域名；导入时需保留精确和后缀条目的不同语义。
- [felixonmars/dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)的 `accelerated-domains.china.conf` 是另一种域名基础名单。其 [README](https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/README.md)以国内 NS 或国内 DNS 可得到大陆 CDN 等条件收录；`google.china.conf` 明确提示稳定性风险，Apple 也有部分运营商例外。因此不要把独立 Google/Apple 列表全部合并成默认直连。
- [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip)提供每日更新的大陆运营商 [IPv4 文本](https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt)和 [IPv6 文本](https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt)，便于转换成 Helios CIDR。
- [17mon/china_ip_list](https://github.com/17mon/china_ip_list)也是常用来源，但 [说明](https://raw.githubusercontent.com/17mon/china_ip_list/master/README.md)声明通常季度更新、范围可能模糊化，以及 CC-BY-NC-SA 4.0 授权；公开再分发应保留相应来源与许可说明。

优先复用本机已启用且符合需求的规则来源；如果它只是通用机场模板，应改成上述直连白名单与代理兜底，而不是照搬分组、广告拦截、游戏加速等无关规则。更新应记录上游版本与校验值，验证全部条目后原子替换，失败保留旧版本。规则列表是数据依赖，仍需审查来源及许可。

## 验证边界

规则测试至少覆盖国内 `.com`、`.cn`、海外域名及图片/视频子域、CN 公网 IP、海外公网 IP、私网 IPv4/IPv6，以及“域名未知但解析 IP 在大陆”的差异。系统代理只处理遵守系统代理的应用；应用自行直连、缓存 IP、DoH 和未保留域名上下文的 TUN 流量，无法靠域名规则保证全部分流。

未修改任何运行中配置，也未保证上游名单所有条目完全正确。
