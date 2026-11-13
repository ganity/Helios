use std::sync::atomic::{AtomicBool, Ordering};

use helios_client_model::Language;

static ENGLISH: AtomicBool = AtomicBool::new(false);

pub fn set_language(language: Language) {
    ENGLISH.store(language == Language::English, Ordering::Relaxed);
}

pub fn t(source: &str) -> &str {
    translate(source, ENGLISH.load(Ordering::Relaxed))
}

fn translate(source: &str, english: bool) -> &str {
    for &(zh, en) in TEXT {
        if source == zh || source == en {
            return if english { en } else { zh };
        }
    }
    source
}

pub fn message(source: &str) -> String {
    translate_message(source, ENGLISH.load(Ordering::Relaxed))
}

fn translate_message(source: &str, english: bool) -> String {
    for &(zh, en) in TEXT {
        for pattern in [zh, en] {
            if let Some((prefix, suffix)) = pattern.split_once("{error}")
                && let Some(detail) = source
                    .strip_prefix(prefix)
                    .and_then(|s| s.strip_suffix(suffix))
            {
                let template = if english { en } else { zh };
                return template.replace("{error}", detail);
            }
        }
    }
    translate(source, english).to_owned()
}

const TEXT: &[(&str, &str)] = &[
    ("后台测试", "Test with daemon"),
    (
        "需要启动后台并点击后台测试",
        "Start the daemon and run a runtime test",
    ),
    ("解析地址", "Resolved addresses"),
    ("规则匹配地址", "Addresses matching the rule"),
    (
        "DNS 解析失败，已继续匹配后续规则",
        "DNS failed; evaluation continued with later rules",
    ),
    ("清理 DNS 缓存", "Clear DNS cache"),
    (
        "已清理真实 DNS 缓存及过期映射，保留有效 Fake-IP 映射",
        "Real DNS cache and expired mappings cleared; active Fake-IP mappings preserved",
    ),
    (
        "节点故障时自动切换备用节点",
        "Switch to a backup node when the current node fails",
    ),
    ("有效映射", "Active mappings"),
    ("命中", "Hits"),
    ("未命中", "Misses"),
    ("已过期", "Expired"),
    ("清理过期记录", "Prune expired entries"),
    (
        "已清理过期 DNS 记录，保留有效映射",
        "Expired DNS entries pruned; active mappings preserved",
    ),
    ("DNS 清理失败：{error}", "DNS cache pruning failed: {error}"),
    (
        "请先关闭虚拟网卡",
        "Turn off the virtual network adapter first",
    ),
    (
        "正在应用配置，请稍候",
        "Applying configuration, please wait",
    ),
    (
        "配置未生效，原节点继续运行：{error}",
        "Configuration was not applied; the previous node is still active: {error}",
    ),
    (
        "配置已生效，但保存失败：{error}",
        "Configuration applied, but saving failed: {error}",
    ),
    (
        "Helios 已在运行，请从托盘打开",
        "Helios is already running; open it from the tray",
    ),
    ("本次后台累计", "Daemon session totals"),
    ("UDP 丢包", "UDP drops"),
    ("筛选连接", "Filter connections"),
    ("筛选日志", "Filter logs"),
    ("全部级别", "All levels"),
    ("关闭连接", "Close connection"),
    ("已请求关闭连接", "Connection close requested"),
    (
        "关闭连接失败：{error}",
        "Could not close connection: {error}",
    ),
    ("导出诊断", "Export diagnostics"),
    ("诊断已导出：", "Diagnostics exported:"),
    (
        "导出诊断失败：{error}",
        "Could not export diagnostics: {error}",
    ),
    (
        "流量趋势 · 上传 / 下载",
        "Traffic trend · upload / download",
    ),
    ("流量趋势", "Traffic trend"),
    ("最近 60 秒", "Last 60 seconds"),
    ("累计下载", "Downloaded"),
    ("累计上传", "Uploaded"),
    ("握手", "Handshake"),
    ("测试于", "Tested"),
    ("秒前", "seconds ago"),
    (
        "正在检查后台，请稍候",
        "Checking the background service, please wait",
    ),
    ("Helios · 曜光", "Helios"),
    ("高级设置", "Advanced"),
    ("关闭提示", "Dismiss"),
    ("确认删除此节点？", "Remove this node?"),
    ("确认删除", "Confirm removal"),
    ("连接", "Connect"),
    ("连接概览", "Overview"),
    ("节点", "Nodes"),
    ("诊断", "Diagnostics"),
    ("设置", "Settings"),
    ("工作空间", "Workspace"),
    ("网络配置", "Network"),
    ("运行与诊断", "Runtime & diagnostics"),
    ("曜光 · 自由连接", "Free connection"),
    ("后台服务运行中", "Background service running"),
    ("后台服务未运行", "Background service stopped"),
    ("分流规则", "Routing rules"),
    ("连接记录", "Connections"),
    ("日志", "Logs"),
    ("未连接", "Disconnected"),
    ("已连接", "Connected"),
    ("连接中", "Connecting"),
    ("节点暂不可用", "Node unavailable"),
    ("系统代理已开启", "System proxy enabled"),
    ("系统代理未开启", "System proxy disabled"),
    ("状态未知", "Status unknown"),
    (
        "配置更新失败或超时，请刷新状态确认",
        "Configuration update failed or timed out; refresh status to confirm",
    ),
    (
        "无法确认当前连接状态",
        "Cannot verify the current connection status",
    ),
    (
        "状态刷新失败，显示上次结果",
        "Status refresh failed; showing last result",
    ),
    ("正在连接节点", "Connecting to node"),
    ("断开连接", "Disconnect"),
    ("开始连接", "Connect"),
    ("已断开连接", "Disconnected"),
    ("取消连接", "Cancel"),
    ("当前节点", "Current node"),
    ("切换节点 ›", "Switch node ›"),
    ("测延迟", "Test latency"),
    ("延迟", "Latency"),
    ("上传速度", "Upload"),
    ("下载速度", "Download"),
    ("节点可用", "Node available"),
    ("节点未连接", "Node disconnected"),
    ("按规则分流", "Rule mode"),
    ("流量路由", "Traffic routing"),
    ("配置分流规则 ›", "Configure rules ›"),
    (
        "匹配直连规则的流量直连，其余流量经过代理。",
        "Matching traffic connects directly; all other traffic uses the proxy.",
    ),
    (
        "所有流量都经过当前代理节点。",
        "All traffic uses the current proxy node.",
    ),
    (
        "所有流量直接连接，不经过代理节点。",
        "All traffic connects directly.",
    ),
    ("全部代理", "Global proxy"),
    ("全部直连", "Direct"),
    ("系统代理", "System proxy"),
    ("浏览器与支持代理的应用", "Browsers and proxy-aware apps"),
    ("虚拟网卡 TUN", "Virtual adapter TUN"),
    ("接管更多应用的流量", "Capture traffic from more apps"),
    ("虚拟网卡", "Virtual adapter"),
    ("虚拟网卡已开启", "Virtual adapter enabled"),
    ("个连接", "connections"),
    ("开启系统代理", "Enable system proxy"),
    ("启用虚拟网卡", "Enable TUN"),
    ("已开启", "On"),
    ("已关闭", "Off"),
    ("正在开启", "Enabling"),
    ("Linux 暂未开放", "Not available on Linux yet"),
    (
        "当前为全部直连模式，网页不会经过代理",
        "Direct mode is active; web traffic will not use the proxy",
    ),
    ("我的节点", "My nodes"),
    ("搜索节点名称或地址", "Search by node name or address"),
    ("切换", "Switch"),
    ("编辑", "Edit"),
    (
        "当前节点请先切换后再删除",
        "Switch away before removing the current node",
    ),
    ("测试详情", "Test details"),
    ("证书与凭据", "Certificate and credentials"),
    (
        "证书与凭据已包含在链接中",
        "Certificate and credentials are included in the link",
    ),
    (
        "先保存节点，需要时再连接。",
        "Save the node first, then connect when needed.",
    ),
    ("IPv6 地址格式：[IPv6]:端口", "IPv6 format: [IPv6]:port"),
    ("保存并连接", "Save and connect"),
    ("仅保存", "Save only"),
    (
        "节点已保存，运行中的连接未更改",
        "Node saved; the running connection was not changed",
    ),
    ("取消", "Cancel"),
    (
        "每行一条规则，按顺序匹配，末尾需要最终规则。",
        "One rule per line; first match wins; a final rule is required.",
    ),
    (
        "本地监听、后台服务与平台能力。",
        "Local listeners, background service, and platform capabilities.",
    ),
    (
        "监听、路径与网络参数都可以直接编辑。",
        "Listeners, paths, and network parameters are directly editable.",
    ),
    ("常规", "General"),
    (
        "缩短连接等待时间；系统代理仍需手动开启。",
        "Reduce connection startup time; system proxy remains manual.",
    ),
    ("界面语言", "Interface language"),
    (
        "可随时切换，设置会自动保存。",
        "Switch at any time; this setting saves automatically.",
    ),
    ("网络", "Network"),
    (
        "虚拟网卡开启时，同时接管 IPv6 流量。",
        "Capture IPv6 traffic when TUN is enabled.",
    ),
    ("本地监听", "Local listeners"),
    (
        "只允许本机回环地址；IPv6 使用 [::1]:端口。",
        "Loopback addresses only; use [::1]:port for IPv6.",
    ),
    ("后台与虚拟网卡程序", "Background service and TUN programs"),
    ("代理绕过与传输参数", "Proxy bypass and transport"),
    ("平台控制", "Platform controls"),
    (
        "保存设置不会自动切换当前节点。",
        "Saving settings does not switch the current node.",
    ),
    (
        "保留域名分流，避免本地解析污染。",
        "Preserve domain routing without local resolver pollution.",
    ),
    (
        "一条链接，就能开始连接。",
        "One link is all you need to connect.",
    ),
    ("节点链接", "Node link"),
    (
        "粘贴 helios:// 链接，证书和凭据会自动导入。",
        "Paste a helios:// link to import its certificate and credentials.",
    ),
    ("手动添加节点", "Add manually"),
    ("连接链接", "Connection link"),
    ("解析并添加", "Import link"),
    (
        "连接链接已导入，点击“应用配置”生效",
        "Connection link imported; apply configuration to use it",
    ),
    (
        "节点链接已导入；选择“切换”后使用",
        "Node imported; select Switch when you want to use it",
    ),
    ("测试全部", "Test all"),
    ("添加节点", "Add node"),
    ("删除", "Remove"),
    ("编辑节点配置", "Edit node"),
    (
        "首次使用：从服务端安全复制证书 cert.pem 和凭据 token.hex 到本机，再填写两个文件的完整路径。不要复制服务端私钥 key.pem。所有输入框支持系统复制 / 粘贴快捷键。",
        "First use: securely copy cert.pem and token.hex from your server to this computer, then enter their full local paths. Never copy the server private key key.pem. All fields support system copy/paste shortcuts.",
    ),
    (
        "填写本机 .pem 文件的完整路径，不是证书内容；证书对应域名 / IP 必须与证书匹配。",
        "Enter the full local .pem file path, not its contents. The TLS server name / IP must match the certificate.",
    ),
    (
        "填写本机 token.hex 的完整路径，不是 token 内容；凭据标识须与服务端 auth.id 一致。完成后测试延迟，再点击应用配置。",
        "Enter the full local token.hex file path, not the token itself. Credential ID must match the server auth.id. Test latency, then apply configuration.",
    ),
    ("节点名称", "Node name"),
    ("服务器地址", "Server address"),
    ("证书对应域名 / IP", "TLS server name"),
    ("受信证书文件", "CA certificate"),
    ("凭据标识", "Credential ID"),
    ("凭据文件", "Token file"),
    ("传输方式", "Transport"),
    ("测试中…", "Testing…"),
    ("测试失败", "Test failed"),
    ("测试延迟", "Test latency"),
    ("应用配置", "Apply configuration"),
    ("导入 / 导出", "Import / export"),
    ("节点 JSON", "Node JSON"),
    (
        "不包含证书和凭据内容",
        "Certificate and token contents are not included",
    ),
    ("导出节点", "Export node"),
    ("导入节点", "Import node"),
    ("节点已导入", "Node imported"),
    (
        "已选择节点，点击“应用配置”生效",
        "Node selected; apply configuration to switch",
    ),
    (
        "已选择节点，连接时生效",
        "Node selected; it will be used on connection",
    ),
    ("代理模式", "Proxy mode"),
    ("按规则", "Rules"),
    ("规则", "Rules"),
    ("保存并应用", "Save and apply"),
    ("测试规则", "Test rule"),
    ("目标地址", "Target"),
    ("域名或 IP", "Domain or IP"),
    ("端口", "Port"),
    ("后台程序路径", "Daemon executable"),
    ("后台配置文件", "Daemon configuration"),
    (
        "打开软件时预启动后台（不自动开启系统代理）",
        "Pre-start daemon on launch (system proxy stays off)",
    ),
    ("虚拟网卡辅助程序", "TUN helper executable"),
    ("虚拟网卡配置文件", "TUN configuration"),
    ("TUN 接管 IPv6", "Route IPv6 through TUN"),
    ("SOCKS5 监听地址", "SOCKS5 listen address"),
    ("HTTP 监听地址", "HTTP listen address"),
    ("本地控制地址", "Control address"),
    ("运行日志", "Daemon log"),
    ("打开目录", "Open folder"),
    ("UDP 空闲超时（秒）", "UDP idle timeout (seconds)"),
    ("不使用系统代理的地址", "System proxy bypass"),
    ("每行一个域名、IP 或网段", "One domain, IP or CIDR per line"),
    ("保存设置", "Save settings"),
    ("DNS 设置", "DNS settings"),
    ("启用", "Enabled"),
    ("DNS 监听地址", "DNS listen address"),
    ("域名缓存数量", "Cached domains"),
    ("缓存有效期（秒）", "Cache TTL (seconds)"),
    (
        "应用内置的加密 DNS 可能绕过此设置",
        "Built-in encrypted DNS may bypass this setting",
    ),
    ("保存 DNS 设置", "Save DNS settings"),
    (
        "DNS 配置已保存，请应用配置生效",
        "DNS saved; apply configuration to activate",
    ),
    ("当前连接", "Active connections"),
    ("后台未运行", "Daemon is offline"),
    ("仅显示前 256 个连接", "Showing the first 256 connections"),
    ("暂无连接", "No active connections"),
    ("刷新", "Refresh"),
    ("暂无日志", "No events yet"),
    ("此平台不支持", "Not supported on this platform"),
    ("显示 Helios", "Show Helios"),
    ("连接 / 断开", "Connect / disconnect"),
    ("退出 Helios", "Quit Helios"),
    ("未测试", "Not tested"),
    ("失败：{error}", "Failed: {error}"),
    ("系统托盘不可用：{error}", "Tray unavailable: {error}"),
    (
        "已检测到另一个正在运行的 Helios",
        "Another Helios instance is running",
    ),
    (
        "控制端口被占用，且身份校验未通过",
        "Control endpoint is occupied and authentication failed",
    ),
    (
        "后台启动检查失败：{error}",
        "Daemon startup check failed: {error}",
    ),
    ("节点测试成功", "Node test succeeded"),
    ("节点测试失败：{error}", "Node test failed: {error}"),
    ("分流规则已保存并生效", "Routing rules saved and applied"),
    (
        "规则已保存，但应用失败：{error}",
        "Rules saved but apply failed: {error}",
    ),
    (
        "后台已退出，系统代理已恢复",
        "Daemon exited; system proxy restored",
    ),
    (
        "无法检查后台进程：{error}",
        "Could not check daemon: {error}",
    ),
    ("控制地址无效", "Invalid control address"),
    ("配置已保存", "Configuration saved"),
    ("后台已启动", "Daemon started"),
    ("正在启动后台，请稍候", "Starting daemon, please wait"),
    (
        "后台未能就绪，请查看诊断日志",
        "Daemon did not become ready; check diagnostic logs",
    ),
    (
        "请先从托盘退出另一个 Helios 窗口，再点击连接",
        "Quit the other Helios instance from the tray, then connect",
    ),
    (
        "连接超时，请检查节点地址、网络或在高级设置中查看日志",
        "Connection timed out; check the node, network or logs",
    ),
    (
        "无法重启其他窗口启动的后台，请先退出另一个 Helios",
        "Cannot restart another instance's daemon; quit the other Helios first",
    ),
    ("停止后台失败：{error}", "Failed to stop daemon: {error}"),
    ("配置已应用", "Configuration applied"),
    ("无法打开日志：{error}", "Cannot open log: {error}"),
    ("启动后台失败：{error}", "Failed to start daemon: {error}"),
    (
        "正在关闭虚拟网卡，请等待关闭后再停止后台",
        "Wait for TUN to stop before stopping the daemon",
    ),
    (
        "此后台不是当前窗口启动的",
        "This window does not own the daemon",
    ),
    (
        "后台关闭超时，已停止",
        "Daemon stopped after shutdown timed out",
    ),
    (
        "正在关闭虚拟网卡，关闭后可启用系统代理",
        "Wait for TUN to stop before enabling system proxy",
    ),
    (
        "虚拟网卡配置无效：{error}",
        "Invalid TUN configuration: {error}",
    ),
    (
        "正在恢复虚拟网卡路由，完成后可启用系统代理",
        "Wait for TUN route recovery before enabling system proxy",
    ),
    (
        "恢复虚拟网卡路由失败：{error}",
        "TUN route recovery failed: {error}",
    ),
    (
        "请先启动后台，再启用系统代理",
        "Start the daemon before enabling system proxy",
    ),
    (
        "HTTP 代理必须监听本机回环地址",
        "HTTP proxy must listen on a loopback address",
    ),
    (
        "系统代理被其他程序修改，已保留你的设置",
        "System proxy changed outside Helios; your settings were preserved",
    ),
    ("系统代理已恢复", "System proxy restored"),
    (
        "请先启动后台，再启用虚拟网卡",
        "Start the daemon before enabling TUN",
    ),
    (
        "正在恢复虚拟网卡，完成后可重新开启",
        "Wait for TUN recovery before enabling it again",
    ),
    ("恢复虚拟网卡失败：{error}", "TUN recovery failed: {error}"),
    (
        "请在系统提示中授权虚拟网卡",
        "Authorize TUN in the system prompt",
    ),
    ("启动虚拟网卡失败：{error}", "Failed to start TUN: {error}"),
    ("正在关闭虚拟网卡", "Stopping TUN"),
    ("关闭虚拟网卡失败：{error}", "Failed to stop TUN: {error}"),
    (
        "节点配置有误，请先检查地址和凭据",
        "Check node address and credentials first",
    ),
    ("Helios 已最小化到托盘", "Helios is running in the tray"),
    ("已打开日志目录", "Opened log folder"),
    (
        "打开日志目录失败：{error}",
        "Failed to open log folder: {error}",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_languages_preserve_unknown_user_data() {
        assert_eq!(translate("系统代理", true), "System proxy");
        assert_eq!(translate("System proxy", false), "系统代理");
        assert_eq!(translate("example.com:24443", true), "example.com:24443");
        assert_eq!(translate("我的自定义节点", true), "我的自定义节点");
        assert_eq!(
            translate_message("节点测试失败：timeout", true),
            "Node test failed: timeout"
        );
        assert_eq!(
            translate_message("Node test failed: timeout", false),
            "节点测试失败：timeout"
        );
    }
}
