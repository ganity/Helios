#[cfg(any(test, windows, target_os = "macos"))]
use std::net::IpAddr;
use std::net::SocketAddr;
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use helios_config::{
    ClientTimeouts, ConnectionLink, DaemonConfig, DnsConfig, NodeConfig, OutboundConfig,
    TransportPreference,
};
use helios_protocol::{Address, Target};
use helios_routing::{Network, RouteAction, RuleConfig, RuleSet};
use serde::{Deserialize, Serialize};

pub type ModelError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeProfile {
    pub name: String,
    pub server: String,
    pub server_name: String,
    pub ca_certificate: PathBuf,
    pub credential_id: String,
    pub token_file: PathBuf,
    pub preferred_transport: TransportPreference,
}

impl Default for NodeProfile {
    fn default() -> Self {
        Self {
            name: "Personal VPS".into(),
            server: "203.0.113.10:443".into(),
            server_name: "vpn.example.com".into(),
            ca_certificate: PathBuf::from("ca.pem"),
            credential_id: "desktop-main".into(),
            token_file: PathBuf::from("token.hex"),
            preferred_transport: TransportPreference::Quic,
        }
    }
}

impl NodeProfile {
    pub fn config(&self) -> Result<NodeConfig, ModelError> {
        Ok(NodeConfig {
            server: self.server.parse()?,
            server_name: self.server_name.clone(),
            ca_certificate: self.ca_certificate.clone(),
            credential_id: self.credential_id.clone(),
            token_file: self.token_file.clone(),
            preferred_transport: self.preferred_transport,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopProfile {
    #[serde(default)]
    pub language: Language,
    pub daemon_binary: PathBuf,
    pub daemon_config: PathBuf,
    /// Session-only binding; never restore a stale physical address from desktop.json.
    #[serde(skip)]
    pub tun_outbound: Option<OutboundConfig>,
    #[serde(default = "default_true")]
    pub auto_start_daemon: bool,
    #[serde(default = "default_helper_binary")]
    pub helper_binary: PathBuf,
    #[serde(default = "default_helper_config")]
    pub helper_config: PathBuf,
    #[serde(default = "default_tun_mtu")]
    pub tun_mtu: u16,
    #[serde(default = "default_true")]
    pub tun_ipv6_enabled: bool,
    pub active_node: usize,
    pub nodes: Vec<NodeProfile>,
    #[serde(default)]
    pub auto_failover: bool,
    pub socks_listen: String,
    pub http_listen: String,
    pub control_listen: String,
    #[serde(default = "default_udp_idle_seconds")]
    pub udp_idle_seconds: u64,
    #[serde(default)]
    pub fake_ip_dns_enabled: bool,
    #[serde(default = "default_dns_listen")]
    pub dns_listen: String,
    #[serde(default = "default_fake_ip_capacity")]
    pub fake_ip_capacity: usize,
    #[serde(default = "default_fake_ip_ttl")]
    pub fake_ip_ttl_seconds: u32,
    #[serde(default)]
    pub mode: RoutingMode,
    #[serde(default = "default_proxy_bypass")]
    pub proxy_bypass: Vec<String>,
    pub rules: Vec<RuleConfig>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum Language {
    #[default]
    #[serde(rename = "zh-CN")]
    Chinese,
    #[serde(rename = "en")]
    English,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingMode {
    #[default]
    Rule,
    GlobalProxy,
    GlobalDirect,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDesktopProfile {
    name: String,
    daemon_binary: PathBuf,
    daemon_config: PathBuf,
    server: String,
    server_name: String,
    ca_certificate: PathBuf,
    credential_id: String,
    token_file: PathBuf,
    preferred_transport: TransportPreference,
    socks_listen: String,
    http_listen: String,
    control_listen: String,
    rules: Vec<RuleConfig>,
}

impl From<LegacyDesktopProfile> for DesktopProfile {
    fn from(legacy: LegacyDesktopProfile) -> Self {
        Self {
            language: Language::default(),
            daemon_binary: legacy.daemon_binary,
            daemon_config: legacy.daemon_config,
            tun_outbound: None,
            auto_start_daemon: true,
            helper_binary: default_helper_binary(),
            helper_config: default_helper_config(),
            tun_mtu: default_tun_mtu(),
            tun_ipv6_enabled: true,
            active_node: 0,
            auto_failover: false,
            nodes: vec![NodeProfile {
                name: legacy.name,
                server: legacy.server,
                server_name: legacy.server_name,
                ca_certificate: legacy.ca_certificate,
                credential_id: legacy.credential_id,
                token_file: legacy.token_file,
                preferred_transport: legacy.preferred_transport,
            }],
            socks_listen: legacy.socks_listen,
            http_listen: legacy.http_listen,
            control_listen: legacy.control_listen,
            udp_idle_seconds: default_udp_idle_seconds(),
            fake_ip_dns_enabled: false,
            dns_listen: default_dns_listen(),
            fake_ip_capacity: default_fake_ip_capacity(),
            fake_ip_ttl_seconds: default_fake_ip_ttl(),
            mode: RoutingMode::Rule,
            proxy_bypass: default_proxy_bypass(),
            rules: legacy.rules,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StoredDesktopProfile {
    Current(DesktopProfile),
    Legacy(LegacyDesktopProfile),
}

impl Default for DesktopProfile {
    fn default() -> Self {
        Self {
            language: Language::default(),
            daemon_binary: sibling_binary("helios-daemon"),
            daemon_config: default_state_dir().join("daemon.toml"),
            tun_outbound: None,
            auto_start_daemon: true,
            helper_binary: default_helper_binary(),
            helper_config: default_helper_config(),
            tun_mtu: default_tun_mtu(),
            tun_ipv6_enabled: true,
            active_node: 0,
            nodes: vec![NodeProfile::default()],
            auto_failover: false,
            socks_listen: "127.0.0.1:1080".into(),
            http_listen: "127.0.0.1:8080".into(),
            control_listen: "127.0.0.1:9080".into(),
            udp_idle_seconds: default_udp_idle_seconds(),
            fake_ip_dns_enabled: false,
            dns_listen: default_dns_listen(),
            fake_ip_capacity: default_fake_ip_capacity(),
            fake_ip_ttl_seconds: default_fake_ip_ttl(),
            mode: RoutingMode::Rule,
            proxy_bypass: default_proxy_bypass(),
            rules: vec![
                RuleConfig::IpCidr {
                    value: "192.168.0.0/16".into(),
                    action: RouteAction::Direct,
                    resolve: false,
                },
                RuleConfig::Final {
                    action: RouteAction::Proxy,
                },
            ],
        }
    }
}

impl DesktopProfile {
    pub fn active_node(&self) -> &NodeProfile {
        &self.nodes[self.active_node.min(self.nodes.len() - 1)]
    }

    pub fn daemon_config(&self) -> Result<DaemonConfig, ModelError> {
        if self.nodes.is_empty() {
            return Err("at least one node is required".into());
        }
        let dns = if self.fake_ip_dns_enabled || self.tun_outbound.is_some() {
            Some(DnsConfig {
                listen: self.dns_listen.parse()?,
                fake_ip_capacity: self.fake_ip_capacity,
                fake_ip_ttl_seconds: self.fake_ip_ttl_seconds,
            })
        } else {
            None
        };
        let config = DaemonConfig {
            schema_version: 1,
            listen: self.socks_listen.parse()?,
            http_listen: self.http_listen.parse()?,
            control_listen: self.control_listen.parse()?,
            control_socket: default_control_socket(),
            control_pipe: default_control_pipe(),
            control_token_file: Some(default_state_dir().join("control-token.hex")),
            proxy_bypass: system_proxy_bypass(self),
            dns,
            outbound: self.tun_outbound.clone(),
            node: self.active_node().config()?,
            backup_nodes: if self.auto_failover {
                self.nodes
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != self.active_node)
                    .map(|(_, node)| node.config())
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                Vec::new()
            },
            rules: self.effective_rules(),
            timeouts: ClientTimeouts {
                udp_idle_seconds: self.udp_idle_seconds,
                ..Default::default()
            },
        };
        config.validate()?;
        Ok(config)
    }

    pub fn effective_rules(&self) -> Vec<RuleConfig> {
        match self.mode {
            RoutingMode::Rule => self.rules.clone(),
            RoutingMode::GlobalProxy => vec![RuleConfig::Final {
                action: RouteAction::Proxy,
            }],
            RoutingMode::GlobalDirect => vec![RuleConfig::Final {
                action: RouteAction::Direct,
            }],
        }
    }

    #[cfg(any(test, windows, target_os = "macos"))]
    pub fn helper_config_toml(&self) -> Result<String, ModelError> {
        #[derive(Serialize)]
        struct HelperConfig {
            schema_version: u8,
            socks_listen: SocketAddr,
            server_ip: IpAddr,
            mtu: u16,
            ipv6_enabled: bool,
            bypass: Vec<String>,
            source_bypass: Vec<IpAddr>,
            desktop_pid: u32,
            status_file: PathBuf,
            stop_file: PathBuf,
        }

        let socks_listen: SocketAddr = self.socks_listen.parse()?;
        if !socks_listen.ip().is_loopback() {
            return Err("SOCKS5 listen must be a loopback address".into());
        }
        let server_ip = self.active_node().config()?.server.ip();
        let mut bypass: Vec<String> = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            .into_iter()
            .map(str::to_string)
            .collect();
        for node in &self.nodes {
            let ip = node.config()?.server.ip();
            let cidr = format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 });
            if !bypass.contains(&cidr) {
                bypass.push(cidr);
            }
        }
        Ok(toml::to_string_pretty(&HelperConfig {
            schema_version: 1,
            socks_listen,
            server_ip,
            mtu: self.tun_mtu,
            ipv6_enabled: self.tun_ipv6_enabled,
            bypass,
            source_bypass: self
                .tun_outbound
                .as_ref()
                .map(|outbound| outbound.source_bypass.clone())
                .unwrap_or_default(),
            desktop_pid: std::process::id(),
            status_file: tun_status_file(),
            stop_file: tun_stop_file(),
        })?)
    }
}

pub fn parse_rules(text: &str) -> Result<Vec<RuleConfig>, ModelError> {
    let mut rules = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<_> = line.split(',').map(str::trim).collect();
        let action = |value: &str| -> Result<RouteAction, ModelError> {
            Ok(match value.to_ascii_lowercase().as_str() {
                "proxy" => RouteAction::Proxy,
                "direct" => RouteAction::Direct,
                "reject" => RouteAction::Reject,
                _ => return Err(format!("line {}: invalid action", index + 1).into()),
            })
        };
        let rule = match parts.as_slice() {
            ["geoip", value, result] | ["geoip", value, result, "no-resolve"] => {
                RuleConfig::Geoip {
                    value: (*value).into(),
                    action: action(result)?,
                    no_resolve: parts.len() == 4,
                }
            }
            ["domain", value, result] => RuleConfig::Domain {
                value: (*value).into(),
                action: action(result)?,
            },
            ["domain-suffix", value, result] => RuleConfig::DomainSuffix {
                value: (*value).into(),
                action: action(result)?,
            },
            ["ip-cidr", value, result] | ["ip-cidr", value, result, "resolve"] => {
                RuleConfig::IpCidr {
                    value: (*value).into(),
                    action: action(result)?,
                    resolve: parts.len() == 4,
                }
            }
            ["ip-cidr6", value, result] | ["ip-cidr6", value, result, "resolve"] => {
                RuleConfig::IpCidr6 {
                    value: (*value).into(),
                    action: action(result)?,
                    resolve: parts.len() == 4,
                }
            }
            ["dst-port", value, result] => RuleConfig::DstPort {
                value: value.parse()?,
                action: action(result)?,
            },
            ["network", value, result] => RuleConfig::Network {
                value: match *value {
                    "tcp" => Network::Tcp,
                    "udp" => Network::Udp,
                    _ => {
                        return Err(
                            format!("line {}: network must be tcp or udp", index + 1).into()
                        );
                    }
                },
                action: action(result)?,
            },
            ["final", result] => RuleConfig::Final {
                action: action(result)?,
            },
            _ => return Err(format!("line {}: invalid rule format", index + 1).into()),
        };
        rules.push(rule);
    }
    RuleSet::new(&rules)?;
    Ok(rules)
}

pub fn render_rules(rules: &[RuleConfig]) -> String {
    rules
        .iter()
        .map(|rule| match rule {
            RuleConfig::Geoip {
                value,
                action,
                no_resolve,
            } => format!(
                "geoip,{value},{}{}",
                action_name(*action),
                if *no_resolve { ",no-resolve" } else { "" }
            ),
            RuleConfig::Domain { value, action } => {
                format!("domain,{value},{}", action_name(*action))
            }
            RuleConfig::DomainSuffix { value, action } => {
                format!("domain-suffix,{value},{}", action_name(*action))
            }
            RuleConfig::IpCidr {
                value,
                action,
                resolve,
            } => {
                format!(
                    "ip-cidr,{value},{}{}",
                    action_name(*action),
                    if *resolve { ",resolve" } else { "" }
                )
            }
            RuleConfig::IpCidr6 {
                value,
                action,
                resolve,
            } => {
                format!(
                    "ip-cidr6,{value},{}{}",
                    action_name(*action),
                    if *resolve { ",resolve" } else { "" }
                )
            }
            RuleConfig::DstPort { value, action } => {
                format!("dst-port,{value},{}", action_name(*action))
            }
            RuleConfig::Final { action } => format!("final,{}", action_name(*action)),
            RuleConfig::Network { value, action } => format!(
                "network,{},{}",
                match value {
                    Network::Tcp => "tcp",
                    Network::Udp => "udp",
                },
                action_name(*action)
            ),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn action_name(action: RouteAction) -> &'static str {
    match action {
        RouteAction::Proxy => "proxy",
        RouteAction::Direct => "direct",
        RouteAction::Reject => "reject",
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct RouteTestResult {
    pub action: RouteAction,
    pub rule: String,
}

fn test_route(
    rules: &str,
    host: &str,
    port: &str,
    network: Network,
) -> Result<RouteTestResult, String> {
    let rules = parse_rules(rules).map_err(|error| error.to_string())?;
    let port = port
        .parse::<u16>()
        .map_err(|_| "invalid destination port".to_string())?;
    let host = host.trim().trim_matches(['[', ']']);
    let address = host
        .parse()
        .map(Address::Ip)
        .unwrap_or_else(|_| Address::Domain(host.to_string()));
    let target = Target::new(address, port).map_err(|error| error.to_string())?;
    let (action, index, _) = RuleSet::new(&rules)
        .map_err(|error| error.to_string())?
        .evaluate(&target, network, None)
        .ok_or_else(|| {
            "This rule requires runtime DNS resolution; offline test cannot determine the route"
                .to_string()
        })?;
    Ok(RouteTestResult {
        action,
        rule: index
            .map(|index| {
                format!(
                    "rule {} · {}",
                    index + 1,
                    render_rules(&rules[index..=index])
                )
            })
            .unwrap_or_else(|| "implicit final,proxy".into()),
    })
}

pub fn test_route_for_mode(
    mode: RoutingMode,
    rules: &str,
    host: &str,
    port: &str,
) -> Result<RouteTestResult, String> {
    test_route_for_network(mode, rules, host, port, Network::Tcp)
}

pub fn test_route_for_network(
    mode: RoutingMode,
    rules: &str,
    host: &str,
    port: &str,
    network: Network,
) -> Result<RouteTestResult, String> {
    match mode {
        RoutingMode::Rule => test_route(rules, host, port, network),
        RoutingMode::GlobalProxy => Ok(RouteTestResult {
            action: RouteAction::Proxy,
            rule: "global proxy mode".into(),
        }),
        RoutingMode::GlobalDirect => Ok(RouteTestResult {
            action: RouteAction::Direct,
            rule: "global direct mode".into(),
        }),
    }
}

pub fn load_profile(path: &Path) -> Option<DesktopProfile> {
    let stored: StoredDesktopProfile = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    let mut profile = match stored {
        StoredDesktopProfile::Current(profile) => profile,
        StoredDesktopProfile::Legacy(profile) => profile.into(),
    };
    if profile.nodes.is_empty() {
        profile.nodes.push(NodeProfile::default());
    }
    profile.active_node = profile.active_node.min(profile.nodes.len() - 1);
    Some(profile)
}

pub fn save_profile(path: &Path, profile: &DesktopProfile) -> Result<(), ModelError> {
    let config = profile.daemon_config()?;
    write_atomic(path, &serde_json::to_vec_pretty(profile)?)?;
    write_atomic(
        &profile.daemon_config,
        toml::to_string_pretty(&config)?.as_bytes(),
    )
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ModelError> {
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temporary = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary)?;
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

pub fn import_node(text: &str) -> Result<NodeProfile, String> {
    let node: NodeProfile =
        serde_json::from_str(text).map_err(|error| format!("invalid node JSON: {error}"))?;
    node.config()
        .map_err(|error| format!("invalid node settings: {error}"))?;
    if node.name.trim().is_empty() || node.name.len() > 80 {
        return Err("node name must contain 1 to 80 characters".into());
    }
    if node.server_name.trim().is_empty() || node.server_name.len() > 253 {
        return Err("TLS server name is invalid".into());
    }
    if node.credential_id.trim().is_empty() || node.credential_id.len() > 64 {
        return Err("credential ID must contain 1 to 64 characters".into());
    }
    Ok(node)
}

pub fn import_connection_link(text: &str, state_dir: &Path) -> Result<NodeProfile, String> {
    let link = ConnectionLink::decode(text).map_err(|error| error.to_string())?;
    let node_dir = state_dir.join("nodes").join(format!(
        "imported-{}",
        link.storage_id().map_err(|error| error.to_string())?
    ));
    let certificate = node_dir.join("cert.pem");
    let token = node_dir.join("token.hex");
    write_atomic(
        &certificate,
        link.certificate_pem()
            .map_err(|error| error.to_string())?
            .as_bytes(),
    )
    .map_err(|error| error.to_string())?;
    write_atomic(&token, link.token.as_bytes()).map_err(|error| error.to_string())?;
    let node = NodeProfile {
        name: link.name,
        server: link.server.to_string(),
        server_name: link.server_name,
        ca_certificate: certificate,
        credential_id: link.credential_id,
        token_file: token,
        preferred_transport: link.preferred_transport,
    };
    import_node(&serde_json::to_string(&node).map_err(|error| error.to_string())?)
}

pub fn default_state_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Helios")
    } else {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".helios")
    }
}

pub fn default_control_socket() -> Option<PathBuf> {
    if cfg!(unix) {
        Some(default_state_dir().join("control.sock"))
    } else {
        None
    }
}

pub fn tun_status_file() -> PathBuf {
    if cfg!(target_os = "linux") {
        PathBuf::from("/run/helios/tun.status")
    } else {
        default_state_dir().join("helios-helper.status")
    }
}

pub fn tun_stop_file() -> PathBuf {
    default_state_dir().join("helios-helper.stop")
}

pub fn parse_proxy_bypass(text: &str) -> Result<Vec<String>, String> {
    let mut bypass = Vec::new();
    for (index, value) in text.lines().map(str::trim).enumerate() {
        if value.is_empty() {
            continue;
        }
        if value.len() > 255 || value.contains([';', ',', '\r', '\n']) {
            return Err(format!("proxy bypass line {} is invalid", index + 1));
        }
        if !bypass.iter().any(|existing| existing == value) {
            bypass.push(value.to_owned());
        }
    }
    Ok(bypass)
}

pub fn system_proxy_bypass(profile: &DesktopProfile) -> Vec<String> {
    let mut bypass = profile.proxy_bypass.clone();
    for node in &profile.nodes {
        if let Ok(address) = node.server.parse::<SocketAddr>() {
            let address = address.ip().to_string();
            if !bypass.contains(&address) {
                bypass.push(address);
            }
        }
    }
    bypass
}

fn default_helper_binary() -> PathBuf {
    sibling_binary("helios-helper")
}

fn default_helper_config() -> PathBuf {
    default_state_dir().join("helper.toml")
}

fn default_control_pipe() -> Option<String> {
    cfg!(windows).then(|| r"\.\pipe\helios-control".into())
}

fn default_tun_mtu() -> u16 {
    1280
}

fn default_udp_idle_seconds() -> u64 {
    60
}

fn default_true() -> bool {
    true
}

fn default_dns_listen() -> String {
    "127.0.0.1:1053".into()
}

fn default_fake_ip_capacity() -> usize {
    4096
}

fn default_fake_ip_ttl() -> u32 {
    60
}

fn default_proxy_bypass() -> Vec<String> {
    [
        "<local>",
        "localhost",
        "127.*",
        "[::1]",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "*.local",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn sibling_binary(name: &str) -> PathBuf {
    let name = if cfg!(target_os = "windows") {
        format!("{name}.exe")
    } else {
        name.into()
    };
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(&name)))
        .unwrap_or_else(|| PathBuf::from(name))
}

#[cfg(test)]
mod tests {
    #[test]
    fn resolved_rules_round_trip_and_keep_legacy_defaults() {
        let text = "ip-cidr,192.168.0.0/16,direct\nip-cidr,182.92.0.0/16,direct,resolve\nip-cidr6,2400::/12,direct,resolve\ngeoip,cn,direct,no-resolve\ngeoip,cn,direct\nfinal,proxy";
        let rules = super::parse_rules(text).unwrap();
        assert_eq!(super::render_rules(&rules), text);
        assert!(super::parse_rules("geoip,us,direct\nfinal,proxy").is_err());
        assert!(super::parse_rules("domain,example.com,direct,resolve\nfinal,proxy").is_err());
        let legacy: helios_routing::RuleConfig = serde_json::from_str(
            r#"{"type":"ip-cidr","value":"192.168.0.0/16","action":"direct"}"#,
        )
        .unwrap();
        assert_eq!(legacy, rules[0]);
        assert!(!serde_json::to_string(&legacy).unwrap().contains("resolve"));
    }
    use super::*;

    #[test]
    fn language_is_optional_for_existing_profiles_and_round_trips() {
        let mut json = serde_json::to_value(DesktopProfile::default()).unwrap();
        json.as_object_mut().unwrap().remove("language");
        let mut profile: DesktopProfile = serde_json::from_value(json).unwrap();
        assert_eq!(profile.language, Language::Chinese);
        profile.language = Language::English;
        let restored: DesktopProfile =
            serde_json::from_str(&serde_json::to_string(&profile).unwrap()).unwrap();
        assert_eq!(restored.language, Language::English);
    }

    #[test]
    fn rules_round_trip_through_editor_format() {
        let rules = vec![
            RuleConfig::DomainSuffix {
                value: "example.cn".into(),
                action: RouteAction::Direct,
            },
            RuleConfig::Final {
                action: RouteAction::Proxy,
            },
        ];
        assert_eq!(parse_rules(&render_rules(&rules)).unwrap(), rules);
        assert!(parse_rules("domain,broken,proxy").is_err());
    }

    #[test]
    fn generated_daemon_config_round_trips_through_toml() {
        let config = DesktopProfile::default().daemon_config().unwrap();
        let encoded = toml::to_string_pretty(&config).unwrap();
        let decoded: DaemonConfig = toml::from_str(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, config);
    }

    #[test]
    fn save_profile_writes_profile_and_matching_daemon_config() {
        let root =
            std::env::temp_dir().join(format!("helios-client-model-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join("desktop.json");
        let mut profile = DesktopProfile {
            daemon_config: root.join("daemon.toml"),
            ..Default::default()
        };
        profile.mode = RoutingMode::GlobalDirect;

        save_profile(&path, &profile).unwrap();

        assert_eq!(load_profile(&path).unwrap().mode, RoutingMode::GlobalDirect);
        let config: DaemonConfig =
            toml::from_str(&std::fs::read_to_string(&profile.daemon_config).unwrap()).unwrap();
        assert_eq!(config.rules, profile.effective_rules());
        #[cfg(unix)]
        for file in [&path, &profile.daemon_config] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn enabled_fake_ip_dns_is_written_to_daemon_config() {
        let profile = DesktopProfile {
            fake_ip_dns_enabled: true,
            dns_listen: "127.0.0.1:2053".into(),
            fake_ip_capacity: 8192,
            fake_ip_ttl_seconds: 120,
            ..Default::default()
        };
        let dns = profile.daemon_config().unwrap().dns.unwrap();
        assert_eq!(dns.listen, "127.0.0.1:2053".parse().unwrap());
        assert_eq!(dns.fake_ip_capacity, 8192);
        assert_eq!(dns.fake_ip_ttl_seconds, 120);
    }

    #[test]
    fn active_node_drives_generated_daemon_config() {
        let mut profile = DesktopProfile::default();
        profile.nodes.push(NodeProfile {
            server: "198.51.100.20:8443".into(),
            ..Default::default()
        });
        profile.active_node = 1;
        assert_eq!(
            profile.daemon_config().unwrap().node.server,
            "198.51.100.20:8443".parse().unwrap()
        );
    }

    #[test]
    fn generated_helper_config_uses_active_node_and_loopback_socks() {
        let mut profile = DesktopProfile::default();
        profile.nodes[0].server = "198.51.100.20:443".into();
        let value: toml::Value = toml::from_str(&profile.helper_config_toml().unwrap()).unwrap();
        assert_eq!(value["server_ip"].as_str(), Some("198.51.100.20"));
        assert_eq!(value["socks_listen"].as_str(), Some("127.0.0.1:1080"));
        assert_eq!(value["mtu"].as_integer(), Some(1280));
    }

    #[test]
    fn generated_helper_config_enables_ipv6_when_requested() {
        let profile = DesktopProfile {
            tun_ipv6_enabled: true,
            ..Default::default()
        };
        let value: toml::Value = toml::from_str(&profile.helper_config_toml().unwrap()).unwrap();
        assert_eq!(value["ipv6_enabled"].as_bool(), Some(true));
    }

    #[test]
    fn legacy_profile_migrates_to_single_node() {
        let legacy = serde_json::json!({
            "name": "Old VPS",
            "daemon_binary": "helios-daemon",
            "daemon_config": "daemon.toml",
            "server": "203.0.113.50:443",
            "server_name": "old.example.com",
            "ca_certificate": "ca.pem",
            "credential_id": "old",
            "token_file": "token.hex",
            "preferred_transport": "quic",
            "socks_listen": "127.0.0.1:1080",
            "http_listen": "127.0.0.1:8080",
            "control_listen": "127.0.0.1:9080",
            "rules": [{ "type": "final", "action": "proxy" }]
        });
        let stored: StoredDesktopProfile = serde_json::from_value(legacy).unwrap();
        let StoredDesktopProfile::Legacy(legacy) = stored else {
            panic!("legacy profile parsed as current");
        };
        let profile = DesktopProfile::from(legacy);
        assert_eq!(profile.nodes.len(), 1);
        assert_eq!(profile.active_node().name, "Old VPS");
        assert_eq!(profile.active_node().server_name, "old.example.com");
    }

    #[test]
    fn route_tester_uses_unsaved_rule_text_for_domains_ips_and_ports() {
        let rules = "domain-suffix,example.cn,direct\nip-cidr,10.0.0.0/8,reject\ndst-port,22,reject\nfinal,proxy";
        let result = test_route(rules, "www.example.cn", "443", Network::Tcp).unwrap();
        assert_eq!(result.action, RouteAction::Direct);
        assert_eq!(result.rule, "rule 1 · domain-suffix,example.cn,direct");
        assert_eq!(
            test_route(rules, "10.2.3.4", "443", Network::Tcp)
                .unwrap()
                .action,
            RouteAction::Reject
        );
        assert_eq!(
            test_route(rules, "example.com", "22", Network::Tcp)
                .unwrap()
                .action,
            RouteAction::Reject
        );
        assert_eq!(
            test_route(rules, "example.com", "443", Network::Tcp)
                .unwrap()
                .action,
            RouteAction::Proxy
        );
        assert!(test_route(rules, "example.com", "0", Network::Tcp).is_err());
    }

    #[test]
    fn network_rules_round_trip_and_preview_udp() {
        let text = "network,udp,reject\nfinal,proxy";
        let rules = parse_rules(text).unwrap();
        assert_eq!(render_rules(&rules), text);
        assert_eq!(
            test_route_for_network(RoutingMode::Rule, text, "example.com", "443", Network::Udp)
                .unwrap()
                .action,
            RouteAction::Reject
        );
        assert_eq!(
            test_route_for_mode(RoutingMode::Rule, text, "example.com", "443")
                .unwrap()
                .action,
            RouteAction::Proxy
        );
        assert!(parse_rules("network,icmp,proxy\nfinal,direct").is_err());
    }

    #[test]
    fn routing_modes_generate_single_final_rules() {
        let profile = DesktopProfile {
            mode: RoutingMode::GlobalProxy,
            ..Default::default()
        };
        assert_eq!(
            profile.effective_rules(),
            vec![RuleConfig::Final {
                action: RouteAction::Proxy
            }]
        );
        assert_eq!(
            test_route_for_mode(RoutingMode::GlobalDirect, "invalid", "example.com", "443")
                .unwrap()
                .action,
            RouteAction::Direct
        );
    }

    #[test]
    fn proxy_bypass_is_validated_deduplicated_and_includes_node_ip() {
        assert_eq!(
            parse_proxy_bypass("localhost\nlocalhost\n192.168.0.0/16\n").unwrap(),
            vec!["localhost", "192.168.0.0/16"]
        );
        assert!(parse_proxy_bypass("good.example;bad.example").is_err());
        let profile = DesktopProfile {
            proxy_bypass: vec!["localhost".into()],
            ..Default::default()
        };
        assert!(system_proxy_bypass(&profile).contains(&"203.0.113.10".to_string()));
    }

    #[test]
    fn node_exchange_round_trips_paths_without_secret_contents() {
        let node = NodeProfile::default();
        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains("token.hex"));
        assert!(json.contains("ca.pem"));
        assert!(!json.contains(&"07".repeat(32)));
        assert_eq!(import_node(&json).unwrap().server, node.server);
        assert!(import_node("{}").is_err());
    }

    #[test]
    fn connection_link_import_writes_private_material_and_returns_a_node() {
        let root =
            std::env::temp_dir().join(format!("helios-client-link-import-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let certificate =
            rcgen::generate_simple_self_signed(vec!["node-a1.helios.invalid".to_owned()])
                .unwrap()
                .cert;
        let link = ConnectionLink::new(
            "Imported VPS".into(),
            "203.0.113.10:4800".parse().unwrap(),
            "node-a1.helios.invalid".into(),
            certificate.der(),
            "desktop-main".into(),
            [9; 32],
            TransportPreference::Tls,
        )
        .unwrap()
        .encode()
        .unwrap();

        let node = import_connection_link(&link, &root).unwrap();
        assert_eq!(node.name, "Imported VPS");
        assert_eq!(node.server_name, "node-a1.helios.invalid");
        assert!(node.ca_certificate.starts_with(root.join("nodes")));
        assert!(node.ca_certificate.is_file());
        assert_eq!(
            std::fs::read_to_string(&node.token_file).unwrap(),
            "09".repeat(32)
        );
        #[cfg(unix)]
        for file in [&node.ca_certificate, &node.token_file] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
