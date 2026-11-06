use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use helios_protocol::{AUTH_PROOF_LEN, Auth};
use helios_routing::{RuleConfig, RuleSet};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CONFIG_SCHEMA_VERSION: u32 = 1;
pub const CONNECTION_LINK_PREFIX: &str = "helios://v1/";
const MAX_CONNECTION_LINK_LEN: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionLink {
    pub version: u8,
    pub name: String,
    pub server: SocketAddr,
    pub server_name: String,
    pub certificate: String,
    pub credential_id: String,
    pub token: String,
    pub preferred_transport: TransportPreference,
}

impl ConnectionLink {
    pub fn new(
        name: String,
        server: SocketAddr,
        server_name: String,
        certificate: &[u8],
        credential_id: String,
        token: [u8; 32],
        preferred_transport: TransportPreference,
    ) -> Result<Self, ConfigError> {
        let value = Self {
            version: 1,
            name,
            server,
            server_name,
            certificate: URL_SAFE_NO_PAD.encode(certificate),
            credential_id,
            token: token.iter().map(|byte| format!("{byte:02x}")).collect(),
            preferred_transport,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn encode(&self) -> Result<String, ConfigError> {
        self.validate()?;
        let payload =
            serde_json::to_vec(self).map_err(|error| ConfigError::Invalid(error.to_string()))?;
        let encoded = URL_SAFE_NO_PAD.encode(payload);
        if CONNECTION_LINK_PREFIX.len() + encoded.len() > MAX_CONNECTION_LINK_LEN {
            return Err(ConfigError::Invalid("connection link is too long".into()));
        }
        Ok(format!("{CONNECTION_LINK_PREFIX}{encoded}"))
    }

    pub fn decode(value: &str) -> Result<Self, ConfigError> {
        let value = value.trim();
        if value.len() > MAX_CONNECTION_LINK_LEN {
            return Err(ConfigError::Invalid("connection link is too long".into()));
        }
        let payload = value.strip_prefix(CONNECTION_LINK_PREFIX).ok_or_else(|| {
            ConfigError::Invalid("connection link must start with helios://v1/".into())
        })?;
        let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| {
            ConfigError::Invalid("connection link payload is not valid base64url".into())
        })?;
        let link: Self = serde_json::from_slice(&bytes).map_err(|error| {
            ConfigError::Invalid(format!("connection link JSON is invalid: {error}"))
        })?;
        link.validate()?;
        Ok(link)
    }

    pub fn certificate_der(&self) -> Result<Vec<u8>, ConfigError> {
        URL_SAFE_NO_PAD
            .decode(&self.certificate)
            .map_err(|_| ConfigError::Invalid("connection link certificate is invalid".into()))
    }

    pub fn certificate_pem(&self) -> Result<String, ConfigError> {
        let encoded = STANDARD.encode(self.certificate_der()?);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        Ok(pem)
    }

    pub fn token_bytes(&self) -> Result<[u8; 32], ConfigError> {
        parse_token(&self.token)
    }

    pub fn storage_id(&self) -> Result<String, ConfigError> {
        let payload =
            serde_json::to_vec(self).map_err(|error| ConfigError::Invalid(error.to_string()))?;
        let digest = Sha256::digest(payload);
        Ok(digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1 {
            return Err(ConfigError::Invalid(format!(
                "unsupported connection link version {}",
                self.version
            )));
        }
        if self.name.trim().is_empty()
            || self.name.len() > 80
            || self.name.chars().any(char::is_control)
        {
            return Err(ConfigError::Invalid(
                "node name must contain 1 to 80 printable characters".into(),
            ));
        }
        if self.server.port() == 0 {
            return Err(ConfigError::Invalid("server port must not be zero".into()));
        }
        ServerName::try_from(self.server_name.clone())
            .map_err(|_| ConfigError::Invalid("TLS server name is invalid".into()))?;
        validate_credential_id(&self.credential_id)?;
        parse_token(&self.token)?;
        let certificate = self.certificate_der()?;
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(certificate))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub schema_version: u32,
    pub listen: SocketAddr,
    #[serde(default)]
    pub listen_ipv6: Option<SocketAddr>,
    pub tls: TlsFiles,
    pub auth: CredentialConfig,
    #[serde(default)]
    pub limits: ServerLimits,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfig {
    pub id: String,
    pub token_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerLimits {
    pub handshake_timeout_seconds: u64,
    pub max_sessions: usize,
    pub max_flows_per_session: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            handshake_timeout_seconds: 10,
            max_sessions: 64,
            max_flows_per_session: 1024,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    pub schema_version: u32,
    pub listen: SocketAddr,
    pub http_listen: SocketAddr,
    pub control_listen: SocketAddr,
    #[serde(default)]
    pub control_socket: Option<PathBuf>,
    #[serde(default)]
    pub control_pipe: Option<String>,
    #[serde(default)]
    pub control_token_file: Option<PathBuf>,
    #[serde(default)]
    pub proxy_bypass: Vec<String>,
    #[serde(default)]
    pub dns: Option<DnsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<OutboundConfig>,
    pub node: NodeConfig,
    #[serde(default)]
    pub backup_nodes: Vec<NodeConfig>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub timeouts: ClientTimeouts,
}

/// Explicit uplink binding for Linux source-policy TUN; absence preserves normal routing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundConfig {
    pub source_bypass: Vec<IpAddr>,
    pub dns_servers: Vec<SocketAddr>,
}

/// Bounded, path-free request passed through pkexec's stdin. Never contains root file paths.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopTunRequest {
    pub socks_listen: SocketAddr,
    pub server_ip: IpAddr,
    pub node_ips: Vec<IpAddr>,
    pub mtu: u16,
    pub ipv6_enabled: bool,
    pub outbound: OutboundConfig,
    pub desktop_pid: u32,
    pub daemon_pid: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TunDaemonInfo {
    pub pid: u32,
    pub outbound: OutboundConfig,
}

impl OutboundConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !cfg!(target_os = "linux") {
            return Err(ConfigError::Invalid(
                "outbound binding currently requires Linux".into(),
            ));
        }
        if self.source_bypass.is_empty()
            || self.source_bypass.len() > 2
            || self.source_bypass.iter().any(|ip| !valid_uplink(*ip))
            || (self.source_bypass.len() == 2
                && self.source_bypass[0].is_ipv4() == self.source_bypass[1].is_ipv4())
        {
            return Err(ConfigError::Invalid(
                "outbound.source_bypass requires one unicast uplink address per enabled IP family"
                    .into(),
            ));
        }
        if self.dns_servers.is_empty()
            || self.dns_servers.len() > 4
            || self.dns_servers.iter().any(|server| {
                server.port() == 0
                    || !valid_uplink(server.ip())
                    || !self
                        .source_bypass
                        .iter()
                        .any(|source| source.is_ipv4() == server.is_ipv4())
            })
        {
            return Err(ConfigError::Invalid("outbound.dns_servers requires 1 to 4 real upstream addresses with a matching source family; loopback/stub resolvers are unsupported".into()));
        }
        Ok(())
    }
}

fn valid_uplink(ip: IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_link_local()
                && !ip.is_broadcast()
                && ip.octets()[0] != 0
                && ip.octets()[0] < 224
                && (u32::from(ip) & 0xfffe_0000 != 0xc612_0000)
        }
        IpAddr::V6(ip) => {
            !ip.is_unicast_link_local()
                && ip.to_ipv4_mapped().is_none()
                && (u128::from(ip) >> 32 != 0xfdfe_dcba_9876_0000_0000_0000)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub listen: SocketAddr,
    pub fake_ip_capacity: usize,
    pub fake_ip_ttl_seconds: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1053".parse().unwrap(),
            fake_ip_capacity: 4096,
            fake_ip_ttl_seconds: 60,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub server: SocketAddr,
    pub server_name: String,
    pub ca_certificate: PathBuf,
    pub credential_id: String,
    pub token_file: PathBuf,
    pub preferred_transport: TransportPreference,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportPreference {
    Quic,
    Tls,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientTimeouts {
    pub socks_handshake_seconds: u64,
    pub http_handshake_seconds: u64,
    pub connect_milliseconds: u32,
    pub health_probe_seconds: u64,
    pub udp_idle_seconds: u64,
}

impl Default for ClientTimeouts {
    fn default() -> Self {
        Self {
            socks_handshake_seconds: 5,
            http_handshake_seconds: 5,
            connect_milliseconds: 10_000,
            health_probe_seconds: 30,
            udp_idle_seconds: 60,
        }
    }
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let mut config: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        resolve(&mut config.tls.certificate, base);
        resolve(&mut config.tls.private_key, base);
        resolve(&mut config.auth.token_file, base);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_schema(self.schema_version)?;
        if self.listen.port() == 0 {
            return Err(ConfigError::Invalid("listen port must not be zero".into()));
        }
        if let Some(listen_ipv6) = self.listen_ipv6 {
            if self.listen.is_ipv6() || !listen_ipv6.is_ipv6() {
                return Err(ConfigError::Invalid(
                    "listen_ipv6 requires an IPv4 listen address and an IPv6 address".into(),
                ));
            }
            if listen_ipv6.port() == 0 {
                return Err(ConfigError::Invalid(
                    "listen_ipv6 port must not be zero".into(),
                ));
            }
        }
        validate_credential_id(&self.auth.id)?;
        if !(1..=60).contains(&self.limits.handshake_timeout_seconds) {
            return Err(ConfigError::Invalid(
                "handshake_timeout_seconds must be between 1 and 60".into(),
            ));
        }
        if !(1..=10_000).contains(&self.limits.max_sessions) {
            return Err(ConfigError::Invalid(
                "max_sessions must be between 1 and 10000".into(),
            ));
        }
        if !(1..=10_000).contains(&self.limits.max_flows_per_session) {
            return Err(ConfigError::Invalid(
                "max_flows_per_session must be between 1 and 10000".into(),
            ));
        }
        Ok(())
    }
}

impl DaemonConfig {
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        use std::io::Write;
        self.validate()?;
        let bytes = toml::to_string_pretty(self)
            .map_err(|error| ConfigError::Invalid(error.to_string()))?;
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).map_err(|error| ConfigError::Invalid(error.to_string()))?;
        let temporary = parent.join(format!(
            ".helios-config-{:016x}.tmp",
            u64::from_le_bytes(random)
        ));
        let result = (|| -> Result<(), ConfigError> {
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(bytes.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let mut config: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        resolve(&mut config.node.ca_certificate, base);
        resolve(&mut config.node.token_file, base);
        for node in &mut config.backup_nodes {
            resolve(&mut node.ca_certificate, base);
            resolve(&mut node.token_file, base);
        }
        if let Some(path) = &mut config.control_token_file {
            resolve(path, base);
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_schema(self.schema_version)?;
        if let Some(outbound) = &self.outbound {
            outbound.validate()?;
            if std::iter::once(&self.node)
                .chain(&self.backup_nodes)
                .any(|node| {
                    !outbound
                        .source_bypass
                        .iter()
                        .any(|source| source.is_ipv4() == node.server.is_ipv4())
                })
            {
                return Err(ConfigError::Invalid(
                    "every node needs a matching outbound source family".into(),
                ));
            }
        }
        if self.backup_nodes.len() > 16 {
            return Err(ConfigError::Invalid(
                "at most 16 backup nodes are allowed".into(),
            ));
        }
        for node in &self.backup_nodes {
            if node.server.port() == 0 {
                return Err(ConfigError::Invalid(
                    "backup node port must not be zero".into(),
                ));
            }
            ServerName::try_from(node.server_name.clone())
                .map_err(|_| ConfigError::Invalid("backup server_name is invalid".into()))?;
            validate_credential_id(&node.credential_id)?;
        }
        if !self.listen.ip().is_loopback() {
            return Err(ConfigError::Invalid(
                "SOCKS5 listen address must be loopback".into(),
            ));
        }
        if !self.http_listen.ip().is_loopback() {
            return Err(ConfigError::Invalid(
                "HTTP CONNECT listen address must be loopback".into(),
            ));
        }
        if !self.control_listen.ip().is_loopback() {
            return Err(ConfigError::Invalid(
                "control listen address must be loopback".into(),
            ));
        }
        if let Some(path) = &self.control_socket
            && !path.is_absolute()
        {
            return Err(ConfigError::Invalid(
                "control_socket must be an absolute path".into(),
            ));
        }
        #[cfg(unix)]
        if let Some(path) = &self.control_socket
            && path.as_os_str().as_encoded_bytes().len() > 100
        {
            return Err(ConfigError::Invalid(
                "control_socket path must be at most 100 bytes".into(),
            ));
        }
        if let Some(pipe) = &self.control_pipe
            && (!pipe.starts_with(r"\.\pipe\") || pipe.len() <= 9)
        {
            return Err(ConfigError::Invalid(
                r"control_pipe must start with \.\pipe\ and include a name".into(),
            ));
        }
        if self.listen == self.http_listen
            || self.listen == self.control_listen
            || self.http_listen == self.control_listen
        {
            return Err(ConfigError::Invalid(
                "SOCKS5, HTTP CONNECT and control listen addresses must differ".into(),
            ));
        }
        if let Some(dns) = &self.dns {
            if !dns.listen.ip().is_loopback() || dns.listen.port() == 0 {
                return Err(ConfigError::Invalid(
                    "DNS listen address must be loopback with a non-zero port".into(),
                ));
            }
            if !(1..=65_536).contains(&dns.fake_ip_capacity) {
                return Err(ConfigError::Invalid(
                    "dns.fake_ip_capacity must be between 1 and 65536".into(),
                ));
            }
            if !(30..=3600).contains(&dns.fake_ip_ttl_seconds) {
                return Err(ConfigError::Invalid(
                    "dns.fake_ip_ttl_seconds must be between 30 and 3600".into(),
                ));
            }
        }
        if self.listen.port() == 0
            || self.http_listen.port() == 0
            || self.control_listen.port() == 0
            || self.node.server.port() == 0
        {
            return Err(ConfigError::Invalid("ports must not be zero".into()));
        }
        ServerName::try_from(self.node.server_name.clone()).map_err(|_| {
            ConfigError::Invalid("server_name is not a valid DNS name or IP".into())
        })?;
        validate_credential_id(&self.node.credential_id)?;
        RuleSet::new(&self.rules)
            .map_err(|error| ConfigError::Invalid(format!("routing rules are invalid: {error}")))?;
        if !(1..=60).contains(&self.timeouts.socks_handshake_seconds) {
            return Err(ConfigError::Invalid(
                "socks_handshake_seconds must be between 1 and 60".into(),
            ));
        }
        if !(1..=60).contains(&self.timeouts.http_handshake_seconds) {
            return Err(ConfigError::Invalid(
                "http_handshake_seconds must be between 1 and 60".into(),
            ));
        }
        if !(1_000..=30_000).contains(&self.timeouts.connect_milliseconds) {
            return Err(ConfigError::Invalid(
                "connect_milliseconds must be between 1000 and 30000".into(),
            ));
        }
        if !(5..=300).contains(&self.timeouts.health_probe_seconds) {
            return Err(ConfigError::Invalid(
                "health_probe_seconds must be between 5 and 300".into(),
            ));
        }
        if !(30..=300).contains(&self.timeouts.udp_idle_seconds) {
            return Err(ConfigError::Invalid(
                "timeouts.udp_idle_seconds must be between 30 and 300".into(),
            ));
        }
        Ok(())
    }
}

pub fn load_certificates(
    path: impl AsRef<Path>,
) -> Result<Vec<CertificateDer<'static>>, ConfigError> {
    let mut reader = BufReader::new(File::open(path)?);
    let certificates = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(ConfigError::Invalid("certificate file is empty".into()));
    }
    Ok(certificates)
}

pub fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>, ConfigError> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| ConfigError::Invalid("private key file is empty".into()))
}

pub fn load_roots(path: impl AsRef<Path>) -> Result<RootCertStore, ConfigError> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut roots = RootCertStore::empty();
    let mut count = 0;
    for certificate in rustls_pemfile::certs(&mut reader) {
        roots.add(certificate?)?;
        count += 1;
    }
    if count == 0 {
        return Err(ConfigError::Invalid("CA certificate file is empty".into()));
    }
    Ok(roots)
}

pub fn load_token(path: impl AsRef<Path>) -> Result<[u8; 32], ConfigError> {
    let path = path.as_ref();
    validate_secret_permissions(path)?;
    let value = std::fs::read_to_string(path)?;
    parse_token(value.trim())
}

/// The local control credential survives node changes and is never sent to the VPS.
pub fn ensure_control_token(path: &Path) -> Result<(), ConfigError> {
    use std::io::Write;
    if path.exists() {
        load_token(path)?;
        return Ok(());
    }
    let mut token = [0u8; 32];
    getrandom::fill(&mut token).map_err(|error| ConfigError::Invalid(error.to_string()))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            let encoded = token
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            file.write_all(encoded.as_bytes())?;
            file.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            load_token(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn parse_token(value: &str) -> Result<[u8; 32], ConfigError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::Invalid(
            "token file must contain exactly 64 hexadecimal characters".into(),
        ));
    }
    let mut token = [0; 32];
    for (index, byte) in token.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ConfigError::Invalid("token contains invalid hexadecimal".into()))?;
    }
    Ok(token)
}

#[cfg(unix)]
fn validate_secret_permissions(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(ConfigError::Invalid(
            "token path is not a regular file".into(),
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ConfigError::Invalid(
            "token file must not be readable or writable by group/other".into(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_permissions(path: &Path) -> Result<(), ConfigError> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(ConfigError::Invalid(
            "token path is not a regular file".into(),
        ));
    }
    Ok(())
}

fn validate_schema(version: u32) -> Result<(), ConfigError> {
    if version != CONFIG_SCHEMA_VERSION {
        return Err(ConfigError::Invalid(format!(
            "unsupported schema_version {version}"
        )));
    }
    Ok(())
}

fn validate_credential_id(value: &str) -> Result<(), ConfigError> {
    Auth::new(value.to_owned(), [0; AUTH_PROOF_LEN], Vec::new())
        .map(|_| ())
        .map_err(|_| ConfigError::Invalid("credential ID is invalid".into()))
}

fn resolve(path: &mut PathBuf, base: &Path) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("configuration TOML is invalid: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("TLS trust configuration is invalid: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("configuration is invalid: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_link_round_trips_and_rejects_tampering() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["node-a1.helios.invalid".to_owned()])
                .unwrap()
                .cert;
        let link = ConnectionLink::new(
            "Personal VPS".into(),
            "203.0.113.10:4800".parse().unwrap(),
            "node-a1.helios.invalid".into(),
            certificate.der(),
            "desktop-main".into(),
            [7; 32],
            TransportPreference::Tls,
        )
        .unwrap();
        let encoded = link.encode().unwrap();
        assert!(encoded.starts_with(CONNECTION_LINK_PREFIX));
        assert_eq!(ConnectionLink::decode(&encoded).unwrap(), link);
        assert!(
            link.certificate_pem()
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        assert_eq!(link.token_bytes().unwrap(), [7; 32]);
        assert_eq!(link.storage_id().unwrap().len(), 32);

        assert!(ConnectionLink::decode("https://example.com/node").is_err());
        let mut json = serde_json::to_value(&link).unwrap();
        json["unexpected"] = serde_json::json!(true);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json).unwrap());
        assert!(ConnectionLink::decode(&format!("{CONNECTION_LINK_PREFIX}{payload}")).is_err());
    }

    #[test]
    fn local_control_identity_is_private_stable_and_never_overwrites_invalid_existing_data() {
        let path =
            std::env::temp_dir().join(format!("helios-control-token-{}.hex", std::process::id()));
        ensure_control_token(&path).unwrap();
        let first = load_token(&path).unwrap();
        ensure_control_token(&path).unwrap();
        assert_eq!(load_token(&path).unwrap(), first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::write(&path, "invalid-existing-credential").unwrap();
        assert!(ensure_control_token(&path).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "invalid-existing-credential"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn parses_and_validates_server_defaults() {
        let config: ServerConfig = toml::from_str(
            r#"
schema_version = 1
listen = "127.0.0.1:443"
[tls]
certificate = "cert.pem"
private_key = "key.pem"
[auth]
id = "desktop-main"
token_file = "token.hex"
"#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.limits, ServerLimits::default());
    }

    #[test]
    fn server_accepts_an_optional_ipv6_listener() {
        let config: ServerConfig = toml::from_str(
            r#"
schema_version = 1
listen = "0.0.0.0:443"
listen_ipv6 = "[::]:443"
[tls]
certificate = "cert.pem"
private_key = "key.pem"
[auth]
id = "desktop-main"
token_file = "token.hex"
"#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.listen_ipv6, Some("[::]:443".parse().unwrap()));

        let mut invalid = config.clone();
        invalid.listen_ipv6 = Some("0.0.0.0:443".parse().unwrap());
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn parses_and_validates_daemon_defaults() {
        let config: DaemonConfig = toml::from_str(
            r#"
schema_version = 1
listen = "127.0.0.1:1080"
http_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:9080"
[node]
server = "203.0.113.1:443"
server_name = "vpn.example.com"
ca_certificate = "ca.pem"
credential_id = "desktop-main"
token_file = "token.hex"
preferred_transport = "quic"
"#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.timeouts, ClientTimeouts::default());
        assert!(config.outbound.is_none());
    }

    #[test]
    fn outbound_binding_requires_real_sources_and_explicit_matching_dns_servers() {
        let mut config = OutboundConfig {
            source_bypass: vec!["192.0.2.1".parse().unwrap()],
            dns_servers: vec!["192.0.2.53:53".parse().unwrap()],
        };
        assert_eq!(config.validate().is_ok(), cfg!(target_os = "linux"));
        let encoded = toml::to_string(&config).unwrap();
        assert_eq!(toml::from_str::<OutboundConfig>(&encoded).unwrap(), config);
        assert!(toml::from_str::<OutboundConfig>(&(encoded + "unknown = 1\n")).is_err());
        for source in [
            "0.0.0.0",
            "127.0.0.1",
            "198.18.0.1",
            "169.254.0.1",
            "224.0.0.1",
            "::",
            "::1",
            "fe80::1",
            "fdfe:dcba:9876::1",
            "::ffff:192.0.2.1",
        ] {
            config.source_bypass = vec![source.parse().unwrap()];
            assert!(config.validate().is_err(), "{source}");
        }
        config.source_bypass = vec!["192.0.2.1".parse().unwrap()];
        for server in [
            "127.0.0.53:53",
            "198.19.255.254:53",
            "192.0.2.53:0",
            "[::1]:53",
            "[2001:db8::53]:53",
        ] {
            config.dns_servers = vec![server.parse().unwrap()];
            assert!(config.validate().is_err(), "{server}");
        }
        config.dns_servers.clear();
        assert!(config.validate().is_err());
        config.dns_servers = vec!["192.0.2.53:53".parse().unwrap()];
        config.source_bypass.push("192.0.2.2".parse().unwrap());
        assert!(config.validate().is_err());
        config.source_bypass.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_unsafe_ranges() {
        let unknown = r#"
schema_version = 1
listen = "127.0.0.1:1080"
http_listen = "127.0.0.1:8080"
control_listen = "127.0.0.1:9080"
unexpected = true
[node]
server = "203.0.113.1:443"
server_name = "vpn.example.com"
ca_certificate = "ca.pem"
credential_id = "desktop-main"
token_file = "token.hex"
preferred_transport = "quic"
"#;
        assert!(toml::from_str::<DaemonConfig>(unknown).is_err());

        let mut config: DaemonConfig =
            toml::from_str(&unknown.replace("unexpected = true", "")).unwrap();
        config.timeouts.connect_milliseconds = 100;
        assert!(config.validate().is_err());
        config.timeouts.connect_milliseconds = 10_000;
        config.timeouts.udp_idle_seconds = 29;
        assert!(config.validate().is_err());
        config.timeouts.udp_idle_seconds = 60;
        config.http_listen = "0.0.0.0:8080".parse().unwrap();
        assert!(config.validate().is_err());
        config.http_listen = config.listen;
        assert!(config.validate().is_err());
        config.http_listen = "127.0.0.1:8080".parse().unwrap();
        config.control_listen = "0.0.0.0:9080".parse().unwrap();
        assert!(config.validate().is_err());
        config.control_listen = config.listen;
        assert!(config.validate().is_err());
        config.control_listen = "127.0.0.1:9080".parse().unwrap();
        config.control_pipe = Some("helios-control".into());
        assert!(config.validate().is_err());
        config.control_pipe = Some(r"\.\pipe\helios-control".into());
        config.validate().unwrap();
    }
}
