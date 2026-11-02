use std::{
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use helios_protocol::{AUTH_PROOF_LEN, Auth};
use helios_routing::{RuleConfig, RuleSet};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONFIG_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub schema_version: u32,
    pub listen: SocketAddr,
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
    pub node: NodeConfig,
    #[serde(default)]
    pub backup_nodes: Vec<NodeConfig>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub timeouts: ClientTimeouts,
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
