use helios_routing::RuleConfig;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CONTROL_VERSION: u16 = 5;
pub const MAX_CONTROL_MESSAGE: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub version: u16,
    pub token: [u8; 32],
    pub command: ControlCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlCommand {
    TestRoute {
        rules: Vec<RuleConfig>,
        host: String,
        port: u16,
        network: helios_routing::Network,
    },
    GetStatus,
    UpdateRules {
        rules: Vec<RuleConfig>,
    },
    CloseFlow {
        id: u64,
    },
    SetSystemProxy {
        enabled: bool,
    },
    ApplyConfig {
        expected_revision: u64,
        config: Box<helios_config::DaemonConfig>,
    },
    PruneDnsCache,
    Shutdown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResponse {
    pub version: u16,
    pub result: ControlResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlResult {
    RouteTest { report: RouteTestReport },
    Status { snapshot: StatusSnapshot },
    RulesUpdated,
    FlowClosed { id: u64 },
    SystemProxyUpdated { enabled: bool },
    ConfigApplied { revision: u64 },
    DnsCachePruned { stats: helios_dns::CacheStats },
    ShutdownAccepted,
    Error { message: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteTestReport {
    pub action: helios_routing::RouteAction,
    pub rule_index: Option<usize>,
    pub resolved_ips: Vec<std::net::IpAddr>,
    pub selected_ips: Vec<std::net::IpAddr>,
    pub dns_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StatusSnapshot {
    #[serde(default)]
    pub desktop_managed: bool,
    #[serde(default)]
    pub system_proxy_enabled: bool,
    #[serde(default)]
    pub system_proxy_verified: bool,
    #[serde(default)]
    pub system_proxy_error: Option<String>,
    #[serde(default)]
    pub config_revision: u64,
    #[serde(default)]
    pub active_server: Option<std::net::SocketAddr>,
    #[serde(default)]
    pub dns_cache: Option<helios_dns::CacheStats>,
    pub state: ConnectionState,
    pub transport: ActiveTransport,
    pub quic_rtt_micros: Option<u64>,
    pub tls_rtt_micros: Option<u64>,
    pub active_flows: u64,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub udp_dropped_packets: u64,
    #[serde(default)]
    pub active_flow_details: Vec<ActiveFlowSnapshot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveFlowSnapshot {
    pub id: u64,
    pub inbound: String,
    pub target: String,
    pub decision: String,
    pub transport: String,
    pub duration_seconds: u64,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Unknown,
    Connected,
    Degraded,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ActiveTransport {
    Quic,
    Tls,
}

pub async fn read_message<T, S>(stream: &mut S) -> Result<T, ControlError>
where
    T: DeserializeOwned,
    S: AsyncRead + Unpin,
{
    let length = stream.read_u32().await? as usize;
    if length > MAX_CONTROL_MESSAGE {
        return Err(ControlError::MessageTooLarge(length));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub async fn write_message<T, S>(stream: &mut S, value: &T) -> Result<(), ControlError>
where
    T: Serialize,
    S: AsyncWrite + Unpin,
{
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_CONTROL_MESSAGE {
        return Err(ControlError::MessageTooLarge(bytes.len()));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("control I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("control JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("control message is too large: {0} bytes")]
    MessageTooLarge(usize),
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn round_trips_a_framed_status_response() {
        let expected = ControlResponse {
            version: CONTROL_VERSION,
            result: ControlResult::Status {
                snapshot: StatusSnapshot {
                    dns_cache: None,
                    desktop_managed: false,
                    system_proxy_enabled: false,
                    system_proxy_verified: false,
                    system_proxy_error: None,
                    config_revision: 0,
                    active_server: None,
                    state: ConnectionState::Connected,
                    transport: ActiveTransport::Quic,
                    quic_rtt_micros: Some(12_345),
                    tls_rtt_micros: Some(20_000),
                    active_flows: 2,
                    uploaded_bytes: 100,
                    downloaded_bytes: 200,
                    udp_dropped_packets: 3,
                    active_flow_details: vec![ActiveFlowSnapshot {
                        id: 7,
                        inbound: "socks5".into(),
                        target: "example.com:443".into(),
                        decision: "proxy".into(),
                        transport: "quic".into(),
                        duration_seconds: 3,
                        uploaded_bytes: 100,
                        downloaded_bytes: 200,
                    }],
                },
            },
        };
        let (mut writer, mut reader) = duplex(1024);
        write_message(&mut writer, &expected).await.unwrap();
        assert_eq!(
            read_message::<ControlResponse, _>(&mut reader)
                .await
                .unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn rejects_oversized_message_before_reading_payload() {
        let (mut writer, mut reader) = duplex(16);
        writer
            .write_u32((MAX_CONTROL_MESSAGE + 1) as u32)
            .await
            .unwrap();
        assert!(matches!(
            read_message::<ControlRequest, _>(&mut reader).await,
            Err(ControlError::MessageTooLarge(length)) if length == MAX_CONTROL_MESSAGE + 1
        ));
    }

    #[tokio::test]
    async fn request_round_trip_preserves_authentication_token() {
        let expected = ControlRequest {
            version: CONTROL_VERSION,
            token: [7; 32],
            command: ControlCommand::GetStatus,
        };
        let (mut writer, mut reader) = duplex(1024);
        write_message(&mut writer, &expected).await.unwrap();
        assert_eq!(
            read_message::<ControlRequest, _>(&mut reader)
                .await
                .unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn request_round_trip_preserves_rule_updates() {
        let expected = ControlRequest {
            version: CONTROL_VERSION,
            token: [3; 32],
            command: ControlCommand::UpdateRules {
                rules: vec![RuleConfig::Final {
                    action: helios_routing::RouteAction::Direct,
                }],
            },
        };
        let (mut writer, mut reader) = duplex(1024);
        write_message(&mut writer, &expected).await.unwrap();
        assert_eq!(
            read_message::<ControlRequest, _>(&mut reader)
                .await
                .unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn request_round_trip_preserves_shutdown() {
        let expected = ControlRequest {
            version: CONTROL_VERSION,
            token: [5; 32],
            command: ControlCommand::Shutdown,
        };
        let (mut writer, mut reader) = duplex(1024);
        write_message(&mut writer, &expected).await.unwrap();
        assert_eq!(
            read_message::<ControlRequest, _>(&mut reader)
                .await
                .unwrap(),
            expected
        );
    }
}
