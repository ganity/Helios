use std::{
    io::{Error as IoError, ErrorKind},
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use helios_config::{ConfigError, NodeConfig, TransportPreference, load_roots, load_token};
use helios_control::{
    CONTROL_VERSION, ControlCommand, ControlError, ControlRequest, ControlResponse, ControlResult,
    StatusSnapshot, read_message, write_message,
};
use helios_protocol::CAP_TCP_CONNECT;
use helios_routing::RuleConfig;
use helios_transport::{ClientCrypto, FrameIo, QuicBiStream, authenticate_client, ping};
use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

trait ControlIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ControlIo for T {}
type ControlStream = Box<dyn ControlIo>;
pub type ProbeError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Debug)]
pub struct ProbeMeasurement {
    /// Transport connection plus authenticated application handshake, excluding PING.
    pub handshake: Duration,
    pub rtt: Duration,
}

#[derive(Clone, Debug)]
pub struct NodeProbeReport {
    pub checked_at_unix_ms: u128,
    pub quic: Result<ProbeMeasurement, String>,
    pub tls: Result<ProbeMeasurement, String>,
}

pub async fn probe_transports(node: NodeConfig) -> NodeProbeReport {
    let mut quic = node.clone();
    quic.preferred_transport = TransportPreference::Quic;
    let mut tls = node;
    tls.preferred_transport = TransportPreference::Tls;
    let (quic, tls) = tokio::join!(measure_node(quic), measure_node(tls));
    NodeProbeReport {
        checked_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        quic: quic.map_err(|error| error.to_string()),
        tls: tls.map_err(|error| error.to_string()),
    }
}

pub async fn probe_node(node: NodeConfig) -> Result<Duration, ProbeError> {
    Ok(measure_node(node).await?.rtt)
}

async fn measure_node(node: NodeConfig) -> Result<ProbeMeasurement, ProbeError> {
    tokio::time::timeout(Duration::from_secs(10), probe_node_inner(node))
        .await
        .map_err(|_| IoError::new(ErrorKind::TimedOut, "node probe exceeded 10 seconds"))?
}

async fn probe_node_inner(node: NodeConfig) -> Result<ProbeMeasurement, ProbeError> {
    let roots = load_roots(&node.ca_certificate)?;
    let token = load_token(&node.token_file)?;
    let crypto = ClientCrypto::new(roots)?;
    let server_name = ServerName::try_from(node.server_name.clone())?;
    let started = Instant::now();
    match node.preferred_transport {
        TransportPreference::Tls => {
            let tcp = tokio::time::timeout(
                Duration::from_secs(5),
                helios_transport::connect_node_tcp(node.server),
            )
            .await??;
            let mut io = crypto.tls.connect(server_name, tcp).await?;
            authenticate_client(&mut io, &node.credential_id, &token, CAP_TCP_CONNECT).await?;
            let handshake = started.elapsed();
            let rtt = ping(&mut io, 700, b"desktop-probe").await?;
            Ok(ProbeMeasurement { handshake, rtt })
        }
        TransportPreference::Quic => {
            let mut endpoint = helios_transport::client_quic_endpoint(node.server)?;
            endpoint.set_default_client_config(crypto.quic);
            let connection = tokio::time::timeout(
                Duration::from_secs(5),
                endpoint
                    .connect(node.server, &node.server_name)?
                    .into_future(),
            )
            .await??;
            let (send, recv) = connection.open_bi().await?;
            let mut io = FrameIo::new(QuicBiStream::new(send, recv));
            authenticate_client(&mut io, &node.credential_id, &token, CAP_TCP_CONNECT).await?;
            let handshake = started.elapsed();
            let rtt = ping(&mut io, 700, b"desktop-probe").await?;
            connection.close(0u32.into(), b"probe complete");
            Ok(ProbeMeasurement { handshake, rtt })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonPresence {
    Offline,
    Authenticated,
    Occupied,
}

#[derive(Clone, Debug)]
pub struct DaemonClient {
    #[cfg(not(windows))]
    address: SocketAddr,
    #[cfg(unix)]
    local_socket: Option<PathBuf>,
    token_file: PathBuf,
}

impl DaemonClient {
    pub fn new(address: SocketAddr, local_socket: Option<PathBuf>, token_file: PathBuf) -> Self {
        #[cfg(windows)]
        let _ = address;
        #[cfg(not(unix))]
        let _ = local_socket;
        Self {
            #[cfg(not(windows))]
            address,
            #[cfg(unix)]
            local_socket,
            token_file,
        }
    }

    pub async fn status(&self) -> Result<StatusSnapshot, ClientControlError> {
        match self.request(ControlCommand::GetStatus).await? {
            ControlResult::Status { snapshot } => Ok(snapshot),
            ControlResult::Error { message } => Err(ClientControlError::Remote(message)),
            _ => Err(ClientControlError::UnexpectedResponse),
        }
    }

    pub async fn update_rules(&self, rules: Vec<RuleConfig>) -> Result<(), ClientControlError> {
        match self.request(ControlCommand::UpdateRules { rules }).await? {
            ControlResult::RulesUpdated => Ok(()),
            ControlResult::Error { message } => Err(ClientControlError::Remote(message)),
            _ => Err(ClientControlError::UnexpectedResponse),
        }
    }

    pub async fn shutdown(&self) -> Result<(), ClientControlError> {
        match self.request(ControlCommand::Shutdown).await? {
            ControlResult::ShutdownAccepted => Ok(()),
            ControlResult::Error { message } => Err(ClientControlError::Remote(message)),
            _ => Err(ClientControlError::UnexpectedResponse),
        }
    }

    pub async fn close_flow(&self, id: u64) -> Result<(), ClientControlError> {
        match self.request(ControlCommand::CloseFlow { id }).await? {
            ControlResult::FlowClosed { id: actual } if actual == id => Ok(()),
            ControlResult::Error { message } => Err(ClientControlError::Remote(message)),
            _ => Err(ClientControlError::UnexpectedResponse),
        }
    }

    pub async fn set_system_proxy(&self, enabled: bool) -> Result<bool, ClientControlError> {
        match self
            .request(ControlCommand::SetSystemProxy { enabled })
            .await?
        {
            ControlResult::SystemProxyUpdated { enabled } => Ok(enabled),
            ControlResult::Error { message } => Err(ClientControlError::Remote(message)),
            _ => Err(ClientControlError::UnexpectedResponse),
        }
    }

    pub async fn prune_dns_cache(
        &self,
    ) -> Result<helios_control::StatusSnapshot, ClientControlError> {
        match self.request(ControlCommand::PruneDnsCache).await? {
            ControlResult::DnsCachePruned { .. } => self.status().await,
            ControlResult::Error { message } => Err(ClientControlError::Remote(message)),
            _ => Err(ClientControlError::UnexpectedResponse),
        }
    }

    pub async fn apply_config(
        &self,
        expected_revision: u64,
        config: helios_config::DaemonConfig,
    ) -> Result<u64, ClientControlError> {
        match self
            .request(ControlCommand::ApplyConfig {
                expected_revision,
                config: Box::new(config),
            })
            .await?
        {
            ControlResult::ConfigApplied { revision } => Ok(revision),
            ControlResult::Error { message } => Err(ClientControlError::Remote(message)),
            _ => Err(ClientControlError::UnexpectedResponse),
        }
    }

    pub async fn presence(&self) -> Result<DaemonPresence, ClientControlError> {
        let mut stream =
            match tokio::time::timeout(Duration::from_millis(500), self.connect()).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) if is_offline_error(&error) => return Ok(DaemonPresence::Offline),
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => return Err(ClientControlError::Timeout),
            };
        let token = load_token(&self.token_file)?;
        if write_message(
            &mut stream,
            &ControlRequest {
                version: CONTROL_VERSION,
                token,
                command: ControlCommand::GetStatus,
            },
        )
        .await
        .is_err()
        {
            return Ok(DaemonPresence::Occupied);
        }
        let response = tokio::time::timeout(
            Duration::from_millis(500),
            read_message::<ControlResponse, _>(&mut stream),
        )
        .await;
        Ok(match response {
            Ok(Ok(ControlResponse {
                version,
                result: ControlResult::Status { .. },
            })) if version == CONTROL_VERSION => DaemonPresence::Authenticated,
            _ => DaemonPresence::Occupied,
        })
    }

    async fn request(&self, command: ControlCommand) -> Result<ControlResult, ClientControlError> {
        let deadline = match &command {
            ControlCommand::ApplyConfig { .. } => Duration::from_secs(30),
            ControlCommand::SetSystemProxy { .. } => Duration::from_secs(15),
            _ => Duration::from_secs(2),
        };
        let token = load_token(&self.token_file)?;
        let mut stream = tokio::time::timeout(Duration::from_secs(1), self.connect())
            .await
            .map_err(|_| ClientControlError::Timeout)??;
        write_message(
            &mut stream,
            &ControlRequest {
                version: CONTROL_VERSION,
                token,
                command,
            },
        )
        .await?;
        let response: ControlResponse = tokio::time::timeout(deadline, read_message(&mut stream))
            .await
            .map_err(|_| ClientControlError::Timeout)??;
        if response.version != CONTROL_VERSION {
            return Err(ClientControlError::UnexpectedResponse);
        }
        Ok(response.result)
    }

    async fn connect(&self) -> Result<ControlStream, IoError> {
        #[cfg(windows)]
        {
            Ok(Box::new(
                tokio::net::windows::named_pipe::ClientOptions::new()
                    .open(r"\.\pipe\helios-control")?,
            ))
        }
        #[cfg(not(windows))]
        {
            #[cfg(unix)]
            if let Some(path) = &self.local_socket {
                return Ok(Box::new(tokio::net::UnixStream::connect(path).await?));
            }
            Ok(Box::new(
                tokio::net::TcpStream::connect(self.address).await?,
            ))
        }
    }
}

fn is_offline_error(error: &IoError) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::AddrNotAvailable | ErrorKind::NotFound
    )
}

#[derive(Debug, Error)]
pub enum ClientControlError {
    #[error("control configuration is invalid: {0}")]
    Config(#[from] ConfigError),
    #[error("control connection failed: {0}")]
    Io(#[from] IoError),
    #[error("control protocol failed: {0}")]
    Protocol(#[from] ControlError),
    #[error("control request timed out")]
    Timeout,
    #[error("daemon rejected the request: {0}")]
    Remote(String),
    #[error("daemon returned an unexpected control response")]
    UnexpectedResponse,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use base64::{Engine, engine::general_purpose::STANDARD};
    use helios_config::TransportPreference;
    use helios_control::{ActiveTransport, ConnectionState};
    use helios_protocol::CAP_TCP_CONNECT;
    use helios_transport::{ServerCrypto, authenticate_server, serve_control};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;

    use super::*;

    static NEXT_TOKEN_FILE: AtomicU64 = AtomicU64::new(0);

    fn token_file() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "helios-client-control-{}-{}",
            std::process::id(),
            NEXT_TOKEN_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, "07".repeat(32)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    #[tokio::test]
    async fn status_uses_authenticated_bounded_control_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request: ControlRequest = read_message(&mut stream).await.unwrap();
            assert_eq!(request.token, [7; 32]);
            write_message(
                &mut stream,
                &ControlResponse {
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
                            quic_rtt_micros: Some(1_000),
                            tls_rtt_micros: None,
                            active_flows: 0,
                            uploaded_bytes: 10,
                            downloaded_bytes: 20,
                            udp_dropped_packets: 0,
                            active_flow_details: Vec::new(),
                        },
                    },
                },
            )
            .await
            .unwrap();
        });
        let token = token_file();
        let snapshot = DaemonClient::new(address, None, token.clone())
            .status()
            .await
            .unwrap();
        assert_eq!(snapshot.state, ConnectionState::Connected);
        server.await.unwrap();
        std::fs::remove_file(token).unwrap();
    }

    #[tokio::test]
    async fn presence_distinguishes_offline_from_occupied() {
        let token = token_file();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::AsyncWriteExt;
            stream.write_all(b"not-helios").await.unwrap();
        });
        assert_eq!(
            DaemonClient::new(address, None, token.clone())
                .presence()
                .await
                .unwrap(),
            DaemonPresence::Occupied
        );
        server.await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unused = listener.local_addr().unwrap();
        drop(listener);
        assert_eq!(
            DaemonClient::new(unused, None, token.clone())
                .presence()
                .await
                .unwrap(),
            DaemonPresence::Offline
        );
        std::fs::remove_file(token).unwrap();
    }

    #[tokio::test]
    async fn probe_times_out_when_peer_accepts_but_never_sends_tls() {
        let CertifiedKey { cert, .. } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let token = token_file();
        let certificate = token.with_extension("pem");
        std::fs::write(
            &certificate,
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                STANDARD.encode(cert.der())
            ),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let result = tokio::time::timeout(
            Duration::from_secs(12),
            probe_node(NodeConfig {
                server: address,
                server_name: "localhost".into(),
                ca_certificate: certificate.clone(),
                credential_id: "desktop-probe".into(),
                token_file: token.clone(),
                preferred_transport: TransportPreference::Tls,
            }),
        )
        .await
        .expect("probe must enforce its own deadline");
        server.abort();
        assert_eq!(
            result
                .unwrap_err()
                .downcast_ref::<IoError>()
                .unwrap()
                .kind(),
            ErrorKind::TimedOut
        );
        std::fs::remove_file(token).unwrap();
        std::fs::remove_file(certificate).unwrap();
    }

    #[tokio::test]
    async fn probe_performs_tls_authentication_and_ping() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = ServerCrypto::new(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let token = token_file();
        let certificate = token.with_extension("pem");
        let encoded = STANDARD.encode(cert.der());
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            encoded
                .as_bytes()
                .chunks(64)
                .map(|line| std::str::from_utf8(line).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        );
        std::fs::write(&certificate, pem).unwrap();
        let endpoint = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut io = server.tls.accept(tcp).await.unwrap();
                authenticate_server(&mut io, CAP_TCP_CONNECT, |id| {
                    (id == "probe").then_some([7; 32])
                })
                .await
                .unwrap();
                serve_control(io).await.unwrap_err();
            }
        });

        let elapsed = probe_node(NodeConfig {
            server: address,
            server_name: "localhost".into(),
            ca_certificate: certificate.clone(),
            credential_id: "probe".into(),
            token_file: token.clone(),
            preferred_transport: TransportPreference::Tls,
        })
        .await
        .unwrap();

        assert!(elapsed < Duration::from_secs(1));
        let report = probe_transports(NodeConfig {
            server: address,
            server_name: "localhost".into(),
            ca_certificate: certificate.clone(),
            credential_id: "probe".into(),
            token_file: token.clone(),
            preferred_transport: TransportPreference::Quic,
        })
        .await;
        assert!(report.quic.is_err(), "no UDP listener exists");
        let tls = report.tls.unwrap();
        assert!(tls.handshake > Duration::ZERO);
        assert!(tls.rtt < Duration::from_secs(1));
        assert!(report.checked_at_unix_ms > 0);
        endpoint.await.unwrap();
        std::fs::remove_file(token).unwrap();
        std::fs::remove_file(certificate).unwrap();
    }
}
