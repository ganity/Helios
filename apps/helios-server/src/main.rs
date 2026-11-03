use std::{
    env, error::Error, fs::OpenOptions, io::Write, path::PathBuf, sync::Arc, time::Duration,
};

use helios_config::{ServerConfig, load_certificates, load_private_key, load_token};
use helios_protocol::{
    Address, CAP_TCP_CONNECT, CAP_UDP_DATAGRAM, CAP_UDP_OVER_STREAM, Frame, FrameType,
    MAX_UDP_PAYLOAD, Target, UdpAssociate, UdpPacket,
};
use helios_transport::{
    FrameIo, QuicBiStream, ServerCrypto, TlsServer, accept_tcp_frame, authenticate_server,
    serve_control,
};
use quinn::Endpoint;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    time::timeout,
};
use tracing::{debug, info, warn};
use tracing_subscriber::{EnvFilter, fmt::MakeWriter, util::SubscriberInitExt};

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Clone)]
struct Credential {
    id: Arc<str>,
    token: [u8; 32],
}

enum ServerCommand {
    Run(PathBuf),
    Check(PathBuf),
    GenerateToken(PathBuf),
    Version,
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let command = parse_command(env::args())?;
    match command {
        ServerCommand::Check(path) => {
            validate_runtime_config(path)?;
            println!("configuration is valid");
            return Ok(());
        }
        ServerCommand::GenerateToken(path) => {
            generate_token_file(path)?;
            println!("token generated");
            return Ok(());
        }
        ServerCommand::Version => {
            println!("helios-server {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        ServerCommand::Run(path) => run(path).await,
    }
}

async fn run(config_path: PathBuf) -> Result<(), AnyError> {
    init_logging()?;
    let config = ServerConfig::load(config_path)?;
    let certificates = load_certificates(&config.tls.certificate)?;
    let private_key = load_private_key(&config.tls.private_key)?;
    let credential = Credential {
        id: Arc::from(config.auth.id.as_str()),
        token: load_token(&config.auth.token_file)?,
    };
    let crypto = ServerCrypto::new(certificates, private_key)?;
    let tcp_listener = TcpListener::bind(config.listen).await?;
    let quic_endpoint = Endpoint::server(crypto.quic, config.listen)?;
    let sessions = Arc::new(Semaphore::new(config.limits.max_sessions));
    let shutdown_sessions = sessions.clone();
    let max_sessions = config.limits.max_sessions;
    info!(event = "server_listening", listen = %config.listen);

    let (shutdown, _) = watch::channel(false);
    let listeners = async {
        tokio::try_join!(
            run_tls(
                tcp_listener,
                crypto.tls,
                credential.clone(),
                config.limits.handshake_timeout_seconds,
                sessions.clone(),
                shutdown.subscribe(),
            ),
            run_quic(
                quic_endpoint,
                credential,
                config.limits.handshake_timeout_seconds,
                config.limits.max_flows_per_session,
                sessions,
                shutdown.subscribe(),
            ),
        )
    };
    tokio::select! {
        result = listeners => {
            result?;
            drain_sessions(&shutdown_sessions, max_sessions).await;
            Ok::<(), AnyError>(())
        },
        result = shutdown_signal() => {
            result?;
            let _ = shutdown.send(true);
            drain_sessions(&shutdown_sessions, max_sessions).await;
            Ok::<(), AnyError>(())
        }
    }?;
    Ok(())
}

fn validate_runtime_config(path: PathBuf) -> Result<(), AnyError> {
    let config = ServerConfig::load(path)?;
    let certificates = load_certificates(&config.tls.certificate)?;
    let private_key = load_private_key(&config.tls.private_key)?;
    load_token(&config.auth.token_file)?;
    ServerCrypto::new(certificates, private_key)?;
    Ok(())
}

fn generate_token_file(path: PathBuf) -> Result<(), AnyError> {
    let mut token = [0u8; 32];
    getrandom::fill(&mut token)?;
    let encoded = token
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(encoded.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn init_logging() -> Result<(), AnyError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    log_subscriber(filter, std::io::stderr).try_init()?;
    Ok(())
}

fn log_subscriber<S>(
    filter: EnvFilter,
    writer: S,
) -> impl tracing::Subscriber + Send + Sync + 'static
where
    S: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_current_span(false)
        .with_span_list(false)
        .finish()
}

async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

async fn drain_sessions(sessions: &Semaphore, capacity: usize) {
    info!(event = "shutdown_draining", deadline_milliseconds = 2000);
    if !wait_for_sessions(sessions, capacity, Duration::from_secs(2)).await {
        warn!(event = "shutdown_deadline_reached");
    }
}

async fn wait_for_sessions(sessions: &Semaphore, capacity: usize, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if sessions.available_permits() == capacity {
            return true;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return false;
        }
        tokio::time::sleep((deadline - now).min(Duration::from_millis(25))).await;
    }
}

async fn run_tls(
    listener: TcpListener,
    tls: TlsServer,
    credential: Credential,
    handshake_timeout_seconds: u64,
    sessions: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let (stream, _) = tokio::select! {
            accepted = listener.accept() => accepted?,
            changed = shutdown.changed() => {
                changed?;
                return Ok(());
            }
        };
        let permit = tokio::select! {
            permit = sessions.clone().acquire_owned() => permit?,
            changed = shutdown.changed() => {
                changed?;
                return Ok(());
            }
        };
        let tls = tls.clone();
        let credential = credential.clone();
        tokio::spawn(async move {
            if let Err(error) =
                serve_tls_flow(tls, stream, credential, handshake_timeout_seconds, permit).await
            {
                warn!(event = "tls_session_failed");
                debug!(event = "tls_session_error", error = %error);
            }
        });
    }
}

async fn serve_tls_flow(
    tls: TlsServer,
    stream: TcpStream,
    credential: Credential,
    handshake_timeout_seconds: u64,
    _permit: OwnedSemaphorePermit,
) -> Result<(), AnyError> {
    let mut io = timeout(Duration::from_secs(handshake_timeout_seconds), async {
        let mut io = tls.accept(stream).await?;
        authenticate_server(&mut io, CAP_TCP_CONNECT | CAP_UDP_OVER_STREAM, |id| {
            (id == credential.id.as_ref()).then_some(credential.token)
        })
        .await?;
        Ok::<_, AnyError>(io)
    })
    .await??;
    let frame = io.read_frame().await?;
    if frame.frame_type == FrameType::Ping {
        io.write_frame(&Frame::new(
            FrameType::Pong,
            frame.request_id,
            frame.payload,
        )?)
        .await?;
        return Ok(());
    }
    if frame.frame_type == FrameType::UdpAssociate {
        return serve_udp_stream(io, frame).await;
    }
    let (mut client, mut target) = accept_tcp_frame(io, frame).await?;
    copy_bidirectional(&mut client, &mut target).await?;
    Ok(())
}

async fn run_quic(
    endpoint: Endpoint,
    credential: Credential,
    handshake_timeout_seconds: u64,
    max_flows_per_session: usize,
    sessions: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        };
        let incoming = tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { return Ok(()); };
                incoming
            }
            changed = shutdown.changed() => {
                changed?;
                return Ok(());
            }
        };
        let permit = tokio::select! {
            permit = sessions.clone().acquire_owned() => permit?,
            changed = shutdown.changed() => {
                changed?;
                incoming.refuse();
                return Ok(());
            }
        };
        let credential = credential.clone();
        tokio::spawn(async move {
            match timeout(
                Duration::from_secs(handshake_timeout_seconds),
                authenticate_quic(incoming, credential),
            )
            .await
            {
                Ok(Ok((connection, control))) => {
                    serve_quic_session(connection, control, max_flows_per_session, permit).await;
                }
                Ok(Err(error)) => {
                    warn!(event = "quic_session_failed");
                    debug!(event = "quic_session_error", error = %error);
                }
                Err(_) => warn!(event = "quic_handshake_timeout"),
            }
        });
    }
}

async fn authenticate_quic(
    incoming: quinn::Incoming,
    credential: Credential,
) -> Result<(quinn::Connection, FrameIo<QuicBiStream>), AnyError> {
    let connection = incoming.await?;
    let (send, recv) = connection.accept_bi().await?;
    let mut control = FrameIo::new(QuicBiStream::new(send, recv));
    authenticate_server(
        &mut control,
        CAP_TCP_CONNECT | CAP_UDP_DATAGRAM | CAP_UDP_OVER_STREAM,
        |id| (id == credential.id.as_ref()).then_some(credential.token),
    )
    .await?;
    Ok((connection, control))
}

async fn serve_udp_stream<S>(mut io: FrameIo<S>, first: Frame) -> Result<(), AnyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let _request = UdpAssociate::decode(&first.payload)?;
    let association_id = first.request_id.max(1);
    io.write_frame(&Frame::new(
        FrameType::UdpAssociateOk,
        first.request_id,
        association_id.to_be_bytes().to_vec(),
    )?)
    .await?;
    loop {
        let frame = io.read_frame().await?;
        if frame.frame_type == FrameType::Close {
            return Ok(());
        }
        if frame.frame_type != FrameType::UdpPacket {
            continue;
        }
        let packet = UdpPacket::decode(&frame.payload)?;
        if packet.association_id != association_id {
            continue;
        }
        let destination = match &packet.target.address {
            Address::Ip(ip) => std::net::SocketAddr::new(*ip, packet.target.port),
            Address::Domain(domain) => {
                let Some(address) = tokio::net::lookup_host((domain.as_str(), packet.target.port))
                    .await?
                    .next()
                else {
                    continue;
                };
                address
            }
        };
        let bind_address = if destination.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_address).await?;
        socket.send_to(&packet.payload, destination).await?;
        let mut buffer = vec![0u8; MAX_UDP_PAYLOAD];
        let Ok((length, source)) =
            timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await?
        else {
            continue;
        };
        let target = Target::new(Address::Ip(source.ip()), source.port())?;
        let response = UdpPacket::new(
            association_id,
            packet.packet_id,
            target,
            buffer[..length].to_vec(),
        )?;
        io.write_frame(&Frame::new(
            FrameType::UdpPacket,
            frame.request_id,
            response.encode()?,
        )?)
        .await?;
    }
}

async fn serve_quic_session(
    connection: quinn::Connection,
    control: FrameIo<QuicBiStream>,
    max_flows: usize,
    _session_permit: OwnedSemaphorePermit,
) {
    tokio::select! {
        result = serve_control(control) => {
            if let Err(error) = result {
                warn!(event = "quic_control_failed");
                debug!(event = "quic_control_error", error = %error);
            }
        }
        _ = serve_quic_flows(connection.clone(), max_flows) => {}
    }
    connection.close(0u32.into(), b"control session ended");
}

async fn serve_quic_flows(connection: quinn::Connection, max_flows: usize) {
    let flows = Arc::new(Semaphore::new(max_flows));
    loop {
        let Ok((send, recv)) = connection.accept_bi().await else {
            return;
        };
        let Ok(permit) = flows.clone().try_acquire_owned() else {
            drop((send, recv));
            continue;
        };
        let connection = connection.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let io = FrameIo::new(QuicBiStream::new(send, recv));
            match serve_quic_flow(io, connection).await {
                Ok(()) => {}
                Err(error) => {
                    warn!(event = "quic_flow_setup_failed");
                    debug!(event = "quic_flow_setup_error", error = %error);
                }
            }
        });
    }
}

async fn serve_quic_flow(
    mut io: FrameIo<QuicBiStream>,
    connection: quinn::Connection,
) -> Result<(), AnyError> {
    let first = io.read_frame().await?;
    if first.frame_type == FrameType::UdpAssociate {
        let _request = UdpAssociate::decode(&first.payload)?;
        let association_id = first.request_id.max(1);
        io.write_frame(&Frame::new(
            FrameType::UdpAssociateOk,
            first.request_id,
            association_id.to_be_bytes().to_vec(),
        )?)
        .await?;
        let packets = Arc::new(Semaphore::new(64));
        loop {
            tokio::select! {
                result = io.read_frame() => {
                    if result.is_err() { return Ok(()); }
                    let frame = result?;
                    if frame.frame_type == FrameType::Close { return Ok(()); }
                }
                result = connection.read_datagram() => {
                    let Ok(data) = result else { return Ok(()); };
                    let Ok(packet) = UdpPacket::decode(&data) else { continue; };
                    if packet.association_id != association_id || packet.payload.len() > MAX_UDP_PAYLOAD { continue; }
                    let Ok(permit) = packets.clone().try_acquire_owned() else { continue; };
                    let connection = connection.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let destination = match &packet.target.address {
                            Address::Ip(ip) => std::net::SocketAddr::new(*ip, packet.target.port),
                            Address::Domain(domain) => match tokio::net::lookup_host((domain.as_str(), packet.target.port)).await.ok().and_then(|mut values| values.next()) { Some(address) => address, None => return },
                        };
                        let bind_address = if destination.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                        let Ok(socket) = UdpSocket::bind(bind_address).await else { return; };
                        if socket.send_to(&packet.payload, destination).await.is_err() { return; }
                        let mut buffer = vec![0u8; MAX_UDP_PAYLOAD];
                        let Ok(Ok((length, source))) = timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await else { return; };
                        let Ok(target) = Target::new(Address::Ip(source.ip()), source.port()) else { return; };
                        let Ok(response) = UdpPacket::new(association_id, packet.packet_id, target, buffer[..length].to_vec()).and_then(|value| value.encode()) else { return; };
                        let _ = connection.send_datagram(bytes::Bytes::from(response));
                    });
                }
            }
        }
    } else {
        match accept_tcp_frame(io, first).await {
            Ok((mut client, mut target)) => {
                if let Err(error) = copy_bidirectional(&mut client, &mut target).await {
                    warn!(event = "quic_flow_relay_failed");
                    debug!(event = "quic_flow_relay_error", error = %error);
                }
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

fn parse_command(values: impl IntoIterator<Item = String>) -> Result<ServerCommand, AnyError> {
    let values = values.into_iter().collect::<Vec<_>>();
    match values.as_slice() {
        [_, command] if command == "version" || command == "--version" => {
            Ok(ServerCommand::Version)
        }
        [_, path] => Ok(ServerCommand::Run(PathBuf::from(path))),
        [_, command, flag, path] if command == "run" && flag == "--config" => {
            Ok(ServerCommand::Run(PathBuf::from(path)))
        }
        [_, command, flag, path] if command == "check" && flag == "--config" => {
            Ok(ServerCommand::Check(PathBuf::from(path)))
        }
        [_, parent, command, flag, path]
            if parent == "credential" && command == "generate" && flag == "--output" =>
        {
            Ok(ServerCommand::GenerateToken(PathBuf::from(path)))
        }
        _ => Err("usage: helios-server CONFIG_TOML | run --config PATH | check --config PATH | credential generate --output TOKEN_FILE | version".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio::io::duplex;

    use super::*;

    #[derive(Clone, Default)]
    struct TestWriter(Arc<Mutex<Vec<u8>>>);

    struct TestGuard(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for TestGuard {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for TestWriter {
        type Writer = TestGuard;

        fn make_writer(&'writer self) -> Self::Writer {
            TestGuard(self.0.clone())
        }
    }

    #[test]
    fn parses_legacy_and_explicit_server_commands() {
        assert!(matches!(
            parse_command(["helios-server".into(), "server.toml".into()]).unwrap(),
            ServerCommand::Run(path) if path.as_os_str() == "server.toml"
        ));
        assert!(matches!(
            parse_command([
                "helios-server".into(),
                "check".into(),
                "--config".into(),
                "server.toml".into()
            ])
            .unwrap(),
            ServerCommand::Check(_)
        ));
        assert!(matches!(
            parse_command(["helios-server".into(), "version".into()]).unwrap(),
            ServerCommand::Version
        ));
        assert!(parse_command(["helios-server".into()]).is_err());
    }

    #[test]
    fn generated_token_is_private_and_never_overwritten() {
        let path =
            std::env::temp_dir().join(format!("helios-server-token-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        generate_token_file(path.clone()).unwrap();
        let token = std::fs::read_to_string(&path).unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(generate_token_file(path.clone()).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), token);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn default_logs_are_json_and_hide_debug_details() {
        let writer = TestWriter::default();
        tracing::subscriber::with_default(
            log_subscriber(EnvFilter::new("info"), writer.clone()),
            || {
                info!(event = "visible");
                debug!(event = "hidden", error = "sensitive.example");
            },
        );
        let bytes = writer.0.lock().unwrap().clone();
        let output = String::from_utf8(bytes).unwrap();
        let value: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(value["fields"]["event"], "visible");
        assert!(!output.contains("sensitive.example"));
    }

    #[tokio::test]
    async fn shutdown_drain_finishes_early_or_at_deadline() {
        let sessions = Arc::new(Semaphore::new(2));
        assert!(wait_for_sessions(&sessions, 2, Duration::from_secs(1)).await);

        let permit = sessions.clone().acquire_owned().await.unwrap();
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            drop(permit);
        });
        let started = tokio::time::Instant::now();
        assert!(wait_for_sessions(&sessions, 2, Duration::from_secs(1)).await);
        assert!(started.elapsed() < Duration::from_millis(500));
        release.await.unwrap();

        let _permit = sessions.clone().acquire_owned().await.unwrap();
        let started = tokio::time::Instant::now();
        assert!(!wait_for_sessions(&sessions, 2, Duration::from_millis(40)).await);
        assert!(started.elapsed() >= Duration::from_millis(40));
    }

    #[tokio::test]
    async fn udp_over_stream_relays_a_real_datagram() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0; 64];
            let (length, peer) = echo.recv_from(&mut buffer).await.unwrap();
            echo.send_to(&buffer[..length], peer).await.unwrap();
        });
        let (client, server) = duplex(16 * 1024);
        let first = Frame::new(
            FrameType::UdpAssociate,
            7,
            UdpAssociate { target: None }.encode().unwrap(),
        )
        .unwrap();
        let server_task = tokio::spawn(serve_udp_stream(FrameIo::new(server), first));
        let mut client = FrameIo::new(client);
        let accepted = client.read_frame().await.unwrap();
        assert_eq!(accepted.frame_type, FrameType::UdpAssociateOk);
        let packet = UdpPacket::new(
            7,
            9,
            Target::new(Address::Ip(echo_address.ip()), echo_address.port()).unwrap(),
            b"tls-udp".to_vec(),
        )
        .unwrap();
        client
            .write_frame(&Frame::new(FrameType::UdpPacket, 9, packet.encode().unwrap()).unwrap())
            .await
            .unwrap();
        let response = client.read_frame().await.unwrap();
        assert_eq!(response.frame_type, FrameType::UdpPacket);
        let response = UdpPacket::decode(&response.payload).unwrap();
        assert_eq!(response.association_id, 7);
        assert_eq!(response.packet_id, 9);
        assert_eq!(response.payload, b"tls-udp");
        client
            .write_frame(&Frame::new(FrameType::Close, 10, Vec::new()).unwrap())
            .await
            .unwrap();
        server_task.await.unwrap().unwrap();
        echo_task.await.unwrap();
    }
}
