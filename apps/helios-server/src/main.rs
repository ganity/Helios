use std::{
    env,
    error::Error,
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use helios_config::{
    ConnectionLink, ServerConfig, TransportPreference, load_certificates, load_private_key,
    load_token,
};
use helios_protocol::{
    Address, CAP_TCP_CONNECT, CAP_UDP_DATAGRAM, CAP_UDP_LARGE_STREAM, CAP_UDP_OVER_STREAM, Frame,
    FrameType, MAX_UDP_PAYLOAD, MAX_UDP_STREAM_PAYLOAD, Target, UdpAssociate, UdpPacket,
};
use helios_transport::{
    ClientCrypto, FrameIo, QuicBiStream, ServerCrypto, TlsServer, accept_tcp_frame,
    authenticate_server, serve_control,
};
use quinn::Endpoint;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use rustls::{RootCertStore, pki_types::ServerName};
use socket2::{Domain, Protocol, Socket, Type};
use time::OffsetDateTime;
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

#[derive(Clone)]
struct ListenerServices {
    tls: TlsServer,
    credential: Credential,
    handshake_timeout_seconds: u64,
    max_flows_per_session: usize,
    sessions: Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
}

enum ServerCommand {
    Run(PathBuf),
    Check(PathBuf),
    GenerateToken(PathBuf),
    GenerateIdentity(PathBuf),
    ClientLink {
        config: PathBuf,
        address: SocketAddr,
        server_name: String,
        name: String,
    },
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
        ServerCommand::GenerateIdentity(path) => {
            let server_name = generate_identity(&path)?;
            println!("{server_name}");
            return Ok(());
        }
        ServerCommand::ClientLink {
            config,
            address,
            server_name,
            name,
        } => {
            println!(
                "{}",
                generate_client_link(config, address, server_name, name).await?
            );
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
    let tcp_listener = bind_tcp_listener(config.listen, false)?;
    let quic_endpoint = server_quic_endpoint(crypto.quic.clone(), config.listen, false)?;
    let ipv6_listener = if let Some(address) = config.listen_ipv6 {
        Some((
            bind_tcp_listener(address, true)?,
            server_quic_endpoint(crypto.quic.clone(), address, true)?,
            address,
        ))
    } else {
        None
    };
    let sessions = Arc::new(Semaphore::new(config.limits.max_sessions));
    let shutdown_sessions = sessions.clone();
    let max_sessions = config.limits.max_sessions;
    info!(event = "server_listening", listen = %config.listen);
    if let Some((_, _, address)) = &ipv6_listener {
        info!(event = "server_listening", listen = %address);
    }

    let (shutdown, _) = watch::channel(false);
    let listeners = async {
        let services = ListenerServices {
            tls: crypto.tls,
            credential,
            handshake_timeout_seconds: config.limits.handshake_timeout_seconds,
            max_flows_per_session: config.limits.max_flows_per_session,
            sessions,
            shutdown: shutdown.subscribe(),
        };
        let primary = run_listener_pair(tcp_listener, quic_endpoint, services.clone());
        if let Some((tcp_listener, quic_endpoint, _)) = ipv6_listener {
            tokio::try_join!(
                primary,
                run_listener_pair(tcp_listener, quic_endpoint, services)
            )?;
            Ok(())
        } else {
            primary.await
        }
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

fn bind_tcp_listener(address: SocketAddr, ipv6_only: bool) -> std::io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if ipv6_only {
        socket.set_only_v6(true)?;
    }
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

fn bind_udp_socket(address: SocketAddr, ipv6_only: bool) -> std::io::Result<std::net::UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if ipv6_only {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(socket.into())
}

fn server_quic_endpoint(
    config: quinn::ServerConfig,
    address: SocketAddr,
    ipv6_only: bool,
) -> std::io::Result<Endpoint> {
    Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        bind_udp_socket(address, ipv6_only)?,
        Arc::new(quinn::TokioRuntime),
    )
}

async fn run_listener_pair(
    tcp_listener: TcpListener,
    quic_endpoint: Endpoint,
    services: ListenerServices,
) -> Result<(), AnyError> {
    tokio::try_join!(
        run_tls(
            tcp_listener,
            services.tls,
            services.credential.clone(),
            services.handshake_timeout_seconds,
            services.sessions.clone(),
            services.shutdown.clone(),
        ),
        run_quic(
            quic_endpoint,
            services.credential,
            services.handshake_timeout_seconds,
            services.max_flows_per_session,
            services.sessions,
            services.shutdown,
        ),
    )?;
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

fn generate_identity(output: &Path) -> Result<String, AnyError> {
    if output.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "identity output already exists",
        )
        .into());
    }
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)?;
    let id = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let server_name = format!("node-{id}.helios.invalid");
    let mut params = CertificateParams::new(vec![server_name.clone()])?;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365 * 5);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, server_name.clone());
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;

    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(".helios-identity-{id}.tmp"));
    std::fs::create_dir(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o700))?;
    }
    let result = (|| -> Result<(), AnyError> {
        write_new_file(
            &temporary.join("cert.pem"),
            encode_pem("CERTIFICATE", certificate.der()).as_bytes(),
            0o644,
        )?;
        write_new_file(
            &temporary.join("key.pem"),
            encode_pem("PRIVATE KEY", &key.serialize_der()).as_bytes(),
            0o600,
        )?;
        write_new_file(
            &temporary.join("server-name.txt"),
            server_name.as_bytes(),
            0o644,
        )?;
        std::fs::rename(&temporary, output)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&temporary);
    }
    result?;
    Ok(server_name)
}

fn encode_pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), AnyError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

async fn generate_client_link(
    config_path: PathBuf,
    address: SocketAddr,
    server_name: String,
    name: String,
) -> Result<String, AnyError> {
    let config = ServerConfig::load(config_path)?;
    let certificates = load_certificates(&config.tls.certificate)?;
    let trust_anchor = certificates
        .last()
        .cloned()
        .ok_or("server certificate file is empty")?;
    let private_key = load_private_key(&config.tls.private_key)?;
    let server_crypto = ServerCrypto::new(certificates, private_key)?;
    let mut roots = RootCertStore::empty();
    roots.add(trust_anchor.clone())?;
    let client_crypto = ClientCrypto::new(roots)?;
    let tls_name = ServerName::try_from(server_name.clone())?;
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let (client_result, server_result) = tokio::join!(
        client_crypto.tls.connect(tls_name, client_io),
        server_crypto.tls.accept(server_io),
    );
    client_result?;
    server_result?;

    let link = ConnectionLink::new(
        name,
        address,
        server_name,
        trust_anchor.as_ref(),
        config.auth.id,
        load_token(&config.auth.token_file)?,
        TransportPreference::Tls,
    )?;
    Ok(link.encode()?)
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
    let (mut io, capabilities) = timeout(Duration::from_secs(handshake_timeout_seconds), async {
        helios_transport::configure_tcp(&stream)?;
        let mut io = tls.accept(stream).await?;
        let session = authenticate_server(
            &mut io,
            CAP_TCP_CONNECT | CAP_UDP_OVER_STREAM | CAP_UDP_LARGE_STREAM,
            |id| (id == credential.id.as_ref()).then_some(credential.token),
        )
        .await?;
        Ok::<_, AnyError>((io, session.capabilities))
    })
    .await??;
    let frame = timeout(
        Duration::from_secs(handshake_timeout_seconds),
        io.read_frame(),
    )
    .await??;
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
        return serve_udp_stream(io, frame, capabilities).await;
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
                Ok(Ok((connection, control, capabilities))) => {
                    serve_quic_session(
                        connection,
                        control,
                        capabilities,
                        max_flows_per_session,
                        permit,
                    )
                    .await;
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
) -> Result<(quinn::Connection, FrameIo<QuicBiStream>, u32), AnyError> {
    let connection = incoming.await?;
    let (send, recv) = connection.accept_bi().await?;
    let mut control = FrameIo::new(QuicBiStream::new(send, recv));
    let session = authenticate_server(
        &mut control,
        CAP_TCP_CONNECT | CAP_UDP_DATAGRAM | CAP_UDP_OVER_STREAM | CAP_UDP_LARGE_STREAM,
        |id| (id == credential.id.as_ref()).then_some(credential.token),
    )
    .await?;
    Ok((connection, control, session.capabilities))
}

async fn serve_udp_stream<S>(
    mut io: FrameIo<S>,
    first: Frame,
    capabilities: u32,
) -> Result<(), AnyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let limit = if capabilities & CAP_UDP_LARGE_STREAM != 0 {
        MAX_UDP_STREAM_PAYLOAD
    } else {
        MAX_UDP_PAYLOAD
    };
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
        let packet = UdpPacket::decode_with_limit(&frame.payload, limit)?;
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
        let mut buffer = vec![0u8; limit + 1];
        let Ok((length, source)) =
            timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await?
        else {
            continue;
        };
        if length > limit {
            continue;
        }
        let target = Target::new(Address::Ip(source.ip()), source.port())?;
        let response = UdpPacket::new_with_limit(
            association_id,
            packet.packet_id,
            target,
            buffer[..length].to_vec(),
            limit,
        )?;
        io.write_frame(&Frame::new(
            FrameType::UdpPacket,
            frame.request_id,
            response.encode_with_limit(limit)?,
        )?)
        .await?;
    }
}

async fn serve_quic_session(
    connection: quinn::Connection,
    control: FrameIo<QuicBiStream>,
    capabilities: u32,
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
        _ = serve_quic_flows(connection.clone(), capabilities, max_flows) => {}
    }
    connection.close(0u32.into(), b"control session ended");
}

async fn serve_quic_flows(connection: quinn::Connection, capabilities: u32, max_flows: usize) {
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
            match serve_quic_flow(io, connection, capabilities).await {
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
    capabilities: u32,
) -> Result<(), AnyError> {
    let first = io.read_frame().await?;
    if first.frame_type == FrameType::UdpAssociate {
        if capabilities & CAP_UDP_LARGE_STREAM != 0 {
            return serve_udp_stream(io, first, capabilities).await;
        }
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
        [_, parent, command, flag, path]
            if parent == "identity" && command == "generate" && flag == "--output" =>
        {
            Ok(ServerCommand::GenerateIdentity(PathBuf::from(path)))
        }
        [
            _,
            command,
            config_flag,
            config,
            address_flag,
            address,
            server_name_flag,
            server_name,
            name_flag,
            name,
        ] if command == "client-link"
            && config_flag == "--config"
            && address_flag == "--address"
            && server_name_flag == "--server-name"
            && name_flag == "--name" =>
        {
            Ok(ServerCommand::ClientLink {
                config: PathBuf::from(config),
                address: address.parse()?,
                server_name: server_name.clone(),
                name: name.clone(),
            })
        }
        _ => Err("usage: helios-server CONFIG_TOML | run --config PATH | check --config PATH | credential generate --output TOKEN_FILE | identity generate --output DIRECTORY | client-link --config PATH --address IP:PORT --server-name NAME --name DISPLAY_NAME | version".into()),
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

    #[tokio::test]
    async fn ipv4_and_ipv6_wildcard_listeners_can_share_a_port() {
        let tcp4 = bind_tcp_listener("0.0.0.0:0".parse().unwrap(), false).unwrap();
        let tcp_port = tcp4.local_addr().unwrap().port();
        let tcp6 =
            bind_tcp_listener(SocketAddr::new("::".parse().unwrap(), tcp_port), true).unwrap();
        assert!(tcp6.local_addr().unwrap().is_ipv6());

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let crypto = ServerCrypto::new(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                signing_key.serialize_der(),
            )),
        )
        .unwrap();
        let quic4 =
            server_quic_endpoint(crypto.quic.clone(), "0.0.0.0:0".parse().unwrap(), false).unwrap();
        let quic_port = quic4.local_addr().unwrap().port();
        let quic6 = server_quic_endpoint(
            crypto.quic,
            SocketAddr::new("::".parse().unwrap(), quic_port),
            true,
        )
        .unwrap();
        assert!(quic6.local_addr().unwrap().is_ipv6());
    }

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
        assert!(matches!(
            parse_command([
                "helios-server".into(),
                "identity".into(),
                "generate".into(),
                "--output".into(),
                "identity".into(),
            ])
            .unwrap(),
            ServerCommand::GenerateIdentity(path) if path.as_os_str() == "identity"
        ));
        assert!(matches!(
            parse_command([
                "helios-server".into(),
                "client-link".into(),
                "--config".into(),
                "server.toml".into(),
                "--address".into(),
                "203.0.113.10:4800".into(),
                "--server-name".into(),
                "node-a.helios.invalid".into(),
                "--name".into(),
                "VPS A".into(),
            ])
            .unwrap(),
            ServerCommand::ClientLink { address, .. }
                if address == "203.0.113.10:4800".parse().unwrap()
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

    #[tokio::test]
    async fn generated_identity_produces_an_importable_verified_link() {
        let root = std::env::temp_dir().join(format!(
            "helios-server-identity-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let identity = root.join("identity");
        std::fs::create_dir(&root).unwrap();
        let server_name = generate_identity(&identity).unwrap();
        assert!(server_name.starts_with("node-"));
        assert!(server_name.ends_with(".helios.invalid"));
        assert!(generate_identity(&identity).is_err());
        let token = root.join("token.hex");
        generate_token_file(token.clone()).unwrap();
        let config = root.join("server.toml");
        std::fs::write(
            &config,
            r#"schema_version = 1
listen = "0.0.0.0:4800"
[tls]
certificate = "identity/cert.pem"
private_key = "identity/key.pem"
[auth]
id = "desktop-main"
token_file = "token.hex"
"#,
        )
        .unwrap();

        let encoded = generate_client_link(
            config,
            "[2001:db8::10]:4800".parse().unwrap(),
            server_name.clone(),
            "Test VPS".into(),
        )
        .await
        .unwrap();
        let link = ConnectionLink::decode(&encoded).unwrap();
        assert_eq!(link.server, "[2001:db8::10]:4800".parse().unwrap());
        assert_eq!(link.server_name, server_name);
        assert_eq!(link.name, "Test VPS");
        assert_eq!(link.preferred_transport, TransportPreference::Tls);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(identity.join("key.pem"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(root).unwrap();
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
        for (capabilities, payload) in [
            (0, b"tls-udp".to_vec()),
            (CAP_UDP_LARGE_STREAM, vec![67; 1400]),
        ] {
            let limit = if capabilities == 0 {
                MAX_UDP_PAYLOAD
            } else {
                MAX_UDP_STREAM_PAYLOAD
            };
            let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let echo_address = echo.local_addr().unwrap();
            let echo_task = tokio::spawn(async move {
                let mut buffer = [0; MAX_UDP_STREAM_PAYLOAD + 1];
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
            let server_task =
                tokio::spawn(serve_udp_stream(FrameIo::new(server), first, capabilities));
            let mut client = FrameIo::new(client);
            let accepted = client.read_frame().await.unwrap();
            assert_eq!(accepted.frame_type, FrameType::UdpAssociateOk);
            let packet = UdpPacket::new_with_limit(
                7,
                9,
                Target::new(Address::Ip(echo_address.ip()), echo_address.port()).unwrap(),
                payload.clone(),
                limit,
            )
            .unwrap();
            client
                .write_frame(
                    &Frame::new(
                        FrameType::UdpPacket,
                        9,
                        packet.encode_with_limit(limit).unwrap(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let response = client.read_frame().await.unwrap();
            assert_eq!(response.frame_type, FrameType::UdpPacket);
            let response = UdpPacket::decode_with_limit(&response.payload, limit).unwrap();
            assert_eq!(response.association_id, 7);
            assert_eq!(response.packet_id, 9);
            assert_eq!(response.payload, payload);
            client
                .write_frame(&Frame::new(FrameType::Close, 10, Vec::new()).unwrap())
                .await
                .unwrap();
            server_task.await.unwrap().unwrap();
            echo_task.await.unwrap();
        }
    }
}
