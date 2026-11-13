use std::{
    collections::BTreeMap,
    env,
    error::Error,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

mod managed_proxy;
mod outbound;
mod runtime;

#[cfg(test)]
mod quic_tests;

use helios_config::{DaemonConfig, TransportPreference, load_roots, load_token};
use helios_control::{
    ActiveFlowSnapshot, ActiveTransport, CONTROL_VERSION, ConnectionState, ControlCommand,
    ControlRequest, ControlResponse, ControlResult, StatusSnapshot, read_request, write_message,
};
use helios_dns::FakeIpPool;
use helios_protocol::{
    CAP_TCP_CONNECT, CAP_UDP_DATAGRAM, CAP_UDP_OVER_STREAM, ConnectErrorCode, ConnectTcp, Frame,
    FrameType, MAX_UDP_PAYLOAD, Target, UdpAssociate, UdpPacket,
};
use helios_proxy::{HttpConnect, Socks5, Socks5Reply, UdpDatagram};
use helios_routing::{Network, RouteAction, RuleSet};
#[cfg(target_os = "linux")]
use helios_system_proxy::LinuxProxyAdapter;
#[cfg(target_os = "macos")]
use helios_system_proxy::MacosProxyAdapter;
#[cfg(windows)]
use helios_system_proxy::WindowsProxyAdapter;
#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
use helios_system_proxy::{ReleaseOutcome, SystemProxyLease};
use helios_transport::{
    ClientCrypto, ConnectError, FrameIo, QuicBiStream, TlsClient, authenticate_client, open_tcp,
    ping,
};
use quinn::{Connection, Endpoint};
use rustls::pki_types::ServerName;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{RwLock, watch},
    time::{Instant, MissedTickBehavior, interval, sleep, timeout},
};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

type AnyError = Box<dyn Error + Send + Sync>;
const MAX_ACTIVE_FLOW_DETAILS: usize = 256;

struct Args {
    outbound: outbound::Outbound,
    transport: TransportPreference,
    listen: SocketAddr,
    http_listen: SocketAddr,
    control_listen: SocketAddr,
    control_socket: Option<PathBuf>,
    control_pipe: Option<String>,
    server: SocketAddr,
    server_name: ServerName<'static>,
    credential_id: Arc<str>,
    token: [u8; 32],
    socks_handshake_seconds: u64,
    http_handshake_seconds: u64,
    connect_milliseconds: u32,
    health_probe_seconds: u64,
    udp_idle_seconds: u64,
    rules: RuleSet,
}

enum DaemonCommand {
    ProxyWatchdog(PathBuf),
    Run(PathBuf),
    DesktopManaged {
        config: PathBuf,
        proxy_lease: PathBuf,
    },
    Check(PathBuf),
    RecoverNetwork,
    Version,
}

#[derive(Clone)]
struct Remote {
    outbound: outbound::Outbound,
    _monitors: Option<Arc<MonitorTasks>>,
    tls: TlsClient,
    quic: Arc<RwLock<Option<QuicRemote>>>,
    udp_config: Option<NodeConnectConfig>,
    server: SocketAddr,
    server_name: ServerName<'static>,
    credential_id: Arc<str>,
    token: [u8; 32],
    connect_milliseconds: u32,
    rules: Arc<RwLock<RuleSet>>,
    protected_listeners: [SocketAddr; 3],
    metrics: Arc<DaemonMetrics>,
    fake_ips: Option<FakeIpPool>,
}

struct MonitorTasks(Vec<tokio::task::AbortHandle>);
impl Drop for MonitorTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

#[derive(Clone)]
struct QuicRemote {
    _endpoint: Endpoint,
    connection: Connection,
    padding_negotiated: bool,
}

#[derive(Clone)]
struct NodeConnectConfig {
    outbound: outbound::Outbound,
    server: SocketAddr,
    server_name: ServerName<'static>,
    credential_id: Arc<str>,
    token: [u8; 32],
    client_config: quinn::ClientConfig,
}

struct DaemonMetrics {
    runtime: Mutex<Option<std::sync::Weak<runtime::Runtime>>>,
    proxy: Mutex<Option<managed_proxy::NativeProxy>>,
    proxy_status: Mutex<(bool, bool, Option<String>)>,
    desktop_managed: AtomicBool,
    prefers_quic: bool,
    quic_healthy: AtomicBool,
    quic_rtt_micros: AtomicU64,
    tls_rtt_micros: AtomicU64,
    tls_checked: AtomicBool,
    tls_healthy: AtomicBool,
    active_flows: AtomicU64,
    uploaded_bytes: AtomicU64,
    downloaded_bytes: AtomicU64,
    udp_dropped_packets: AtomicU64,
    next_flow_id: AtomicU64,
    active_flow_details: Mutex<BTreeMap<u64, Arc<ActiveFlowRecord>>>,
}

impl DaemonMetrics {
    fn new(preference: TransportPreference) -> Self {
        Self {
            runtime: Mutex::new(None),
            proxy: Mutex::new(None),
            proxy_status: Mutex::new((false, false, None)),
            desktop_managed: AtomicBool::new(false),
            prefers_quic: preference == TransportPreference::Quic,
            quic_healthy: AtomicBool::new(false),
            quic_rtt_micros: AtomicU64::new(0),
            tls_rtt_micros: AtomicU64::new(0),
            tls_checked: AtomicBool::new(false),
            tls_healthy: AtomicBool::new(false),
            active_flows: AtomicU64::new(0),
            uploaded_bytes: AtomicU64::new(0),
            downloaded_bytes: AtomicU64::new(0),
            udp_dropped_packets: AtomicU64::new(0),
            next_flow_id: AtomicU64::new(1),
            active_flow_details: Mutex::new(BTreeMap::new()),
        }
    }

    fn snapshot(&self) -> StatusSnapshot {
        let (proxy_enabled, proxy_verified, proxy_error) = self
            .proxy_status
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let quic_healthy = self.quic_healthy.load(Ordering::Relaxed);
        let tls_checked = self.tls_checked.load(Ordering::Relaxed);
        let tls_healthy = self.tls_healthy.load(Ordering::Relaxed);
        let rtt = self.quic_rtt_micros.load(Ordering::Relaxed);
        let tls_rtt = self.tls_rtt_micros.load(Ordering::Relaxed);
        StatusSnapshot {
            dns_cache: None,
            config_revision: 0,
            active_server: None,
            system_proxy_enabled: proxy_enabled,
            system_proxy_verified: proxy_verified,
            system_proxy_error: proxy_error,
            desktop_managed: self.desktop_managed.load(Ordering::Relaxed),
            state: if self.prefers_quic {
                if quic_healthy {
                    ConnectionState::Connected
                } else if tls_checked && !tls_healthy {
                    ConnectionState::Unavailable
                } else {
                    ConnectionState::Degraded
                }
            } else if !tls_checked {
                ConnectionState::Unknown
            } else if tls_healthy {
                ConnectionState::Connected
            } else {
                ConnectionState::Unavailable
            },
            transport: if quic_healthy {
                ActiveTransport::Quic
            } else {
                ActiveTransport::Tls
            },
            quic_rtt_micros: (rtt != 0).then_some(rtt),
            tls_rtt_micros: (tls_rtt != 0).then_some(tls_rtt),
            active_flows: self.active_flows.load(Ordering::Relaxed),
            uploaded_bytes: self.uploaded_bytes.load(Ordering::Relaxed),
            downloaded_bytes: self.downloaded_bytes.load(Ordering::Relaxed),
            udp_dropped_packets: self.udp_dropped_packets.load(Ordering::Relaxed),
            active_flow_details: self
                .active_flow_details
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .values()
                .map(|flow| flow.snapshot())
                .collect(),
        }
    }

    fn record_udp_drop(&self) {
        self.udp_dropped_packets.fetch_add(1, Ordering::Relaxed);
    }
}

struct ActiveFlow {
    metrics: Arc<DaemonMetrics>,
    id: u64,
    record: Arc<ActiveFlowRecord>,
}

struct ActiveFlowRecord {
    cancelled: watch::Sender<bool>,
    id: u64,
    inbound: String,
    target: String,
    decision: String,
    transport: String,
    started: Instant,
    uploaded_bytes: AtomicU64,
    downloaded_bytes: AtomicU64,
}

impl ActiveFlowRecord {
    fn snapshot(&self) -> ActiveFlowSnapshot {
        ActiveFlowSnapshot {
            id: self.id,
            inbound: self.inbound.clone(),
            target: self.target.clone(),
            decision: self.decision.clone(),
            transport: self.transport.clone(),
            duration_seconds: self.started.elapsed().as_secs(),
            uploaded_bytes: self.uploaded_bytes.load(Ordering::Relaxed),
            downloaded_bytes: self.downloaded_bytes.load(Ordering::Relaxed),
        }
    }
}

impl ActiveFlow {
    fn start(
        metrics: Arc<DaemonMetrics>,
        inbound: &str,
        target: String,
        decision: &str,
        transport: &str,
    ) -> Self {
        metrics.active_flows.fetch_add(1, Ordering::Relaxed);
        let id = metrics.next_flow_id.fetch_add(1, Ordering::Relaxed);
        let record = Arc::new(ActiveFlowRecord {
            cancelled: watch::channel(false).0,
            id,
            inbound: inbound.into(),
            target,
            decision: decision.into(),
            transport: transport.into(),
            started: Instant::now(),
            uploaded_bytes: AtomicU64::new(0),
            downloaded_bytes: AtomicU64::new(0),
        });
        let mut details = metrics
            .active_flow_details
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if details.len() < MAX_ACTIVE_FLOW_DETAILS {
            details.insert(id, record.clone());
        }
        drop(details);
        Self {
            metrics,
            id,
            record,
        }
    }

    fn upload(&self, bytes: usize) {
        self.record
            .uploaded_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn download(&self, bytes: usize) {
        self.record
            .downloaded_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

impl Drop for ActiveFlow {
    fn drop(&mut self) {
        self.metrics.active_flows.fetch_sub(1, Ordering::Relaxed);
        self.metrics
            .active_flow_details
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.id);
    }
}

struct MeteredLocal<S> {
    stream: S,
    metrics: Arc<DaemonMetrics>,
    flow: Arc<ActiveFlowRecord>,
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredLocal<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.metrics
                .uploaded_bytes
                .fetch_add((buffer.filled().len() - before) as u64, Ordering::Relaxed);
            self.flow
                .uploaded_bytes
                .fetch_add((buffer.filled().len() - before) as u64, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredLocal<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(context, buffer);
        if let Poll::Ready(Ok(written)) = result {
            self.metrics
                .downloaded_bytes
                .fetch_add(written as u64, Ordering::Relaxed);
            self.flow
                .downloaded_bytes
                .fetch_add(written as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

enum RemoteStream {
    Direct(TcpStream),
    Tls(Box<helios_transport::ClientTlsStream<TcpStream>>),
    Quic(QuicBiStream),
}

impl RemoteStream {
    fn decision(&self) -> &'static str {
        match self {
            Self::Direct(_) => "direct",
            Self::Tls(_) | Self::Quic(_) => "proxy",
        }
    }

    fn transport(&self) -> &'static str {
        match self {
            Self::Direct(_) => "direct",
            Self::Tls(_) => "tls",
            Self::Quic(_) => "quic",
        }
    }
}

impl AsyncRead for RemoteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::Quic(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for RemoteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::Quic(stream) => Pin::new(stream).poll_write(context, buffer),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_flush(context),
            Self::Tls(stream) => Pin::new(stream).poll_flush(context),
            Self::Quic(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Quic(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

#[derive(Debug, Error)]
enum RemoteError {
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error("remote transport failed: {0}")]
    Transport(#[source] AnyError),
    #[error("direct connection failed: {0}")]
    Direct(#[source] std::io::Error),
    #[error("connection rejected by routing rule")]
    Rejected,
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let result = run_daemon().await;
    if let Err(error) = &result {
        tracing::error!(event = "daemon_failed", error = %error);
    }
    result
}

async fn run_daemon() -> Result<(), AnyError> {
    let mut proxy_lease = None;
    let config_path = match parse_command(env::args())? {
        DaemonCommand::Run(path) => path,
        DaemonCommand::DesktopManaged {
            config,
            proxy_lease: path,
        } => {
            proxy_lease = Some(path);
            config
        }
        DaemonCommand::Check(path) => {
            validate_runtime_config(path)?;
            println!("configuration is valid");
            return Ok(());
        }
        DaemonCommand::RecoverNetwork => {
            recover_network()?;
            println!("network recovery completed");
            return Ok(());
        }
        DaemonCommand::Version => {
            println!("helios-daemon {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        DaemonCommand::ProxyWatchdog(path) => return managed_proxy::watch(&path),
    };
    init_logging()?;
    let config = DaemonConfig::load(&config_path)?;
    let control_token = load_token(
        config
            .control_token_file
            .as_ref()
            .unwrap_or(&config.node.token_file),
    )?;
    let roots = load_roots(&config.node.ca_certificate)?;
    let crypto = ClientCrypto::new(roots)?;
    let args = Args {
        outbound: outbound::Outbound::new(config.outbound.clone()),
        transport: config.node.preferred_transport,
        listen: config.listen,
        http_listen: config.http_listen,
        control_listen: config.control_listen,
        control_socket: config.control_socket.clone(),
        control_pipe: config.control_pipe.clone(),
        server: config.node.server,
        server_name: ServerName::try_from(config.node.server_name.clone())?,
        credential_id: Arc::from(config.node.credential_id.clone()),
        token: load_token(&config.node.token_file)?,
        socks_handshake_seconds: config.timeouts.socks_handshake_seconds,
        http_handshake_seconds: config.timeouts.http_handshake_seconds,
        connect_milliseconds: config.timeouts.connect_milliseconds,
        health_probe_seconds: config.timeouts.health_probe_seconds,
        udp_idle_seconds: config.timeouts.udp_idle_seconds,
        rules: RuleSet::new(&config.rules)?,
    };
    let fake_ips = config
        .dns
        .as_ref()
        .map(|dns| {
            FakeIpPool::new(
                dns.fake_ip_capacity,
                Duration::from_secs(dns.fake_ip_ttl_seconds.into()),
            )
        })
        .transpose()?;
    let remote = build_remote(&args, crypto, fake_ips.clone()).await?;
    let socks_listener = TcpListener::bind(args.listen).await?;
    let http_listener = TcpListener::bind(args.http_listen).await?;
    let control_listener = if args.control_socket.is_none() && args.control_pipe.is_none() {
        Some(TcpListener::bind(args.control_listen).await?)
    } else {
        None
    };
    #[cfg(unix)]
    let control_socket = bind_control_socket(args.control_socket.as_deref())?;
    let dns_socket = match &config.dns {
        Some(dns) => Some((UdpSocket::bind(dns.listen).await?, dns.fake_ip_ttl_seconds)),
        None => None,
    };
    // Only the desktop-managed process owns the desktop proxy lease.
    let desktop_managed = proxy_lease.is_some();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let bound_desktop = desktop_managed && config.outbound.is_some();
    if let Some(path) = proxy_lease {
        let settings = helios_system_proxy::ProxySettings {
            endpoint: helios_system_proxy::ProxyEndpoint::new(
                args.http_listen.ip().to_string(),
                args.http_listen.port(),
            )?,
            bypass: config.proxy_bypass.clone(),
        };
        *remote
            .metrics
            .proxy
            .lock()
            .unwrap_or_else(|error| error.into_inner()) =
            Some(managed_proxy::native(&path, settings)?);
        managed_proxy::spawn_watchdog(&path)?;
    }
    remote
        .metrics
        .desktop_managed
        .store(desktop_managed, Ordering::Relaxed);
    let metrics = remote.metrics.clone();
    let rules = remote.rules.clone();
    let runtime = runtime::Runtime::new(remote, config, Some(config_path));
    *metrics
        .runtime
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(Arc::downgrade(&runtime));
    info!(event = "socks_listening", listen = %args.listen);
    info!(event = "http_listening", listen = %args.http_listen);
    if let Some(pipe) = &args.control_pipe {
        info!(event = "control_pipe_listening", pipe);
    } else if let Some(path) = &args.control_socket {
        info!(event = "control_socket_listening", path = %path.display());
    } else {
        info!(event = "control_tcp_listening", listen = %args.control_listen);
    }
    if let Some(dns) = &runtime.config().await.dns {
        info!(event = "fake_ip_dns_listening", listen = %dns.listen);
    }

    let (shutdown, _) = watch::channel(false);
    let shutdown_metrics = metrics.clone();
    #[cfg(unix)]
    let unix_control_listener = run_unix_control_listener(
        control_socket,
        metrics.clone(),
        rules.clone(),
        control_token,
        shutdown.clone(),
        shutdown.subscribe(),
    );
    #[cfg(not(unix))]
    let unix_control_listener = std::future::ready(Ok::<(), AnyError>(()));
    let listeners = async {
        tokio::try_join!(
            run_socks_listener(
                socks_listener,
                runtime.clone(),
                args.socks_handshake_seconds,
                args.udp_idle_seconds,
                shutdown.subscribe(),
            ),
            run_http_listener(
                http_listener,
                runtime.clone(),
                args.http_handshake_seconds,
                shutdown.subscribe(),
            ),
            run_control_listener(
                control_listener,
                metrics.clone(),
                rules.clone(),
                control_token,
                shutdown.clone(),
                shutdown.subscribe()
            ),
            unix_control_listener,
            run_named_pipe_listener(
                args.control_pipe.clone(),
                metrics.clone(),
                rules.clone(),
                control_token,
                shutdown.clone(),
                shutdown.subscribe()
            ),
            run_dns_listener(dns_socket, fake_ips, shutdown.subscribe()),
            runtime.clone().monitor(shutdown.subscribe()),
            runtime::restore_proxy_after_wake(metrics.clone(), shutdown.subscribe()),
            monitor_proxy_status(metrics.clone(), shutdown.subscribe()),
        )
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let desktop_lifetime = async {
        if bound_desktop {
            use std::os::fd::AsFd;
            let mut pipe = tokio::net::unix::pipe::Receiver::from_owned_fd(
                std::io::stdin().as_fd().try_clone_to_owned()?,
            )?;
            let _ = pipe.read_u8().await;
            Ok::<(), std::io::Error>(())
        } else {
            std::future::pending().await
        }
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let desktop_lifetime = std::future::pending::<std::io::Result<()>>();
    let result = tokio::select! {
        result = listeners => {
            drain_for_shutdown(&shutdown_metrics).await;
            result.map(|_| ())
        },
        result = async { tokio::select! {
            result = shutdown_signal() => result,
            result = desktop_lifetime => result,
        }} => {
            runtime.close();
            let _ = shutdown.send(true);
            drain_for_shutdown(&shutdown_metrics).await;
            result.map_err(AnyError::from)
        }
    };
    // Release the proxy while listeners are stopped, before dropping the runtime.
    runtime.close();
    if let Some(mut proxy) = metrics
        .proxy
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
    {
        proxy.set(false)?;
    }
    result?;
    Ok(())
}

fn init_logging() -> Result<(), AnyError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(std::io::stderr)
        .try_init()?;
    Ok(())
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

async fn drain_for_shutdown(metrics: &DaemonMetrics) {
    info!(event = "shutdown_draining", deadline_milliseconds = 2000);
    if !wait_for_flows(metrics, Duration::from_secs(2)).await {
        warn!(event = "shutdown_deadline_reached");
    }
}

async fn wait_for_flows(metrics: &DaemonMetrics, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if metrics.active_flows.load(Ordering::Relaxed) == 0 {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        sleep((deadline - now).min(Duration::from_millis(25))).await;
    }
}

async fn run_dns_listener(
    dns: Option<(UdpSocket, u32)>,
    pool: Option<FakeIpPool>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    let (Some((socket, ttl)), Some(pool)) = (dns, pool) else {
        shutdown.changed().await?;
        return Ok(());
    };
    tokio::select! {
        result = helios_dns::serve_udp(socket, pool, ttl) => result.map_err(Into::into),
        changed = shutdown.changed() => { changed?; Ok(()) }
    }
}

async fn run_socks_listener(
    listener: TcpListener,
    runtime: Arc<runtime::Runtime>,
    handshake_seconds: u64,
    udp_idle_seconds: u64,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let remote = runtime.remote().await;
                tokio::spawn(async move {
                    if let Err(error) = serve_socks(stream, remote, handshake_seconds, udp_idle_seconds).await {
                        warn!(event = "socks_flow_failed");
                        debug!(event = "socks_flow_error", error = %error);
                    }
                });
            }
            changed = shutdown.changed() => {
                changed?;
                return Ok(());
            }
        }
    }
}

async fn run_http_listener(
    listener: TcpListener,
    runtime: Arc<runtime::Runtime>,
    handshake_seconds: u64,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let remote = runtime.remote().await;
                tokio::spawn(async move {
                    if let Err(error) = serve_http(stream, remote, handshake_seconds).await {
                        warn!(event = "http_flow_failed");
                        debug!(event = "http_flow_error", error = %error);
                    }
                });
            }
            changed = shutdown.changed() => {
                changed?;
                return Ok(());
            }
        }
    }
}

async fn run_control_listener(
    listener: Option<TcpListener>,
    metrics: Arc<DaemonMetrics>,
    rules: Arc<RwLock<RuleSet>>,
    token: [u8; 32],
    shutdown_tx: watch::Sender<bool>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    let Some(listener) = listener else {
        shutdown.changed().await?;
        return Ok(());
    };
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let metrics = metrics.clone();
                let rules = rules.clone();
                let shutdown_tx = shutdown_tx.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_control_connection(stream, metrics, rules, token, shutdown_tx).await {
                        warn!(event = "control_request_failed", channel = "tcp");
                        debug!(event = "control_request_error", channel = "tcp", error = %error);
                    }
                });
            }
            changed = shutdown.changed() => {
                changed?;
                return Ok(());
            }
        }
    }
}

async fn serve_control_connection(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    metrics: Arc<DaemonMetrics>,
    rules: Arc<RwLock<RuleSet>>,
    token: [u8; 32],
    shutdown: watch::Sender<bool>,
) -> Result<(), AnyError> {
    let request: ControlRequest =
        timeout(Duration::from_secs(10), read_request(&mut stream, &token)).await??;
    let (mut result, should_shutdown) = control_result(&request, &token, &metrics, &rules).await;
    bound_status_response(&mut result)?;
    let response = write_message(
        &mut stream,
        &ControlResponse {
            version: CONTROL_VERSION,
            result,
        },
    )
    .await;
    if should_shutdown {
        let _ = shutdown.send(true);
    }
    response?;
    Ok(())
}

// Bound bytes as well as count: legal long domains can overflow a 256-flow response.
fn bound_status_response(result: &mut ControlResult) -> Result<(), serde_json::Error> {
    if let ControlResult::Status { snapshot } = result {
        let mut details = std::mem::take(&mut snapshot.active_flow_details);
        let base = serde_json::to_vec(&ControlResponse {
            version: CONTROL_VERSION,
            result: ControlResult::Status {
                snapshot: snapshot.clone(),
            },
        })?
        .len();
        let mut size = base;
        for detail in details.drain(..) {
            let extra = serde_json::to_vec(&detail)?.len()
                + usize::from(!snapshot.active_flow_details.is_empty());
            if size + extra > helios_control::MAX_CONTROL_MESSAGE {
                break;
            }
            size += extra;
            snapshot.active_flow_details.push(detail);
        }
    }
    Ok(())
}

async fn monitor_proxy_status(
    metrics: Arc<DaemonMetrics>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    let mut ticks = interval(Duration::from_secs(2));
    ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticks.tick() => {},
            changed = shutdown.changed() => { changed?; return Ok(()); }
        }
        let metrics = metrics.clone();
        tokio::task::spawn_blocking(move || {
            let proxy = metrics
                .proxy
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let status = proxy
                .as_ref()
                .map(|proxy| proxy.status())
                .unwrap_or((false, false, None));
            *metrics
                .proxy_status
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = status;
        })
        .await?;
    }
}

#[cfg(unix)]
struct UnixSocketGuard(PathBuf);

#[cfg(unix)]
impl Drop for UnixSocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(unix)]
fn bind_control_socket(
    path: Option<&Path>,
) -> Result<Option<(tokio::net::UnixListener, UnixSocketGuard)>, AnyError> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    let Some(path) = path else {
        return Ok(None);
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    if path.exists() {
        if !std::fs::symlink_metadata(path)?.file_type().is_socket() {
            return Err(format!("control socket path is not a socket: {}", path.display()).into());
        }
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => {
                return Err(format!("control socket is already in use: {}", path.display()).into());
            }
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(path)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(Some((listener, UnixSocketGuard(path.to_owned()))))
}

#[cfg(unix)]
async fn run_unix_control_listener(
    listener: Option<(tokio::net::UnixListener, UnixSocketGuard)>,
    metrics: Arc<DaemonMetrics>,
    rules: Arc<RwLock<RuleSet>>,
    token: [u8; 32],
    shutdown_tx: watch::Sender<bool>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    let Some((listener, _guard)) = listener else {
        shutdown.changed().await?;
        return Ok(());
    };
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let metrics = metrics.clone();
                let rules = rules.clone();
                let shutdown_tx = shutdown_tx.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_control_connection(stream, metrics, rules, token, shutdown_tx).await {
                        warn!(event = "control_request_failed", channel = "unix");
                        debug!(event = "control_request_error", channel = "unix", error = %error);
                    }
                });
            }
            changed = shutdown.changed() => {
                changed?;
                return Ok(());
            }
        }
    }
}

#[cfg(windows)]
fn create_control_pipe(
    name: Option<&str>,
    first: bool,
) -> Result<Option<tokio::net::windows::named_pipe::NamedPipeServer>, AnyError> {
    use std::{ffi::c_void, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
    };

    let Some(name) = name else {
        return Ok(None);
    };
    let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;OW)\0".encode_utf16().collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
    options.first_pipe_instance(first);
    let result = unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    Ok(Some(result?))
}

#[cfg(windows)]
async fn run_named_pipe_listener(
    name: Option<String>,
    metrics: Arc<DaemonMetrics>,
    rules: Arc<RwLock<RuleSet>>,
    token: [u8; 32],
    shutdown_tx: watch::Sender<bool>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    let Some(name) = name else {
        shutdown.changed().await?;
        return Ok(());
    };
    let mut server = create_control_pipe(Some(&name), true)?.expect("pipe name is present");
    loop {
        tokio::select! {
            connected = server.connect() => {
                connected?;
                let connected = server;
                server = create_control_pipe(Some(&name), false)?.expect("pipe name is present");
                let metrics = metrics.clone();
                let rules = rules.clone();
                let shutdown_tx = shutdown_tx.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_control_connection(connected, metrics, rules, token, shutdown_tx).await {
                        warn!(event = "control_request_failed", channel = "pipe");
                        debug!(event = "control_request_error", channel = "pipe", error = %error);
                    }
                });
            }
            changed = shutdown.changed() => {
                changed?;
                return Ok(());
            }
        }
    }
}

#[cfg(not(windows))]
async fn run_named_pipe_listener(
    _name: Option<String>,
    _metrics: Arc<DaemonMetrics>,
    _rules: Arc<RwLock<RuleSet>>,
    _token: [u8; 32],
    _shutdown_tx: watch::Sender<bool>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    shutdown.changed().await?;
    Ok(())
}

async fn control_result(
    request: &ControlRequest,
    token: &[u8; 32],
    metrics: &DaemonMetrics,
    rules: &RwLock<RuleSet>,
) -> (ControlResult, bool) {
    if !bool::from(request.token.ct_eq(token)) {
        (
            ControlResult::Error {
                message: "control authentication failed".into(),
            },
            false,
        )
    } else if request.version != CONTROL_VERSION {
        (
            ControlResult::Error {
                message: format!("unsupported control version {}", request.version),
            },
            false,
        )
    } else {
        let runtime = metrics
            .runtime
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .and_then(std::sync::Weak::upgrade);
        let result = match &request.command {
            ControlCommand::LargeRequest { .. } => ControlResult::Error {
                message: "large request envelope must be handled by the control transport".into(),
            },
            ControlCommand::TestRoute {
                rules,
                host,
                port,
                network,
            } => match RuleSet::new(rules) {
                Ok(rules) => match &runtime {
                    Some(runtime) => {
                        let remote = runtime.remote().await;
                        let address = host
                            .parse()
                            .map(helios_protocol::Address::Ip)
                            .unwrap_or_else(|_| helios_protocol::Address::Domain(host.clone()));
                        match Target::new(address, *port)
                            .map_err(std::io::Error::other)
                            .and_then(|target| remote.restore_target(target))
                        {
                            Ok(target) => ControlResult::RouteTest {
                                report: remote
                                    .outbound
                                    .evaluate_route(&rules, &target, *network)
                                    .await,
                            },
                            Err(error) => ControlResult::Error {
                                message: error.to_string(),
                            },
                        }
                    }
                    None => ControlResult::Error {
                        message: "DNS runtime is unavailable".into(),
                    },
                },
                Err(error) => ControlResult::Error {
                    message: error.to_string(),
                },
            },
            ControlCommand::PruneDnsCache => match &runtime {
                Some(runtime) => {
                    let remote = runtime.remote().await;
                    remote.outbound.clear_cache();
                    match remote.fake_ips {
                        Some(pool) => ControlResult::DnsCachePruned {
                            stats: pool.stats(),
                        },
                        None => ControlResult::DnsCachePruned {
                            stats: helios_dns::CacheStats::default(),
                        },
                    }
                }
                None => ControlResult::Error {
                    message: "DNS runtime is unavailable".into(),
                },
            },
            ControlCommand::GetStatus => ControlResult::Status {
                snapshot: match &runtime {
                    Some(runtime) => runtime.snapshot().await,
                    None => metrics.snapshot(),
                },
            },
            ControlCommand::ApplyConfig {
                expected_revision,
                config,
            } => match &runtime {
                Some(runtime) => match timeout(
                    Duration::from_secs(25),
                    runtime.apply(*expected_revision, *config.clone()),
                )
                .await
                {
                    Ok(Ok(revision)) => ControlResult::ConfigApplied { revision },
                    Ok(Err(error)) => ControlResult::Error {
                        message: error.to_string(),
                    },
                    Err(_) => ControlResult::Error {
                        message: "configuration update is still pending; refresh status to confirm the result".into(),
                    },
                },
                None => ControlResult::Error {
                    message: "runtime configuration is unavailable".into(),
                },
            },
            ControlCommand::UpdateRules { rules: configs } if runtime.is_some() => {
                match runtime.as_ref().unwrap().update_rules(configs).await {
                    Ok(()) => ControlResult::RulesUpdated,
                    Err(error) => ControlResult::Error {
                        message: error.to_string(),
                    },
                }
            }
            ControlCommand::UpdateRules { rules: configs } => match RuleSet::new(configs) {
                Ok(updated) => {
                    *rules.write().await = updated;
                    ControlResult::RulesUpdated
                }
                Err(error) => ControlResult::Error {
                    message: error.to_string(),
                },
            },
            ControlCommand::Shutdown => {
                if let Some(runtime) = &runtime {
                    runtime.close();
                }
                ControlResult::ShutdownAccepted
            }
            ControlCommand::SetSystemProxy { enabled } => {
                if *enabled && runtime.as_ref().is_some_and(|runtime| runtime.is_closing()) {
                    return (
                        ControlResult::Error {
                            message: "daemon is shutting down".into(),
                        },
                        false,
                    );
                }
                let metrics = runtime.as_ref().map(|runtime| runtime.metrics.clone());
                let Some(metrics) = metrics else {
                    return (
                        ControlResult::Error {
                            message: "runtime configuration is unavailable".into(),
                        },
                        false,
                    );
                };
                let enabled = *enabled;
                match tokio::task::spawn_blocking(move || {
                    let mut proxy = metrics
                        .proxy
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    let result = match proxy.as_mut() {
                        Some(proxy) => match proxy.set(enabled) {
                            Ok(enabled) => ControlResult::SystemProxyUpdated { enabled },
                            Err(error) => ControlResult::Error {
                                message: error.to_string(),
                            },
                        },
                        None => ControlResult::Error {
                            message: "system proxy requires a desktop-managed daemon".into(),
                        },
                    };
                    *metrics
                        .proxy_status
                        .lock()
                        .unwrap_or_else(|error| error.into_inner()) = proxy
                        .as_ref()
                        .map(|proxy| proxy.status())
                        .unwrap_or((false, false, None));
                    result
                })
                .await
                {
                    Ok(result) => result,
                    Err(error) => ControlResult::Error {
                        message: error.to_string(),
                    },
                }
            }
            ControlCommand::CloseFlow { id } => {
                let details = metrics
                    .active_flow_details
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match details.get(id) {
                    Some(flow) => {
                        flow.cancelled.send_replace(true);
                        ControlResult::FlowClosed { id: *id }
                    }
                    None => ControlResult::Error {
                        message: "flow is no longer active or is not listed".into(),
                    },
                }
            }
        };
        (result, matches!(request.command, ControlCommand::Shutdown))
    }
}

async fn build_remote(
    args: &Args,
    crypto: ClientCrypto,
    fake_ips: Option<FakeIpPool>,
) -> Result<Remote, AnyError> {
    let metrics = Arc::new(DaemonMetrics::new(args.transport));
    let quic_config = NodeConnectConfig {
        outbound: args.outbound.clone(),
        server: args.server,
        server_name: args.server_name.clone(),
        credential_id: args.credential_id.clone(),
        token: args.token,
        client_config: crypto.quic.clone(),
    };
    let mut monitors = MonitorTasks(vec![
        tokio::spawn(monitor_tls(
            crypto.tls.clone(),
            quic_config.clone(),
            Duration::from_secs(args.health_probe_seconds),
            metrics.clone(),
        ))
        .abort_handle(),
    ]);
    let quic = Arc::new(RwLock::new(None));
    let udp_config = (args.transport == TransportPreference::Quic).then(|| quic_config.clone());
    if args.transport == TransportPreference::Quic {
        match timeout(
            Duration::from_millis(args.connect_milliseconds.into()),
            establish_quic(&quic_config),
        )
        .await
        {
            Ok(Ok((remote, control))) => {
                *quic.write().await = Some(remote);
                monitors.0.push(
                    tokio::spawn(monitor_quic(
                        Some(control),
                        quic_config.clone(),
                        Duration::from_secs(args.health_probe_seconds),
                        quic.clone(),
                        metrics.clone(),
                    ))
                    .abort_handle(),
                );
            }
            Ok(Err(error)) => {
                warn!(event = "quic_initial_unavailable", fallback = "tls");
                debug!(event = "quic_initial_error", error = %error);
            }
            Err(_) => {
                warn!(event = "quic_initial_timeout", fallback = "tls");
            }
        }
        if quic.read().await.is_none() {
            monitors.0.push(
                tokio::spawn(monitor_quic(
                    None,
                    quic_config.clone(),
                    Duration::from_secs(args.health_probe_seconds),
                    quic.clone(),
                    metrics.clone(),
                ))
                .abort_handle(),
            );
        }
    }
    Ok(Remote {
        outbound: args.outbound.clone(),
        _monitors: Some(Arc::new(monitors)),
        tls: crypto.tls,
        quic,
        udp_config,
        server: args.server,
        server_name: args.server_name.clone(),
        credential_id: args.credential_id.clone(),
        token: args.token,
        connect_milliseconds: args.connect_milliseconds,
        rules: Arc::new(RwLock::new(args.rules.clone())),
        protected_listeners: [args.listen, args.http_listen, args.control_listen],
        metrics,
        fake_ips,
    })
}

async fn probe_tls(
    client: &TlsClient,
    server: SocketAddr,
    server_name: &ServerName<'static>,
    credential_id: &str,
    token: &[u8; 32],
    outbound: &outbound::Outbound,
) -> Result<Duration, AnyError> {
    let tcp = outbound.node_tcp(server).await?;
    let mut io = client.connect(server_name.clone(), tcp).await?;
    authenticate_client(&mut io, credential_id, token, CAP_TCP_CONNECT).await?;
    Ok(ping(&mut io, 200, b"tls-health").await?)
}

async fn monitor_tls(
    client: TlsClient,
    config: NodeConnectConfig,
    probe_interval: Duration,
    metrics: Arc<DaemonMetrics>,
) {
    let mut ticker = interval(probe_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        match timeout(
            Duration::from_secs(5),
            probe_tls(
                &client,
                config.server,
                &config.server_name,
                &config.credential_id,
                &config.token,
                &config.outbound,
            ),
        )
        .await
        {
            Ok(Ok(elapsed)) => {
                metrics
                    .tls_rtt_micros
                    .store(elapsed.as_micros().max(1) as u64, Ordering::Relaxed);
                metrics.tls_healthy.store(true, Ordering::Relaxed);
                metrics.tls_checked.store(true, Ordering::Relaxed);
            }
            Ok(Err(error)) => {
                warn!(event = "tls_health_failed");
                debug!(event = "tls_health_error", error = %error);
                metrics.tls_healthy.store(false, Ordering::Relaxed);
                metrics.tls_checked.store(true, Ordering::Relaxed);
            }
            Err(_) => {
                warn!(event = "tls_health_timeout");
                metrics.tls_healthy.store(false, Ordering::Relaxed);
                metrics.tls_checked.store(true, Ordering::Relaxed);
            }
        }
    }
}

async fn establish_quic(
    config: &NodeConnectConfig,
) -> Result<(QuicRemote, FrameIo<QuicBiStream>), AnyError> {
    let mut endpoint = config.outbound.quic(config.server)?;
    endpoint.set_default_client_config(config.client_config.clone());
    let connection = endpoint
        .connect(config.server, config.server_name.to_str().as_ref())?
        .await?;
    let (send, recv) = connection.open_bi().await?;
    let mut control = FrameIo::new(QuicBiStream::new(send, recv));
    authenticate_client(
        &mut control,
        &config.credential_id,
        &config.token,
        CAP_TCP_CONNECT | CAP_UDP_DATAGRAM,
    )
    .await?;
    Ok((
        QuicRemote {
            padding_negotiated: control.padding_negotiated(),
            _endpoint: endpoint,
            connection,
        },
        control,
    ))
}

async fn monitor_quic(
    initial_control: Option<FrameIo<QuicBiStream>>,
    config: NodeConnectConfig,
    probe_interval: Duration,
    quic_slot: Arc<RwLock<Option<QuicRemote>>>,
    metrics: Arc<DaemonMetrics>,
) {
    let mut control = initial_control;
    let mut current = quic_slot.read().await.clone();
    let mut request_id = 100u32;
    loop {
        if control.is_none() {
            metrics.quic_healthy.store(false, Ordering::Relaxed);
            tokio::time::sleep(probe_interval).await;
            match timeout(Duration::from_secs(10), establish_quic(&config)).await {
                Ok(Ok((remote, new_control))) => {
                    *quic_slot.write().await = Some(remote.clone());
                    current = Some(remote);
                    control = Some(new_control);
                    info!(event = "quic_recovered");
                }
                Ok(Err(error)) => {
                    debug!(event = "quic_recovery_error", error = %error);
                    continue;
                }
                Err(_) => {
                    warn!(event = "quic_recovery_timeout");
                    continue;
                }
            }
        }
        let mut io = control.take().expect("control exists after establish");
        let mut ticker = interval(probe_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            match probe_quic_health(&mut io, request_id).await {
                Ok(elapsed) => {
                    metrics
                        .quic_rtt_micros
                        .store(elapsed.as_micros().max(1) as u64, Ordering::Relaxed);
                    metrics.quic_healthy.store(true, Ordering::Relaxed);
                    if let Some(remote) = &current {
                        *quic_slot.write().await = Some(remote.clone());
                    }
                    request_id = request_id.wrapping_add(1).max(100);
                }
                Err(error) => {
                    warn!(event = "quic_health_failed", fallback = "tls");
                    debug!(event = "quic_health_error", error = %error);
                    break;
                }
            }
        }
        metrics.quic_healthy.store(false, Ordering::Relaxed);
        *quic_slot.write().await = None;
        if let Some(remote) = current.take() {
            remote.connection.close(0u32.into(), b"health probe failed");
        }
        control = None;
    }
}

async fn probe_quic_health<S>(io: &mut FrameIo<S>, request_id: u32) -> Result<Duration, AnyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let payload = request_id.to_be_bytes();
    // Retain the entire write/read transaction across soft deadlines: FrameIo is not cancel-safe.
    let probe = ping(io, request_id, &payload);
    tokio::pin!(probe);
    let mut timeouts = 0;
    loop {
        match timeout(Duration::from_secs(5), &mut probe).await {
            Ok(result) => return result.map_err(Into::into),
            Err(error) => {
                timeouts += 1;
                warn!(event = "quic_health_timeout", consecutive = timeouts);
                if should_degrade_after_timeout(timeouts) {
                    return Err(error.into());
                }
            }
        }
    }
}

fn should_degrade_after_timeout(consecutive_timeouts: u8) -> bool {
    consecutive_timeouts >= 3
}

async fn serve_socks_udp(
    mut socks: Socks5<TcpStream>,
    _requested: Option<Target>,
    remote: Remote,
    idle_seconds: u64,
) -> Result<(), AnyError> {
    let socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
    let direct_socket_v4 = remote.outbound.udp(false).await.ok();
    let direct_socket_v6 = remote.outbound.udp(true).await.ok();
    let bound = socket.local_addr()?;
    let proxy = if let Some(config) = remote.udp_config.as_ref() {
        match timeout(
            Duration::from_millis(remote.connect_milliseconds.into()),
            establish_quic(config),
        )
        .await
        {
            Ok(Ok((quic, transport_control))) => match timeout(
                Duration::from_millis(remote.connect_milliseconds.into()),
                open_udp_association(&quic),
            )
            .await
            {
                Ok(Ok((association, association_id))) => {
                    Some((quic, transport_control, association, association_id))
                }
                Ok(Err(error)) => {
                    warn!(event = "udp_quic_association_unavailable");
                    debug!(event = "udp_quic_association_error", error = %error);
                    None
                }
                Err(_) => None,
            },
            Ok(Err(error)) => {
                warn!(event = "udp_quic_unavailable");
                debug!(event = "udp_quic_error", error = %error);
                None
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let mut tls_proxy = if proxy.is_none() {
        match timeout(
            Duration::from_millis(remote.connect_milliseconds.into()),
            open_tls_udp_association(&remote),
        )
        .await
        {
            Ok(Ok(value)) => Some(value),
            Ok(Err(error)) => {
                warn!(event = "udp_tls_unavailable");
                debug!(event = "udp_tls_error", error = %error);
                None
            }
            Err(_) => None,
        }
    } else {
        None
    };
    socks.reply_udp_bound(Socks5Reply::Succeeded, bound).await?;
    let active = ActiveFlow::start(
        remote.metrics.clone(),
        "socks5-udp",
        "UDP association".into(),
        "mixed",
        if proxy.is_some() {
            "quic"
        } else if tls_proxy.is_some() {
            "tls"
        } else {
            "direct"
        },
    );
    let mut control = socks.into_inner();
    let mut cancelled = active.record.cancelled.subscribe();
    let mut source = None;
    let mut packet_id = 1u32;
    let mut buffer = vec![0u8; 65_535];
    let mut direct_buffer_v4 = vec![0u8; 65_535];
    let mut direct_buffer_v6 = vec![0u8; 65_535];
    let idle = sleep(Duration::from_secs(idle_seconds));
    tokio::pin!(idle);
    loop {
        tokio::select! {
            _ = async { let _ = cancelled.wait_for(|closed| *closed).await; } => return Ok(()),
            () = &mut idle => return Ok(()),
            result = control.read_u8() => {
                match result { Ok(_) => continue, Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()), Err(error) => return Err(error.into()) }
            }
            result = socket.recv_from(&mut buffer) => {
                let (length, peer) = result?;
                let Ok(packet) = UdpDatagram::decode(&buffer[..length]) else { remote.metrics.record_udp_drop(); continue; };
                if packet.payload.len() > MAX_UDP_PAYLOAD { remote.metrics.record_udp_drop(); continue; }
                if source.is_none() { source = Some(peer); }
                if source != Some(peer) { remote.metrics.record_udp_drop(); continue; }
                idle.as_mut().reset(Instant::now() + Duration::from_secs(idle_seconds));
                let target = match remote.restore_target(packet.target) {
                    Ok(target) => target,
                    Err(_) => { remote.metrics.record_udp_drop(); continue; },
                };
                let (action, classified_ips) = remote.route(&target, Network::Udp).await;
                if action == RouteAction::Reject { remote.metrics.record_udp_drop(); continue; }
                if action == RouteAction::Direct {
                    let destination = match timeout(Duration::from_millis(remote.connect_milliseconds.into()), async { if classified_ips.is_empty() { remote.outbound.resolve(&target).await } else { Ok(classified_ips) } }).await {
                        Ok(Ok(ips)) => SocketAddr::new(ips[0], target.port),
                        _ => { remote.metrics.record_udp_drop(); continue; },
                    };
                    if remote.protected_listeners.contains(&destination) { remote.metrics.record_udp_drop(); continue; }
                    let Some(direct_socket) = (if destination.is_ipv4() { &direct_socket_v4 } else { &direct_socket_v6 }) else {
                        remote.metrics.record_udp_drop(); continue;
                    };
                    if direct_socket.send_to(&packet.payload, destination).await.is_ok() {
                        remote.metrics.uploaded_bytes.fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
                        active.upload(packet.payload.len());
                    } else {
                        remote.metrics.record_udp_drop();
                    }
                    continue;
                }
                let id = packet_id;
                packet_id = packet_id.wrapping_add(1).max(1);
                let payload_len = packet.payload.len();
                if let Some((quic, _, _, association_id)) = proxy.as_ref() {
                    let packet = UdpPacket::new(*association_id, id, target, packet.payload)?;
                    let encoded = packet.encode()?;
                    if quic.connection.max_datagram_size().is_some_and(|max| encoded.len() <= max)
                        && quic.connection.send_datagram(bytes::Bytes::from(encoded)).is_ok()
                    {
                        remote.metrics.uploaded_bytes.fetch_add(payload_len as u64, Ordering::Relaxed);
                        active.upload(payload_len);
                    } else {
                        remote.metrics.record_udp_drop();
                    }
                } else if let Some((io, association_id)) = tls_proxy.as_mut() {
                    let packet = UdpPacket::new(*association_id, id, target, packet.payload)?;
                    io.write_frame(&Frame::new(FrameType::UdpPacket, id, packet.encode()?)?).await?;
                    remote.metrics.uploaded_bytes.fetch_add(payload_len as u64, Ordering::Relaxed);
                    active.upload(payload_len);
                    let mut response_cancelled = active.record.cancelled.subscribe();
                    let response = tokio::select! {
                        _ = async { let _ = response_cancelled.wait_for(|closed| *closed).await; } => return Ok(()),
                        result = timeout(Duration::from_secs(6), io.read_frame()) => result??,
                    };
                    if response.frame_type != FrameType::UdpPacket { remote.metrics.record_udp_drop(); continue; }
                    let response = UdpPacket::decode(&response.payload)?;
                    let response_len = response.payload.len();
                    let reply = UdpDatagram { target: response.target, payload: response.payload }.encode()?;
                    if socket.send_to(&reply, peer).await.is_ok() {
                        remote.metrics.downloaded_bytes.fetch_add(response_len as u64, Ordering::Relaxed);
                        active.download(response_len);
                    } else {
                        remote.metrics.record_udp_drop();
                    }
                } else {
                    remote.metrics.record_udp_drop();
                }
            }
            result = async {
                match proxy.as_ref() {
                    Some((quic, _, _, _)) => quic.connection.read_datagram().await,
                    None => std::future::pending::<Result<bytes::Bytes, quinn::ConnectionError>>().await,
                }
            } => {
                let Ok(data) = result else { return Ok(()); };
                let Ok(packet) = UdpPacket::decode(&data) else { remote.metrics.record_udp_drop(); continue; };
                if proxy.as_ref().is_none_or(|(_, _, _, association_id)| packet.association_id != *association_id) { remote.metrics.record_udp_drop(); continue; }
                idle.as_mut().reset(Instant::now() + Duration::from_secs(idle_seconds));
                let payload_len = packet.payload.len();
                let reply = UdpDatagram { target: packet.target, payload: packet.payload }.encode()?;
                if let Some(source) = source
                    && socket.send_to(&reply, source).await.is_ok()
                {
                    remote.metrics.downloaded_bytes.fetch_add(payload_len as u64, Ordering::Relaxed);
                    active.download(payload_len);
                } else {
                    remote.metrics.record_udp_drop();
                }
            }
            result = outbound::receive(&direct_socket_v4, &mut direct_buffer_v4) => {
                let (length, peer) = result?;
                idle.as_mut().reset(Instant::now() + Duration::from_secs(idle_seconds));
                let target = Target::new(helios_protocol::Address::Ip(peer.ip()), peer.port())?;
                let reply = UdpDatagram { target, payload: direct_buffer_v4[..length].to_vec() }.encode()?;
                if let Some(source) = source
                    && socket.send_to(&reply, source).await.is_ok()
                {
                    remote.metrics.downloaded_bytes.fetch_add(length as u64, Ordering::Relaxed);
                    active.download(length);
                } else {
                    remote.metrics.record_udp_drop();
                }
            }
            result = outbound::receive(&direct_socket_v6, &mut direct_buffer_v6) => {
                let (length, peer) = result?;
                idle.as_mut().reset(Instant::now() + Duration::from_secs(idle_seconds));
                let target = Target::new(helios_protocol::Address::Ip(peer.ip()), peer.port())?;
                let reply = UdpDatagram { target, payload: direct_buffer_v6[..length].to_vec() }.encode()?;
                if let Some(source) = source
                    && socket.send_to(&reply, source).await.is_ok()
                {
                    remote.metrics.downloaded_bytes.fetch_add(length as u64, Ordering::Relaxed);
                    active.download(length);
                } else {
                    remote.metrics.record_udp_drop();
                }
            }
        }
    }
}

async fn open_udp_association(quic: &QuicRemote) -> Result<(FrameIo<QuicBiStream>, u32), AnyError> {
    let (send, recv) = quic.connection.open_bi().await?;
    let mut association = FrameIo::new(QuicBiStream::new(send, recv));
    let request_id = 1;
    association
        .write_frame(&Frame::new(
            FrameType::UdpAssociate,
            request_id,
            UdpAssociate { target: None }.encode()?,
        )?)
        .await?;
    let accepted = association.read_frame().await?;
    if accepted.frame_type != FrameType::UdpAssociateOk
        || accepted.request_id != request_id
        || accepted.payload.len() != 4
    {
        return Err("invalid UDP association response".into());
    }
    Ok((
        association,
        u32::from_be_bytes(accepted.payload[..4].try_into()?),
    ))
}

async fn open_tls_udp_association(
    remote: &Remote,
) -> Result<(FrameIo<helios_transport::ClientTlsStream<TcpStream>>, u32), AnyError> {
    let tcp = remote.outbound.node_tcp(remote.server).await?;
    let mut io = remote.tls.connect(remote.server_name.clone(), tcp).await?;
    authenticate_client(
        &mut io,
        &remote.credential_id,
        &remote.token,
        CAP_UDP_OVER_STREAM,
    )
    .await?;
    let request_id = 1;
    io.write_frame(&Frame::new(
        FrameType::UdpAssociate,
        request_id,
        UdpAssociate { target: None }.encode()?,
    )?)
    .await?;
    let accepted = io.read_frame().await?;
    if accepted.frame_type != FrameType::UdpAssociateOk
        || accepted.request_id != request_id
        || accepted.payload.len() != 4
    {
        return Err("invalid UDP association response".into());
    }
    Ok((io, u32::from_be_bytes(accepted.payload[..4].try_into()?)))
}

async fn serve_socks(
    stream: TcpStream,
    remote: Remote,
    socks_handshake_seconds: u64,
    udp_idle_seconds: u64,
) -> Result<(), AnyError> {
    let duration = Duration::from_secs(socks_handshake_seconds);
    let mut socks = timeout(duration, Socks5::negotiate(stream)).await??;
    let (command, target) = timeout(duration, socks.read_request()).await??;
    if command == 3 {
        return serve_socks_udp(socks, target, remote, udp_idle_seconds).await;
    }
    if command != 1 {
        socks.reply(Socks5Reply::CommandNotSupported).await?;
        return Ok(());
    }

    let target = target.ok_or_else(|| AnyError::from("SOCKS CONNECT target is required"))?;
    if target.port == 54
        && target.address == helios_protocol::Address::Ip(helios_dns::TUN_DNS)
        && remote.fake_ips.is_some()
        && let Some(outbound) = &remote.outbound.config
    {
        socks.reply(Socks5Reply::Succeeded).await?;
        let bytes = serde_json::to_vec(&helios_config::TunDaemonInfo {
            pid: std::process::id(),
            outbound: outbound.clone(),
        })?;
        let mut stream = socks.into_inner();
        stream.write_u32(bytes.len().try_into()?).await?;
        stream.write_all(&bytes).await?;
        return Ok(());
    }
    if remote.outbound.config.is_some()
        && target.port == 53
        && target.address == helios_protocol::Address::Ip(helios_dns::TUN_DNS)
        && let Some(pool) = &remote.fake_ips
    {
        socks.reply(Socks5Reply::Succeeded).await?;
        return helios_dns::serve_tcp(socks.into_inner(), pool.clone())
            .await
            .map_err(Into::into);
    }
    let target_label = target_label(&target);
    let mut remote_stream = match remote.open(target).await {
        Ok(stream) => stream,
        Err(error) => {
            socks.reply(socks_reply(&error)).await?;
            return Err(error.into());
        }
    };
    socks.reply(Socks5Reply::Succeeded).await?;
    relay(
        socks.into_inner(),
        &mut remote_stream,
        remote.metrics.clone(),
        "socks5",
        target_label,
    )
    .await?;
    Ok(())
}

async fn serve_http(
    stream: TcpStream,
    remote: Remote,
    handshake_seconds: u64,
) -> Result<(), AnyError> {
    let duration = Duration::from_secs(handshake_seconds);
    let (mut connect, target) = timeout(duration, HttpConnect::accept(stream)).await??;
    let target_label = target_label(&target);
    let mut remote_stream = match remote.open(target).await {
        Ok(stream) => stream,
        Err(error) => {
            connect.failed().await?;
            return Err(error.into());
        }
    };
    if !connect.forward_head().is_empty() {
        use tokio::io::AsyncWriteExt;
        remote_stream.write_all(connect.forward_head()).await?;
        remote_stream.flush().await?;
    }
    connect.connected().await?;
    relay(
        connect.into_inner(),
        &mut remote_stream,
        remote.metrics.clone(),
        "http",
        target_label,
    )
    .await?;
    Ok(())
}

async fn relay(
    local: TcpStream,
    remote: &mut RemoteStream,
    metrics: Arc<DaemonMetrics>,
    inbound: &str,
    target: String,
) -> std::io::Result<()> {
    let active = ActiveFlow::start(
        metrics.clone(),
        inbound,
        target,
        remote.decision(),
        remote.transport(),
    );
    let mut local = MeteredLocal {
        stream: local,
        metrics,
        flow: active.record.clone(),
    };
    let mut cancelled = active.record.cancelled.subscribe();
    tokio::select! {
        _ = async { let _ = cancelled.wait_for(|closed| *closed).await; } => {},
        result = copy_bidirectional(&mut local, remote) => { result?; },
    }
    Ok(())
}

fn target_label(target: &Target) -> String {
    match &target.address {
        helios_protocol::Address::Ip(ip) => format!("{ip}:{}", target.port),
        helios_protocol::Address::Domain(domain) => format!("{domain}:{}", target.port),
    }
}

impl Remote {
    async fn route(
        &self,
        target: &Target,
        network: Network,
    ) -> (RouteAction, Vec<std::net::IpAddr>) {
        let rules = self.rules.read().await.clone();
        let report = self.outbound.evaluate_route(&rules, target, network).await;
        (report.action, report.selected_ips)
    }

    fn restore_target(&self, target: Target) -> std::io::Result<Target> {
        let helios_protocol::Address::Ip(ip) = target.address else {
            return Ok(target);
        };
        if let Some(domain) = self.fake_ips.as_ref().and_then(|pool| pool.lookup_ip(ip)) {
            return Target::new(helios_protocol::Address::Domain(domain), target.port)
                .map_err(std::io::Error::other);
        }
        if helios_dns::is_fake_ip(ip) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Fake-IP mapping is missing or expired",
            ));
        }
        Ok(target)
    }

    async fn open(&self, target: Target) -> Result<RemoteStream, RemoteError> {
        let target = self.restore_target(target).map_err(RemoteError::Direct)?;
        if self.is_protected_listener(&target) {
            return Err(RemoteError::Rejected);
        }
        let (action, mut ips) = self.route(&target, Network::Tcp).await;
        match action {
            RouteAction::Direct => {
                if ips.is_empty() {
                    return self.open_direct(&target).await;
                }
                return match timeout(
                    Duration::from_millis(self.connect_milliseconds.into()),
                    self.outbound
                        .connect_ips(target.port, &mut ips, &self.protected_listeners),
                )
                .await
                {
                    Ok(result) => result
                        .map(RemoteStream::Direct)
                        .map_err(RemoteError::Direct),
                    Err(_) => Err(RemoteError::Direct(std::io::ErrorKind::TimedOut.into())),
                };
            }
            RouteAction::Reject => return Err(RemoteError::Rejected),
            RouteAction::Proxy => {}
        }
        let request = ConnectTcp::new(target, self.connect_milliseconds, Vec::new())
            .map_err(|error| RemoteError::Transport(Box::new(error)))?;
        let quic = self.quic.read().await.clone();
        if let Some(quic) = quic {
            match quic.open(&request).await {
                Ok(stream) => return Ok(stream),
                Err(error) if !should_fallback(&error) => return Err(error),
                Err(error) => {
                    // A single flow timeout must not evict a live or newly recovered session.
                    if quic.connection.close_reason().is_some() {
                        let mut current = self.quic.write().await;
                        if current.as_ref().is_some_and(|active| {
                            active.connection.stable_id() == quic.connection.stable_id()
                        }) {
                            *current = None;
                            self.metrics.quic_healthy.store(false, Ordering::Relaxed);
                        }
                    }
                    warn!(event = "quic_flow_failed", fallback = "tls");
                    debug!(event = "quic_flow_error", error = %error);
                }
            }
        }
        self.open_tls(&request).await
    }

    fn is_protected_listener(&self, target: &Target) -> bool {
        self.protected_listeners.iter().any(|listener| {
            listener.port() == target.port
                && match &target.address {
                    helios_protocol::Address::Ip(ip) => *ip == listener.ip(),
                    helios_protocol::Address::Domain(domain) => {
                        listener.ip().is_loopback() && domain.eq_ignore_ascii_case("localhost")
                    }
                }
        })
    }

    async fn open_direct(&self, target: &Target) -> Result<RemoteStream, RemoteError> {
        let connect = self.outbound.connect(target, &self.protected_listeners);
        match timeout(
            Duration::from_millis(self.connect_milliseconds.into()),
            connect,
        )
        .await
        {
            Ok(Ok(stream)) => Ok(RemoteStream::Direct(stream)),
            Ok(Err(error)) => Err(RemoteError::Direct(error)),
            Err(_) => Err(RemoteError::Direct(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "direct connection timed out",
            ))),
        }
    }

    async fn open_tls(&self, request: &ConnectTcp) -> Result<RemoteStream, RemoteError> {
        let result = self.open_tls_inner(request).await;
        self.metrics.tls_checked.store(true, Ordering::Relaxed);
        self.metrics
            .tls_healthy
            .store(result.is_ok(), Ordering::Relaxed);
        result
    }

    async fn open_tls_inner(&self, request: &ConnectTcp) -> Result<RemoteStream, RemoteError> {
        let io = timeout(
            Duration::from_millis(self.connect_milliseconds.into()),
            async {
                let stage = std::time::Instant::now();
                debug!(event = "node_connect_stage", stage = "tcp");
                let tcp = self.outbound.node_tcp(self.server).await?;
                debug!(
                    event = "node_tcp_connected",
                    elapsed_ms = stage.elapsed().as_millis() as u64
                );
                let stage = std::time::Instant::now();
                debug!(event = "node_connect_stage", stage = "tls");
                let mut io = self.tls.connect(self.server_name.clone(), tcp).await?;
                debug!(
                    event = "node_tls_connected",
                    elapsed_ms = stage.elapsed().as_millis() as u64
                );
                let stage = std::time::Instant::now();
                debug!(event = "node_connect_stage", stage = "auth");
                helios_transport::authenticate_client_with_connect(
                    &mut io,
                    &self.credential_id,
                    &self.token,
                    request,
                )
                .await?;
                debug!(
                    event = "node_authenticated",
                    elapsed_ms = stage.elapsed().as_millis() as u64
                );
                Ok::<_, AnyError>(io)
            },
        )
        .await
        .map_err(|error| RemoteError::Transport(Box::new(error)))?
        .map_err(RemoteError::Transport)?;
        Ok(RemoteStream::Tls(Box::new(
            helios_transport::finish_tcp_connect(io, request).await?,
        )))
    }
}

impl QuicRemote {
    async fn open(&self, request: &ConnectTcp) -> Result<RemoteStream, RemoteError> {
        timeout(
            Duration::from_millis(u64::from(request.timeout_ms) + 1000),
            async {
                let (send, recv) = self
                    .connection
                    .open_bi()
                    .await
                    .map_err(|error| RemoteError::Transport(Box::new(error)))?;
                let mut io = FrameIo::new(QuicBiStream::new(send, recv));
                io.set_padding_negotiated(self.padding_negotiated);
                Ok(RemoteStream::Quic(open_tcp(io, 3, request).await?))
            },
        )
        .await
        .map_err(|_| RemoteError::Connect(ConnectError::ResponseTimeout))?
    }
}

fn should_fallback(error: &RemoteError) -> bool {
    !matches!(error, RemoteError::Connect(ConnectError::Rejected(_)))
}

fn socks_reply(error: &RemoteError) -> Socks5Reply {
    match error {
        RemoteError::Rejected => Socks5Reply::NotAllowed,
        RemoteError::Direct(error) => match error.kind() {
            std::io::ErrorKind::ConnectionRefused => Socks5Reply::ConnectionRefused,
            std::io::ErrorKind::TimedOut => Socks5Reply::TtlExpired,
            std::io::ErrorKind::NetworkUnreachable => Socks5Reply::NetworkUnreachable,
            std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NotFound => {
                Socks5Reply::HostUnreachable
            }
            std::io::ErrorKind::PermissionDenied => Socks5Reply::NotAllowed,
            _ => Socks5Reply::GeneralFailure,
        },
        RemoteError::Connect(ConnectError::Rejected(code)) => match code {
            ConnectErrorCode::NotAllowed => Socks5Reply::NotAllowed,
            ConnectErrorCode::NetworkUnreachable => Socks5Reply::NetworkUnreachable,
            ConnectErrorCode::HostUnreachable => Socks5Reply::HostUnreachable,
            ConnectErrorCode::ConnectionRefused => Socks5Reply::ConnectionRefused,
            ConnectErrorCode::Timeout => Socks5Reply::TtlExpired,
            ConnectErrorCode::AddressUnsupported => Socks5Reply::AddressTypeNotSupported,
            _ => Socks5Reply::GeneralFailure,
        },
        _ => Socks5Reply::GeneralFailure,
    }
}

fn parse_command(values: impl IntoIterator<Item = String>) -> Result<DaemonCommand, AnyError> {
    let values = values.into_iter().collect::<Vec<_>>();
    match values.as_slice() {
        [_, command, path] if command == "proxy-watchdog" => {
            let path = PathBuf::from(path);
            if !path.is_absolute() || path.file_name().is_none() { return Err("proxy lease must be an absolute file path".into()); }
            Ok(DaemonCommand::ProxyWatchdog(path))
        },
        [_, command] if command == "version" || command == "--version" => {
            Ok(DaemonCommand::Version)
        }
        [_, command] if command == "recover-network" => Ok(DaemonCommand::RecoverNetwork),
        [_, path] => Ok(DaemonCommand::Run(PathBuf::from(path))),
        [_, command, flag, path, lease_flag, lease_path] if command == "desktop-managed" && flag == "--config" && lease_flag == "--proxy-lease" => {
            let proxy_lease = PathBuf::from(lease_path);
            if !proxy_lease.is_absolute() || proxy_lease.file_name().is_none() {
                return Err("proxy lease must be an absolute file path".into());
            }
            Ok(DaemonCommand::DesktopManaged { config: PathBuf::from(path), proxy_lease })
        }
        [_, command, flag, path] if command == "run" && flag == "--config" => {
            Ok(DaemonCommand::Run(PathBuf::from(path)))
        }
        [_, command, flag, path] if command == "check" && flag == "--config" => {
            Ok(DaemonCommand::Check(PathBuf::from(path)))
        }
        _ => Err("usage: helios-daemon CONFIG_TOML | run --config PATH | check --config PATH | recover-network | version".into()),
    }
}

fn validate_runtime_config(path: PathBuf) -> Result<(), AnyError> {
    let config = DaemonConfig::load(path)?;
    let roots = load_roots(&config.node.ca_certificate)?;
    ClientCrypto::new(roots)?;
    ServerName::try_from(config.node.server_name)?;
    load_token(&config.node.token_file)?;
    if let Some(path) = &config.control_token_file {
        load_token(path)?;
    }
    RuleSet::new(&config.rules)?;
    if let Some(dns) = config.dns {
        FakeIpPool::new(
            dns.fake_ip_capacity,
            Duration::from_secs(dns.fake_ip_ttl_seconds.into()),
        )?;
    }
    Ok(())
}

#[cfg(windows)]
fn recover_proxy_at(path: &Path) -> Result<(), AnyError> {
    recover_proxy_lease(SystemProxyLease::new(WindowsProxyAdapter, path))
}

#[cfg(target_os = "macos")]
fn recover_proxy_at(path: &Path) -> Result<(), AnyError> {
    recover_proxy_lease(SystemProxyLease::new(MacosProxyAdapter, path))
}

#[cfg(target_os = "linux")]
fn recover_proxy_at(path: &Path) -> Result<(), AnyError> {
    recover_proxy_lease(SystemProxyLease::new(LinuxProxyAdapter, path))
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn recover_proxy_lease<A: helios_system_proxy::SystemProxyAdapter>(
    lease: SystemProxyLease<A>,
) -> Result<(), AnyError> {
    match lease.recover()? {
        ReleaseOutcome::Drifted { .. } => {
            Err("system proxy changed outside Helios; user settings were preserved".into())
        }
        _ => Ok(()),
    }
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn recover_proxy_at(_path: &Path) -> Result<(), AnyError> {
    Err("network recovery is only available on Windows and macOS".into())
}

fn recover_network() -> Result<(), AnyError> {
    let path = default_state_dir().join("system-proxy-lease.json");
    std::fs::create_dir_all(path.parent().unwrap())?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path.with_extension("lock"))?;
    lock.try_lock()?;
    recover_proxy_at(&path)
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn default_state_dir() -> PathBuf {
    if cfg!(windows) {
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

#[cfg(test)]
mod tests {
    #[test]
    fn desktop_logging_writes_structured_events_to_stderr() {
        const MARKER: &str = "HELIOS_TEST_LOG_STDERR";
        if std::env::var_os(MARKER).is_some() {
            super::init_logging().unwrap();
            tracing::info!(event = "desktop_log_smoke");
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::desktop_logging_writes_structured_events_to_stderr",
                "--nocapture",
            ])
            .env(MARKER, "1")
            .env("RUST_LOG", "info")
            .output()
            .unwrap();
        assert!(output.status.success());
        let events: Vec<serde_json::Value> = String::from_utf8_lossy(&output.stderr)
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        assert!(
            events
                .iter()
                .any(|value| value["fields"]["event"] == "desktop_log_smoke")
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("desktop_log_smoke"));
    }

    use std::net::IpAddr;

    use helios_protocol::{Address, Frame, FrameType};
    use helios_routing::RuleConfig;
    use helios_transport::{ServerCrypto, accept_tcp_frame, authenticate_server, serve_control};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{
        RootCertStore,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn parses_legacy_and_explicit_daemon_commands() {
        assert!(matches!(
            parse_command(["helios-daemon".into(), "daemon.toml".into()]).unwrap(),
            DaemonCommand::Run(path) if path.as_os_str() == "daemon.toml"
        ));
        assert!(matches!(
            parse_command([
                "helios-daemon".into(),
                "check".into(),
                "--config".into(),
                "daemon.toml".into()
            ])
            .unwrap(),
            DaemonCommand::Check(_)
        ));
        assert!(matches!(
            parse_command(["helios-daemon".into(), "recover-network".into()]).unwrap(),
            DaemonCommand::RecoverNetwork
        ));
        assert!(matches!(
            parse_command(["helios-daemon".into(), "version".into()]).unwrap(),
            DaemonCommand::Version
        ));
        assert!(parse_command(["helios-daemon".into()]).is_err());
    }

    #[test]
    fn managed_daemon_requires_an_explicit_absolute_lease_path() {
        let path = std::env::temp_dir().join("helios-managed-test-lease.json");
        let command = |lease: &Path| {
            parse_command([
                "helios-daemon".into(),
                "desktop-managed".into(),
                "--config".into(),
                "daemon.toml".into(),
                "--proxy-lease".into(),
                lease.to_string_lossy().into_owned(),
            ])
        };
        assert!(
            matches!(command(&path).unwrap(), DaemonCommand::DesktopManaged { proxy_lease, .. } if proxy_lease == path)
        );
        assert!(command(Path::new("relative.json")).is_err());
        assert!(
            parse_command([
                "helios-daemon".into(),
                "desktop-managed".into(),
                "--config".into(),
                "daemon.toml".into()
            ])
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires HELIOS_ISOLATED_PROXY_TEST=1 and a private dbus-run-session/XDG_CONFIG_HOME"]
    fn managed_guard_restores_lease_on_exit_and_on_startup_recovery() {
        use helios_system_proxy::{
            ProxyEndpoint, ProxySettings, SystemProxyAdapter, SystemProxyLease,
        };
        assert_eq!(
            std::env::var("HELIOS_ISOLATED_PROXY_TEST").as_deref(),
            Ok("1")
        );
        let directory = PathBuf::from(
            std::env::var_os("HELIOS_ISOLATED_GSETTINGS_DIR")
                .expect("private test directory required"),
        );
        assert_eq!(
            std::env::var_os("XDG_CONFIG_HOME"),
            Some(directory.clone().into_os_string())
        );
        let path = directory.join("managed-proxy-lease.json");
        let adapter = LinuxProxyAdapter;
        let original = adapter.read().unwrap();
        let lease = SystemProxyLease::new(adapter, path.clone());
        let desired = ProxySettings {
            endpoint: ProxyEndpoint {
                host: "127.0.0.1".into(),
                port: 18080,
            },
            bypass: vec!["localhost".into()],
        };
        lease.acquire(desired.clone()).unwrap();
        assert!(lease.is_applied().unwrap());
        let mut managed = managed_proxy::native(&path, desired.clone()).unwrap();
        assert_eq!(LinuxProxyAdapter.read().unwrap(), original);
        managed.set(true).unwrap();
        assert!(lease.is_applied().unwrap());
        drop(managed);
        assert_eq!(LinuxProxyAdapter.read().unwrap(), original);
        assert!(!path.exists());
        lease.acquire(desired).unwrap();
        recover_proxy_at(&path).unwrap();
        assert_eq!(LinuxProxyAdapter.read().unwrap(), original);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn control_socket_is_private_and_does_not_replace_regular_files() {
        use std::os::unix::fs::PermissionsExt;

        let directory = std::env::temp_dir().join(format!("hcs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let path = directory.join("control.sock");
        let listener = bind_control_socket(Some(&path)).unwrap().unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(listener);
        assert!(!path.exists());

        std::fs::write(&path, b"keep").unwrap();
        assert!(bind_control_socket(Some(&path)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn control_requests_require_the_exact_token() {
        let metrics = DaemonMetrics::new(TransportPreference::Quic);
        let rules = RwLock::new(RuleSet::new(&[]).unwrap());
        let token = [9; 32];
        let request = ControlRequest {
            version: CONTROL_VERSION,
            token,
            command: ControlCommand::GetStatus,
        };
        assert!(matches!(
            control_result(&request, &token, &metrics, &rules).await,
            (ControlResult::Status { .. }, false)
        ));

        let mut wrong = request.clone();
        wrong.token[31] ^= 1;
        assert_eq!(
            control_result(&wrong, &token, &metrics, &rules).await,
            (
                ControlResult::Error {
                    message: "control authentication failed".into()
                },
                false
            )
        );

        let mut old = request;
        old.version = CONTROL_VERSION - 1;
        assert_eq!(
            control_result(&old, &token, &metrics, &rules).await,
            (
                ControlResult::Error {
                    message: format!("unsupported control version {}", CONTROL_VERSION - 1)
                },
                false
            )
        );

        let shutdown = ControlRequest {
            version: CONTROL_VERSION,
            token,
            command: ControlCommand::Shutdown,
        };
        assert_eq!(
            control_result(&shutdown, &token, &metrics, &rules).await,
            (ControlResult::ShutdownAccepted, true)
        );
    }

    #[tokio::test]
    async fn long_flow_details_fit_the_status_frame_without_losing_totals() {
        let metrics = DaemonMetrics::new(TransportPreference::Tls);
        let host = format!(
            "{}.{}.{}.example.com:443",
            "a".repeat(60),
            "b".repeat(60),
            "c".repeat(60)
        );
        let flows: Vec<_> = (0..256)
            .map(|_| {
                ActiveFlow::start(
                    Arc::new(DaemonMetrics::new(TransportPreference::Tls)),
                    "http",
                    host.clone(),
                    "direct",
                    "direct",
                )
            })
            .collect();
        let mut snapshot = metrics.snapshot();
        snapshot.active_flows = 999;
        snapshot.uploaded_bytes = 12345;
        snapshot.active_flow_details = flows.iter().map(|flow| flow.record.snapshot()).collect();
        let mut result = ControlResult::Status { snapshot };
        bound_status_response(&mut result).unwrap();
        let ControlResult::Status { snapshot } = &result else {
            unreachable!()
        };
        assert_eq!(snapshot.active_flows, 999);
        assert_eq!(snapshot.uploaded_bytes, 12345);
        assert!(!snapshot.active_flow_details.is_empty());
        assert!(snapshot.active_flow_details.len() < 256);
        write_message(
            &mut tokio::io::sink(),
            &ControlResponse {
                version: CONTROL_VERSION,
                result,
            },
        )
        .await
        .unwrap();
    }

    #[test]
    fn status_snapshot_does_not_wait_for_system_proxy_io() {
        let metrics = Arc::new(DaemonMetrics::new(TransportPreference::Quic));
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let owner = metrics.clone();
        let owner = std::thread::spawn(move || {
            let _proxy = owner.proxy.lock().unwrap();
            locked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        locked_rx.recv().unwrap();
        let (snapshot_tx, snapshot_rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || snapshot_tx.send(metrics.snapshot()).unwrap());
        let result = snapshot_rx.recv_timeout(Duration::from_millis(500));
        release_tx.send(()).unwrap();
        owner.join().unwrap();
        reader.join().unwrap();
        assert!(result.is_ok(), "status blocked on platform proxy I/O");
    }

    #[tokio::test]
    async fn shutdown_drain_finishes_early_or_at_deadline() {
        let metrics = Arc::new(DaemonMetrics::new(TransportPreference::Tls));
        assert!(wait_for_flows(&metrics, Duration::from_secs(1)).await);

        let flow = ActiveFlow::start(
            metrics.clone(),
            "test",
            "example.com:443".into(),
            "proxy",
            "tls",
        );
        let release = tokio::spawn(async move {
            sleep(Duration::from_millis(30)).await;
            drop(flow);
        });
        let started = Instant::now();
        assert!(wait_for_flows(&metrics, Duration::from_secs(1)).await);
        assert!(started.elapsed() < Duration::from_millis(500));
        release.await.unwrap();

        let _flow = ActiveFlow::start(
            metrics.clone(),
            "test",
            "example.com:443".into(),
            "proxy",
            "tls",
        );
        let started = Instant::now();
        assert!(!wait_for_flows(&metrics, Duration::from_millis(40)).await);
        assert!(started.elapsed() >= Duration::from_millis(40));
    }

    #[test]
    fn active_flow_details_exist_only_for_the_flow_lifetime() {
        let metrics = Arc::new(DaemonMetrics::new(TransportPreference::Tls));
        let flow = ActiveFlow::start(
            metrics.clone(),
            "socks5",
            "example.com:443".into(),
            "proxy",
            "quic",
        );
        flow.upload(100);
        flow.download(200);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.active_flows, 1);
        assert_eq!(snapshot.active_flow_details.len(), 1);
        assert_eq!(snapshot.active_flow_details[0].target, "example.com:443");
        assert_eq!(snapshot.active_flow_details[0].decision, "proxy");
        assert_eq!(snapshot.active_flow_details[0].transport, "quic");
        assert_eq!(snapshot.active_flow_details[0].uploaded_bytes, 100);
        assert_eq!(snapshot.active_flow_details[0].downloaded_bytes, 200);
        drop(flow);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.active_flows, 0);
        assert!(snapshot.active_flow_details.is_empty());
    }

    #[tokio::test]
    async fn full_china_rules_apply_over_control_connection() {
        let configs = helios_client_model::parse_rules(include_str!(
            "../../../config/china-direct-full.rules"
        ))
        .unwrap();
        let metrics = Arc::new(DaemonMetrics::new(TransportPreference::Quic));
        let rules = Arc::new(RwLock::new(RuleSet::new(&[]).unwrap()));
        let token = [4; 32];
        let request = ControlRequest {
            version: CONTROL_VERSION,
            token,
            command: ControlCommand::UpdateRules { rules: configs },
        };
        assert!(serde_json::to_vec(&request).unwrap().len() > 7_000_000);
        let (mut client, server) = tokio::io::duplex(4096);
        let (shutdown, _) = watch::channel(false);
        let server_rules = rules.clone();
        let server = tokio::spawn(async move {
            serve_control_connection(server, metrics, server_rules, token, shutdown).await
        });
        helios_control::write_request(&mut client, &request)
            .await
            .unwrap();
        let response: ControlResponse = helios_control::read_message(&mut client).await.unwrap();
        assert_eq!(response.result, ControlResult::RulesUpdated);
        server.await.unwrap().unwrap();
        let target = Target::new(Address::Domain("baidu.com".into()), 443).unwrap();
        assert_eq!(rules.read().await.decide(&target), RouteAction::Direct);
    }

    #[tokio::test(start_paused = true)]
    async fn incomplete_large_request_times_out_without_changing_rules() {
        let metrics = Arc::new(DaemonMetrics::new(TransportPreference::Quic));
        let rules = Arc::new(RwLock::new(
            RuleSet::new(&[RuleConfig::Final {
                action: RouteAction::Direct,
            }])
            .unwrap(),
        ));
        let (mut client, stream) = tokio::io::duplex(1024);
        let (shutdown, _) = watch::channel(false);
        let server_rules = rules.clone();
        let server = tokio::spawn(async move {
            serve_control_connection(stream, metrics, server_rules, [4; 32], shutdown).await
        });
        write_message(
            &mut client,
            &ControlRequest {
                version: CONTROL_VERSION,
                token: [4; 32],
                command: ControlCommand::LargeRequest { length: 1_000_000 },
            },
        )
        .await
        .unwrap();
        client.write_all(b"{").await.unwrap();
        assert!(
            server
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("deadline")
        );
        let target = Target::new(Address::Domain("example.com".into()), 443).unwrap();
        assert_eq!(rules.read().await.decide(&target), RouteAction::Direct);
    }

    #[tokio::test]
    async fn control_rule_updates_are_atomic() {
        let metrics = DaemonMetrics::new(TransportPreference::Quic);
        let rules = RwLock::new(RuleSet::new(&[]).unwrap());
        let token = [4; 32];
        let target = Target::new(Address::Domain("example.com".into()), 443).unwrap();
        let request = ControlRequest {
            version: CONTROL_VERSION,
            token,
            command: ControlCommand::UpdateRules {
                rules: vec![RuleConfig::Final {
                    action: RouteAction::Direct,
                }],
            },
        };
        assert_eq!(
            control_result(&request, &token, &metrics, &rules).await,
            (ControlResult::RulesUpdated, false)
        );
        assert_eq!(rules.read().await.decide(&target), RouteAction::Direct);

        let invalid = ControlRequest {
            command: ControlCommand::UpdateRules {
                rules: vec![RuleConfig::Domain {
                    value: "example.com".into(),
                    action: RouteAction::Reject,
                }],
            },
            ..request
        };
        assert!(matches!(
            control_result(&invalid, &token, &metrics, &rules).await,
            (ControlResult::Error { .. }, false)
        ));
        assert_eq!(rules.read().await.decide(&target), RouteAction::Direct);
    }

    #[tokio::test]
    async fn authenticated_close_stops_a_real_tcp_relay_and_removes_its_metrics() {
        let metrics = Arc::new(DaemonMetrics::new(TransportPreference::Tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let mut client = client.unwrap();
        let local = accepted.unwrap().0;
        let (remote, accepted) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let mut target = accepted.unwrap().0;
        let metrics_for_relay = metrics.clone();
        let relay = tokio::spawn(async move {
            let mut remote = RemoteStream::Direct(remote.unwrap());
            relay(
                local,
                &mut remote,
                metrics_for_relay,
                "test",
                "localhost:443".into(),
            )
            .await
            .unwrap();
        });
        client.write_all(b"hello").await.unwrap();
        let mut bytes = [0; 5];
        timeout(Duration::from_secs(1), target.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"hello");
        let id = metrics.snapshot().active_flow_details[0].id;
        let token = [5; 32];
        let rules = RwLock::new(RuleSet::new(&[]).unwrap());
        let mut request = ControlRequest {
            version: CONTROL_VERSION,
            token: [0; 32],
            command: ControlCommand::CloseFlow { id },
        };
        assert!(matches!(
            control_result(&request, &token, &metrics, &rules).await,
            (ControlResult::Error { .. }, false)
        ));
        assert!(
            !*metrics.active_flow_details.lock().unwrap()[&id]
                .cancelled
                .borrow()
        );
        request.token = token;
        assert_eq!(
            control_result(&request, &token, &metrics, &rules).await,
            (ControlResult::FlowClosed { id }, false)
        );
        timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), client.read(&mut bytes))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(metrics.snapshot().active_flows, 0);
        assert!(metrics.snapshot().active_flow_details.is_empty());
        assert!(matches!(
            control_result(&request, &token, &metrics, &rules).await,
            (ControlResult::Error { .. }, false)
        ));
    }

    #[test]
    fn fake_ip_targets_restore_the_original_domain() {
        let pool = FakeIpPool::new(4, Duration::from_secs(60)).unwrap();
        let ip = pool.allocate("blocked.example").unwrap();
        let ip6 = pool.allocate_v6("blocked.example").unwrap();
        let remote = Remote {
            outbound: Default::default(),
            _monitors: None,
            tls: ClientCrypto::new(RootCertStore::empty()).unwrap().tls,
            quic: Arc::new(RwLock::new(None)),
            udp_config: None,
            server: "127.0.0.1:9".parse().unwrap(),
            server_name: ServerName::try_from("localhost").unwrap(),
            credential_id: Arc::from("desktop-main"),
            token: [0; 32],
            connect_milliseconds: 1_000,
            rules: Arc::new(RwLock::new(RuleSet::new(&[]).unwrap())),
            protected_listeners: ["127.0.0.1:1".parse().unwrap(); 3],
            metrics: Arc::new(DaemonMetrics::new(TransportPreference::Tls)),
            fake_ips: Some(pool),
        };
        assert_eq!(
            remote
                .restore_target(Target::new(Address::Ip(IpAddr::V4(ip)), 443).unwrap())
                .unwrap(),
            Target::new(Address::Domain("blocked.example".into()), 443).unwrap()
        );
        assert_eq!(
            remote
                .restore_target(Target::new(Address::Ip(IpAddr::V6(ip6)), 443).unwrap())
                .unwrap(),
            Target::new(Address::Domain("blocked.example".into()), 443).unwrap()
        );
        for ip in ["198.18.0.0", "fdfe:dcba:9876::ffff", "::ffff:198.18.0.1"] {
            assert!(
                remote
                    .restore_target(Target::new(Address::Ip(ip.parse().unwrap()), 443).unwrap())
                    .is_err()
            );
        }
    }

    #[test]
    fn maps_connect_errors_to_socks_replies() {
        assert_eq!(
            socks_reply(&RemoteError::Connect(ConnectError::Rejected(
                ConnectErrorCode::ConnectionRefused
            ))),
            Socks5Reply::ConnectionRefused
        );
        assert_eq!(
            socks_reply(&RemoteError::Connect(ConnectError::Rejected(
                ConnectErrorCode::AddressUnsupported
            ))),
            Socks5Reply::AddressTypeNotSupported
        );
        assert!(!should_fallback(&RemoteError::Connect(
            ConnectError::Rejected(ConnectErrorCode::ConnectionRefused)
        )));
        assert!(should_fallback(&RemoteError::Transport(Box::new(
            std::io::Error::other("closed")
        ))));
        assert!(!should_degrade_after_timeout(1));
        assert!(!should_degrade_after_timeout(2));
        assert!(should_degrade_after_timeout(3));
    }

    #[tokio::test]
    async fn health_monitor_records_application_rtt() {
        let (client, server) = tokio::io::duplex(4096);
        let responder = tokio::spawn(serve_control(FrameIo::new(server)));
        let metrics = Arc::new(DaemonMetrics::new(TransportPreference::Quic));
        let mut control = FrameIo::new(client);
        let elapsed = ping(&mut control, 100, b"health").await.unwrap();
        metrics
            .quic_rtt_micros
            .store(elapsed.as_micros().max(1) as u64, Ordering::Relaxed);
        metrics.quic_healthy.store(true, Ordering::Relaxed);
        assert!(metrics.quic_rtt_micros.load(Ordering::Relaxed) > 0);
        assert!(metrics.quic_healthy.load(Ordering::Relaxed));
        metrics.record_udp_drop();
        assert_eq!(metrics.snapshot().udp_dropped_packets, 1);

        responder.abort();
    }

    #[tokio::test]
    async fn socks_udp_associate_relays_over_quic_datagrams() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let server_crypto = ServerCrypto::new(vec![cert_der.clone()], key).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_crypto = ClientCrypto::new(roots).unwrap();
        let quic_endpoint = Endpoint::server(
            server_crypto.quic,
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        )
        .unwrap();
        let server_address = quic_endpoint.local_addr().unwrap();
        let token = [9; 32];
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut bytes = [0; 128];
            let (length, peer) = echo.recv_from(&mut bytes).await.unwrap();
            echo.send_to(&bytes[..length], peer).await.unwrap();
        });
        let server_task = tokio::spawn(async move {
            let connection = quic_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let mut control = FrameIo::new(QuicBiStream::new(send, recv));
            authenticate_server(&mut control, CAP_TCP_CONNECT | CAP_UDP_DATAGRAM, |id| {
                (id == "desktop-main").then_some(token)
            })
            .await
            .unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let mut association = FrameIo::new(QuicBiStream::new(send, recv));
            let request = association.read_frame().await.unwrap();
            assert_eq!(request.frame_type, FrameType::UdpAssociate);
            let association_id = request.request_id;
            association
                .write_frame(
                    &Frame::new(
                        FrameType::UdpAssociateOk,
                        request.request_id,
                        association_id.to_be_bytes().to_vec(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let packet = UdpPacket::decode(&connection.read_datagram().await.unwrap()).unwrap();
            assert_eq!(packet.association_id, association_id);
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket
                .send_to(&packet.payload, ("127.0.0.1", echo_address.port()))
                .await
                .unwrap();
            let mut bytes = [0; 128];
            let (length, source) = socket.recv_from(&mut bytes).await.unwrap();
            let response = UdpPacket::new(
                association_id,
                packet.packet_id,
                Target::new(Address::Ip(source.ip()), source.port()).unwrap(),
                bytes[..length].to_vec(),
            )
            .unwrap()
            .encode()
            .unwrap();
            connection
                .send_datagram(bytes::Bytes::from(response))
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let config = NodeConnectConfig {
            outbound: Default::default(),
            server: server_address,
            server_name: ServerName::try_from("localhost").unwrap(),
            credential_id: Arc::from("desktop-main"),
            token,
            client_config: client_crypto.quic,
        };
        let metrics = Arc::new(DaemonMetrics::new(TransportPreference::Quic));
        let remote = Remote {
            outbound: Default::default(),
            _monitors: None,
            tls: client_crypto.tls,
            quic: Arc::new(RwLock::new(None)),
            udp_config: Some(config),
            server: server_address,
            server_name: ServerName::try_from("localhost").unwrap(),
            credential_id: Arc::from("desktop-main"),
            token,
            connect_milliseconds: 1_000,
            rules: Arc::new(RwLock::new(RuleSet::new(&[]).unwrap())),
            protected_listeners: ["127.0.0.1:1".parse().unwrap(); 3],
            metrics: metrics.clone(),
            fake_ips: None,
        };
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_address = socks_listener.local_addr().unwrap();
        let socks_task = tokio::spawn(async move {
            let (stream, _) = socks_listener.accept().await.unwrap();
            serve_socks(stream, remote, 2, 60).await.unwrap();
        });
        let mut control = TcpStream::connect(socks_address).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut bound = [0; 10];
        control.read_exact(&mut bound).await.unwrap();
        assert_eq!(bound[1], Socks5Reply::Succeeded as u8);
        let proxy_address = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(bound[4], bound[5], bound[6], bound[7])),
            u16::from_be_bytes([bound[8], bound[9]]),
        );
        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packet = UdpDatagram {
            target: Target::new(
                Address::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                echo_address.port(),
            )
            .unwrap(),
            payload: b"helios-udp".to_vec(),
        };
        udp_client
            .send_to(&packet.encode().unwrap(), proxy_address)
            .await
            .unwrap();
        let mut response = [0; 1500];
        let (length, _) = timeout(Duration::from_secs(3), udp_client.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            UdpDatagram::decode(&response[..length]).unwrap().payload,
            b"helios-udp"
        );
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.active_flows, 1);
        assert_eq!(snapshot.uploaded_bytes, b"helios-udp".len() as u64);
        assert_eq!(snapshot.downloaded_bytes, b"helios-udp".len() as u64);
        drop(control);
        socks_task.await.unwrap();
        server_task.await.unwrap();
        echo_task.await.unwrap();
    }

    #[tokio::test]
    async fn direct_socks_udp_works_without_quic() {
        use helios_routing::{RouteAction, RuleConfig};

        for (bind_source, resolve_domain) in [
            (None, false),
            (
                Some(
                    if cfg!(target_os = "linux") {
                        "127.0.0.2"
                    } else {
                        "127.0.0.1"
                    }
                    .parse::<IpAddr>()
                    .unwrap(),
                ),
                false,
            ),
            (None, true),
        ] {
            let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let echo_address = echo.local_addr().unwrap();
            let echo_task = tokio::spawn(async move {
                let mut bytes = [0; 64];
                let (length, peer) = echo.recv_from(&mut bytes).await.unwrap();
                assert_eq!(
                    peer.ip(),
                    bind_source.unwrap_or("127.0.0.1".parse().unwrap())
                );
                echo.send_to(&bytes[..length], peer).await.unwrap();
            });
            let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let dns_address = dns.local_addr().unwrap();
            let dns_task = tokio::spawn(async move {
                let mut bytes = [0; 1024];
                let (length, peer) = dns.recv_from(&mut bytes).await.unwrap();
                let request = hickory_proto::op::Message::from_vec(&bytes[..length]).unwrap();
                let mut response = hickory_proto::op::Message::response(
                    request.id,
                    hickory_proto::op::OpCode::Query,
                );
                response.add_queries(request.queries.clone());
                response.add_answer(hickory_proto::rr::Record::from_rdata(
                    request.queries[0].name().clone(),
                    60,
                    hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                        std::net::Ipv4Addr::LOCALHOST,
                    )),
                ));
                dns.send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            });
            let remote = Remote {
                outbound: outbound::Outbound::new(if resolve_domain {
                    Some(helios_config::OutboundConfig {
                        source_bypass: vec![std::net::Ipv4Addr::LOCALHOST.into()],
                        dns_servers: vec![dns_address],
                    })
                } else {
                    bind_source.map(|source| helios_config::OutboundConfig {
                        source_bypass: vec![source],
                        dns_servers: vec!["127.0.0.1:53".parse().unwrap()],
                    })
                }),
                _monitors: None,
                tls: ClientCrypto::new(RootCertStore::empty()).unwrap().tls,
                quic: Arc::new(RwLock::new(None)),
                udp_config: None,
                server: "127.0.0.1:9".parse().unwrap(),
                server_name: ServerName::try_from("localhost").unwrap(),
                credential_id: Arc::from("desktop-main"),
                token: [0; 32],
                connect_milliseconds: 100,
                rules: Arc::new(RwLock::new(
                    RuleSet::new(&[
                        RuleConfig::IpCidr {
                            value: "127.0.0.0/8".into(),
                            action: RouteAction::Direct,
                            resolve: resolve_domain,
                        },
                        RuleConfig::Final {
                            action: RouteAction::Proxy,
                        },
                    ])
                    .unwrap(),
                )),
                protected_listeners: ["127.0.0.1:1".parse().unwrap(); 3],
                metrics: Arc::new(DaemonMetrics::new(TransportPreference::Tls)),
                fake_ips: None,
            };
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                serve_socks(stream, remote, 2, 60).await.unwrap();
            });
            let mut control = TcpStream::connect(address).await.unwrap();
            control.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            control.read_exact(&mut method).await.unwrap();
            control
                .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut bound = [0; 10];
            control.read_exact(&mut bound).await.unwrap();
            assert_eq!(bound[1], Socks5Reply::Succeeded as u8);
            let relay_address = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(bound[4], bound[5], bound[6], bound[7])),
                u16::from_be_bytes([bound[8], bound[9]]),
            );
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let packet = UdpDatagram {
                target: Target::new(
                    if resolve_domain {
                        Address::Domain("udp.example".into())
                    } else {
                        Address::Ip(echo_address.ip())
                    },
                    echo_address.port(),
                )
                .unwrap(),
                payload: b"direct".to_vec(),
            }
            .encode()
            .unwrap();
            client.send_to(&packet, relay_address).await.unwrap();
            let mut response = [0; 256];
            let (length, _) = timeout(Duration::from_secs(2), client.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                UdpDatagram::decode(&response[..length]).unwrap().payload,
                b"direct"
            );
            drop(control);
            task.await.unwrap();
            echo_task.await.unwrap();
            dns_task.abort();
        }
    }

    #[tokio::test]
    async fn socks_udp_association_expires_when_idle() {
        let remote = Remote {
            outbound: Default::default(),
            _monitors: None,
            tls: ClientCrypto::new(RootCertStore::empty()).unwrap().tls,
            quic: Arc::new(RwLock::new(None)),
            udp_config: None,
            server: "127.0.0.1:1".parse().unwrap(),
            server_name: ServerName::try_from("localhost").unwrap(),
            credential_id: Arc::from("desktop-main"),
            token: [1; 32],
            connect_milliseconds: 1_000,
            rules: Arc::new(RwLock::new(RuleSet::new(&[]).unwrap())),
            protected_listeners: ["127.0.0.1:1".parse().unwrap(); 3],
            metrics: Arc::new(DaemonMetrics::new(TransportPreference::Tls)),
            fake_ips: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_socks(stream, remote, 2, 0).await.unwrap();
        });
        let mut control = TcpStream::connect(address).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        control.read_exact(&mut method).await.unwrap();
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut bound = [0; 10];
        control.read_exact(&mut bound).await.unwrap();
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn direct_http_forward_proxy_rewrites_and_relays_request() {
        use helios_routing::{RouteAction, RuleConfig};

        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            let mut body = [0; 4];
            stream.read_exact(&mut body).await.unwrap();
            request.extend_from_slice(&body);
            assert_eq!(
                request,
                format!(
                    "POST /submit HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: 4\r\n\r\nbody",
                    origin_address.port()
                )
                .as_bytes()
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        let remote = Remote {
            outbound: Default::default(),
            _monitors: None,
            tls: ClientCrypto::new(RootCertStore::empty()).unwrap().tls,
            quic: Arc::new(RwLock::new(None)),
            udp_config: None,
            server: "127.0.0.1:9".parse().unwrap(),
            server_name: ServerName::try_from("localhost").unwrap(),
            credential_id: Arc::from("desktop-main"),
            token: [0; 32],
            connect_milliseconds: 1_000,
            rules: Arc::new(RwLock::new(
                RuleSet::new(&[
                    RuleConfig::IpCidr {
                        value: "127.0.0.0/8".into(),
                        action: RouteAction::Direct,
                        resolve: false,
                    },
                    RuleConfig::Final {
                        action: RouteAction::Proxy,
                    },
                ])
                .unwrap(),
            )),
            protected_listeners: ["127.0.0.1:1".parse().unwrap(); 3],
            metrics: Arc::new(DaemonMetrics::new(TransportPreference::Tls)),
            fake_ips: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_http(stream, remote, 2).await.unwrap();
        });
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        client
            .write_all(
                format!(
                    "POST http://127.0.0.1:{}/submit HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Connection: keep-alive\r\nContent-Length: 4\r\n\r\nbody",
                    origin_address.port(),
                    origin_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(b"\r\n\r\nok"));
        proxy_task.await.unwrap();
        origin_task.await.unwrap();
    }

    #[tokio::test]
    async fn falls_back_to_tls_when_udp_is_unavailable() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let server_tls = ServerCrypto::new(vec![cert_der.clone()], key).unwrap().tls;
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let crypto = ClientCrypto::new(roots).unwrap();
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_address = server_listener.local_addr().unwrap();
        let token = [7; 32];
        let source: IpAddr = if cfg!(target_os = "linux") {
            "127.0.0.2"
        } else {
            "127.0.0.1"
        }
        .parse()
        .unwrap();

        let target = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, peer) = server_listener.accept().await.unwrap();
                assert_eq!(peer.ip(), source);
                let mut io = server_tls.accept(tcp).await.unwrap();
                authenticate_server(&mut io, CAP_TCP_CONNECT, |id| {
                    (id == "desktop-main").then_some(token)
                })
                .await
                .unwrap();
                let frame = io.read_frame().await.unwrap();
                if frame.frame_type == FrameType::Ping {
                    io.write_frame(
                        &Frame::new(FrameType::Pong, frame.request_id, frame.payload).unwrap(),
                    )
                    .await
                    .unwrap();
                } else {
                    let (mut client, mut target) = accept_tcp_frame(io, frame).await.unwrap();
                    copy_bidirectional(&mut client, &mut target).await.unwrap();
                }
            }
        });

        let args = Args {
            outbound: outbound::Outbound::new(Some(helios_config::OutboundConfig {
                source_bypass: vec![source],
                dns_servers: vec!["127.0.0.1:53".parse().unwrap()],
            })),
            transport: TransportPreference::Quic,
            listen: "127.0.0.1:0".parse().unwrap(),
            http_listen: "127.0.0.1:0".parse().unwrap(),
            control_listen: "127.0.0.1:0".parse().unwrap(),
            control_socket: None,
            control_pipe: None,
            server: server_address,
            server_name: ServerName::try_from("localhost").unwrap(),
            credential_id: Arc::from("desktop-main"),
            token,
            socks_handshake_seconds: 1,
            http_handshake_seconds: 1,
            connect_milliseconds: 1_000,
            health_probe_seconds: 30,
            udp_idle_seconds: 60,
            rules: RuleSet::new(&[]).unwrap(),
        };
        let remote = build_remote(&args, crypto, None).await.unwrap();
        assert!(remote.quic.read().await.is_none());
        let request_target =
            Target::new(Address::Ip(target_address.ip()), target_address.port()).unwrap();
        let mut stream = remote.open(request_target).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        stream.shutdown().await.unwrap();
        drop(stream);

        target.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_association_falls_back_to_tls_stream() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let server_tls = ServerCrypto::new(vec![cert_der.clone()], key).unwrap().tls;
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_tls = ClientCrypto::new(roots).unwrap().tls;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let token = [8; 32];
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut io = server_tls.accept(tcp).await.unwrap();
            authenticate_server(&mut io, CAP_UDP_OVER_STREAM, |id| {
                (id == "desktop-main").then_some(token)
            })
            .await
            .unwrap();
            let associate = io.read_frame().await.unwrap();
            assert_eq!(associate.frame_type, FrameType::UdpAssociate);
            io.write_frame(
                &Frame::new(
                    FrameType::UdpAssociateOk,
                    associate.request_id,
                    associate.request_id.to_be_bytes().to_vec(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
            let frame = io.read_frame().await.unwrap();
            let packet = UdpPacket::decode(&frame.payload).unwrap();
            io.write_frame(
                &Frame::new(
                    FrameType::UdpPacket,
                    frame.request_id,
                    packet.encode().unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        });
        let remote = Remote {
            outbound: Default::default(),
            _monitors: None,
            tls: client_tls,
            quic: Arc::new(RwLock::new(None)),
            udp_config: None,
            server: address,
            server_name: ServerName::try_from("localhost").unwrap(),
            credential_id: Arc::from("desktop-main"),
            token,
            connect_milliseconds: 1_000,
            rules: Arc::new(RwLock::new(RuleSet::new(&[]).unwrap())),
            protected_listeners: ["127.0.0.1:1".parse().unwrap(); 3],
            metrics: Arc::new(DaemonMetrics::new(TransportPreference::Tls)),
            fake_ips: None,
        };
        let (mut io, association_id) = open_tls_udp_association(&remote).await.unwrap();
        let packet = UdpPacket::new(
            association_id,
            5,
            Target::new(Address::Domain("example.com".into()), 53).unwrap(),
            b"dns".to_vec(),
        )
        .unwrap();
        io.write_frame(&Frame::new(FrameType::UdpPacket, 5, packet.encode().unwrap()).unwrap())
            .await
            .unwrap();
        let response = io.read_frame().await.unwrap();
        assert_eq!(UdpPacket::decode(&response.payload).unwrap(), packet);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn direct_rule_bypasses_helios_transport_and_protects_inbounds() {
        use helios_routing::{RouteAction, RuleConfig};

        let CertifiedKey {
            cert,
            signing_key: _,
        } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let protected: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let metrics = Arc::new(DaemonMetrics::new(TransportPreference::Tls));
        let source: IpAddr = if cfg!(target_os = "linux") {
            "127.0.0.2"
        } else {
            "127.0.0.1"
        }
        .parse()
        .unwrap();
        let remote = Remote {
            outbound: outbound::Outbound::new(Some(helios_config::OutboundConfig {
                source_bypass: vec![source],
                dns_servers: vec!["127.0.0.1:53".parse().unwrap()],
            })),
            _monitors: None,
            tls: ClientCrypto::new(roots).unwrap().tls,
            quic: Arc::new(RwLock::new(None)),
            udp_config: None,
            server: "127.0.0.1:9".parse().unwrap(),
            server_name: ServerName::try_from("localhost").unwrap(),
            credential_id: Arc::from("desktop-main"),
            token: [7; 32],
            connect_milliseconds: 1_000,
            rules: Arc::new(RwLock::new(
                RuleSet::new(&[
                    RuleConfig::IpCidr {
                        value: "127.0.0.0/8".into(),
                        action: RouteAction::Direct,
                        resolve: false,
                    },
                    RuleConfig::Final {
                        action: RouteAction::Proxy,
                    },
                ])
                .unwrap(),
            )),
            protected_listeners: [
                protected,
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.1:9080".parse().unwrap(),
            ],
            metrics,
            fake_ips: None,
        };
        let target = tokio::spawn(async move {
            let (mut stream, peer) = target_listener.accept().await.unwrap();
            assert_eq!(peer.ip(), source);
            let mut request = [0; 6];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"direct");
            stream.write_all(b"bypass").await.unwrap();
        });

        let destination =
            Target::new(Address::Ip(target_address.ip()), target_address.port()).unwrap();
        let mut stream = remote.open(destination).await.unwrap();
        stream.write_all(b"direct").await.unwrap();
        let mut response = [0; 6];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"bypass");
        target.await.unwrap();

        let recursive = Target::new(Address::Ip(protected.ip()), protected.port()).unwrap();
        assert!(matches!(
            remote.open(recursive).await,
            Err(RemoteError::Rejected)
        ));
    }
}
