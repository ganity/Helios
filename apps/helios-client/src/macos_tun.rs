//! Only installation/update requires authorization; TUN sessions use a local service socket.
use super::*;
use helios_config::{
    DesktopTunRequest, MACOS_TUN_SOCKET, OutboundConfig, TunServiceReply, TunServiceRequest,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn connect() -> Result<tokio::net::UnixStream, AnyError> {
    let stream = tokio::net::UnixStream::connect(MACOS_TUN_SOCKET).await?;
    if stream.peer_cred()?.uid() != 0 {
        return Err("TUN service is not running as root".into());
    }
    Ok(stream)
}

async fn send(
    stream: &mut tokio::net::UnixStream,
    request: &TunServiceRequest,
) -> Result<(), AnyError> {
    let mut bytes = serde_json::to_vec(request)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn receive<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<TunServiceReply, AnyError> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    let size = reader.take(65_537).read_until(b'\n', &mut bytes).await?;
    if size == 0 || size > 65_536 || bytes.last() != Some(&b'\n') {
        return Err("TUN service disconnected; see /Library/Logs/Helios/helper.log".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

async fn service_digest() -> Result<String, AnyError> {
    let mut stream = connect().await?;
    send(&mut stream, &TunServiceRequest::Ping {}).await?;
    match receive(&mut BufReader::new(stream)).await? {
        TunServiceReply::Available { digest } => Ok(digest),
        _ => Err("unexpected TUN service reply".into()),
    }
}

fn ensure_service(binary: &Path) -> Result<(), AnyError> {
    let digest = format!("{:x}", Sha256::digest(std::fs::read(binary)?));
    if run_async(async { tokio::time::timeout(Duration::from_secs(3), service_digest()).await? })
        .is_ok_and(|installed| installed == digest)
    {
        return Ok(());
    }
    let uid = Command::new("/usr/bin/id").arg("-u").output()?;
    if !uid.status.success() {
        return Err("cannot identify desktop user".into());
    }
    let uid: u32 = std::str::from_utf8(&uid.stdout)?.trim().parse()?;
    let script = r#"on run argv
set helperCommand to quoted form of item 1 of argv & " --install-service " & quoted form of item 2 of argv & " " & quoted form of item 3 of argv
do shell script helperCommand with administrator privileges
end run"#;
    let output = Command::new("/usr/bin/osascript")
        .args(["-e", script])
        .arg(binary)
        .arg(uid.to_string())
        .arg(std::env::current_exe()?)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "安装 TUN 系统服务失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    run_async(async {
        for _ in 0..50 {
            if tokio::time::timeout(Duration::from_secs(1), service_digest())
                .await
                .is_ok_and(|result| result.is_ok_and(|installed| installed == digest))
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("TUN 系统服务未就绪；请查看 /Library/Logs/Helios/helper.log".into())
    })
}

pub(super) fn prepare(id: u64, profile: &DesktopProfile, events: Sender<Event>) {
    let profile = profile.clone();
    thread::spawn(move || {
        let result = (|| {
            ensure_service(&profile.helper_binary)?;
            run_async(recover_network())?;
            let (source_bypass, dns) =
                tproxy_config::macos_uplink_snapshot(profile.tun_ipv6_enabled)?;
            let config = OutboundConfig {
                source_bypass,
                dns_servers: dns.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect(),
            };
            config.validate()?;
            Ok(config)
        })()
        .map_err(|error: AnyError| error.to_string());
        let _ = events.send(Event::TunPrepared(id, result));
    });
}

async fn recover_network() -> Result<(), AnyError> {
    let mut stream = connect().await?;
    send(&mut stream, &TunServiceRequest::Recover {}).await?;
    match tokio::time::timeout(
        Duration::from_secs(30),
        receive(&mut BufReader::new(stream)),
    )
    .await??
    {
        TunServiceReply::Ended { error: None } => Ok(()),
        TunServiceReply::Ended { error: Some(error) } => Err(error.into()),
        _ => Err("unexpected TUN recovery reply".into()),
    }
}

pub(super) fn recover(_profile: &DesktopProfile, events: Sender<Event>) {
    thread::spawn(move || {
        // Recovery never reinstalls the service or opens an authorization dialog.
        let result = run_async(recover_network()).map_err(|error| error.to_string());
        let _ = events.send(Event::TunRecovered(result));
    });
}

pub(super) fn launch(
    id: u64,
    profile: DesktopProfile,
    cancel: Arc<AtomicBool>,
    events: Sender<Event>,
) {
    thread::spawn(move || {
        let result =
            launch_inner(id, &profile, &cancel, &events).map_err(|error| error.to_string());
        let _ = events.send(Event::TunEnded(id, result));
    });
}

fn launch_inner(
    id: u64,
    profile: &DesktopProfile,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<(), AnyError> {
    let outbound = profile
        .tun_outbound
        .clone()
        .ok_or("missing TUN outbound policy")?;
    let socks_listen = profile.socks_listen.parse()?;
    run_async(async {
        let mut info = None;
        for _ in 0..80 {
            if cancel.load(Ordering::Relaxed) {
                return Ok(());
            }
            if let Ok(Ok(daemon)) =
                tokio::time::timeout(Duration::from_millis(500), daemon_info(socks_listen)).await
                && daemon.outbound == outbound
            {
                info = Some(daemon);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let info = info.ok_or("source-bound daemon did not become ready")?;
        if cancel.load(Ordering::Relaxed) {
            return Ok(());
        }
        let request = DesktopTunRequest {
            socks_listen,
            server_ip: profile.active_node().config()?.server.ip(),
            node_ips: profile
                .nodes
                .iter()
                .map(|node| node.config().map(|node| node.server.ip()))
                .collect::<Result<Vec<_>, _>>()?,
            mtu: profile.tun_mtu,
            ipv6_enabled: profile.tun_ipv6_enabled,
            outbound,
            desktop_pid: std::process::id(),
            daemon_pid: info.pid,
        };
        let mut stream = connect().await?;
        send(&mut stream, &TunServiceRequest::Start { config: request }).await?;
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut bytes = Vec::new();
        let mut ready = false;
        let mut stopping = false;
        let started = Instant::now();
        loop {
            tokio::select! {
                size = reader.read_until(b'\n', &mut bytes) => {
                    if size? == 0 || bytes.len() > 65_536 { return Err("TUN service disconnected; see /Library/Logs/Helios/helper.log".into()); }
                    match serde_json::from_slice::<TunServiceReply>(&bytes)? {
                        TunServiceReply::Ready if !stopping => { ready = true; let _ = events.send(Event::TunReady(id)); }
                        TunServiceReply::Ended { error: Some(error) } => return Err(error.into()),
                        TunServiceReply::Ended { error: None } => return if ready || cancel.load(Ordering::Relaxed) { Ok(()) } else { Err("TUN stopped before readiness".into()) },
                        _ => {},
                    }
                    bytes.clear();
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if !stopping && (cancel.load(Ordering::Relaxed) || (!ready && started.elapsed() > Duration::from_secs(30))) {
                        writer.shutdown().await?;
                        stopping = true;
                    }
                }
            }
        }
    })
}
