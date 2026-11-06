//! Linux TUN uses the installed root helper, never a user-selected executable or root path.
use super::*;
use helios_config::{DesktopTunRequest, OutboundConfig, TunDaemonInfo};
use std::{
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::AsFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    process::ChildStdin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

const HELPER: &str = "/usr/libexec/helios-helper";

pub(super) struct Session {
    pub id: u64,
    pub input: Option<ChildStdin>,
    pub stopping: bool,
    pub cancel: Arc<AtomicBool>,
}
impl Session {
    pub fn new(id: u64) -> Self {
        Self {
            id,
            input: None,
            stopping: false,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn stop(&mut self) {
        self.stopping = true;
        self.cancel.store(true, Ordering::Relaxed);
        self.input.take(); // EOF is the authenticated session's stop request.
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

fn trusted_helper(path: &Path) -> Result<(), AnyError> {
    let path = std::fs::canonicalize(path)
        .map_err(|_| "请先安装 Linux TUN 系统组件（Debian 包或 install-linux-tun.sh）")?;
    for part in path.ancestors() {
        let info = std::fs::symlink_metadata(part)?;
        if info.uid() != 0 || info.mode() & 0o022 != 0 {
            return Err("Linux TUN helper 及其目录必须由 root 拥有，且其他用户不可写".into());
        }
    }
    if !std::fs::metadata(path)?.is_file() {
        return Err("TUN helper is not a regular executable".into());
    }
    Ok(())
}

pub(super) fn prepare(id: u64, ipv6: bool, events: Sender<Event>) {
    thread::spawn(move || {
        let result = (|| {
            trusted_helper(Path::new(HELPER))?;
            run_async(async move {
                let mut source_bypass = Vec::new();
                for destination in ["1.1.1.1:53", "[2606:4700:4700::1111]:53"] {
                    let destination: SocketAddr = destination.parse()?;
                    if destination.is_ipv6() && !ipv6 {
                        continue;
                    }
                    let wildcard = if destination.is_ipv4() {
                        "0.0.0.0:0"
                    } else {
                        "[::]:0"
                    };
                    if let Ok(socket) = UdpSocket::bind(wildcard)
                        && socket.connect(destination).is_ok()
                        && let Ok(local) = socket.local_addr()
                    {
                        source_bypass.push(local.ip());
                    }
                }
                // UDP connect only asks the kernel for a route; it transmits no packet.
                let mut dns_servers = Vec::new();
                for ip in tproxy_config::linux_dns_upstreams().await? {
                    if !ip.is_loopback()
                        && !ip.is_unspecified()
                        && source_bypass
                            .iter()
                            .any(|source| source.is_ipv4() == ip.is_ipv4())
                    {
                        let server = SocketAddr::new(ip, 53);
                        if !dns_servers.contains(&server) {
                            dns_servers.push(server);
                        }
                    }
                }
                dns_servers.truncate(4);
                let config = OutboundConfig {
                    source_bypass,
                    dns_servers,
                };
                config.validate()?;
                Ok(config)
            })
        })()
        .map_err(|error: AnyError| error.to_string());
        let _ = events.send(Event::LinuxTunPrepared(id, result));
    });
}

async fn daemon_info(address: SocketAddr) -> Result<TunDaemonInfo, AnyError> {
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err("TUN daemon negotiation failed".into());
    }
    stream
        .write_all(&[5, 1, 0, 1, 198, 18, 0, 0, 0, 54])
        .await?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await?;
    if reply[..3] != [5, 0, 0] {
        return Err("daemon is not ready for Linux TUN".into());
    }
    let size = match reply[3] {
        1 => 4,
        4 => 16,
        _ => return Err("invalid TUN daemon reply".into()),
    };
    stream.read_exact(&mut vec![0; size + 2]).await?;
    let size = stream.read_u32().await? as usize;
    if size > 4096 {
        return Err("oversized TUN daemon handshake".into());
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(super) fn launch(
    id: u64,
    profile: DesktopProfile,
    cancel: Arc<AtomicBool>,
    events: Sender<Event>,
) {
    thread::spawn(move || {
        let result = launch_inner(id, profile, cancel, &events).map_err(|error| error.to_string());
        let _ = events.send(Event::LinuxTunEnded(id, result));
    });
}

fn launch_inner(
    id: u64,
    profile: DesktopProfile,
    cancel: Arc<AtomicBool>,
    events: &Sender<Event>,
) -> Result<(), AnyError> {
    trusted_helper(Path::new(HELPER))?;
    let outbound = profile
        .tun_outbound
        .clone()
        .ok_or("missing Linux TUN outbound policy")?;
    let socks_listen = profile.socks_listen.parse()?;
    let info = run_async(async {
        for _ in 0..80 {
            if cancel.load(Ordering::Relaxed) {
                return Err("TUN start cancelled".into());
            }
            if let Ok(Ok(info)) =
                tokio::time::timeout(Duration::from_millis(500), daemon_info(socks_listen)).await
                && info.outbound == outbound
            {
                return Ok(info);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("source-bound daemon did not become ready".into())
    })?;
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
            .collect::<Result<Vec<IpAddr>, _>>()?,
        mtu: profile.tun_mtu,
        ipv6_enabled: profile.tun_ipv6_enabled,
        outbound,
        desktop_pid: std::process::id(),
        daemon_pid: info.pid,
    };
    let log_path = default_state_dir().join("tun-helper.log");
    let log = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&log_path)?;
    let mut child = Command::new("/usr/bin/pkexec")
        .args([HELPER, "--desktop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(log))
        .spawn()?;
    let mut input = child.stdin.take().ok_or("missing helper pipe")?;
    let mut bytes = serde_json::to_vec(&request)?;
    bytes.push(b'\n');
    if let Err(error) = input.write_all(&bytes) {
        let _ = child.wait();
        return Err(error.into());
    }
    let _ = events.send(Event::LinuxTunPipe(id, input));
    let stdout = child.stdout.take().ok_or("missing helper output")?;
    let ready = run_async(async {
        let pipe =
            tokio::net::unix::pipe::Receiver::from_owned_fd(stdout.as_fd().try_clone_to_owned()?)?;
        let mut reader = tokio::io::BufReader::new(pipe);
        let mut line = String::new();
        let mut ready = false;
        loop {
            tokio::select! {
                length = reader.read_line(&mut line) => {
                    if length? == 0 { break; }
                    if line.trim() == "ready" {
                        ready = true;
                        let _ = events.send(Event::LinuxTunReady(id));
                    }
                    line.clear();
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Before authorization, pkexec still belongs to this UID and can be
                    // cancelled. After elevation, EOF asks the helper to restore and stop.
                    if cancel.load(Ordering::Relaxed) && !ready { let _ = child.kill(); }
                }
            }
        }
        Ok(ready)
    })?;
    let result = child.wait()?;
    if !result.success() && (!cancel.load(Ordering::Relaxed) || tun_status_file().exists()) {
        let mut details = String::new();
        std::fs::File::open(log_path)?
            .take(65_536)
            .read_to_string(&mut details)?;
        return Err(format!("Linux TUN 启停失败（{result}）：{}", details.trim()).into());
    }
    if !ready && !cancel.load(Ordering::Relaxed) {
        return Err("helper exited before real TUN readiness".into());
    }
    Ok(())
}

pub(super) fn recover(events: Sender<Event>) {
    thread::spawn(move || {
        let result = (|| {
            trusted_helper(Path::new(HELPER))?;
            let output = Command::new("/usr/bin/pkexec")
                .args([HELPER, "--desktop-recover"])
                .output()?;
            if !output.status.success() {
                return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
            }
            Ok(())
        })()
        .map_err(|error: AnyError| error.to_string());
        let _ = events.send(Event::LinuxTunRecovered(result));
    });
}
