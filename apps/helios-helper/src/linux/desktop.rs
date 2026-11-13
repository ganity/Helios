//! The delegated root interface accepts bounded, path-free JSON on a lifetime pipe.
use super::*;
use helios_config::{DesktopTunRequest, TunDaemonInfo};
use std::{
    ffi::OsString,
    os::{
        fd::AsFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    process::{Command, Stdio},
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};

const OWNER: &str = "/var/lib/helios/tun-desktop-owner.json";
const WATCHDOG_READY: &str = "/run/helios/watchdog.ready";
const STATUS: &str = "/run/helios/tun.status";
const LEASE: &str = "/var/lib/helios/tun-route-lease.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct Owner {
    uid: u32,
    pid: u32,
    start: String,
}

fn process_identity(pid: u32, uid: u32) -> Result<String, AnyError> {
    if pid <= 1 || fs::metadata(format!("/proc/{pid}"))?.uid() != uid {
        return Err("TUN owner process has another UID".into());
    }
    let ns = fs::metadata(format!("/proc/{pid}/ns/net"))?;
    let ours = fs::metadata("/proc/self/ns/net")?;
    if (ns.dev(), ns.ino()) != (ours.dev(), ours.ino()) {
        return Err("TUN owner process belongs to another network namespace".into());
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields = stat.rsplit_once(')').ok_or("invalid process identity")?.1;
    if fields.split_whitespace().next() == Some("Z") {
        return Err("owner process exited".into());
    }
    Ok(fields
        .split_whitespace()
        .nth(19)
        .ok_or("missing process start time")?
        .to_owned())
}

fn trusted_program(path: &Path) -> Result<(), AnyError> {
    let path = fs::canonicalize(path)?;
    for part in path.ancestors() {
        let info = fs::symlink_metadata(part)?;
        if info.uid() != 0 || info.mode() & 0o022 != 0 {
            return Err(
                "desktop helper and ancestors must be root-owned and not writable by other users"
                    .into(),
            );
        }
    }
    if !fs::metadata(path)?.is_file() {
        return Err("helper is not a regular executable".into());
    }
    Ok(())
}

fn runtime_directory() -> Result<(), AnyError> {
    let path = Path::new("/run/helios");
    match fs::DirBuilder::new().mode(0o755).create(path) {
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        result => result?,
    }
    let info = fs::symlink_metadata(path)?;
    if !info.is_dir() || info.uid() != 0 || info.mode() & 0o022 != 0 {
        return Err("untrusted helper runtime directory".into());
    }
    // A caller's private umask must not hide the public readiness/recovery marker.
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn owner() -> Result<Option<Owner>, AnyError> {
    match fs::symlink_metadata(OWNER) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(info)
            if info.is_file()
                && info.uid() == 0
                && info.mode() & 0o077 == 0
                && info.len() <= 4096 =>
        {
            Ok(Some(serde_json::from_slice(&fs::read(OWNER)?)?))
        }
        _ => Err("untrusted desktop lease owner record".into()),
    }
}

async fn recover(uid: u32) -> Result<(), AnyError> {
    match owner()? {
        Some(owner) if owner.uid != uid && uid != 0 => {
            return Err("TUN lease belongs to another desktop user".into());
        }
        None if Path::new(LEASE).exists() && uid != 0 => {
            return Err(
                "an administrator's manual TUN lease requires administrator CLI recovery".into(),
            );
        }
        _ => {}
    }
    if Path::new(LEASE).exists() {
        recover_routes().await?;
    }
    for path in [STATUS, OWNER, WATCHDOG_READY] {
        match fs::remove_file(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            result => result?,
        }
    }
    Ok(())
}

pub(crate) async fn command(args: &[OsString]) -> Result<(), AnyError> {
    if fs::metadata("/proc/self")?.uid() != 0 {
        return Err("desktop TUN requires administrator authorization".into());
    }
    trusted_program(&std::env::current_exe()?)?;
    if let [flag, uid, pid, start] = args
        && flag == "--desktop-watchdog"
    {
        if std::env::var_os("PKEXEC_UID").is_some() {
            return Err("watchdog is an internal root-only command".into());
        }
        let uid: u32 = uid.to_str().ok_or("invalid UID")?.parse()?;
        let pid: u32 = pid.to_str().ok_or("invalid PID")?.parse()?;
        return watchdog(uid, pid, start.to_str().ok_or("invalid start time")?).await;
    }
    if args.len() != 1 || (args[0] != "--desktop" && args[0] != "--desktop-recover") {
        return Err("usage: pkexec /usr/libexec/helios-helper --desktop|--desktop-recover".into());
    }
    let uid: u32 = std::env::var("PKEXEC_UID")
        .unwrap_or_else(|_| "0".into())
        .parse()?;
    let _lock = lock_helper_instance()?;
    configure_route_state()?;
    runtime_directory()?;
    recover(uid).await?;
    if args[0] == "--desktop-recover" {
        return Ok(());
    }
    let input = tokio::net::unix::pipe::Receiver::from_owned_fd(
        std::io::stdin().as_fd().try_clone_to_owned()?,
    )?;
    let mut input = BufReader::new(input);
    let mut bytes = Vec::new();
    let size = tokio::time::timeout(
        Duration::from_secs(10),
        (&mut input).take(65_537).read_until(b'\n', &mut bytes),
    )
    .await??;
    if size == 0 || size > 65_536 || bytes.last() != Some(&b'\n') {
        return Err("invalid or oversized desktop request".into());
    }
    let request: DesktopTunRequest = serde_json::from_slice(&bytes)?;
    request.outbound.validate()?;
    if request.node_ips.iter().copied().any(helios_dns::is_fake_ip) {
        return Err("node bypasses must not intersect the shared Fake-IP pools".into());
    }
    if request.node_ips.len() > 64 {
        return Err("too many TUN node bypasses".into());
    }
    let desktop = process_identity(request.desktop_pid, uid)?;
    let daemon = process_identity(request.daemon_pid, uid)?;
    let mut config = HelperConfig {
        desktop_pid: None,
        schema_version: 1,
        socks_listen: request.socks_listen,
        server_ip: request.server_ip,
        tun_name: Some("heliostun0".into()),
        mtu: request.mtu,
        ipv6_enabled: request.ipv6_enabled,
        source_bypass: request.outbound.source_bypass.clone(),
        bypass: request.node_ips.iter().copied().map(host_cidr).collect(),
        status_file: STATUS.into(),
        stop_file: "/run/helios/unused-desktop-stop".into(),
    };
    config
        .bypass
        .extend(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].map(str::to_owned));
    config.validate_for_start()?;
    preflight(&config).await?;
    tokio::time::timeout(Duration::from_secs(3), check_daemon(&request)).await??;
    let uplink = tproxy_config::linux_uplink_snapshot(&config.source_bypass, "heliostun0").await?;
    let our_start = process_identity(std::process::id(), 0)?;
    let record = Owner {
        uid,
        pid: std::process::id(),
        start: our_start.clone(),
    };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(OWNER)?;
    file.write_all(&serde_json::to_vec(&record)?)?;
    file.sync_all()?;
    // The separate root watcher survives SIGKILL and cleans only this exact owner record.
    let mut guardian = Command::new(std::env::current_exe()?)
        .args([
            "--desktop-watchdog",
            &uid.to_string(),
            &record.pid.to_string(),
            &our_start,
        ])
        .env_clear()
        .stdin(Stdio::null())
        .spawn()?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if guardian.try_wait()?.is_some() {
                return Err::<(), AnyError>("TUN recovery watchdog failed to start".into());
            }
            if fs::read_to_string(WATCHDOG_READY).ok().as_deref()
                == Some(&guardian.id().to_string())
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let mut status = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(STATUS)?;
    use std::os::unix::fs::PermissionsExt;
    status.set_permissions(fs::Permissions::from_mode(0o644))?;
    status.write_all(b"starting\n")?;
    let shutdown = CancellationToken::new();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let run = super::run(&config, config.tun_args()?, shutdown.clone(), Some(tx));
    tokio::pin!(run);
    let monitor = async {
        let mut rx = rx;
        tokio::select! {
            ready = &mut rx => {
                ready.map_err(|_| "TUN stopped before readiness")?;
                status.set_len(0)?;
                std::io::Seek::rewind(&mut status)?;
                status.write_all(b"ready\n")?;
                std::io::stdout().write_all(b"ready\n")?;
                std::io::stdout().flush()?;
            }
            _ = input.read_u8() => return Ok::<(), AnyError>(()),
        }
        loop {
            tokio::select! {
                _ = input.read_u8() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_millis(500)) => {},
            }
            status.set_modified(std::time::SystemTime::now())?;
            if process_identity(request.desktop_pid, uid).ok().as_ref() != Some(&desktop)
                || process_identity(request.daemon_pid, uid).ok().as_ref() != Some(&daemon)
            {
                return Err("desktop or daemon process exited".into());
            }
            if tproxy_config::linux_uplink_snapshot(&config.source_bypass, "heliostun0").await?
                != uplink
            {
                return Err(
                    "physical network changed; TUN stopped and must reacquire its uplink".into(),
                );
            }
            tproxy_config::check_linux_tun().await?;
            tokio::time::timeout(Duration::from_secs(3), check_daemon(&request)).await??;
        }
    };
    tokio::pin!(monitor);
    let result: Result<(), AnyError> = tokio::select! {
        result = &mut run => result.map(|_| ()).map_err(Into::into),
        trigger = &mut monitor => {
            shutdown.cancel();
            let result = run.await;
            result?;
            trigger
        }
        signal = shutdown_signal() => {
            shutdown.cancel();
            run.await?;
            signal.map_err(Into::into)
        }
    };
    if !Path::new(LEASE).exists() {
        recover(uid).await?;
    }
    // Reap the watcher on an ordinary exit; SIGKILL is handled by its parent-identity check.
    if !Path::new(LEASE).exists() {
        let _ = guardian.kill();
        let _ = guardian.wait();
    }
    // With a pending lease, exit and let the independent watcher retry after this lock drops.
    result
}

async fn watchdog(uid: u32, pid: u32, start: &str) -> Result<(), AnyError> {
    let Some(record) = owner()? else {
        return Ok(());
    };
    if record.uid != uid || record.pid != pid || record.start != start {
        return Ok(());
    }
    let mut ready = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(WATCHDOG_READY)?;
    ready.write_all(std::process::id().to_string().as_bytes())?;
    ready.sync_all()?;
    while process_identity(pid, 0).ok().as_deref() == Some(start) {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let _lock = match lock_helper_instance() {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("TUN watchdog lock unavailable: {error}");
            return Ok(());
        }
    };
    configure_route_state()?;
    let Some(record) = owner()? else {
        return Ok(());
    };
    if record.uid != uid || record.pid != pid || record.start != start {
        return Ok(());
    }
    for _ in 0..20 {
        match recover(uid).await {
            Ok(()) => return Ok(()),
            Err(error) => eprintln!("TUN recovery pending: {error}"),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    recover(uid).await
}

async fn check_daemon(request: &DesktopTunRequest) -> Result<(), AnyError> {
    let mut stream = tokio::net::TcpStream::connect(request.socks_listen).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err("daemon refused TUN handshake".into());
    }
    stream
        .write_all(&[5, 1, 0, 1, 198, 18, 0, 0, 0, 54])
        .await?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await?;
    if reply[..3] != [5, 0, 0] {
        return Err("daemon does not support the TUN configuration handshake".into());
    }
    let size = match reply[3] {
        1 => 4,
        4 => 16,
        _ => return Err("invalid TUN handshake response".into()),
    };
    stream.read_exact(&mut vec![0; size + 2]).await?;
    let length = stream.read_u32().await? as usize;
    if length > 4096 {
        return Err("oversized daemon handshake".into());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    let info: TunDaemonInfo = serde_json::from_slice(&bytes)?;
    if info.pid != request.daemon_pid || info.outbound != request.outbound {
        return Err("helper and daemon uplink/DNS configurations disagree".into());
    }
    Ok(())
}
