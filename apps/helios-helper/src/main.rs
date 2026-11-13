use std::{
    error::Error,
    fs,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::Deserialize;
use tproxy_config::IpCidr;
use tproxy_config::tproxy_remove;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use tun2proxy::general_run_async;
use tun2proxy::{ArgDns, ArgProxy, Args, CancellationToken};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod session;

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperConfig {
    schema_version: u8,
    socks_listen: SocketAddr,
    server_ip: IpAddr,
    #[serde(default)]
    tun_name: Option<String>,
    #[serde(default = "default_mtu")]
    mtu: u16,
    #[serde(default)]
    ipv6_enabled: bool,
    #[serde(default)]
    bypass: Vec<String>,
    #[serde(default)]
    source_bypass: Vec<IpAddr>,
    #[serde(default)]
    desktop_pid: Option<u32>,
    status_file: PathBuf,
    stop_file: PathBuf,
}

impl HelperConfig {
    fn load(path: impl AsRef<Path>) -> Result<Self, AnyError> {
        let config: Self = toml::from_str(&fs::read_to_string(path)?)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), AnyError> {
        if self.schema_version != 1 {
            return Err("unsupported helper schema_version".into());
        }
        if !self.socks_listen.ip().is_loopback() || self.socks_listen.port() == 0 {
            return Err("socks_listen must be a loopback address with a nonzero port".into());
        }
        if self.server_ip.is_loopback()
            || self.server_ip.is_unspecified()
            || helios_dns::is_fake_ip(self.server_ip)
        {
            return Err("server_ip must be the public Helios server IP".into());
        }
        if !(576..=9000).contains(&self.mtu) {
            return Err("mtu must be between 576 and 9000".into());
        }
        if cfg!(any(target_os = "linux", target_os = "macos")) && !self.source_bypass.is_empty() {
            helios_config::OutboundConfig {
                source_bypass: self.source_bypass.clone(),
                dns_servers: vec![SocketAddr::new(self.server_ip, 53)],
            }
            .validate()?;
        } else if !cfg!(any(target_os = "linux", target_os = "macos"))
            && !self.source_bypass.is_empty()
        {
            return Err("source_bypass requires Linux or macOS".into());
        }
        if cfg!(target_os = "linux")
            && let Some(name) = &self.tun_name
            && (name.is_empty()
                || name.len() > 15
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)))
        {
            return Err("tun_name must contain 1 to 15 ASCII letters, digits, '_' or '-'".into());
        }
        for value in &self.bypass {
            IpCidr::from_str(value)?;
        }
        if !self.status_file.is_absolute() || !self.stop_file.is_absolute() {
            return Err("status_file and stop_file must be absolute paths".into());
        }
        if self.status_file == self.stop_file {
            return Err("status_file and stop_file must be different".into());
        }
        Ok(())
    }

    fn validate_for_start(&self) -> Result<(), AnyError> {
        self.validate()?;
        if self.desktop_pid.is_some_and(|pid| pid <= 1) {
            return Err("invalid desktop process ID".into());
        }
        if cfg!(any(target_os = "linux", target_os = "macos")) && self.source_bypass.is_empty() {
            return Err("TUN requires source_bypass matching the running daemon; legacy unbound routing is unsafe".into());
        }
        Ok(())
    }

    fn tun_args(&self) -> Result<Args, AnyError> {
        let mut args = Args {
            proxy: ArgProxy::try_from(format!("socks5://{}", self.socks_listen).as_str())?,
            tun: self.tun_name.clone(),
            ipv6_enabled: self.ipv6_enabled,
            setup: true,
            dns: ArgDns::Virtual,
            mtu: self.mtu,
            tcp_mss: Some(self.mtu.saturating_sub(40)),
            udp_timeout: 60,
            exit_on_fatal_error: true,
            ..Args::default()
        };
        args.bypass
            .push(IpCidr::from_str(&host_cidr(self.server_ip))?);
        for value in &self.bypass {
            args.bypass.push(IpCidr::from_str(value)?);
        }
        Ok(args)
    }
}

fn default_mtu() -> u16 {
    1280
}

fn host_cidr(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => format!("{ip}/32"),
        IpAddr::V6(ip) => format!("{ip}/128"),
    }
}

fn finish_helper_run(path: &Path, result: Result<(), AnyError>) -> Result<(), AnyError> {
    result?;
    fs::remove_file(path)?;
    Ok(())
}

fn create_status_file(path: &Path) -> Result<fs::File, AnyError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if cfg!(target_os = "macos") {
            0o644
        } else {
            0o600
        });
    }
    let mut file = options.open(path)?;
    file.write_all(std::process::id().to_string().as_bytes())?;
    Ok(file)
}

async fn wait_for_stop(path: &Path, status: &fs::File) -> Result<(), AnyError> {
    loop {
        if path.exists() {
            fs::remove_file(path)?;
            return Ok(());
        }
        status.set_modified(std::time::SystemTime::now())?;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    #[cfg(target_os = "macos")]
    let log = macos_log_file()?;
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(move || {
            #[cfg(target_os = "macos")]
            {
                Box::new(log.try_clone().expect("clone helper log")) as Box<dyn Write + Send>
            }
            #[cfg(not(target_os = "macos"))]
            {
                Box::new(std::io::stderr()) as Box<dyn Write + Send>
            }
        })
        .try_init()
        .ok();
    let result = run_helper().await;
    match &result {
        Ok(()) => tracing::info!(event = "tun_helper_finished"),
        Err(error) => tracing::error!(event = "tun_helper_failed", error = %error),
    }
    result
}

async fn run_helper() -> Result<(), AnyError> {
    tracing::info!(event = "tun_helper_started");
    let values: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(target_os = "linux")]
    {
        if values
            .first()
            .is_some_and(|arg| arg.to_string_lossy().starts_with("--desktop"))
        {
            return session::desktop::command(&values).await;
        }
        if std::env::var_os("PKEXEC_UID").is_some() {
            return Err("pkexec only supports --desktop and --desktop-recover; administrator CLI mode is not delegated".into());
        }
    }
    let (recover, path) = parse_command(&values)?;
    let config = HelperConfig::load(&path)
        .map_err(|error| format!("load helper config {}: {error}", path.display()))?;
    #[cfg(unix)]
    let _instance_lock = lock_helper_instance()?;
    configure_route_state()?;
    if recover {
        return recover_helper(&config).await;
    }
    config.validate_for_start()?;
    if status_is_fresh(&config.status_file) {
        return Err("another helios-helper instance is already running".into());
    }
    if config.status_file.exists() {
        return Err("stale helper state detected; refusing to modify routes without a trusted recovery record".into());
    }
    let args = config.tun_args()?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    session::preflight(&config).await?;
    if let Some(parent) = config.status_file.parent() {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_file(&config.stop_file);
    let status_file = create_status_file(&config.status_file)?;
    let shutdown = CancellationToken::new();
    #[cfg(target_os = "linux")]
    let run = session::run(&config, args, shutdown.clone(), None);
    #[cfg(target_os = "macos")]
    let run = async {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let run = session::run(&config, args, shutdown.clone(), Some(tx));
        tokio::pin!(run);
        tokio::select! {
            result = &mut run => result,
            ready = rx => {
                if ready.is_ok() {
                    let mut status = &status_file;
                    use std::io::{Seek, SeekFrom};
                    if let Err(error) = status.seek(SeekFrom::Start(0)).and_then(|_| status.write_all(format!("ready:{}", std::process::id()).as_bytes())).and_then(|_|status.sync_all()) {
                        shutdown.cancel(); let _ = run.await; return Err(error);
                    }
                }
                run.await
            }
        }
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let run = general_run_async(args, config.mtu, false, shutdown.clone());
    tokio::pin!(run);

    let result: Result<(), AnyError> = tokio::select! {
        result = &mut run => {
            result.map(|_| ()).map_err(Into::into)
        }
        signal = shutdown_signal() => {
            shutdown.cancel();
            let result = run.await;
            signal?;
            result.map(|_| ()).map_err(Into::into)
        }
        owner = wait_for_desktop(config.desktop_pid) => {
            shutdown.cancel();
            let result = run.await;
            owner.and(result.map(|_| ()).map_err(Into::into))
        }
        stop = wait_for_stop(&config.stop_file, &status_file) => {
            shutdown.cancel();
            let result = run.await;
            stop.and(result.map(|_| ()).map_err(Into::into))
        }
    };
    #[cfg(not(target_os = "macos"))]
    drop(status_file);
    #[cfg(target_os = "linux")]
    let pending = Path::new("/var/lib/helios/tun-route-lease.json").try_exists()?;
    #[cfg(target_os = "macos")]
    let pending = route_state_file()?.try_exists()?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if result.is_err() && !pending {
        // A failed preflight or a fully recovered data-plane error has no pending network lease.
        fs::remove_file(&config.status_file)?;
        return result;
    }
    finish_helper_run(&config.status_file, result)
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

#[cfg(unix)]
fn lock_helper_instance() -> Result<fs::File, AnyError> {
    use std::os::unix::fs::MetadataExt;

    #[cfg(target_os = "macos")]
    let path = Path::new("/Library/Application Support/Helios/helios-helper.lock");
    #[cfg(not(target_os = "macos"))]
    let path = Path::new("/run/helios-helper.lock");
    #[cfg(target_os = "macos")]
    prepare_private_lock_directory(path.parent().unwrap())?;
    let parent = fs::symlink_metadata(path.parent().unwrap())?;
    if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
        return Err("helper lock directory must be a root-owned, non-writable directory".into());
    }
    let file = lock_instance_file(path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("helper lock must be owned by root and not writable by other users".into());
    }
    Ok(file)
}

#[cfg(all(unix, any(test, target_os = "macos")))]
fn prepare_private_lock_directory(path: &Path) -> Result<(), AnyError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    // macOS's shared runtime directory may be group-writable; use our own private directory.
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        result => result?,
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err("helper lock directory must be a private directory".into());
    }
    // The caller checks root ownership before opening the lock.
    Ok(())
}

#[cfg(unix)]
fn lock_instance_file(path: &Path) -> Result<fs::File, AnyError> {
    use std::os::unix::fs::OpenOptionsExt;

    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() => {
            return Err("helper lock is not a regular file".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    file.try_lock()
        .map_err(|error| format!("another helper operation holds the instance lock: {error}"))?;
    // Never unlink the lock: all processes must lock the same inode.
    Ok(file)
}

fn status_is_fresh(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
        .is_ok_and(|age| age < std::time::Duration::from_secs(2))
}

async fn recover_helper(config: &HelperConfig) -> Result<(), AnyError> {
    if status_is_fresh(&config.status_file) {
        return Err(
            "helios-helper heartbeat is active; stop the helper before recovering routes".into(),
        );
    }
    #[cfg(target_os = "macos")]
    if route_state_file()?.try_exists()? {
        recover_routes().await?;
    }
    #[cfg(not(target_os = "macos"))]
    recover_routes().await?;
    let _ = fs::remove_file(&config.status_file);
    let _ = fs::remove_file(&config.stop_file);
    Ok(())
}

async fn recover_routes() -> Result<(), AnyError> {
    tproxy_remove(None).await.map_err(|error| {
        #[cfg(any(windows, target_os = "macos"))]
        let path = route_state_file().unwrap_or_default();
        #[cfg(target_os = "linux")]
        let path = PathBuf::from("/var/lib/helios/tun-route-lease.json");
        format!(
            "restore TUN routes from {}: {error}; recovery state preserved",
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_log_file() -> Result<fs::File, AnyError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    let directory = Path::new("/Library/Logs/Helios");
    match fs::DirBuilder::new().mode(0o755).create(directory) {
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        result => result?,
    }
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("untrusted helper log directory".into());
    }
    let path = directory.join("helper.log");
    match fs::symlink_metadata(&path) {
        Ok(metadata)
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 =>
        {
            return Err("untrusted helper log file".into());
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o644))?;
    if file.metadata()?.len() > 5 * 1024 * 1024 {
        file.set_len(0)?;
    }
    Ok(file)
}

fn parse_command(values: &[std::ffi::OsString]) -> Result<(bool, PathBuf), AnyError> {
    match values {
        [path] => Ok((false, PathBuf::from(path))),
        [flag, path] if flag == "--recover" => Ok((true, PathBuf::from(path))),
        _ => Err("usage: helios-helper [--recover] CONFIG.toml (run with platform administrator privileges)".into()),
    }
}

#[cfg(windows)]
fn route_state_file() -> Result<PathBuf, AnyError> {
    Ok(
        PathBuf::from(std::env::var_os("ProgramData").ok_or("ProgramData is not set")?)
            .join("Helios")
            .join("tun-route-lease.json"),
    )
}

#[cfg(target_os = "macos")]
fn route_state_file() -> Result<PathBuf, AnyError> {
    Ok(PathBuf::from(
        "/Library/Application Support/Helios/tun-route-lease.json",
    ))
}

#[cfg(any(windows, target_os = "macos"))]
fn configure_route_state() -> Result<(), AnyError> {
    tproxy_config::set_state_file_path(route_state_file()?)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_route_state() -> Result<(), AnyError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let directory = Path::new("/var/lib/helios");
    match fs::DirBuilder::new().mode(0o700).create(directory) {
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        result => result?,
    }
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err("Linux route journal directory must be a root-owned, private directory".into());
    }
    let path = directory.join("tun-route-lease.json");
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (!metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0)
    {
        return Err("Linux route journal must be a root-owned, private regular file".into());
    }
    tproxy_config::set_state_file_path(path)?;
    Ok(())
}

#[cfg(target_os = "macos")]
async fn wait_for_desktop(pid: Option<u32>) -> Result<(), AnyError> {
    let Some(pid) = pid else {
        return std::future::pending().await;
    };
    let identity = || -> std::io::Result<Vec<u8>> {
        let output = std::process::Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "lstart="])
            .output()?;
        Ok(if output.status.success() {
            output.stdout
        } else {
            Vec::new()
        })
    };
    let original = identity()?;
    if original.is_empty() {
        return Ok(());
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if identity()? != original {
            return Ok(());
        }
    }
}

#[cfg(not(target_os = "macos"))]
async fn wait_for_desktop(_pid: Option<u32>) -> Result<(), AnyError> {
    std::future::pending().await
}

#[cfg(test)]
mod tests {
    use super::*;

    // fork on macOS can temporarily inherit another test's flock until exec closes it.
    #[cfg(unix)]
    static CHILD_PROCESS_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    #[test]
    fn private_lock_directory_does_not_require_changing_shared_parent_permissions() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        let directory = std::env::temp_dir().join(format!(
            "helios-private-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o775)).unwrap();
        let private = directory.join("Helios");
        prepare_private_lock_directory(&private).unwrap();
        prepare_private_lock_directory(&private).unwrap();
        assert_eq!(fs::metadata(&private).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o775);
        let lock = lock_instance_file(&private.join("helper.lock")).unwrap();
        assert!(lock_instance_file(&private.join("helper.lock")).is_err());
        drop(lock);

        fs::set_permissions(&private, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(prepare_private_lock_directory(&private).is_err());
        assert_eq!(fs::metadata(&private).unwrap().mode() & 0o777, 0o770);
        let link = directory.join("linked");
        symlink(&private, &link).unwrap();
        assert!(prepare_private_lock_directory(&link).is_err());
        let file = directory.join("file");
        fs::write(&file, b"preserve").unwrap();
        assert!(prepare_private_lock_directory(&file).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"preserve");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_run_preserves_status_and_success_cleans_it() {
        let path = std::env::temp_dir().join(format!(
            "helios-helper-finish-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        drop(create_status_file(&path).unwrap());
        let original = fs::read(&path).unwrap();
        assert!(finish_helper_run(&path, Err("route cleanup failed".into())).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        finish_helper_run(&path, Ok(())).unwrap();
        assert!(!path.exists());
        assert!(finish_helper_run(&path, Ok(())).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn heartbeat_never_follows_replaced_status_symlink() {
        let directory = std::env::temp_dir().join(format!(
            "helios-helper-status-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("status");
        let target = directory.join("target");
        let stop = directory.join("stop");
        fs::write(&target, b"preserve").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(create_status_file(&path).is_err());
        fs::remove_file(&path).unwrap();
        let status = create_status_file(&path).unwrap();
        assert!(create_status_file(&path).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let before = fs::metadata(&target).unwrap().modified().unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                wait_for_stop(&stop, &status)
            )
            .await
            .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), b"preserve");
        assert_eq!(fs::metadata(&target).unwrap().modified().unwrap(), before);
        fs::write(&stop, b"stop").unwrap();
        wait_for_stop(&stop, &status).await.unwrap();
        assert!(!stop.exists());
        drop(status);
        fs::remove_file(path).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn instance_lock_excludes_other_processes_and_releases_on_drop() {
        let _serial = CHILD_PROCESS_TEST.lock().unwrap();
        const LOCK_PATH: &str = "HELIOS_HELPER_LOCK_TEST_PATH";
        if let Some(path) = std::env::var_os(LOCK_PATH) {
            assert!(lock_instance_file(Path::new(&path)).is_err());
            return;
        }
        let path = std::env::temp_dir().join(format!(
            "helios-helper-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = lock_instance_file(&path).unwrap();
        assert!(lock_instance_file(&path).is_err());
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::instance_lock_excludes_other_processes_and_releases_on_drop",
            ])
            .env(LOCK_PATH, &path)
            .status()
            .unwrap();
        assert!(status.success());
        drop(first);
        let second = lock_instance_file(&path).unwrap();
        drop(second);
        fs::remove_file(&path).unwrap();
        let target = path.with_extension("target");
        fs::write(&target, b"preserve").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(lock_instance_file(&path).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"preserve");
        fs::remove_file(path).unwrap();
        fs::remove_file(target).unwrap();
    }

    #[tokio::test]
    async fn recovery_refuses_active_heartbeat_without_removing_state() {
        let directory = std::env::temp_dir().join(format!(
            "helios-helper-active-recovery-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let mut config = config();
        config.status_file = directory.join("status");
        config.stop_file = directory.join("stop");
        fs::write(&config.status_file, b"active").unwrap();
        fs::write(&config.stop_file, b"stop").unwrap();
        let error = recover_helper(&config).await.unwrap_err();
        assert!(error.to_string().contains("heartbeat is active"));
        assert_eq!(fs::read(&config.status_file).unwrap(), b"active");
        assert_eq!(fs::read(&config.stop_file).unwrap(), b"stop");
        fs::remove_file(config.status_file).unwrap();
        fs::remove_file(config.stop_file).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn shutdown_signal_handles_sigterm_and_sigint_in_child() {
        let _serial = CHILD_PROCESS_TEST.lock().unwrap();
        use std::{
            future::Future,
            process::Command,
            task::Poll,
            time::{Duration, Instant},
        };

        const READY: &str = "HELIOS_HELPER_SIGNAL_TEST_READY";
        if let Some(path) = std::env::var_os(READY) {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let shutdown = shutdown_signal();
                    tokio::pin!(shutdown);
                    std::future::poll_fn(|cx| {
                        assert!(shutdown.as_mut().poll(cx).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    fs::write(path, b"ready").unwrap();
                    tokio::time::timeout(Duration::from_secs(5), shutdown)
                        .await
                        .unwrap()
                        .unwrap();
                });
            return;
        }

        for signal in ["-TERM", "-INT"] {
            let path = std::env::temp_dir().join(format!(
                "helios-helper-signal-{}-{signal}",
                std::process::id()
            ));
            assert!(!path.exists());
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::shutdown_signal_handles_sigterm_and_sigint_in_child",
                ])
                .env(READY, &path)
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !path.exists() && Instant::now() < deadline && child.try_wait().unwrap().is_none()
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            if !path.exists() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not install signal handlers");
            }
            let sent = Command::new("kill")
                .args([signal, &child.id().to_string()])
                .status()
                .unwrap();
            let status = child.wait().unwrap();
            fs::remove_file(path).unwrap();
            assert!(sent.success());
            assert!(status.success());
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_recovery_cannot_report_success_without_a_route_lease() {
        assert!(recover_routes().await.is_err());
    }

    #[cfg(target_os = "linux")]
    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn failed_recovery_preserves_stale_status_and_stop_request() {
        let directory = std::env::temp_dir().join(format!(
            "helios-helper-stale-recovery-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let mut config = config();
        config.status_file = directory.join("status");
        config.stop_file = directory.join("stop");
        fs::write(&config.status_file, b"stale").unwrap();
        fs::File::options()
            .write(true)
            .open(&config.status_file)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
            .unwrap();
        fs::write(&config.stop_file, b"stop").unwrap();
        assert!(!status_is_fresh(&config.status_file));
        assert!(recover_helper(&config).await.is_err());
        assert_eq!(fs::read(&config.status_file).unwrap(), b"stale");
        assert_eq!(fs::read(&config.stop_file).unwrap(), b"stop");
        fs::remove_file(config.status_file).unwrap();
        fs::remove_file(config.stop_file).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    fn config() -> HelperConfig {
        HelperConfig {
            schema_version: 1,
            socks_listen: "127.0.0.1:1080".parse().unwrap(),
            server_ip: "203.0.113.8".parse().unwrap(),
            tun_name: None,
            mtu: 1280,
            ipv6_enabled: false,
            bypass: vec!["192.168.0.0/16".into()],
            source_bypass: if cfg!(any(target_os = "linux", target_os = "macos")) {
                vec!["192.0.2.1".parse().unwrap()]
            } else {
                vec![]
            },
            desktop_pid: None,
            status_file: std::env::temp_dir().join("helios-helper-test.status"),
            stop_file: std::env::temp_dir().join("helios-helper-test.stop"),
        }
    }

    #[test]
    fn builds_loop_safe_tun_arguments() {
        let args = config().tun_args().unwrap();
        assert_eq!(args.proxy.addr, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(args.dns, ArgDns::Virtual);
        assert_eq!(args.mtu, 1280);
        assert_eq!(args.tcp_mss, Some(1240));
        assert_eq!(args.bypass.len(), 2);
    }

    #[test]
    fn enables_ipv6_routes_and_packets_when_configured() {
        let mut config = config();
        config.ipv6_enabled = true;
        assert!(config.tun_args().unwrap().ipv6_enabled);
    }

    #[test]
    fn rejects_unsafe_or_invalid_configuration() {
        let mut value = config();
        value.socks_listen = "0.0.0.0:1080".parse().unwrap();
        assert!(value.validate().is_err());

        let mut value = config();
        value.socks_listen = "127.0.0.1:0".parse().unwrap();
        assert!(value.validate().is_err());

        let mut value = config();
        value.server_ip = "127.0.0.1".parse().unwrap();
        assert!(value.validate().is_err());

        let mut value = config();
        value.server_ip = "198.18.1.2".parse().unwrap();
        assert!(value.validate().is_err());

        let mut value = config();
        value.mtu = 500;
        assert!(value.validate().is_err());

        let mut value = config();
        value.bypass.push("not-a-cidr".into());
        assert!(value.validate().is_err());

        let mut value = config();
        value.stop_file = value.status_file.clone();
        assert!(value.validate().is_err());
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            let mut value = config();
            value.source_bypass.clear();
            assert!(value.validate().is_ok()); // Legacy configuration remains usable for --recover.
            assert!(value.validate_for_start().is_err());
            value.source_bypass = vec!["127.0.0.1".parse().unwrap()];
            assert!(value.validate().is_err());
        }
        let mut value = config();
        value.tun_name = Some("../eth0".into());
        assert_eq!(value.validate().is_err(), cfg!(target_os = "linux"));
    }

    #[test]
    fn example_configuration_stays_valid() {
        let mut value: HelperConfig =
            toml::from_str(include_str!("../../../config/helper.example.toml")).unwrap();
        let paths = config();
        value.status_file = paths.status_file;
        value.stop_file = paths.stop_file;
        value.source_bypass = paths.source_bypass;
        value.validate().unwrap();
    }

    #[test]
    fn status_heartbeat_only_accepts_recent_files() {
        let path = std::env::temp_dir().join(format!(
            "helios-helper-heartbeat-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        assert!(!status_is_fresh(&path));
        fs::write(&path, b"test").unwrap();
        assert!(status_is_fresh(&path));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn parses_start_and_recovery_commands_strictly() {
        use std::ffi::OsString;

        assert_eq!(
            parse_command(&[OsString::from("helper.toml")]).unwrap(),
            (false, PathBuf::from("helper.toml"))
        );
        assert_eq!(
            parse_command(&[OsString::from("--recover"), OsString::from("helper.toml")]).unwrap(),
            (true, PathBuf::from("helper.toml"))
        );
        assert!(parse_command(&[]).is_err());
        assert!(parse_command(&[OsString::from("--bad"), OsString::from("helper.toml")]).is_err());
    }
}
