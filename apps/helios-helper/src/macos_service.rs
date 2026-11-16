//! launchd owns the privileged service; a verified local socket owns each TUN session.
use super::*;
use helios_config::{DesktopTunRequest, MACOS_TUN_STATUS, TunServiceReply, TunServiceRequest};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

async fn read_message<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, AnyError> {
    let mut bytes = Vec::new();
    let size = reader.take(65_537).read_until(b'\n', &mut bytes).await?;
    if size == 0 || size > 65_536 || bytes.last() != Some(&b'\n') {
        return Err("invalid or oversized TUN service message".into());
    }
    Ok(bytes)
}

fn config(request: DesktopTunRequest) -> Result<HelperConfig, AnyError> {
    request.outbound.validate()?;
    if request.node_ips.len() > 64 || request.node_ips.iter().copied().any(helios_dns::is_fake_ip) {
        return Err("invalid TUN node bypasses".into());
    }
    let mut config = HelperConfig {
        schema_version: 1,
        socks_listen: request.socks_listen,
        server_ip: request.server_ip,
        tun_name: None,
        mtu: request.mtu,
        ipv6_enabled: request.ipv6_enabled,
        bypass: request.node_ips.into_iter().map(host_cidr).collect(),
        source_bypass: request.outbound.source_bypass,
        desktop_pid: Some(request.desktop_pid),
        status_file: MACOS_TUN_STATUS.into(),
        stop_file: "/var/run/helios/tun.stop".into(),
    };
    config
        .bypass
        .extend(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].map(str::to_owned));
    config.validate_for_start()?;
    Ok(config)
}

async fn read_reply<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    bytes: &mut Vec<u8>,
) -> Result<TunServiceReply, AnyError> {
    let remaining = 65_537usize.saturating_sub(bytes.len());
    let size = reader
        .take(remaining as u64)
        .read_until(b'\n', bytes)
        .await?;
    if size == 0 || bytes.len() > 65_536 || bytes.last() != Some(&b'\n') {
        return Err("invalid or oversized TUN worker reply".into());
    }
    Ok(serde_json::from_slice(bytes)?)
}

async fn relay_worker(
    mut child: tokio::process::Child,
    reader: &mut BufReader<tokio::net::unix::ReadHalf<'_>>,
    writer: &mut tokio::net::unix::WriteHalf<'_>,
    request: &TunServiceRequest,
) -> Result<Option<String>, AnyError> {
    let mut input = child.stdin.take().ok_or("missing TUN worker input")?;
    input.write_all(&message(&request)?).await?;
    let mut output = BufReader::new(child.stdout.take().ok_or("missing TUN worker output")?);
    let mut completion = None;
    let mut bytes = Vec::new();
    let forward = async {
        loop {
            let reply = read_reply(&mut output, &mut bytes).await?;
            bytes.clear();
            match reply {
                TunServiceReply::Ended { error } => return Ok::<_, AnyError>(error),
                TunServiceReply::Ready => {
                    writer.write_all(&message(&TunServiceReply::Ready)?).await?
                }
                _ => return Err("unexpected TUN worker reply".into()),
            }
        }
    };
    tokio::select! {
        result = forward => { completion = Some(result); },
        _ = reader.read_u8() => {}, // EOF (or any extra byte) ends this session.
    }
    drop(input); // EOF makes the worker restore routes and DNS before exiting.
    let status = child.wait().await?;
    if completion.is_none() {
        completion = Some(
            async {
                loop {
                    let reply = read_reply(&mut output, &mut bytes).await?;
                    bytes.clear();
                    if let TunServiceReply::Ended { error } = reply {
                        return Ok::<_, AnyError>(error);
                    }
                }
            }
            .await,
        );
    }
    let error = match completion {
        Some(Ok(error)) => error,
        Some(Err(error)) => Some(error.to_string()),
        None if !status.success() => {
            Some("TUN worker exited unexpectedly; see /Library/Logs/Helios/helper.log".into())
        }
        None => None,
    };
    Ok(error)
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use helios_config::{MACOS_TUN_SERVICE, MACOS_TUN_SOCKET};
    use sha2::{Digest, Sha256};
    use std::time::Duration;
    use std::{
        ffi::OsString,
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        process::Stdio,
    };
    use tokio::{
        net::{UnixListener, UnixStream},
        process::Command,
    };

    const PLIST: &str = "/Library/LaunchDaemons/net.helios.tun.plist";
    const LABEL: &str = "system/net.helios.tun";
    const DIRECTORY: &str = "/Library/Application Support/Helios/service";

    fn root_directory(path: &Path, mode: u32) -> Result<(), AnyError> {
        match fs::DirBuilder::new().mode(mode).create(path) {
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            result => result?,
        }
        let info = fs::symlink_metadata(path)?;
        if !info.is_dir() || info.uid() != 0 || info.mode() & 0o022 != 0 {
            return Err("untrusted TUN service directory".into());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    fn digest(path: &Path) -> Result<String, AnyError> {
        Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
    }

    async fn launchctl(args: &[&str]) -> Result<(), AnyError> {
        let output = Command::new("/bin/launchctl").args(args).output().await?;
        if !output.status.success() {
            return Err(format!(
                "launchctl: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
            .into());
        }
        Ok(())
    }

    fn legacy_status(uid: u32) -> Result<PathBuf, AnyError> {
        // Installation is single-threaded; copy passwd data before another lookup.
        let entry = unsafe { libc::getpwuid(uid) };
        if entry.is_null() {
            return Err("unknown desktop user".into());
        }
        let home = unsafe { std::ffi::CStr::from_ptr((*entry).pw_dir) };
        use std::os::unix::ffi::OsStrExt;
        Ok(Path::new(std::ffi::OsStr::from_bytes(home.to_bytes()))
            .join(".helios/helios-helper.status"))
    }

    async fn install(uid: u32, client: &Path) -> Result<(), AnyError> {
        if uid == 0 {
            return Err("install for a desktop user, not root".into());
        }
        let client_digest = digest(client)?;
        let _lock = lock_helper_instance()?;
        let legacy_status = legacy_status(uid)?;
        if status_is_fresh(&legacy_status) {
            return Err(
                "stop the previous Helios TUN session before installing the service".into(),
            );
        }
        // Do not replace a service while a session still owns its route journal.
        configure_route_state()?;
        if route_state_file()?.exists() {
            recover_routes().await?;
        }
        root_directory(Path::new(DIRECTORY), 0o700)?;
        let temporary = Path::new(DIRECTORY).join("helper.new");
        let _ = fs::remove_file(&temporary);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&temporary)?;
        file.write_all(&fs::read(std::env::current_exe()?)?)?;
        file.sync_all()?;
        drop(file);
        // bootout can report 'not loaded' on the first installation.
        let _ = launchctl(&["bootout", LABEL]).await;
        fs::rename(temporary, MACOS_TUN_SERVICE)?;
        fs::write(Path::new(DIRECTORY).join("client.sha256"), client_digest)?;
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>net.helios.tun</string>
<key>ProgramArguments</key><array><string>{MACOS_TUN_SERVICE}</string><string>--service</string><string>{uid}</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>AbandonProcessGroup</key><true/><key>ThrottleInterval</key><integer>3</integer>
</dict></plist>
"#
        );
        let directory = Path::new(PLIST).parent().unwrap();
        let info = fs::symlink_metadata(directory)?;
        if !info.is_dir() || info.uid() != 0 || info.mode() & 0o022 != 0 {
            return Err("untrusted LaunchDaemons directory".into());
        }
        if let Ok(info) = fs::symlink_metadata(PLIST)
            && (!info.is_file() || info.uid() != 0 || info.mode() & 0o022 != 0)
        {
            return Err("untrusted TUN service plist".into());
        }
        let new_plist = Path::new(DIRECTORY).join("service.plist");
        fs::write(&new_plist, plist)?;
        fs::set_permissions(&new_plist, fs::Permissions::from_mode(0o644))?;
        fs::rename(new_plist, PLIST)?;
        launchctl(&["enable", LABEL]).await?;
        drop(_lock);
        launchctl(&["bootstrap", "system", PLIST]).await
    }

    fn process_uid(pid: u32) -> Result<u32, AnyError> {
        if pid <= 1 {
            return Err("invalid TUN process ID".into());
        }
        let output = std::process::Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "uid="])
            .output()?;
        if !output.status.success() {
            return Err("TUN process exited".into());
        }
        Ok(std::str::from_utf8(&output.stdout)?.trim().parse()?)
    }

    fn verify_client(pid: u32, expected: &str) -> Result<(), AnyError> {
        let mut bytes = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let size = unsafe {
            libc::proc_pidpath(pid as i32, bytes.as_mut_ptr().cast(), bytes.len() as u32)
        };
        if size <= 0 {
            return Err("cannot identify TUN client executable".into());
        }
        let path = std::ffi::CStr::from_bytes_until_nul(&bytes)?;
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(path.to_bytes()));
        if digest(path)? != expected {
            return Err("TUN client changed; reinstall the system service from Helios".into());
        }
        Ok(())
    }

    fn recovery_config() -> HelperConfig {
        HelperConfig {
            schema_version: 1,
            socks_listen: "127.0.0.1:1080".parse().unwrap(),
            server_ip: "192.0.2.1".parse().unwrap(),
            tun_name: None,
            mtu: 1280,
            ipv6_enabled: false,
            bypass: vec![],
            source_bypass: vec![],
            desktop_pid: None,
            status_file: MACOS_TUN_STATUS.into(),
            stop_file: "/var/run/helios/tun.stop".into(),
        }
    }

    async fn worker(uid: u32) -> Result<(), AnyError> {
        let mut input = BufReader::new(tokio::io::stdin());
        let bytes =
            tokio::time::timeout(Duration::from_secs(10), read_message(&mut input)).await??;
        let request: TunServiceRequest = serde_json::from_slice(&bytes)?;
        // A fresh worker gets the exclusive instance lock before stale-state recovery.
        {
            let _lock = lock_helper_instance()?;
            configure_route_state()?;
            recover_helper(&recovery_config()).await?;
        }
        match request {
            TunServiceRequest::Start { config: request } => {
                if process_uid(request.desktop_pid)? != uid
                    || process_uid(request.daemon_pid)? != uid
                {
                    return Err("TUN processes belong to another user".into());
                }
                tokio::time::timeout(Duration::from_secs(3), session::check_daemon(&request))
                    .await??;
                run_config(config(request)?, false, true).await
            }
            TunServiceRequest::Recover {} => Ok(()),
            _ => Err("invalid TUN worker command".into()),
        }
    }

    async fn handle(
        stream: &mut UnixStream,
        uid: u32,
        digest: &str,
        operation: std::sync::Arc<tokio::sync::Mutex<()>>,
    ) -> Result<(), AnyError> {
        let credentials = stream.peer_cred()?;
        if credentials.uid() != uid {
            return Err("TUN service peer belongs to another user".into());
        }
        let pid = credentials.pid().ok_or("missing TUN peer PID")? as u32;
        verify_client(
            pid,
            &fs::read_to_string(Path::new(DIRECTORY).join("client.sha256"))?,
        )?;
        let (reader, mut writer) = stream.split();
        let mut reader = BufReader::new(reader);
        let request: TunServiceRequest = serde_json::from_slice(
            &tokio::time::timeout(Duration::from_secs(5), read_message(&mut reader)).await??,
        )?;
        if matches!(request, TunServiceRequest::Ping {}) {
            writer
                .write_all(&message(&TunServiceReply::Available {
                    digest: digest.into(),
                })?)
                .await?;
            return Ok(());
        }
        let _operation = operation
            .try_lock_owned()
            .map_err(|_| "another TUN operation is in progress")?;
        if let TunServiceRequest::Start { config: request } = &request {
            if request.desktop_pid != pid {
                return Err("TUN request does not match its peer process".into());
            }
            config(request.clone())?;
        }
        let child = Command::new(MACOS_TUN_SERVICE)
            .args(["--service-session", &uid.to_string()])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let error = relay_worker(child, &mut reader, &mut writer, &request).await?;
        let _lock = lock_helper_instance()?;
        configure_route_state()?;
        if route_state_file()?.exists() {
            recover_routes().await?;
        }
        let _ = fs::remove_file(MACOS_TUN_STATUS);
        writer
            .write_all(&message(&TunServiceReply::Ended { error })?)
            .await?;
        Ok(())
    }

    async fn serve(uid: u32) -> Result<(), AnyError> {
        {
            // A restarted launchd parent waits for its old worker to finish restoration.
            let _lock = lock_helper_instance()?;
            configure_route_state()?;
            if route_state_file()?.exists() {
                recover_routes().await?;
            }
            let _ = fs::remove_file(MACOS_TUN_STATUS);
        }
        root_directory(Path::new("/var/run/helios"), 0o755)?;
        if let Ok(info) = fs::symlink_metadata(MACOS_TUN_SOCKET) {
            use std::os::unix::fs::FileTypeExt;
            if !info.file_type().is_socket() {
                return Err("TUN socket path is not a socket".into());
            }
            fs::remove_file(MACOS_TUN_SOCKET)?;
        }
        let listener = UnixListener::bind(MACOS_TUN_SOCKET)?;
        fs::set_permissions(MACOS_TUN_SOCKET, fs::Permissions::from_mode(0o600))?;
        let path = std::ffi::CString::new(MACOS_TUN_SOCKET)?;
        // Only the installed desktop user may connect; the directory remains root-owned.
        if unsafe { libc::chown(path.as_ptr(), uid, u32::MAX) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let digest = digest(Path::new(MACOS_TUN_SERVICE))?;
        let operation = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        loop {
            let (mut stream, _) = listener.accept().await?;
            let digest = digest.clone();
            let operation = operation.clone();
            tokio::spawn(async move {
                if let Err(error) = handle(&mut stream, uid, &digest, operation).await {
                    tracing::error!(event = "tun_service_request_failed", error = %error);
                    if let Ok(bytes) = message(&TunServiceReply::Ended {
                        error: Some(error.to_string()),
                    }) {
                        let _ = stream.write_all(&bytes).await;
                    }
                }
            });
        }
    }

    pub(crate) async fn command(args: &[OsString]) -> Result<(), AnyError> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("TUN service requires administrator privileges".into());
        }
        match args {
            [flag, uid, client] if flag == "--install-service" => {
                install(
                    uid.to_str().ok_or("invalid UID")?.parse()?,
                    Path::new(client),
                )
                .await
            }
            [flag, uid] if flag == "--service" => {
                serve(uid.to_str().ok_or("invalid UID")?.parse()?).await
            }
            [flag, uid] if flag == "--service-session" => {
                let result = worker(uid.to_str().ok_or("invalid UID")?.parse()?).await;
                reply(&TunServiceReply::Ended {
                    error: result.as_ref().err().map(ToString::to_string),
                })?;
                result
            }
            [flag] if flag == "--uninstall-service" => {
                let _lock = lock_helper_instance()?;
                configure_route_state()?;
                if route_state_file()?.exists() {
                    recover_routes().await?;
                }
                launchctl(&["bootout", LABEL]).await?;
                fs::remove_file(PLIST)?;
                fs::remove_file(MACOS_TUN_SERVICE)?;
                fs::remove_file(Path::new(DIRECTORY).join("client.sha256"))?;
                let _ = fs::remove_file(MACOS_TUN_SOCKET);
                Ok(())
            }
            _ => Err("invalid TUN service command".into()),
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn client_identity_requires_the_installed_executable_digest() {
            let pid = std::process::id();
            verify_client(pid, &digest(&std::env::current_exe().unwrap()).unwrap()).unwrap();
            assert!(verify_client(pid, "wrong executable").is_err());
            assert!(verify_client(u32::MAX, "").is_err());
        }
    }
}

fn message(value: &impl serde::Serialize) -> Result<Vec<u8>, AnyError> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(target_os = "macos")]
pub(super) use native::command;

#[cfg(target_os = "macos")]
pub(super) fn reply(value: &helios_config::TunServiceReply) -> Result<(), AnyError> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&message(value)?)?;
    stdout.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{process::Stdio, time::Duration};
    use tokio::{net::UnixStream, process::Command};

    #[tokio::test]
    async fn socket_eof_waits_for_worker_cleanup_and_keeps_its_error() {
        let (mut service, mut client) = UnixStream::pair().unwrap();
        assert_eq!(service.peer_cred().unwrap().uid(), unsafe {
            libc::getuid()
        });
        let worker = Command::new("/bin/sh")
            .args([
                "-c",
                r#"read request
printf '%s\n' '{"state":"ready"}'
cat >/dev/null
printf '%s\n' '{"state":"ended","error":"cleanup reported a failure"}'
"#,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let session = async {
            let (reader, mut writer) = service.split();
            relay_worker(
                worker,
                &mut BufReader::new(reader),
                &mut writer,
                &TunServiceRequest::Recover {},
            )
            .await
            .unwrap()
        };
        let disconnect = async {
            let mut line = Vec::new();
            BufReader::new(&mut client)
                .read_until(b'\n', &mut line)
                .await
                .unwrap();
            assert!(matches!(
                serde_json::from_slice::<TunServiceReply>(&line).unwrap(),
                TunServiceReply::Ready
            ));
            client.shutdown().await.unwrap();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(session, disconnect)
        })
        .await
        .unwrap();
        assert_eq!(result.as_deref(), Some("cleanup reported a failure"));
    }

    #[tokio::test]
    async fn interrupted_reply_keeps_partial_bytes_for_cleanup_result() {
        let (mut writer, reader) = tokio::io::duplex(256);
        let mut reader = BufReader::new(reader);
        let mut bytes = Vec::new();
        writer
            .write_all(br#"{"state":"ended","error":"partial"#)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                read_reply(&mut reader, &mut bytes)
            )
            .await
            .is_err()
        );
        assert!(!bytes.is_empty());
        writer.write_all(b" failure\"}\n").await.unwrap();
        assert!(
            matches!(read_reply(&mut reader, &mut bytes).await.unwrap(), TunServiceReply::Ended { error: Some(error) } if error == "partial failure")
        );
    }

    #[tokio::test]
    async fn protocol_is_bounded_strict_and_does_not_accept_root_paths() {
        for bytes in [b"".to_vec(), b"{}".to_vec(), vec![b'x'; 65_537]] {
            assert!(read_message(&mut bytes.as_slice()).await.is_err());
        }
        let bytes = message(&TunServiceRequest::Recover {}).unwrap();
        let mut input = bytes.as_slice();
        assert!(matches!(
            serde_json::from_slice::<TunServiceRequest>(&read_message(&mut input).await.unwrap())
                .unwrap(),
            TunServiceRequest::Recover {}
        ));
        assert!(
            serde_json::from_str::<TunServiceRequest>(
                r#"{"command":"recover","path":"/etc/passwd"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn worker_uses_fixed_paths_and_validates_before_network_changes() {
        let mut request = DesktopTunRequest {
            socks_listen: "127.0.0.1:1080".parse().unwrap(),
            server_ip: "203.0.113.1".parse().unwrap(),
            node_ips: vec!["203.0.113.1".parse().unwrap()],
            mtu: 1280,
            ipv6_enabled: true,
            outbound: helios_config::OutboundConfig {
                source_bypass: vec!["192.168.1.2".parse().unwrap()],
                dns_servers: vec!["192.168.1.1:53".parse().unwrap()],
            },
            desktop_pid: 2,
            daemon_pid: 3,
        };
        let accepted = config(request.clone()).unwrap();
        assert_eq!(accepted.status_file, Path::new(MACOS_TUN_STATUS));
        assert_eq!(accepted.desktop_pid, Some(2));
        request.node_ips.push("198.18.0.1".parse().unwrap());
        assert!(config(request.clone()).is_err());
        request.node_ips.clear();
        request.mtu = 1;
        assert!(config(request.clone()).is_err());
        request.mtu = 1280;
        request.socks_listen = "0.0.0.0:1080".parse().unwrap();
        assert!(config(request).is_err());
    }
}
