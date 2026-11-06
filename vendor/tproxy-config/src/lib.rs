#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod common;
mod fn_holder;
mod linux;
mod macos;
mod private_ip;
mod tproxy_args;
mod windows;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(all(
    feature = "secure-state-file",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
use std::path::{Path, PathBuf};
pub use {private_ip::is_private_ip, tproxy_args::TproxyArgs};

pub use cidr::IpCidr;

#[cfg(target_os = "linux")]
pub use linux::resolver::check_resolver as check_linux_resolver;
#[cfg(all(target_os = "linux", feature = "secure-state-file"))]
pub use linux::{
    monitor::{check_active as check_linux_tun, uplink_snapshot as linux_uplink_snapshot},
    resolver::upstreams as linux_dns_upstreams,
};

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub use common::{tproxy_remove, tproxy_setup};

#[cfg(target_os = "linux")]
use rtnetlink::packet_route::route::RouteMessage;
#[cfg(target_os = "linux")]
mod linux_state;

pub const TUN_NAME: &str = if cfg!(target_os = "linux") {
    "tun0"
} else if cfg!(target_os = "windows") {
    "wintun"
} else if cfg!(target_os = "macos") {
    "utun5"
} else {
    // panic!("Unsupported OS")
    "unknown-tun"
};
pub const TUN_MTU: u16 = 1500;
pub const PROXY_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080);
pub const TUN_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 33));
pub const TUN_NETMASK: IpAddr = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0));
pub const TUN_GATEWAY: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
pub const TUN_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
pub const SOCKET_FWMARK_TABLE: &str = "100";

#[allow(dead_code)]
#[cfg(unix)]
pub(crate) const ETC_RESOLV_CONF_FILE: &str = "/etc/resolv.conf";

#[allow(dead_code)]
pub(crate) fn run_command(command: &str, args: &[&str]) -> std::io::Result<Vec<u8>> {
    let full_cmd = format!("{} {}", command, args.join(" "));
    log::trace!("Running command: \"{full_cmd}\"...");
    let out = match std::process::Command::new(command).args(args).output() {
        Ok(out) => out,
        Err(e) => {
            log::trace!("Run command: \"{full_cmd}\" failed with: {e}");
            return Err(e);
        }
    };
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() {
            &out.stdout
        } else {
            &out.stderr
        });
        let info = format!("Run command: \"{full_cmd}\" failed with {err}");
        log::trace!("{info}");
        return Err(std::io::Error::other(info));
    }
    Ok(out.stdout)
}

#[allow(dead_code)]
#[cfg(all(
    feature = "unsafe-state-file",
    any(target_os = "macos", target_os = "windows")
))]
pub(crate) fn get_state_file_path() -> std::path::PathBuf {
    let temp_dir = std::env::temp_dir();
    temp_dir.join("tproxy_config_restore_state.json")
}

#[cfg(all(
    feature = "secure-state-file",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
static STATE_FILE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

#[cfg(all(
    feature = "secure-state-file",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
pub fn set_state_file_path(path: PathBuf) -> std::io::Result<()> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "state file path must be absolute and include a file name",
        ));
    }
    STATE_FILE.set(path).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "state file path already set",
        )
    })
}

#[cfg(all(
    feature = "secure-state-file",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
fn get_secure_state_file_path() -> std::io::Result<&'static Path> {
    STATE_FILE.get().map(PathBuf::as_path).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "state file path was not configured",
        )
    })
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct FwmarkRestore {
    #[serde(with = "linux_state::ip_version")]
    pub(crate) ip_version: rtnetlink::IpVersion,
    pub(crate) fwmark: u32,
    pub(crate) table: u32,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
#[cfg_attr(
    all(
        any(feature = "unsafe-state-file", feature = "secure-state-file"),
        any(target_os = "macos", target_os = "windows", target_os = "linux")
    ),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(crate) struct TproxyStateInner {
    #[cfg(target_os = "linux")]
    #[cfg_attr(
        any(feature = "unsafe-state-file", feature = "secure-state-file"),
        serde(default)
    )]
    pub(crate) linux_context: Option<linux::recovery::Context>,
    #[cfg(all(target_os = "linux", feature = "secure-state-file"))]
    #[serde(default)]
    pub(crate) linux_resolved: Option<linux::resolved::Lease>,
    #[cfg(target_os = "linux")]
    #[cfg_attr(
        any(feature = "unsafe-state-file", feature = "secure-state-file"),
        serde(default)
    )]
    pub(crate) applied_resolvconf_content: Option<Vec<u8>>,
    #[cfg(target_os = "linux")]
    #[cfg_attr(
        any(feature = "unsafe-state-file", feature = "secure-state-file"),
        serde(default, with = "linux_state::rules")
    )]
    pub(crate) remove_rules: Vec<rtnetlink::packet_route::rule::RuleMessage>,
    pub(crate) tproxy_args: Option<TproxyArgs>,
    pub(crate) original_dns_servers: Option<Vec<IpAddr>>,
    pub(crate) gateway: Option<IpAddr>,
    pub(crate) gw_scope: Option<String>,
    pub(crate) umount_resolvconf: bool,
    pub(crate) restore_resolvconf_content: Option<Vec<u8>>,
    pub(crate) tproxy_removed_done: bool,
    #[cfg(target_os = "linux")]
    #[cfg_attr(
        any(feature = "unsafe-state-file", feature = "secure-state-file"),
        serde(with = "linux_state::routes")
    )]
    pub(crate) restore_routes: Vec<RouteMessage>,
    #[cfg(target_os = "linux")]
    #[cfg_attr(
        any(feature = "unsafe-state-file", feature = "secure-state-file"),
        serde(with = "linux_state::routes")
    )]
    pub(crate) remove_routes: Vec<RouteMessage>,
    #[cfg(target_os = "linux")]
    pub(crate) restore_gateway_mode: Option<Vec<String>>,
    #[cfg(target_os = "linux")]
    pub(crate) restore_ip_forwarding: bool,
    #[cfg(target_os = "linux")]
    pub(crate) restore_socket_fwmark: Vec<FwmarkRestore>,
    #[cfg(target_os = "macos")]
    pub(crate) default_service_id: Option<String>,
    #[cfg(target_os = "macos")]
    pub(crate) default_service_dns: Option<Vec<IpAddr>>,
    #[cfg(target_os = "macos")]
    pub(crate) orig_iface_name: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
pub struct TproxyState {
    inner: std::sync::Arc<futures::lock::Mutex<TproxyStateInner>>,
}

#[allow(dead_code)]
impl TproxyState {
    fn new(state: TproxyStateInner) -> Self {
        Self {
            inner: std::sync::Arc::new(futures::lock::Mutex::new(state)),
        }
    }
}

#[allow(dead_code)]
#[cfg(all(
    feature = "unsafe-state-file",
    any(target_os = "macos", target_os = "windows")
))]
pub(crate) fn store_intermediate_state(state: &TproxyStateInner) -> std::io::Result<()> {
    let contents = serde_json::to_string(&state)?;
    std::fs::write(crate::get_state_file_path(), contents)?;
    Ok(())
}

#[allow(dead_code)]
#[cfg(all(
    feature = "unsafe-state-file",
    any(target_os = "macos", target_os = "windows")
))]
pub(crate) fn retrieve_intermediate_state() -> std::io::Result<TproxyStateInner> {
    let path = crate::get_state_file_path();
    if !path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No state file found",
        ));
    }
    let s = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str::<TproxyStateInner>(&s)?)
}

#[allow(dead_code)]
#[cfg(all(
    feature = "secure-state-file",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
pub(crate) fn store_secure_state(state: &TproxyStateInner) -> std::io::Result<()> {
    let contents = serde_json::to_vec(state)?;
    write_secure_record(get_secure_state_file_path()?, &contents)
}

#[cfg(all(
    feature = "secure-state-file",
    any(test, target_os = "macos", target_os = "windows", target_os = "linux")
))]
fn write_secure_record(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    if contents.len() as u64 > MAX_RECORD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "recovery record exceeds 4 MiB",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("state file has no parent"))?;
    std::fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    // A killed writer may leave its staging file; never let that block later recovery.
    static NEXT_RECORD: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let serial = NEXT_RECORD.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_nanos();
    let temporary = parent.join(format!(
        ".helios-state-{}-{timestamp}-{serial}.new",
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        // Only remove the temporary file successfully created by this call.
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[allow(dead_code)]
#[cfg(all(
    feature = "secure-state-file",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
pub(crate) fn retrieve_secure_state() -> std::io::Result<TproxyStateInner> {
    Ok(serde_json::from_slice(&read_secure_record(
        get_secure_state_file_path()?,
    )?)?)
}

#[cfg(all(
    feature = "secure-state-file",
    any(test, target_os = "macos", target_os = "windows", target_os = "linux")
))]
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;

#[cfg(all(
    feature = "secure-state-file",
    any(test, target_os = "macos", target_os = "windows", target_os = "linux")
))]
fn read_secure_record(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "recovery record must be a regular file no larger than 4 MiB",
        ));
    }
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "recovery record is not a regular file",
        ));
    }
    // Limit the read itself as the file may grow after the metadata check.
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "recovery record exceeds 4 MiB",
        ));
    }
    Ok(bytes)
}

#[cfg(all(test, feature = "secure-state-file"))]
mod secure_record_tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_state_storage_round_trip_and_corrupt_record_preservation() {
        let directory = std::env::temp_dir().join(format!(
            "helios-linux-record-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = directory.join("lease.json");
        set_state_file_path(path.clone()).unwrap();
        let route = rtnetlink::RouteMessageBuilder::<std::net::Ipv4Addr>::new()
            .destination_prefix("203.0.113.0".parse().unwrap(), 24)
            .output_interface(7)
            .build();
        let state = TproxyStateInner {
            restore_routes: vec![route.clone()],
            restore_gateway_mode: Some(vec!["-D FORWARD -o tun0 -j ACCEPT".into()]),
            restore_ip_forwarding: true,
            ..Default::default()
        };
        store_secure_state(&state).unwrap();
        let restored = retrieve_secure_state().unwrap();
        assert_eq!(restored.restore_routes, [route]);
        assert_eq!(
            serde_json::to_vec(&state).unwrap(),
            serde_json::to_vec(&restored).unwrap()
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(retrieve_secure_state().is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
        remove_secure_state();
        assert!(!path.exists());
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn recovery_record_write_preserves_old_record_on_failure() {
        let directory = std::env::temp_dir().join(format!(
            "helios-record-write-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("record.json");
        write_secure_record(&path, b"old").unwrap();
        let temporary = path.with_extension("new");
        std::fs::write(&temporary, b"existing").unwrap();
        write_secure_record(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::read(&temporary).unwrap(), b"existing");
        std::fs::remove_file(&temporary).unwrap();
        assert!(write_secure_record(&path, &vec![0; MAX_RECORD_BYTES as usize + 1]).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert!(!temporary.exists());
        write_secure_record(&path, b"new").unwrap();
        assert_eq!(read_secure_record(&path).unwrap(), b"new");
        assert!(!temporary.exists());
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(write_secure_record(&path, b"rename fails").is_err());
        assert!(!temporary.exists());
        std::fs::remove_dir(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn recovery_record_read_is_bounded_and_rejects_nonregular_paths() {
        let directory = std::env::temp_dir().join(format!(
            "helios-record-read-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("record");
        std::fs::write(&path, b"{}").unwrap();
        assert_eq!(read_secure_record(&path).unwrap(), b"{}");
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(4 * 1024 * 1024).unwrap();
        assert_eq!(read_secure_record(&path).unwrap().len(), 4 * 1024 * 1024);
        file.set_len(4 * 1024 * 1024 + 1).unwrap();
        assert_eq!(
            read_secure_record(&path).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(read_secure_record(&directory).is_err());
        drop(file);
        #[cfg(unix)]
        {
            let link = directory.join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_secure_record(&link).is_err());
            std::fs::remove_file(link).unwrap();
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}

#[allow(dead_code)]
#[cfg(all(
    feature = "secure-state-file",
    any(target_os = "macos", target_os = "windows", target_os = "linux")
))]
pub(crate) fn remove_secure_state() {
    if let Ok(path) = get_secure_state_file_path() {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("new"));
    }
}

/// Compare two version strings
/// Returns 1 if v1 > v2, -1 if v1 < v2, 0 if v1 == v2
#[allow(dead_code)]
pub(crate) fn compare_version(v1: &str, v2: &str) -> i32 {
    let split_parse = |ver: &str| -> Vec<i32> {
        ver.split('.')
            .map(|s| s.parse::<i32>().unwrap_or(0))
            .collect()
    };

    let mut v1_parts = split_parse(v1);
    let mut v2_parts = split_parse(v2);

    let max_len = v1_parts.len().max(v2_parts.len());
    v1_parts.resize(max_len, 0);
    v2_parts.resize(max_len, 0);

    for (a, b) in v1_parts.iter().zip(v2_parts.iter()) {
        match a.cmp(b) {
            std::cmp::Ordering::Greater => return 1,
            std::cmp::Ordering::Less => return -1,
            std::cmp::Ordering::Equal => continue,
        }
    }
    0
}
