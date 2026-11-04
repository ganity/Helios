use helios_system_proxy::{ProxySettings, ReleaseOutcome, SystemProxyAdapter, SystemProxyLease};
use std::{
    fs::{File, OpenOptions},
    path::Path,
};

type Error = Box<dyn std::error::Error + Send + Sync>;
#[cfg(target_os = "linux")]
type NativeAdapter = helios_system_proxy::LinuxProxyAdapter;
#[cfg(target_os = "macos")]
type NativeAdapter = helios_system_proxy::MacosProxyAdapter;
#[cfg(windows)]
type NativeAdapter = helios_system_proxy::WindowsProxyAdapter;

pub type NativeProxy = ManagedProxy<NativeAdapter>;

pub fn native(path: &Path, settings: ProxySettings) -> Result<NativeProxy, Error> {
    ManagedProxy::new(adapter(), path, settings)
}

fn adapter() -> NativeAdapter {
    #[cfg(target_os = "linux")]
    let adapter = helios_system_proxy::LinuxProxyAdapter;
    #[cfg(target_os = "macos")]
    let adapter = helios_system_proxy::MacosProxyAdapter;
    #[cfg(windows)]
    let adapter = helios_system_proxy::WindowsProxyAdapter;
    adapter
}

pub fn spawn_watchdog(path: &Path) -> Result<(), Error> {
    use std::process::{Command, Stdio};
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("proxy-watchdog")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command.spawn()?;
    Ok(())
}

pub fn watch(path: &Path) -> Result<(), Error> {
    watch_with(adapter(), path)
}

fn watch_with<A: SystemProxyAdapter>(adapter: A, path: &Path) -> Result<(), Error> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path.with_extension("lock"))?;
    // The kernel releases the daemon's lock even on SIGKILL; the watchdog never races a live owner.
    lock.lock()?;
    restore(&SystemProxyLease::new(adapter, path))
}

pub struct ManagedProxy<A: SystemProxyAdapter> {
    lease: SystemProxyLease<A>,
    settings: ProxySettings,
    enabled: bool,
    _lock: File,
}

impl<A: SystemProxyAdapter> ManagedProxy<A> {
    pub fn new(adapter: A, path: &Path, settings: ProxySettings) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path.with_extension("lock"))?;
        lock.try_lock()?;
        let lease = SystemProxyLease::new(adapter, path);
        restore(&lease)?;
        Ok(Self {
            lease,
            settings,
            enabled: false,
            _lock: lock,
        })
    }

    pub fn set(&mut self, enabled: bool) -> Result<bool, Error> {
        if enabled {
            if self.enabled {
                if !self.lease.reapply_if_restored()? {
                    return Err(
                        "system proxy changed outside Helios; user settings were preserved".into(),
                    );
                }
                return Ok(true);
            }
            if let Err(error) = self.lease.acquire(self.settings.clone()) {
                // Keep a failed rollback recoverable and never discard its lease.
                restore(&self.lease)?;
                return Err(error.into());
            }
            self.enabled = true;
        } else {
            restore(&self.lease)?;
            self.enabled = false;
        }
        Ok(self.enabled)
    }

    pub fn status(&self) -> (bool, bool, Option<String>) {
        if !self.enabled {
            return (false, false, None);
        }
        match self.lease.is_applied() {
            Ok(true) => (true, true, None),
            Ok(false) => (
                true,
                false,
                Some("system proxy changed outside Helios; user settings were preserved".into()),
            ),
            Err(error) => (true, false, Some(error.to_string())),
        }
    }

    pub fn update_settings(&mut self, settings: ProxySettings) -> Result<(), Error> {
        if self.settings == settings {
            return Ok(());
        }
        let enabled = self.enabled;
        let previous = self.settings.clone();
        if enabled {
            self.set(false)?;
        }
        self.settings = settings;
        if enabled && let Err(error) = self.set(true) {
            self.settings = previous;
            self.set(true)?;
            return Err(error);
        }
        Ok(())
    }
}

fn restore<A: SystemProxyAdapter>(lease: &SystemProxyLease<A>) -> Result<(), Error> {
    match lease.recover()? {
        ReleaseOutcome::Drifted { .. } => {
            Err("system proxy changed outside Helios; user settings were preserved".into())
        }
        _ => Ok(()),
    }
}

impl<A: SystemProxyAdapter> Drop for ManagedProxy<A> {
    fn drop(&mut self) {
        if let Err(error) = restore(&self.lease) {
            tracing::warn!(event = "system_proxy_recovery_failed");
            tracing::debug!(event = "system_proxy_recovery_error", error = %error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_system_proxy::{ProxyEndpoint, SystemProxyError};
    use std::sync::{Arc, Mutex};
    use std::{
        path::PathBuf,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };

    struct FileAdapter(PathBuf);
    impl SystemProxyAdapter for FileAdapter {
        type Snapshot = u16;
        fn read(&self) -> Result<u16, SystemProxyError> {
            Ok(std::fs::read_to_string(&self.0)?
                .parse()
                .map_err(std::io::Error::other)?)
        }
        fn desired(&self, _: &u16, settings: &ProxySettings) -> Result<u16, SystemProxyError> {
            Ok(settings.endpoint.port)
        }
        fn apply(&self, value: &u16) -> Result<(), SystemProxyError> {
            std::fs::write(&self.0, value.to_string())?;
            Ok(())
        }
    }

    #[test]
    fn watchdog_restores_after_owner_is_killed() {
        let name = "managed_proxy::tests::watchdog_restores_after_owner_is_killed";
        if let Some(directory) = std::env::var_os("HELIOS_PROXY_CRASH_TEST") {
            let directory = PathBuf::from(directory);
            let adapter = FileAdapter(directory.join("settings"));
            if std::env::var("HELIOS_PROXY_CRASH_ROLE").as_deref() == Ok("owner") {
                let mut owner =
                    ManagedProxy::new(adapter, &directory.join("lease.json"), settings(8080))
                        .unwrap();
                owner.set(true).unwrap();
                std::fs::write(directory.join("ready"), "ready").unwrap();
                std::thread::sleep(Duration::from_secs(30));
                panic!("parent did not kill the owner");
            }
            watch_with(adapter, &directory.join("lease.json")).unwrap();
            return;
        }
        let directory =
            std::env::temp_dir().join(format!("helios-proxy-crash-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("settings"), "7000").unwrap();
        let spawn = |role| {
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name])
                .env("HELIOS_PROXY_CRASH_TEST", &directory)
                .env("HELIOS_PROXY_CRASH_ROLE", role)
                .stdin(Stdio::null())
                .spawn()
                .unwrap()
        };
        let mut owner = spawn("owner");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !directory.join("ready").exists() {
            assert!(owner.try_wait().unwrap().is_none());
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut watcher = spawn("watchdog");
        assert_eq!(
            std::fs::read_to_string(directory.join("settings")).unwrap(),
            "8080"
        );
        owner.kill().unwrap();
        owner.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = watcher.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if Instant::now() > deadline {
                watcher.kill().unwrap();
                watcher.wait().unwrap();
                panic!("watchdog timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            std::fs::read_to_string(directory.join("settings")).unwrap(),
            "7000"
        );
        assert!(!directory.join("lease.json").exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[derive(Clone)]
    struct Adapter(Arc<Mutex<u16>>);
    impl SystemProxyAdapter for Adapter {
        type Snapshot = u16;
        fn read(&self) -> Result<u16, SystemProxyError> {
            Ok(*self.0.lock().unwrap())
        }
        fn desired(&self, _: &u16, settings: &ProxySettings) -> Result<u16, SystemProxyError> {
            Ok(settings.endpoint.port)
        }
        fn apply(&self, value: &u16) -> Result<(), SystemProxyError> {
            *self.0.lock().unwrap() = *value;
            Ok(())
        }
    }
    fn settings(port: u16) -> ProxySettings {
        ProxySettings {
            endpoint: ProxyEndpoint::new("127.0.0.1", port).unwrap(),
            bypass: vec!["localhost".into()],
        }
    }

    #[test]
    fn owner_is_exclusive_and_restores_original_after_reconfiguration() {
        let directory =
            std::env::temp_dir().join(format!("helios-proxy-owner-{}", std::process::id()));
        let path = directory.join("lease.json");
        let adapter = Adapter(Arc::new(Mutex::new(7000)));
        let mut owner = ManagedProxy::new(adapter.clone(), &path, settings(8080)).unwrap();
        assert!(ManagedProxy::new(adapter.clone(), &path, settings(9090)).is_err());
        assert!(owner.set(true).unwrap());
        assert_eq!(owner.status(), (true, true, None));
        owner.update_settings(settings(9090)).unwrap();
        assert_eq!(adapter.read().unwrap(), 9090);
        drop(owner);
        assert_eq!(adapter.read().unwrap(), 7000);
        assert!(!path.exists());
        let mut owner = ManagedProxy::new(adapter.clone(), &path, settings(8080)).unwrap();
        owner.set(true).unwrap();
        adapter.apply(&9999).unwrap();
        assert!(owner.set(true).is_err());
        assert_eq!(adapter.read().unwrap(), 9999);
        assert!(owner.set(false).is_err());
        assert_eq!((owner.status().0, owner.status().1), (true, false));
        drop(owner);
        assert_eq!(adapter.read().unwrap(), 9999);
        assert!(path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn active_proxy_reapplies_after_system_restores_original_settings() {
        let directory =
            std::env::temp_dir().join(format!("helios-proxy-resume-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("lease.json");
        let adapter = Adapter(Arc::new(Mutex::new(7000)));
        let mut owner = ManagedProxy::new(adapter.clone(), &path, settings(8080)).unwrap();
        owner.set(true).unwrap();
        adapter.apply(&7000).unwrap(); // macOS can restore its pre-sleep settings.
        assert!(owner.set(true).unwrap());
        assert_eq!(adapter.read().unwrap(), 8080);
        owner.set(false).unwrap();
        assert_eq!(adapter.read().unwrap(), 7000);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
