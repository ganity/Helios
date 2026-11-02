use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::fs::File;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

const LEASE_SCHEMA_VERSION: u32 = 1;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{LinuxProxyAdapter, LinuxProxySnapshot};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{WindowsProxyAdapter, WindowsProxySnapshot};

#[cfg(any(test, target_os = "macos"))]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{MacosProxyAdapter, MacosProxySnapshot};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
}

impl ProxyEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, SystemProxyError> {
        let host = host.into();
        if host.is_empty() || port == 0 {
            return Err(SystemProxyError::InvalidSettings);
        }
        Ok(Self { host, port })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySettings {
    pub endpoint: ProxyEndpoint,
    pub bypass: Vec<String>,
}

pub trait SystemProxyAdapter {
    type Snapshot: Clone + Eq + DeserializeOwned + Serialize;

    fn read(&self) -> Result<Self::Snapshot, SystemProxyError>;
    fn desired(
        &self,
        current: &Self::Snapshot,
        settings: &ProxySettings,
    ) -> Result<Self::Snapshot, SystemProxyError>;
    fn apply(&self, state: &Self::Snapshot) -> Result<(), SystemProxyError>;
}

pub struct SystemProxyLease<A> {
    adapter: A,
    lease_path: PathBuf,
}

impl<A: SystemProxyAdapter> SystemProxyLease<A> {
    pub fn new(adapter: A, lease_path: impl Into<PathBuf>) -> Self {
        Self {
            adapter,
            lease_path: lease_path.into(),
        }
    }

    pub fn acquire(&self, settings: ProxySettings) -> Result<(), SystemProxyError> {
        validate_settings(&settings)?;
        if self.lease_path.exists() {
            return Err(SystemProxyError::LeaseExists);
        }
        let original = self.adapter.read()?;
        let desired = self.adapter.desired(&original, &settings)?;
        let record = LeaseRecord {
            schema_version: LEASE_SCHEMA_VERSION,
            original,
            applied: desired.clone(),
        };
        write_new_record(&self.lease_path, &record)?;
        self.adapter.apply(&desired)?;
        if self.adapter.read()? != desired {
            return Err(SystemProxyError::VerificationFailed);
        }
        write_active_marker(&self.active_path())?;
        Ok(())
    }

    pub fn release(&self) -> Result<ReleaseOutcome<A::Snapshot>, SystemProxyError> {
        let Some(record) = read_record(&self.lease_path)? else {
            return Ok(ReleaseOutcome::NoLease);
        };
        let current = self.adapter.read()?;
        if !self.active_path().exists() {
            if current != record.original {
                self.adapter.apply(&record.original)?;
                if self.adapter.read()? != record.original {
                    return Err(SystemProxyError::VerificationFailed);
                }
            }
            std::fs::remove_file(&self.lease_path)?;
            return Ok(if current == record.original {
                ReleaseOutcome::AlreadyRestored
            } else {
                ReleaseOutcome::Released
            });
        }
        if current == record.original {
            self.remove_record()?;
            return Ok(ReleaseOutcome::AlreadyRestored);
        }
        if current != record.applied {
            return Ok(ReleaseOutcome::Drifted { current });
        }
        self.adapter.apply(&record.original)?;
        if self.adapter.read()? != record.original {
            return Err(SystemProxyError::VerificationFailed);
        }
        self.remove_record()?;
        Ok(ReleaseOutcome::Released)
    }

    pub fn recover(&self) -> Result<ReleaseOutcome<A::Snapshot>, SystemProxyError> {
        self.release()
    }

    pub fn is_applied(&self) -> Result<bool, SystemProxyError> {
        let Some(record) = read_record::<A::Snapshot>(&self.lease_path)? else {
            return Ok(false);
        };
        Ok(self.active_path().exists() && self.adapter.read()? == record.applied)
    }

    fn active_path(&self) -> PathBuf {
        self.lease_path.with_extension("active")
    }

    fn remove_record(&self) -> Result<(), SystemProxyError> {
        match std::fs::remove_file(self.active_path()) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        std::fs::remove_file(&self.lease_path)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseOutcome<S> {
    NoLease,
    Released,
    AlreadyRestored,
    Drifted { current: S },
}

#[derive(Debug, Error)]
pub enum SystemProxyError {
    #[error("system proxy settings are invalid")]
    InvalidSettings,
    #[error("a system proxy lease already exists")]
    LeaseExists,
    #[error("system proxy state did not match the requested value after apply")]
    VerificationFailed,
    #[error("system proxy platform operation failed: {0}")]
    Platform(String),
    #[error("system proxy lease I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("system proxy lease JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported system proxy lease schema {0}")]
    UnsupportedSchema(u32),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LeaseRecord<S> {
    schema_version: u32,
    original: S,
    applied: S,
}

fn validate_settings(settings: &ProxySettings) -> Result<(), SystemProxyError> {
    if settings.endpoint.host.is_empty()
        || settings.endpoint.port == 0
        || settings.bypass.iter().any(String::is_empty)
    {
        return Err(SystemProxyError::InvalidSettings);
    }
    Ok(())
}

fn write_new_record<S: Serialize>(
    path: &Path,
    record: &LeaseRecord<S>,
) -> Result<(), SystemProxyError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temporary = path.with_extension("tmp");
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let bytes = serde_json::to_vec(record)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    sync_parent(parent)?;
    Ok(())
}

fn write_active_marker(path: &Path) -> Result<(), SystemProxyError> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.sync_all()?;
    sync_parent(path.parent().unwrap_or_else(|| Path::new(".")))?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), SystemProxyError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), SystemProxyError> {
    Ok(())
}

fn read_record<S: DeserializeOwned>(
    path: &Path,
) -> Result<Option<LeaseRecord<S>>, SystemProxyError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let record: LeaseRecord<S> = serde_json::from_slice(&bytes)?;
    if record.schema_version != LEASE_SCHEMA_VERSION {
        return Err(SystemProxyError::UnsupportedSchema(record.schema_version));
    }
    Ok(Some(record))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct FakeState {
        port: u16,
        user_value: String,
    }

    struct FakeAdapter(Mutex<FakeState>);

    impl SystemProxyAdapter for FakeAdapter {
        type Snapshot = FakeState;

        fn read(&self) -> Result<Self::Snapshot, SystemProxyError> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn desired(
            &self,
            current: &Self::Snapshot,
            settings: &ProxySettings,
        ) -> Result<Self::Snapshot, SystemProxyError> {
            Ok(FakeState {
                port: settings.endpoint.port,
                user_value: current.user_value.clone(),
            })
        }

        fn apply(&self, state: &Self::Snapshot) -> Result<(), SystemProxyError> {
            *self.0.lock().unwrap() = state.clone();
            Ok(())
        }
    }

    fn state(port: u16) -> FakeState {
        FakeState {
            port,
            user_value: "preserved".into(),
        }
    }

    fn settings(port: u16) -> ProxySettings {
        ProxySettings {
            endpoint: ProxyEndpoint::new("127.0.0.1", port).unwrap(),
            bypass: vec!["localhost".into(), "127.0.0.1".into()],
        }
    }

    fn lease_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "helios-system-proxy-{name}-{}-{}.json",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[test]
    fn acquires_and_restores_exact_original_state() {
        let path = lease_path("restore");
        let original = state(8000);
        let desired = state(8080);
        let lease = SystemProxyLease::new(FakeAdapter(Mutex::new(original.clone())), &path);

        assert!(!lease.is_applied().unwrap());
        lease.acquire(settings(8080)).unwrap();
        assert!(lease.is_applied().unwrap());
        assert_eq!(lease.adapter.read().unwrap(), desired);
        assert_eq!(lease.release().unwrap(), ReleaseOutcome::Released);
        assert!(!lease.is_applied().unwrap());
        assert_eq!(lease.adapter.read().unwrap(), original);
        assert!(!path.exists());
    }

    #[test]
    fn drift_does_not_overwrite_user_changes() {
        let path = lease_path("drift");
        let lease = SystemProxyLease::new(FakeAdapter(Mutex::new(state(8000))), &path);
        lease.acquire(settings(8080)).unwrap();
        let user_state = state(9000);
        lease.adapter.apply(&user_state).unwrap();
        assert!(!lease.is_applied().unwrap());

        assert_eq!(
            lease.release().unwrap(),
            ReleaseOutcome::Drifted {
                current: user_state.clone()
            }
        );
        assert_eq!(lease.adapter.read().unwrap(), user_state);
        assert!(path.exists());
        lease.remove_record().unwrap();
    }

    #[test]
    fn recover_removes_lease_when_apply_never_happened() {
        let path = lease_path("not-applied");
        let original = state(8000);
        let record = LeaseRecord {
            schema_version: LEASE_SCHEMA_VERSION,
            original: original.clone(),
            applied: state(8080),
        };
        write_new_record(&path, &record).unwrap();
        let lease = SystemProxyLease::new(FakeAdapter(Mutex::new(original)), &path);

        assert_eq!(lease.recover().unwrap(), ReleaseOutcome::AlreadyRestored);
        assert!(!path.exists());
    }

    #[test]
    fn recover_rolls_back_incomplete_acquire() {
        let path = lease_path("partial");
        let original = state(8000);
        let partial = state(8081);
        let record = LeaseRecord {
            schema_version: LEASE_SCHEMA_VERSION,
            original: original.clone(),
            applied: state(8080),
        };
        write_new_record(&path, &record).unwrap();
        let lease = SystemProxyLease::new(FakeAdapter(Mutex::new(partial)), &path);

        assert_eq!(lease.recover().unwrap(), ReleaseOutcome::Released);
        assert_eq!(lease.adapter.read().unwrap(), original);
        assert!(!path.exists());
    }
}
