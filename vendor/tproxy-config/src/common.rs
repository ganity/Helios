use crate::{TproxyArgs, TproxyState};

#[cfg(target_os = "linux")]
use crate::linux::{_tproxy_remove, _tproxy_setup};

#[cfg(target_os = "windows")]
use crate::windows::{_tproxy_remove, _tproxy_setup};

#[cfg(target_os = "macos")]
use crate::macos::{_tproxy_remove, _tproxy_setup};

impl Drop for TproxyState {
    fn drop(&mut self) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            log::debug!("restoring network settings");
            let mut state = inner.lock().await;

            _ = _tproxy_remove(&mut state).await;
        });
    }
}

pub async fn tproxy_setup(tproxy_args: &TproxyArgs) -> std::io::Result<TproxyState> {
    log::debug!("Setting up TProxy with args: {tproxy_args:?}");
    match _tproxy_setup(tproxy_args).await {
        Ok(state) => {
            log::debug!("TProxy setup completed successfully");
            Ok(TproxyState::new(state))
        }
        Err(e) => {
            log::error!("Failed to set up TProxy: {e}");
            Err(std::io::Error::other(format!("{e}")))
        }
    }
}

pub async fn tproxy_remove(state: Option<TproxyState>) -> std::io::Result<()> {
    match state {
        Some(state) => {
            let inner = state.inner.clone();
            let mut state = inner.lock().await;
            return _tproxy_remove(&mut state)
                .await
                .map_err(|e| std::io::Error::other(format!("{e}")));
        }
        #[cfg(all(
            feature = "unsafe-state-file",
            any(target_os = "macos", target_os = "windows")
        ))]
        None => {
            if let Ok(mut state) = crate::retrieve_intermediate_state() {
                return _tproxy_remove(&mut state)
                    .await
                    .map_err(|e| std::io::Error::other(format!("{e}")));
            }
            Ok(())
        }
        #[cfg(all(
            feature = "secure-state-file",
            any(target_os = "macos", target_os = "windows", target_os = "linux")
        ))]
        None => {
            let mut state = crate::retrieve_secure_state()?;
            _tproxy_remove(&mut state)
                .await
                .map_err(|e| std::io::Error::other(format!("{e}")))
        }
        #[cfg(not(all(
            feature = "unsafe-state-file",
            any(target_os = "macos", target_os = "windows")
        )))]
        #[cfg(not(all(
            feature = "secure-state-file",
            any(target_os = "macos", target_os = "windows", target_os = "linux")
        )))]
        None => Ok(()),
    }
}

#[cfg(all(
    test,
    feature = "secure-state-file",
    any(target_os = "macos", target_os = "windows")
))]
mod tests {
    #[test]
    fn recovery_rejects_missing_or_corrupt_secure_record() {
        let directory = std::env::temp_dir().join(format!(
            "helios-route-recovery-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("lease.json");
        crate::set_state_file_path(path.clone()).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert_eq!(
            runtime
                .block_on(super::tproxy_remove(None))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        std::fs::write(&path, b"not-json").unwrap();
        assert!(runtime.block_on(super::tproxy_remove(None)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"not-json");
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
