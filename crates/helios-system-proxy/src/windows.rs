use serde::{Deserialize, Serialize};
use windows_registry::{CURRENT_USER, Key};
use windows_sys::Win32::Networking::WinInet::{
    INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
};

use crate::{ProxySettings, SystemProxyAdapter, SystemProxyError};

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProxySnapshot {
    proxy_enable: Option<u32>,
    proxy_server: Option<String>,
    proxy_override: Option<String>,
}

pub struct WindowsProxyAdapter;

impl SystemProxyAdapter for WindowsProxyAdapter {
    type Snapshot = WindowsProxySnapshot;

    fn read(&self) -> Result<Self::Snapshot, SystemProxyError> {
        let key = settings_key()?;
        Ok(WindowsProxySnapshot {
            proxy_enable: optional_u32(&key, "ProxyEnable")?,
            proxy_server: optional_string(&key, "ProxyServer")?,
            proxy_override: optional_string(&key, "ProxyOverride")?,
        })
    }

    fn desired(
        &self,
        _current: &Self::Snapshot,
        settings: &ProxySettings,
    ) -> Result<Self::Snapshot, SystemProxyError> {
        Ok(WindowsProxySnapshot {
            proxy_enable: Some(1),
            proxy_server: Some(format!(
                "http={0}:{1};https={0}:{1}",
                settings.endpoint.host, settings.endpoint.port
            )),
            proxy_override: (!settings.bypass.is_empty()).then(|| settings.bypass.join(";")),
        })
    }

    fn apply(&self, state: &Self::Snapshot) -> Result<(), SystemProxyError> {
        let key = settings_key()?;
        apply_u32(&key, "ProxyEnable", state.proxy_enable)?;
        apply_string(&key, "ProxyServer", state.proxy_server.as_deref())?;
        apply_string(&key, "ProxyOverride", state.proxy_override.as_deref())?;
        notify_change()
    }
}

fn settings_key() -> Result<Key, SystemProxyError> {
    CURRENT_USER
        .open(INTERNET_SETTINGS)
        .map_err(|error| SystemProxyError::Platform(error.to_string()))
}

fn optional_u32(key: &Key, name: &str) -> Result<Option<u32>, SystemProxyError> {
    match key.get_u32(name) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.code().0 as u32 == 2 => Ok(None),
        Err(error) => Err(SystemProxyError::Platform(error.to_string())),
    }
}

fn optional_string(key: &Key, name: &str) -> Result<Option<String>, SystemProxyError> {
    match key.get_string(name) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.code().0 as u32 == 2 => Ok(None),
        Err(error) => Err(SystemProxyError::Platform(error.to_string())),
    }
}

fn apply_u32(key: &Key, name: &str, value: Option<u32>) -> Result<(), SystemProxyError> {
    match value {
        Some(value) => key
            .set_u32(name, value)
            .map_err(|error| SystemProxyError::Platform(error.to_string())),
        None => remove_value(key, name),
    }
}

fn apply_string(key: &Key, name: &str, value: Option<&str>) -> Result<(), SystemProxyError> {
    match value {
        Some(value) => key
            .set_string(name, value)
            .map_err(|error| SystemProxyError::Platform(error.to_string())),
        None => remove_value(key, name),
    }
}

fn remove_value(key: &Key, name: &str) -> Result<(), SystemProxyError> {
    match key.remove_value(name) {
        Ok(()) => Ok(()),
        Err(error) if error.code().0 as u32 == 2 => Ok(()),
        Err(error) => Err(SystemProxyError::Platform(error.to_string())),
    }
}

fn notify_change() -> Result<(), SystemProxyError> {
    // SAFETY: WinINet accepts a null internet handle and no buffer for both global notifications.
    let changed = unsafe {
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        )
    };
    let refreshed = unsafe {
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        )
    };
    if changed == 0 || refreshed == 0 {
        return Err(SystemProxyError::Platform(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}
