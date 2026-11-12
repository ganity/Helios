//! Persisted mobile preferences; credentials remain in the node store.
use serde::{Deserialize, Serialize};
use std::{io::Write, net::SocketAddr, path::Path};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub dns: SocketAddr,
    pub auto_reconnect: bool,
    pub auto_failover: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            dns: "1.1.1.1:53".parse().unwrap(),
            auto_reconnect: false,
            auto_failover: false,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), String> {
        if self.dns.port() == 0
            || self.dns.ip().is_unspecified()
            || self.dns.ip().is_multicast()
            || self.dns.ip().is_loopback()
            || self.dns.ip() == "10.88.0.1".parse::<std::net::IpAddr>().unwrap()
        {
            return Err("DNS 必须是服务端能够访问的 IP:端口；IPv6 使用 [地址]:端口".into());
        }
        Ok(())
    }

    pub fn load(root: &Path) -> Result<Self, String> {
        let bytes = match std::fs::read(root.join("mobile-settings.json")) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.to_string()),
        };
        let settings: Self = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn save(&self, root: &Path) -> Result<(), String> {
        self.validate()?;
        let mut file = tempfile::NamedTempFile::new_in(root).map_err(|e| e.to_string())?;
        file.write_all(&serde_json::to_vec(self).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        file.as_file().sync_all().map_err(|e| e.to_string())?;
        file.persist(root.join("mobile-settings.json"))
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_round_trip_and_invalid_update_preserves_previous() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(Settings::load(root.path()).unwrap(), Settings::default());
        let mut settings = Settings {
            dns: "[2606:4700:4700::1111]:53".parse().unwrap(),
            auto_reconnect: true,
            auto_failover: true,
        };
        settings.save(root.path()).unwrap();
        assert_eq!(Settings::load(root.path()).unwrap(), settings);
        settings.dns = "10.88.0.1:53".parse().unwrap();
        assert!(settings.save(root.path()).is_err());
        assert_ne!(Settings::load(root.path()).unwrap().dns, settings.dns);
    }
}
