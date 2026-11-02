use std::collections::BTreeMap;
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::{ProxySettings, SystemProxyAdapter, SystemProxyError};

const KEYS: &[(&str, &str)] = &[
    ("org.gnome.system.proxy", "mode"),
    ("org.gnome.system.proxy", "ignore-hosts"),
    ("org.gnome.system.proxy", "use-same-proxy"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.http", "use-authentication"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxProxySnapshot {
    values: BTreeMap<String, String>,
}

pub struct LinuxProxyAdapter;

impl SystemProxyAdapter for LinuxProxyAdapter {
    type Snapshot = LinuxProxySnapshot;

    fn read(&self) -> Result<Self::Snapshot, SystemProxyError> {
        let mut values = BTreeMap::new();
        for &(schema, key) in KEYS {
            values.insert(format!("{schema}/{key}"), run(&["get", schema, key])?);
        }
        Ok(LinuxProxySnapshot { values })
    }

    fn desired(
        &self,
        current: &Self::Snapshot,
        settings: &ProxySettings,
    ) -> Result<Self::Snapshot, SystemProxyError> {
        let mut state = current.clone();
        let mut set = |schema: &str, key: &str, value: String| {
            state.values.insert(format!("{schema}/{key}"), value);
        };
        set("org.gnome.system.proxy", "mode", quote("manual"));
        set("org.gnome.system.proxy", "use-same-proxy", "false".into());
        set(
            "org.gnome.system.proxy",
            "ignore-hosts",
            if settings.bypass.is_empty() {
                "@as []".into()
            } else {
                format!(
                    "[{}]",
                    settings
                        .bypass
                        .iter()
                        .map(|host| quote(host))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
        );
        set(
            "org.gnome.system.proxy.http",
            "use-authentication",
            "false".into(),
        );
        for schema in [
            "org.gnome.system.proxy.http",
            "org.gnome.system.proxy.https",
        ] {
            set(schema, "host", quote(&settings.endpoint.host));
            set(schema, "port", settings.endpoint.port.to_string());
        }
        Ok(state)
    }

    fn apply(&self, state: &Self::Snapshot) -> Result<(), SystemProxyError> {
        if KEYS
            .iter()
            .any(|(schema, key)| !state.values.contains_key(&format!("{schema}/{key}")))
        {
            return Err(SystemProxyError::InvalidSettings);
        }
        // Enable the new mode only after all endpoints have been installed.
        for &(schema, key) in KEYS.iter().skip(1).chain(KEYS.iter().take(1)) {
            let value = state
                .values
                .get(&format!("{schema}/{key}"))
                .ok_or(SystemProxyError::InvalidSettings)?;
            run(&["set", schema, key, value])?;
        }
        Ok(())
    }
}

fn quote(value: &str) -> String {
    let delimiter = if value.contains('\'') { '"' } else { '\'' };
    let escaped = value
        .replace('\\', "\\\\")
        .replace(delimiter, &format!("\\{delimiter}"))
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("{delimiter}{escaped}{delimiter}")
}

fn run(args: &[&str]) -> Result<String, SystemProxyError> {
    let output = Command::new("gsettings").args(args).output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(SystemProxyError::Platform(format!(
            "GNOME gsettings failed (requires a writable desktop session): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| SystemProxyError::Platform(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires explicit opt-in; temporarily changes the real GNOME proxy and needs Chrome plus a working local proxy"]
    fn real_browser_uses_gnome_system_proxy() {
        assert_eq!(
            std::env::var("HELIOS_REAL_BROWSER_TEST").as_deref(),
            Ok("1")
        );
        std::net::TcpStream::connect("127.0.0.1:8080").unwrap();
        let directory =
            std::env::temp_dir().join(format!("helios-browser-test-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        struct Restore(crate::SystemProxyLease<LinuxProxyAdapter>);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = self.0.release();
            }
        }
        let lease = Restore(crate::SystemProxyLease::new(
            LinuxProxyAdapter,
            directory.join("lease.json"),
        ));
        let original = LinuxProxyAdapter.read().unwrap();
        lease
            .0
            .acquire(ProxySettings {
                endpoint: crate::ProxyEndpoint::new("127.0.0.1", 8080).unwrap(),
                bypass: vec!["localhost".into(), "127.0.0.0/8".into()],
            })
            .unwrap();
        assert!(lease.0.is_applied().unwrap());
        let browser_profile = directory.join("browser");
        let mut browser = Command::new("/opt/google/chrome/chrome")
            .args([
                "--headless",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-background-networking",
                "--disable-extensions",
                "--no-first-run",
                "--no-default-browser-check",
                "--remote-debugging-port=0",
            ])
            .arg(format!("--user-data-dir={}", browser_profile.display()))
            .arg("about:blank")
            .env("XDG_CURRENT_DESKTOP", "GNOME")
            .env_remove("http_proxy")
            .env_remove("https_proxy")
            .env_remove("all_proxy")
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY")
            .env_remove("no_proxy")
            .env_remove("NO_PROXY")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let output = Command::new("timeout")
            .args(["25", "node"])
            .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/browser-probe.mjs"))
            .arg(&browser_profile)
            .output();
        let _ = browser.kill();
        let _ = browser.wait();
        let restored = lease.0.release().unwrap();
        assert_eq!(restored, crate::ReleaseOutcome::Released);
        assert_eq!(LinuxProxyAdapter.read().unwrap(), original);
        std::fs::remove_dir_all(&directory).unwrap();
        let output = output.unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    #[test]
    #[ignore = "requires an isolated D-Bus session and temporary XDG_CONFIG_HOME"]
    fn isolated_gsettings_lease_round_trip() {
        let directory = std::path::PathBuf::from(
            std::env::var_os("HELIOS_ISOLATED_GSETTINGS_DIR")
                .expect("run only in an isolated test session"),
        );
        assert_eq!(
            std::env::var_os("XDG_CONFIG_HOME"),
            Some(directory.clone().into_os_string())
        );
        assert!(directory.is_dir());
        // Seed non-default user settings only inside the isolated dconf database.
        run(&["set", "org.gnome.system.proxy", "mode", "'auto'"]).unwrap();
        run(&[
            "set",
            "org.gnome.system.proxy",
            "autoconfig-url",
            "'https://pac.example.invalid/proxy.pac'",
        ])
        .unwrap();
        run(&[
            "set",
            "org.gnome.system.proxy.socks",
            "host",
            "'socks.example.invalid'",
        ])
        .unwrap();
        run(&["set", "org.gnome.system.proxy.socks", "port", "1081"]).unwrap();
        run(&[
            "set",
            "org.gnome.system.proxy.http",
            "use-authentication",
            "true",
        ])
        .unwrap();
        let original = LinuxProxyAdapter.read().unwrap();
        let lease = crate::SystemProxyLease::new(LinuxProxyAdapter, directory.join("lease.json"));
        for bypass in [
            vec!["localhost".into(), "127.0.0.0/8".into()],
            vec!["a'b\\c".into(), "a'b\"c".into()],
            vec![],
        ] {
            let settings = ProxySettings {
                endpoint: crate::ProxyEndpoint::new("127.0.0.1", 18080).unwrap(),
                bypass,
            };
            let expected = LinuxProxyAdapter.desired(&original, &settings).unwrap();
            lease.acquire(settings).unwrap();
            assert_eq!(LinuxProxyAdapter.read().unwrap(), expected);
            assert_eq!(
                run(&["get", "org.gnome.system.proxy", "autoconfig-url"]).unwrap(),
                "'https://pac.example.invalid/proxy.pac'"
            );
            assert_eq!(
                run(&["get", "org.gnome.system.proxy.socks", "host"]).unwrap(),
                "'socks.example.invalid'"
            );
            assert_eq!(
                run(&["get", "org.gnome.system.proxy.socks", "port"]).unwrap(),
                "1081"
            );
            assert_eq!(lease.recover().unwrap(), crate::ReleaseOutcome::Released);
            assert_eq!(LinuxProxyAdapter.read().unwrap(), original);
        }
        assert!(!directory.join("lease.json").exists());
        lease
            .acquire(ProxySettings {
                endpoint: crate::ProxyEndpoint::new("127.0.0.1", 18080).unwrap(),
                bypass: vec![],
            })
            .unwrap();
        run(&["set", "org.gnome.system.proxy.http", "port", "18081"]).unwrap();
        let changed = LinuxProxyAdapter.read().unwrap();
        assert_eq!(
            lease.recover().unwrap(),
            crate::ReleaseOutcome::Drifted {
                current: changed.clone()
            }
        );
        assert_eq!(LinuxProxyAdapter.read().unwrap(), changed);
        LinuxProxyAdapter.apply(&original).unwrap();
        assert_eq!(
            lease.recover().unwrap(),
            crate::ReleaseOutcome::AlreadyRestored
        );
    }

    #[test]
    fn desired_proxy_preserves_snapshot_and_quotes_values() {
        let current = LinuxProxySnapshot {
            values: BTreeMap::new(),
        };
        let desired = LinuxProxyAdapter
            .desired(
                &current,
                &ProxySettings {
                    endpoint: crate::ProxyEndpoint::new("127.0.0.1", 8080).unwrap(),
                    bypass: vec!["localhost".into(), "a'b\\c".into()],
                },
            )
            .unwrap();
        assert!(current.values.is_empty());
        assert_eq!(desired.values["org.gnome.system.proxy/mode"], "'manual'");
        assert_eq!(
            desired.values["org.gnome.system.proxy/ignore-hosts"],
            "['localhost', \"a'b\\\\c\"]"
        );
        assert_eq!(desired.values.len(), KEYS.len());
    }

    #[test]
    fn empty_bypass_uses_canonical_gvariant_array() {
        let desired = LinuxProxyAdapter
            .desired(
                &LinuxProxySnapshot {
                    values: BTreeMap::new(),
                },
                &ProxySettings {
                    endpoint: crate::ProxyEndpoint::new("127.0.0.1", 8080).unwrap(),
                    bypass: vec![],
                },
            )
            .unwrap();
        assert_eq!(
            desired.values["org.gnome.system.proxy/ignore-hosts"],
            "@as []"
        );
    }

    #[test]
    fn incomplete_snapshot_is_rejected_before_platform_writes() {
        assert!(matches!(
            LinuxProxyAdapter.apply(&LinuxProxySnapshot {
                values: BTreeMap::new()
            }),
            Err(SystemProxyError::InvalidSettings)
        ));
    }
}
