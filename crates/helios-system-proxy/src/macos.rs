#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::{
    io::Read,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{ProxySettings, SystemProxyAdapter, SystemProxyError};

const NETWORKSETUP: &str = "/usr/sbin/networksetup";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MacosProxySnapshot {
    services: Vec<ServiceProxyState>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceProxyState {
    name: String,
    web: ProxyState,
    secure_web: ProxyState,
    bypass: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProxyState {
    enabled: bool,
    server: String,
    port: u16,
}

pub struct MacosProxyAdapter;

impl SystemProxyAdapter for MacosProxyAdapter {
    type Snapshot = MacosProxySnapshot;

    fn read(&self) -> Result<Self::Snapshot, SystemProxyError> {
        let services = run(&["-listallnetworkservices"])?;
        let services = parse_services(&services)?
            .into_iter()
            .map(|name| {
                Ok(ServiceProxyState {
                    web: parse_proxy(&run(&["-getwebproxy", &name])?)?,
                    secure_web: parse_proxy(&run(&["-getsecurewebproxy", &name])?)?,
                    bypass: parse_bypass(&run(&["-getproxybypassdomains", &name])?),
                    name,
                })
            })
            .collect::<Result<Vec<_>, SystemProxyError>>()?;
        Ok(MacosProxySnapshot { services })
    }

    fn desired(
        &self,
        current: &Self::Snapshot,
        settings: &ProxySettings,
    ) -> Result<Self::Snapshot, SystemProxyError> {
        let proxy = ProxyState {
            enabled: true,
            server: settings.endpoint.host.clone(),
            port: settings.endpoint.port,
        };
        Ok(MacosProxySnapshot {
            services: current
                .services
                .iter()
                .map(|service| ServiceProxyState {
                    name: service.name.clone(),
                    web: proxy.clone(),
                    secure_web: proxy.clone(),
                    bypass: settings.bypass.clone(),
                })
                .collect(),
        })
    }

    fn apply(&self, state: &Self::Snapshot) -> Result<(), SystemProxyError> {
        for service in &state.services {
            apply_proxy(&service.name, false, &service.web)?;
            apply_proxy(&service.name, true, &service.secure_web)?;
            let mut args = vec!["-setproxybypassdomains", service.name.as_str()];
            if service.bypass.is_empty() {
                args.push("Empty");
            } else {
                args.extend(service.bypass.iter().map(String::as_str));
            }
            run(&args)?;
        }
        Ok(())
    }

    fn was_reset(
        &self,
        current: &Self::Snapshot,
        original: &Self::Snapshot,
        applied: &Self::Snapshot,
    ) -> bool {
        if current == original {
            return true;
        }
        let mut with_proxy_enabled = current.clone();
        for service in &mut with_proxy_enabled.services {
            service.web.enabled = true;
            service.secure_web.enabled = true;
        }
        with_proxy_enabled == *applied
    }
}

fn apply_proxy(service: &str, secure: bool, state: &ProxyState) -> Result<(), SystemProxyError> {
    let set = if secure {
        "-setsecurewebproxy"
    } else {
        "-setwebproxy"
    };
    let toggle = if secure {
        "-setsecurewebproxystate"
    } else {
        "-setwebproxystate"
    };
    run(&[set, service, &state.server, &state.port.to_string()])?;
    run(&[toggle, service, if state.enabled { "on" } else { "off" }])?;
    Ok(())
}

fn run(args: &[&str]) -> Result<String, SystemProxyError> {
    let output = command_output(
        Command::new(NETWORKSETUP).env("LC_ALL", "C").args(args),
        Duration::from_secs(3),
    )?;
    if !output.status.success() {
        return Err(SystemProxyError::Platform(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| SystemProxyError::Platform(error.to_string()))
}

fn command_output(command: &mut Command, limit: Duration) -> Result<Output, SystemProxyError> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() < limit => std::thread::sleep(Duration::from_millis(10)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(match result {
                    Err(error) => error,
                    _ => std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "networksetup command timed out",
                    ),
                });
            }
        }
    };
    let stdout = out
        .join()
        .map_err(|_| SystemProxyError::Platform("stdout reader failed".into()))??;
    let stderr = err
        .join()
        .map_err(|_| SystemProxyError::Platform("stderr reader failed".into()))??;
    Ok(Output {
        status: status?,
        stdout,
        stderr,
    })
}

fn parse_services(output: &str) -> Result<Vec<String>, SystemProxyError> {
    let services: Vec<_> = output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty() && !line.starts_with("An asterisk") && !line.starts_with('*')
        })
        .map(str::to_owned)
        .collect();
    if services.is_empty() {
        return Err(SystemProxyError::Platform(
            "no enabled macOS network services found".into(),
        ));
    }
    Ok(services)
}

fn parse_proxy(output: &str) -> Result<ProxyState, SystemProxyError> {
    let value = |name: &str| {
        output.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.trim() == name)
                .map(|(_, value)| value.trim())
        })
    };
    if value("Authenticated Proxy Enabled").is_some_and(parse_enabled) {
        return Err(SystemProxyError::Platform(
            "authenticated macOS proxy cannot be safely snapshotted".into(),
        ));
    }
    Ok(ProxyState {
        enabled: value("Enabled").is_some_and(parse_enabled),
        server: value("Server").unwrap_or_default().to_owned(),
        port: value("Port")
            .unwrap_or("0")
            .parse()
            .map_err(|_| SystemProxyError::Platform("invalid networksetup proxy port".into()))?,
    })
}

fn parse_enabled(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "yes" | "on" | "true"
    )
}

fn parse_bypass(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("There aren't any"))
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn command_deadline_kills_and_reaps_the_child_and_drains_pipes() {
        let started = Instant::now();
        let error = command_output(
            Command::new("/bin/sleep").arg("30"),
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
        let output =
            command_output(Command::new("/bin/echo").arg("ok"), Duration::from_secs(1)).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"ok\n");
    }

    #[test]
    fn parses_services_proxies_and_bypass_output() {
        assert_eq!(
            parse_services("An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*USB 10/100 LAN\nThunderbolt Bridge\n").unwrap(),
            ["Wi-Fi", "Thunderbolt Bridge"]
        );
        assert_eq!(
            parse_proxy(
                "Enabled: Yes\nServer: 127.0.0.1\nPort: 8080\nAuthenticated Proxy Enabled: 0\n"
            )
            .unwrap(),
            ProxyState {
                enabled: true,
                server: "127.0.0.1".into(),
                port: 8080
            }
        );
        assert_eq!(
            parse_bypass("localhost\n127.0.0.1\n"),
            ["localhost", "127.0.0.1"]
        );
        assert!(
            parse_proxy(
                "Enabled: Yes\nServer: proxy\nPort: 8080\nAuthenticated Proxy Enabled: 1\n"
            )
            .is_err()
        );
        assert!(
            parse_proxy(
                "Enabled: 1\nServer: 127.0.0.1\nPort: 8080\nAuthenticated Proxy Enabled: 0\n"
            )
            .unwrap()
            .enabled
        );
    }

    #[test]
    fn resume_accepts_disabled_proxy_flags_but_not_another_proxy() {
        let adapter = MacosProxyAdapter;
        let original = MacosProxySnapshot {
            services: vec![ServiceProxyState {
                name: "Wi-Fi".into(),
                web: ProxyState {
                    enabled: false,
                    server: String::new(),
                    port: 0,
                },
                secure_web: ProxyState {
                    enabled: false,
                    server: String::new(),
                    port: 0,
                },
                bypass: vec!["localhost".into()],
            }],
        };
        let applied = adapter
            .desired(
                &original,
                &ProxySettings {
                    endpoint: crate::ProxyEndpoint::new("127.0.0.1", 8080).unwrap(),
                    bypass: vec!["localhost".into()],
                },
            )
            .unwrap();
        let mut reset = applied.clone();
        reset.services[0].web.enabled = false;
        reset.services[0].secure_web.enabled = false;
        assert!(adapter.was_reset(&reset, &original, &applied));
        reset.services[0].web.server = "another-proxy".into();
        assert!(!adapter.was_reset(&reset, &original, &applied));
    }
}
