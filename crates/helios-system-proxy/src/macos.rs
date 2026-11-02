#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::process::Command;

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
    let output = Command::new(NETWORKSETUP).args(args).output()?;
    if !output.status.success() {
        return Err(SystemProxyError::Platform(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| SystemProxyError::Platform(error.to_string()))
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
    if value("Authenticated Proxy Enabled").is_some_and(|value| matches!(value, "1" | "Yes")) {
        return Err(SystemProxyError::Platform(
            "authenticated macOS proxy cannot be safely snapshotted".into(),
        ));
    }
    Ok(ProxyState {
        enabled: matches!(value("Enabled"), Some("Yes")),
        server: value("Server").unwrap_or_default().to_owned(),
        port: value("Port")
            .unwrap_or("0")
            .parse()
            .map_err(|_| SystemProxyError::Platform("invalid networksetup proxy port".into()))?,
    })
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
    }
}
