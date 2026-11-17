use std::{fmt, net::SocketAddr, str::FromStr};

use helios_protocol::{Address, Target};
use serde::{Deserialize, Serialize};

/// One server identity may have several independently reachable ingress addresses.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct NodeAddresses(Vec<Target>);

impl NodeAddresses {
    pub fn endpoints(&self) -> &[Target] {
        &self.0
    }

    pub fn port(&self) -> u16 {
        self.0[0].port
    }
}

impl FromStr for NodeAddresses {
    type Err = String;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.len() > 4096 {
            return Err("node addresses exceed 4096 bytes".into());
        }
        let mut endpoints = Vec::new();
        for value in input
            .split([',', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let target = if let Ok(address) = value.parse::<SocketAddr>() {
                Target::new(Address::Ip(address.ip()), address.port())
            } else {
                let (host, port) = value
                    .rsplit_once(':')
                    .ok_or("expected host:port or [IPv6]:port")?;
                // Numeric-looking invalid IPv4 and unbracketed IPv6 must not become DNS names.
                if host.contains(':') || host.chars().all(|c| c.is_ascii_digit() || c == '.') {
                    return Err(format!("invalid node address: {value}"));
                }
                let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
                Target::new(
                    Address::Domain(host),
                    port.parse().map_err(|_| "invalid node port")?,
                )
            }
            .map_err(|error| error.to_string())?;
            if !endpoints.contains(&target) {
                endpoints.push(target);
            }
            if endpoints.len() > 8 {
                return Err("a node supports at most 8 ingress addresses".into());
            }
        }
        if endpoints.is_empty() {
            return Err("at least one node address is required".into());
        }
        Ok(Self(endpoints))
    }
}

impl TryFrom<String> for NodeAddresses {
    type Error = String;
    fn try_from(value: String) -> Result<Self, String> {
        value.parse()
    }
}
impl From<NodeAddresses> for String {
    fn from(value: NodeAddresses) -> Self {
        value.to_string()
    }
}
impl From<SocketAddr> for NodeAddresses {
    fn from(value: SocketAddr) -> Self {
        // SocketAddr may contain port zero; configuration validation still rejects it.
        Self(vec![Target {
            address: Address::Ip(value.ip()),
            port: value.port(),
        }])
    }
}
impl fmt::Display for NodeAddresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, target) in self.0.iter().enumerate() {
            if i != 0 {
                f.write_str(", ")?;
            }
            match &target.address {
                Address::Ip(ip) => write!(f, "{}", SocketAddr::new(*ip, target.port))?,
                Address::Domain(host) => write!(f, "{host}:{}", target.port)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trips_mixed_ingress_and_rejects_malformed_addresses() {
        let addresses: NodeAddresses =
            "VPN.Example.com:443\n[2001:db8::1]:24443, 192.0.2.1:444, vpn.example.com:443"
                .parse()
                .unwrap();
        assert_eq!(addresses.endpoints().len(), 3);
        assert_eq!(
            addresses.to_string(),
            "vpn.example.com:443, [2001:db8::1]:24443, 192.0.2.1:444"
        );
        let json = serde_json::to_string(&addresses).unwrap();
        assert_eq!(
            serde_json::from_str::<NodeAddresses>(&json).unwrap(),
            addresses
        );
        for invalid in [
            "",
            "example.com",
            "example.com:0",
            "example.com:65536",
            "https://example.com:443",
            "2001:db8::1:443",
            "999.1.1.1:443",
            "-bad.test:443",
            "bad.test..:443",
            "example.com:443/path",
        ] {
            assert!(invalid.parse::<NodeAddresses>().is_err(), "{invalid}");
        }
    }
}
