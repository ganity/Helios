use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use helios_protocol::{Address, Target};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteAction {
    Proxy,
    Direct,
    Reject,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuleConfig {
    Domain { value: String, action: RouteAction },
    DomainSuffix { value: String, action: RouteAction },
    IpCidr { value: String, action: RouteAction },
    IpCidr6 { value: String, action: RouteAction },
    DstPort { value: u16, action: RouteAction },
    Network { value: Network, action: RouteAction },
    Final { action: RouteAction },
}

#[derive(Clone, Debug)]
pub struct RuleSet {
    rules: Vec<Rule>,
    implicit_final: bool,
}

#[derive(Clone, Debug)]
enum Rule {
    Domain(String, RouteAction),
    DomainSuffix(String, RouteAction),
    Cidr(IpAddr, u8, RouteAction),
    DstPort(u16, RouteAction),
    Network(Network, RouteAction),
    Final(RouteAction),
}

impl RuleSet {
    pub fn new(configs: &[RuleConfig]) -> Result<Self, RuleError> {
        if configs.is_empty() {
            return Ok(Self {
                rules: vec![Rule::Final(RouteAction::Proxy)],
                implicit_final: true,
            });
        }
        let mut rules = Vec::with_capacity(configs.len());
        for (index, config) in configs.iter().enumerate() {
            if matches!(config, RuleConfig::Final { .. }) && index + 1 != configs.len() {
                return Err(RuleError::FinalNotLast);
            }
            rules.push(Rule::try_from(config)?);
        }
        if !matches!(rules.last(), Some(Rule::Final(_))) {
            return Err(RuleError::MissingFinal);
        }
        Ok(Self {
            rules,
            implicit_final: false,
        })
    }

    pub fn decide(&self, target: &Target) -> RouteAction {
        self.decide_for_network(target, Network::Tcp)
    }

    pub fn decide_for_network(&self, target: &Target, network: Network) -> RouteAction {
        self.decide_with_network_index(target, network).0
    }

    pub fn decide_with_index(&self, target: &Target) -> (RouteAction, Option<usize>) {
        self.decide_with_network_index(target, Network::Tcp)
    }

    pub fn decide_with_network_index(
        &self,
        target: &Target,
        network: Network,
    ) -> (RouteAction, Option<usize>) {
        let normalized_domain = match &target.address {
            Address::Domain(value) => Some(value.trim_end_matches('.').to_ascii_lowercase()),
            Address::Ip(_) => None,
        };
        for (index, rule) in self.rules.iter().enumerate() {
            if let Some(action) = rule.matches(target, normalized_domain.as_deref(), network) {
                return (action, (!self.implicit_final).then_some(index));
            }
        }
        unreachable!("validated rule sets end with FINAL")
    }
}

impl TryFrom<&RuleConfig> for Rule {
    type Error = RuleError;

    fn try_from(config: &RuleConfig) -> Result<Self, Self::Error> {
        Ok(match config {
            RuleConfig::Domain { value, action } => Rule::Domain(normalize_domain(value)?, *action),
            RuleConfig::DomainSuffix { value, action } => {
                Rule::DomainSuffix(normalize_domain(value)?, *action)
            }
            RuleConfig::IpCidr { value, action } => {
                let (ip, prefix) = parse_cidr(value)?;
                if !ip.is_ipv4() {
                    return Err(RuleError::AddressFamily);
                }
                Rule::Cidr(ip, prefix, *action)
            }
            RuleConfig::IpCidr6 { value, action } => {
                let (ip, prefix) = parse_cidr(value)?;
                if !ip.is_ipv6() {
                    return Err(RuleError::AddressFamily);
                }
                Rule::Cidr(ip, prefix, *action)
            }
            RuleConfig::DstPort { value, action } => {
                if *value == 0 {
                    return Err(RuleError::ZeroPort);
                }
                Rule::DstPort(*value, *action)
            }
            RuleConfig::Final { action } => Rule::Final(*action),
            RuleConfig::Network { value, action } => Rule::Network(*value, *action),
        })
    }
}

impl Rule {
    fn matches(
        &self,
        target: &Target,
        domain: Option<&str>,
        network: Network,
    ) -> Option<RouteAction> {
        match self {
            Self::Domain(expected, action) => domain
                .is_some_and(|actual| actual == expected)
                .then_some(*action),
            Self::DomainSuffix(suffix, action) => domain
                .is_some_and(|actual| {
                    actual == suffix
                        || actual
                            .strip_suffix(suffix)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                })
                .then_some(*action),
            Self::Cidr(network, prefix, action) => match &target.address {
                Address::Ip(ip) if contains(*network, *prefix, *ip) => Some(*action),
                _ => None,
            },
            Self::DstPort(port, action) => (target.port == *port).then_some(*action),
            Self::Final(action) => Some(*action),
            Self::Network(expected, action) => (*expected == network).then_some(*action),
        }
    }
}

fn normalize_domain(value: &str) -> Result<String, RuleError> {
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || !value.is_ascii()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(RuleError::InvalidDomain);
    }
    Ok(value)
}

fn parse_cidr(value: &str) -> Result<(IpAddr, u8), RuleError> {
    let (address, prefix) = value.split_once('/').ok_or(RuleError::InvalidCidr)?;
    let address: IpAddr = address.parse().map_err(|_| RuleError::InvalidCidr)?;
    let prefix: u8 = prefix.parse().map_err(|_| RuleError::InvalidCidr)?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        return Err(RuleError::InvalidCidr);
    }
    Ok((address, prefix))
}

fn contains(network: IpAddr, prefix: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            masked_v4(network, prefix) == masked_v4(address, prefix)
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            masked_v6(network, prefix) == masked_v6(address, prefix)
        }
        _ => false,
    }
}

fn masked_v4(address: Ipv4Addr, prefix: u8) -> u32 {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(address) & mask
}

fn masked_v6(address: Ipv6Addr, prefix: u8) -> u128 {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    u128::from(address) & mask
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RuleError {
    #[error("rule domain is invalid")]
    InvalidDomain,
    #[error("rule CIDR is invalid")]
    InvalidCidr,
    #[error("rule CIDR address family does not match its type")]
    AddressFamily,
    #[error("destination port rule cannot be zero")]
    ZeroPort,
    #[error("non-empty rules must end with FINAL")]
    MissingFinal,
    #[error("FINAL must be the last rule")]
    FinalNotLast,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(address: Address, port: u16) -> Target {
        Target::new(address, port).unwrap()
    }

    #[test]
    fn network_rules_respect_protocol_and_order() {
        let rules = RuleSet::new(&[
            RuleConfig::DstPort {
                value: 53,
                action: RouteAction::Direct,
            },
            RuleConfig::Network {
                value: Network::Udp,
                action: RouteAction::Reject,
            },
            RuleConfig::Final {
                action: RouteAction::Proxy,
            },
        ])
        .unwrap();
        let web = target(Address::Domain("example.com".into()), 443);
        assert_eq!(rules.decide(&web), RouteAction::Proxy);
        assert_eq!(
            rules.decide_for_network(&web, Network::Udp),
            RouteAction::Reject
        );
        assert_eq!(
            rules.decide_with_network_index(&web, Network::Udp).1,
            Some(1)
        );
        let dns = target(Address::Domain("example.com".into()), 53);
        assert_eq!(
            rules.decide_for_network(&dns, Network::Udp),
            RouteAction::Direct
        );
    }

    #[test]
    fn matches_in_order_across_supported_rule_types() {
        let rules = RuleSet::new(&[
            RuleConfig::Domain {
                value: "Exact.Example.".into(),
                action: RouteAction::Reject,
            },
            RuleConfig::DomainSuffix {
                value: "example.com".into(),
                action: RouteAction::Direct,
            },
            RuleConfig::IpCidr {
                value: "192.168.0.0/16".into(),
                action: RouteAction::Direct,
            },
            RuleConfig::IpCidr6 {
                value: "2001:db8::/32".into(),
                action: RouteAction::Direct,
            },
            RuleConfig::DstPort {
                value: 22,
                action: RouteAction::Reject,
            },
            RuleConfig::Final {
                action: RouteAction::Proxy,
            },
        ])
        .unwrap();

        assert_eq!(
            rules.decide(&target(Address::Domain("exact.example".into()), 443)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.decide(&target(Address::Domain("a.example.com".into()), 443)),
            RouteAction::Direct
        );
        assert_eq!(
            rules.decide(&target(Address::Ip("192.168.1.2".parse().unwrap()), 80)),
            RouteAction::Direct
        );
        assert_eq!(
            rules.decide(&target(Address::Ip("2001:db8::1".parse().unwrap()), 80)),
            RouteAction::Direct
        );
        assert_eq!(
            rules.decide(&target(Address::Domain("other.example".into()), 22)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.decide(&target(Address::Domain("badexample.com".into()), 443)),
            RouteAction::Proxy
        );
        assert_eq!(
            rules.decide_with_index(&target(Address::Domain("a.example.com".into()), 443)),
            (RouteAction::Direct, Some(1))
        );
        assert_eq!(
            RuleSet::new(&[])
                .unwrap()
                .decide_with_index(&target(Address::Domain("example.com".into()), 443)),
            (RouteAction::Proxy, None)
        );
    }

    #[test]
    fn rejects_ambiguous_or_invalid_rule_sets() {
        assert_eq!(
            RuleSet::new(&[RuleConfig::DstPort {
                value: 80,
                action: RouteAction::Direct,
            }])
            .unwrap_err(),
            RuleError::MissingFinal
        );
        assert_eq!(
            RuleSet::new(&[
                RuleConfig::Final {
                    action: RouteAction::Proxy,
                },
                RuleConfig::Final {
                    action: RouteAction::Direct,
                },
            ])
            .unwrap_err(),
            RuleError::FinalNotLast
        );
    }
}
