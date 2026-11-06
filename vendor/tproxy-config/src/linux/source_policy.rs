//! Source-bound daemon sockets use the unchanged main table; applications use a TUN table.
use super::{recovery::checkpoint, *};
use rtnetlink::packet_route::{
    AddressFamily,
    address::AddressAttribute,
    route::{RouteAttribute, RouteProtocol},
    rule::{RuleAction, RuleAttribute, RuleMessage},
};

const TABLE: u32 = 20220;
const SOURCE_PRIORITY: u32 = 20220;
const SOURCE_BLOCK_PRIORITY: u32 = 20221;
const LAN_PRIORITY: u32 = 20222;
const TUN_PRIORITY: u32 = 20223;
const TUN_IPV6: &str = "fd00:6865:6c69::2";

fn priority(rule: &RuleMessage) -> Option<u32> {
    rule.attributes
        .iter()
        .find_map(|attribute| match attribute {
            RuleAttribute::Priority(value) => Some(*value),
            _ => None,
        })
}

fn rule(ipv6: bool, priority: u32, table: u32) -> RuleMessage {
    let mut rule = RuleMessage::default();
    rule.header.family = if ipv6 {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    };
    rule.header.action = RuleAction::ToTable;
    // Use the extended attribute consistently, including table IDs below 256.
    rule.attributes = vec![
        RuleAttribute::Priority(priority),
        RuleAttribute::Table(table),
        RuleAttribute::Protocol(RouteProtocol::Other(253)),
    ];
    rule
}

fn source_rule(source: IpAddr) -> RuleMessage {
    let mut rule = rule(source.is_ipv6(), SOURCE_PRIORITY, ROUTING_TABLE_MAIN);
    rule.header.src_len = if source.is_ipv6() { 128 } else { 32 };
    rule.attributes.push(RuleAttribute::Source(source));
    rule
}

fn policy_rules(args: &TproxyArgs) -> Vec<RuleMessage> {
    let mut rules: Vec<_> = args
        .source_bypass
        .iter()
        .copied()
        .map(source_rule)
        .collect();
    // An uplink disappearing must fail, rather than sending daemon traffic back to TUN.
    for source in &args.source_bypass {
        let mut blocked = source_rule(*source);
        blocked.header.action = RuleAction::Unreachable;
        blocked.attributes.retain(|attribute| {
            !matches!(
                attribute,
                RuleAttribute::Table(_) | RuleAttribute::Priority(_)
            )
        });
        blocked
            .attributes
            .push(RuleAttribute::Priority(SOURCE_BLOCK_PRIORITY));
        rules.push(blocked);
    }
    for (ipv6, enabled) in [
        (false, args.ipv4_default_route),
        (true, args.ipv6_default_route),
    ] {
        let mut lan = rule(ipv6, LAN_PRIORITY, ROUTING_TABLE_MAIN);
        lan.attributes.push(RuleAttribute::SuppressPrefixLen(0));
        rules.push(lan);
        let mut tun = rule(ipv6, TUN_PRIORITY, TABLE);
        if !enabled {
            tun.header.action = RuleAction::Unreachable;
            tun.attributes
                .retain(|attribute| !matches!(attribute, RuleAttribute::Table(_)));
        }
        rules.push(tun);
    }
    rules
}

async fn rules(ipv6: bool) -> Result<Vec<RuleMessage>> {
    netlink_do(async |handle| {
        Ok(handle
            .rule()
            .get(bool_to_ip_version(ipv6))
            .execute()
            .try_collect()
            .await?)
    })
    .await
}

fn require_free_rules(existing: &[RuleMessage]) -> Result<()> {
    for rule in existing {
        let table = rule
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RuleAttribute::Table(value) => Some(*value),
                _ => None,
            })
            .unwrap_or(u32::from(rule.header.table));
        let standard = rule.header.action == RuleAction::ToTable
            && rule.header.src_len == 0
            && rule.header.dst_len == 0
            && rule.header.tos == 0
            && rule.header.flags.is_empty()
            && matches!(
                (priority(rule).unwrap_or(0), table),
                (0, 255) | (32766, 254) | (32767, 253)
            )
            && rule.attributes.iter().all(|attribute| {
                matches!(
                    attribute,
                    RuleAttribute::Priority(_)
                        | RuleAttribute::Table(_)
                        | RuleAttribute::Protocol(_)
                        | RuleAttribute::SuppressPrefixLen(u32::MAX)
                        | RuleAttribute::SuppressIfGroup(u32::MAX)
                )
            });
        if !standard {
            return Err(std::io::Error::other("source-policy routing requires standard Linux rules; another VPN or policy rule is active").into());
        }
    }
    Ok(())
}

pub(super) async fn preflight(args: &TproxyArgs) -> Result<()> {
    if args.source_bypass.len() > 2
        || args
            .source_bypass
            .iter()
            .any(|ip| ip.is_unspecified() || ip.is_loopback() || ip.is_multicast())
        || args
            .source_bypass
            .windows(2)
            .any(|pair| pair[0].is_ipv4() == pair[1].is_ipv4())
    {
        return Err(std::io::Error::other(
            "source_bypass requires at most one unicast address per family",
        )
        .into());
    }
    for ipv6 in [false, true] {
        require_free_rules(&rules(ipv6).await?)?;
        if !ip_route_show(bool_to_ip_version(ipv6), TABLE)
            .await?
            .is_empty()
        {
            return Err(std::io::Error::other(format!(
                "Helios routing table {TABLE} is not empty"
            ))
            .into());
        }
    }
    netlink_do(async |handle| {
        let tun_index = ip_link_get_index(&args.tun_name).await?;
        let addresses: Vec<_> = handle.address().get().execute().try_collect().await?;
        for source in &args.source_bypass {
            if !addresses.iter().any(|address| {
                address.header.index != tun_index
                    && address.attributes.iter().any(|attribute| {
                        matches!(attribute,
                    AddressAttribute::Local(ip) | AddressAttribute::Address(ip) if ip == source)
                    })
            }) {
                return Err(std::io::Error::other(format!(
                    "source address {source} is not assigned to an uplink"
                ))
                .into());
            }
        }
        Ok(())
    })
    .await
}

async fn add_rule(state: &mut TproxyStateInner, rule: RuleMessage) -> Result<()> {
    state.remove_rules.push(rule.clone());
    checkpoint(state)?;
    let result = netlink_do(async |handle| {
        let mut request = handle.rule().add();
        *request.message_mut() = rule.clone();
        Ok(request.execute().await?)
    })
    .await;
    if result.is_err() {
        state.remove_rules.pop();
        checkpoint(state)?;
    }
    result
}

pub(super) async fn setup(state: &mut TproxyStateInner) -> Result<()> {
    let args = state.tproxy_args.clone().unwrap();
    let index = ip_link_get_index(&args.tun_name).await?;
    if args.ipv6_default_route {
        // A distinct TUN source prevents unbound IPv6 applications selecting the uplink source.
        netlink_do(async |handle| {
            let mut request = handle.address().add(index, TUN_IPV6.parse()?, 128);
            request
                .message_mut()
                .header
                .flags
                .insert(rtnetlink::packet_route::address::AddressHeaderFlags::Nodad);
            Ok(request.execute().await?)
        })
        .await?;
    }
    for (enabled, default) in [
        (args.ipv4_default_route, &*IPV4_DEFAULT_ROUTE),
        (args.ipv6_default_route, &*IPV6_DEFAULT_ROUTE),
    ] {
        if enabled {
            let mut route = RouteMessageBuilder::<IpAddr>::new()
                .destination_prefix(default.first_address(), 0)?
                .table_id(TABLE)
                .output_interface(index)
                .build();
            route
                .attributes
                .push(RouteAttribute::PrefSource(if default.is_ipv6() {
                    rtnetlink::packet_route::route::RouteAddress::Inet6(TUN_IPV6.parse()?)
                } else {
                    match args.tun_ip {
                        IpAddr::V4(ip) => rtnetlink::packet_route::route::RouteAddress::Inet(ip),
                        _ => {
                            return Err(std::io::Error::other("TUN IPv4 source is not IPv4").into());
                        }
                    }
                }));
            super::recovery::add_route(state, route).await?;
        }
    }
    // Install the catch-all last; every preceding operation is already journaled.
    for rule in policy_rules(&args) {
        add_rule(state, rule).await?;
    }
    Ok(())
}

fn equivalent(left: &RuleMessage, right: &RuleMessage) -> bool {
    fn normalized(rule: &RuleMessage) -> (rtnetlink::packet_route::rule::RuleHeader, Vec<String>) {
        let mut header = rule.header.clone();
        let table = rule
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RuleAttribute::Table(value) => Some(*value),
                _ => None,
            })
            .unwrap_or(u32::from(header.table));
        header.table = 0;
        let mut attributes: Vec<_> = rule
            .attributes
            .iter()
            .filter(|attribute| {
                !matches!(
                    attribute,
                    RuleAttribute::Table(_)
                        | RuleAttribute::SuppressPrefixLen(u32::MAX)
                        | RuleAttribute::SuppressIfGroup(u32::MAX)
                )
            })
            .map(|attribute| format!("{attribute:?}"))
            .collect();
        attributes.push(format!("table:{table}"));
        attributes.sort();
        (header, attributes)
    }
    normalized(left) == normalized(right)
}

pub(super) async fn remove(state: &mut TproxyStateInner) -> Result<()> {
    while let Some(expected) = state.remove_rules.last().cloned() {
        let current: Vec<_> = rules(expected.header.family == AddressFamily::Inet6)
            .await?
            .into_iter()
            .filter(|rule| priority(rule) == priority(&expected))
            .collect();
        if let Some(rule) = current.iter().find(|rule| equivalent(rule, &expected)) {
            let rule = rule.clone();
            netlink_do(async |handle| Ok(handle.rule().del(rule.clone()).execute().await?)).await?;
        } else if !current.is_empty() {
            return Err(std::io::Error::other(
                "Helios policy rule was changed externally; recovery preserved",
            )
            .into());
        }
        state.remove_rules.pop();
        checkpoint(state)?;
    }
    Ok(())
}

pub(super) async fn check_active(state: &TproxyStateInner) -> Result<()> {
    for ipv6 in [false, true] {
        let current = rules(ipv6).await?;
        require_free_rules(
            &current
                .iter()
                .filter(|rule| {
                    !state
                        .remove_rules
                        .iter()
                        .any(|expected| equivalent(rule, expected))
                })
                .cloned()
                .collect::<Vec<_>>(),
        )?;
        for expected in state
            .remove_rules
            .iter()
            .filter(|rule| (rule.header.family == AddressFamily::Inet6) == ipv6)
        {
            if !current.iter().any(|rule| equivalent(rule, expected)) {
                return Err(std::io::Error::other("TUN policy rule disappeared or changed").into());
            }
        }
        if current
            .iter()
            .filter(|rule| (20220..=20223).contains(&priority(rule).unwrap_or(0)))
            .count()
            != state
                .remove_rules
                .iter()
                .filter(|rule| (rule.header.family == AddressFamily::Inet6) == ipv6)
                .count()
        {
            return Err(std::io::Error::other("conflicting TUN policy rule appeared").into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_policy_preserves_local_rules_and_blocks_disabled_family() {
        let args = TproxyArgs::new()
            .source_bypass(&["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()]);
        let rules = policy_rules(&args);
        assert_eq!(rules[0].header.src_len, 32);
        assert_eq!(rules[1].header.src_len, 128);
        assert_eq!(rules.last().unwrap().header.action, RuleAction::Unreachable);
        assert_eq!(priority(rules.last().unwrap()), Some(TUN_PRIORITY));
        let mut reordered = rules[0].clone();
        reordered.attributes.reverse();
        reordered
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(u32::MAX));
        assert!(equivalent(&reordered, &rules[0]));
        reordered.attributes.push(RuleAttribute::FwMark(42));
        assert!(!equivalent(&reordered, &rules[0]));
        assert!(require_free_rules(&[rule(false, 0, 255), rule(false, 32766, 254)]).is_ok());
        assert!(require_free_rules(&rules).is_err());
        let mut foreign = rule(false, 32766, 254);
        foreign.attributes.push(RuleAttribute::FwMark(42));
        assert!(require_free_rules(&[foreign]).is_err());
        let args = args.ipv4_default_route(false).ipv6_default_route(true);
        assert!(!args.ipv4_default_route);
        assert!(args.ipv6_default_route);
        assert_eq!(
            policy_rules(&args).last().unwrap().header.action,
            RuleAction::ToTable
        );
    }
}
