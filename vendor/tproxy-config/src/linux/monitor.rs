//! Poll only invariants that affect this lease. No privileged shell commands.
use super::*;
use rtnetlink::packet_route::{address::AddressAttribute, route::RouteAttribute};

pub async fn uplink_snapshot(sources: &[IpAddr], tun_name: &str) -> Result<Vec<String>> {
    let tun = ip_link_get_index(tun_name).await.ok();
    let mut result = netlink_do(async |handle| {
        let mut result = Vec::new();
        let addresses: Vec<_> = handle.address().get().execute().try_collect().await?;
        for source in sources {
            let address = addresses.iter().find(|a| Some(a.header.index) != tun && a.attributes.iter().any(|attribute|
                matches!(attribute, AddressAttribute::Local(ip) | AddressAttribute::Address(ip) if ip == source)
            )).ok_or_else(|| std::io::Error::other("physical source address disappeared"))?;
            let links: Vec<_> = handle.link().get().match_index(address.header.index).execute().try_collect().await?;
            result.push(format!("source:{source}:{}:{:?}", address.header.index, links.first().map(|link| &link.header.flags)));
        }
        Ok(result)
    }).await?;
    for ipv6 in [false, true] {
        for mut route in ip_route_show(bool_to_ip_version(ipv6), ROUTING_TABLE_MAIN).await? {
            if route
                .attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Oif(index) if Some(*index) == tun))
            {
                continue;
            }
            // Kernel cache ages change continuously; forwarding attributes remain comparable.
            route.attributes.retain(|a| {
                !matches!(
                    a,
                    RouteAttribute::CacheInfo(_)
                        | RouteAttribute::Expires(_)
                        | RouteAttribute::MulticastExpires(_)
                )
            });
            route
                .attributes
                .sort_by_key(|attribute| format!("{attribute:?}"));
            result.push(format!("route:{route:?}"));
        }
    }
    result.sort();
    Ok(result)
}

pub async fn check_active() -> Result<()> {
    let state = crate::retrieve_secure_state()?;
    recovery::validate(&state).await?;
    source_policy::check_active(&state).await?;
    resolved::check_active(&state).await?;
    if let Some(expected) = &state.applied_resolvconf_content
        && fs::read(ETC_RESOLV_CONF_FILE)? != *expected
    {
        return Err(std::io::Error::other("static resolver changed during TUN session").into());
    }
    for route in &state.remove_routes {
        let current = ip_route_get(&route_msg_to_cidr(route)?, route_table(route), true).await?;
        if !current
            .as_ref()
            .is_some_and(|current| recovery::equivalent(current, route))
        {
            return Err(std::io::Error::other("TUN route disappeared or changed").into());
        }
    }
    Ok(())
}
