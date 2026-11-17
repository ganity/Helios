use futures_util::{StreamExt, stream::FuturesUnordered};
use helios_config::NodeAddresses;
use helios_protocol::{Address, Target};
use std::sync::OnceLock;
use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
pub fn clear_node_dns_cache() {
    if let Some(resolver) = NODE_RESOLVER.get() {
        resolver.clear();
    }
}

static NODE_RESOLVER: OnceLock<crate::dial::Resolver> = OnceLock::new();

pub type NodeError = Box<dyn std::error::Error + Send + Sync>;

/// Resolve every ingress independently: a broken domain must not hide a literal backup.
pub async fn resolve_node(node: &NodeAddresses) -> Result<Vec<SocketAddr>, NodeError> {
    resolve_node_with(node, |target| async move {
        match target.address {
            Address::Ip(ip) => Ok(vec![ip]),
            Address::Domain(host) => Ok(NODE_RESOLVER
                .get_or_init(Default::default)
                .resolve(&host)
                .await?),
        }
    })
    .await
}

/// Hosts supply a bootstrap resolver that bypasses their VPN's DNS capture.
pub async fn resolve_node_with<F, Fut>(
    node: &NodeAddresses,
    lookup: F,
) -> Result<Vec<SocketAddr>, NodeError>
where
    F: Fn(Target) -> Fut,
    Fut: Future<Output = Result<Vec<IpAddr>, NodeError>>,
{
    let mut lookups = FuturesUnordered::new();
    for (index, target) in node.endpoints().iter().cloned().enumerate() {
        let lookup = &lookup;
        lookups.push(async move {
            let result = match &target.address {
                Address::Ip(ip) => Ok(vec![*ip]),
                Address::Domain(_) => {
                    match tokio::time::timeout(Duration::from_secs(3), lookup(target.clone())).await
                    {
                        Ok(result) => result,
                        Err(error) => Err(Box::new(error) as NodeError),
                    }
                }
            };
            (index, target.port, result)
        });
    }
    let mut resolved = Vec::new();
    let mut last = String::from("no node addresses");
    while let Some((index, port, result)) = lookups.next().await {
        match result {
            Ok(ips) => resolved.push((index, port, ips)),
            Err(error) => last = error.to_string(),
        }
    }
    resolved.sort_unstable_by_key(|(index, _, _)| *index);
    let mut addresses = Vec::new();
    for (_, port, ips) in resolved {
        for ip in ips {
            let address = SocketAddr::new(ip, port);
            if !addresses.contains(&address) {
                addresses.push(address);
            }
            if addresses.len() > 64 {
                return Err(
                    io::Error::other("node DNS returned more than 64 ingress addresses").into(),
                );
            }
        }
    }
    if addresses.is_empty() {
        return Err(io::Error::other(format!("node DNS failed: {last}")).into());
    }
    Ok(addresses)
}

/// Race the whole authenticated handshake; TCP acceptance alone is not proof of a usable node.
pub async fn race_node<T, F, Fut>(
    addresses: Vec<SocketAddr>,
    mut connect: F,
) -> Result<T, NodeError>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, NodeError>>,
{
    let first_v6 = addresses.first().is_some_and(SocketAddr::is_ipv6);
    let (first, other): (Vec<_>, Vec<_>) =
        addresses.into_iter().partition(|a| a.is_ipv6() == first_v6);
    let mut ordered = Vec::new();
    for i in 0..first.len().max(other.len()) {
        if let Some(a) = first.get(i) {
            ordered.push(*a);
        }
        if let Some(a) = other.get(i) {
            ordered.push(*a);
        }
    }
    let mut addresses = ordered.into_iter();
    let mut pending = FuturesUnordered::new();
    let mut next = tokio::time::Instant::now();
    let mut errors = Vec::new();
    let mut last_kind = io::ErrorKind::NotFound;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(next), if addresses.len() > 0 => {
                let address = addresses.next().unwrap();
                let attempt = connect(address);
                pending.push(async move {
                    let result = tokio::time::timeout(Duration::from_secs(5), attempt).await;
                    (address, result)
                });
                next = tokio::time::Instant::now() + Duration::from_millis(250);
            }
            Some((address, result)) = pending.next(), if !pending.is_empty() => {
                match result {
                    Ok(Ok(value)) => { tracing::debug!(event = "node_ingress_connected", %address); return Ok(value); }
                    Ok(Err(error)) => { last_kind = error.downcast_ref::<io::Error>().map_or(io::ErrorKind::Other, io::Error::kind); errors.push(format!("{address}: {error}")); },
                    Err(_) => { last_kind = io::ErrorKind::TimedOut; errors.push(format!("{address}: handshake timed out")); },
                }
                if pending.is_empty() { next = tokio::time::Instant::now(); }
            }
            else => return Err(io::Error::new(last_kind, format!("all node ingresses failed: {}", errors.join("; "))).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn a_stalled_or_unauthenticated_ingress_does_not_block_a_backup() {
        let addresses = vec![
            "[::1]:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
            "127.0.0.1:3".parse().unwrap(),
        ];
        let start = std::time::Instant::now();
        let chosen = race_node(addresses, |address| async move {
            match address.port() {
                1 => std::future::pending().await,
                2 => Err(io::Error::other("certificate mismatch").into()),
                _ => Ok(address),
            }
        })
        .await
        .unwrap();
        assert_eq!(chosen.port(), 3);
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[tokio::test]
    async fn bad_dns_does_not_discard_numeric_ingress() {
        let node: NodeAddresses = "unresolvable.invalid:443, [::1]:24443, 127.0.0.1:24443"
            .parse()
            .unwrap();
        let addresses = resolve_node_with(&node, |_| async {
            Err(io::Error::new(io::ErrorKind::NotFound, "test DNS failure").into())
        })
        .await
        .unwrap();
        assert!(addresses.contains(&"[::1]:24443".parse().unwrap()));
        assert!(addresses.contains(&"127.0.0.1:24443".parse().unwrap()));
    }
}
