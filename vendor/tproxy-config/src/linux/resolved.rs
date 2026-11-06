//! A journaled per-link lease on a newly created TUN. Never change physical-link DNS.
use super::{recovery::checkpoint, *};
use serde::{Deserialize, Serialize};
use zbus::{Connection, Proxy, proxy::CacheProperties, zvariant::OwnedObjectPath};

const SERVICE: &str = "org.freedesktop.resolve1";
const MANAGER: &str = "/org/freedesktop/resolve1";

type Dns = Vec<(i32, Vec<u8>, u16, String)>;
type Domains = Vec<(String, bool)>;
type GlobalDns = Vec<(i32, i32, Vec<u8>, u16, String)>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    dns: Dns,
    domains: Domains,
    default_route: bool,
    dnssec: String,
    tls: String,
    llmnr: String,
    mdns: String,
    trust_anchors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Lease {
    bus: String,
    owner: String,
    original: Snapshot,
    applied: Snapshot,
    pending: Option<Snapshot>,
    #[serde(default)]
    upstreams: Option<GlobalDns>,
}

struct Resolved {
    connection: Connection,
    bus: String,
    owner: String,
}

fn refused(message: &str) -> Box<dyn std::error::Error + Send + Sync> {
    std::io::Error::other(message).into()
}

impl Resolved {
    async fn connect() -> Result<Self> {
        // Privileged code must not follow DBUS_SYSTEM_BUS_ADDRESS from a caller's environment.
        let connection = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")?
                .method_timeout(std::time::Duration::from_secs(3))
                .build(),
        )
        .await??;
        let dbus = zbus::fdo::DBusProxy::new(&connection).await?;
        let bus = dbus.get_id().await?.to_string();
        let owner = dbus.get_name_owner(SERVICE.try_into()?).await?.to_string();
        Ok(Self {
            connection,
            bus,
            owner,
        })
    }

    async fn manager(&self) -> Result<Proxy<'_>> {
        self.proxy(MANAGER, "org.freedesktop.resolve1.Manager")
            .await
    }

    async fn proxy<'a>(&'a self, path: &'a str, interface: &'a str) -> Result<Proxy<'a>> {
        Ok(zbus::proxy::Builder::new(&self.connection)
            .destination(self.owner.as_str())?
            .path(path)?
            .interface(interface)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?)
    }

    async fn link(&self, index: u32) -> Result<Proxy<'static>> {
        let path: OwnedObjectPath = self
            .manager()
            .await?
            .call("GetLink", &(index as i32))
            .await?;
        Ok(zbus::proxy::Builder::new(&self.connection)
            .destination(self.owner.clone())?
            .path(path)?
            .interface("org.freedesktop.resolve1.Link")?
            .cache_properties(CacheProperties::No)
            .build()
            .await?)
    }

    async fn preflight(&self, tun: Option<u32>) -> Result<()> {
        let uid = zbus::fdo::DBusProxy::new(&self.connection)
            .await?
            .get_connection_unix_user(self.owner.as_str().try_into()?)
            .await?;
        let metadata = fs::metadata(crate::ETC_RESOLV_CONF_FILE)?;
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 && metadata.uid() != uid {
            return Err(refused(
                "systemd-resolved stub is not owned by root or the resolver service",
            ));
        }
        let manager = self.manager().await?;
        if manager.get_property::<String>("ResolvConfMode").await? != "stub"
            || manager.get_property::<String>("DNSStubListener").await? == "no"
        {
            return Err(refused(
                "systemd-resolved must use its active standard stub resolver",
            ));
        }
        // ponytail: refuse split DNS instead of modifying another manager's domains; a future
        // explicit split-DNS policy can opt into forwarding more-specific domains unchanged.
        let domains: Vec<(i32, String, bool)> = manager.get_property("Domains").await?;
        if domains
            .iter()
            .any(|(index, _, _)| Some(*index as u32) != tun)
        {
            return Err(refused(
                "systemd-resolved has competing search/routing domains; split DNS is unsupported",
            ));
        }
        Ok(())
    }
}

async fn snapshot(link: &Proxy<'_>) -> Result<Snapshot> {
    Ok(Snapshot {
        dns: link.get_property("DNSEx").await?,
        domains: link.get_property("Domains").await?,
        default_route: link.get_property("DefaultRoute").await?,
        dnssec: link.get_property("DNSSEC").await?,
        tls: link.get_property("DNSOverTLS").await?,
        llmnr: link.get_property("LLMNR").await?,
        mdns: link.get_property("MulticastDNS").await?,
        trust_anchors: link.get_property("DNSSECNegativeTrustAnchors").await?,
    })
}

pub(super) async fn preflight() -> Result<()> {
    Resolved::connect().await?.preflight(None).await
}

pub(super) async fn prepare(index: u32) -> Result<Lease> {
    let resolved = Resolved::connect().await?;
    resolved.preflight(Some(index)).await?;
    let original = snapshot(&resolved.link(index).await?).await?;
    if !original.dns.is_empty()
        || !original.domains.is_empty()
        || !original.trust_anchors.is_empty()
    {
        return Err(refused(
            "new TUN already has DNS settings owned by another service",
        ));
    }
    let mut upstreams: GlobalDns = resolved.manager().await?.get_property("DNSEx").await?;
    upstreams.retain(|(link, ..)| *link != index as i32);
    upstreams.sort();
    Ok(Lease {
        bus: resolved.bus,
        owner: resolved.owner,
        applied: original.clone(),
        original,
        pending: None,
        upstreams: Some(upstreams),
    })
}

pub(super) async fn apply(state: &mut TproxyStateInner) -> Result<()> {
    let resolved = Resolved::connect().await?;
    let lease = state.linux_resolved.as_ref().unwrap();
    if lease.bus != resolved.bus || lease.owner != resolved.owner {
        return Err(refused("systemd-resolved restarted during TUN setup"));
    }
    let index = state.linux_context.as_ref().unwrap().tun_index;
    resolved.preflight(Some(index)).await?;
    let link = resolved.link(index).await?;
    let args = state.tproxy_args.as_ref().unwrap();
    let dns = match args.tun_dns {
        IpAddr::V4(ip) => vec![(2, ip.octets().to_vec(), 0, String::new())],
        IpAddr::V6(ip) => vec![(10, ip.octets().to_vec(), 0, String::new())],
    };
    for step in 0..5 {
        let lease = state.linux_resolved.as_ref().unwrap();
        if snapshot(&link).await? != lease.applied {
            return Err(refused(
                "TUN DNS settings changed externally during setup; recovery preserved",
            ));
        }
        let mut next = lease.applied.clone();
        match step {
            0 => next.dnssec = "no".into(),
            1 => next.tls = "no".into(),
            2 => next.default_route = true,
            3 => next.dns = dns.clone(),
            _ => next.domains = vec![(".".into(), true)],
        }
        state.linux_resolved.as_mut().unwrap().pending = Some(next.clone());
        checkpoint(state)?;
        // A crash or failed reply can leave either snapshot applied; both are journaled first.
        match step {
            0 => link.call::<_, _, ()>("SetDNSSEC", &"no").await?,
            1 => link.call::<_, _, ()>("SetDNSOverTLS", &"no").await?,
            2 => link.call::<_, _, ()>("SetDefaultRoute", &true).await?,
            3 => link.call::<_, _, ()>("SetDNSEx", &(&dns,)).await?,
            _ => {
                link.call::<_, _, ()>("SetDomains", &(&next.domains,))
                    .await?
            }
        }
        let current = snapshot(&link).await?;
        if current != next {
            return Err(refused(
                "systemd-resolved did not retain the requested TUN DNS settings",
            ));
        }
        let lease = state.linux_resolved.as_mut().unwrap();
        lease.applied = next;
        lease.pending = None;
        checkpoint(state)?;
    }
    // Clear real-IP entries so new flows use the shared Fake-IP cache immediately.
    resolved
        .manager()
        .await?
        .call::<_, _, ()>("FlushCaches", &())
        .await?;
    Ok(())
}

pub(super) async fn remove(state: &mut TproxyStateInner) -> Result<()> {
    let Some(lease) = state.linux_resolved.as_ref() else {
        return Ok(());
    };
    let resolved = Resolved::connect().await?;
    let args = state.tproxy_args.as_ref().unwrap();
    let index = state.linux_context.as_ref().unwrap().tun_index;
    // When the kernel destroys a nonpersistent TUN (including SIGKILL), resolved removes its
    // per-link settings too. Never address a disappeared/reused ifindex by D-Bus path alone.
    match ip_link_get_index(&args.tun_name).await {
        Ok(current) if current == index => {
            if lease.bus != resolved.bus || lease.owner != resolved.owner {
                return Err(refused(
                    "systemd-resolved restarted; live TUN DNS recovery preserved",
                ));
            }
            let link = resolved.link(index).await?;
            let current = snapshot(&link).await?;
            if current != lease.original {
                if current != lease.applied && lease.pending.as_ref() != Some(&current) {
                    return Err(refused(
                        "TUN DNS settings were changed externally; recovery preserved",
                    ));
                }
                link.call::<_, _, ()>("Revert", &()).await?;
                if snapshot(&link).await? != lease.original {
                    return Err(refused(
                        "systemd-resolved did not restore the original TUN DNS settings",
                    ));
                }
            }
        }
        Ok(_) => return Err(refused("TUN ifindex was reused; DNS recovery refused")),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
        Err(error) => return Err(error),
    }
    // Do this even after SIGKILL: stale Fake-IP answers must not survive the lease.
    resolved
        .manager()
        .await?
        .call::<_, _, ()>("FlushCaches", &())
        .await?;
    state.linux_resolved = None;
    checkpoint(state)?;
    Ok(())
}

pub(super) async fn upstreams() -> Result<Vec<IpAddr>> {
    let resolved = Resolved::connect().await?;
    let dns: Vec<(i32, i32, Vec<u8>)> = resolved.manager().await?.get_property("DNS").await?;
    Ok(dns
        .into_iter()
        .filter_map(|(_, family, bytes)| match family {
            2 => <[u8; 4]>::try_from(bytes)
                .ok()
                .map(|ip| IpAddr::V4(ip.into())),
            10 => <[u8; 16]>::try_from(bytes)
                .ok()
                .map(|ip| IpAddr::V6(ip.into())),
            _ => None,
        })
        .collect())
}

pub(super) async fn check_active(state: &TproxyStateInner) -> Result<()> {
    let Some(lease) = &state.linux_resolved else {
        return Ok(());
    };
    if !super::resolver::uses_resolved()? {
        return Err(refused("resolver backend changed"));
    }
    let resolved = Resolved::connect().await?;
    if resolved.bus != lease.bus || resolved.owner != lease.owner {
        return Err(refused("systemd-resolved restarted during TUN session"));
    }
    let index = state.linux_context.as_ref().unwrap().tun_index;
    resolved.preflight(Some(index)).await?;
    if let Some(expected) = &lease.upstreams {
        let mut current: GlobalDns = resolved.manager().await?.get_property("DNSEx").await?;
        current.retain(|(link, ..)| *link != index as i32);
        current.sort();
        if &current != expected {
            return Err(refused("physical or global DNS upstreams changed"));
        }
    }
    if snapshot(&resolved.link(index).await?).await? != lease.applied {
        return Err(refused("TUN DNS lease changed externally"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires real resolved and a private D-Bus in a disposable container; never run on host"]
    fn isolated_resolved_lease_preserves_conflicts_and_recovers_unacknowledged_calls() {
        assert_eq!(std::env::var("HELIOS_TEST_RESOLVED").as_deref(), Ok("1"));
        assert_eq!(
            fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim(),
            "helios-tun-client"
        );
        assert!(Path::new("/.dockerenv").exists());
        let path = "/tmp/helios-resolved-unit/lease.json";
        crate::set_state_file_path(path.into()).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                crate::run_command("ip", &["link", "add", "resolvedtest", "type", "dummy"])
                    .unwrap();
                crate::run_command(
                    "ip",
                    &["addr", "add", "10.0.0.33/24", "dev", "resolvedtest"],
                )
                .unwrap();
                let args = TproxyArgs::new()
                    .tun_name("resolvedtest")
                    .source_bypass(&["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()])
                    .tun_dns("198.18.0.0".parse().unwrap());
                let mut state = super::super::recovery::setup(&args).await.unwrap();
                let resolved = Resolved::connect().await.unwrap();
                let link = resolved
                    .link(state.linux_context.as_ref().unwrap().tun_index)
                    .await
                    .unwrap();
                let expected = state.linux_resolved.as_ref().unwrap().applied.clone();
                assert_eq!(snapshot(&link).await.unwrap(), expected);

                // Any other live service/bus identity must be preserved, even with identical DNS.
                let original_owner = state.linux_resolved.as_ref().unwrap().owner.clone();
                state.linux_resolved.as_mut().unwrap().owner = ":1.999999".into();
                assert!(
                    remove(&mut state)
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains("restarted")
                );
                assert_eq!(snapshot(&link).await.unwrap(), expected);
                state.linux_resolved.as_mut().unwrap().owner = original_owner;

                // Do not erase another manager's modifications, or consume its retryable lease.
                link.call::<_, _, ()>("SetDomains", &(vec![("foreign.test", true)],))
                    .await
                    .unwrap();
                let foreign = snapshot(&link).await.unwrap();
                assert!(
                    remove(&mut state)
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains("externally")
                );
                assert_eq!(snapshot(&link).await.unwrap(), foreign);
                assert!(Path::new(path).exists());
                link.call::<_, _, ()>("SetDomains", &(&expected.domains,))
                    .await
                    .unwrap();

                // Emulate a crash after the last D-Bus mutation succeeded but before its reply
                // could be committed. Deserialize the actual on-disk journal for recovery.
                let lease = state.linux_resolved.as_mut().unwrap();
                lease.applied.domains.clear();
                lease.pending = Some(expected);
                checkpoint(&state).unwrap();
                let mut recovered = crate::retrieve_secure_state().unwrap();
                remove(&mut recovered).await.unwrap();
                assert_eq!(
                    snapshot(&link).await.unwrap(),
                    state.linux_resolved.as_ref().unwrap().original
                );

                // A crash after Revert but before checkpoint is also safe to retry.
                super::super::recovery::remove(&mut state).await.unwrap();
                assert!(!Path::new(path).exists());
                assert!(ip_link_get_index("resolvedtest").await.is_err());
                // Reboot resets kernel state. Restore only an identical static DNS file,
                // and never address an old name/ifindex that now belongs to a physical link.
                let original = fs::read(ETC_RESOLV_CONF_FILE).unwrap();
                let desired = b"nameserver 198.18.0.0\n".to_vec();
                let mut encoded = serde_json::to_value(&state).unwrap();
                encoded["linux_context"]["boot"] = "00000000-0000-0000-0000-000000000001\n".into();
                encoded["tproxy_args"]["tun_name"] = "uplink".into();
                let mut previous: TproxyStateInner = serde_json::from_value(encoded).unwrap();
                previous.restore_resolvconf_content = Some(original.clone());
                previous.applied_resolvconf_content = Some(desired.clone());
                checkpoint(&previous).unwrap();
                fs::write(ETC_RESOLV_CONF_FILE, b"nameserver 192.0.2.253\n").unwrap();
                assert!(
                    super::super::recovery::remove(&mut previous)
                        .await
                        .unwrap_err()
                        .to_string()
                        .contains("externally")
                );
                assert!(Path::new(path).exists());
                assert_eq!(
                    fs::read(ETC_RESOLV_CONF_FILE).unwrap(),
                    b"nameserver 192.0.2.253\n"
                );
                fs::write(ETC_RESOLV_CONF_FILE, desired).unwrap();
                super::super::recovery::remove(&mut previous).await.unwrap();
                assert_eq!(fs::read(ETC_RESOLV_CONF_FILE).unwrap(), original);
                assert!(ip_link_get_index("uplink").await.is_ok());
                assert!(!Path::new(path).exists());
            });
    }
}
