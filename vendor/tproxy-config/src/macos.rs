#![cfg(target_os = "macos")]

use cidr::IpCidr;
use system_configuration::{
    core_foundation::{
        array::CFArray,
        base::TCFType,
        dictionary::CFDictionary,
        propertylist::{CFPropertyList, CFPropertyListSubClass},
        string::CFString,
    },
    dynamic_store::SCDynamicStoreBuilder,
};

use crate::macos_lease::Network;
use crate::{TproxyArgs, TproxyStateInner, run_command};
use std::{net::IpAddr, str::FromStr};

pub(crate) async fn _tproxy_setup(args: &TproxyArgs) -> std::io::Result<TproxyStateInner> {
    use crate::macos_lease::{self, Dns, Lease, Route};
    #[cfg(feature = "secure-state-file")]
    if crate::get_secure_state_file_path()?.try_exists()? {
        return Err(std::io::Error::other(
            "an earlier TUN recovery record exists; recover it before starting a new session",
        ));
    }
    let (gateway, interface, service, name) = get_default_iface_params()?;
    let name =
        name.ok_or_else(|| std::io::Error::other("cannot identify the uplink network service"))?;
    let (sources, _) = snapshot(args.ipv6_default_route, Some(&args.tun_name))?;
    if args.source_bypass.is_empty()
        || args
            .source_bypass
            .iter()
            .any(|source| !sources.contains(source))
    {
        return Err(std::io::Error::other(
            "TUN requires a daemon bound to the current physical uplink",
        ));
    }
    let ipv6 = default_gateway(true)?;
    let mut routes = Vec::new();
    let mut bypass = args.bypass_ips.clone();
    if bypass.is_empty() && !crate::is_private_ip(args.proxy_addr.ip()) {
        bypass.push(IpCidr::new_host(args.proxy_addr.ip()));
    }
    bypass.sort_by_key(ToString::to_string);
    bypass.dedup();
    for cidr in bypass {
        let (route_gateway, route_interface) = if cidr.first_address().is_ipv4() {
            (gateway.to_string(), interface.clone())
        } else {
            if !args.ipv6_default_route {
                continue;
            }
            let Some((gateway, interface)) = &ipv6 else {
                continue;
            };
            (gateway.clone(), interface.clone())
        };
        routes.push(Route {
            cidr,
            gateway: Some(route_gateway),
            interface: route_interface,
            tagged: true,
        });
    }
    for (enabled, prefixes) in [
        (args.ipv4_default_route, ["0.0.0.0/1", "128.0.0.0/1"]),
        (args.ipv6_default_route, ["::/1", "8000::/1"]),
    ] {
        if enabled {
            for prefix in prefixes {
                routes.push(Route {
                    cidr: prefix.parse().unwrap(),
                    gateway: None,
                    interface: args.tun_name.clone(),
                    tagged: true,
                });
            }
        }
    }
    let mut lease = Lease {
        boot: boot_identity()?,
        tun: args.tun_name.clone(),
        tun_index: interface_index(&args.tun_name)?,
        routes: Vec::new(),
        dns: None,
    };
    let dns = Dns {
        service: service.clone(),
        name: name.clone(),
        original: get_dns_servers(&service)?,
        applied: vec![args.tun_gateway],
    };
    let mut state = TproxyStateInner {
        tproxy_args: Some(args.clone()),
        ..Default::default()
    };
    let mut network = Native { state: &mut state };
    // Configuring only our newly created interface cannot remove the physical default route.
    run_command(
        "/sbin/ifconfig",
        &[
            &args.tun_name,
            &args.tun_ip.to_string(),
            &args.tun_gateway.to_string(),
            "netmask",
            &args.tun_netmask.to_string(),
        ],
    )?;
    if args.ipv6_default_route {
        run_command(
            "/sbin/ifconfig",
            &[&args.tun_name, "inet6", "fdfe:dcba:9875::1/126", "alias"],
        )?;
    }
    if lease.tun_index == 0 {
        return Err(std::io::Error::other("TUN interface does not exist"));
    }
    macos_lease::apply(&mut lease, &routes, dns, &mut network)?;
    if let Err(error) = flush_dns_cache() {
        log::warn!("DNS cache flush failed: {error}");
    }
    Ok(state)
}

pub(crate) async fn _tproxy_remove(state: &mut TproxyStateInner) -> std::io::Result<()> {
    if state.tproxy_removed_done {
        return Ok(());
    }
    if let Some(mut lease) = state.macos_lease.clone() {
        // Kernel routes cannot survive a reboot; never remove another session's matching routes.
        if lease.boot != boot_identity()? {
            lease.routes.clear();
            lease.boot = boot_identity()?;
            lease.tun_index = interface_index(&lease.tun)?;
            Native { state }.save(&lease)?;
        }
        crate::macos_lease::recover(&mut lease, &mut Native { state })?;
        if let Err(error) = flush_dns_cache() {
            log::warn!("DNS cache flush after recovery failed: {error}");
        }
    } else {
        recover_legacy(state)?;
    }
    state.tproxy_removed_done = true;
    Ok(())
}

struct Native<'a> {
    state: &'a mut TproxyStateInner,
}
impl crate::macos_lease::Network for Native<'_> {
    fn validate(&mut self, lease: &crate::macos_lease::Lease) -> std::io::Result<()> {
        if lease.boot != boot_identity()? {
            return Err(std::io::Error::other(
                "TUN recovery belongs to a previous boot; record preserved",
            ));
        }
        Ok(())
    }
    fn route(
        &mut self,
        route: &crate::macos_lease::Route,
    ) -> std::io::Result<Option<crate::macos_lease::Route>> {
        if let Some(lease) = &self.state.macos_lease
            && route.interface == lease.tun
        {
            let index = interface_index(&lease.tun)?;
            if index != 0 && index != lease.tun_index {
                return Err(std::io::Error::other(
                    "TUN interface was reused; route record preserved",
                ));
            }
        }
        lookup_route(
            &route.cidr.to_string(),
            route.cidr.first_address().is_ipv6(),
        )
        .map(|found| found.filter(|found| found.cidr == route.cidr))
    }
    fn add(&mut self, route: &crate::macos_lease::Route) -> std::io::Result<()> {
        let (kind, destination) = crate::macos_lease::route_destination(route.cidr);
        let family = if route.cidr.first_address().is_ipv4() {
            "-inet"
        } else {
            "-inet6"
        };
        let mut args = vec!["-n", "add", family, "-proto2", kind, &destination];
        if let Some(gateway) = &route.gateway {
            args.push(gateway);
        } else {
            args.extend(["-interface", &route.interface]);
        }
        run_command("/sbin/route", &args).map(|_| ())
    }
    fn delete(&mut self, route: &crate::macos_lease::Route) -> std::io::Result<()> {
        let (kind, destination) = crate::macos_lease::route_destination(route.cidr);
        let family = if route.cidr.first_address().is_ipv4() {
            "-inet"
        } else {
            "-inet6"
        };
        run_command("/sbin/route", &["-n", "delete", family, kind, &destination]).map(|_| ())
    }
    fn dns(&mut self, service: &str) -> std::io::Result<Option<Vec<IpAddr>>> {
        get_dns_servers(service)
    }
    fn set_dns(&mut self, dns: &crate::macos_lease::Dns, restore: bool) -> std::io::Result<()> {
        if restore {
            match &dns.original {
                Some(servers) if !servers.is_empty() => {
                    configure_dns_servers(&dns.name, &dns.service, servers)
                }
                _ => remove_dns_servers(&dns.service, &dns.name),
            }
        } else {
            configure_dns_servers(&dns.name, &dns.service, &dns.applied)
        }
    }
    fn save(&mut self, lease: &crate::macos_lease::Lease) -> std::io::Result<()> {
        self.state.macos_lease = Some(lease.clone());
        #[cfg(feature = "secure-state-file")]
        {
            crate::store_secure_state(self.state)
        }
        #[cfg(not(feature = "secure-state-file"))]
        {
            Err(std::io::Error::other(
                "macOS TUN requires secure-state-file recovery",
            ))
        }
    }
    fn clear(&mut self) -> std::io::Result<()> {
        #[cfg(feature = "secure-state-file")]
        {
            let path = crate::get_secure_state_file_path()?;
            match std::fs::remove_file(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                result => result?,
            }
            std::fs::File::open(path.parent().unwrap())?.sync_all()?;
        }
        Ok(())
    }
}

fn interface_index(name: &str) -> std::io::Result<u32> {
    let name = std::ffi::CString::new(name).map_err(std::io::Error::other)?;
    Ok(unsafe { libc::if_nametoindex(name.as_ptr()) })
}
fn boot_identity() -> std::io::Result<String> {
    Ok(
        String::from_utf8_lossy(&run_command("/usr/sbin/sysctl", &["-n", "kern.boottime"])?)
            .trim()
            .to_owned(),
    )
}

fn lookup_route(
    destination: &str,
    ipv6: bool,
) -> std::io::Result<Option<crate::macos_lease::Route>> {
    let family = if ipv6 { "-inet6" } else { "-inet" };
    let cidr = if destination == "default" {
        if ipv6 { "::/0" } else { "0.0.0.0/0" }
    } else {
        destination
    }
    .parse()
    .map_err(std::io::Error::other)?;
    let (kind, destination) = crate::macos_lease::route_destination(cidr);
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "get", family, kind, &destination])
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("not in table") {
        return Ok(None);
    }
    if !output.status.success() || !stderr.trim().is_empty() {
        return Err(std::io::Error::other(format!(
            "route lookup failed: {stderr}"
        )));
    }
    crate::macos_lease::parse_route(&String::from_utf8_lossy(&output.stdout), ipv6)
}

fn default_gateway(ipv6: bool) -> std::io::Result<Option<(String, String)>> {
    let store = SCDynamicStoreBuilder::new("Helios uplink")
        .build()
        .ok_or_else(|| std::io::Error::other("cannot open network settings"))?;
    let key = if ipv6 {
        "State:/Network/Global/IPv6"
    } else {
        "State:/Network/Global/IPv4"
    };
    let Some(dict) = store
        .get(key)
        .and_then(|value| value.downcast::<CFDictionary>())
    else {
        return Ok(None);
    };
    let Some(gateway) = get_cf_dict_entry::<CFString>(&dict, "Router".into()) else {
        return Ok(None);
    };
    let Some(interface) = get_cf_dict_entry::<CFString>(&dict, "PrimaryInterface".into()) else {
        return Ok(None);
    };
    let mut gateway = gateway.to_string();
    let interface = interface.to_string();
    if ipv6 && gateway.starts_with("fe80:") && !gateway.contains('%') {
        gateway = format!("{gateway}%{interface}");
    }
    Ok(Some((gateway, interface)))
}

fn check_physical_default(ipv6: bool, interface: &str, gateway: &str) -> std::io::Result<()> {
    let family = if ipv6 { "-inet6" } else { "-inet" };
    let output = run_command(
        "/sbin/route",
        &["-n", "get", family, "-ifscope", interface, "default"],
    )?;
    crate::macos_lease::physical_default(
        &String::from_utf8_lossy(&output),
        ipv6,
        interface,
        gateway,
    )
}

/// Capture real uplink addresses and resolver IPs before installing TUN routes or DNS.
pub fn uplink_snapshot(ipv6: bool) -> std::io::Result<(Vec<IpAddr>, Vec<IpAddr>)> {
    snapshot(ipv6, None)
}

fn snapshot(ipv6: bool, own: Option<&str>) -> std::io::Result<(Vec<IpAddr>, Vec<IpAddr>)> {
    for family in ["inet", "inet6"] {
        let table = run_command("/usr/sbin/netstat", &["-rn", "-f", family])?;
        if let Some(route) =
            crate::macos_lease::foreign_tunnel_route(&String::from_utf8_lossy(&table), own)
        {
            return Err(std::io::Error::other(format!(
                "another VPN owns route {route}; disable it before enabling Helios TUN"
            )));
        }
    }
    let (_, interface, service, _) = get_default_iface_params()?;
    let store = SCDynamicStoreBuilder::new("Helios uplink snapshot")
        .build()
        .ok_or_else(|| std::io::Error::other("cannot open network settings"))?;
    let mut sources = Vec::new();
    for family in [false, true] {
        if family && !ipv6 {
            continue;
        }
        let Some((gateway, iface)) = default_gateway(family)? else {
            continue;
        };
        if iface.starts_with("utun") || iface == "lo0" {
            return Err(std::io::Error::other(
                "another VPN owns the uplink; disable it before enabling Helios TUN",
            ));
        }
        check_physical_default(family, &iface, &gateway)?;
        let key = format!(
            "State:/Network/Interface/{iface}/{}",
            if family { "IPv6" } else { "IPv4" }
        );
        let addresses = read_addresses(&store, &key, "Addresses")?;
        if let Some(ip) = addresses.into_iter().find(|ip| {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !matches!(ip,IpAddr::V6(ip) if ip.is_unicast_link_local())
        }) {
            sources.push(ip);
        }
    }
    if sources.is_empty() {
        return Err(std::io::Error::other(format!(
            "no physical uplink address on {interface}"
        )));
    }
    let mut dns = read_addresses(
        &store,
        &format!("State:/Network/Service/{service}/DNS"),
        "ServerAddresses",
    )?;
    dns.retain(|ip| {
        !ip.is_loopback()
            && !ip.is_unspecified()
            && sources
                .iter()
                .any(|source| source.is_ipv4() == ip.is_ipv4())
    });
    dns.dedup();
    dns.truncate(4);
    if dns.is_empty() {
        return Err(std::io::Error::other(
            "no real upstream DNS servers on physical uplink",
        ));
    }
    Ok((sources, dns))
}

fn read_addresses(
    store: &system_configuration::dynamic_store::SCDynamicStore,
    key: &str,
    field: &str,
) -> std::io::Result<Vec<IpAddr>> {
    let Some(dict) = store
        .get(key)
        .and_then(|value| value.downcast::<CFDictionary>())
    else {
        return Ok(Vec::new());
    };
    let Some(array) = get_cf_dict_entry::<CFArray>(&dict, field.into()) else {
        return Ok(Vec::new());
    };
    let mut addresses = Vec::new();
    for item in array.iter() {
        if item.is_null() {
            continue;
        }
        let value = unsafe { CFPropertyList::wrap_under_get_rule(*item) };
        if let Some(value) = value.downcast::<CFString>() {
            addresses.push(value.to_string().parse().map_err(std::io::Error::other)?);
        }
    }
    Ok(addresses)
}

// Old releases replaced the default route. Restore only their recognizable changes.
fn recover_legacy(state: &mut TproxyStateInner) -> std::io::Result<()> {
    let args = state
        .tproxy_args
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing legacy TUN arguments"))?;
    let gateway = state
        .gateway
        .ok_or_else(|| std::io::Error::other("missing original gateway"))?
        .to_string();
    let interface = state
        .gw_scope
        .as_ref()
        .ok_or_else(|| std::io::Error::other("missing original interface"))?;
    let mut errors = Vec::new();
    let restore = || -> std::io::Result<()> {
        match lookup_route("default", false)? {
            Some(route)
                if route.gateway.as_ref() == Some(&gateway) && &route.interface == interface =>
            {
                Ok(())
            }
            None => {
                run_command("/sbin/route", &["-n", "add", "-inet", "default", &gateway]).map(|_| ())
            }
            Some(route)
                if route.interface == args.tun_name
                    && route.gateway.as_ref() == Some(&args.tun_gateway.to_string()) =>
            {
                run_command(
                    "/sbin/route",
                    &["-n", "change", "-inet", "default", &gateway],
                )
                .map(|_| ())
            }
            _ => Err(std::io::Error::other(
                "default route changed externally; legacy recovery refused",
            )),
        }
    };
    if let Err(error) = restore() {
        errors.push(error.to_string());
    }
    match lookup_route("default", false) {
        Ok(Some(route))
            if route.gateway.as_ref() == Some(&gateway) && &route.interface == interface => {}
        _ => errors.push("original unscoped default route was not restored".into()),
    }
    if let Some(service) = &state.default_service_id {
        let name = state.orig_iface_name.as_deref().unwrap_or("");
        let current = get_dns_servers(service);
        let applied = Some(vec![args.tun_gateway]);
        let result = match current {
            Ok(current) if current == state.default_service_dns => Ok(()),
            Ok(current) if current == applied => match &state.default_service_dns {
                Some(servers) => configure_dns_servers(name, service, servers),
                None => remove_dns_servers(service, name),
            },
            Ok(_) => Err(std::io::Error::other(
                "DNS changed externally; legacy recovery refused",
            )),
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            errors.push(error.to_string());
        }
        match get_dns_servers(service) {
            Ok(current) if current == state.default_service_dns => {}
            Ok(_) => errors.push("original DNS was not restored".into()),
            Err(error) => errors.push(error.to_string()),
        }
    }
    let mut bypass = args.bypass_ips.clone();
    bypass.sort_by_key(ToString::to_string);
    bypass.dedup();
    for cidr in bypass {
        if cidr.first_address().is_ipv6() {
            continue;
        }
        let expected = crate::macos_lease::Route {
            cidr,
            gateway: Some(gateway.clone()),
            interface: interface.clone(),
            tagged: false,
        };
        let result = (|| {
            let current =
                lookup_route(&cidr.to_string(), false)?.filter(|route| route.cidr == cidr);
            match current {
                None => Ok(()),
                Some(route) if expected.matches(&route) => Native {
                    state: &mut TproxyStateInner::default(),
                }
                .delete(&expected),
                _ => Err(std::io::Error::other(
                    "legacy bypass route changed externally",
                )),
            }
        })();
        if let Err(error) = result {
            errors.push(error.to_string());
        }
    }
    if !errors.is_empty() {
        return Err(std::io::Error::other(errors.join("; ")));
    }
    Native { state }.clear()?;
    flush_dns_cache()
}

fn get_cf_dict_entry<T>(dict: &CFDictionary, key: CFString) -> Option<T>
where
    T: CFPropertyListSubClass,
{
    let result = dict.find(key.as_CFTypeRef())?;
    if result.is_null() {
        return None;
    }
    let property_list = unsafe { CFPropertyList::wrap_under_get_rule(*result) };
    property_list.downcast::<T>()
}

/// The path strings can be found in command `scutil` with subcommand `list`.
///
/// Get the gatway IP, name, service ID, friendly name of the default interface.
pub(crate) fn get_default_iface_params() -> std::io::Result<(IpAddr, String, String, Option<String>)>
{
    let store = SCDynamicStoreBuilder::new("tproxy-config get iface params")
        .build()
        .ok_or(std::io::Error::other("Create SC DynamicStore failed"))?;
    let Some(property_list) = store.get("State:/Network/Global/IPv4") else {
        return Err(std::io::Error::other("Failed to get network state"));
    };
    let Some(dict) = property_list.downcast::<CFDictionary>() else {
        return Err(std::io::Error::other("Dictionary conversion failed"));
    };
    let Some(gateway) = get_cf_dict_entry::<CFString>(&dict, "Router".into()) else {
        return Err(std::io::Error::other("Failed to get default gateway"));
    };
    let Some(interface) = get_cf_dict_entry::<CFString>(&dict, "PrimaryInterface".into()) else {
        return Err(std::io::Error::other("Failed to get default interface"));
    };
    let Some(service_id) = get_cf_dict_entry::<CFString>(&dict, "PrimaryService".into()) else {
        return Err(std::io::Error::other("Failed to get default service"));
    };

    use std::io::{Error, ErrorKind::InvalidData};
    let gateway_ip = IpAddr::from_str(gateway.to_string().as_str())
        .map_err(|err| Error::new(InvalidData, err))?;

    let svc_path = format!("Setup:/Network/Service/{service_id}");
    let iface_name = store
        .get(svc_path.as_str())
        .and_then(|value| value.downcast::<CFDictionary>())
        .and_then(|dict| get_cf_dict_entry::<CFString>(&dict, "UserDefinedName".into()))
        .map(|name| name.to_string());

    Ok((
        gateway_ip,
        interface.to_string(),
        service_id.to_string(),
        iface_name,
    ))
}

fn configure_dns_servers(
    iface_friendly_name: &str,
    _service_id: &str,
    dns_servers: &[IpAddr],
) -> std::io::Result<()> {
    if iface_friendly_name.is_empty() || dns_servers.is_empty() {
        return Err(std::io::Error::other(
            "missing DNS service name or addresses",
        ));
    }
    let addrs = dns_servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let mut args = vec!["-setdnsservers", iface_friendly_name];
    args.extend(addrs.iter().map(String::as_str));
    run_command("/usr/sbin/networksetup", &args)?;
    Ok(())
}

/// Get the DNS servers from the specified service.
/// If the DNS servers are obtained through DHCP, this function will return None.
/// Overridden DNS servers are returned as a vector.
fn get_dns_servers(service_id: &str) -> std::io::Result<Option<Vec<IpAddr>>> {
    let store = SCDynamicStoreBuilder::new("tproxy-config get dns")
        .build()
        .ok_or(std::io::Error::other("Create SC DynamicStore failed"))?;
    let key: CFString = format!("Setup:/Network/Service/{service_id}/DNS")
        .as_str()
        .into();

    let Some(result) = store.get(key) else {
        return Ok(None);
    };

    let Some(cf_dict) = result.downcast::<CFDictionary>() else {
        return Err(std::io::Error::other(
            "Network service DNS server conversion failed",
        ));
    };

    let Some(server_addresses) = cf_dict.find(CFString::from("ServerAddresses").as_CFTypeRef())
    else {
        return Ok(None);
    };

    if server_addresses.is_null() {
        return Err(std::io::Error::other("Server addresses are null"));
    }

    let server_addr_prop = unsafe { CFPropertyList::wrap_under_get_rule(*server_addresses) };
    let Some(cf_array) = server_addr_prop.downcast::<CFArray>() else {
        return Err(std::io::Error::other("Server address conversion failed"));
    };

    let mut vec: Vec<IpAddr> = Vec::new();
    for item in cf_array.iter() {
        if item.is_null() {
            continue;
        }

        let property_list = unsafe { CFPropertyList::wrap_under_get_rule(*item) };
        let Some(addr_str) = property_list.downcast::<CFString>() else {
            continue;
        };
        use std::io::{Error, ErrorKind::InvalidData};
        let ip = IpAddr::from_str(addr_str.to_string().as_str())
            .map_err(|err| Error::new(InvalidData, err))?;

        vec.push(ip);
    }
    Ok(Some(vec))
}

fn remove_dns_servers(_service_id: &str, friendly_name: &str) -> std::io::Result<()> {
    if friendly_name.is_empty() {
        return Err(std::io::Error::other("missing DNS service name"));
    }
    run_command(
        "/usr/sbin/networksetup",
        &["-setdnsservers", friendly_name, "Empty"],
    )?;
    Ok(())
}

pub(crate) fn flush_dns_cache() -> std::io::Result<()> {
    run_command("/usr/bin/dscacheutil", &["-flushcache"])?;
    run_command("/usr/bin/killall", &["-HUP", "mDNSResponder"])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_native_route_and_dns_queries_are_read_only() {
        for (host, ipv6) in [("127.0.0.1/32", false), ("::1/128", true)] {
            let route = lookup_route(host, ipv6).unwrap().unwrap();
            assert_eq!(route.interface, "lo0");
            assert_eq!(route.cidr, host.parse().unwrap());
        }
        let (gateway, interface, service, name) = get_default_iface_params().unwrap();
        check_physical_default(false, &interface, &gateway.to_string()).unwrap();
        assert!(name.is_some());
        get_dns_servers(&service).unwrap();
        assert!(!boot_identity().unwrap().is_empty());
    }

    #[test]
    fn macos_native_uplink_preflight_is_read_only() {
        let (sources, dns) = uplink_snapshot(false).unwrap();
        assert!(!sources.is_empty() && sources.iter().all(IpAddr::is_ipv4));
        assert!(!dns.is_empty());
    }
}
