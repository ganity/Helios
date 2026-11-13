//! macOS route/DNS transactions, shared with fault-injection tests on other hosts.
use std::{io, net::IpAddr};

pub(crate) fn route_destination(cidr: cidr::IpCidr) -> (&'static str, String) {
    // Darwin needs RTF_HOST for /32 and /128; IpCidr displays these without a prefix.
    if cidr.is_host_address() {
        ("-host", cidr.first_address().to_string())
    } else {
        ("-net", cidr.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Route {
    pub cidr: cidr::IpCidr,
    pub gateway: Option<String>,
    pub interface: String,
    pub tagged: bool,
}

impl Route {
    pub fn matches(&self, current: &Self) -> bool {
        self.tagged == current.tagged && self.same_path(current)
    }
    fn same_path(&self, current: &Self) -> bool {
        self.cidr == current.cidr
            && self.interface == current.interface
            && self
                .gateway
                .as_ref()
                .is_none_or(|gateway| current.gateway.as_ref() == Some(gateway))
    }
}

pub(crate) fn foreign_tunnel_route(table: &str, own: Option<&str>) -> Option<String> {
    table.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4 {
            return None;
        }
        let (destination, flags, interface) = (fields[0], fields[2], fields[3]);
        (interface.starts_with("utun")
            && own != Some(interface)
            && flags.contains('U')
            && !flags.contains('I')
            && !destination.starts_with("fe80:")
            && !destination.starts_with("ff0")
            && !destination.starts_with("169.254"))
        .then(|| format!("{destination} on {interface}"))
    })
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Dns {
    pub service: String,
    pub name: String,
    pub original: Option<Vec<IpAddr>>,
    pub applied: Vec<IpAddr>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Lease {
    pub boot: String,
    pub tun: String,
    pub tun_index: u32,
    pub routes: Vec<Route>,
    pub dns: Option<Dns>,
}

pub(crate) trait Network {
    fn validate(&mut self, lease: &Lease) -> io::Result<()>;
    fn route(&mut self, route: &Route) -> io::Result<Option<Route>>;
    fn add(&mut self, route: &Route) -> io::Result<()>;
    fn delete(&mut self, route: &Route) -> io::Result<()>;
    fn dns(&mut self, service: &str) -> io::Result<Option<Vec<IpAddr>>>;
    fn set_dns(&mut self, dns: &Dns, restore: bool) -> io::Result<()>;
    fn save(&mut self, lease: &Lease) -> io::Result<()>;
    fn clear(&mut self) -> io::Result<()>;
}

pub(crate) fn parse_route(output: &str, ipv6: bool) -> io::Result<Option<Route>> {
    parse_route_inner(output, ipv6, false)
}

pub(crate) fn physical_default(
    output: &str,
    ipv6: bool,
    interface: &str,
    gateway: &str,
) -> io::Result<()> {
    // Every TUN daemon socket is bound to this physical interface, so its scoped default is valid.
    let route = parse_route_inner(output, ipv6, true)?;
    let gateway_ip = |value: &str| value.split('%').next().unwrap().parse::<IpAddr>();
    if route.is_some_and(|route| {
        !interface.starts_with("utun")
            && interface != "lo0"
            && route.cidr.network_length() == 0
            && route.interface == interface
            && route.gateway.as_deref().is_some_and(|current| {
                matches!((gateway_ip(current), gateway_ip(gateway)), (Ok(a), Ok(b)) if a == b)
            })
    }) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "no matching physical IPv{} default route on {interface} via {gateway}",
            if ipv6 { 6 } else { 4 }
        )))
    }
}

fn parse_route_inner(output: &str, ipv6: bool, allow_scoped: bool) -> io::Result<Option<Route>> {
    let field = |name: &str| {
        output.lines().find_map(|line| {
            let (key, value) = line.trim().split_once(':')?;
            (key == name).then(|| value.trim())
        })
    };
    let interface = field("interface").ok_or_else(|| io::Error::other("route has no interface"))?;
    let destination =
        field("destination").ok_or_else(|| io::Error::other("route has no destination"))?;
    let flags = field("flags").unwrap_or("");
    // A scoped route does not provide an unscoped default for ordinary sockets.
    if flags.contains("IFSCOPE") && !allow_scoped {
        return Ok(None);
    }
    let parse_ip = |value: &str| -> io::Result<IpAddr> {
        if value == "default" {
            return Ok(if ipv6 { "::" } else { "0.0.0.0" }.parse().unwrap());
        }
        let value = value.split('%').next().unwrap();
        let value = if !ipv6 && !value.contains(':') {
            let mut parts: Vec<_> = value.split('.').collect();
            if parts.len() > 4 {
                return Err(io::Error::other("invalid route address"));
            }
            parts.resize(4, "0");
            parts.join(".")
        } else {
            value.to_owned()
        };
        value.parse().map_err(io::Error::other)
    };
    // Darwin prints a zero network as "default" even when its mask is /1.
    let cidr = if destination == "default" && field("mask").is_none() {
        if ipv6 { "::/0" } else { "0.0.0.0/0" }.parse().unwrap()
    } else if destination.contains('/') {
        destination.parse().map_err(io::Error::other)?
    } else {
        let ip = parse_ip(destination)?;
        let bits = if flags.split([',', '<', '>']).any(|flag| flag == "HOST") {
            if ipv6 { 128 } else { 32 }
        } else {
            let mask =
                parse_ip(field("mask").ok_or_else(|| io::Error::other("route has no mask"))?)?;
            match mask {
                IpAddr::V4(mask) => {
                    let mask = u32::from(mask);
                    if mask != u32::MAX.checked_shl(mask.trailing_zeros()).unwrap_or(0) {
                        return Err(io::Error::other("noncontiguous route mask"));
                    }
                    mask.count_ones() as u8
                }
                IpAddr::V6(mask) => {
                    let mask = u128::from(mask);
                    if mask != u128::MAX.checked_shl(mask.trailing_zeros()).unwrap_or(0) {
                        return Err(io::Error::other("noncontiguous route mask"));
                    }
                    mask.count_ones() as u8
                }
            }
        };
        cidr::IpCidr::new(ip, bits).map_err(io::Error::other)?
    };
    if cidr.first_address().is_ipv6() != ipv6 {
        return Err(io::Error::other("route family mismatch"));
    }
    Ok(Some(Route {
        cidr,
        gateway: field("gateway").map(str::to_owned),
        interface: interface.to_owned(),
        tagged: flags.contains("PROTO2"),
    }))
}

pub(crate) fn apply(
    lease: &mut Lease,
    routes: &[Route],
    dns: Dns,
    network: &mut impl Network,
) -> io::Result<()> {
    network.validate(lease)?;
    // Check the entire plan before the first mutation, including other VPNs' split routes.
    let mut additions = Vec::new();
    for route in routes {
        match network.route(route)? {
            Some(current) if route.gateway.is_some() && route.same_path(&current) => {}
            Some(_) => {
                return Err(io::Error::other(format!(
                    "route {} already exists; refusing to replace it",
                    route.cidr
                )));
            }
            None => additions.push(route.clone()),
        }
    }
    if network.dns(&dns.service)? != dns.original {
        return Err(io::Error::other("DNS changed during TUN preflight"));
    }
    network.save(lease)?;
    let result = (|| {
        for route in additions {
            // Journal intent before issuing a command, including an interrupted/unacknowledged add.
            lease.routes.push(route.clone());
            network.save(lease)?;
            network.add(&route)?;
            if !network
                .route(&route)?
                .as_ref()
                .is_some_and(|current| route.matches(current))
            {
                return Err(io::Error::other("TUN route was not installed as requested"));
            }
        }
        lease.dns = Some(dns);
        network.save(lease)?;
        network.set_dns(lease.dns.as_ref().unwrap(), false)?;
        if network.dns(&lease.dns.as_ref().unwrap().service)?
            != Some(lease.dns.as_ref().unwrap().applied.clone())
        {
            return Err(io::Error::other("TUN DNS was not installed as requested"));
        }
        Ok(())
    })();
    if let Err(error) = result {
        return match recover(lease, network) {
            Ok(()) => Err(io::Error::other(format!(
                "TUN setup failed; network restored: {error}"
            ))),
            Err(cleanup) => Err(io::Error::other(format!(
                "TUN setup failed: {error}; recovery remains pending: {cleanup}"
            ))),
        };
    }
    Ok(())
}

pub(crate) fn recover(lease: &mut Lease, network: &mut impl Network) -> io::Result<()> {
    network.validate(lease)?;
    let mut errors = Vec::new();
    if let Some(dns) = &lease.dns {
        let result = (|| {
            let current = network.dns(&dns.service)?;
            if current == dns.original {
                return Ok(());
            }
            if current != Some(dns.applied.clone()) {
                return Err(io::Error::other(
                    "DNS was changed externally; recovery record preserved",
                ));
            }
            network.set_dns(dns, true)?;
            if network.dns(&dns.service)? != dns.original {
                return Err(io::Error::other("original DNS was not restored"));
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                lease.dns = None;
                if let Err(error) = network.save(lease) {
                    errors.push(error.to_string());
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
    }
    for index in (0..lease.routes.len()).rev() {
        let route = &lease.routes[index];
        let result = (|| {
            if let Some(current) = network.route(route)? {
                if !route.matches(&current) {
                    return Err(io::Error::other(format!(
                        "route {} changed externally; recovery record preserved",
                        route.cidr
                    )));
                }
                network.delete(route)?;
                if network.route(route)?.is_some() {
                    return Err(io::Error::other(format!(
                        "route {} still exists",
                        route.cidr
                    )));
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                lease.routes.remove(index);
                if let Err(error) = network.save(lease) {
                    errors.push(error.to_string());
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
    }
    if !errors.is_empty() {
        return Err(io::Error::other(errors.join("; ")));
    }
    network.clear()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn physical_default_accepts_scoped_uplink_without_claiming_its_route() {
        let scoped = "route to: default\ndestination: default\nmask: default\ngateway: 192.168.15.1\ninterface: en0\nflags: <UP,GATEWAY,DONE,STATIC,PRCLONING,IFSCOPE,GLOBAL>";
        physical_default(scoped, false, "en0", "192.168.15.1").unwrap();
        assert!(parse_route(scoped, false).unwrap().is_none());
        let ipv6 = "route to: ::\ndestination: ::\nmask: default\ngateway: fe80::82ae:54ff:fe93:c4a2%en0\ninterface: en0\nflags: <UP,GATEWAY,DONE,PRCLONING,GLOBAL>";
        physical_default(ipv6, true, "en0", "fe80::82ae:54ff:fe93:c4a2%en0").unwrap();
        physical_default(
            &format!("{ipv6},IFSCOPE"),
            true,
            "en0",
            "fe80::82ae:54ff:fe93:c4a2%en0",
        )
        .unwrap();
        assert!(physical_default(scoped, false, "en1", "192.168.15.1").is_err());
        assert!(physical_default(scoped, false, "en0", "192.168.15.2").is_err());
        assert!(
            physical_default(
                &scoped.replace("en0", "utun5"),
                false,
                "en0",
                "192.168.15.1"
            )
            .is_err()
        );
        assert!(
            physical_default(
                &scoped.replace("mask: default", "mask: 128.0.0.0"),
                false,
                "en0",
                "192.168.15.1"
            )
            .is_err()
        );
    }

    #[test]
    fn host_route_commands_do_not_use_network_lookups() {
        for (cidr, kind, destination) in [
            ("127.0.0.1/32", "-host", "127.0.0.1"),
            ("127.0.0.1", "-host", "127.0.0.1"),
            ("::1/128", "-host", "::1"),
            ("::1", "-host", "::1"),
            ("2602:fd37:10b:3d::a/128", "-host", "2602:fd37:10b:3d::a"),
            ("0.0.0.0/0", "-net", "0.0.0.0/0"),
            ("::/0", "-net", "::/0"),
            ("0.0.0.0/1", "-net", "0.0.0.0/1"),
            ("8000::/1", "-net", "8000::/1"),
            ("192.168.0.0/16", "-net", "192.168.0.0/16"),
        ] {
            assert_eq!(
                route_destination(cidr.parse().unwrap()),
                (kind, destination.into())
            );
        }
    }

    #[test]
    fn parses_native_route_output_without_confusing_scoped_defaults() {
        for (text, ipv6, expected) in [
            (
                "destination: default\ngateway: 192.168.15.1\ninterface: en0\nflags: <UP,GATEWAY,DONE>",
                false,
                "0.0.0.0/0",
            ),
            (
                "destination: default\nmask: 128.0.0.0\ninterface: utun5\nflags: <UP,DONE,STATIC,PROTO2>",
                false,
                "0.0.0.0/1",
            ),
            (
                "destination: default\nmask: default\ngateway: 192.168.15.1\ninterface: en0",
                false,
                "0.0.0.0/0",
            ),
            (
                "destination: 128.0\nmask: 128.0.0.0\ninterface: utun5\nflags: <UP,DONE>",
                false,
                "128.0.0.0/1",
            ),
            (
                "destination: 8000::\nmask: 8000::\ninterface: utun5",
                true,
                "8000::/1",
            ),
            (
                "destination: 2602:fd37:10b:3d::a\ngateway: fe80::1%en0\ninterface: en0\nflags: <UP,GATEWAY,HOST,DONE>",
                true,
                "2602:fd37:10b:3d::a/128",
            ),
        ] {
            assert_eq!(
                parse_route(text, ipv6).unwrap().unwrap().cidr,
                expected.parse().unwrap()
            );
        }
        assert!(
            parse_route(
                "destination: default\ninterface: en0\nflags: <UP,GATEWAY,IFSCOPE>",
                false
            )
            .unwrap()
            .is_none()
        );
        assert!(parse_route("destination: 128.0\ninterface: utun5", false).is_err());
    }

    #[test]
    fn detects_other_vpns_more_specific_routes_but_allows_scoped_and_link_local_routes() {
        let table = "Internet:\nDestination Gateway Flags Netif Expire\nfe80::%utun3/64 link#17 UcI utun3\nff02::/32 link#17 UmCI utun3\ndefault fe80::1 UGcI utun4\n1 198.18.0.1 UGSc utun1500\n";
        assert_eq!(
            foreign_tunnel_route(table, None).as_deref(),
            Some("1 on utun1500")
        );
        assert!(foreign_tunnel_route(table, Some("utun1500")).is_none());
        assert!(foreign_tunnel_route("default 192.168.15.1 UGSc en0", None).is_none());
    }

    #[derive(Default)]
    struct Fake {
        routes: HashMap<String, Route>,
        dns: Option<Vec<IpAddr>>,
        journal: Option<Lease>,
        adds: usize,
        fail_add: usize,
        fail_delete: Option<String>,
        fail_dns: bool,
        saves: usize,
        fail_save: usize,
        fail_after_add: bool,
        fail_after_dns: bool,
        fail_clear: bool,
    }
    impl Network for Fake {
        fn validate(&mut self, _: &Lease) -> io::Result<()> {
            Ok(())
        }
        fn route(&mut self, route: &Route) -> io::Result<Option<Route>> {
            Ok(self.routes.get(&route.cidr.to_string()).cloned())
        }
        fn add(&mut self, route: &Route) -> io::Result<()> {
            self.adds += 1;
            assert!(self.journal.as_ref().unwrap().routes.contains(route));
            if self.adds == self.fail_add {
                return Err(io::Error::other("injected add failure"));
            }
            self.routes.insert(route.cidr.to_string(), route.clone());
            if self.fail_after_add {
                self.fail_after_add = false;
                return Err(io::Error::other("lost add acknowledgement"));
            }
            Ok(())
        }
        fn delete(&mut self, route: &Route) -> io::Result<()> {
            if self.fail_delete.as_deref() == Some(&route.cidr.to_string()) {
                return Err(io::Error::other("injected delete failure"));
            }
            self.routes.remove(&route.cidr.to_string());
            Ok(())
        }
        fn dns(&mut self, _: &str) -> io::Result<Option<Vec<IpAddr>>> {
            Ok(self.dns.clone())
        }
        fn set_dns(&mut self, dns: &Dns, restore: bool) -> io::Result<()> {
            assert!(self.journal.as_ref().unwrap().dns.is_some());
            if self.fail_dns {
                return Err(io::Error::other("injected DNS failure"));
            }
            self.dns = if restore {
                dns.original.clone()
            } else {
                Some(dns.applied.clone())
            };
            if self.fail_after_dns {
                self.fail_after_dns = false;
                return Err(io::Error::other("lost DNS acknowledgement"));
            }
            Ok(())
        }
        fn save(&mut self, lease: &Lease) -> io::Result<()> {
            self.saves += 1;
            if self.saves == self.fail_save {
                return Err(io::Error::other("injected journal failure"));
            }
            self.journal = Some(lease.clone());
            Ok(())
        }
        fn clear(&mut self) -> io::Result<()> {
            if self.fail_clear {
                return Err(io::Error::other("injected unlink failure"));
            }
            self.journal = None;
            Ok(())
        }
    }
    fn fixture() -> (Lease, Vec<Route>, Dns, Fake) {
        let routes = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
            .map(|cidr| Route {
                cidr: cidr.parse().unwrap(),
                gateway: None,
                interface: "utun99".into(),
                tagged: true,
            })
            .to_vec();
        let dns = Dns {
            service: "wifi".into(),
            name: "Wi-Fi".into(),
            original: None,
            applied: vec!["10.0.0.1".parse().unwrap()],
        };
        let lease = Lease {
            boot: "boot".into(),
            tun: "utun99".into(),
            tun_index: 99,
            routes: vec![],
            dns: None,
        };
        let mut fake = Fake::default();
        let original = Route {
            cidr: "0.0.0.0/0".parse().unwrap(),
            gateway: Some("192.168.15.1".into()),
            interface: "en0".into(),
            tagged: false,
        };
        fake.routes.insert(original.cidr.to_string(), original);
        (lease, routes, dns, fake)
    }
    #[test]
    fn every_failed_setup_step_rolls_back_without_touching_default() {
        for step in 1..=5 {
            let (mut lease, routes, dns, mut fake) = fixture();
            fake.fail_add = step;
            fake.fail_dns = step == 5;
            assert!(apply(&mut lease, &routes, dns, &mut fake).is_err());
            assert_eq!(fake.routes.len(), 1);
            assert!(fake.routes.contains_key("0.0.0.0/0"));
            assert!(fake.dns.is_none());
            assert!(fake.journal.is_none());
        }
    }
    #[test]
    fn cleanup_attempts_other_items_and_keeps_failed_items_retryable() {
        let (mut lease, routes, dns, mut fake) = fixture();
        apply(&mut lease, &routes, dns, &mut fake).unwrap();
        fake.fail_dns = true;
        fake.fail_delete = Some(routes[2].cidr.to_string());
        assert!(recover(&mut lease, &mut fake).is_err());
        assert_eq!(lease.routes, [routes[2].clone()]);
        assert!(lease.dns.is_some());
        assert!(fake.journal.is_some());
        fake.fail_dns = false;
        fake.fail_delete = None;
        recover(&mut lease, &mut fake).unwrap();
        recover(&mut lease, &mut fake).unwrap();
        assert_eq!(fake.routes.len(), 1);
        assert!(fake.dns.is_none());
        assert!(fake.journal.is_none());
    }
    #[test]
    fn foreign_routes_and_dns_are_preserved() {
        let (mut lease, routes, dns, mut fake) = fixture();
        apply(&mut lease, &routes, dns, &mut fake).unwrap();
        fake.routes
            .get_mut(&routes[0].cidr.to_string())
            .unwrap()
            .interface = "utun100".into();
        fake.dns = Some(vec!["192.168.15.1".parse().unwrap()]);
        assert!(recover(&mut lease, &mut fake).is_err());
        assert_eq!(lease.routes.len(), 1);
        assert_eq!(fake.dns.as_ref().unwrap()[0].to_string(), "192.168.15.1");
        assert!(fake.journal.is_some());
    }
    #[test]
    fn recovery_preserves_a_replacement_route_even_when_its_path_is_identical() {
        let (mut lease, routes, dns, mut fake) = fixture();
        apply(&mut lease, &routes, dns, &mut fake).unwrap();
        fake.routes
            .get_mut(&routes[0].cidr.to_string())
            .unwrap()
            .tagged = false;
        assert!(recover(&mut lease, &mut fake).is_err());
        assert_eq!(lease.routes, [routes[0].clone()]);
        assert!(!fake.routes[&routes[0].cidr.to_string()].tagged);
        assert!(fake.dns.is_none());
    }
    #[test]
    fn missing_routes_and_interrupted_adds_are_recoverable() {
        let (mut lease, routes, dns, mut fake) = fixture();
        apply(&mut lease, &routes, dns, &mut fake).unwrap();
        fake.routes.remove(&routes[0].cidr.to_string());
        lease.routes.push(Route {
            cidr: "203.0.113.1/32".parse().unwrap(),
            gateway: Some("192.168.15.1".into()),
            interface: "en0".into(),
            tagged: false,
        });
        recover(&mut lease, &mut fake).unwrap();
        assert_eq!(fake.routes.len(), 1);
        assert!(fake.journal.is_none());
    }
    #[test]
    fn existing_vpn_is_rejected_before_mutation() {
        let (mut lease, routes, dns, mut fake) = fixture();
        let mut foreign = routes[3].clone();
        foreign.interface = "utun100".into();
        fake.routes.insert(foreign.cidr.to_string(), foreign);
        assert!(apply(&mut lease, &routes, dns, &mut fake).is_err());
        assert_eq!(fake.adds, 0);
        assert!(fake.journal.is_none());
    }

    #[test]
    fn every_journal_checkpoint_and_lost_acknowledgement_can_recover() {
        for checkpoint in 1..=6 {
            let (mut lease, routes, dns, mut fake) = fixture();
            fake.fail_save = checkpoint;
            assert!(apply(&mut lease, &routes, dns, &mut fake).is_err());
            assert_eq!(fake.routes.len(), 1);
            assert!(fake.dns.is_none());
            assert!(fake.journal.is_none());
        }
        for after_dns in [false, true] {
            let (mut lease, routes, dns, mut fake) = fixture();
            fake.fail_after_add = !after_dns;
            fake.fail_after_dns = after_dns;
            assert!(apply(&mut lease, &routes, dns, &mut fake).is_err());
            assert_eq!(fake.routes.len(), 1);
            assert!(fake.dns.is_none());
            assert!(fake.journal.is_none());
        }
    }

    #[test]
    fn manual_dns_is_restored_and_failed_journal_removal_can_retry() {
        let (mut lease, routes, mut dns, mut fake) = fixture();
        dns.original = Some(vec![
            "192.168.15.1".parse().unwrap(),
            "240c::6666".parse().unwrap(),
        ]);
        fake.dns = dns.original.clone();
        let original = fake.dns.clone();
        apply(&mut lease, &routes, dns, &mut fake).unwrap();
        fake.fail_clear = true;
        assert!(recover(&mut lease, &mut fake).is_err());
        assert_eq!(fake.dns, original);
        assert!(fake.journal.is_some());
        fake.fail_clear = false;
        recover(&mut lease, &mut fake).unwrap();
        assert_eq!(fake.routes.len(), 1);
        assert!(fake.journal.is_none());
    }
}
