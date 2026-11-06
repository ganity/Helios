#[cfg(feature = "secure-state-file")]
use super::*;
#[cfg(feature = "secure-state-file")]
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Context {
    boot: String,
    #[serde(default)]
    machine_id: Option<String>,
    net_namespace: (u64, u64),
    mount_namespace: (u64, u64),
    pub(super) tun_index: u32,
    resolver: (u64, u64),
}

#[cfg(feature = "secure-state-file")]
fn identity(path: &str) -> Result<(u64, u64)> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(feature = "secure-state-file")]
pub(super) fn checkpoint(state: &TproxyStateInner) -> Result<()> {
    crate::store_secure_state(state)?;
    Ok(())
}

#[cfg(feature = "secure-state-file")]
pub(super) async fn validate(state: &TproxyStateInner) -> Result<()> {
    if state.umount_resolvconf
        || state.restore_ip_forwarding
        || !state.restore_socket_fwmark.is_empty()
        || state
            .restore_gateway_mode
            .as_ref()
            .is_some_and(|rules| !rules.is_empty())
    {
        return Err(std::io::Error::other(
            "legacy gateway/fwmark/mount recovery is not supported by the desktop journal",
        )
        .into());
    }
    let context = state
        .linux_context
        .as_ref()
        .ok_or_else(|| std::io::Error::other("Linux recovery record has no ownership context"))?;
    if context.boot != fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        || context.net_namespace != identity("/proc/self/ns/net")?
        || context.mount_namespace != identity("/proc/self/ns/mnt")?
    {
        return Err(std::io::Error::other(
            "recovery record belongs to another boot or network/mount namespace",
        )
        .into());
    }
    let args = state
        .tproxy_args
        .as_ref()
        .ok_or_else(|| std::io::Error::other("tproxy_args is None"))?;
    match ip_link_get_index(&args.tun_name).await {
        Ok(index) if index != context.tun_index => {
            return Err(std::io::Error::other(
                "TUN name was reused by another interface; recovery refused",
            )
            .into());
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_none_or(|error| error.kind() != std::io::ErrorKind::NotFound) =>
        {
            return Err(error);
        }
        _ => {}
    }
    if state.restore_resolvconf_content.is_some()
        && context.resolver != identity(ETC_RESOLV_CONF_FILE)?
    {
        return Err(std::io::Error::other(
            "resolver file was replaced externally; recovery refused",
        )
        .into());
    }
    Ok(())
}

#[cfg(feature = "secure-state-file")]
pub(super) async fn add_route(state: &mut TproxyStateInner, mut route: RouteMessage) -> Result<()> {
    let cidr = route_msg_to_cidr(&route)?;
    if ip_route_get(&cidr, route_table(&route), true)
        .await?
        .is_some()
    {
        return Err(std::io::Error::other(format!(
            "route {cidr} already exists; refusing to replace it"
        ))
        .into());
    }
    route.header.protocol = rtnetlink::packet_route::route::RouteProtocol::Other(253);
    state.remove_routes.push(route.clone());
    checkpoint(state)?;
    if let Err(error) = ip_route_add_msg(&route).await {
        state.remove_routes.pop();
        checkpoint(state)?;
        return Err(error);
    }
    Ok(())
}

#[cfg(feature = "secure-state-file")]
async fn add_tun_route(state: &mut TproxyStateInner, cidr: &IpCidr) -> Result<()> {
    let context = state.linux_context.as_ref().unwrap();
    let route = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(cidr.first_address(), cidr.network_length())?
        .table_id(ROUTING_TABLE_MAIN)
        .output_interface(context.tun_index)
        .build();
    add_route(state, route).await
}

#[cfg(feature = "secure-state-file")]
async fn bypass(state: &mut TproxyStateInner, cidr: &IpCidr) -> Result<()> {
    let Some(mut route) = ip_route_get(cidr, ROUTING_TABLE_MAIN, false).await? else {
        return Err(std::io::Error::other(format!("no existing route for bypass {cidr}")).into());
    };
    if route_msg_to_cidr(&route)?.network_length() != 0 {
        return Ok(());
    }
    route.header.destination_prefix_length = cidr.network_length();
    route.attributes.retain(|attribute| {
        !matches!(
            attribute,
            rtnetlink::packet_route::route::RouteAttribute::Destination(_)
        )
    });
    let address = match cidr.first_address() {
        IpAddr::V4(ip) => rtnetlink::packet_route::route::RouteAddress::Inet(ip),
        IpAddr::V6(ip) => rtnetlink::packet_route::route::RouteAddress::Inet6(ip),
    };
    route
        .attributes
        .push(rtnetlink::packet_route::route::RouteAttribute::Destination(
            address,
        ));
    add_route(state, route).await
}

#[cfg(feature = "secure-state-file")]
async fn setup_inner(state: &mut TproxyStateInner) -> Result<()> {
    let args = state.tproxy_args.clone().unwrap();
    ip_link_set_up(&args.tun_name).await?;
    let bypass_ips = if args.bypass_ips.is_empty() {
        vec![IpCidr::new_host(args.proxy_addr.ip())]
    } else {
        args.bypass_ips.clone()
    };
    for cidr in bypass_ips {
        bypass(state, &cidr).await?;
    }
    if !args.source_bypass.is_empty() {
        super::source_policy::setup(state).await?;
    } else {
        for (enabled, default, lower, upper) in [
            (
                args.ipv4_default_route,
                &*IPV4_DEFAULT_ROUTE,
                &*IPV4_SPACE_LOWER,
                &*IPV4_SPACE_UPPER,
            ),
            (
                args.ipv6_default_route,
                &*IPV6_DEFAULT_ROUTE,
                &*IPV6_SPACE_LOWER,
                &*IPV6_SPACE_UPPER,
            ),
        ] {
            let original = ip_route_get(default, ROUTING_TABLE_MAIN, true).await?;
            if enabled {
                if original.is_some() {
                    add_tun_route(state, lower).await?;
                    add_tun_route(state, upper).await?;
                } else {
                    add_tun_route(state, default).await?;
                }
            } else if let Some(route) = original {
                state.restore_routes.push(route.clone());
                checkpoint(state)?;
                ip_route_del_msg(&route).await?;
            }
        }
    }
    detect_routing_loop(&IpCidr::new_host(args.proxy_addr.ip()), &args.tun_name).await?;
    if state.linux_resolved.is_some() {
        return super::resolved::apply(state).await;
    }
    let original = fs::read(ETC_RESOLV_CONF_FILE)?;
    let desired = format!("nameserver {}\n", args.tun_gateway).into_bytes();
    state.restore_resolvconf_content = Some(original);
    state.applied_resolvconf_content = Some(desired.clone());
    checkpoint(state)?;
    write_resolver(&desired)?;
    Ok(())
}

#[cfg(feature = "secure-state-file")]
fn write_resolver(contents: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(ETC_RESOLV_CONF_FILE)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(feature = "secure-state-file")]
pub(super) async fn setup(args: &TproxyArgs) -> Result<TproxyStateInner> {
    if args.gateway_mode || args.socket_fwmark.is_some() {
        return Err(std::io::Error::other("persistent Linux recovery supports desktop mode only; gateway/fwmark modes are refused").into());
    }
    let path = crate::get_secure_state_file_path()?;
    if path.exists() {
        return Err(std::io::Error::other(
            "a Linux recovery record already exists; recover it before starting TUN",
        )
        .into());
    }
    if !args.source_bypass.is_empty() {
        super::resolver::check_resolver().await?;
        super::source_policy::preflight(args).await?;
    }
    let mut state = TproxyStateInner {
        tproxy_args: Some(args.clone()),
        linux_context: Some(Context {
            boot: fs::read_to_string("/proc/sys/kernel/random/boot_id")?,
            machine_id: machine_id(),
            net_namespace: identity("/proc/self/ns/net")?,
            mount_namespace: identity("/proc/self/ns/mnt")?,
            tun_index: ip_link_get_index(&args.tun_name).await?,
            resolver: identity(ETC_RESOLV_CONF_FILE)?,
        }),
        ..Default::default()
    };
    if !args.source_bypass.is_empty() && super::resolver::uses_resolved()? {
        state.linux_resolved =
            Some(super::resolved::prepare(state.linux_context.as_ref().unwrap().tun_index).await?);
    }
    checkpoint(&state)?;
    if let Err(error) = setup_inner(&mut state).await {
        if let Err(cleanup) = remove(&mut state).await {
            return Err(std::io::Error::other(format!(
                "setup failed: {error}; recovery remains pending: {cleanup}"
            ))
            .into());
        }
        return Err(error);
    }
    Ok(state)
}

#[cfg(feature = "secure-state-file")]
pub(super) fn equivalent(left: &RouteMessage, right: &RouteMessage) -> bool {
    use rtnetlink::packet_route::{
        AddressFamily,
        route::{RouteAttribute, RoutePreference},
    };
    fn normalized(
        route: &RouteMessage,
    ) -> (rtnetlink::packet_route::route::RouteHeader, Vec<String>) {
        let mut header = route.header.clone();
        header.table = 0;
        let mut attributes = route
            .attributes
            .iter()
            .filter(|attribute| match attribute {
                RouteAttribute::CacheInfo(_) | RouteAttribute::Table(_) => false,
                RouteAttribute::Destination(address)
                    if route.header.destination_prefix_length == 0 =>
                {
                    !matches!(address,
                    rtnetlink::packet_route::route::RouteAddress::Inet(ip) if ip.is_unspecified())
                        && !matches!(address,
                    rtnetlink::packet_route::route::RouteAddress::Inet6(ip) if ip.is_unspecified())
                }
                RouteAttribute::Preference(RoutePreference::Medium)
                    if route.header.address_family == AddressFamily::Inet6 =>
                {
                    false
                }
                _ => true,
            })
            .map(|attribute| format!("{attribute:?}"))
            .collect::<Vec<_>>();
        if route.header.address_family == AddressFamily::Inet6
            && !route
                .attributes
                .iter()
                .any(|attribute| matches!(attribute, RouteAttribute::Priority(_)))
        {
            attributes.push(format!("{:?}", RouteAttribute::Priority(1024)));
        }
        attributes.push(format!("table:{}", route_table(route)));
        attributes.sort();
        (header, attributes)
    }
    normalized(left) == normalized(right)
}

#[cfg(feature = "secure-state-file")]
fn machine_id() -> Option<String> {
    fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|id| id.trim().to_owned())
        .filter(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(feature = "secure-state-file")]
fn recover_previous_boot(state: &TproxyStateInner) -> Result<bool> {
    let Some(context) = &state.linux_context else {
        return Ok(false);
    };
    if context.boot == fs::read_to_string("/proc/sys/kernel/random/boot_id")? {
        return Ok(false);
    }
    if context.machine_id.is_none() || context.machine_id != machine_id() {
        return Err(std::io::Error::other(
            "old-boot lease cannot be associated with this machine; recovery preserved",
        )
        .into());
    }
    // Kernel routes/rules and per-link resolved state disappeared on reboot. Do not touch
    // current interfaces or reuse an old ifindex. Only a still-identical static DNS file persists.
    if let Some(original) = &state.restore_resolvconf_content {
        if context.resolver != identity(ETC_RESOLV_CONF_FILE)? {
            return Err(std::io::Error::other(
                "old-boot resolver inode changed; recovery preserved",
            )
            .into());
        }
        let current = fs::read(ETC_RESOLV_CONF_FILE)?;
        if &current != original {
            if state.applied_resolvconf_content.as_ref() != Some(&current) {
                return Err(std::io::Error::other(
                    "old-boot DNS changed externally; recovery preserved",
                )
                .into());
            }
            write_resolver(original)?;
        }
    }
    fs::remove_file(crate::get_secure_state_file_path()?)?;
    Ok(true)
}

#[cfg(feature = "secure-state-file")]
pub(super) async fn remove(state: &mut TproxyStateInner) -> Result<()> {
    if recover_previous_boot(state)? {
        return Ok(());
    }
    validate(state).await?;
    let dns_error = super::resolved::remove(state).await.err();
    // A stopped DNS manager must not retain otherwise removable kernel policy rules.
    super::source_policy::remove(state).await?;
    // A cancelled cleanup can be retried from the journal; operations are idempotent.
    while let Some(route) = state.restore_routes.last().cloned() {
        match ip_route_get(&route_msg_to_cidr(&route)?, route_table(&route), true).await? {
            Some(current) if equivalent(&current, &route) => {}
            Some(_) => {
                return Err(std::io::Error::other(
                    "original route was changed externally; recovery preserved",
                )
                .into());
            }
            None => ip_route_add_msg(&route).await?,
        }
        state.restore_routes.pop();
        checkpoint(state)?;
    }
    while let Some(route) = state.remove_routes.last().cloned() {
        match ip_route_get(&route_msg_to_cidr(&route)?, route_table(&route), true).await? {
            Some(current) if equivalent(&current, &route) => ip_route_del_msg(&current).await?,
            Some(_) => {
                return Err(std::io::Error::other(
                    "Helios route was changed externally; recovery preserved",
                )
                .into());
            }
            None => {}
        }
        state.remove_routes.pop();
        checkpoint(state)?;
    }
    if let Some(original) = &state.restore_resolvconf_content {
        let current = fs::read(ETC_RESOLV_CONF_FILE)?;
        if &current != original {
            if state.applied_resolvconf_content.as_ref() != Some(&current) {
                return Err(std::io::Error::other(
                    "DNS settings were changed externally; recovery preserved",
                )
                .into());
            }
            write_resolver(original)?;
        }
        state.restore_resolvconf_content = None;
        state.applied_resolvconf_content = None;
        checkpoint(state)?;
    }
    if let Some(error) = dns_error {
        return Err(error);
    }
    let args = state.tproxy_args.as_ref().unwrap();
    match ip_link_del(&args.tun_name).await {
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
        result => result?,
    }
    // Keep an exhausted record if unlink fails; a later retry still validates its ownership.
    match std::fs::remove_file(crate::get_secure_state_file_path()?) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        result => result?,
    }
    state.tproxy_removed_done = true;
    Ok(())
}

#[cfg(all(test, feature = "secure-state-file"))]
mod tests {
    use super::*;
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    const LEASE: &str = "/tmp/helios-isolated-route-test/lease.json";

    fn routes() -> Vec<String> {
        let mut routes = Vec::new();
        for family in ["-4", "-6"] {
            routes.extend(
                String::from_utf8(
                    crate::run_command("ip", &[family, "route", "show", "table", "all"]).unwrap(),
                )
                .unwrap()
                .lines()
                .map(str::to_owned),
            );
        }
        routes.sort();
        routes
    }

    #[test]
    fn kernel_route_defaults_normalize_without_ignoring_ownership_or_metric() {
        use rtnetlink::packet_route::route::{RouteAttribute, RoutePreference, RouteProtocol};
        let expected = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
            .destination_prefix("::".parse().unwrap(), 0)
            .table_id(20220)
            .output_interface(7)
            .build();
        let mut current = expected.clone();
        current.header.table = 252;
        current
            .attributes
            .retain(|attribute| !matches!(attribute, RouteAttribute::Destination(_)));
        current.attributes.push(RouteAttribute::Priority(1024));
        current
            .attributes
            .push(RouteAttribute::Preference(RoutePreference::Medium));
        assert!(equivalent(&expected, &current));
        let mut foreign = current.clone();
        foreign.header.protocol = RouteProtocol::Dhcp;
        assert!(!equivalent(&expected, &foreign));
        let mut foreign = current.clone();
        foreign
            .attributes
            .retain(|attribute| !matches!(attribute, RouteAttribute::Priority(_)));
        foreign.attributes.push(RouteAttribute::Priority(2048));
        assert!(!equivalent(&expected, &foreign));
        let mut foreign = current;
        foreign
            .attributes
            .retain(|attribute| !matches!(attribute, RouteAttribute::Table(_)));
        foreign.attributes.push(RouteAttribute::Table(20221));
        assert!(!equivalent(&expected, &foreign));
    }

    #[test]
    #[ignore = "requires a disposable Docker network/mount namespace; never run on the host"]
    fn isolated_sigkill_recovery_preserves_routes_dns_and_rejects_foreign_context() {
        isolated_recovery(false);
    }

    #[test]
    #[ignore = "requires a disposable Docker network/mount namespace; never run on the host"]
    fn isolated_source_policy_routes_bound_sockets_and_recovers_after_sigkill() {
        isolated_recovery(true);
    }

    fn rules_snapshot() -> Vec<u8> {
        ["-4", "-6"]
            .into_iter()
            .flat_map(|family| crate::run_command("ip", &[family, "rule", "show"]).unwrap())
            .collect()
    }

    fn isolated_recovery(source_policy: bool) {
        assert_eq!(
            std::env::var("HELIOS_ISOLATED_TUN_TEST").as_deref(),
            Ok("1")
        );
        assert_eq!(
            fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim(),
            "helios-tun-test"
        );
        assert!(Path::new("/.dockerenv").exists());
        crate::set_state_file_path(LEASE.into()).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        if std::env::var_os("HELIOS_TUN_CHILD").is_some() {
            let args = TproxyArgs {
                tun_name: "heliostest".into(),
                proxy_addr: "203.0.113.7:24443".parse().unwrap(),
                bypass_ips: vec!["203.0.113.7/32".parse().unwrap()],
                source_bypass: if source_policy {
                    vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()]
                } else {
                    vec![]
                },
                ipv6_default_route: source_policy,
                ..Default::default()
            };
            let _state = runtime.block_on(setup(&args)).unwrap();
            fs::write("/tmp/helios-isolated-route-test/ready", "ready").unwrap();
            std::thread::sleep(Duration::from_secs(30));
            panic!("parent did not kill test child");
        }
        for args in [
            vec!["link", "set", "lo", "up"],
            vec!["link", "add", "uplinktest", "type", "dummy"],
            vec!["link", "set", "uplinktest", "up"],
            vec!["addr", "add", "192.0.2.1/24", "dev", "uplinktest"],
            vec![
                "route",
                "add",
                "default",
                "via",
                "192.0.2.254",
                "dev",
                "uplinktest",
            ],
            vec![
                "-6",
                "addr",
                "add",
                "2001:db8::1/64",
                "dev",
                "uplinktest",
                "nodad",
            ],
            vec![
                "-6",
                "route",
                "add",
                "default",
                "via",
                "2001:db8::fe",
                "dev",
                "uplinktest",
            ],
            vec!["link", "add", "heliostest", "type", "dummy"],
        ] {
            crate::run_command("ip", &args).unwrap();
        }
        let original_routes = routes();
        if source_policy {
            crate::run_command("ip", &["addr", "add", "10.0.0.33/24", "dev", "heliostest"])
                .unwrap();
        }
        let original_rules = rules_snapshot();
        let original_dns = fs::read(ETC_RESOLV_CONF_FILE).unwrap();
        let test_name = if source_policy {
            "linux::recovery::tests::isolated_source_policy_routes_bound_sockets_and_recovers_after_sigkill"
        } else {
            "linux::recovery::tests::isolated_sigkill_recovery_preserves_routes_dns_and_rejects_foreign_context"
        };
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--ignored", "--nocapture"])
            .env("HELIOS_TUN_CHILD", "1")
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !Path::new("/tmp/helios-isolated-route-test/ready").exists() {
            assert!(child.try_wait().unwrap().is_none(), "setup child failed");
            assert!(Instant::now() < deadline, "setup timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
        if source_policy {
            for (target, source) in [
                ("198.51.100.1", "192.0.2.1"),
                ("2001:db8:1::1", "2001:db8::1"),
            ] {
                let application =
                    String::from_utf8(crate::run_command("ip", &["route", "get", target]).unwrap())
                        .unwrap();
                assert!(application.contains("dev heliostest"), "{application}");
                let daemon = String::from_utf8(
                    crate::run_command("ip", &["route", "get", target, "from", source]).unwrap(),
                )
                .unwrap();
                assert!(daemon.contains("dev uplinktest"), "{daemon}");
                let source: IpAddr = source.parse().unwrap();
                let destination = std::net::SocketAddr::new(target.parse().unwrap(), 443);
                let unbound = std::net::UdpSocket::bind(if source.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                })
                .unwrap();
                unbound.connect(destination).unwrap();
                assert_eq!(
                    unbound.local_addr().unwrap().ip(),
                    if source.is_ipv4() {
                        "10.0.0.33".parse::<IpAddr>().unwrap()
                    } else {
                        "fd00:6865:6c69::2".parse().unwrap()
                    }
                );
                let bound =
                    std::net::UdpSocket::bind(std::net::SocketAddr::new(source, 0)).unwrap();
                bound.connect(destination).unwrap();
                assert_eq!(bound.local_addr().unwrap().ip(), source);
            }
            assert_ne!(rules_snapshot(), original_rules);
            // Losing an uplink must not recursively capture source-bound daemon traffic.
            crate::run_command("ip", &["route", "del", "default"]).unwrap();
            assert!(
                crate::run_command("ip", &["route", "get", "198.51.100.1", "from", "192.0.2.1"])
                    .is_err()
            );
            crate::run_command(
                "ip",
                &[
                    "route",
                    "add",
                    "default",
                    "via",
                    "192.0.2.254",
                    "dev",
                    "uplinktest",
                ],
            )
            .unwrap();
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        assert_ne!(routes(), original_routes);
        assert_ne!(fs::read(ETC_RESOLV_CONF_FILE).unwrap(), original_dns);
        let state = crate::retrieve_secure_state().unwrap();
        let mut foreign = state.clone();
        foreign.linux_context.as_mut().unwrap().net_namespace.1 ^= 1;
        crate::store_secure_state(&foreign).unwrap();
        assert!(
            runtime
                .block_on(crate::tproxy_remove(None))
                .unwrap_err()
                .to_string()
                .contains("namespace")
        );
        assert!(Path::new(LEASE).exists());
        crate::store_secure_state(&state).unwrap();
        if source_policy {
            // A foreign replacement at our priority is preserved, with the journal retryable.
            crate::run_command("ip", &["-6", "rule", "del", "pref", "20223"]).unwrap();
            crate::run_command(
                "ip",
                &["-6", "rule", "add", "pref", "20223", "table", "main"],
            )
            .unwrap();
            let foreign_rules = rules_snapshot();
            assert!(
                runtime
                    .block_on(crate::tproxy_remove(None))
                    .unwrap_err()
                    .to_string()
                    .contains("policy rule")
            );
            assert_eq!(rules_snapshot(), foreign_rules);
            assert!(Path::new(LEASE).exists());
            crate::run_command("ip", &["-6", "rule", "del", "pref", "20223"]).unwrap();
            crate::run_command(
                "ip",
                &[
                    "-6", "rule", "add", "pref", "20223", "table", "20220", "protocol", "253",
                ],
            )
            .unwrap();
        }
        runtime.block_on(crate::tproxy_remove(None)).unwrap();
        assert_eq!(routes(), original_routes);
        assert_eq!(rules_snapshot(), original_rules);
        assert_eq!(fs::read(ETC_RESOLV_CONF_FILE).unwrap(), original_dns);
        assert!(!Path::new(LEASE).exists());
        let mut retry = state;
        runtime.block_on(remove(&mut retry)).unwrap();
        assert!(retry.tproxy_removed_done);
        assert_eq!(routes(), original_routes);
        assert_eq!(rules_snapshot(), original_rules);
    }
}
