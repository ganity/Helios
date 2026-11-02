#![cfg(target_os = "linux")]
// Legacy gateway/fwmark helpers remain available to builds without protected desktop recovery.
#![cfg_attr(feature = "secure-state-file", allow(dead_code))]

pub(crate) mod recovery;

use futures::stream::TryStreamExt;
use std::fs;
use std::fs::Permissions;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::PermissionsExt;
use std::str::FromStr;

use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::path::Path;

use rtnetlink::packet_route::route::RouteMessage;
use rtnetlink::{
    Handle, IpVersion, LinkMessageBuilder, LinkUnspec, RouteMessageBuilder, new_connection,
};

use cidr::IpCidr;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

use crate::{ETC_RESOLV_CONF_FILE, TproxyArgs, TproxyStateInner, run_command};

static IPV6_DEFAULT_ROUTE: std::sync::LazyLock<IpCidr> =
    std::sync::LazyLock::new(|| IpCidr::from_str("::/0").unwrap());
static IPV6_SPACE_LOWER: std::sync::LazyLock<IpCidr> =
    std::sync::LazyLock::new(|| IpCidr::from_str("::/1").unwrap());
static IPV6_SPACE_UPPER: std::sync::LazyLock<IpCidr> =
    std::sync::LazyLock::new(|| IpCidr::from_str("8000::/1").unwrap());

static IPV4_DEFAULT_ROUTE: std::sync::LazyLock<IpCidr> =
    std::sync::LazyLock::new(|| IpCidr::from_str("0.0.0.0/0").unwrap());
static IPV4_SPACE_LOWER: std::sync::LazyLock<IpCidr> =
    std::sync::LazyLock::new(|| IpCidr::from_str("0.0.0.0/1").unwrap());
static IPV4_SPACE_UPPER: std::sync::LazyLock<IpCidr> =
    std::sync::LazyLock::new(|| IpCidr::from_str("128.0.0.0/1").unwrap());

static ROUTING_TABLE_MAIN: u32 = 254;

fn bytes_to_string(bytes: Vec<u8>) -> Result<String> {
    match String::from_utf8(bytes) {
        Ok(content) => Ok(content),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("error converting bytes to string: {e}"),
        )
        .into()),
    }
}

async fn netlink_do<F, T, R>(f: F) -> Result<R>
where
    F: Fn(Handle) -> T,
    T: Future<Output = Result<R>>,
{
    let action = async || {
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        f(handle).await
    };
    action().await
}

async fn ip_route_add_msg(msg: &RouteMessage) -> Result<()> {
    netlink_do(async |handle| Ok(handle.route().add(msg.clone()).execute().await?)).await
}

async fn ip_link_get_index(dev: &str) -> Result<u32> {
    netlink_do(async |handle| {
        let mut interfaces = handle.link().get().match_name(String::from(dev)).execute();
        match interfaces.try_next().await {
            Ok(Some(link)) => Ok(link.header.index),
            Ok(None) => {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Interface not found").into())
            }
            Err(rtnetlink::Error::NetlinkError(error))
                if error.raw_code() == -nix::libc::ENODEV =>
            {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Interface not found").into())
            }
            Err(error) => Err(error.into()),
        }
    })
    .await
}

async fn ip_route_add(dest: &IpCidr, dev: &str, table: u32) -> Result<RouteMessage> {
    let index = ip_link_get_index(dev).await?;
    netlink_do(async |handle| {
        let route = RouteMessageBuilder::<std::net::IpAddr>::new()
            .destination_prefix(dest.first_address(), dest.network_length())?
            .table_id(table)
            .output_interface(index)
            .build();
        handle.route().add(route.clone()).execute().await?;
        Ok(route)
    })
    .await
}

async fn ip_route_del_msg(msg: &RouteMessage) -> Result<()> {
    netlink_do(async |handle| Ok(handle.route().del(msg.clone()).execute().await?)).await
}

async fn ip_link_set_up(dev: &str) -> Result<()> {
    netlink_do(async |handle| {
        let msg = LinkMessageBuilder::<LinkUnspec>::default()
            .name(String::from(dev))
            .up()
            .build();
        Ok(handle.link().set(msg).execute().await?)
    })
    .await
}

async fn ip_link_del(dev: &str) -> Result<()> {
    let index = ip_link_get_index(dev).await?;
    netlink_do(async |handle| Ok(handle.link().del(index).execute().await?)).await
}

async fn ip_route_show(ip_version: IpVersion, table: u32) -> Result<Vec<RouteMessage>> {
    netlink_do(async |handle| {
        let route = match ip_version {
            IpVersion::V4 => RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                .table_id(table)
                .build(),
            IpVersion::V6 => RouteMessageBuilder::<std::net::Ipv6Addr>::new()
                .table_id(table)
                .build(),
        };
        let mut routes = handle.route().get(route).execute();
        let mut route_messages = Vec::new();
        while let Some(route) = routes.try_next().await? {
            route_messages.push(route);
        }

        // Sort routes by prefix length, the most specific route comes first.
        route_messages.sort_by(|entry1: &RouteMessage, entry2: &RouteMessage| {
            // If the prefix lengths are equal, we compare the priority of the routes.

            let mut prio1 = 0;
            let mut prio2 = 0;

            for nla in &entry1.attributes {
                if let rtnetlink::packet_route::route::RouteAttribute::Priority(prio) = nla {
                    prio1 = *prio
                }
            }

            for nla in &entry1.attributes {
                if let rtnetlink::packet_route::route::RouteAttribute::Priority(prio) = nla {
                    prio2 = *prio
                }
            }

            let prio_cmp = prio1.cmp(&prio2);
            if prio_cmp != std::cmp::Ordering::Equal {
                return prio_cmp;
            }

            entry2
                .header
                .destination_prefix_length
                .cmp(&entry1.header.destination_prefix_length)
        });

        Ok(route_messages)
    })
    .await
}

async fn ip_rule_add(ip_version: IpVersion, fwmark: u32, table: u32) -> Result<()> {
    netlink_do(async |handle| {
        if ip_version == IpVersion::V6 {
            Ok(handle
                .rule()
                .add()
                .v6()
                .fw_mark(fwmark)
                .table_id(table)
                .execute()
                .await?)
        } else {
            Ok(handle
                .rule()
                .add()
                .v4()
                .fw_mark(fwmark)
                .table_id(table)
                .execute()
                .await?)
        }
    })
    .await
}

fn matches_fwmark_rule(
    rule: &rtnetlink::packet_route::rule::RuleMessage,
    fwmark: u32,
    table: u32,
) -> bool {
    use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute};
    let mut actual_mark = None;
    let mut actual_table = u32::from(rule.header.table);
    let mut mask = u32::MAX;
    for attribute in &rule.attributes {
        match attribute {
            RuleAttribute::FwMark(value) => actual_mark = Some(*value),
            RuleAttribute::FwMask(value) => mask = *value,
            RuleAttribute::Table(value) => actual_table = *value,
            _ => {}
        }
    }
    rule.header.action == RuleAction::ToTable
        && actual_mark == Some(fwmark)
        && actual_table == table
        && mask == u32::MAX
}

async fn ip_rule_del(ip_version: IpVersion, fwmark: u32, table: u32) -> Result<()> {
    netlink_do(async |handle| {
        let mut rules = handle.rule().get(ip_version.clone()).execute();
        while let Some(rule) = rules.try_next().await? {
            if matches_fwmark_rule(&rule, fwmark, table) {
                return Ok(handle.rule().del(rule).execute().await?);
            }
        }
        Ok(())
    })
    .await
}

fn route_msg_to_cidr(msg: &rtnetlink::packet_route::route::RouteMessage) -> Result<IpCidr> {
    let mut net_addr: Option<IpAddr> = match msg.header.address_family {
        rtnetlink::packet_route::AddressFamily::Inet => {
            Some(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        }
        rtnetlink::packet_route::AddressFamily::Inet6 => {
            Some(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))
        }
        _ => None,
    };
    let prefix_len = msg.header.destination_prefix_length;
    let attrs = &msg.attributes;
    for nla in attrs.iter() {
        if let rtnetlink::packet_route::route::RouteAttribute::Destination(addr) = nla {
            if let rtnetlink::packet_route::route::RouteAddress::Inet(ip) = addr {
                net_addr = Some(IpAddr::V4(*ip));
            } else if let rtnetlink::packet_route::route::RouteAddress::Inet6(ip) = addr {
                net_addr = Some(IpAddr::V6(*ip));
            }
        }
    }

    if let Some(addr) = net_addr {
        return create_cidr(addr, prefix_len);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "failed to find destination in message attributes",
    )
    .into())
}

fn bool_to_ip_version(is_ipv6: bool) -> IpVersion {
    if is_ipv6 {
        IpVersion::V6
    } else {
        IpVersion::V4
    }
}

fn get_table_id(table_name: String) -> Result<u32> {
    if let Ok(table_id) = u32::from_str(table_name.as_str()) {
        return Ok(table_id);
    }

    for path in ["/etc/iproute2/rt_tables", "/usr/share/iproute2/rt_tables"] {
        let rt_tables = parse_rt_tables(String::from(path))?;
        if let Some(&id) = rt_tables.get(&table_name) {
            return Ok(id);
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("Routing table '{table_name}' not found"),
    )
    .into())
}

/// Parses the /etc/iproute2/rt_tables file and returns a map of table ID to name.
fn parse_rt_tables<P: AsRef<Path>>(path: P) -> Result<HashMap<String, u32>> {
    let file = File::open(path)?;
    let reader = std::io::BufReader::new(file);

    let mut table_map = HashMap::new();
    // Defaults cf. https://github.com/iproute2/iproute2/blob/d30f38d5d752abe12174b1ea05707bcf86f3d305/lib/rt_names.c#L508
    table_map.insert("default".to_string(), 253);
    table_map.insert("main".to_string(), 254);
    table_map.insert("local".to_string(), 255);

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 2 {
            log::debug!("Warning: skipping malformed line: {line}");
            continue;
        }

        match parts[0].parse::<u32>() {
            Ok(id) => {
                table_map.insert(parts[1].to_string(), id);
            }
            Err(_) => {
                log::debug!("Warning: invalid table ID in line: {line}");
            }
        }
    }

    Ok(table_map)
}

/// Retrieves a route message for the given CIDR and routing table.
async fn ip_route_get(
    search_cidr: &IpCidr,
    table: u32,
    strict: bool,
) -> Result<Option<RouteMessage>> {
    let ip_version = bool_to_ip_version(search_cidr.is_ipv6());
    let route_messages = ip_route_show(ip_version, table).await?;
    for msg in route_messages {
        let route_cidr = route_msg_to_cidr(&msg)?;
        if strict && route_cidr == *search_cidr
            || !strict
                && route_cidr.contains(&search_cidr.first_address())
                && route_cidr.contains(&search_cidr.last_address())
        {
            return Ok(Some(msg));
        }
    }
    Ok(None)
}

async fn route_exists(route: &IpCidr, table: u32, strict: bool) -> Result<bool> {
    Ok(ip_route_get(route, table, strict).await?.is_some())
}

fn create_cidr(addr: IpAddr, len: u8) -> Result<IpCidr> {
    match IpCidr::new(addr, len) {
        Ok(cidr) => Ok(cidr),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to convert {addr}/{len} to CIDR"),
        )
        .into()),
    }
}

fn write_buffer_to_fd(fd: std::os::fd::BorrowedFd<'_>, data: &[u8]) -> Result<()> {
    let mut written = 0;
    loop {
        if written >= data.len() {
            break;
        }
        written += nix::unistd::write(fd, &data[written..])?;
    }
    Ok(())
}

fn write_nameserver(fd: std::os::fd::BorrowedFd<'_>, tun_gateway: Option<IpAddr>) -> Result<()> {
    let tun_gateway = tun_gateway.unwrap_or_else(|| "198.18.0.1".parse().unwrap());
    let data = format!("nameserver {tun_gateway}\n");
    write_buffer_to_fd(fd, data.as_bytes())?;
    Ok(())
}

fn ip_forwarding_file_path(ipv6: bool) -> &'static str {
    if ipv6 {
        "/proc/sys/net/ipv6/conf/all/forwarding"
    } else {
        "/proc/sys/net/ipv4/ip_forward"
    }
}

fn ip_fowarding_enabled(ipv6: bool) -> Result<bool> {
    let path = ip_forwarding_file_path(ipv6);
    Ok(bytes_to_string(fs::read(path)?)?.trim() == "1")
}

fn configure_ip_forwarding(ipv6: bool, enable: bool) -> Result<()> {
    let path = ip_forwarding_file_path(ipv6);
    fs::write(path, if enable { "1\n" } else { "0\n" })?;
    Ok(())
}

fn setup_resolv_conf(restore: &mut TproxyStateInner) -> Result<()> {
    let tun_gateway = restore.tproxy_args.as_ref().map(|args| args.tun_gateway);
    // We use a mount here because software like NetworkManager is known to fiddle with the
    // resolv.conf file and restore it to its original state.
    // Example: https://stackoverflow.com/q/51784208
    // Using a readonly bind mount, we can pin our configuration without having the user update
    // the NetworkManager configuration.
    let file = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o644))
        .rand_bytes(32)
        .tempfile()?;
    write_nameserver(file.as_fd(), tun_gateway)?;
    let source = format!("/proc/self/fd/{}", file.as_raw_fd());
    let flags = nix::mount::MsFlags::MS_BIND;
    let mount1 = nix::mount::mount(
        source.as_str().into(),
        ETC_RESOLV_CONF_FILE,
        "".into(),
        flags,
        "".into(),
    );
    if mount1.is_ok() {
        restore.umount_resolvconf = true;
        let flags = nix::mount::MsFlags::MS_REMOUNT
            | nix::mount::MsFlags::MS_RDONLY
            | nix::mount::MsFlags::MS_BIND;
        if nix::mount::mount("".into(), ETC_RESOLV_CONF_FILE, "".into(), flags, "".into()).is_err()
        {
            log::warn!("failed to remount /etc/resolv.conf as readonly");
        }
    }
    drop(file);
    if mount1.is_err() {
        log::warn!(
            "failed to bind mount custom resolv.conf onto /etc/resolv.conf, resorting to direct write"
        );

        restore.restore_resolvconf_content = Some(fs::read(ETC_RESOLV_CONF_FILE)?);

        // Older versions chmod'ed /etc/resolv.conf to 0444 on this path, which made the
        // write here fail with EACCES on every subsequent start in containers that
        // drop CAP_DAC_OVERRIDE (e.g. Docker's bind-mounted resolv.conf). Restore
        // writability before reopening.
        let write_mode = nix::sys::stat::Mode::from_bits(0o644).unwrap();
        let flags =
            nix::fcntl::OFlag::O_WRONLY | nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_TRUNC;
        let fd = match nix::fcntl::open(ETC_RESOLV_CONF_FILE, flags, write_mode) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::EACCES) => {
                // Recover from the 0444 mode left behind by older versions (see comment above).
                fs::set_permissions(ETC_RESOLV_CONF_FILE, Permissions::from_mode(0o644))?;
                nix::fcntl::open(ETC_RESOLV_CONF_FILE, flags, write_mode)?
            }
            Err(err) => return Err(err.into()),
        };
        write_nameserver(fd.as_fd(), tun_gateway)?;
    }
    Ok(())
}

async fn do_bypass_ip(state: &mut TproxyStateInner, ip: &IpCidr) -> Result<bool> {
    let route_info = ip_route_show(bool_to_ip_version(ip.is_ipv6()), ROUTING_TABLE_MAIN).await?;

    let cidr = *ip;

    for route_message in route_info {
        let route_cidr = match route_msg_to_cidr(&route_message) {
            Ok(cidr) => cidr,
            Err(_) => {
                log::debug!("failed to convert route message to CIDR: {route_message:?}");
                continue;
            }
        };

        // If the route does not contain the target CIDR, it is not interesting for us.
        if !route_cidr.contains(&cidr.first_address()) || !route_cidr.contains(&cidr.last_address())
        {
            continue;
        }

        // The IP address is routed through a more specific route than the default route.
        // In this case, there is nothing to do.
        if route_cidr.network_length() != 0 {
            break;
        }

        let mut new_route_message = route_message.clone();
        let dst_attr = rtnetlink::packet_route::route::RouteAttribute::Destination(
            match cidr.first_address() {
                IpAddr::V4(ip) => rtnetlink::packet_route::route::RouteAddress::Inet(ip),
                IpAddr::V6(ip) => rtnetlink::packet_route::route::RouteAddress::Inet6(ip),
            },
        );
        new_route_message.header.destination_prefix_length = cidr.network_length();

        let mut dst_index = None;
        new_route_message
            .attributes
            .iter()
            .enumerate()
            .for_each(|(i, nla)| {
                if let rtnetlink::packet_route::route::RouteAttribute::Destination(_) = nla {
                    dst_index = Some(i);
                }
            });

        match dst_index {
            Some(index) => new_route_message.attributes[index] = dst_attr,
            None => new_route_message.attributes.push(dst_attr),
        }

        let result = ip_route_add_msg(&new_route_message).await;
        let mut route_exists = false;

        if let Err(err) = &result {
            if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                route_exists = io_err.kind() == std::io::ErrorKind::AlreadyExists;
            }
            result?;
        }

        if !route_exists {
            log::debug!("added bypass route: {new_route_message:?}");
            state.remove_routes.push(new_route_message);
        } else {
            log::debug!("bypass route already exists: {new_route_message:?}");
        }

        return Ok(true);
    }
    Ok(false)
}

fn apply_gateway_rule(
    state: &mut TproxyStateInner,
    args: &[&str],
    run: impl FnOnce(&[&str]) -> std::io::Result<Vec<u8>>,
) -> Result<()> {
    let mut restore = args.to_vec();
    let action = restore
        .iter()
        .position(|arg| *arg == "-A")
        .ok_or_else(|| std::io::Error::other("gateway rule has no append action"))?;
    restore[action] = "-D";
    run(args)?;
    state
        .restore_gateway_mode
        .get_or_insert_with(Vec::new)
        .push(restore.join(" "));
    Ok(())
}

fn setup_gateway_mode(state: &mut TproxyStateInner, tun_name: &str) -> Result<()> {
    // sudo iptables -t nat -A POSTROUTING -o "tun_name" -j MASQUERADE
    let args = &[
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-o",
        tun_name,
        "-j",
        "MASQUERADE",
    ];
    apply_gateway_rule(state, args, |args| run_command("iptables", args))?;

    // sudo iptables -A FORWARD -o "tun_name" -j ACCEPT
    let args = &["-A", "FORWARD", "-o", tun_name, "-j", "ACCEPT"];
    apply_gateway_rule(state, args, |args| run_command("iptables", args))?;

    // sudo iptables -A FORWARD -i "tun_name" -o "default_interface" -m state --state RELATED,ESTABLISHED -j ACCEPT
    let args = &[
        "-A",
        "FORWARD",
        "-i",
        tun_name,
        "-m",
        "state",
        "--state",
        "RELATED,ESTABLISHED",
        "-j",
        "ACCEPT",
    ];
    apply_gateway_rule(state, args, |args| run_command("iptables", args))?;

    if !ip_fowarding_enabled(false)? {
        log::debug!("IP forwarding not enabled");
        configure_ip_forwarding(false, true)?;

        state.restore_ip_forwarding = true;
    }

    log::debug!("restore gateway mode: {:?}", state.restore_gateway_mode);

    Ok(())
}

async fn setup_fwmark_table(state: &mut TproxyStateInner, tproxy_args: &TproxyArgs) -> Result<()> {
    let Some(fwmark) = tproxy_args.socket_fwmark else {
        return Err(Box::new(std::io::Error::other("fwmark is None")));
    };

    let table = get_table_id(tproxy_args.socket_fwmark_table.clone())?;

    let ipv4_routes = ip_route_show(IpVersion::V4, table).await?;
    let ipv6_routes = ip_route_show(IpVersion::V6, table).await?;
    require_empty_fwmark_table(table, &ipv4_routes, &ipv6_routes)?;
    for ip_version in [IpVersion::V4, IpVersion::V6] {
        ip_rule_add(ip_version.clone(), fwmark, table).await?;
        state.restore_socket_fwmark.push(crate::FwmarkRestore {
            ip_version,
            fwmark,
            table,
        });
    }
    log::debug!("restore socket fwmark: {:?}", state.restore_socket_fwmark);

    Ok(())
}

fn require_empty_fwmark_table(
    table: u32,
    ipv4_routes: &[RouteMessage],
    ipv6_routes: &[RouteMessage],
) -> Result<()> {
    if !ipv4_routes.is_empty() || !ipv6_routes.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("refusing to use nonempty fwmark routing table {table}"),
        )
        .into());
    }
    Ok(())
}

async fn detect_routing_loop(proxy_cidr: &IpCidr, tun_name: &str) -> Result<()> {
    let tun_interface_id = ip_link_get_index(tun_name).await?;
    log::debug!("tun ({tun_name}) interface id: {tun_interface_id}");
    let mut routing_loop = false;

    let proxy_route = ip_route_get(proxy_cidr, ROUTING_TABLE_MAIN, false).await?;
    if let Some(route) = proxy_route {
        route.attributes.iter().for_each(|nla| {
            if let rtnetlink::packet_route::route::RouteAttribute::Oif(index) = nla {
                log::debug!("proxy route output interface index: {index}");
                if *index == tun_interface_id {
                    routing_loop = true;
                }
            }
        });
        if routing_loop {
            return Err(std::io::Error::other("routing loop detected".to_string()).into());
        }
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("route to proxy {proxy_cidr} not found"),
        )
        .into());
    }
    Ok(())
}

pub(crate) async fn _tproxy_setup_inner(
    tproxy_args: &TproxyArgs,
    state: &mut TproxyStateInner,
) -> Result<()> {
    let tun_name = &tproxy_args.tun_name;

    let proxy_cidr = IpCidr::new_host(tproxy_args.proxy_addr.ip());

    flush_dns_cache()?;

    // check for gateway mode
    if tproxy_args.gateway_mode {
        setup_gateway_mode(state, tun_name)?;
    }

    // check for socket fwmark
    if tproxy_args.socket_fwmark.is_some() {
        setup_fwmark_table(state, tproxy_args).await?;
    }

    // sudo ip link set tun0 up
    ip_link_set_up(tun_name).await?;

    for ip in tproxy_args.bypass_ips.iter() {
        do_bypass_ip(state, ip).await?;
    }

    if tproxy_args.bypass_ips.is_empty() {
        do_bypass_ip(state, &proxy_cidr).await?;
    }

    if tproxy_args.ipv4_default_route {
        if !route_exists(&IPV4_DEFAULT_ROUTE, ROUTING_TABLE_MAIN, true).await? {
            state
                .remove_routes
                .push(ip_route_add(&IPV4_DEFAULT_ROUTE, tun_name, ROUTING_TABLE_MAIN).await?);
        } else {
            state
                .remove_routes
                .push(ip_route_add(&IPV4_SPACE_LOWER, tun_name, ROUTING_TABLE_MAIN).await?);
            state
                .remove_routes
                .push(ip_route_add(&IPV4_SPACE_UPPER, tun_name, ROUTING_TABLE_MAIN).await?);
        }
    } else {
        // If IPv4 is not enabled, we do not want IPv4 traffic to bypass the proxy if a route
        // already exists.
        let default_route = ip_route_get(&IPV4_DEFAULT_ROUTE, ROUTING_TABLE_MAIN, true).await?;

        if let Some(msg) = default_route {
            ip_route_del_msg(&msg).await?;
            state.restore_routes.push(msg.clone());
        } else {
            log::debug!("no IPv4 default route found");
        }
    }

    if tproxy_args.ipv6_default_route {
        if !route_exists(&IPV6_DEFAULT_ROUTE, ROUTING_TABLE_MAIN, true).await? {
            state
                .remove_routes
                .push(ip_route_add(&IPV6_DEFAULT_ROUTE, tun_name, ROUTING_TABLE_MAIN).await?);
        } else {
            state
                .remove_routes
                .push(ip_route_add(&IPV6_SPACE_LOWER, tun_name, ROUTING_TABLE_MAIN).await?);
            state
                .remove_routes
                .push(ip_route_add(&IPV6_SPACE_UPPER, tun_name, ROUTING_TABLE_MAIN).await?);
        }
    } else {
        // If IPv6 is not enabled, we do not want IPv6 traffic to bypass the proxy if a route
        // already exists.
        let default_route = ip_route_get(&IPV6_DEFAULT_ROUTE, ROUTING_TABLE_MAIN, true).await?;

        if let Some(msg) = default_route {
            ip_route_del_msg(&msg).await?;
            state.restore_routes.push(msg.clone());
        } else {
            log::debug!("no IPv6 default route found");
        }
    }

    setup_resolv_conf(state)?;

    detect_routing_loop(&proxy_cidr, tun_name).await?;

    Ok(())
}

pub(crate) async fn _tproxy_setup(tproxy_args: &TproxyArgs) -> Result<TproxyStateInner> {
    #[cfg(feature = "secure-state-file")]
    {
        return recovery::setup(tproxy_args).await;
    }
    #[cfg(not(feature = "secure-state-file"))]
    {
        let mut state: TproxyStateInner = TproxyStateInner {
            tproxy_args: Some(tproxy_args.clone()),
            ..Default::default()
        };
        let result = _tproxy_setup_inner(tproxy_args, &mut state).await;
        if result.is_err() {
            let remove_result = _tproxy_remove(&mut state).await;
            if let Err(remove_result) = &remove_result {
                log::error!("tproxy removal failed: {remove_result}");
            }
            result?;
        }
        Ok(state)
    }
}

async fn cleanup_pending<T>(
    items: &mut Vec<T>,
    mut operation: impl AsyncFnMut(&T) -> Result<()>,
) -> Result<()> {
    let mut first_error = None;
    let mut index = 0;
    while index < items.len() {
        match operation(&items[index]).await {
            Ok(()) => {
                items.remove(index);
            }
            Err(error) => {
                log::error!("network cleanup failed: {error}");
                first_error.get_or_insert(error);
                index += 1;
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

pub(crate) async fn _tproxy_remove(state: &mut TproxyStateInner) -> Result<()> {
    if state.tproxy_removed_done {
        return Ok(());
    }
    if state.tproxy_args.is_none() {
        return Err(std::io::Error::other("tproxy_args is None").into());
    }
    #[cfg(feature = "secure-state-file")]
    {
        return recovery::remove(state).await;
    }
    #[cfg(not(feature = "secure-state-file"))]
    {
        let tproxy_args = state.tproxy_args.as_ref().ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tproxy_args is None",
        ))?;

        let restore_result = cleanup_pending(&mut state.restore_routes, async |route| {
            ip_route_add_msg(route).await
        })
        .await;
        let remove_result = cleanup_pending(&mut state.remove_routes, async |route| {
            ip_route_del_msg(route).await
        })
        .await;

        let gateway_result = if let Some(items) = &mut state.restore_gateway_mode {
            cleanup_pending(items, async |restore| {
                run_command("iptables", &restore.split(' ').collect::<Vec<&str>>())
                    .map(|_| ())
                    .map_err(Into::into)
            })
            .await
        } else {
            Ok(())
        };
        let fwmark_result = cleanup_pending(&mut state.restore_socket_fwmark, async |entry| {
            ip_rule_del(entry.ip_version.clone(), entry.fwmark, entry.table).await
        })
        .await;
        let forwarding_result = if state.restore_ip_forwarding {
            let result = configure_ip_forwarding(false, false);
            if result.is_ok() {
                state.restore_ip_forwarding = false;
            }
            result
        } else {
            Ok(())
        };

        log::debug!("deleting link: {}", tproxy_args.tun_name);
        // sudo ip link del tun0
        let link_result = if restore_result.is_ok() && remove_result.is_ok() {
            match ip_link_del(&tproxy_args.tun_name).await {
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
                {
                    Ok(())
                }
                result => result,
            }
        } else {
            Ok(())
        };

        let unmount_result: Result<()> = if state.umount_resolvconf {
            log::debug!("unmounting {ETC_RESOLV_CONF_FILE}");
            let result = nix::mount::umount(ETC_RESOLV_CONF_FILE).map_err(Into::into);
            if result.is_ok() {
                state.umount_resolvconf = false;
            }
            result
        } else {
            Ok(())
        };

        let dns_result: Result<()> = if !state.umount_resolvconf
            && let Some(data) = &state.restore_resolvconf_content
        {
            let result = fs::write(ETC_RESOLV_CONF_FILE, data).map_err(Into::into);
            if result.is_ok() {
                state.restore_resolvconf_content = None;
            }
            result
        } else {
            Ok(())
        };

        flush_dns_cache()?;

        for result in [
            restore_result,
            remove_result,
            gateway_result,
            fwmark_result,
            forwarding_result,
            link_result,
            unmount_result,
            dns_result,
        ] {
            result?;
        }
        state.tproxy_removed_done = true;
        Ok(())
    }
}

pub(crate) fn flush_dns_cache() -> Result<()> {
    // do nothing in linux
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_rules_record_only_successful_commands_immediately() {
        let mut state = TproxyStateInner::default();
        let args = [
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            "tun-test",
            "-j",
            "MASQUERADE",
        ];
        apply_gateway_rule(&mut state, &args, |actual| {
            assert_eq!(actual, args);
            Ok(Vec::new())
        })
        .unwrap();
        let expected = vec!["-t nat -D POSTROUTING -o tun-test -j MASQUERADE".to_string()];
        assert_eq!(state.restore_gateway_mode.as_ref().unwrap(), &expected);
        assert!(
            apply_gateway_rule(&mut state, &["-A", "FORWARD", "-j", "ACCEPT"], |_| {
                Err(std::io::Error::other("injected command failure"))
            })
            .is_err()
        );
        assert_eq!(state.restore_gateway_mode.as_ref().unwrap(), &expected);
        assert!(
            apply_gateway_rule(&mut state, &["-D", "FORWARD"], |_| {
                panic!("invalid action must be rejected before executing")
            })
            .is_err()
        );
        assert_eq!(state.restore_gateway_mode.as_ref().unwrap(), &expected);
    }

    #[test]
    fn fwmark_setup_rejects_nonempty_ipv4_or_ipv6_tables() {
        let routes = vec![RouteMessage::default()];
        require_empty_fwmark_table(100, &[], &[]).unwrap();
        for (v4, v6) in [(routes.as_slice(), &[][..]), (&[][..], routes.as_slice())] {
            let error = require_empty_fwmark_table(100, v4, v6).unwrap_err();
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::AlreadyExists
            );
        }
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn fwmark_cleanup_requires_matching_table_mask_and_action() {
        use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
        let mut rule = RuleMessage::default();
        rule.header.action = RuleAction::ToTable;
        rule.header.table = 100;
        rule.attributes = vec![RuleAttribute::FwMark(42)];
        assert!(matches_fwmark_rule(&rule, 42, 100));
        assert!(!matches_fwmark_rule(&rule, 43, 100));
        assert!(!matches_fwmark_rule(&rule, 42, 101));
        rule.attributes.push(RuleAttribute::Table(1000));
        assert!(!matches_fwmark_rule(&rule, 42, 100));
        assert!(matches_fwmark_rule(&rule, 42, 1000));
        rule.attributes.push(RuleAttribute::FwMask(0xff));
        assert!(!matches_fwmark_rule(&rule, 42, 1000));
        *rule.attributes.last_mut().unwrap() = RuleAttribute::FwMask(u32::MAX);
        assert!(matches_fwmark_rule(&rule, 42, 1000));
        rule.header.action = RuleAction::Goto;
        assert!(!matches_fwmark_rule(&rule, 42, 1000));
        rule.header.action = RuleAction::ToTable;
        rule.attributes
            .retain(|attribute| !matches!(attribute, RuleAttribute::FwMark(_)));
        assert!(!matches_fwmark_rule(&rule, 0, 1000));
    }

    #[test]
    fn cleanup_attempts_every_item_and_retries_only_failures() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut items = vec![1, 2, 3, 4];
            let mut visited = Vec::new();
            let result = cleanup_pending(&mut items, async |item| {
                visited.push(*item);
                if *item == 2 || *item == 4 {
                    Err("injected failure".into())
                } else {
                    Ok(())
                }
            })
            .await;
            assert!(result.is_err());
            assert_eq!(visited, [1, 2, 3, 4]);
            assert_eq!(items, [2, 4]);
            visited.clear();
            cleanup_pending(&mut items, async |item| {
                visited.push(*item);
                Ok(())
            })
            .await
            .unwrap();
            assert_eq!(visited, [2, 4]);
            assert!(items.is_empty());
            cleanup_pending(&mut items, async |_| -> Result<()> {
                panic!("completed cleanup must not repeat operations")
            })
            .await
            .unwrap();
        });
    }

    #[test]
    fn failed_cleanup_remains_retryable_without_marking_done() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut state = TproxyStateInner::default();
        for _ in 0..2 {
            let error = runtime.block_on(_tproxy_remove(&mut state)).unwrap_err();
            assert!(error.to_string().contains("tproxy_args is None"));
            assert!(!state.tproxy_removed_done);
        }
        state.tproxy_removed_done = true;
        runtime.block_on(_tproxy_remove(&mut state)).unwrap();
    }
}
