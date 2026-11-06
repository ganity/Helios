//! Select an explicitly unmanaged resolver file or the standard systemd-resolved stub.
use std::{fs, io, net::IpAddr, os::unix::fs::MetadataExt};

pub async fn check_resolver() -> io::Result<()> {
    #[cfg(feature = "secure-state-file")]
    if uses_resolved()? {
        return super::resolved::preflight()
            .await
            .map_err(|error| io::Error::other(error.to_string()));
    }
    let path = crate::ETC_RESOLV_CONF_FILE;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 65_536
    {
        return Err(io::Error::other(
            "Linux TUN currently requires an unmanaged, root-owned regular /etc/resolv.conf; symlinks and writable/shared resolver files are unsupported",
        ));
    }
    check_contents(&fs::read_to_string(path)?)
}

#[cfg(feature = "secure-state-file")]
pub(super) fn uses_resolved() -> io::Result<bool> {
    let path = std::path::Path::new(crate::ETC_RESOLV_CONF_FILE);
    if !fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Ok(false);
    }
    // Only the stub routes all client queries through per-link DNS. The uplink file bypasses it.
    if fs::canonicalize(path)? != std::path::Path::new("/run/systemd/resolve/stub-resolv.conf") {
        return Err(io::Error::other(
            "unsupported resolver symlink; systemd-resolved requires its standard stub-resolv.conf",
        ));
    }
    let metadata = fs::metadata(path)?;
    if metadata.mode() & 0o022 != 0 || !metadata.is_file() || metadata.len() > 65_536 {
        return Err(io::Error::other("untrusted systemd-resolved stub file"));
    }
    let contents = fs::read_to_string(path)?;
    if !contents
        .lines()
        .any(|line| line.split_whitespace().collect::<Vec<_>>() == ["nameserver", "127.0.0.53"])
        || contents
            .lines()
            .filter(|line| line.trim_start().starts_with("nameserver"))
            .count()
            != 1
    {
        return Err(io::Error::other(
            "untrusted or unsupported systemd-resolved stub configuration",
        ));
    }
    Ok(true)
}

fn check_contents(contents: &str) -> io::Result<()> {
    // ponytail: markers cannot prove a regular file is unmanaged; only the resolved stub
    // has a native per-link backend. Other managers need an explicit backend before support.
    let lower = contents.to_ascii_lowercase();
    if [
        "systemd-resolved",
        "networkmanager",
        "resolvconf",
        "netconfig",
        "connman",
        "dhclient",
        "dhcpcd",
    ]
    .iter()
    .any(|manager| lower.contains(manager))
    {
        return Err(io::Error::other(
            "resolver is managed by another service; Linux TUN will not overwrite its DNS configuration",
        ));
    }
    let mut servers = 0;
    for line in contents.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("");
        let mut words = line.split_whitespace();
        match words.next() {
            Some("nameserver") => {
                let ip = words
                    .next()
                    .and_then(|value| value.parse::<IpAddr>().ok())
                    .ok_or_else(|| io::Error::other("invalid resolv.conf nameserver"))?;
                if ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || matches!(ip, IpAddr::V4(ip) if u32::from(ip) & 0xfffe_0000 == 0xc612_0000)
                    || matches!(ip, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() || u128::from(ip) >> 32 == 0xfdfe_dcba_9876_0000_0000_0000)
                {
                    return Err(io::Error::other(
                        "stub/Fake-IP resolver is unsupported; configure the DNS manager before enabling Linux TUN",
                    ));
                }
                servers += 1;
            }
            None | Some("search" | "domain" | "options" | "sortlist") => {}
            Some(_) => return Err(io::Error::other("unsupported resolv.conf directive")),
        }
    }
    if servers == 0 {
        return Err(io::Error::other(
            "resolv.conf has no real upstream nameserver",
        ));
    }
    Ok(())
}

#[cfg(feature = "secure-state-file")]
pub async fn upstreams() -> Result<Vec<IpAddr>, Box<dyn std::error::Error + Send + Sync>> {
    check_resolver().await?;
    if uses_resolved()? {
        return super::resolved::upstreams().await;
    }
    Ok(fs::read_to_string(crate::ETC_RESOLV_CONF_FILE)?
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver"))
                .then(|| words.next()?.parse().ok())
                .flatten()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plain_dns_preflight_preserves_managed_or_unknown_resolvers() {
        assert!(
            check_contents(
                "# static DNS\nnameserver 192.0.2.53\nsearch example.test\noptions timeout:2\n"
            )
            .is_ok()
        );
        assert!(check_contents("nameserver 2001:db8::53\n").is_ok());
        for content in [
            "nameserver 127.0.0.53\n",
            "# Generated by NetworkManager\nnameserver 192.0.2.53",
            "# systemd-resolved\nnameserver 192.0.2.53",
            "nameserver 198.18.0.0",
            "nameserver ::ffff:192.0.2.53",
            "nameserver nope",
            "",
            "unknown option\nnameserver 192.0.2.53",
        ] {
            assert!(check_contents(content).is_err(), "{content}");
        }
    }
}
