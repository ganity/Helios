use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tun::AbstractDevice;
#[cfg(target_os = "linux")]
#[path = "linux/desktop.rs"]
pub(super) mod desktop;

/// Refuse unsupported DNS managers or an existing interface before creating status or changing routes.
pub(super) async fn preflight(config: &HelperConfig) -> Result<(), AnyError> {
    #[cfg(target_os = "macos")]
    tproxy_config::macos_uplink_snapshot(config.ipv6_enabled)?;
    #[cfg(target_os = "linux")]
    tproxy_config::check_linux_resolver().await?;
    #[cfg(target_os = "linux")]
    if let Some(name) = &config.tun_name
        && Path::new("/sys/class/net").join(name).exists()
    {
        return Err(
            "requested TUN name already exists; refusing to configure another interface".into(),
        );
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        check_dns_gateway(config.socks_listen),
    )
    .await??;
    Ok(())
}

// The general tun2proxy API cannot pass source_bypass; own setup and await cleanup on every outcome.
pub(super) async fn run(
    config: &HelperConfig,
    mut args: Args,
    shutdown: CancellationToken,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> std::io::Result<usize> {
    let mut tun_config = tun::Configuration::default();
    tun_config
        .address(tproxy_config::TUN_IPV4)
        .netmask(tproxy_config::TUN_NETMASK)
        .destination(helios_dns::TUN_DNS)
        .mtu(config.mtu)
        .up();
    if let Some(name) = &config.tun_name {
        tun_config.tun_name(name);
    }
    // Use raw IP frames, without the optional Linux packet-information prefix.
    #[cfg(target_os = "linux")]
    tun_config.platform_config(|platform| {
        platform.ensure_root_privileges(true);
    });
    #[cfg(target_os = "macos")]
    tun_config.platform_config(|platform| {
        // Keep utun framing, but leave every explicit route mutation to the journal.
        platform.packet_information(true).enable_routing(false);
    });
    let device = tun::create_as_async(&tun_config)?;
    let routes = tproxy_config::TproxyArgs::new()
        .tun_name(&device.tun_name()?)
        .tun_mtu(config.mtu)
        .tun_gateway(helios_dns::TUN_DNS)
        .tun_dns(helios_dns::TUN_DNS)
        .proxy_addr(args.proxy.addr)
        .bypass_ips(&args.bypass)
        .source_bypass(&config.source_bypass)
        .ipv6_default_route(config.ipv6_enabled);
    let restore = tproxy_config::tproxy_setup(&routes).await?;
    // One Fake-IP cache lives in daemon for both A/AAAA. Transcode TUN UDP DNS to SOCKS TCP DNS.
    args.setup = false;
    args.dns = ArgDns::OverTcp;
    args.dns_addr = helios_dns::TUN_DNS;
    let maximum = args.max_sessions;
    let run = tun2proxy::run(device, config.mtu, args, shutdown.clone());
    tokio::pin!(run);
    let result = if let Some(ready) = ready {
        // Poll the real data plane while testing its DNS path; only then report ready.
        let probe = tokio::time::timeout(std::time::Duration::from_secs(5), probe_tun_dns());
        tokio::pin!(probe);
        tokio::select! {
            result = &mut run => result,
            probe = &mut probe => {
                match probe {
                    Ok(Ok(())) => { let _ = ready.send(()); }
                    error => {
                        shutdown.cancel();
                        let _ = (&mut run).await;
                        let cleanup = tproxy_remove(Some(restore)).await;
                        return Err(std::io::Error::other(format!("TUN readiness probe failed: {error:?}; cleanup: {cleanup:?}")));
                    }
                }
                run.await
            }
        }
    } else {
        run.await
    };
    let cleanup = tproxy_remove(Some(restore)).await;
    match (result, cleanup) {
        (result, Err(error)) => Err(std::io::Error::other(format!(
            "TUN stopped ({result:?}); route/DNS recovery remains pending: {error}"
        ))),
        (Err(error), Ok(())) => Err(std::io::Error::other(error)),
        (Ok(sessions), Ok(())) if sessions >= maximum => Err(std::io::Error::other(
            "TUN stopped after reaching its session limit",
        )),
        (Ok(sessions), Ok(())) => Ok(sessions),
    }
}

/// An old/unbound daemon rejects this reserved target. Verify the shared DNS cache before setup.
async fn check_dns_gateway(socks: SocketAddr) -> Result<(), AnyError> {
    use hickory_proto::{
        op::{Message, Query},
        rr::{Name, RData, RecordType},
    };
    let mut stream = tokio::net::TcpStream::connect(socks).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err("daemon SOCKS5 negotiation failed".into());
    }
    let IpAddr::V4(ip) = helios_dns::TUN_DNS else {
        unreachable!()
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&53u16.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await?;
    if reply[..3] != [5, 0, 0] {
        return Err("TUN requires a running source-bound daemon with DNS enabled".into());
    }
    let length = match reply[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await? as usize,
        _ => return Err("invalid SOCKS5 reply".into()),
    };
    stream.read_exact(&mut vec![0; length + 2]).await?;
    let mut query = Message::query();
    query.metadata.id = 0x484c;
    query.add_query(Query::query(
        Name::from_str("helios-tun-probe.invalid.")?,
        RecordType::AAAA,
    ));
    let bytes = query.to_vec()?;
    stream.write_u16(bytes.len().try_into()?).await?;
    stream.write_all(&bytes).await?;
    let length = stream.read_u16().await? as usize;
    if length > 4096 {
        return Err("oversized daemon DNS probe response".into());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    let response = Message::from_vec(&bytes)?;
    if response.id != query.id || response.queries != query.queries || !response.answers.iter().any(|record| matches!(&record.data, RData::AAAA(ip) if helios_dns::is_fake_ip(IpAddr::V6(ip.0)))) {
        return Err("daemon DNS gateway did not return a dual-stack Fake-IP answer".into());
    }
    Ok(())
}

pub(super) async fn probe_tun_dns() -> Result<(), AnyError> {
    let mut stream = tokio::net::TcpStream::connect((helios_dns::TUN_DNS, 53)).await?;
    let query = hickory_proto::op::Message::query()
        .add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_str("helios-tun-ready.invalid.")?,
            hickory_proto::rr::RecordType::AAAA,
        ))
        .to_vec()?;
    stream.write_u16(query.len().try_into()?).await?;
    stream.write_all(&query).await?;
    let size = stream.read_u16().await? as usize;
    if size > 4096 {
        return Err("oversized TUN DNS probe".into());
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    let reply = hickory_proto::op::Message::from_vec(&bytes)?;
    if !reply.answers.iter().any(|r| matches!(&r.data, hickory_proto::rr::RData::AAAA(ip) if helios_dns::is_fake_ip(IpAddr::V6(ip.0)))) {
        return Err("TUN DNS probe did not reach the shared cache".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "requires root on a disposable macOS GitHub runner; changes TUN routes and DNS"]
    async fn macos_real_tun_dns_readiness_and_network_restoration() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(
            std::process::Command::new("/usr/bin/id")
                .arg("-u")
                .output()
                .unwrap()
                .stdout,
            b"0\n"
        );
        let before = tproxy_config::macos_uplink_snapshot(false).unwrap();
        let directory =
            std::env::temp_dir().join(format!("helios-tun-smoke-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let lease = directory.join("lease.json");
        tproxy_config::set_state_file_path(lease.clone()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = crate::tests::config();
        config.socks_listen = listener.local_addr().unwrap();
        config.source_bypass = before.0.clone();
        let pool = helios_dns::FakeIpPool::new(8, std::time::Duration::from_secs(30)).unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let pool = pool.clone();
                tokio::spawn(async move {
                    let mut greeting = [0; 3];
                    stream.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 1, 0]);
                    stream.write_all(&[5, 0]).await.unwrap();
                    let mut request = [0; 10];
                    stream.read_exact(&mut request).await.unwrap();
                    assert_eq!(&request[4..8], &[198, 18, 0, 0]);
                    stream
                        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                        .await
                        .unwrap();
                    helios_dns::serve_tcp(stream, pool).await.unwrap();
                });
            }
        });
        let preflight = preflight(&config).await;
        assert!(preflight.is_ok(), "{preflight:?}");
        let shutdown = CancellationToken::new();
        let (ready, ready_rx) = tokio::sync::oneshot::channel();
        let session = run(
            &config,
            config.tun_args().unwrap(),
            shutdown.clone(),
            Some(ready),
        );
        tokio::pin!(session);
        let (ready, ended) = tokio::select! {
            result = &mut session => (Err(format!("TUN ended before readiness: {result:?}")), true),
            result = tokio::time::timeout(std::time::Duration::from_secs(15), ready_rx) => (result.map_err(|error| error.to_string()).and_then(|result|result.map_err(|error|error.to_string())), false),
        };
        shutdown.cancel();
        // Always finish cleanup before asserting, including failed readiness.
        let stopped = if !ended {
            Some(tokio::time::timeout(std::time::Duration::from_secs(15), &mut session).await)
        } else {
            None
        };
        if lease.exists() {
            tproxy_config::tproxy_remove(None).await.unwrap();
        }
        server.abort();
        let after = tproxy_config::macos_uplink_snapshot(false).unwrap();
        assert_eq!(before, after, "physical uplink and DNS must be restored");
        assert!(!lease.exists());
        fs::remove_dir(directory).unwrap();
        assert!(ready.is_ok(), "{ready:?}");
        assert!(matches!(stopped, Some(Ok(Ok(_)))), "{stopped:?}");
    }

    #[tokio::test]
    async fn dns_preflight_accepts_shared_cache_and_rejects_old_socks_servers() {
        for enabled in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let worker = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 10];
                stream.read_exact(&mut request).await.unwrap();
                assert_eq!(&request[4..8], &[198, 18, 0, 0]);
                stream
                    .write_all(&[5, if enabled { 0 } else { 1 }, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                if enabled {
                    let pool =
                        helios_dns::FakeIpPool::new(8, std::time::Duration::from_secs(30)).unwrap();
                    helios_dns::serve_tcp(stream, pool).await.unwrap();
                }
            });
            assert_eq!(check_dns_gateway(address).await.is_ok(), enabled);
            worker.await.unwrap();
        }
    }
}
