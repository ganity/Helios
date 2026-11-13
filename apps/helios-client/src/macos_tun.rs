//! macOS authorization adapts the shared desktop TUN session and bound daemon.
use super::*;
use helios_config::OutboundConfig;

pub(super) fn prepare(id: u64, ipv6: bool, events: Sender<Event>) {
    thread::spawn(move || {
        let result = (|| {
            let (source_bypass, dns) = tproxy_config::macos_uplink_snapshot(ipv6)?;
            let config = OutboundConfig {
                source_bypass,
                dns_servers: dns.into_iter().map(|ip| SocketAddr::new(ip, 53)).collect(),
            };
            config.validate()?;
            Ok(config)
        })()
        .map_err(|error: AnyError| error.to_string());
        let _ = events.send(Event::TunPrepared(id, result));
    });
}

pub(super) fn recover(profile: &DesktopProfile, events: Sender<Event>) {
    let profile = profile.clone();
    thread::spawn(move || {
        let result = (|| {
            write_atomic(
                &profile.helper_config,
                profile.helper_config_toml()?.as_bytes(),
            )?;
            launch_helper_elevated(&profile.helper_binary, &profile.helper_config, true)
        })()
        .map_err(|error| error.to_string());
        let _ = events.send(Event::TunRecovered(result));
    });
}

pub(super) fn launch(
    id: u64,
    profile: DesktopProfile,
    cancel: Arc<AtomicBool>,
    events: Sender<Event>,
) {
    thread::spawn(move || {
        let result =
            launch_inner(id, &profile, &cancel, &events).map_err(|error| error.to_string());
        let _ = events.send(Event::TunEnded(id, result));
    });
}

fn launch_inner(
    id: u64,
    profile: &DesktopProfile,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<(), AnyError> {
    let outbound = profile
        .tun_outbound
        .as_ref()
        .ok_or("missing TUN outbound policy")?;
    let socks = profile.socks_listen.parse()?;
    run_async(async {
        for _ in 0..80 {
            if cancel.load(Ordering::Relaxed) {
                return Ok(());
            }
            if let Ok(Ok(info)) =
                tokio::time::timeout(Duration::from_millis(500), daemon_info(socks)).await
                && &info.outbound == outbound
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("source-bound daemon did not become ready".into())
    })?;
    if cancel.load(Ordering::Relaxed) {
        return Ok(());
    }
    write_atomic(
        &profile.helper_config,
        profile.helper_config_toml()?.as_bytes(),
    )?;
    launch_helper_elevated(&profile.helper_binary, &profile.helper_config, false)?;
    let started = Instant::now();
    let mut seen = false;
    let mut ready = false;
    loop {
        let fresh = status_is_fresh(&tun_status_file());
        seen |= fresh;
        if fresh
            && !ready
            && std::fs::read_to_string(tun_status_file())
                .is_ok_and(|text| text.starts_with("ready:"))
        {
            ready = true;
            let _ = events.send(Event::TunReady(id));
        }
        if cancel.load(Ordering::Relaxed) || (!ready && started.elapsed() > Duration::from_secs(15))
        {
            // Repeat until the helper exits: its startup may precede creation of the stop marker.
            write_atomic(&tun_stop_file(), b"stop")?;
        }
        if (ready && seen && !fresh) || (!ready && started.elapsed() > Duration::from_secs(15)) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    if tun_status_file().exists() || (!ready && !cancel.load(Ordering::Relaxed)) {
        return Err("TUN 启停失败，正在检查并恢复网络设置；详细信息见 helper.log".into());
    }
    Ok(())
}
