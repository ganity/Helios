use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpStream, lookup_host},
    sync::Mutex as AsyncMutex,
    task::JoinSet,
};

type LookupResult = Result<Vec<IpAddr>, (io::ErrorKind, String)>;
type Answer = Option<(Instant, LookupResult)>;
type Entry = Arc<AsyncMutex<Answer>>;
const CAPACITY: usize = 256;
// The system resolver exposes no DNS TTL; do not retain answers beyond this short cap.
const CACHE_AGE: Duration = Duration::from_secs(30);

#[derive(Default)]
struct Resolver {
    entries: Mutex<HashMap<String, Entry>>,
}

impl Resolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let key = host.to_ascii_lowercase();
        let entry = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = entries.get(&key) {
                entry.clone()
            } else {
                if entries.len() >= CAPACITY {
                    let victim = entries
                        .iter()
                        .find(|(_, e)| Arc::strong_count(e) == 1)
                        .map(|(k, _)| k.clone());
                    if let Some(victim) = victim {
                        entries.remove(&victim);
                    }
                }
                let entry = Arc::new(AsyncMutex::new(None));
                if entries.len() < CAPACITY {
                    entries.insert(key, entry.clone());
                }
                entry
            }
        };
        // The per-host lock coalesces lookups, and cancellation always releases it.
        let mut answer = entry.lock().await;
        if let Some((at, result)) = answer.as_ref()
            && at.elapsed()
                < if result.is_ok() {
                    CACHE_AGE
                } else {
                    Duration::from_secs(1)
                }
        {
            return result
                .clone()
                .map_err(|(kind, message)| io::Error::new(kind, message));
        }
        let result = async {
            let mut ips = Vec::new();
            for address in lookup_host((host, 0)).await? {
                if !ips.contains(&address.ip()) {
                    ips.push(address.ip());
                }
            }
            if ips.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no target addresses",
                ));
            }
            Ok(ips)
        }
        .await;
        *answer = Some((
            Instant::now(),
            result
                .as_ref()
                .map(Clone::clone)
                .map_err(|error: &io::Error| (error.kind(), error.to_string())),
        ));
        result
    }
}

pub(crate) async fn connect_target(target: &helios_protocol::Target) -> io::Result<TcpStream> {
    let start = Instant::now();
    let ips = match &target.address {
        helios_protocol::Address::Ip(ip) => vec![*ip],
        helios_protocol::Address::Domain(host) => {
            static RESOLVER: OnceLock<Resolver> = OnceLock::new();
            tracing::debug!(event = "target_dns_started");
            let result = RESOLVER.get_or_init(Resolver::default).resolve(host).await;
            tracing::debug!(
                event = "target_dns",
                elapsed_ms = start.elapsed().as_millis() as u64,
                success = result.is_ok()
            );
            result?
        }
    };
    let start = Instant::now();
    tracing::debug!(event = "target_tcp_started");
    let result = race_addresses(ips, target.port).await;
    tracing::debug!(
        event = "target_tcp_finished",
        elapsed_ms = start.elapsed().as_millis() as u64,
        success = result.is_ok()
    );
    result
}

async fn race_addresses(ips: Vec<IpAddr>, port: u16) -> io::Result<TcpStream> {
    // Interleave address families so a broken first family cannot consume the whole deadline.
    let first_v6 = ips.first().is_some_and(IpAddr::is_ipv6);
    let (mut first, mut other): (Vec<_>, Vec<_>) =
        ips.into_iter().partition(|ip| ip.is_ipv6() == first_v6);
    first.reverse();
    other.reverse();
    let mut ordered = Vec::new();
    while !first.is_empty() || !other.is_empty() {
        if let Some(ip) = first.pop() {
            ordered.push(ip);
        }
        if let Some(ip) = other.pop() {
            ordered.push(ip);
        }
    }
    let mut addresses = ordered.into_iter();
    let mut pending = JoinSet::new();
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no target addresses");
    let mut next = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(next), if addresses.len() > 0 => {
                let ip = addresses.next().unwrap();
                pending.spawn(TcpStream::connect((ip, port)));
                next = tokio::time::Instant::now() + Duration::from_millis(250);
            }
            result = pending.join_next(), if !pending.is_empty() => {
                match result.unwrap() {
                    Ok(Ok(stream)) => { super::tls::configure_tcp(&stream)?; return Ok(stream); }
                    Ok(Err(error)) => last = error,
                    Err(error) => last = io::Error::other(error),
                }
                if pending.is_empty() { next = tokio::time::Instant::now(); }
            }
            else => return Err(last),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn lookup_failure_is_shared_only_for_one_second() {
        let resolver = Resolver::default();
        let entry = Arc::new(AsyncMutex::new(Some((
            Instant::now(),
            Err((io::ErrorKind::NotFound, "shared failure".into())),
        ))));
        resolver
            .entries
            .lock()
            .unwrap()
            .insert("localhost".into(), entry.clone());
        let (a, b) = tokio::join!(resolver.resolve("localhost"), resolver.resolve("localhost"));
        assert_eq!(a.unwrap_err().to_string(), "shared failure");
        assert_eq!(b.unwrap_err().to_string(), "shared failure");
        entry.lock().await.as_mut().unwrap().0 = Instant::now() - Duration::from_secs(1);
        assert!(!resolver.resolve("localhost").await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn cache_is_bounded_when_entries_are_busy() {
        let resolver = Resolver::default();
        let held: Vec<_> = (0..CAPACITY)
            .map(|i| {
                let entry = Arc::new(AsyncMutex::new(None));
                resolver
                    .entries
                    .lock()
                    .unwrap()
                    .insert(format!("host-{i}"), entry.clone());
                entry
            })
            .collect();
        resolver.resolve("localhost").await.unwrap();
        assert_eq!(resolver.entries.lock().unwrap().len(), CAPACITY);
        drop(held);
        resolver.resolve("localhost").await.unwrap();
        assert_eq!(resolver.entries.lock().unwrap().len(), CAPACITY);
        assert!(resolver.entries.lock().unwrap().contains_key("localhost"));
    }
    #[tokio::test]
    async fn cached_lookup_coalesces_and_expires() {
        let resolver = Resolver::default();
        let (a, b) = tokio::join!(resolver.resolve("localhost"), resolver.resolve("LOCALHOST"));
        assert_eq!(a.unwrap(), b.unwrap());
        let entry = resolver.entries.lock().unwrap()["localhost"].clone();
        *entry.lock().await = Some((Instant::now(), Ok(vec!["192.0.2.1".parse().unwrap()])));
        assert_eq!(
            resolver.resolve("localhost").await.unwrap()[0],
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
        entry.lock().await.as_mut().unwrap().0 = Instant::now() - CACHE_AGE;
        assert_ne!(
            resolver.resolve("localhost").await.unwrap()[0],
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
    }
    #[tokio::test]
    async fn failed_address_does_not_block_working_family() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = tokio::time::timeout(
            Duration::from_secs(1),
            race_addresses(
                vec!["::1".parse().unwrap(), "127.0.0.1".parse().unwrap()],
                listener.local_addr().unwrap().port(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(stream.peer_addr().unwrap().is_ipv4());
    }

    #[tokio::test]
    async fn connects_to_an_ipv6_target() {
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let target = helios_protocol::Target::new(
            helios_protocol::Address::Ip("::1".parse().unwrap()),
            listener.local_addr().unwrap().port(),
        )
        .unwrap();
        let stream = connect_target(&target).await.unwrap();
        assert!(stream.peer_addr().unwrap().is_ipv6());
    }
}
