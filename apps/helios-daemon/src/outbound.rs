use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use helios_config::OutboundConfig;
use helios_protocol::{Address, Target};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

/// One immutable policy shared by every outbound path, including node health probes.
#[derive(Clone, Default)]
pub(super) struct Outbound {
    pub(super) config: Option<OutboundConfig>,
    cache: Arc<Mutex<HashMap<DnsKey, DnsSlot>>>,
}

type DnsKey = (String, Option<RecordType>);
type DnsSlot = Arc<tokio::sync::Mutex<Option<CacheEntry>>>;

struct CacheEntry {
    expires: Instant,
    result: Result<Vec<IpAddr>, (io::ErrorKind, String)>,
}

impl CacheEntry {
    fn result(&self) -> io::Result<Vec<IpAddr>> {
        self.result
            .clone()
            .map_err(|(kind, message)| io::Error::new(kind, message))
    }
}

impl Outbound {
    pub async fn evaluate_route(
        &self,
        rules: &helios_routing::RuleSet,
        target: &Target,
        network: helios_routing::Network,
    ) -> helios_control::RouteTestReport {
        let mut resolved_ips = Vec::new();
        let mut dns_error = None;
        let (action, rule_index, selected_ips) = match rules.evaluate_from(target, network, None, 0)
        {
            Ok(decision) => decision,
            Err(cursor) => {
                match self.resolve(target).await {
                    Ok(ips) => resolved_ips = ips,
                    Err(error) => dns_error = Some(error.to_string()),
                }
                rules
                    .evaluate_from(target, network, Some(&resolved_ips), cursor)
                    .expect("resolved route evaluation")
            }
        };
        helios_control::RouteTestReport {
            action,
            rule_index,
            selected_ips,
            resolved_ips,
            dns_error,
        }
    }
    pub fn new(config: Option<OutboundConfig>) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub fn clear_cache(&self) {
        self.cache.lock().expect("DNS cache poisoned").clear();
    }

    async fn cached_lookup(&self, host: &str, kind: Option<RecordType>) -> io::Result<Vec<IpAddr>> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let key = (host.trim_end_matches('.').to_ascii_lowercase(), kind);
        let slot = {
            let mut cache = self.cache.lock().expect("DNS cache poisoned");
            if !cache.contains_key(&key) && cache.len() >= 1024 {
                // In-flight slots must not be evicted, or concurrent callers would duplicate DNS.
                let victim = cache
                    .iter()
                    .find(|(_, slot)| Arc::strong_count(slot) == 1)
                    .map(|(key, _)| key.clone());
                if let Some(victim) = victim {
                    cache.remove(&victim);
                } else {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
            }
            cache.entry(key.clone()).or_default().clone()
        };
        let mut entry = tokio::time::timeout_at(deadline, slot.lock())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        if let Some(value) = entry
            .as_ref()
            .filter(|value| value.expires > Instant::now())
        {
            return value.result();
        }
        let result = tokio::time::timeout_at(deadline, async {
            match kind {
                Some(kind) => self.lookup(&key.0, kind).await,
                None => Ok((
                    tokio::net::lookup_host((key.0.as_str(), 0))
                        .await?
                        .map(|address| address.ip())
                        .collect(),
                    30,
                )),
            }
        })
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
        let ttl = match &result {
            Ok((ips, ttl)) if !ips.is_empty() => (*ttl).min(300),
            _ => 2,
        };
        *entry = Some(CacheEntry {
            expires: Instant::now() + Duration::from_secs(ttl.into()),
            result: result
                .map(|(ips, _)| ips)
                .map_err(|error| (error.kind(), error.to_string())),
        });
        entry.as_ref().unwrap().result()
    }
    pub fn source(&self, destination: SocketAddr) -> io::Result<Option<IpAddr>> {
        match &self.config {
            None => Ok(None),
            Some(config) => config
                .source_bypass
                .iter()
                .find(|source| source.is_ipv4() == destination.is_ipv4())
                .copied()
                .map(Some)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "no uplink source for target IP family",
                    )
                }),
        }
    }

    pub async fn node_tcp(&self, destination: SocketAddr) -> io::Result<TcpStream> {
        helios_transport::connect_node_tcp_bound(destination, self.source(destination)?).await
    }

    pub fn quic(&self, destination: SocketAddr) -> io::Result<quinn::Endpoint> {
        helios_transport::client_quic_endpoint_bound(destination, self.source(destination)?)
    }

    pub async fn udp(&self, ipv6: bool) -> io::Result<UdpSocket> {
        let any = if ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let source = self.source(SocketAddr::new(any, 0))?.unwrap_or(any);
        UdpSocket::bind((source, 0)).await
    }

    pub async fn connect(
        &self,
        target: &Target,
        protected: &[SocketAddr],
    ) -> io::Result<TcpStream> {
        let mut ips = self.resolve(target).await?;
        self.connect_ips(target.port, &mut ips, protected).await
    }

    pub async fn connect_ips(
        &self,
        port: u16,
        ips: &mut Vec<IpAddr>,
        protected: &[SocketAddr],
    ) -> io::Result<TcpStream> {
        ips.retain(|ip| !protected.contains(&SocketAddr::new(*ip, port)));
        helios_transport::connect_tcp_ips(
            ips.clone(),
            port,
            self.config
                .as_ref()
                .map(|config| config.source_bypass.as_slice()),
        )
        .await
    }

    pub async fn resolve(&self, target: &Target) -> io::Result<Vec<IpAddr>> {
        let ips = match &target.address {
            Address::Ip(ip) => vec![*ip],
            Address::Domain(host) => match &self.config {
                None => self.cached_lookup(host, None).await?,
                Some(config) => {
                    let (a, aaaa) = tokio::join!(
                        async {
                            if config.source_bypass.iter().any(IpAddr::is_ipv4) {
                                self.cached_lookup(host, Some(RecordType::A)).await
                            } else {
                                Ok(Vec::new())
                            }
                        },
                        async {
                            if config.source_bypass.iter().any(IpAddr::is_ipv6) {
                                self.cached_lookup(host, Some(RecordType::AAAA)).await
                            } else {
                                Ok(Vec::new())
                            }
                        },
                    );
                    match (a, aaaa) {
                        (Ok(mut a), Ok(aaaa)) => {
                            a.extend(aaaa);
                            a
                        }
                        (Ok(ips), Err(_)) | (Err(_), Ok(ips)) if !ips.is_empty() => ips,
                        (Err(error), _) | (_, Err(error)) => return Err(error),
                    }
                }
            },
        };
        if ips.iter().any(|ip| helios_dns::is_fake_ip(*ip)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "real DNS/Direct target contains a Fake-IP address",
            ));
        }
        let mut result = Vec::new();
        for ip in ips {
            let ip = match ip {
                IpAddr::V6(ip) => ip
                    .to_ipv4_mapped()
                    .map(IpAddr::V4)
                    .unwrap_or(IpAddr::V6(ip)),
                ip => ip,
            };
            if ip.is_unspecified() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unspecified Direct target",
                ));
            }
            if !result.contains(&ip) && self.source(SocketAddr::new(ip, target.port)).is_ok() {
                result.push(ip);
            }
        }
        if result.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no usable real target addresses",
            ));
        }
        Ok(result)
    }

    async fn lookup(&self, host: &str, kind: RecordType) -> io::Result<(Vec<IpAddr>, u32)> {
        let config = self
            .config
            .as_ref()
            .expect("explicit resolver requires outbound config");
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no real DNS servers");
        for server in &config.dns_servers {
            match timeout(
                Duration::from_secs(3),
                self.query_chain(host, kind, *server),
            )
            .await
            {
                Ok(Ok(ips)) => return Ok(ips),
                Ok(Err(error)) => last = error,
                Err(_) => {
                    last = io::Error::new(io::ErrorKind::TimedOut, "real DNS query timed out")
                }
            }
        }
        Err(last)
    }

    async fn query_chain(
        &self,
        host: &str,
        kind: RecordType,
        server: SocketAddr,
    ) -> io::Result<(Vec<IpAddr>, u32)> {
        let mut ttl = u32::MAX;
        let mut name = Name::from_ascii(host).map_err(io::Error::other)?;
        name.set_fqdn(true);
        let mut visited = Vec::new();
        for _ in 0..8 {
            if visited.contains(&name) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS CNAME cycle",
                ));
            }
            visited.push(name.clone());
            let mut request = Message::query();
            let mut id = [0; 2];
            getrandom::fill(&mut id).map_err(io::Error::other)?;
            request.metadata.id = u16::from_ne_bytes(id);
            request.metadata.recursion_desired = true;
            request.add_query(Query::query(name.clone(), kind));
            let response = self.exchange(server, &request).await?;
            match response.response_code {
                ResponseCode::NoError => {}
                ResponseCode::NXDomain => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "DNS name does not exist",
                    ));
                }
                _ => return Err(io::Error::other("DNS upstream returned an error")),
            }
            let start = name.clone();
            // Accept only IN records belonging to the query or its CNAME chain, never unrelated glue.
            for _ in 0..8 {
                for record in response.answers.iter().filter(|record| {
                    record.name == name
                        && record.dns_class == DNSClass::IN
                        && (record.record_type() == kind
                            || record.record_type() == RecordType::CNAME)
                }) {
                    ttl = ttl.min(record.ttl);
                }
                let ips: Vec<_> = response
                    .answers
                    .iter()
                    .filter(|record| record.name == name && record.dns_class == DNSClass::IN)
                    .filter_map(|record| match (&record.data, kind) {
                        (RData::A(ip), RecordType::A) => Some(IpAddr::V4(ip.0)),
                        (RData::AAAA(ip), RecordType::AAAA) => Some(IpAddr::V6(ip.0)),
                        _ => None,
                    })
                    .collect();
                if !ips.is_empty() {
                    return Ok((ips, ttl));
                }
                let alias = response
                    .answers
                    .iter()
                    .filter(|record| record.name == name && record.dns_class == DNSClass::IN)
                    .find_map(|record| match &record.data {
                        RData::CNAME(alias) => Some(alias.0.clone()),
                        _ => None,
                    });
                let Some(alias) = alias else {
                    break;
                };
                if visited.contains(&alias) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DNS CNAME cycle",
                    ));
                }
                visited.push(name.clone());
                name = alias;
            }
            if name == start {
                return Ok((Vec::new(), 2));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS CNAME chain exceeds limit",
        ))
    }

    async fn exchange(&self, server: SocketAddr, request: &Message) -> io::Result<Message> {
        let bytes = request.to_vec().map_err(io::Error::other)?;
        let socket = self.udp(server.is_ipv6()).await?;
        socket.connect(server).await?;
        socket.send(&bytes).await?;
        let mut buffer = vec![0; 65_535];
        let response = loop {
            let length = socket.recv(&mut buffer).await?;
            let Ok(response) = Message::from_vec(&buffer[..length]) else {
                continue;
            };
            if matches_request(request, &response) {
                break response;
            }
        };
        if !response.truncation {
            return Ok(response);
        }
        let mut tcp = helios_transport::tcp_socket(server, self.source(server)?)?
            .connect(server)
            .await?;
        tcp.write_u16(bytes.len().try_into().map_err(io::Error::other)?)
            .await?;
        tcp.write_all(&bytes).await?;
        let length = tcp.read_u16().await? as usize;
        tcp.read_exact(&mut buffer[..length]).await?;
        let response = Message::from_vec(&buffer[..length]).map_err(io::Error::other)?;
        if !matches_request(request, &response) || response.truncation {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TCP DNS response",
            ));
        }
        Ok(response)
    }
}

fn matches_request(request: &Message, response: &Message) -> bool {
    request.id == response.id
        && response.message_type == MessageType::Response
        && response.op_code == OpCode::Query
        && response.queries == request.queries
}

pub(super) async fn receive(
    socket: &Option<UdpSocket>,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    match socket {
        Some(socket) => socket.recv_from(buffer).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{
        Record,
        rdata::{A, CNAME},
    };
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn cancelled_lookup_releases_waiters_and_cache_capacity_is_bounded() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound = bound("127.0.0.1", server.local_addr().unwrap());
        let (started, ready) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            let mut bytes = [0; 1024];
            server.recv_from(&mut bytes).await.unwrap();
            started.send(()).unwrap();
            let (length, peer) = server.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..length]).unwrap();
            server
                .send_to(&answer(&request, "182.92.244.55").to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let clone = outbound.clone();
        let first =
            tokio::spawn(async move { clone.resolve(&domain_target("cancel.example")).await });
        ready.await.unwrap();
        first.abort();
        let _ = first.await;
        assert!(
            timeout(
                Duration::from_secs(2),
                outbound.resolve(&domain_target("cancel.example"))
            )
            .await
            .unwrap()
            .is_ok()
        );
        worker.await.unwrap();
        outbound.clear_cache();
        let mut active = Vec::new();
        {
            let mut cache = outbound.cache.lock().unwrap();
            for index in 0..1024 {
                let slot: DnsSlot = Arc::default();
                cache.insert(
                    (format!("{index}.example"), Some(RecordType::A)),
                    slot.clone(),
                );
                active.push(slot);
            }
        }
        assert_eq!(
            outbound
                .cached_lookup("overflow.example", Some(RecordType::A))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(outbound.cache.lock().unwrap().len(), 1024);
    }

    #[tokio::test]
    async fn stalled_dns_has_a_total_deadline_and_caches_the_failure() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound = bound("127.0.0.1", server.local_addr().unwrap());
        let started = Instant::now();
        assert_eq!(
            outbound
                .resolve(&domain_target("timeout.example"))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        let started = Instant::now();
        assert_eq!(
            outbound
                .resolve(&domain_target("timeout.example"))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(started.elapsed() < Duration::from_millis(250));
        drop(server);
    }

    #[tokio::test]
    async fn dns_cache_coalesces_and_expires_and_is_scoped_to_policy() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound = bound("127.0.0.1", server.local_addr().unwrap());
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        let worker = tokio::spawn(async move {
            let mut buffer = [0; 1024];
            loop {
                let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let request = Message::from_vec(&buffer[..length]).unwrap();
                let mut response = answer(&request, "182.92.244.55");
                if request.queries[0].name().to_ascii().starts_with("missing.") {
                    response.answers.clear();
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
                server
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let mut jobs = Vec::new();
        for _ in 0..16 {
            let outbound = outbound.clone();
            jobs.push(tokio::spawn(async move {
                outbound
                    .cached_lookup("Cache.Example.", Some(RecordType::A))
                    .await
                    .unwrap()
            }));
        }
        for job in jobs {
            assert_eq!(
                job.await.unwrap(),
                vec!["182.92.244.55".parse::<IpAddr>().unwrap()]
            );
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let slot = outbound
            .cache
            .lock()
            .unwrap()
            .get(&("cache.example".into(), Some(RecordType::A)))
            .unwrap()
            .clone();
        slot.lock().await.as_mut().unwrap().expires = Instant::now();
        outbound
            .resolve(&domain_target("cache.example"))
            .await
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        for _ in 0..2 {
            assert!(
                outbound
                    .resolve(&domain_target("missing.example"))
                    .await
                    .is_err()
            );
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        let replacement = Outbound::new(outbound.config.clone());
        replacement
            .resolve(&domain_target("cache.example"))
            .await
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 4);
        outbound.clear_cache();
        outbound
            .resolve(&domain_target("cache.example"))
            .await
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 5);
        worker.abort();
    }

    #[tokio::test]
    async fn cname_ttl_zero_prevents_caching_and_failed_dns_keeps_final_policy() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound = bound("127.0.0.1", server.local_addr().unwrap());
        let worker = tokio::spawn(async move {
            let mut bytes = [0; 1024];
            for _ in 0..2 {
                let (length, peer) = timeout(Duration::from_secs(2), server.recv_from(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap();
                let request = Message::from_vec(&bytes[..length]).unwrap();
                let alias = Name::from_ascii("alias.example.").unwrap();
                let mut response = Message::response(request.id, OpCode::Query);
                response.add_queries(request.queries.clone());
                response.add_answer(Record::from_rdata(
                    request.queries[0].name().clone(),
                    0,
                    RData::CNAME(CNAME(alias.clone())),
                ));
                response.add_answer(Record::from_rdata(
                    alias,
                    60,
                    RData::A(A("182.92.244.55".parse().unwrap())),
                ));
                server
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        for _ in 0..2 {
            outbound
                .resolve(&domain_target("ttl.example"))
                .await
                .unwrap();
        }
        worker.await.unwrap();
        // The now-closed local DNS port fails deterministically, without a production DNS dependency.
        let rules = helios_routing::RuleSet::new(&[
            helios_routing::RuleConfig::Geoip {
                value: "cn".into(),
                action: helios_routing::RouteAction::Direct,
                no_resolve: false,
            },
            helios_routing::RuleConfig::Final {
                action: helios_routing::RouteAction::Proxy,
            },
        ])
        .unwrap();
        let report = outbound
            .evaluate_route(
                &rules,
                &domain_target("failure.example"),
                helios_routing::Network::Tcp,
            )
            .await;
        assert_eq!(report.action, helios_routing::RouteAction::Proxy);
        assert!(report.dns_error.is_some());
        assert!(report.selected_ips.is_empty());
    }

    #[tokio::test]
    async fn route_classification_connects_only_to_matching_ips_for_tcp_and_udp() {
        use helios_routing::{Network, RouteAction, RuleConfig, RuleSet};
        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound = bound("127.0.0.1", dns.local_addr().unwrap());
        let worker = tokio::spawn(async move {
            let mut bytes = [0; 1024];
            let (length, peer) = dns.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..length]).unwrap();
            let mut response = answer(&request, "192.0.2.1");
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::A(A("127.0.0.1".parse().unwrap())),
            ));
            dns.send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let rules = RuleSet::new(&[
            RuleConfig::IpCidr {
                value: "127.0.0.1/32".into(),
                action: RouteAction::Direct,
                resolve: true,
            },
            RuleConfig::Final {
                action: RouteAction::Reject,
            },
        ])
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Target::new(
            Address::Domain("mixed.example".into()),
            listener.local_addr().unwrap().port(),
        )
        .unwrap();
        for network in [Network::Tcp, Network::Udp] {
            let mut report = outbound.evaluate_route(&rules, &target, network).await;
            assert_eq!(report.action, RouteAction::Direct);
            assert_eq!(
                report.selected_ips,
                vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
            );
            assert_eq!(report.resolved_ips.len(), 2);
            if network == Network::Tcp {
                let stream = outbound
                    .connect_ips(target.port, &mut report.selected_ips, &[])
                    .await
                    .unwrap();
                assert_eq!(stream.peer_addr().unwrap(), listener.local_addr().unwrap());
            } else {
                let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let sender = outbound.udp(false).await.unwrap();
                sender
                    .send_to(
                        b"classified",
                        SocketAddr::new(
                            report.selected_ips[0],
                            receiver.local_addr().unwrap().port(),
                        ),
                    )
                    .await
                    .unwrap();
                let mut bytes = [0; 32];
                let (length, _) = receiver.recv_from(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..length], b"classified");
            }
        }
        worker.await.unwrap();
    }

    fn bound(source: &str, server: SocketAddr) -> Outbound {
        Outbound::new(Some(OutboundConfig {
            source_bypass: vec![source.parse().unwrap()],
            dns_servers: vec![server],
        }))
    }
    fn domain_target(host: &str) -> Target {
        Target::new(Address::Domain(host.into()), 443).unwrap()
    }
    fn answer(request: &Message, ip: &str) -> Message {
        let mut response = Message::response(request.id, OpCode::Query);
        response.add_queries(request.queries.clone());
        response.add_answer(Record::from_rdata(
            request.queries[0].name().clone(),
            60,
            RData::A(A(ip.parse().unwrap())),
        ));
        response
    }

    #[tokio::test]
    async fn bound_dns_validates_question_and_id_and_follows_only_the_cname_chain() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound = bound("127.0.0.1", server.local_addr().unwrap());
        let worker = tokio::spawn(async move {
            let mut buffer = [0; 1024];
            let (n, peer) = server.recv_from(&mut buffer).await.unwrap();
            assert_eq!(peer.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
            let request = Message::from_vec(&buffer[..n]).unwrap();
            assert_eq!(request.queries[0].query_type(), RecordType::A);
            let mut wrong = answer(&request, "198.18.0.1");
            wrong.metadata.id ^= 1;
            server
                .send_to(&wrong.to_vec().unwrap(), peer)
                .await
                .unwrap();
            wrong.metadata.id = request.id;
            wrong.queries[0] =
                Query::query(Name::from_ascii("other.invalid.").unwrap(), RecordType::A);
            server
                .send_to(&wrong.to_vec().unwrap(), peer)
                .await
                .unwrap();
            let mut response = Message::response(request.id, OpCode::Query);
            response.add_queries(request.queries.clone());
            response.add_answer(Record::from_rdata(
                Name::from_ascii("unrelated.invalid.").unwrap(),
                60,
                RData::A(A("198.18.0.1".parse().unwrap())),
            ));
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::CNAME(CNAME(Name::from_ascii("canonical.invalid.").unwrap())),
            ));
            server
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
            let (n, peer) = server.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..n]).unwrap();
            assert_eq!(request.queries[0].name().to_ascii(), "canonical.invalid.");
            server
                .send_to(&answer(&request, "192.0.2.8").to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        assert_eq!(
            outbound
                .resolve(&domain_target("deliberately-not-in-system-dns.invalid"))
                .await
                .unwrap(),
            vec!["192.0.2.8".parse::<IpAddr>().unwrap()]
        );
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn truncated_dns_uses_bound_tcp_and_fake_answers_are_rejected() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = UdpSocket::bind(tcp.local_addr().unwrap()).await.unwrap();
        let source = if cfg!(target_os = "linux") {
            "127.0.0.2"
        } else {
            "127.0.0.1"
        };
        let outbound = bound(source, server.local_addr().unwrap());
        let worker = tokio::spawn(async move {
            let mut bytes = [0; 1024];
            let (n, peer) = server.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..n]).unwrap();
            let mut truncated = Message::response(request.id, OpCode::Query);
            truncated.add_queries(request.queries.clone());
            truncated.metadata.truncation = true;
            server
                .send_to(&truncated.to_vec().unwrap(), peer)
                .await
                .unwrap();
            let (mut stream, peer) = tcp.accept().await.unwrap();
            assert_eq!(peer.ip(), source.parse::<IpAddr>().unwrap());
            let n = stream.read_u16().await.unwrap() as usize;
            stream.read_exact(&mut bytes[..n]).await.unwrap();
            let request = Message::from_vec(&bytes[..n]).unwrap();
            let response = answer(&request, "198.19.255.254").to_vec().unwrap();
            stream.write_u16(response.len() as u16).await.unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let error = outbound
            .resolve(&domain_target("example.invalid"))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        worker.await.unwrap();
    }

    #[tokio::test]
    async fn no_system_dns_or_unbound_fallback_when_sources_or_upstreams_fail() {
        let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound = bound("127.0.0.1", closed.local_addr().unwrap());
        drop(closed);
        // localhost would succeed via lookup_host: an error proves no system fallback.
        assert!(outbound.resolve(&domain_target("localhost")).await.is_err());
        assert!(outbound.udp(true).await.is_err());
        assert!(
            outbound
                .node_tcp("[::1]:80".parse().unwrap())
                .await
                .is_err()
        );
        assert!(outbound.quic("[::1]:443".parse().unwrap()).is_err());
        for ip in [
            "198.18.0.0",
            "198.19.255.255",
            "fdfe:dcba:9876::1",
            "::ffff:198.18.0.1",
        ] {
            let target = Target::new(Address::Ip(ip.parse().unwrap()), 443).unwrap();
            assert!(outbound.resolve(&target).await.is_err());
        }
        let invalid = bound("192.0.2.77", "192.0.2.53:53".parse().unwrap());
        assert!(invalid.udp(false).await.is_err());
        assert!(
            invalid
                .node_tcp("127.0.0.1:80".parse().unwrap())
                .await
                .is_err()
        );
        assert!(invalid.quic("127.0.0.1:443".parse().unwrap()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn every_socket_uses_the_selected_source_and_missing_family_cannot_connect() {
        let outbound = bound("127.0.0.2", "127.0.0.1:53".parse().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let target = Target::new(Address::Ip(address.ip()), address.port()).unwrap();
        for node in [false, true] {
            let stream = if node {
                outbound.node_tcp(address).await.unwrap()
            } else {
                outbound.connect(&target, &[]).await.unwrap()
            };
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(peer.ip(), "127.0.0.2".parse::<IpAddr>().unwrap());
            drop(stream);
        }
        assert!(outbound.connect(&target, &[address]).await.is_err());
        let udp = outbound.udp(false).await.unwrap();
        assert_eq!(
            udp.local_addr().unwrap().ip(),
            "127.0.0.2".parse::<IpAddr>().unwrap()
        );
        let endpoint = outbound.quic(address).unwrap();
        assert_eq!(
            endpoint.local_addr().unwrap().ip(),
            "127.0.0.2".parse::<IpAddr>().unwrap()
        );
        let ipv6 = TcpListener::bind("[::1]:0").await.unwrap();
        let address = ipv6.local_addr().unwrap();
        let target = Target::new(Address::Ip(address.ip()), address.port()).unwrap();
        assert!(outbound.connect(&target, &[]).await.is_err());
        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let outbound = bound("127.0.0.2", dns.local_addr().unwrap());
        let worker = tokio::spawn(async move {
            let mut bytes = [0; 1024];
            let (n, peer) = dns.recv_from(&mut bytes).await.unwrap();
            assert_eq!(peer.ip(), "127.0.0.2".parse::<IpAddr>().unwrap());
            let request = Message::from_vec(&bytes[..n]).unwrap();
            dns.send_to(&answer(&request, "192.0.2.1").to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        outbound
            .resolve(&domain_target("example.invalid"))
            .await
            .unwrap();
        worker.await.unwrap();
    }
    #[tokio::test]
    async fn ipv6_only_dns_and_connections_use_the_ipv6_source() {
        use hickory_proto::rr::rdata::AAAA;
        let server = UdpSocket::bind("[::1]:0").await.unwrap();
        let outbound = bound("::1", server.local_addr().unwrap());
        let worker = tokio::spawn(async move {
            let mut bytes = [0; 1024];
            let (n, peer) = server.recv_from(&mut bytes).await.unwrap();
            assert_eq!(peer.ip(), "::1".parse::<IpAddr>().unwrap());
            let request = Message::from_vec(&bytes[..n]).unwrap();
            assert_eq!(request.queries[0].query_type(), RecordType::AAAA);
            let mut response = Message::response(request.id, OpCode::Query);
            response.add_queries(request.queries.clone());
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::AAAA(AAAA("2400:1040::8".parse().unwrap())),
            ));
            server
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        assert_eq!(
            outbound
                .resolve(&domain_target("ipv6.invalid"))
                .await
                .unwrap(),
            vec!["2400:1040::8".parse::<IpAddr>().unwrap()]
        );
        worker.await.unwrap();
        let rules = helios_routing::RuleSet::new(&[
            helios_routing::RuleConfig::Geoip {
                value: "cn".into(),
                action: helios_routing::RouteAction::Direct,
                no_resolve: false,
            },
            helios_routing::RuleConfig::Final {
                action: helios_routing::RouteAction::Proxy,
            },
        ])
        .unwrap();
        let report = outbound
            .evaluate_route(
                &rules,
                &domain_target("ipv6.invalid"),
                helios_routing::Network::Udp,
            )
            .await;
        assert_eq!(report.action, helios_routing::RouteAction::Direct);
        assert_eq!(
            report.selected_ips,
            vec!["2400:1040::8".parse::<IpAddr>().unwrap()]
        );

        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let target = Target::new(Address::Ip(address.ip()), address.port()).unwrap();
        let stream = outbound.connect(&target, &[]).await.unwrap();
        assert_eq!(
            stream.local_addr().unwrap().ip(),
            "::1".parse::<IpAddr>().unwrap()
        );
        assert!(
            outbound
                .node_tcp("127.0.0.1:80".parse().unwrap())
                .await
                .is_err()
        );
        assert!(outbound.udp(false).await.is_err());
    }
}
