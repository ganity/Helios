use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
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
pub(super) struct Outbound(pub Option<OutboundConfig>);

impl Outbound {
    pub fn source(&self, destination: SocketAddr) -> io::Result<Option<IpAddr>> {
        match &self.0 {
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
        ips.retain(|ip| !protected.contains(&SocketAddr::new(*ip, target.port)));
        helios_transport::connect_tcp_ips(
            ips,
            target.port,
            self.0
                .as_ref()
                .map(|config| config.source_bypass.as_slice()),
        )
        .await
    }

    pub async fn resolve(&self, target: &Target) -> io::Result<Vec<IpAddr>> {
        let ips = match &target.address {
            Address::Ip(ip) => vec![*ip],
            Address::Domain(host) => match &self.0 {
                None => tokio::net::lookup_host((host.as_str(), target.port))
                    .await?
                    .map(|address| address.ip())
                    .collect(),
                Some(config) => {
                    // ponytail: resolve per flow/UDP packet; add a bounded TTL cache if lookup cost matters.
                    let (a, aaaa) = tokio::join!(
                        self.lookup(
                            host,
                            RecordType::A,
                            config.source_bypass.iter().any(IpAddr::is_ipv4)
                        ),
                        self.lookup(
                            host,
                            RecordType::AAAA,
                            config.source_bypass.iter().any(IpAddr::is_ipv6)
                        ),
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

    async fn lookup(&self, host: &str, kind: RecordType, enabled: bool) -> io::Result<Vec<IpAddr>> {
        if !enabled {
            return Ok(Vec::new());
        }
        let config = self
            .0
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
    ) -> io::Result<Vec<IpAddr>> {
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
                    return Ok(ips);
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
                return Ok(Vec::new());
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

    fn bound(source: &str, server: SocketAddr) -> Outbound {
        Outbound(Some(OutboundConfig {
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
                RData::AAAA(AAAA("2001:db8::8".parse().unwrap())),
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
            vec!["2001:db8::8".parse::<IpAddr>().unwrap()]
        );
        worker.await.unwrap();
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
