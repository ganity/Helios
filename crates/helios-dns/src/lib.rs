use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, OpCode, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use tokio::net::UdpSocket;

const FIRST_FAKE_IP: u32 = 0xc612_0001;
const LAST_FAKE_IP: u32 = 0xc613_fffe;
const IPV6_PREFIX: u128 = 0xfdfe_dcba_9876_0000_0000_0000_0000_0000;

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CacheStats {
    pub entries: usize,
    pub capacity: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub expired: u64,
}

#[derive(Clone)]
pub struct FakeIpPool {
    inner: Arc<Mutex<PoolState>>,
    capacity: usize,
    ttl: Duration,
}

struct PoolState {
    next: u32,
    by_domain: HashMap<String, Entry>,
    by_ip: HashMap<Ipv4Addr, String>,
    order: VecDeque<String>,
    hits: u64,
    misses: u64,
    evictions: u64,
    expired: u64,
}

#[derive(Clone, Copy)]
struct Entry {
    ip: Ipv4Addr,
    expires_at: Instant,
}

impl FakeIpPool {
    pub fn new(capacity: usize, ttl: Duration) -> Result<Self, FakeIpError> {
        if capacity == 0 || capacity > (LAST_FAKE_IP - FIRST_FAKE_IP + 1) as usize {
            return Err(FakeIpError::InvalidCapacity);
        }
        if ttl.is_zero() {
            return Err(FakeIpError::InvalidTtl);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(PoolState {
                next: FIRST_FAKE_IP,
                by_domain: HashMap::new(),
                by_ip: HashMap::new(),
                order: VecDeque::new(),
                hits: 0,
                misses: 0,
                evictions: 0,
                expired: 0,
            })),
            capacity,
            ttl,
        })
    }

    pub fn allocate(&self, domain: &str) -> Result<Ipv4Addr, FakeIpError> {
        let domain = normalize_domain(domain)?;
        let now = Instant::now();
        let mut state = self.inner.lock().expect("fake IP pool poisoned");
        purge_expired(&mut state, now);
        if state.by_domain.contains_key(&domain) {
            state.hits = state.hits.saturating_add(1);
        } else {
            state.misses = state.misses.saturating_add(1);
        }
        if let Some(entry) = state.by_domain.get_mut(&domain) {
            entry.expires_at = now + self.ttl;
            return Ok(entry.ip);
        }
        while state.by_domain.len() >= self.capacity {
            evict_oldest(&mut state);
        }
        let ip = next_free_ip(&mut state)?;
        state.by_ip.insert(ip, domain.clone());
        state.by_domain.insert(
            domain.clone(),
            Entry {
                ip,
                expires_at: now + self.ttl,
            },
        );
        state.order.push_back(domain);
        Ok(ip)
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        let now = Instant::now();
        let mut state = self.inner.lock().expect("fake IP pool poisoned");
        purge_expired(&mut state, now);
        state.by_ip.get(&ip).cloned()
    }

    pub fn allocate_v6(&self, domain: &str) -> Result<Ipv6Addr, FakeIpError> {
        Ok(Ipv6Addr::from(
            IPV6_PREFIX | u128::from(u32::from(self.allocate(domain)?)),
        ))
    }

    pub fn lookup_ip(&self, ip: IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(ip) => self.lookup(ip),
            IpAddr::V6(ip) if u128::from(ip) & !u128::from(u32::MAX) == IPV6_PREFIX => {
                self.lookup(Ipv4Addr::from(u128::from(ip) as u32))
            }
            _ => None,
        }
    }

    // Only expired mappings may be cleared: applications can still hold unexpired DNS answers.
    pub fn stats(&self) -> CacheStats {
        let mut state = self.inner.lock().expect("fake IP pool poisoned");
        purge_expired(&mut state, Instant::now());
        CacheStats {
            entries: state.by_domain.len(),
            capacity: self.capacity,
            hits: state.hits,
            misses: state.misses,
            evictions: state.evictions,
            expired: state.expired,
        }
    }
}

pub async fn serve_udp(
    socket: UdpSocket,
    pool: FakeIpPool,
    ttl_seconds: u32,
) -> std::io::Result<()> {
    let mut buffer = [0u8; 1232];
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        let Ok(response) = answer_query(&buffer[..length], &pool, ttl_seconds) else {
            continue;
        };
        let _ = socket.send_to(&response, peer).await;
    }
}

pub fn answer_query(
    bytes: &[u8],
    pool: &FakeIpPool,
    ttl_seconds: u32,
) -> Result<Vec<u8>, DnsError> {
    let request = Message::from_vec(bytes)?;
    let mut response = Message::response(request.id, request.op_code);
    response.add_queries(request.queries.iter().cloned());
    if request.op_code != OpCode::Query || request.queries.len() != 1 {
        response.metadata.response_code = ResponseCode::NotImp;
        return Ok(response.to_vec()?);
    }
    let query = &request.queries[0];
    match query.query_type() {
        RecordType::A => {
            let ip = pool.allocate(&query.name().to_utf8())?;
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                ttl_seconds,
                RData::A(A(ip)),
            ));
        }
        RecordType::AAAA => {
            let ip = pool.allocate_v6(&query.name().to_utf8())?;
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                ttl_seconds,
                RData::AAAA(AAAA(ip)),
            ));
        }
        _ => response.metadata.response_code = ResponseCode::NotImp,
    }
    Ok(response.to_vec()?)
}

fn normalize_domain(domain: &str) -> Result<String, FakeIpError> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || !domain.is_ascii() || domain.len() > 253 {
        return Err(FakeIpError::InvalidDomain);
    }
    Ok(domain)
}

fn purge_expired(state: &mut PoolState, now: Instant) {
    let expired: Vec<_> = state
        .by_domain
        .iter()
        .filter_map(|(domain, entry)| (entry.expires_at <= now).then_some(domain.clone()))
        .collect();
    for domain in expired {
        if let Some(entry) = state.by_domain.remove(&domain) {
            state.expired = state.expired.saturating_add(1);
            state.by_ip.remove(&entry.ip);
        }
    }
    state
        .order
        .retain(|domain| state.by_domain.contains_key(domain));
}

fn evict_oldest(state: &mut PoolState) {
    while let Some(domain) = state.order.pop_front() {
        if let Some(entry) = state.by_domain.remove(&domain) {
            state.evictions = state.evictions.saturating_add(1);
            state.by_ip.remove(&entry.ip);
            return;
        }
    }
}

fn next_free_ip(state: &mut PoolState) -> Result<Ipv4Addr, FakeIpError> {
    let start = state.next;
    loop {
        let ip = Ipv4Addr::from(state.next);
        state.next = if state.next == LAST_FAKE_IP {
            FIRST_FAKE_IP
        } else {
            state.next + 1
        };
        if !state.by_ip.contains_key(&ip) {
            return Ok(ip);
        }
        if state.next == start {
            return Err(FakeIpError::Exhausted);
        }
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum FakeIpError {
    #[error("fake IP capacity is invalid")]
    InvalidCapacity,
    #[error("fake IP TTL is invalid")]
    InvalidTtl,
    #[error("domain is invalid")]
    InvalidDomain,
    #[error("fake IP pool is exhausted")]
    Exhausted,
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error(transparent)]
    Proto(#[from] hickory_proto::ProtoError),
    #[error(transparent)]
    Decode(#[from] hickory_proto::serialize::binary::DecodeError),
    #[error(transparent)]
    FakeIp(#[from] FakeIpError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{Message, Query},
        rr::{Name, RData, RecordType},
    };

    #[test]
    fn allocation_is_stable_and_reverse_lookup_works() {
        let pool = FakeIpPool::new(4, Duration::from_secs(60)).unwrap();
        let first = pool.allocate("Example.COM.").unwrap();
        assert_eq!(pool.allocate("example.com").unwrap(), first);
        assert_eq!(pool.lookup(first).as_deref(), Some("example.com"));
        assert!((FIRST_FAKE_IP..=LAST_FAKE_IP).contains(&u32::from(first)));
    }

    #[test]
    fn capacity_evicts_the_oldest_mapping() {
        let pool = FakeIpPool::new(2, Duration::from_secs(60)).unwrap();
        let first = pool.allocate("one.example").unwrap();
        pool.allocate("two.example").unwrap();
        pool.allocate("three.example").unwrap();
        assert_eq!(pool.lookup(first), None);
    }

    #[test]
    fn answers_a_and_aaaa_without_upstream_dns_leakage() {
        let pool = FakeIpPool::new(4, Duration::from_secs(60)).unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let response =
            Message::from_vec(&answer_query(&request.to_vec().unwrap(), &pool, 60).unwrap())
                .unwrap();
        assert_eq!(response.answers.len(), 1);
        assert!(matches!(response.answers[0].data, RData::A(_)));

        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::AAAA,
        ));
        let response =
            Message::from_vec(&answer_query(&request.to_vec().unwrap(), &pool, 60).unwrap())
                .unwrap();
        assert_eq!(response.answers.len(), 1);
        let RData::AAAA(AAAA(ip)) = response.answers[0].data else {
            panic!("expected AAAA");
        };
        assert_eq!(
            pool.lookup_ip(IpAddr::V6(ip)).as_deref(),
            Some("example.com")
        );
        assert_eq!(pool.stats().entries, 1);
        assert_eq!(pool.stats().hits, 1);
        assert_eq!(pool.stats().misses, 1);
    }
}
