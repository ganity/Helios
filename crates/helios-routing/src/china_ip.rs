use std::{net::IpAddr, sync::OnceLock};

type Range = (u128, u128);

struct ChinaIp {
    v4: Vec<Range>,
    v6: Vec<Range>,
}

fn ranges() -> &'static ChinaIp {
    static RANGES: OnceLock<ChinaIp> = OnceLock::new();
    RANGES.get_or_init(|| {
        let mut result = ChinaIp {
            v4: vec![],
            v6: vec![],
        };
        for line in include_str!("../data/china-ip.txt").lines() {
            let (ip, prefix) = super::parse_cidr(line).expect("valid bundled China IP network");
            let (number, bits, list) = match ip {
                IpAddr::V4(ip) => (u128::from(u32::from(ip)), 32u32, &mut result.v4),
                IpAddr::V6(ip) => (u128::from(ip), 128u32, &mut result.v6),
            };
            let host_bits = bits - u32::from(prefix);
            let host_mask = if host_bits == 128 {
                u128::MAX
            } else {
                (1u128 << host_bits) - 1
            };
            list.push((number & !host_mask, number | host_mask));
        }
        for list in [&mut result.v4, &mut result.v6] {
            list.sort_unstable();
            let mut merged: Vec<Range> = Vec::new();
            for &(start, end) in list.iter() {
                if let Some(last) = merged.last_mut()
                    && start <= last.1.saturating_add(1)
                {
                    last.1 = last.1.max(end);
                    continue;
                }
                merged.push((start, end));
            }
            *list = merged;
        }
        result
    })
}

pub fn contains(ip: IpAddr) -> bool {
    let data = ranges();
    let (number, list) = match ip {
        IpAddr::V4(ip) => (u128::from(u32::from(ip)), &data.v4),
        IpAddr::V6(ip) => (u128::from(ip), &data.v6),
    };
    let index = list.partition_point(|&(start, _)| start <= number);
    index > 0 && number <= list[index - 1].1
}

#[cfg(test)]
mod tests {
    #[test]
    fn recognizes_snapshot_boundaries_and_families() {
        assert!(super::contains("1.0.1.0".parse().unwrap()));
        assert!(super::contains("1.0.1.255".parse().unwrap()));
        assert!(!super::contains("1.0.0.1".parse().unwrap()));
        assert!(!super::contains("8.8.8.8".parse().unwrap()));
        assert!(!super::contains("::1".parse().unwrap()));
        assert!(super::contains("2400:1040::1".parse().unwrap()));
        assert!(!super::contains("2001:4860:4860::8888".parse().unwrap()));
        for line in include_str!("../data/china-ip.txt").lines() {
            let (ip, prefix) = crate::parse_cidr(line).unwrap();
            let end = match ip {
                std::net::IpAddr::V4(ip) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                    u32::from(ip) | u32::MAX.checked_shr(prefix.into()).unwrap_or(0),
                )),
                std::net::IpAddr::V6(ip) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    u128::from(ip) | u128::MAX.checked_shr(prefix.into()).unwrap_or(0),
                )),
            };
            assert!(super::contains(ip), "{line}");
            assert!(super::contains(end), "{line}");
        }
    }
}
