pub(super) mod ip_version {
    use rtnetlink::IpVersion;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(value: &IpVersion, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(match value {
            IpVersion::V4 => 4,
            IpVersion::V6 => 6,
        })
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<IpVersion, D::Error> {
        match u8::deserialize(deserializer)? {
            4 => Ok(IpVersion::V4),
            6 => Ok(IpVersion::V6),
            _ => Err(D::Error::custom("invalid recovery IP version")),
        }
    }
}

#[cfg(any(feature = "unsafe-state-file", feature = "secure-state-file"))]
pub(super) mod routes {
    use rtnetlink::{
        packet_core::{Emitable, Parseable},
        packet_route::route::RouteMessage,
    };
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

    pub(super) struct BoundedVec<T, const LIMIT: usize>(pub(super) Vec<T>);

    impl<'de, T: Deserialize<'de>, const LIMIT: usize> Deserialize<'de> for BoundedVec<T, LIMIT> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor<T, const LIMIT: usize>(std::marker::PhantomData<T>);
            impl<'de, T: Deserialize<'de>, const LIMIT: usize> serde::de::Visitor<'de> for Visitor<T, LIMIT> {
                type Value = BoundedVec<T, LIMIT>;

                fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(formatter, "a recovery sequence of at most {LIMIT} elements")
                }

                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut sequence: A,
                ) -> Result<Self::Value, A::Error> {
                    let mut values = Vec::new();
                    while values.len() < LIMIT {
                        match sequence.next_element()? {
                            Some(value) => values.push(value),
                            None => return Ok(BoundedVec(values)),
                        }
                    }
                    if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                        return Err(A::Error::custom("recovery sequence exceeds limit"));
                    }
                    Ok(BoundedVec(values))
                }
            }
            deserializer.deserialize_seq(Visitor::<T, LIMIT>(std::marker::PhantomData))
        }
    }

    // Netlink bytes preserve unknown attributes; records are local to the same host/architecture.
    pub fn serialize<S: Serializer>(
        routes: &[RouteMessage],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if routes.len() > 4096 || routes.iter().any(|route| route.buffer_len() > 65536) {
            return Err(serde::ser::Error::custom(
                "recovery routes exceed record limits",
            ));
        }
        let encoded: Vec<Vec<u8>> = routes
            .iter()
            .map(|route| {
                let mut bytes = vec![0; route.buffer_len()];
                route.emit(&mut bytes);
                bytes
            })
            .collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<RouteMessage>, D::Error> {
        let encoded = BoundedVec::<BoundedVec<u8, 65536>, 4096>::deserialize(deserializer)?.0;
        encoded
            .into_iter()
            .map(|bytes| RouteMessage::parse(bytes.0.as_slice()).map_err(D::Error::custom))
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn bounded_sequences_accept_limit_and_reject_extra_elements() {
            let exact: BoundedVec<u8, 2> = serde_json::from_str("[1,2]").unwrap();
            assert_eq!(exact.0, [1, 2]);
            assert!(serde_json::from_str::<BoundedVec<u8, 2>>("[1,2,3]").is_err());
            let empty: BoundedVec<u8, 0> = serde_json::from_str("[]").unwrap();
            assert!(empty.0.is_empty());
            assert!(serde_json::from_str::<BoundedVec<u8, 0>>("[1]").is_err());
            assert!(serde_json::from_str::<BoundedVec<BoundedVec<u8, 2>, 2>>("[[1,2,3]]").is_err());
            assert!(
                serde_json::from_str::<BoundedVec<BoundedVec<u8, 2>, 2>>("[[],[],[]]").is_err()
            );
        }
    }
}

#[cfg(any(feature = "unsafe-state-file", feature = "secure-state-file"))]
pub(super) mod rules {
    use super::routes::BoundedVec;
    use rtnetlink::{
        packet_core::{Emitable, Parseable},
        packet_route::rule::RuleMessage,
    };
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

    pub fn serialize<S: Serializer>(
        rules: &[RuleMessage],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if rules.len() > 32 || rules.iter().any(|rule| rule.buffer_len() > 4096) {
            return Err(serde::ser::Error::custom(
                "recovery rules exceed record limits",
            ));
        }
        let encoded: Vec<Vec<u8>> = rules
            .iter()
            .map(|rule| {
                let mut bytes = vec![0; rule.buffer_len()];
                rule.emit(&mut bytes);
                bytes
            })
            .collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<RuleMessage>, D::Error> {
        BoundedVec::<BoundedVec<u8, 4096>, 32>::deserialize(deserializer)?
            .0
            .into_iter()
            .map(|bytes| RuleMessage::parse(bytes.0.as_slice()).map_err(D::Error::custom))
            .collect()
    }
}

#[cfg(all(
    test,
    any(feature = "unsafe-state-file", feature = "secure-state-file")
))]
mod tests {
    use crate::{FwmarkRestore, TproxyStateInner};
    use rtnetlink::{IpVersion, RouteMessageBuilder};

    #[test]
    fn linux_recovery_state_round_trips_routes_and_both_ip_versions() {
        let route = RouteMessageBuilder::<std::net::Ipv4Addr>::new()
            .destination_prefix("203.0.113.0".parse().unwrap(), 24)
            .table_id(1000)
            .output_interface(7)
            .build();
        let ipv6 = RouteMessageBuilder::<std::net::Ipv6Addr>::new()
            .destination_prefix("2001:db8::".parse().unwrap(), 32)
            .table_id(1001)
            .output_interface(9)
            .build();
        let state = TproxyStateInner {
            restore_routes: vec![route.clone()],
            remove_routes: vec![ipv6.clone()],
            remove_rules: vec![{
                use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
                let mut rule = RuleMessage::default();
                rule.header.family = rtnetlink::packet_route::AddressFamily::Inet6;
                rule.header.action = RuleAction::ToTable;
                rule.header.src_len = 128;
                rule.attributes = vec![
                    RuleAttribute::Source("2001:db8::1".parse().unwrap()),
                    RuleAttribute::Priority(20220),
                    RuleAttribute::Table(254),
                ];
                rule
            }],
            restore_socket_fwmark: vec![
                FwmarkRestore {
                    ip_version: IpVersion::V4,
                    fwmark: 42,
                    table: 1000,
                },
                FwmarkRestore {
                    ip_version: IpVersion::V6,
                    fwmark: 43,
                    table: 1001,
                },
            ],
            ..Default::default()
        };
        let encoded = serde_json::to_vec(&state).unwrap();
        let restored: TproxyStateInner = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored.restore_routes, [route]);
        assert_eq!(restored.remove_routes, [ipv6]);
        assert_eq!(restored.remove_rules, state.remove_rules);
        assert_eq!(serde_json::to_vec(&restored).unwrap(), encoded);
        let mut legacy = serde_json::to_value(&state).unwrap();
        legacy.as_object_mut().unwrap().remove("remove_rules");
        assert!(
            serde_json::from_value::<TproxyStateInner>(legacy)
                .unwrap()
                .remove_rules
                .is_empty()
        );
        let mut corrupt = serde_json::to_value(&state).unwrap();
        corrupt["restore_routes"] = serde_json::json!([[1, 2, 3]]);
        assert!(serde_json::from_value::<TproxyStateInner>(corrupt).is_err());
        let mut corrupt = serde_json::to_value(&state).unwrap();
        corrupt["restore_socket_fwmark"][0]["ip_version"] = serde_json::json!(5);
        assert!(serde_json::from_value::<TproxyStateInner>(corrupt).is_err());
        let mut corrupt = serde_json::to_value(&state).unwrap();
        corrupt["remove_routes"] = serde_json::json!([vec![0u8; 65537]]);
        assert!(serde_json::from_value::<TproxyStateInner>(corrupt).is_err());
        let mut corrupt = serde_json::to_value(&state).unwrap();
        corrupt["remove_rules"] = serde_json::json!([[1, 2, 3]]);
        assert!(serde_json::from_value::<TproxyStateInner>(corrupt).is_err());
        let mut corrupt = serde_json::to_value(&state).unwrap();
        corrupt["remove_rules"] = serde_json::json!([vec![0u8; 4097]]);
        assert!(serde_json::from_value::<TproxyStateInner>(corrupt).is_err());
        let mut corrupt = serde_json::to_value(&state).unwrap();
        corrupt["remove_rules"] = serde_json::json!(vec![Vec::<u8>::new(); 33]);
        assert!(serde_json::from_value::<TproxyStateInner>(corrupt).is_err());
        let mut oversized = state.clone();
        oversized.remove_rules = vec![state.remove_rules[0].clone(); 33];
        assert!(serde_json::to_vec(&oversized).is_err());
        let mut oversized = state.clone();
        oversized.restore_routes =
            vec![rtnetlink::packet_route::route::RouteMessage::default(); 4097];
        assert!(serde_json::to_vec(&oversized).is_err());
    }
}
