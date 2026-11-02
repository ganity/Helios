use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{DecodeError, EncodeError, MAX_DOMAIN_LEN};

const IPV4: u8 = 1;
const IPV6: u8 = 2;
const DOMAIN: u8 = 3;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Address {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Target {
    pub address: Address,
    pub port: u16,
}

impl Target {
    pub fn new(address: Address, port: u16) -> Result<Self, EncodeError> {
        if port == 0 {
            return Err(EncodeError::ZeroPort);
        }
        validate_address(&address)?;
        Ok(Self { address, port })
    }

    pub fn encoded_len(&self) -> usize {
        let address_len = match &self.address {
            Address::Ip(IpAddr::V4(_)) => 4,
            Address::Ip(IpAddr::V6(_)) => 16,
            Address::Domain(domain) => domain.len(),
        };
        1 + 1 + address_len + 2
    }

    pub fn encode(&self, output: &mut Vec<u8>) -> Result<(), EncodeError> {
        if self.port == 0 {
            return Err(EncodeError::ZeroPort);
        }
        validate_address(&self.address)?;

        match &self.address {
            Address::Ip(IpAddr::V4(ip)) => {
                output.extend_from_slice(&[IPV4, 4]);
                output.extend_from_slice(&ip.octets());
            }
            Address::Ip(IpAddr::V6(ip)) => {
                output.extend_from_slice(&[IPV6, 16]);
                output.extend_from_slice(&ip.octets());
            }
            Address::Domain(domain) => {
                output.extend_from_slice(&[DOMAIN, domain.len() as u8]);
                output.extend_from_slice(domain.as_bytes());
            }
        }
        output.extend_from_slice(&self.port.to_be_bytes());
        Ok(())
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize), DecodeError> {
        let address_type = *input.first().ok_or(DecodeError::UnexpectedEnd)?;
        let length = *input.get(1).ok_or(DecodeError::UnexpectedEnd)? as usize;
        let value_end = 2usize
            .checked_add(length)
            .ok_or(DecodeError::UnexpectedEnd)?;
        let port_end = value_end.checked_add(2).ok_or(DecodeError::UnexpectedEnd)?;
        let value = input.get(2..value_end).ok_or(DecodeError::UnexpectedEnd)?;
        let port_bytes: [u8; 2] = input
            .get(value_end..port_end)
            .ok_or(DecodeError::UnexpectedEnd)?
            .try_into()
            .map_err(|_| DecodeError::UnexpectedEnd)?;
        let port = u16::from_be_bytes(port_bytes);
        if port == 0 {
            return Err(DecodeError::ZeroPort);
        }

        let address = match address_type {
            IPV4 if length == 4 => Address::Ip(IpAddr::V4(Ipv4Addr::new(
                value[0], value[1], value[2], value[3],
            ))),
            IPV6 if length == 16 => {
                let octets: [u8; 16] =
                    value
                        .try_into()
                        .map_err(|_| DecodeError::InvalidAddressLength {
                            address_type,
                            actual: length,
                        })?;
                Address::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            DOMAIN => {
                validate_domain_bytes(value)?;
                Address::Domain(
                    String::from_utf8(value.to_vec()).map_err(|_| DecodeError::InvalidDomain)?,
                )
            }
            IPV4 | IPV6 => {
                return Err(DecodeError::InvalidAddressLength {
                    address_type,
                    actual: length,
                });
            }
            other => return Err(DecodeError::InvalidAddressType(other)),
        };

        Ok((Self { address, port }, port_end))
    }
}

fn validate_address(address: &Address) -> Result<(), EncodeError> {
    if let Address::Domain(domain) = address {
        let bytes = domain.as_bytes();
        if bytes.len() > MAX_DOMAIN_LEN {
            return Err(EncodeError::DomainTooLong {
                actual: bytes.len(),
                limit: MAX_DOMAIN_LEN,
            });
        }
        if !valid_domain(bytes) {
            return Err(EncodeError::InvalidDomain);
        }
    }
    Ok(())
}

fn validate_domain_bytes(bytes: &[u8]) -> Result<(), DecodeError> {
    if bytes.len() > MAX_DOMAIN_LEN {
        return Err(DecodeError::DomainTooLong {
            actual: bytes.len(),
            limit: MAX_DOMAIN_LEN,
        });
    }
    if !valid_domain(bytes) {
        return Err(DecodeError::InvalidDomain);
    }
    Ok(())
}

fn valid_domain(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.is_ascii()
        && bytes.first() != Some(&b'.')
        && bytes.last() != Some(&b'.')
        && bytes.split(|byte| *byte == b'.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.first() != Some(&b'-')
                && label.last() != Some(&b'-')
                && label
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_round_trips_all_address_types() {
        let targets = [
            Target::new(Address::Ip("192.0.2.1".parse().unwrap()), 443).unwrap(),
            Target::new(Address::Ip("2001:db8::1".parse().unwrap()), 53).unwrap(),
            Target::new(Address::Domain("vpn.example.com".into()), 443).unwrap(),
        ];

        for target in targets {
            let mut encoded = Vec::new();
            target.encode(&mut encoded).unwrap();
            let (decoded, consumed) = Target::decode(&encoded).unwrap();
            assert_eq!(decoded, target);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn rejects_invalid_domain_boundaries() {
        for domain in ["", ".example.com", "example.com.", "-bad.test", "bad-.test"] {
            assert_eq!(
                Target::new(Address::Domain(domain.into()), 443),
                Err(EncodeError::InvalidDomain)
            );
        }
    }

    #[test]
    fn decode_rejects_mismatched_ip_length_without_panicking() {
        let bytes = [IPV4, 3, 127, 0, 0, 0, 80];
        assert_eq!(
            Target::decode(&bytes),
            Err(DecodeError::InvalidAddressLength {
                address_type: IPV4,
                actual: 3
            })
        );
    }
}
