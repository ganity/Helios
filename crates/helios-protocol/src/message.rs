use crate::{DecodeError, EncodeError, MAX_PADDING_LEN, Target};

pub const MAX_UDP_PAYLOAD: usize = 1200;
pub const MAX_UDP_STREAM_PAYLOAD: usize = 1472;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpAssociate {
    pub target: Option<Target>,
}

impl UdpAssociate {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut output = Vec::new();
        match &self.target {
            Some(target) => {
                output.push(1);
                target.encode(&mut output)?;
            }
            None => output.push(0),
        }
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let kind = *input.first().ok_or(DecodeError::UnexpectedEnd)?;
        match kind {
            0 if input.len() == 1 => Ok(Self { target: None }),
            1 => {
                let (target, consumed) = Target::decode(&input[1..])?;
                if consumed + 1 != input.len() {
                    return Err(DecodeError::TrailingBytes);
                }
                Ok(Self {
                    target: Some(target),
                })
            }
            _ => Err(DecodeError::InvalidAddressType(kind)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpPacket {
    pub association_id: u32,
    pub packet_id: u32,
    pub target: Target,
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub fn new(
        association_id: u32,
        packet_id: u32,
        target: Target,
        payload: Vec<u8>,
    ) -> Result<Self, EncodeError> {
        Self::new_with_limit(association_id, packet_id, target, payload, MAX_UDP_PAYLOAD)
    }

    pub fn new_with_limit(
        association_id: u32,
        packet_id: u32,
        target: Target,
        payload: Vec<u8>,
        limit: usize,
    ) -> Result<Self, EncodeError> {
        let limit = limit.min(MAX_UDP_STREAM_PAYLOAD);
        if payload.len() > limit {
            return Err(EncodeError::PayloadTooLarge {
                actual: payload.len(),
                limit,
            });
        }
        Ok(Self {
            association_id,
            packet_id,
            target,
            payload,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        self.encode_with_limit(MAX_UDP_PAYLOAD)
    }

    pub fn encode_with_limit(&self, limit: usize) -> Result<Vec<u8>, EncodeError> {
        let limit = limit.min(MAX_UDP_STREAM_PAYLOAD);
        if self.payload.len() > limit {
            return Err(EncodeError::PayloadTooLarge {
                actual: self.payload.len(),
                limit,
            });
        }
        let mut output = Vec::with_capacity(12 + self.payload.len());
        output.extend_from_slice(&self.association_id.to_be_bytes());
        output.extend_from_slice(&self.packet_id.to_be_bytes());
        self.target.encode(&mut output)?;
        output.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        Self::decode_with_limit(input, MAX_UDP_PAYLOAD)
    }

    pub fn decode_with_limit(input: &[u8], limit: usize) -> Result<Self, DecodeError> {
        let limit = limit.min(MAX_UDP_STREAM_PAYLOAD);
        let fixed = input.get(..8).ok_or(DecodeError::UnexpectedEnd)?;
        let association_id = u32::from_be_bytes(fixed[..4].try_into().unwrap());
        let packet_id = u32::from_be_bytes(fixed[4..].try_into().unwrap());
        let (target, consumed) = Target::decode(&input[8..])?;
        let length_start = 8 + consumed;
        let length = u16::from_be_bytes(
            input
                .get(length_start..length_start + 2)
                .ok_or(DecodeError::UnexpectedEnd)?
                .try_into()
                .unwrap(),
        ) as usize;
        if length > limit {
            return Err(DecodeError::PayloadTooLarge {
                actual: length,
                limit,
            });
        }
        let payload_start = length_start + 2;
        let payload_end = payload_start
            .checked_add(length)
            .ok_or(DecodeError::UnexpectedEnd)?;
        if input.len() != payload_end {
            return Err(if input.len() < payload_end {
                DecodeError::UnexpectedEnd
            } else {
                DecodeError::TrailingBytes
            });
        }
        Ok(Self {
            association_id,
            packet_id,
            target,
            payload: input[payload_start..payload_end].to_vec(),
        })
    }
}

const MIN_CONNECT_TIMEOUT_MS: u32 = 1_000;
const MAX_CONNECT_TIMEOUT_MS: u32 = 30_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConnectErrorCode {
    GeneralFailure = 1,
    NotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    Timeout = 6,
    AddressUnsupported = 7,
    RateLimited = 8,
}

impl TryFrom<u8> for ConnectErrorCode {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::GeneralFailure,
            2 => Self::NotAllowed,
            3 => Self::NetworkUnreachable,
            4 => Self::HostUnreachable,
            5 => Self::ConnectionRefused,
            6 => Self::Timeout,
            7 => Self::AddressUnsupported,
            8 => Self::RateLimited,
            other => return Err(DecodeError::UnknownConnectErrorCode(other)),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectTcp {
    pub target: Target,
    pub timeout_ms: u32,
    pub padding: Vec<u8>,
}

impl ConnectTcp {
    pub fn new(target: Target, timeout_ms: u32, padding: Vec<u8>) -> Result<Self, EncodeError> {
        validate_timeout_for_encode(timeout_ms)?;
        validate_padding_for_encode(padding.len())?;
        Ok(Self {
            target,
            timeout_ms,
            padding,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        validate_timeout_for_encode(self.timeout_ms)?;
        validate_padding_for_encode(self.padding.len())?;

        let mut output = Vec::with_capacity(self.target.encoded_len() + 8 + self.padding.len());
        self.target.encode(&mut output)?;
        output.extend_from_slice(&self.timeout_ms.to_be_bytes());
        output.extend_from_slice(&0u16.to_be_bytes()); // v1 metadata length
        output.extend_from_slice(&(self.padding.len() as u16).to_be_bytes());
        output.extend_from_slice(&self.padding);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let (target, consumed) = Target::decode(input)?;
        let fixed = input
            .get(consumed..consumed + 8)
            .ok_or(DecodeError::UnexpectedEnd)?;
        let timeout_ms = u32::from_be_bytes(fixed[0..4].try_into().unwrap());
        if !(MIN_CONNECT_TIMEOUT_MS..=MAX_CONNECT_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(DecodeError::InvalidConnectTimeout(timeout_ms));
        }

        let metadata_len = u16::from_be_bytes(fixed[4..6].try_into().unwrap()) as usize;
        if metadata_len != 0 {
            return Err(DecodeError::UnsupportedMetadata);
        }
        let padding_len = u16::from_be_bytes(fixed[6..8].try_into().unwrap()) as usize;
        if padding_len > MAX_PADDING_LEN {
            return Err(DecodeError::PaddingTooLarge {
                actual: padding_len,
                limit: MAX_PADDING_LEN,
            });
        }

        let padding_start = consumed + 8;
        let padding_end = padding_start
            .checked_add(padding_len)
            .ok_or(DecodeError::UnexpectedEnd)?;
        let padding = input
            .get(padding_start..padding_end)
            .ok_or(DecodeError::UnexpectedEnd)?;
        if input.len() != padding_end {
            return Err(DecodeError::TrailingBytes);
        }

        Ok(Self {
            target,
            timeout_ms,
            padding: padding.to_vec(),
        })
    }
}

fn validate_timeout_for_encode(timeout_ms: u32) -> Result<(), EncodeError> {
    if !(MIN_CONNECT_TIMEOUT_MS..=MAX_CONNECT_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(EncodeError::InvalidConnectTimeout(timeout_ms));
    }
    Ok(())
}

fn validate_padding_for_encode(length: usize) -> Result<(), EncodeError> {
    if length > MAX_PADDING_LEN {
        return Err(EncodeError::PaddingTooLarge {
            actual: length,
            limit: MAX_PADDING_LEN,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn large_udp_requires_an_explicit_negotiated_limit() {
        let target = super::Target::new(crate::Address::Ip("::1".parse().unwrap()), 1234).unwrap();
        let packet = super::UdpPacket::new_with_limit(
            1,
            2,
            target,
            vec![42; 1400],
            super::MAX_UDP_STREAM_PAYLOAD,
        )
        .unwrap();
        assert!(packet.encode().is_err());
        let bytes = packet
            .encode_with_limit(super::MAX_UDP_STREAM_PAYLOAD)
            .unwrap();
        assert!(super::UdpPacket::decode(&bytes).is_err());
        assert_eq!(
            super::UdpPacket::decode_with_limit(&bytes, super::MAX_UDP_STREAM_PAYLOAD).unwrap(),
            packet
        );
        let mut oversized = packet;
        oversized
            .payload
            .resize(super::MAX_UDP_STREAM_PAYLOAD + 1, 0);
        assert!(oversized.encode_with_limit(usize::MAX).is_err());
    }
    use crate::{Address, MAX_PADDING_LEN};

    use super::*;

    fn target() -> Target {
        Target::new(Address::Domain("example.com".into()), 443).unwrap()
    }

    #[test]
    fn connect_tcp_round_trip() {
        let message = ConnectTcp::new(target(), 3_000, vec![7; 256]).unwrap();
        assert_eq!(ConnectTcp::decode(&message.encode().unwrap()), Ok(message));
    }

    #[test]
    fn rejects_timeout_outside_protocol_range() {
        assert_eq!(
            ConnectTcp::new(target(), 999, Vec::new()),
            Err(EncodeError::InvalidConnectTimeout(999))
        );
        assert_eq!(
            ConnectTcp::new(target(), 30_001, Vec::new()),
            Err(EncodeError::InvalidConnectTimeout(30_001))
        );
    }

    #[test]
    fn rejects_padding_over_limit() {
        assert_eq!(
            ConnectTcp::new(target(), 3_000, vec![0; MAX_PADDING_LEN + 1]),
            Err(EncodeError::PaddingTooLarge {
                actual: MAX_PADDING_LEN + 1,
                limit: MAX_PADDING_LEN
            })
        );
    }

    #[test]
    fn rejects_truncated_and_trailing_padding() {
        let encoded = ConnectTcp::new(target(), 3_000, vec![1; 16])
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(
            ConnectTcp::decode(&encoded[..encoded.len() - 1]),
            Err(DecodeError::UnexpectedEnd)
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            ConnectTcp::decode(&trailing),
            Err(DecodeError::TrailingBytes)
        );
    }

    #[test]
    fn udp_associate_and_packet_round_trip_with_bounds() {
        let packet_target = target();
        let associate = UdpAssociate {
            target: Some(packet_target.clone()),
        };
        assert_eq!(
            UdpAssociate::decode(&associate.encode().unwrap()),
            Ok(associate)
        );
        let packet = UdpPacket::new(7, 9, packet_target, vec![3; 128]).unwrap();
        assert_eq!(UdpPacket::decode(&packet.encode().unwrap()), Ok(packet));
        assert_eq!(
            UdpPacket::new(1, 1, target(), vec![0; MAX_UDP_PAYLOAD + 1]),
            Err(EncodeError::PayloadTooLarge {
                actual: MAX_UDP_PAYLOAD + 1,
                limit: MAX_UDP_PAYLOAD
            })
        );
    }

    #[test]
    fn udp_rejects_invalid_association_and_trailing_bytes() {
        assert!(matches!(
            UdpAssociate::decode(&[2]),
            Err(DecodeError::InvalidAddressType(2))
        ));
        let packet = UdpPacket::new(1, 2, target(), vec![1]).unwrap();
        let mut encoded = packet.encode().unwrap();
        encoded.push(0);
        assert_eq!(UdpPacket::decode(&encoded), Err(DecodeError::TrailingBytes));
    }
}
