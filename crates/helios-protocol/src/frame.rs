use crate::{DecodeError, EncodeError, FRAME_HEADER_LEN, MAX_CONTROL_PAYLOAD, VERSION};

const MAGIC: [u8; 2] = *b"HS";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameType {
    ClientHello = 1,
    ServerHello = 2,
    Auth = 3,
    AuthOk = 4,
    AuthError = 5,
    ConnectTcp = 6,
    ConnectOk = 7,
    ConnectError = 8,
    UdpAssociate = 9,
    UdpAssociateOk = 10,
    UdpPacket = 11,
    Ping = 12,
    Pong = 13,
    GoAway = 14,
    Close = 15,
}

impl TryFrom<u8> for FrameType {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::ClientHello,
            2 => Self::ServerHello,
            3 => Self::Auth,
            4 => Self::AuthOk,
            5 => Self::AuthError,
            6 => Self::ConnectTcp,
            7 => Self::ConnectOk,
            8 => Self::ConnectError,
            9 => Self::UdpAssociate,
            10 => Self::UdpAssociateOk,
            11 => Self::UdpPacket,
            12 => Self::Ping,
            13 => Self::Pong,
            14 => Self::GoAway,
            15 => Self::Close,
            other => return Err(DecodeError::UnknownFrameType(other)),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub request_id: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(
        frame_type: FrameType,
        request_id: u32,
        payload: Vec<u8>,
    ) -> Result<Self, EncodeError> {
        check_payload_len(payload.len())?;
        Ok(Self {
            frame_type,
            request_id,
            payload,
        })
    }

    pub fn encoded_len(&self) -> usize {
        FRAME_HEADER_LEN + self.payload.len()
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        check_payload_len(self.payload.len())?;
        let mut output = Vec::with_capacity(self.encoded_len());
        output.extend_from_slice(&MAGIC);
        output.push(VERSION);
        output.push(self.frame_type as u8);
        output.push(0); // flags
        output.push(0); // reserved
        output.extend_from_slice(&self.request_id.to_be_bytes());
        output.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let payload_len = Self::decode_header(input)?;
        let expected_len = FRAME_HEADER_LEN + payload_len;
        if input.len() < expected_len {
            return Err(DecodeError::UnexpectedEnd);
        }
        if input.len() > expected_len {
            return Err(DecodeError::TrailingBytes);
        }

        Ok(Self {
            frame_type: FrameType::try_from(input[3])?,
            request_id: u32::from_be_bytes(input[6..10].try_into().unwrap()),
            payload: input[FRAME_HEADER_LEN..].to_vec(),
        })
    }

    pub fn decode_header(input: &[u8]) -> Result<usize, DecodeError> {
        if input.len() < FRAME_HEADER_LEN {
            return Err(DecodeError::UnexpectedEnd);
        }
        if input[..2] != MAGIC {
            return Err(DecodeError::InvalidMagic);
        }
        if input[2] != VERSION {
            return Err(DecodeError::UnsupportedVersion(input[2]));
        }
        FrameType::try_from(input[3])?;
        if input[4] != 0 {
            return Err(DecodeError::UnknownFlags(input[4]));
        }
        if input[5] != 0 {
            return Err(DecodeError::NonZeroReserved);
        }

        let payload_len = u32::from_be_bytes(input[10..14].try_into().unwrap()) as usize;
        if payload_len > MAX_CONTROL_PAYLOAD {
            return Err(DecodeError::PayloadTooLarge {
                actual: payload_len,
                limit: MAX_CONTROL_PAYLOAD,
            });
        }
        Ok(payload_len)
    }
}

fn check_payload_len(length: usize) -> Result<(), EncodeError> {
    if length > MAX_CONTROL_PAYLOAD {
        return Err(EncodeError::PayloadTooLarge {
            actual: length,
            limit: MAX_CONTROL_PAYLOAD,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let frame = Frame::new(FrameType::Ping, 42, b"probe".to_vec()).unwrap();
        assert_eq!(Frame::decode(&frame.encode().unwrap()), Ok(frame));
    }

    #[test]
    fn rejects_oversized_payload_before_reading_it() {
        let mut header = vec![b'H', b'S', VERSION, FrameType::Ping as u8, 0, 0];
        header.extend_from_slice(&1u32.to_be_bytes());
        header.extend_from_slice(&((MAX_CONTROL_PAYLOAD + 1) as u32).to_be_bytes());

        assert_eq!(
            Frame::decode(&header),
            Err(DecodeError::PayloadTooLarge {
                actual: MAX_CONTROL_PAYLOAD + 1,
                limit: MAX_CONTROL_PAYLOAD
            })
        );
    }

    #[test]
    fn rejects_unknown_header_fields() {
        let frame = Frame::new(FrameType::Ping, 1, Vec::new()).unwrap();
        let encoded = frame.encode().unwrap();

        let mut bad_flags = encoded.clone();
        bad_flags[4] = 1;
        assert_eq!(Frame::decode(&bad_flags), Err(DecodeError::UnknownFlags(1)));

        let mut bad_reserved = encoded;
        bad_reserved[5] = 1;
        assert_eq!(
            Frame::decode(&bad_reserved),
            Err(DecodeError::NonZeroReserved)
        );
    }

    #[test]
    fn arbitrary_short_inputs_do_not_panic() {
        for length in 0..FRAME_HEADER_LEN {
            assert_eq!(
                Frame::decode(&vec![0; length]),
                Err(DecodeError::UnexpectedEnd)
            );
        }
    }
}
