use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{
    AUTH_PROOF_LEN, DecodeError, EncodeError, MAX_CONTROL_PAYLOAD, MAX_CREDENTIAL_ID_LEN,
    MAX_PADDING_LEN, NONCE_LEN, SESSION_ID_LEN, VERSION,
};

type HmacSha256 = Hmac<Sha256>;

const AUTH_DOMAIN: &[u8] = b"helios-auth-v1\0";
const HELLO_FIXED_LEN: usize = NONCE_LEN + 4 + 2;
const SERVER_HELLO_FIXED_LEN: usize = 1 + NONCE_LEN + 4 + 4 + 2;

pub const CAP_TCP_CONNECT: u32 = 1 << 0;
pub const CAP_UDP_DATAGRAM: u32 = 1 << 1;
pub const CAP_UDP_OVER_STREAM: u32 = 1 << 2;
pub const CAP_PADDING_TIERS: u32 = 1 << 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHello {
    pub nonce: [u8; NONCE_LEN],
    pub capabilities: u32,
    pub padding: Vec<u8>,
}

impl ClientHello {
    pub fn new(
        nonce: [u8; NONCE_LEN],
        capabilities: u32,
        padding: Vec<u8>,
    ) -> Result<Self, EncodeError> {
        validate_padding_encode(padding.len())?;
        Ok(Self {
            nonce,
            capabilities,
            padding,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        validate_padding_encode(self.padding.len())?;
        let mut output = Vec::with_capacity(HELLO_FIXED_LEN + self.padding.len());
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(&self.capabilities.to_be_bytes());
        output.extend_from_slice(&(self.padding.len() as u16).to_be_bytes());
        output.extend_from_slice(&self.padding);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let fixed = input
            .get(..HELLO_FIXED_LEN)
            .ok_or(DecodeError::UnexpectedEnd)?;
        let nonce = fixed[..NONCE_LEN].try_into().unwrap();
        let capabilities = u32::from_be_bytes(fixed[NONCE_LEN..NONCE_LEN + 4].try_into().unwrap());
        let padding_len = u16::from_be_bytes(fixed[NONCE_LEN + 4..].try_into().unwrap()) as usize;
        let padding = decode_padding(input, HELLO_FIXED_LEN, padding_len)?;
        Ok(Self {
            nonce,
            capabilities,
            padding,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerHello {
    pub selected_version: u8,
    pub nonce: [u8; NONCE_LEN],
    pub capabilities: u32,
    pub max_control_payload: u32,
    pub padding: Vec<u8>,
}

impl ServerHello {
    pub fn new(
        nonce: [u8; NONCE_LEN],
        capabilities: u32,
        max_control_payload: u32,
        padding: Vec<u8>,
    ) -> Result<Self, EncodeError> {
        validate_server_limit_encode(max_control_payload)?;
        validate_padding_encode(padding.len())?;
        Ok(Self {
            selected_version: VERSION,
            nonce,
            capabilities,
            max_control_payload,
            padding,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        if self.selected_version != VERSION {
            return Err(EncodeError::InvalidSelectedVersion(self.selected_version));
        }
        validate_server_limit_encode(self.max_control_payload)?;
        validate_padding_encode(self.padding.len())?;
        let mut output = Vec::with_capacity(SERVER_HELLO_FIXED_LEN + self.padding.len());
        output.push(self.selected_version);
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(&self.capabilities.to_be_bytes());
        output.extend_from_slice(&self.max_control_payload.to_be_bytes());
        output.extend_from_slice(&(self.padding.len() as u16).to_be_bytes());
        output.extend_from_slice(&self.padding);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let fixed = input
            .get(..SERVER_HELLO_FIXED_LEN)
            .ok_or(DecodeError::UnexpectedEnd)?;
        let selected_version = fixed[0];
        if selected_version != VERSION {
            return Err(DecodeError::InvalidSelectedVersion(selected_version));
        }
        let nonce = fixed[1..1 + NONCE_LEN].try_into().unwrap();
        let capabilities =
            u32::from_be_bytes(fixed[1 + NONCE_LEN..1 + NONCE_LEN + 4].try_into().unwrap());
        let max_control_payload = u32::from_be_bytes(
            fixed[1 + NONCE_LEN + 4..1 + NONCE_LEN + 8]
                .try_into()
                .unwrap(),
        );
        validate_server_limit_decode(max_control_payload)?;
        let padding_len =
            u16::from_be_bytes(fixed[1 + NONCE_LEN + 8..].try_into().unwrap()) as usize;
        let padding = decode_padding(input, SERVER_HELLO_FIXED_LEN, padding_len)?;
        Ok(Self {
            selected_version,
            nonce,
            capabilities,
            max_control_payload,
            padding,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Auth {
    pub credential_id: String,
    pub proof: [u8; AUTH_PROOF_LEN],
    pub padding: Vec<u8>,
}

impl Auth {
    pub fn new(
        credential_id: String,
        proof: [u8; AUTH_PROOF_LEN],
        padding: Vec<u8>,
    ) -> Result<Self, EncodeError> {
        validate_credential_id_encode(&credential_id)?;
        validate_padding_encode(padding.len())?;
        Ok(Self {
            credential_id,
            proof,
            padding,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        validate_credential_id_encode(&self.credential_id)?;
        validate_padding_encode(self.padding.len())?;
        let mut output = Vec::with_capacity(
            1 + self.credential_id.len() + AUTH_PROOF_LEN + 2 + self.padding.len(),
        );
        output.push(self.credential_id.len() as u8);
        output.extend_from_slice(self.credential_id.as_bytes());
        output.extend_from_slice(&self.proof);
        output.extend_from_slice(&(self.padding.len() as u16).to_be_bytes());
        output.extend_from_slice(&self.padding);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let id_len = *input.first().ok_or(DecodeError::UnexpectedEnd)? as usize;
        let proof_start = 1usize
            .checked_add(id_len)
            .ok_or(DecodeError::UnexpectedEnd)?;
        let padding_len_start = proof_start
            .checked_add(AUTH_PROOF_LEN)
            .ok_or(DecodeError::UnexpectedEnd)?;
        let fixed_end = padding_len_start
            .checked_add(2)
            .ok_or(DecodeError::UnexpectedEnd)?;
        let fixed = input.get(..fixed_end).ok_or(DecodeError::UnexpectedEnd)?;
        let credential_id = std::str::from_utf8(&fixed[1..proof_start])
            .map_err(|_| DecodeError::InvalidCredentialId)?;
        validate_credential_id_decode(credential_id)?;
        let proof = fixed[proof_start..padding_len_start].try_into().unwrap();
        let padding_len =
            u16::from_be_bytes(fixed[padding_len_start..fixed_end].try_into().unwrap()) as usize;
        let padding = decode_padding(input, fixed_end, padding_len)?;
        Ok(Self {
            credential_id: credential_id.to_owned(),
            proof,
            padding,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthOk {
    pub session_id: [u8; SESSION_ID_LEN],
}

impl AuthOk {
    pub fn encode(&self) -> [u8; SESSION_ID_LEN] {
        self.session_id
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() < SESSION_ID_LEN {
            return Err(DecodeError::UnexpectedEnd);
        }
        if input.len() > SESSION_ID_LEN {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(Self {
            session_id: input.try_into().unwrap(),
        })
    }
}

pub fn compute_auth_proof(
    token: &[u8; 32],
    client_hello_payload: &[u8],
    server_hello_payload: &[u8],
) -> [u8; AUTH_PROOF_LEN] {
    let mut mac = HmacSha256::new_from_slice(token).expect("HMAC accepts a 32-byte key");
    update_transcript(&mut mac, client_hello_payload, server_hello_payload);
    mac.finalize().into_bytes().into()
}

pub fn verify_auth_proof(
    token: &[u8; 32],
    client_hello_payload: &[u8],
    server_hello_payload: &[u8],
    proof: &[u8; AUTH_PROOF_LEN],
) -> bool {
    let mut mac = HmacSha256::new_from_slice(token).expect("HMAC accepts a 32-byte key");
    update_transcript(&mut mac, client_hello_payload, server_hello_payload);
    mac.verify_slice(proof).is_ok()
}

fn update_transcript(
    mac: &mut HmacSha256,
    client_hello_payload: &[u8],
    server_hello_payload: &[u8],
) {
    mac.update(AUTH_DOMAIN);
    mac.update(&(client_hello_payload.len() as u32).to_be_bytes());
    mac.update(client_hello_payload);
    mac.update(&(server_hello_payload.len() as u32).to_be_bytes());
    mac.update(server_hello_payload);
}

fn decode_padding(input: &[u8], start: usize, length: usize) -> Result<Vec<u8>, DecodeError> {
    if length > MAX_PADDING_LEN {
        return Err(DecodeError::PaddingTooLarge {
            actual: length,
            limit: MAX_PADDING_LEN,
        });
    }
    let end = start
        .checked_add(length)
        .ok_or(DecodeError::UnexpectedEnd)?;
    let padding = input.get(start..end).ok_or(DecodeError::UnexpectedEnd)?;
    if input.len() != end {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(padding.to_vec())
}

fn validate_padding_encode(length: usize) -> Result<(), EncodeError> {
    if length > MAX_PADDING_LEN {
        return Err(EncodeError::PaddingTooLarge {
            actual: length,
            limit: MAX_PADDING_LEN,
        });
    }
    Ok(())
}

fn valid_credential_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CREDENTIAL_ID_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_credential_id_encode(value: &str) -> Result<(), EncodeError> {
    if !valid_credential_id(value) {
        return Err(EncodeError::InvalidCredentialId);
    }
    Ok(())
}

fn validate_credential_id_decode(value: &str) -> Result<(), DecodeError> {
    if !valid_credential_id(value) {
        return Err(DecodeError::InvalidCredentialId);
    }
    Ok(())
}

fn validate_server_limit_encode(value: u32) -> Result<(), EncodeError> {
    if value == 0 || value as usize > MAX_CONTROL_PAYLOAD {
        return Err(EncodeError::InvalidServerLimit(value));
    }
    Ok(())
}

fn validate_server_limit_decode(value: u32) -> Result<(), DecodeError> {
    if value == 0 || value as usize > MAX_CONTROL_PAYLOAD {
        return Err(DecodeError::InvalidServerLimit(value));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_messages_round_trip() {
        let client = ClientHello::new([1; NONCE_LEN], CAP_TCP_CONNECT, vec![2; 32]).unwrap();
        assert_eq!(ClientHello::decode(&client.encode().unwrap()), Ok(client));

        let server = ServerHello::new(
            [3; NONCE_LEN],
            CAP_TCP_CONNECT,
            MAX_CONTROL_PAYLOAD as u32,
            vec![4; 64],
        )
        .unwrap();
        assert_eq!(ServerHello::decode(&server.encode().unwrap()), Ok(server));
    }

    #[test]
    fn auth_round_trips() {
        let auth = Auth::new("desktop-main".into(), [9; AUTH_PROOF_LEN], vec![5; 16]).unwrap();
        assert_eq!(Auth::decode(&auth.encode().unwrap()), Ok(auth));
    }

    #[test]
    fn rejects_invalid_credential_ids() {
        for id in ["", "bad id", "slash/id"] {
            assert_eq!(
                Auth::new(id.into(), [0; AUTH_PROOF_LEN], Vec::new()),
                Err(EncodeError::InvalidCredentialId)
            );
        }
    }

    #[test]
    fn proof_binds_token_and_both_hello_payloads() {
        let token = [7; 32];
        let client = ClientHello::new([1; NONCE_LEN], CAP_TCP_CONNECT, vec![2; 8])
            .unwrap()
            .encode()
            .unwrap();
        let server = ServerHello::new(
            [3; NONCE_LEN],
            CAP_TCP_CONNECT,
            MAX_CONTROL_PAYLOAD as u32,
            vec![4; 8],
        )
        .unwrap()
        .encode()
        .unwrap();
        let proof = compute_auth_proof(&token, &client, &server);

        assert!(verify_auth_proof(&token, &client, &server, &proof));
        assert!(!verify_auth_proof(&[8; 32], &client, &server, &proof));

        let mut changed_client = client.clone();
        changed_client[0] ^= 1;
        assert!(!verify_auth_proof(&token, &changed_client, &server, &proof));

        let mut changed_server = server.clone();
        changed_server[1] ^= 1;
        assert!(!verify_auth_proof(&token, &client, &changed_server, &proof));
    }

    #[test]
    fn auth_ok_requires_exact_session_id_length() {
        let auth_ok = AuthOk {
            session_id: [6; SESSION_ID_LEN],
        };
        assert_eq!(AuthOk::decode(&auth_ok.encode()), Ok(auth_ok));
        assert_eq!(
            AuthOk::decode(&[0; SESSION_ID_LEN - 1]),
            Err(DecodeError::UnexpectedEnd)
        );
    }
}
