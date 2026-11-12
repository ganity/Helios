mod address;
mod error;
mod frame;
mod handshake;
mod message;

pub use address::{Address, Target};
pub use error::{DecodeError, EncodeError};
pub use frame::{Frame, FrameType};
pub use handshake::{
    Auth, AuthOk, CAP_PADDING_TIERS, CAP_TCP_CONNECT, CAP_UDP_DATAGRAM, CAP_UDP_LARGE_STREAM,
    CAP_UDP_OVER_STREAM, ClientHello, ServerHello, compute_auth_proof, verify_auth_proof,
};
pub use message::{
    ConnectErrorCode, ConnectTcp, MAX_UDP_PAYLOAD, MAX_UDP_STREAM_PAYLOAD, UdpAssociate, UdpPacket,
};

pub const VERSION: u8 = 1;
pub const MAX_CONTROL_PAYLOAD: usize = 16 * 1024;
pub const MAX_DOMAIN_LEN: usize = 253;
pub const MAX_PADDING_LEN: usize = 4 * 1024;
pub const FRAME_HEADER_LEN: usize = 14;
pub const NONCE_LEN: usize = 32;
pub const AUTH_PROOF_LEN: usize = 32;
pub const SESSION_ID_LEN: usize = 16;
pub const MAX_CREDENTIAL_ID_LEN: usize = 64;
