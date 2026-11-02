use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DecodeError {
    #[error("input ended before the value was complete")]
    UnexpectedEnd,
    #[error("invalid protocol magic")]
    InvalidMagic,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown frame type {0}")]
    UnknownFrameType(u8),
    #[error("unknown frame flags {0:#04x}")]
    UnknownFlags(u8),
    #[error("reserved header byte must be zero")]
    NonZeroReserved,
    #[error("payload length {actual} exceeds limit {limit}")]
    PayloadTooLarge { actual: usize, limit: usize },
    #[error("invalid address type {0}")]
    InvalidAddressType(u8),
    #[error("invalid address length {actual} for type {address_type}")]
    InvalidAddressLength { address_type: u8, actual: usize },
    #[error("domain is not valid ASCII")]
    InvalidDomain,
    #[error("domain length {actual} exceeds limit {limit}")]
    DomainTooLong { actual: usize, limit: usize },
    #[error("port must not be zero")]
    ZeroPort,
    #[error("trailing bytes after decoded value")]
    TrailingBytes,
    #[error("connect timeout {0}ms is outside the supported range")]
    InvalidConnectTimeout(u32),
    #[error("metadata is not supported by protocol version 1")]
    UnsupportedMetadata,
    #[error("padding length {actual} exceeds limit {limit}")]
    PaddingTooLarge { actual: usize, limit: usize },
    #[error("credential ID is invalid")]
    InvalidCredentialId,
    #[error("selected protocol version {0} is invalid")]
    InvalidSelectedVersion(u8),
    #[error("server control payload limit {0} is invalid")]
    InvalidServerLimit(u32),
    #[error("unknown connect error code {0}")]
    UnknownConnectErrorCode(u8),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EncodeError {
    #[error("payload length {actual} exceeds limit {limit}")]
    PayloadTooLarge { actual: usize, limit: usize },
    #[error("domain is empty or not valid protocol ASCII")]
    InvalidDomain,
    #[error("domain length {actual} exceeds limit {limit}")]
    DomainTooLong { actual: usize, limit: usize },
    #[error("port must not be zero")]
    ZeroPort,
    #[error("connect timeout {0}ms is outside the supported range")]
    InvalidConnectTimeout(u32),
    #[error("padding length {actual} exceeds limit {limit}")]
    PaddingTooLarge { actual: usize, limit: usize },
    #[error("credential ID is invalid")]
    InvalidCredentialId,
    #[error("selected protocol version {0} is invalid")]
    InvalidSelectedVersion(u8),
    #[error("server control payload limit {0} is invalid")]
    InvalidServerLimit(u32),
}
