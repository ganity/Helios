use std::net::IpAddr;

use helios_protocol::{Address, EncodeError, Target};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;

#[derive(Debug, Error)]
pub enum HttpConnectError {
    #[error("HTTP proxy I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP request headers exceed 16 KiB")]
    HeadersTooLarge,
    #[error("HTTP request has too many headers")]
    TooManyHeaders,
    #[error("malformed HTTP proxy request")]
    Malformed,
    #[error("unsupported HTTP proxy method")]
    UnsupportedMethod,
    #[error("invalid HTTP proxy target: {0}")]
    InvalidTarget(#[from] EncodeError),
}

pub struct HttpConnect<S> {
    stream: S,
    connect: bool,
    forward_head: Vec<u8>,
}

impl<S> HttpConnect<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn accept(mut stream: S) -> Result<(Self, Target), HttpConnectError> {
        let mut bytes = Vec::with_capacity(1024);
        while !bytes.ends_with(b"\r\n\r\n") {
            if bytes.len() == MAX_HEADER_BYTES {
                return Err(HttpConnectError::HeadersTooLarge);
            }
            bytes.push(stream.read_u8().await?);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| HttpConnectError::Malformed)?;
        let mut lines = text[..text.len() - 4].split("\r\n");
        let request = lines.next().ok_or(HttpConnectError::Malformed)?;
        let mut parts = request.split_whitespace();
        let method = parts.next().ok_or(HttpConnectError::Malformed)?;
        let authority = parts.next().ok_or(HttpConnectError::Malformed)?;
        let version = parts.next().ok_or(HttpConnectError::Malformed)?;
        if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || parts.next().is_some() {
            return Err(HttpConnectError::Malformed);
        }
        let headers: Vec<_> = lines.collect();
        if headers.len() > MAX_HEADERS {
            return Err(HttpConnectError::TooManyHeaders);
        }
        if headers
            .iter()
            .any(|line| line.is_empty() || !line.contains(':'))
        {
            return Err(HttpConnectError::Malformed);
        }
        if method == "CONNECT" {
            let target = parse_authority(authority)?;
            return Ok((
                Self {
                    stream,
                    connect: true,
                    forward_head: Vec::new(),
                },
                target,
            ));
        }
        if !matches!(
            method,
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
        ) {
            stream
                .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
                .await?;
            return Err(HttpConnectError::UnsupportedMethod);
        }
        let (target, path) = parse_absolute_http_uri(authority)?;
        let mut forward_head = format!("{method} {path} {version}\r\n").into_bytes();
        for header in headers {
            if !header
                .split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("proxy-connection"))
            {
                forward_head.extend_from_slice(header.as_bytes());
                forward_head.extend_from_slice(b"\r\n");
            }
        }
        forward_head.extend_from_slice(b"\r\n");
        Ok((
            Self {
                stream,
                connect: false,
                forward_head,
            },
            target,
        ))
    }

    pub async fn connected(&mut self) -> Result<(), HttpConnectError> {
        if self.connect {
            self.stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            self.stream.flush().await?;
        }
        Ok(())
    }

    pub async fn failed(&mut self) -> Result<(), HttpConnectError> {
        self.stream
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            .await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    pub fn forward_head(&self) -> &[u8] {
        &self.forward_head
    }
}

fn parse_absolute_http_uri(uri: &str) -> Result<(Target, &str), HttpConnectError> {
    let rest = uri
        .strip_prefix("http://")
        .ok_or(HttpConnectError::Malformed)?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') || path.contains('#') {
        return Err(HttpConnectError::Malformed);
    }
    let target = if authority.starts_with('[') || authority.rsplit_once(':').is_some() {
        parse_authority(authority)?
    } else {
        let address = authority
            .parse::<IpAddr>()
            .map(Address::Ip)
            .unwrap_or_else(|_| Address::Domain(authority.to_owned()));
        Target::new(address, 80)?
    };
    Ok((target, path))
}

fn parse_authority(authority: &str) -> Result<Target, HttpConnectError> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or(HttpConnectError::Malformed)?;
        (host, port)
    } else {
        authority
            .rsplit_once(':')
            .ok_or(HttpConnectError::Malformed)?
    };
    if host.is_empty() || host.contains(['/', '@']) {
        return Err(HttpConnectError::Malformed);
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| HttpConnectError::Malformed)?;
    let address = host
        .parse::<IpAddr>()
        .map(Address::Ip)
        .unwrap_or_else(|_| Address::Domain(host.to_owned()));
    Ok(Target::new(address, port)?)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn preserves_domain_and_tunnel_bytes() {
        let (mut client, server) = duplex(1024);
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nhello")
            .await
            .unwrap();
        let (mut connect, target) = HttpConnect::accept(server).await.unwrap();
        assert_eq!(target.address, Address::Domain("example.com".into()));
        assert_eq!(target.port, 443);
        connect.connected().await.unwrap();
        let mut response = [0; 39];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        let mut tunnel = [0; 5];
        connect.into_inner().read_exact(&mut tunnel).await.unwrap();
        assert_eq!(&tunnel, b"hello");
    }

    #[tokio::test]
    async fn rewrites_forward_proxy_requests_and_preserves_body() {
        let (mut client, server) = duplex(256);
        client
            .write_all(b"POST http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nContent-Length: 4\r\n\r\nbody")
            .await
            .unwrap();
        let (request, target) = HttpConnect::accept(server).await.unwrap();
        assert_eq!(target.address, Address::Domain("example.com".into()));
        assert_eq!(target.port, 80);
        assert_eq!(
            request.forward_head(),
            b"POST /path?q=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n"
        );
        let mut body = [0; 4];
        request.into_inner().read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"body");
    }
}
