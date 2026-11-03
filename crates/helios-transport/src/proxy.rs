use std::{io::ErrorKind, time::Duration};

use helios_protocol::{ConnectErrorCode, ConnectTcp, DecodeError, EncodeError, Frame, FrameType};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::timeout,
};

use crate::{FrameIo, FrameIoError};

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("target connect response timed out")]
    ResponseTimeout,
    #[error("operating system random source failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error(transparent)]
    Frame(#[from] FrameIoError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error("unexpected frame {0:?} during TCP connect")]
    UnexpectedFrame(FrameType),
    #[error("connect response request ID does not match request")]
    RequestIdMismatch,
    #[error("proxy rejected TCP connect: {0:?}")]
    Rejected(ConnectErrorCode),
    #[error("target connect failed: {0}")]
    Target(std::io::Error),
}

pub async fn open_tcp<S>(
    mut io: FrameIo<S>,
    request_id: u32,
    request: &ConnectTcp,
) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(
        Duration::from_millis(u64::from(request.timeout_ms) + 1000),
        async {
            let mut request = request.clone();
            if io.padding_negotiated() && request.padding.is_empty() {
                request.padding = crate::padding::random_padding(request.encode()?.len())?;
            }
            io.write_frame(&Frame::new(
                FrameType::ConnectTcp,
                request_id,
                request.encode()?,
            )?)
            .await?;
            read_connect_response(io, request_id).await
        },
    )
    .await
    .map_err(|_| ConnectError::ResponseTimeout)?
}

/// Completes a ConnectTcp already queued by authenticate_client_with_connect.
pub async fn finish_tcp_connect<S>(io: FrameIo<S>, request: &ConnectTcp) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(
        Duration::from_millis(u64::from(request.timeout_ms) + 1000),
        read_connect_response(io, 3),
    )
    .await
    .map_err(|_| ConnectError::ResponseTimeout)?
}

async fn read_connect_response<S>(mut io: FrameIo<S>, request_id: u32) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let response = io.read_frame().await?;
    if response.request_id != request_id {
        return Err(ConnectError::RequestIdMismatch);
    }
    match response.frame_type {
        FrameType::ConnectOk if response.payload.is_empty() => Ok(io.into_inner()),
        FrameType::ConnectError if response.payload.len() == 1 => Err(ConnectError::Rejected(
            ConnectErrorCode::try_from(response.payload[0])?,
        )),
        actual => Err(ConnectError::UnexpectedFrame(actual)),
    }
}

pub async fn accept_tcp<S>(mut io: FrameIo<S>) -> Result<(S, TcpStream), ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = io.read_frame().await?;
    accept_tcp_frame(io, frame).await
}

pub async fn accept_tcp_frame<S>(
    mut io: FrameIo<S>,
    frame: Frame,
) -> Result<(S, TcpStream), ConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if frame.frame_type != FrameType::ConnectTcp {
        return Err(ConnectError::UnexpectedFrame(frame.frame_type));
    }
    let request = ConnectTcp::decode(&frame.payload)?;
    let started = std::time::Instant::now();
    let connect = crate::dial::connect_target(&request.target);
    let target = match timeout(Duration::from_millis(request.timeout_ms.into()), connect).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            let code = map_connect_error(&error);
            send_connect_error(&mut io, frame.request_id, code).await?;
            return Err(ConnectError::Target(error));
        }
        Err(_) => {
            send_connect_error(&mut io, frame.request_id, ConnectErrorCode::Timeout).await?;
            return Err(ConnectError::Target(std::io::Error::new(
                ErrorKind::TimedOut,
                "target connect timed out",
            )));
        }
    };

    tracing::debug!(
        event = "target_connected",
        elapsed_ms = started.elapsed().as_millis() as u64
    );

    io.write_frame(&Frame::new(
        FrameType::ConnectOk,
        frame.request_id,
        Vec::new(),
    )?)
    .await?;
    Ok((io.into_inner(), target))
}

async fn send_connect_error<S>(
    io: &mut FrameIo<S>,
    request_id: u32,
    code: ConnectErrorCode,
) -> Result<(), FrameIoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    io.write_frame(&Frame::new(
        FrameType::ConnectError,
        request_id,
        vec![code as u8],
    )?)
    .await
}

fn map_connect_error(error: &std::io::Error) -> ConnectErrorCode {
    match error.kind() {
        ErrorKind::ConnectionRefused => ConnectErrorCode::ConnectionRefused,
        ErrorKind::TimedOut => ConnectErrorCode::Timeout,
        ErrorKind::AddrNotAvailable | ErrorKind::InvalidInput => {
            ConnectErrorCode::AddressUnsupported
        }
        ErrorKind::NetworkUnreachable => ConnectErrorCode::NetworkUnreachable,
        ErrorKind::HostUnreachable | ErrorKind::NotFound => ConnectErrorCode::HostUnreachable,
        ErrorKind::PermissionDenied => ConnectErrorCode::NotAllowed,
        _ => ConnectErrorCode::GeneralFailure,
    }
}

#[cfg(test)]
mod tests {
    use helios_protocol::{Address, CAP_TCP_CONNECT, Target};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional, duplex};
    use tokio::net::TcpListener;

    use crate::{authenticate_client, authenticate_server};

    use super::*;

    #[tokio::test]
    async fn pipelined_client_works_with_existing_server_and_padding() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, server) = duplex(16384);
        let peer = tokio::spawn(async move {
            let mut io = FrameIo::new(server);
            authenticate_server(&mut io, CAP_TCP_CONNECT, |_| Some([7; 32]))
                .await
                .unwrap();
            assert!(io.padding_negotiated());
            let (mut stream, _target) = accept_tcp(io).await.unwrap();
            stream.write_all(b"verified").await.unwrap();
        });
        let request = ConnectTcp::new(
            Target::new(Address::Ip(address.ip()), address.port()).unwrap(),
            1000,
            vec![],
        )
        .unwrap();
        let mut io = FrameIo::new(client);
        crate::authenticate_client_with_connect(&mut io, "test", &[7; 32], &request)
            .await
            .unwrap();
        let mut stream = finish_tcp_connect(io, &request).await.unwrap();
        let mut bytes = [0; 8];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"verified");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn blocked_request_write_also_has_a_deadline() {
        let (client, _unread_peer) = duplex(1);
        let request = ConnectTcp::new(
            Target::new(Address::Ip("127.0.0.1".parse().unwrap()), 443).unwrap(),
            1000,
            vec![],
        )
        .unwrap();
        assert!(matches!(
            open_tcp(FrameIo::new(client), 3, &request).await,
            Err(ConnectError::ResponseTimeout)
        ));
    }

    #[tokio::test]
    async fn missing_connect_response_does_not_hold_flow_forever() {
        let (client, server) = duplex(4096);
        let request = ConnectTcp::new(
            Target::new(Address::Ip("127.0.0.1".parse().unwrap()), 443).unwrap(),
            1000,
            vec![],
        )
        .unwrap();
        let peer = tokio::spawn(async move {
            let mut io = FrameIo::new(server);
            io.read_frame().await.unwrap();
            std::future::pending::<()>().await;
        });
        assert!(matches!(
            open_tcp(FrameIo::new(client), 3, &request).await,
            Err(ConnectError::ResponseTimeout)
        ));
        peer.abort();
    }

    #[tokio::test]
    async fn connect_padding_requires_negotiation_and_preserves_explicit_padding() {
        for (negotiated, padding) in [(false, vec![]), (true, vec![]), (true, vec![9; 7])] {
            let (client, server) = duplex(4096);
            let original_padding = padding.clone();
            let request = ConnectTcp::new(
                Target::new(Address::Domain("example.com".into()), 443).unwrap(),
                3000,
                padding,
            )
            .unwrap();
            let peer = tokio::spawn(async move {
                let mut io = FrameIo::new(server);
                let frame = io.read_frame().await.unwrap();
                let decoded = ConnectTcp::decode(&frame.payload).unwrap();
                if negotiated && original_padding.is_empty() {
                    assert!(!decoded.padding.is_empty());
                    assert!(
                        [256, 512, 1024, 2048]
                            .contains(&(frame.payload.len() + helios_protocol::FRAME_HEADER_LEN))
                    );
                } else {
                    assert_eq!(decoded.padding, original_padding);
                }
                assert_eq!(decoded.target.port, 443);
                io.write_frame(
                    &Frame::new(FrameType::ConnectOk, frame.request_id, vec![]).unwrap(),
                )
                .await
                .unwrap();
            });
            let mut io = FrameIo::new(client);
            io.set_padding_negotiated(negotiated);
            open_tcp(io, 3, &request).await.unwrap();
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn authenticates_connects_and_relays_raw_bytes() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut request = [0; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.unwrap();
        });

        let token = [7; 32];
        let (client_stream, server_stream) = duplex(16 * 1024);
        let server = tokio::spawn(async move {
            let mut io = FrameIo::new(server_stream);
            authenticate_server(&mut io, CAP_TCP_CONNECT, |_| Some(token))
                .await
                .unwrap();
            let (mut client, mut target) = accept_tcp(io).await.unwrap();
            copy_bidirectional(&mut client, &mut target).await.unwrap();
        });

        let mut io = FrameIo::new(client_stream);
        authenticate_client(&mut io, "desktop-main", &token, CAP_TCP_CONNECT)
            .await
            .unwrap();
        let request = ConnectTcp::new(
            Target::new(Address::Ip(target_address.ip()), target_address.port()).unwrap(),
            3_000,
            Vec::new(),
        )
        .unwrap();
        let mut stream = open_tcp(io, 3, &request).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();

        assert_eq!(response, b"world");
        target.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn returns_specific_refused_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable = listener.local_addr().unwrap();
        drop(listener);

        let (client_stream, server_stream) = duplex(4096);
        let server = tokio::spawn(async move {
            let io = FrameIo::new(server_stream);
            assert!(matches!(
                accept_tcp(io).await,
                Err(ConnectError::Target(error)) if error.kind() == ErrorKind::ConnectionRefused
            ));
        });

        let request = ConnectTcp::new(
            Target::new(Address::Ip(unavailable.ip()), unavailable.port()).unwrap(),
            3_000,
            Vec::new(),
        )
        .unwrap();
        let io = FrameIo::new(client_stream);
        assert!(matches!(
            open_tcp(io, 3, &request).await,
            Err(ConnectError::Rejected(ConnectErrorCode::ConnectionRefused))
        ));
        server.await.unwrap();
    }
}
