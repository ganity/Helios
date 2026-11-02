use std::time::{Duration, Instant};

use helios_protocol::{EncodeError, Frame, FrameType};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{FrameIo, FrameIoError};

#[derive(Debug, Error)]
pub enum ControlError {
    #[error(transparent)]
    Frame(#[from] FrameIoError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error("unexpected control frame {0:?}")]
    UnexpectedFrame(FrameType),
    #[error("control response request ID does not match request")]
    RequestIdMismatch,
    #[error("PONG payload does not match PING")]
    PayloadMismatch,
}

pub async fn ping<S>(
    io: &mut FrameIo<S>,
    request_id: u32,
    payload: &[u8],
) -> Result<Duration, ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    io.write_frame(&Frame::new(FrameType::Ping, request_id, payload.to_vec())?)
        .await?;
    let response = io.read_frame().await?;
    if response.request_id != request_id {
        return Err(ControlError::RequestIdMismatch);
    }
    if response.frame_type != FrameType::Pong {
        return Err(ControlError::UnexpectedFrame(response.frame_type));
    }
    if response.payload != payload {
        return Err(ControlError::PayloadMismatch);
    }
    Ok(started.elapsed())
}

pub async fn serve_control<S>(mut io: FrameIo<S>) -> Result<(), ControlError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let request = io.read_frame().await?;
        match request.frame_type {
            FrameType::Ping => {
                io.write_frame(&Frame::new(
                    FrameType::Pong,
                    request.request_id,
                    request.payload,
                )?)
                .await?;
            }
            FrameType::Close => return Ok(()),
            actual => return Err(ControlError::UnexpectedFrame(actual)),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    #[tokio::test]
    async fn measures_authenticated_control_round_trip() {
        let (client, server) = duplex(4096);
        let server = tokio::spawn(serve_control(FrameIo::new(server)));
        let mut client = FrameIo::new(client);

        let elapsed = ping(&mut client, 7, b"health").await.unwrap();
        assert!(elapsed < Duration::from_secs(1));
        client
            .write_frame(&Frame::new(FrameType::Close, 8, Vec::new()).unwrap())
            .await
            .unwrap();
        server.await.unwrap().unwrap();
    }
}
