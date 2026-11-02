use helios_protocol::{DecodeError, FRAME_HEADER_LEN, Frame};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Error)]
pub enum FrameIoError {
    #[error("frame I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid frame: {0}")]
    Decode(#[from] DecodeError),
    #[error("frame encoding failed: {0}")]
    Encode(#[from] helios_protocol::EncodeError),
}

pub struct FrameIo<S> {
    stream: S,
    padding_negotiated: bool,
}

impl<S> FrameIo<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            padding_negotiated: false,
        }
    }

    pub fn set_padding_negotiated(&mut self, enabled: bool) {
        self.padding_negotiated = enabled;
    }

    pub fn padding_negotiated(&self) -> bool {
        self.padding_negotiated
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S> FrameIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn read_frame(&mut self) -> Result<Frame, FrameIoError> {
        let mut encoded = vec![0; FRAME_HEADER_LEN];
        self.stream.read_exact(&mut encoded).await?;
        let payload_len = Frame::decode_header(&encoded)?;
        encoded.resize(FRAME_HEADER_LEN + payload_len, 0);
        self.stream
            .read_exact(&mut encoded[FRAME_HEADER_LEN..])
            .await?;
        Ok(Frame::decode(&encoded)?)
    }

    pub async fn write_frame(&mut self, frame: &Frame) -> Result<(), FrameIoError> {
        self.stream.write_all(&frame.encode()?).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<(), FrameIoError> {
        self.stream.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use helios_protocol::{FrameType, MAX_CONTROL_PAYLOAD, VERSION};
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn reads_and_writes_frames_over_fragmented_stream() {
        let (client, mut server) = duplex(64);
        let expected = Frame::new(FrameType::Ping, 7, b"probe".to_vec()).unwrap();
        let encoded = expected.encode().unwrap();

        let writer = tokio::spawn(async move {
            for byte in encoded {
                server.write_all(&[byte]).await.unwrap();
            }
        });

        let mut io = FrameIo::new(client);
        assert_eq!(io.read_frame().await.unwrap(), expected);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_oversized_payload_from_header_without_waiting_for_body() {
        let (client, mut server) = duplex(64);
        let mut header = vec![b'H', b'S', VERSION, FrameType::Ping as u8, 0, 0];
        header.extend_from_slice(&1u32.to_be_bytes());
        header.extend_from_slice(&((MAX_CONTROL_PAYLOAD + 1) as u32).to_be_bytes());
        server.write_all(&header).await.unwrap();

        let mut io = FrameIo::new(client);
        assert!(matches!(
            io.read_frame().await,
            Err(FrameIoError::Decode(DecodeError::PayloadTooLarge { .. }))
        ));
    }

    #[tokio::test]
    async fn writes_a_complete_decodable_frame() {
        let (client, server) = duplex(64);
        let expected = Frame::new(FrameType::Pong, 9, b"answer".to_vec()).unwrap();

        let reader = tokio::spawn(async move {
            let mut io = FrameIo::new(server);
            io.read_frame().await.unwrap()
        });
        let mut io = FrameIo::new(client);
        io.write_frame(&expected).await.unwrap();

        assert_eq!(reader.await.unwrap(), expected);
    }
}
