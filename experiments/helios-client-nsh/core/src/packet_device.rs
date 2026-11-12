//! Bounded packet queues for platforms with a packet API instead of a TUN fd.
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};

const QUEUE_PACKETS: usize = 128;
pub const MTU: usize = 1500;
type Reservation = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Vec<u8>>, mpsc::error::SendError<()>>> + Send>,
>;

pub struct PacketDevice {
    input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Vec<u8>>,
    reservation: Option<Reservation>,
}
pub struct PacketPort {
    input: mpsc::Sender<Vec<u8>>,
    output: mpsc::Receiver<Vec<u8>>,
}

pub fn pair() -> (PacketDevice, PacketPort) {
    let (input, incoming) = mpsc::channel(QUEUE_PACKETS);
    let (outgoing, output) = mpsc::channel(QUEUE_PACKETS);
    (
        PacketDevice {
            input: incoming,
            output: outgoing,
            reservation: None,
        },
        PacketPort { input, output },
    )
}

pub fn validate(packet: &[u8]) -> io::Result<()> {
    let valid = match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 15) * 4;
            header >= 20
                && header <= packet.len()
                && usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
        }
        Some(6) if packet.len() >= 40 => {
            usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 == packet.len()
        }
        _ => false,
    };
    if !valid || packet.len() > MTU {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid or oversized IP packet",
        ));
    }
    Ok(())
}

impl PacketPort {
    pub fn push(&self, packet: &[u8]) -> io::Result<()> {
        validate(packet)?;
        self.input
            .try_send(packet.to_vec())
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock.into(),
                mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe.into(),
            })
    }
    pub fn pop(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.output.try_recv() {
            Ok(packet) => Ok(Some(packet)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

impl AsyncRead for PacketDevice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.input.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                if buffer.remaining() < packet.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "packet buffer is too small",
                    )));
                }
                buffer.put_slice(&packet);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}
impl AsyncWrite for PacketDevice {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        validate(bytes)?;
        if self.reservation.is_none() {
            self.reservation = Some(Box::pin(self.output.clone().reserve_owned()));
        }
        match self.reservation.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                self.reservation = None;
                permit.send(bytes.to_vec());
                Poll::Ready(Ok(bytes.len()))
            }
            Poll::Ready(Err(_)) => {
                self.reservation = None;
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn packet() -> Vec<u8> {
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet
    }
    #[tokio::test]
    async fn preserves_packet_boundaries_and_bounds_queues() {
        let (mut device, mut host) = pair();
        let bytes = packet();
        assert!(host.push(b"invalid").is_err());
        for _ in 0..QUEUE_PACKETS {
            host.push(&bytes).unwrap();
        }
        assert_eq!(
            host.push(&bytes).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let mut buffer = [0; MTU];
        assert_eq!(device.read(&mut buffer).await.unwrap(), bytes.len());
        for _ in 0..QUEUE_PACKETS {
            device.write_all(&bytes).await.unwrap();
        }
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                device.write_all(&bytes)
            )
            .await
            .is_err()
        );
        assert_eq!(host.pop().unwrap().unwrap(), bytes);
        device.write_all(&bytes).await.unwrap();
        drop(host);
        assert!(device.write_all(&bytes).await.is_err());
    }
}
