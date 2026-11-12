//! TLS session over a connection supplied by the platform VPN host.
use std::{error::Error, time::Duration};

use helios_client_model::NodeProfile;
use helios_config::{load_roots, load_token};
use helios_protocol::{
    CAP_UDP_LARGE_STREAM, CAP_UDP_OVER_STREAM, ConnectTcp, Frame, FrameType, MAX_UDP_PAYLOAD,
    MAX_UDP_STREAM_PAYLOAD, Target, UdpAssociate, UdpPacket,
};
use helios_transport::{ClientCrypto, ClientTlsStream, FrameIo, TlsClient};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};

type SessionError = Box<dyn Error + Send + Sync>;

pub struct Session {
    pub(crate) tls: TlsClient,
    pub(crate) quic: quinn::ClientConfig,
    pub(crate) prefer_quic: bool,
    pub(crate) name: String,
    server_name: ServerName<'static>,
    pub(crate) credential_id: String,
    pub(crate) token: [u8; 32],
    pub(crate) connection: tokio::sync::Mutex<
        Option<(
            std::net::SocketAddr,
            std::sync::Arc<crate::connection::QuicOwner>,
        )>,
    >,
}

pub struct UdpSession<S> {
    pub(crate) io: FrameIo<S>,
    pub(crate) association_id: u32,
    pub(crate) limit: usize,
}

pub struct UdpSender<S> {
    io: FrameIo<tokio::io::WriteHalf<S>>,
    pub(crate) association_id: u32,
    pub(crate) limit: usize,
}

pub struct UdpReceiver<S> {
    io: FrameIo<tokio::io::ReadHalf<S>>,
    pub(crate) association_id: u32,
    pub(crate) limit: usize,
}

impl Session {
    /// Measures a verified TLS and Helios authentication round trip, not ICMP ping.
    pub async fn probe<S>(&self, stream: S, deadline: Duration) -> Result<Duration, SessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let start = std::time::Instant::now();
        tokio::time::timeout(deadline, async {
            let mut io = self.tls.connect(self.server_name.clone(), stream).await?;
            helios_transport::authenticate_client(
                &mut io,
                &self.credential_id,
                &self.token,
                CAP_UDP_OVER_STREAM,
            )
            .await?;
            Ok::<_, SessionError>(())
        })
        .await??;
        Ok(start.elapsed())
    }

    pub fn from_node(node: &NodeProfile) -> Result<Self, SessionError> {
        let crypto = ClientCrypto::new(load_roots(&node.ca_certificate)?)?;
        Ok(Self {
            tls: crypto.tls,
            quic: crypto.quic,
            prefer_quic: node.preferred_transport == helios_config::TransportPreference::Quic,
            name: node.server_name.clone(),
            server_name: ServerName::try_from(node.server_name.clone())?,
            credential_id: node.credential_id.clone(),
            token: load_token(&node.token_file)?,
            connection: tokio::sync::Mutex::new(None),
        })
    }

    /// The caller must connect to the node outside the VPN's captured routes.
    pub async fn open_tcp<S>(
        &self,
        stream: S,
        target: Target,
        timeout_ms: u32,
    ) -> Result<ClientTlsStream<S>, SessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let request = ConnectTcp::new(target, timeout_ms, Vec::new())?;
        tokio::time::timeout(Duration::from_millis(timeout_ms.into()), async {
            let mut io = self.tls.connect(self.server_name.clone(), stream).await?;
            helios_transport::authenticate_client_with_connect(
                &mut io,
                &self.credential_id,
                &self.token,
                &request,
            )
            .await?;
            Ok::<_, SessionError>(helios_transport::finish_tcp_connect(io, &request).await?)
        })
        .await?
    }

    /// Opens UDP-over-TLS using a connection established outside the VPN.
    pub async fn open_udp<S>(
        &self,
        stream: S,
        deadline: Duration,
    ) -> Result<UdpSession<ClientTlsStream<S>>, SessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::time::timeout(deadline, async {
            let mut io = self.tls.connect(self.server_name.clone(), stream).await?;
            let negotiated = helios_transport::authenticate_client(
                &mut io,
                &self.credential_id,
                &self.token,
                CAP_UDP_OVER_STREAM | CAP_UDP_LARGE_STREAM,
            )
            .await?;
            let limit = if negotiated.capabilities & CAP_UDP_LARGE_STREAM != 0 {
                MAX_UDP_STREAM_PAYLOAD
            } else {
                MAX_UDP_PAYLOAD
            };
            io.write_frame(&Frame::new(
                FrameType::UdpAssociate,
                1,
                UdpAssociate { target: None }.encode()?,
            )?)
            .await?;
            let response = io.read_frame().await?;
            if response.frame_type != FrameType::UdpAssociateOk
                || response.request_id != 1
                || response.payload.len() != 4
            {
                return Err("invalid UDP association response".into());
            }
            let association_id = u32::from_be_bytes(response.payload.as_slice().try_into()?);
            Ok(UdpSession {
                io,
                association_id,
                limit,
            })
        })
        .await?
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> UdpSession<S> {
    pub fn split(self) -> (UdpSender<S>, UdpReceiver<S>) {
        let (read, write) = tokio::io::split(self.io.into_inner());
        (
            UdpSender {
                io: FrameIo::new(write),
                association_id: self.association_id,
                limit: self.limit,
            },
            UdpReceiver {
                io: FrameIo::new(read),
                association_id: self.association_id,
                limit: self.limit,
            },
        )
    }
    pub async fn send(
        &mut self,
        packet_id: u32,
        target: Target,
        payload: Vec<u8>,
    ) -> Result<(), SessionError> {
        let packet =
            UdpPacket::new_with_limit(self.association_id, packet_id, target, payload, self.limit)?;
        self.io
            .write_frame(&Frame::new(
                FrameType::UdpPacket,
                packet_id,
                packet.encode_with_limit(self.limit)?,
            )?)
            .await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<UdpPacket, SessionError> {
        let frame = self.io.read_frame().await?;
        if frame.frame_type != FrameType::UdpPacket {
            return Err("unexpected UDP frame".into());
        }
        let packet = UdpPacket::decode_with_limit(&frame.payload, self.limit)?;
        if packet.association_id != self.association_id || frame.request_id != packet.packet_id {
            return Err("UDP association or packet ID mismatch".into());
        }
        Ok(packet)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> UdpSender<S> {
    pub fn payload_limit(&self) -> usize {
        self.limit
    }
    pub async fn send(
        &mut self,
        packet_id: u32,
        target: Target,
        payload: Vec<u8>,
    ) -> Result<(), SessionError> {
        let packet =
            UdpPacket::new_with_limit(self.association_id, packet_id, target, payload, self.limit)?;
        self.io
            .write_frame(&Frame::new(
                FrameType::UdpPacket,
                packet_id,
                packet.encode_with_limit(self.limit)?,
            )?)
            .await?;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> UdpReceiver<S> {
    pub async fn receive(&mut self) -> Result<UdpPacket, SessionError> {
        let frame = self.io.read_frame().await?;
        if frame.frame_type != FrameType::UdpPacket {
            return Err("unexpected UDP frame".into());
        }
        let packet = UdpPacket::decode_with_limit(&frame.payload, self.limit)?;
        if packet.association_id != self.association_id || frame.request_id != packet.packet_id {
            return Err("UDP association or packet ID mismatch".into());
        }
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use helios_config::{ConnectionLink, TransportPreference};
    use helios_protocol::{Address, CAP_TCP_CONNECT};
    use helios_transport::{FrameIo, ServerCrypto, accept_tcp, authenticate_server};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    #[tokio::test]
    async fn probe_verifies_credentials_and_times_out() {
        let directory = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["node.test".into()]).unwrap();
        let link = ConnectionLink::new(
            "Probe".into(),
            "127.0.0.1:443".parse().unwrap(),
            "node.test".into(),
            cert.cert.der().as_ref(),
            "client".into(),
            [42; 32],
            TransportPreference::Tls,
        )
        .unwrap()
        .encode()
        .unwrap();
        let node = crate::node_store::import(directory.path(), &link).unwrap();
        for accepted in [true, false] {
            let session = Session::from_node(&node).unwrap();
            let server = ServerCrypto::new(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
            )
            .unwrap();
            let (client, peer) = tokio::io::duplex(65536);
            let task = tokio::spawn(async move {
                let mut io = server.tls.accept(peer).await.unwrap();
                authenticate_server(&mut io, CAP_UDP_OVER_STREAM, |_| {
                    Some(if accepted { [42; 32] } else { [7; 32] })
                })
                .await
                .is_ok()
            });
            assert_eq!(
                session.probe(client, Duration::from_secs(3)).await.is_ok(),
                accepted
            );
            assert_eq!(task.await.unwrap(), accepted);
        }
        let (client, _stalled_peer) = tokio::io::duplex(65536);
        assert!(
            Session::from_node(&node)
                .unwrap()
                .probe(client, Duration::from_millis(10))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn imported_node_authenticates_and_opens_a_tcp_stream() {
        let directory = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["node.test".into()]).unwrap();
        let link = ConnectionLink::new(
            "Test".into(),
            "127.0.0.1:443".parse().unwrap(),
            "node.test".into(),
            cert.cert.der().as_ref(),
            "client".into(),
            [42; 32],
            TransportPreference::Tls,
        )
        .unwrap()
        .encode()
        .unwrap();
        let node = crate::node_store::import(directory.path(), &link).unwrap();
        let session = Session::from_node(&node).unwrap();
        let server = ServerCrypto::new(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server_task = tokio::spawn(async move {
            let mut io: FrameIo<_> = server.tls.accept(server_io).await.unwrap();
            authenticate_server(&mut io, CAP_TCP_CONNECT, |id| {
                (id == "client").then_some([42; 32])
            })
            .await
            .unwrap();
            let (mut tunnel, mut target_stream) = accept_tcp(io).await.unwrap();
            tokio::io::copy_bidirectional(&mut tunnel, &mut target_stream)
                .await
                .unwrap();
        });
        let echo = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let target = Target::new(Address::Ip(target_address.ip()), target_address.port()).unwrap();
        let mut stream = session.open_tcp(client_io, target, 3000).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping");
        stream.shutdown().await.unwrap();
        drop(stream);
        echo.await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_a_server_with_an_untrusted_certificate() {
        let directory = tempfile::tempdir().unwrap();
        let trusted = rcgen::generate_simple_self_signed(vec!["node.test".into()]).unwrap();
        let other = rcgen::generate_simple_self_signed(vec!["node.test".into()]).unwrap();
        let link = ConnectionLink::new(
            "Test".into(),
            "127.0.0.1:443".parse().unwrap(),
            "node.test".into(),
            trusted.cert.der().as_ref(),
            "client".into(),
            [42; 32],
            TransportPreference::Tls,
        )
        .unwrap()
        .encode()
        .unwrap();
        let node = crate::node_store::import(directory.path(), &link).unwrap();
        let session = Session::from_node(&node).unwrap();
        let server = ServerCrypto::new(
            vec![other.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(other.signing_key.serialize_der())),
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server_task = tokio::spawn(async move { server.tls.accept(server_io).await.is_err() });
        let target = Target::new(Address::Ip("127.0.0.1".parse().unwrap()), 443).unwrap();
        assert!(session.open_tcp(client_io, target, 3000).await.is_err());
        assert!(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn udp_association_authenticates_and_transfers_datagrams() {
        let directory = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["node.test".into()]).unwrap();
        let link = ConnectionLink::new(
            "Test".into(),
            "127.0.0.1:443".parse().unwrap(),
            "node.test".into(),
            cert.cert.der().as_ref(),
            "client".into(),
            [42; 32],
            TransportPreference::Tls,
        )
        .unwrap()
        .encode()
        .unwrap();
        let node = crate::node_store::import(directory.path(), &link).unwrap();
        let session = Session::from_node(&node).unwrap();
        let server = ServerCrypto::new(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server_task = tokio::spawn(async move {
            let mut io = server.tls.accept(server_io).await.unwrap();
            authenticate_server(&mut io, CAP_UDP_OVER_STREAM, |id| {
                (id == "client").then_some([42; 32])
            })
            .await
            .unwrap();
            let request = io.read_frame().await.unwrap();
            assert_eq!(request.frame_type, FrameType::UdpAssociate);
            io.write_frame(
                &Frame::new(
                    FrameType::UdpAssociateOk,
                    request.request_id,
                    7u32.to_be_bytes().to_vec(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
            let request = io.read_frame().await.unwrap();
            let packet = UdpPacket::decode(&request.payload).unwrap();
            assert_eq!(packet.association_id, 7);
            let second = io.read_frame().await.unwrap();
            assert_eq!(UdpPacket::decode(&second.payload).unwrap().packet_id, 13);
            io.write_frame(
                &Frame::new(
                    FrameType::UdpPacket,
                    request.request_id,
                    packet.encode().unwrap(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
            io.shutdown().await.unwrap();
        });
        let udp = session
            .open_udp(client_io, Duration::from_secs(3))
            .await
            .unwrap();
        let target = Target::new(Address::Ip("127.0.0.1".parse().unwrap()), 53).unwrap();
        let (mut sender, mut receiver) = udp.split();
        sender
            .send(12, target.clone(), b"dns".to_vec())
            .await
            .unwrap();
        sender
            .send(13, target.clone(), b"next".to_vec())
            .await
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(3), receiver.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.target, target);
        assert_eq!(reply.packet_id, 12);
        assert_eq!(reply.payload, b"dns");
        server_task.await.unwrap();
    }
}
