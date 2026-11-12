//! Platform-protected QUIC connections, with the same TLS fallback as the desktop.
use crate::{
    session::{Session, UdpReceiver, UdpSender, UdpSession},
    tunnel::Connector,
};
use helios_protocol::{
    CAP_TCP_CONNECT, CAP_UDP_DATAGRAM, CAP_UDP_LARGE_STREAM, ConnectTcp, Frame, FrameType,
    MAX_UDP_PAYLOAD, MAX_UDP_STREAM_PAYLOAD, Target, UdpAssociate, UdpPacket,
};
use helios_transport::{FrameIo, QuicBiStream};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type Error = Box<dyn std::error::Error + Send + Sync>;
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;

pub(crate) struct QuicOwner {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    _control: FrameIo<QuicBiStream>,
    capabilities: u32,
}
impl Drop for QuicOwner {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"session ended");
    }
}
struct QuicStream {
    inner: QuicBiStream,
    _owner: Arc<QuicOwner>,
}
impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub enum DatagramSender {
    Stream(UdpSender<BoxStream>),
    Quic(QuicDatagrams),
}
pub enum DatagramReceiver {
    Stream(UdpReceiver<BoxStream>),
    Quic(QuicDatagrams),
}
#[derive(Clone)]
pub struct QuicDatagrams {
    owner: Arc<QuicOwner>,
    // Keep the association stream open for the lifetime of both halves.
    _association: Arc<QuicBiStream>,
    id: u32,
}
impl DatagramSender {
    pub fn payload_limit(&self) -> usize {
        match self {
            Self::Stream(sender) => sender.payload_limit(),
            Self::Quic(_) => MAX_UDP_PAYLOAD,
        }
    }
    pub async fn send(&mut self, id: u32, target: Target, payload: Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Stream(sender) => sender.send(id, target, payload).await,
            Self::Quic(state) => {
                let packet = UdpPacket::new(state.id, id, target, payload)?.encode()?;
                state
                    .owner
                    .connection
                    .send_datagram_wait(packet.into())
                    .await?;
                Ok(())
            }
        }
    }
}
impl DatagramReceiver {
    pub async fn receive(&mut self) -> Result<UdpPacket, Error> {
        match self {
            Self::Stream(receiver) => receiver.receive().await,
            Self::Quic(state) => loop {
                let data = state.owner.connection.read_datagram().await?;
                let packet = UdpPacket::decode(&data)?;
                if packet.association_id == state.id {
                    return Ok(packet);
                }
            },
        }
    }
}

impl Session {
    async fn quic_connection<C: Connector>(
        &self,
        connector: &C,
        node: SocketAddr,
        udp: bool,
    ) -> Result<Arc<QuicOwner>, Error> {
        // Serialize establishment so concurrent flows share one authenticated connection.
        let mut cached = self.connection.lock().await;
        if let Some((address, owner)) = cached.as_ref()
            && *address == node
            && owner.connection.close_reason().is_none()
            && (!udp || owner.capabilities & CAP_UDP_LARGE_STREAM != 0)
        {
            return Ok(owner.clone());
        }
        let socket = connector.udp(node.is_ipv6()).await?.into_std()?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(self.quic.clone());
        let connection = endpoint.connect(node, &self.name)?.await?;
        let (send, recv) = connection.open_bi().await?;
        let mut control = FrameIo::new(QuicBiStream::new(send, recv));
        let negotiated = helios_transport::authenticate_client(
            &mut control,
            &self.credential_id,
            &self.token,
            CAP_TCP_CONNECT | CAP_UDP_DATAGRAM | CAP_UDP_LARGE_STREAM,
        )
        .await?;
        if negotiated.capabilities & (CAP_TCP_CONNECT | CAP_UDP_DATAGRAM)
            != CAP_TCP_CONNECT | CAP_UDP_DATAGRAM
        {
            return Err("server does not support QUIC TCP and UDP".into());
        }
        let owner = Arc::new(QuicOwner {
            _endpoint: endpoint,
            connection,
            _control: control,
            capabilities: negotiated.capabilities,
        });
        // Legacy datagrams have one connection-wide receive queue. Isolate their
        // associations so simultaneous readers cannot consume each other's replies.
        if !udp || owner.capabilities & CAP_UDP_LARGE_STREAM != 0 {
            *cached = Some((node, owner.clone()));
        }
        Ok(owner)
    }

    pub async fn connect_tcp<C: Connector>(
        &self,
        connector: &C,
        node: SocketAddr,
        target: Target,
        deadline: Duration,
    ) -> Result<BoxStream, Error> {
        if self.prefer_quic {
            let attempt = async {
                let owner = self.quic_connection(connector, node, false).await?;
                let (send, recv) = owner.connection.open_bi().await?;
                let mut io = FrameIo::new(QuicStream {
                    inner: QuicBiStream::new(send, recv),
                    _owner: owner,
                });
                let request = ConnectTcp::new(
                    target.clone(),
                    deadline.as_millis().min(30000) as u32,
                    Vec::new(),
                )?;
                io.write_frame(&Frame::new(FrameType::ConnectTcp, 3, request.encode()?)?)
                    .await?;
                let stream = helios_transport::finish_tcp_connect(io, &request).await?;
                Ok::<BoxStream, Error>(Box::new(stream))
            };
            match tokio::time::timeout(deadline.min(Duration::from_secs(3)), attempt).await {
                Ok(Ok(stream)) => return Ok(stream),
                _ => crate::telemetry::record("QUIC 不可用，TCP 回退 TLS".into()),
            }
        }
        let socket = connector.tcp(node).await?;
        Ok(Box::new(
            self.open_tcp(socket, target, deadline.as_millis().min(30000) as u32)
                .await?,
        ))
    }

    pub async fn connect_udp<C: Connector>(
        &self,
        connector: &C,
        node: SocketAddr,
        deadline: Duration,
    ) -> Result<(DatagramSender, DatagramReceiver), Error> {
        if self.prefer_quic {
            let attempt = async {
                let owner = self.quic_connection(connector, node, true).await?;
                let (send, recv) = owner.connection.open_bi().await?;
                let mut io = FrameIo::new(QuicBiStream::new(send, recv));
                io.write_frame(&Frame::new(
                    FrameType::UdpAssociate,
                    1,
                    UdpAssociate { target: None }.encode()?,
                )?)
                .await?;
                let reply = io.read_frame().await?;
                if reply.frame_type != FrameType::UdpAssociateOk
                    || reply.request_id != 1
                    || reply.payload.len() != 4
                {
                    return Err("invalid QUIC UDP association".into());
                }
                let id = u32::from_be_bytes(reply.payload.as_slice().try_into()?);
                if owner.capabilities & CAP_UDP_LARGE_STREAM != 0 {
                    let stream: BoxStream = Box::new(QuicStream {
                        inner: io.into_inner(),
                        _owner: owner,
                    });
                    let (send, receive) = UdpSession {
                        io: FrameIo::new(stream),
                        association_id: id,
                        limit: MAX_UDP_STREAM_PAYLOAD,
                    }
                    .split();
                    Ok::<_, Error>((
                        DatagramSender::Stream(send),
                        DatagramReceiver::Stream(receive),
                    ))
                } else {
                    let state = QuicDatagrams {
                        owner,
                        _association: Arc::new(io.into_inner()),
                        id,
                    };
                    Ok((
                        DatagramSender::Quic(state.clone()),
                        DatagramReceiver::Quic(state),
                    ))
                }
            };
            match tokio::time::timeout(deadline.min(Duration::from_secs(3)), attempt).await {
                Ok(Ok(session)) => return Ok(session),
                _ => crate::telemetry::record("QUIC 不可用，UDP 回退 TLS".into()),
            }
        }
        let socket = connector.tcp(node).await?;
        let session = self.open_udp(socket, deadline).await?;
        let stream: BoxStream = Box::new(session.io.into_inner());
        let (send, receive) = UdpSession {
            io: FrameIo::new(stream),
            association_id: session.association_id,
            limit: session.limit,
        }
        .split();
        Ok((
            DatagramSender::Stream(send),
            DatagramReceiver::Stream(receive),
        ))
    }

    pub async fn check<C: Connector>(
        &self,
        connector: &C,
        node: SocketAddr,
        deadline: Duration,
    ) -> Result<(), Error> {
        tokio::time::timeout(
            deadline + Duration::from_secs(3),
            self.connect_udp(connector, node, deadline),
        )
        .await??;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_config::{ConnectionLink, TransportPreference};
    use helios_protocol::Address;
    use helios_transport::{ServerCrypto, authenticate_server};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Sockets {
        tcp: AtomicUsize,
    }
    impl Connector for Sockets {
        fn tcp(
            &self,
            address: SocketAddr,
        ) -> Pin<Box<dyn std::future::Future<Output = io::Result<tokio::net::TcpStream>> + Send + '_>>
        {
            self.tcp.fetch_add(1, Ordering::Relaxed);
            Box::pin(crate::socket::connect_tcp(
                address,
                Duration::from_secs(1),
                |_| Ok(()),
            ))
        }
        fn udp(
            &self,
            ipv6: bool,
        ) -> Pin<Box<dyn std::future::Future<Output = io::Result<tokio::net::UdpSocket>> + Send + '_>>
        {
            Box::pin(crate::socket::bind_udp(ipv6, |_| Ok(())))
        }
    }
    fn fixture(address: SocketAddr) -> (tempfile::TempDir, Session, ServerCrypto) {
        let cert = rcgen::generate_simple_self_signed(vec!["mobile.test".into()]).unwrap();
        let crypto = ServerCrypto::new(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let link = ConnectionLink::new(
            "QUIC test".into(),
            address,
            "mobile.test".into(),
            cert.cert.der().as_ref(),
            "mobile".into(),
            [29; 32],
            TransportPreference::Quic,
        )
        .unwrap()
        .encode()
        .unwrap();
        let node = crate::node_store::import(root.path(), &link).unwrap();
        let session = Session::from_node(&node).unwrap();
        (root, session, crypto)
    }

    #[tokio::test]
    async fn concurrent_tcp_and_udp_share_authentication_and_closed_connections_reconnect() {
        let (_root, session, crypto) = fixture("[::1]:1".parse().unwrap());
        let endpoint = quinn::Endpoint::server(crypto.quic, "[::1]:0".parse().unwrap()).unwrap();
        let address = endpoint.local_addr().unwrap();
        let (close, mut closed) = tokio::sync::mpsc::channel(1);
        let (reconnect, mut ready) = tokio::sync::mpsc::channel(1);
        let server = tokio::spawn(async move {
            for generation in 0..2 {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let (send, recv) = connection.accept_bi().await.unwrap();
                let mut control = FrameIo::new(QuicBiStream::new(send, recv));
                authenticate_server(
                    &mut control,
                    CAP_TCP_CONNECT | CAP_UDP_DATAGRAM | CAP_UDP_LARGE_STREAM,
                    |_| Some([29; 32]),
                )
                .await
                .unwrap();
                let control = tokio::spawn(helios_transport::serve_control(control));
                let count = if generation == 0 { 4 } else { 1 };
                let mut flows = tokio::task::JoinSet::new();
                for _ in 0..count {
                    let (send, recv) =
                        tokio::time::timeout(Duration::from_secs(2), connection.accept_bi())
                            .await
                            .unwrap()
                            .unwrap();
                    flows.spawn(async move {
                        let mut io = FrameIo::new(QuicBiStream::new(send, recv));
                        let first = io.read_frame().await.unwrap();
                        if first.frame_type == FrameType::ConnectTcp {
                            io.write_frame(
                                &Frame::new(FrameType::ConnectOk, first.request_id, vec![])
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                            let mut raw = io.into_inner();
                            let mut bytes = [0; 4];
                            raw.read_exact(&mut bytes).await.unwrap();
                            raw.write_all(&bytes).await.unwrap();
                            raw.shutdown().await.unwrap();
                        } else {
                            assert_eq!(first.frame_type, FrameType::UdpAssociate);
                            io.write_frame(
                                &Frame::new(
                                    FrameType::UdpAssociateOk,
                                    first.request_id,
                                    1u32.to_be_bytes().to_vec(),
                                )
                                .unwrap(),
                            )
                            .await
                            .unwrap();
                            let frame = io.read_frame().await.unwrap();
                            io.write_frame(&frame).await.unwrap();
                            io.shutdown().await.unwrap();
                        }
                    });
                }
                while let Some(flow) = flows.join_next().await {
                    flow.unwrap();
                }
                if generation == 0 {
                    closed.recv().await.unwrap();
                    connection.close(0u32.into(), b"test network loss");
                    reconnect.send(()).await.unwrap();
                } else {
                    connection.closed().await;
                }
                control.abort();
            }
        });
        let sockets = Sockets {
            tcp: AtomicUsize::new(0),
        };
        let target = Target::new(Address::Ip("::1".parse().unwrap()), 8443).unwrap();
        let tcp = || async {
            let mut stream = session
                .connect_tcp(&sockets, address, target.clone(), Duration::from_secs(2))
                .await
                .unwrap();
            stream.write_all(b"echo").await.unwrap();
            let mut reply = [0; 4];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"echo");
        };
        let udp = |id: u32| {
            let session = &session;
            let sockets = &sockets;
            let target = target.clone();
            async move {
                let (mut send, mut receive) = session
                    .connect_udp(sockets, address, Duration::from_secs(2))
                    .await
                    .unwrap();
                send.send(id, target, vec![id as u8; 1400]).await.unwrap();
                let reply = receive.receive().await.unwrap();
                assert_eq!(reply.packet_id, id);
                assert_eq!(reply.payload, vec![id as u8; 1400]);
            }
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(tcp(), tcp(), udp(1), udp(2));
        })
        .await
        .unwrap();
        let connection = session
            .connection
            .lock()
            .await
            .as_ref()
            .unwrap()
            .1
            .connection
            .clone();
        close.send(()).await.unwrap();
        ready.recv().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), connection.closed())
            .await
            .unwrap();
        tcp().await;
        session.connection.lock().await.take();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sockets.tcp.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn quic_relays_tcp_and_both_legacy_and_large_stream_udp_over_ipv6() {
        for extra in [0, CAP_UDP_LARGE_STREAM] {
            let sockets = Sockets {
                tcp: AtomicUsize::new(0),
            };
            let (_root, session, crypto) = fixture("[::1]:1".parse().unwrap());
            let endpoint =
                quinn::Endpoint::server(crypto.quic, "[::1]:0".parse().unwrap()).unwrap();
            let address = endpoint.local_addr().unwrap();
            let server = tokio::spawn(async move {
                for tcp in [true, false] {
                    let connection = endpoint.accept().await.unwrap().await.unwrap();
                    let (send, recv) = connection.accept_bi().await.unwrap();
                    let mut control = FrameIo::new(QuicBiStream::new(send, recv));
                    let negotiated = authenticate_server(
                        &mut control,
                        CAP_TCP_CONNECT | CAP_UDP_DATAGRAM | extra,
                        |id| (id == "mobile").then_some([29; 32]),
                    )
                    .await
                    .unwrap();
                    let control = tokio::spawn(helios_transport::serve_control(control));
                    let (send, recv) = connection.accept_bi().await.unwrap();
                    let mut io = FrameIo::new(QuicBiStream::new(send, recv));
                    let first = io.read_frame().await.unwrap();
                    if tcp {
                        assert_eq!(first.frame_type, FrameType::ConnectTcp);
                        assert_eq!(
                            ConnectTcp::decode(&first.payload).unwrap().target.port,
                            8443
                        );
                        io.write_frame(
                            &Frame::new(FrameType::ConnectOk, first.request_id, vec![]).unwrap(),
                        )
                        .await
                        .unwrap();
                        let mut raw = io.into_inner();
                        let mut bytes = [0; 4];
                        raw.read_exact(&mut bytes).await.unwrap();
                        raw.write_all(&bytes).await.unwrap();
                        raw.flush().await.unwrap();
                    } else {
                        assert_eq!(first.frame_type, FrameType::UdpAssociate);
                        io.write_frame(
                            &Frame::new(
                                FrameType::UdpAssociateOk,
                                first.request_id,
                                1u32.to_be_bytes().to_vec(),
                            )
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                        if negotiated.capabilities & CAP_UDP_LARGE_STREAM != 0 {
                            let frame = io.read_frame().await.unwrap();
                            let packet = UdpPacket::decode_with_limit(
                                &frame.payload,
                                MAX_UDP_STREAM_PAYLOAD,
                            )
                            .unwrap();
                            assert_eq!(packet.payload.len(), 1400);
                            io.write_frame(&frame).await.unwrap();
                        } else {
                            let bytes = connection.read_datagram().await.unwrap();
                            assert_eq!(UdpPacket::decode(&bytes).unwrap().payload.len(), 1000);
                            connection.send_datagram(bytes).unwrap();
                        }
                        connection.closed().await;
                    }
                    control.abort();
                }
            });
            let target = Target::new(Address::Ip("::1".parse().unwrap()), 8443).unwrap();
            let mut tcp = session
                .connect_tcp(&sockets, address, target.clone(), Duration::from_secs(2))
                .await
                .unwrap();
            tcp.write_all(b"echo").await.unwrap();
            let mut bytes = [0; 4];
            tcp.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"echo");
            drop(tcp);
            // This fixture intentionally verifies separate sessions; multiplexing is tested below.
            session.connection.lock().await.take();
            let (mut send, mut receive) = session
                .connect_udp(&sockets, address, Duration::from_secs(2))
                .await
                .unwrap();
            let size = if extra == 0 { 1000 } else { 1400 };
            assert_eq!(
                send.payload_limit(),
                if extra == 0 {
                    MAX_UDP_PAYLOAD
                } else {
                    MAX_UDP_STREAM_PAYLOAD
                }
            );
            send.send(12, target, vec![73; size]).await.unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(2), receive.receive())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.packet_id, 12);
            assert_eq!(reply.payload, vec![73; size]);
            drop((send, receive));
            session.connection.lock().await.take();
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                sockets.tcp.load(Ordering::Relaxed),
                0,
                "test must actually use QUIC"
            );
        }
    }

    #[tokio::test]
    async fn blocked_quic_falls_back_to_authenticated_tls_with_negotiated_large_udp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_root, session, crypto) = fixture(address);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut io = crypto.tls.accept(socket).await.unwrap();
            authenticate_server(
                &mut io,
                helios_protocol::CAP_UDP_OVER_STREAM | CAP_UDP_LARGE_STREAM,
                |_| Some([29; 32]),
            )
            .await
            .unwrap();
            let association = io.read_frame().await.unwrap();
            io.write_frame(
                &Frame::new(
                    FrameType::UdpAssociateOk,
                    association.request_id,
                    1u32.to_be_bytes().to_vec(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
            let packet = io.read_frame().await.unwrap();
            assert_eq!(
                UdpPacket::decode_with_limit(&packet.payload, MAX_UDP_STREAM_PAYLOAD)
                    .unwrap()
                    .payload
                    .len(),
                1400
            );
            io.write_frame(&packet).await.unwrap();
        });
        let sockets = Sockets {
            tcp: AtomicUsize::new(0),
        };
        let (mut send, mut receive) = session
            .connect_udp(&sockets, address, Duration::from_millis(250))
            .await
            .unwrap();
        assert_eq!(send.payload_limit(), MAX_UDP_STREAM_PAYLOAD);
        send.send(
            5,
            Target::new(Address::Ip("127.0.0.1".parse().unwrap()), 1234).unwrap(),
            vec![11; 1400],
        )
        .await
        .unwrap();
        let packet = receive.receive().await.unwrap();
        assert_eq!(packet.payload, vec![11; 1400]);
        server.await.unwrap();
        assert_eq!(sockets.tcp.load(Ordering::Relaxed), 1);
    }
}
