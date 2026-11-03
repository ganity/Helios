use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::{ClientConfig, ServerConfig, pki_types::ServerName};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};

use crate::FrameIo;

/// Connects to a node with conservative segments for paths that black-hole large packets.
pub async fn connect_node_tcp(
    address: std::net::SocketAddr,
) -> std::io::Result<tokio::net::TcpStream> {
    let socket = if address.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    // shortcut: TCP_MAXSEG is unavailable here on Windows; that path still relies on OS PMTU discovery.
    #[cfg(all(unix, not(target_vendor = "apple")))]
    socket2::SockRef::from(&socket).set_tcp_mss(1000)?;
    socket.set_nodelay(true)?;
    let stream = socket.connect(address).await?;
    #[cfg(target_vendor = "apple")]
    {
        // Darwin only permits reducing MSS; wait until connect has negotiated it.
        let socket = socket2::SockRef::from(&stream);
        socket.set_tcp_mss(socket.tcp_mss()?.min(1000))?;
    }
    configure_tcp(&stream)?;
    Ok(stream)
}

pub fn configure_tcp(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    socket2::SockRef::from(stream).set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(60))
            .with_interval(std::time::Duration::from_secs(10)),
    )
}

/// Keeps TCP alive after TLS close_notify so half-close-hostile relays can drain replies.
pub struct TlsTransport<S>(S);

pub type ClientTlsStream<S> = client::TlsStream<TlsTransport<S>>;
pub type ServerTlsStream<S> = server::TlsStream<TlsTransport<S>>;

impl<S: AsyncRead + Unpin> AsyncRead for TlsTransport<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TlsTransport<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // rustls already sends close_notify; defer TCP FIN until both TLS halves are dropped.
        Pin::new(&mut self.0).poll_flush(cx)
    }
}

#[derive(Clone)]
pub struct TlsClient {
    connector: TlsConnector,
}

impl TlsClient {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            connector: TlsConnector::from(Arc::new(config)),
        }
    }

    pub async fn connect<S>(
        &self,
        server_name: ServerName<'static>,
        stream: S,
    ) -> std::io::Result<FrameIo<ClientTlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Ok(FrameIo::new(
            self.connector
                .connect(server_name, TlsTransport(stream))
                .await?,
        ))
    }
}

#[derive(Clone)]
pub struct TlsServer {
    acceptor: TlsAcceptor,
}

impl TlsServer {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        }
    }

    pub async fn accept<S>(&self, stream: S) -> std::io::Result<FrameIo<ServerTlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Ok(FrameIo::new(
            self.acceptor.accept(TlsTransport(stream)).await?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use helios_protocol::{Address, CAP_TCP_CONNECT, ConnectTcp, Frame, FrameType, Target};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{
        RootCertStore,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
        net::{TcpListener, TcpStream},
    };

    use super::*;
    use crate::{accept_tcp, authenticate_client, authenticate_server, open_tcp};

    #[tokio::test]
    async fn node_tcp_connection_limits_segments_and_transfers_large_payloads() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut client, (mut server, _)) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::try_join!(
                    connect_node_tcp(listener.local_addr().unwrap()),
                    listener.accept()
                )
            })
            .await
            .expect("node TCP connection timed out")
            .expect("node TCP connection failed");
        assert!(client.nodelay().unwrap());
        assert!(socket2::SockRef::from(&client).keepalive().unwrap());
        #[cfg(unix)]
        assert!(socket2::SockRef::from(&client).tcp_mss().unwrap() <= 1000);
        let payload = vec![42; 65536];
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        writer.await.unwrap();
        assert_eq!(received, expected);
    }
    const ALPN: &[u8] = b"helios/1";

    fn tls_pair() -> (TlsClient, TlsServer) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key)
            .unwrap();
        server_config.alpn_protocols = vec![ALPN.to_vec()];

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN.to_vec()];

        (TlsClient::new(client_config), TlsServer::new(server_config))
    }

    #[tokio::test]
    async fn exchanges_helios_frames_over_real_tls_tcp() {
        let (client_tls, server_tls) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut io = server_tls.accept(tcp).await.unwrap();
            let ping = io.read_frame().await.unwrap();
            assert_eq!(ping.frame_type, FrameType::Ping);
            io.write_frame(&Frame::new(FrameType::Pong, ping.request_id, ping.payload).unwrap())
                .await
                .unwrap();
        });

        let tcp = connect_node_tcp(address).await.unwrap();
        let mut io = client_tls
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        let ping = Frame::new(FrameType::Ping, 41, b"health".to_vec()).unwrap();
        io.write_frame(&ping).await.unwrap();
        let pong = io.read_frame().await.unwrap();

        assert_eq!(pong.frame_type, FrameType::Pong);
        assert_eq!(pong.request_id, ping.request_id);
        assert_eq!(pong.payload, ping.payload);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tls_relay_closes_cleanly_after_target_eof() {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay_half_close(false, false),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn tls_relay_survives_tcp_proxy_that_closes_on_fin() {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay_half_close(true, false),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn tls_relay_preserves_upload_after_target_half_close_through_proxy() {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay_half_close(true, true),
        )
        .await
        .unwrap();
    }

    async fn relay_half_close(through_proxy: bool, target_first: bool) {
        let (client_tls, server_tls) = tls_pair();
        let token = [7; 32];
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let response = vec![42; 256 * 1024];
            if target_first {
                stream.write_all(&response).await.unwrap();
                stream.shutdown().await.unwrap();
            }
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).await.unwrap();
            if target_first {
                assert_eq!(rest, b"after response");
            } else {
                assert!(rest.is_empty());
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                stream.write_all(&response).await.unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut io = server_tls.accept(tcp).await.unwrap();
            authenticate_server(&mut io, CAP_TCP_CONNECT, |_| Some(token))
                .await
                .unwrap();
            let (mut client, mut target) = accept_tcp(io).await.unwrap();
            copy_bidirectional(&mut client, &mut target).await.unwrap();
        });

        let proxy = if through_proxy {
            let upstream = address;
            let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            address = proxy_listener.local_addr().unwrap();
            Some(tokio::spawn(async move {
                let (mut downstream, _) = proxy_listener.accept().await.unwrap();
                let mut upstream = TcpStream::connect(upstream).await.unwrap();
                let (mut down_read, mut down_write) = downstream.split();
                let (mut up_read, mut up_write) = upstream.split();
                // Model a NAT relay that closes both directions on the first TCP FIN.
                tokio::select! {
                    result = tokio::io::copy(&mut down_read, &mut up_write) => { let _ = result; }
                    result = tokio::io::copy(&mut up_read, &mut down_write) => { let _ = result; }
                }
            }))
        } else {
            None
        };

        let tcp = TcpStream::connect(address).await.unwrap();
        let mut io = client_tls
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        authenticate_client(&mut io, "desktop-main", &token, CAP_TCP_CONNECT)
            .await
            .unwrap();
        let request = ConnectTcp::new(
            Target::new(Address::Ip(target_address.ip()), target_address.port()).unwrap(),
            3_000,
            Vec::new(),
        )
        .unwrap();
        let tls = open_tcp(io, 3, &request).await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(tls);
        let (downloaded, wait_download) = tokio::sync::oneshot::channel();
        let upload = async {
            if target_first {
                wait_download.await.unwrap();
                writer.write_all(b"after response").await.unwrap();
            }
            writer.shutdown().await.unwrap();
        };
        let download = async {
            let mut response = Vec::new();
            reader.read_to_end(&mut response).await.unwrap();
            let _ = downloaded.send(());
            response
        };
        let (_, response) = tokio::join!(upload, download);
        assert_eq!(response, vec![42; 256 * 1024]);
        target.await.unwrap();
        server.await.unwrap();
        if let Some(proxy) = proxy {
            proxy.await.unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_untrusted_server_certificate() {
        let (_, server_tls) = tls_pair();
        let (untrusted_client, _) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            assert!(server_tls.accept(tcp).await.is_err());
        });

        let tcp = TcpStream::connect(address).await.unwrap();
        assert!(
            untrusted_client
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_eof_without_tls_close_notify() {
        let (client_tls, server_tls) = tls_pair();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = server_tls.accept(tcp).await.unwrap().into_inner();
            let mut request = [0; 1];
            tls.read_exact(&mut request).await.unwrap();
            tls.write_all(b"incomplete").await.unwrap();
            tls.flush().await.unwrap();
            // Deliberately drop TLS without sending the authenticated end-of-stream marker.
        });
        let tcp = TcpStream::connect(address).await.unwrap();
        let mut tls = client_tls
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap()
            .into_inner();
        tls.write_all(b"x").await.unwrap();
        tls.flush().await.unwrap();
        let mut response = Vec::new();
        let error = tls.read_to_end(&mut response).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eq!(response, b"incomplete");
        server.await.unwrap();
    }
}
