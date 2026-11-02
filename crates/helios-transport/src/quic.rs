use std::{
    pin::Pin,
    task::{Context, Poll},
};

use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct QuicBiStream {
    send: SendStream,
    recv: RecvStream,
}

impl QuicBiStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(context, buffer)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), context)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use helios_protocol::{Frame, FrameType};
    use quinn::{ClientConfig, Endpoint, ServerConfig};
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{
        RootCertStore,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    };

    use crate::FrameIo;

    use super::*;

    const ALPN: &[u8] = b"helios/1";

    fn configs() -> (ClientConfig, ServerConfig) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key)
            .unwrap();
        server_crypto.alpn_protocols = vec![ALPN.to_vec()];
        let server_crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap();
        let server_config = ServerConfig::with_crypto(Arc::new(server_crypto));

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![ALPN.to_vec()];
        let client_crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap();
        let client_config = ClientConfig::new(Arc::new(client_crypto));

        (client_config, server_config)
    }

    #[tokio::test]
    async fn exchanges_helios_frames_over_quic_stream() {
        let (client_config, server_config) = configs();
        let server_endpoint = Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let server_address = server_endpoint.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();
            let mut io = FrameIo::new(QuicBiStream::new(send, recv));
            let ping = io.read_frame().await.unwrap();
            io.write_frame(&Frame::new(FrameType::Pong, ping.request_id, ping.payload).unwrap())
                .await
                .unwrap();
            io.shutdown().await.unwrap();
            connection.closed().await;
        });

        let mut client_endpoint =
            Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        client_endpoint.set_default_client_config(client_config);
        let connection = client_endpoint
            .connect(server_address, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();
        let mut io = FrameIo::new(QuicBiStream::new(send, recv));
        let ping = Frame::new(FrameType::Ping, 51, b"quic-health".to_vec()).unwrap();
        io.write_frame(&ping).await.unwrap();
        let pong = io.read_frame().await.unwrap();

        assert_eq!(pong.frame_type, FrameType::Pong);
        assert_eq!(pong.request_id, ping.request_id);
        assert_eq!(pong.payload, ping.payload);
        connection.close(0u32.into(), b"test complete");
        server.await.unwrap();
    }
}
