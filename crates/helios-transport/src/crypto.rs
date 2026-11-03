use std::{sync::Arc, time::Duration};

use quinn::crypto::rustls::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use thiserror::Error;

use crate::{TlsClient, TlsServer};

pub const HELIOS_ALPN: &[u8] = b"helios/1";

fn quic_transport_config() -> quinn::TransportConfig {
    let mut congestion = quinn::congestion::BbrConfig::default();
    // Keep the initial burst conservative; BBR sustains throughput on lossy, high-RTT paths.
    congestion.initial_window(12_000);
    let mut transport = quinn::TransportConfig::default();
    transport.congestion_controller_factory(Arc::new(congestion));
    transport
}

pub struct ServerCrypto {
    pub tls: TlsServer,
    pub quic: quinn::ServerConfig,
}

impl ServerCrypto {
    pub fn new(
        certificates: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, CryptoConfigError> {
        let mut tls_config =
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(certificates.clone(), private_key.clone_key())?;
        tls_config.alpn_protocols = vec![HELIOS_ALPN.to_vec()];

        let mut quic_tls_config =
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(certificates, private_key)?;
        quic_tls_config.alpn_protocols = vec![HELIOS_ALPN.to_vec()];
        let quic_crypto = QuicServerConfig::try_from(quic_tls_config)?;
        let mut quic = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        quic.transport_config(Arc::new(quic_transport_config()));

        Ok(Self {
            tls: TlsServer::new(tls_config),
            quic,
        })
    }
}

pub struct ClientCrypto {
    pub tls: TlsClient,
    pub quic: quinn::ClientConfig,
}

impl ClientCrypto {
    pub fn new(roots: RootCertStore) -> Result<Self, CryptoConfigError> {
        let mut tls_config =
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots.clone())
                .with_no_client_auth();
        tls_config.alpn_protocols = vec![HELIOS_ALPN.to_vec()];

        let mut quic_tls_config =
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        quic_tls_config.alpn_protocols = vec![HELIOS_ALPN.to_vec()];
        let quic_crypto = QuicClientConfig::try_from(quic_tls_config)?;

        let mut quic = quinn::ClientConfig::new(Arc::new(quic_crypto));
        let mut transport = quic_transport_config();
        // Health probes may be slower than QUIC's default idle timeout.
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        quic.transport_config(Arc::new(transport));

        Ok(Self {
            tls: TlsClient::new(tls_config),
            quic,
        })
    }
}

#[derive(Debug, Error)]
pub enum CryptoConfigError {
    #[error("invalid TLS certificate or private key: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("TLS configuration has no QUIC-compatible initial cipher suite: {0}")]
    Quinn(#[from] NoInitialCipherSuite),
}

#[cfg(test)]
mod tests {
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;

    #[tokio::test]
    async fn repeated_connections_resume_tls_without_skipping_application_auth() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = ServerCrypto::new(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
        )
        .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client = ClientCrypto::new(roots).unwrap();
        for expected in [rustls::HandshakeKind::Full, rustls::HandshakeKind::Resumed] {
            let (a, b) = tokio::io::duplex(16384);
            let (a, b) = tokio::join!(
                client.tls.connect("localhost".try_into().unwrap(), a),
                server.tls.accept(b)
            );
            let mut a = a.unwrap();
            let mut b = b.unwrap();
            // Application I/O also processes post-handshake session tickets.
            let (auth_client, auth_server) = tokio::join!(
                crate::authenticate_client(
                    &mut a,
                    "test",
                    &[7; 32],
                    helios_protocol::CAP_TCP_CONNECT
                ),
                crate::authenticate_server(&mut b, helios_protocol::CAP_TCP_CONNECT, |_| Some(
                    [7; 32]
                ))
            );
            auth_client.unwrap();
            auth_server.unwrap();
            assert_eq!(a.into_inner().get_ref().1.handshake_kind(), Some(expected));
        }
    }

    #[test]
    fn builds_matching_tls_and_quic_configs() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        ServerCrypto::new(vec![cert_der.clone()], key).unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(cert_der).unwrap();
        ClientCrypto::new(roots).unwrap();
    }

    #[tokio::test]
    async fn negotiates_tls13_and_helios_alpn() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let server = ServerCrypto::new(vec![cert.der().clone()], key).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let client = ClientCrypto::new(roots).unwrap();
        let (client_stream, server_stream) = tokio::io::duplex(16384);
        let (client_io, server_io) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(
                    client
                        .tls
                        .connect("localhost".try_into().unwrap(), client_stream),
                    server.tls.accept(server_stream)
                )
            })
            .await
            .unwrap();
        let client_stream = client_io.unwrap().into_inner();
        let server_stream = server_io.unwrap().into_inner();
        assert_eq!(
            client_stream.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            server_stream.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(client_stream.get_ref().1.alpn_protocol(), Some(HELIOS_ALPN));
        assert_eq!(server_stream.get_ref().1.alpn_protocol(), Some(HELIOS_ALPN));
    }
}
