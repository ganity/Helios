//! Opt-in WAN regression: a userspace relay adds 160 ms RTT and 1% downlink loss.
use std::{sync::Arc, time::Duration};

use helios_transport::{ClientCrypto, ServerCrypto};
use quinn::Endpoint;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{
    RootCertStore,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::{
    net::UdpSocket,
    time::{Instant, sleep_until, timeout},
};

async fn download(cubic_baseline: bool) -> Duration {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut server_crypto = ServerCrypto::new(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
    )
    .unwrap();
    if cubic_baseline {
        server_crypto
            .quic
            .transport_config(Arc::new(quinn::TransportConfig::default()));
    }
    let endpoint = Endpoint::server(server_crypto.quic, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, _recv) = connection.accept_bi().await.unwrap();
        send.write_all(&vec![0x5a; 1 << 20]).await.unwrap();
        send.finish().unwrap();
        let _ = send.stopped().await;
        eprintln!(
            "cubic_baseline={cubic_baseline} path={:?}",
            connection.stats().path
        );
        connection.closed().await;
    });

    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_addr = relay.local_addr().unwrap();
    let (tx, mut rx) =
        tokio::sync::mpsc::unbounded_channel::<(Instant, Vec<u8>, std::net::SocketAddr)>();
    let outgoing = relay.clone();
    let delayed = tokio::spawn(async move {
        while let Some((due, bytes, destination)) = rx.recv().await {
            sleep_until(due).await;
            outgoing.send_to(&bytes, destination).await.unwrap();
        }
    });
    let incoming = tokio::spawn(async move {
        let mut client = None;
        let mut downlink_packets = 0u64;
        let mut buffer = vec![0; 65536];
        loop {
            let (length, source) = relay.recv_from(&mut buffer).await.unwrap();
            let destination = if source == server_addr {
                downlink_packets += 1;
                if downlink_packets.is_multiple_of(100) {
                    continue;
                }
                client.unwrap()
            } else {
                client = Some(source);
                server_addr
            };
            tx.send((
                Instant::now() + Duration::from_millis(80),
                buffer[..length].to_vec(),
                destination,
            ))
            .unwrap();
        }
    });

    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let crypto = ClientCrypto::new(roots).unwrap();
    let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(crypto.quic);
    let connection = client
        .connect(relay_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let started = Instant::now();
    send.write_all(b"download").await.unwrap();
    let mut payload = vec![0; 1 << 20];
    timeout(Duration::from_secs(30), recv.read_exact(&mut payload))
        .await
        .unwrap()
        .unwrap();
    let elapsed = started.elapsed();
    assert!(payload.iter().all(|&byte| byte == 0x5a));
    connection.close(0u32.into(), b"complete");
    server.abort();
    incoming.abort();
    delayed.abort();
    elapsed
}

#[tokio::test]
#[ignore = "timed network regression; run separately from parallel test load"]
async fn configured_quic_sustains_throughput_on_lossy_wan() {
    let cubic = download(true).await;
    let configured = download(false).await;
    eprintln!("1 MiB, 160 ms RTT, 1% loss: CUBIC={cubic:?}, configured={configured:?}");
    assert!(
        configured < cubic.mul_f64(0.7),
        "configured QUIC did not improve lossy-link throughput"
    );
}
