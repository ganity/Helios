use super::*;
use helios_transport::{ServerCrypto, authenticate_server, serve_control};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{
    RootCertStore,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tokio::io::AsyncWriteExt;

struct Peer {
    remote: Remote,
    endpoint: Endpoint,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"test complete");
        self.task.abort();
    }
}

async fn peer(stream_limit: u32) -> Peer {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut crypto = ServerCrypto::new(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
    )
    .unwrap();
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(stream_limit.into());
    crypto.quic.transport_config(Arc::new(transport));
    let endpoint = Endpoint::server(crypto.quic, "127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = endpoint.clone();
    let task = tokio::spawn(async move {
        let connection = listener.accept().await.unwrap().await.unwrap();
        let (send, recv) = connection.accept_bi().await.unwrap();
        let mut control = FrameIo::new(QuicBiStream::new(send, recv));
        authenticate_server(&mut control, CAP_TCP_CONNECT, |_| Some([7; 32]))
            .await
            .unwrap();
        let _ = serve_control(control).await;
    });
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let crypto = ClientCrypto::new(roots).unwrap();
    let config = QuicConnectConfig {
        server: endpoint.local_addr().unwrap(),
        server_name: "localhost".try_into().unwrap(),
        credential_id: Arc::from("test"),
        token: [7; 32],
        client_config: crypto.quic,
    };
    let (quic, control) = establish_quic(&config).await.unwrap();
    let control_task = tokio::spawn(async move {
        let _control = control;
        std::future::pending::<()>().await;
    });
    let remote = Remote {
        _monitors: Some(Arc::new(MonitorTasks(vec![control_task.abort_handle()]))),
        tls: crypto.tls,
        quic: Arc::new(RwLock::new(Some(quic))),
        udp_config: None,
        server: config.server,
        server_name: config.server_name,
        credential_id: config.credential_id,
        token: config.token,
        connect_milliseconds: 1000,
        rules: Arc::new(RwLock::new(RuleSet::new(&[]).unwrap())),
        protected_listeners: ["127.0.0.1:1".parse().unwrap(); 3],
        metrics: Arc::new(DaemonMetrics::new(TransportPreference::Quic)),
        fake_ips: None,
    };
    Peer {
        remote,
        endpoint,
        task,
    }
}

fn target() -> Target {
    Target::new(helios_protocol::Address::Domain("example.com".into()), 443).unwrap()
}

#[tokio::test(start_paused = true)]
async fn health_probe_resumes_partial_io_without_resending_or_desynchronizing() {
    for stall_write in [false, true] {
        let (client, server) = tokio::io::duplex(if stall_write { 1 } else { 4096 });
        let peer = tokio::spawn(async move {
            let mut io = FrameIo::new(server);
            if stall_write {
                sleep(Duration::from_secs(6)).await;
            }
            let request = io.read_frame().await.unwrap();
            assert_eq!(request.request_id, 100);
            let response = Frame::new(FrameType::Pong, request.request_id, request.payload)
                .unwrap()
                .encode()
                .unwrap();
            let mut stream = io.into_inner();
            stream.write_all(&response[..5]).await.unwrap();
            if !stall_write {
                sleep(Duration::from_secs(6)).await;
            }
            stream.write_all(&response[5..]).await.unwrap();
            let mut io = FrameIo::new(stream);
            let next = io.read_frame().await.unwrap();
            assert_eq!(next.request_id, 101, "a soft timeout resent the first PING");
            io.write_frame(&Frame::new(FrameType::Pong, next.request_id, next.payload).unwrap())
                .await
                .unwrap();
        });
        let mut io = FrameIo::new(client);
        let start = Instant::now();
        probe_quic_health(&mut io, 100).await.unwrap();
        assert!(start.elapsed() >= Duration::from_secs(6));
        probe_quic_health(&mut io, 101).await.unwrap();
        peer.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn unresponsive_health_probe_has_a_hard_deadline() {
    let (client, _server) = tokio::io::duplex(4096);
    let mut io = FrameIo::new(client);
    let start = Instant::now();
    assert!(probe_quic_health(&mut io, 100).await.is_err());
    assert_eq!(start.elapsed(), Duration::from_secs(15));
}

#[tokio::test]
async fn closed_quic_reaches_tls_fallback_without_deadlock() {
    let peer = peer(100).await;
    peer.remote
        .quic
        .read()
        .await
        .as_ref()
        .unwrap()
        .connection
        .close(0u32.into(), b"path failed");
    let result = timeout(Duration::from_secs(3), peer.remote.open(target())).await;
    // The peer only listens on UDP: a prompt TCP error proves fallback was reached.
    assert!(matches!(result, Ok(Err(RemoteError::Transport(_)))));
    assert!(peer.remote.quic.read().await.is_none());
}

#[tokio::test]
async fn exhausted_quic_streams_have_a_deadline_without_removing_live_session() {
    let peer = peer(1).await; // The control stream occupies all stream credit.
    let result = timeout(Duration::from_secs(3), peer.remote.open(target())).await;
    assert!(
        result.is_ok(),
        "stream credit wait exceeded the connect deadline"
    );
    let quic = peer.remote.quic.read().await.clone().unwrap();
    assert!(quic.connection.close_reason().is_none());
}

#[tokio::test]
async fn stalled_open_does_not_block_health_writer_or_subsequent_readers() {
    let peer = peer(1).await;
    let remote = peer.remote.clone();
    let opening = tokio::spawn(async move { remote.open(target()).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let remote = peer.remote.clone();
    let writer = tokio::spawn(async move {
        let _guard = remote.quic.write().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let blocked = timeout(Duration::from_millis(200), peer.remote.quic.read())
        .await
        .is_err();
    opening.abort();
    writer.abort();
    assert!(!blocked, "a network wait retained the session read lock");
}

#[tokio::test]
async fn old_session_failure_does_not_clear_replacement() {
    let replacement = peer(1).await;
    let peer = peer(1).await;
    let old = peer.remote.quic.read().await.clone().unwrap();
    let new = replacement.remote.quic.read().await.clone().unwrap();
    let remote = peer.remote.clone();
    let opening = tokio::spawn(async move { remote.open(target()).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let updated = timeout(Duration::from_millis(200), async {
        *peer.remote.quic.write().await = Some(new.clone());
    })
    .await;
    if updated.is_err() {
        opening.abort();
    }
    assert!(updated.is_ok(), "replacement blocked by stale open");
    old.connection.close(0u32.into(), b"old session failed");
    assert!(timeout(Duration::from_secs(3), opening).await.is_ok());
    assert_eq!(
        peer.remote
            .quic
            .read()
            .await
            .as_ref()
            .unwrap()
            .connection
            .stable_id(),
        new.connection.stable_id()
    );
}
