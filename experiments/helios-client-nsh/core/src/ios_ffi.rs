//! C ABI used by the Packet Tunnel extension. No UIKit or NSH dependencies.
use crate::{
    packet_device::{self, PacketPort},
    session::Session,
    tunnel::{Connector, Tunnel},
};
use std::{
    ffi::{CStr, c_char},
    io,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    runtime::Runtime,
    sync::watch,
};

type Error = Box<dyn std::error::Error + Send + Sync>;
struct ProviderSockets;
impl Connector for ProviderSockets {
    fn tcp(
        &self,
        address: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<TcpStream>> + Send + '_>>
    {
        Box::pin(crate::socket::connect_tcp(
            address,
            Duration::from_secs(10),
            |_| Ok(()),
        ))
    }
    fn udp(
        &self,
        ipv6: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<UdpSocket>> + Send + '_>>
    {
        Box::pin(crate::socket::bind_udp(ipv6, |_| Ok(())))
    }
}

struct State {
    runtime: Runtime,
    port: PacketPort,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    status: Arc<Mutex<(u8, String)>>,
    tunnel: Arc<Tunnel<ProviderSockets>>,
    health: Option<tokio::task::JoinHandle<()>>,
}
static ENGINE: Mutex<Option<State>> = Mutex::new(None);
static LAST_ERROR: Mutex<String> = Mutex::new(String::new());

fn start(node: &str, root: &Path) -> Result<(), Error> {
    let mut engine = ENGINE.lock().unwrap_or_else(|e| e.into_inner());
    if engine.is_some() {
        return Err("tunnel is already running".into());
    }
    let value: serde_json::Value = serde_json::from_str(node)?;
    let settings: crate::settings::Settings = value
        .get("settings")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()?
        .unwrap_or_default();
    settings.validate()?;
    let node: helios_client_model::NodeProfile =
        serde_json::from_value(value.get("node").unwrap_or(&value).clone())?;
    let root = root.canonicalize()?;
    for path in [&node.ca_certificate, &node.token_file] {
        if !path.canonicalize()?.starts_with(&root) {
            return Err("credential file is outside the shared container".into());
        }
    }
    let connector = Arc::new(ProviderSockets);
    let tunnel = Arc::new(Tunnel {
        connector: connector.clone(),
        node: node.server.parse()?,
        session: Arc::new(Session::from_node(&node)?),
        rules: None,
        dns_gateway: Some(("10.88.0.1:53".parse()?, settings.dns)),
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let (device, port) = packet_device::pair();
    let (stop, mut receiver) = watch::channel(false);
    let status = Arc::new(Mutex::new((1u8, "正在验证节点".into())));
    let report = status.clone();
    let data_plane = tunnel.clone();
    let authenticate = tunnel.clone();
    let task = runtime.spawn(async move {
        let run_receiver = receiver.clone();
        let run = async {
            authenticate
                .session
                .check(
                    connector.as_ref(),
                    authenticate.node,
                    Duration::from_secs(10),
                )
                .await?;
            *report.lock().unwrap_or_else(|e| e.into_inner()) = (2, "已连接 · 全部代理".into());
            data_plane
                .run(device, packet_device::MTU as u16, run_receiver)
                .await
        };
        let result = tokio::select! {
            result = run => result,
            _ = receiver.changed() => Ok(()),
        };
        match result {
            Ok(()) => *report.lock().unwrap_or_else(|e| e.into_inner()) = (4, "未连接".into()),
            Err(error) => {
                crate::telemetry::record(format!("隧道失败：{error}"));
                *report.lock().unwrap_or_else(|e| e.into_inner()) = (5, error.to_string());
            }
        }
    });
    *engine = Some(State {
        runtime,
        port,
        stop,
        task,
        status,
        tunnel,
        health: None,
    });
    Ok(())
}

/// # Safety
/// Both pointers must reference valid UTF-8, NUL-terminated strings for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn helios_tunnel_start(node: *const c_char, root: *const c_char) -> i32 {
    if node.is_null() || root.is_null() {
        return -1;
    }
    // SAFETY: the host keeps both C strings alive for the call.
    let result = unsafe { CStr::from_ptr(node) }
        .to_str()
        .map_err(|e| -> Error { e.into() })
        .and_then(|node| {
            // SAFETY: same host contract as `node`.
            let root = unsafe { CStr::from_ptr(root) }.to_str()?;
            start(node, Path::new(root))
        });
    match result {
        Ok(()) => {
            LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()).clear();
            0
        }
        Err(error) => {
            *LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()) = error.to_string();
            -1
        }
    }
}

/// # Safety
/// `bytes` must point to `length` readable bytes. No pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn helios_tunnel_push(bytes: *const u8, length: usize) -> i32 {
    if bytes.is_null() || length > packet_device::MTU {
        return -1;
    }
    let engine = ENGINE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(engine) = engine.as_ref() else {
        return -1;
    };
    // SAFETY: checked length and host's readable-buffer contract.
    match engine
        .port
        .push(unsafe { std::slice::from_raw_parts(bytes, length) })
    {
        Ok(()) => 0,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => 1,
        Err(_) => -1,
    }
}

/// # Safety
/// `buffer` must point to `capacity` writable bytes; capacity must be at least the tunnel MTU (1500).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn helios_tunnel_pop(buffer: *mut u8, capacity: usize) -> i32 {
    if buffer.is_null() || capacity < packet_device::MTU {
        return -1;
    }
    let mut engine = ENGINE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(engine) = engine.as_mut() else {
        return -1;
    };
    match engine.port.pop() {
        Ok(Some(packet)) => {
            // SAFETY: packet validation guarantees at most MTU bytes; caller supplied capacity.
            unsafe {
                std::ptr::copy_nonoverlapping(packet.as_ptr(), buffer, packet.len());
            }
            packet.len() as i32
        }
        Ok(None) => 0,
        Err(_) => -1,
    }
}

/// # Safety
/// `buffer` is null, or points to `capacity` writable bytes. Returns required JSON length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn helios_tunnel_snapshot(buffer: *mut u8, capacity: usize) -> usize {
    let engine = ENGINE.lock().unwrap_or_else(|e| e.into_inner());
    let (phase, message) = engine
        .as_ref()
        .map(|engine| {
            engine
                .status
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        })
        .unwrap_or_else(|| {
            (
                4,
                LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            )
        });
    let (up, down, active) = crate::telemetry::snapshot();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "phase": phase, "message": message, "uploaded": up,
        "downloaded": down, "active": active, "logs": crate::telemetry::logs(),
    }))
    .expect("serializable snapshot");
    if !buffer.is_null() && capacity >= bytes.len() {
        // SAFETY: the host supplied a buffer of sufficient capacity.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
        }
    }
    bytes.len()
}

#[unsafe(no_mangle)]
pub extern "C" fn helios_tunnel_stop() {
    let engine = ENGINE.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(mut engine) = engine {
        if let Some(health) = engine.health.take() {
            health.abort();
        }
        let _ = engine.stop.send(true);
        engine.runtime.block_on(async {
            if tokio::time::timeout(Duration::from_secs(2), &mut engine.task)
                .await
                .is_err()
            {
                engine.task.abort();
                let _ = engine.task.await;
            }
        });
        engine.runtime.shutdown_timeout(Duration::from_millis(500));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn helios_tunnel_clear_logs() {
    crate::telemetry::clear();
}

#[unsafe(no_mangle)]
pub extern "C" fn helios_tunnel_recheck() {
    recheck(false);
}

#[unsafe(no_mangle)]
pub extern "C" fn helios_tunnel_network_changed() {
    recheck(true);
}

fn recheck(network_changed: bool) {
    let mut engine = ENGINE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(engine) = engine.as_mut() else {
        return;
    };
    // A successful probe cannot revive a terminated packet-processing task.
    if engine.task.is_finished() {
        return;
    }
    if engine
        .health
        .as_ref()
        .is_some_and(|task| !task.is_finished())
    {
        if !network_changed {
            return;
        }
        if let Some(health) = engine.health.take() {
            health.abort();
        }
    }
    let tunnel = engine.tunnel.clone();
    let status = engine.status.clone();
    engine.health = Some(engine.runtime.spawn(async move {
        if network_changed {
            tunnel.session.connection.lock().await.take();
        }
        for attempt in 0..3 {
            let result = async {
                tunnel
                    .session
                    .check(
                        tunnel.connector.as_ref(),
                        tunnel.node,
                        Duration::from_secs(10),
                    )
                    .await?;
                Ok::<_, Error>(())
            }
            .await;
            match result {
                Ok(()) => {
                    *status.lock().unwrap_or_else(|e| e.into_inner()) =
                        (2, "已连接 · 全部代理".into());
                    return;
                }
                Err(error) if attempt == 2 => {
                    *status.lock().unwrap_or_else(|e| e.into_inner()) =
                        (5, format!("节点重连失败：{error}"));
                    return;
                }
                Err(_) => {
                    // The peer may not have closed a connection bound to the old path.
                    tunnel.session.connection.lock().await.take();
                    *status.lock().unwrap_or_else(|e| e.into_inner()) =
                        (3, "节点暂时不可达，正在重试".into());
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_config::{ConnectionLink, TransportPreference};
    use helios_protocol::{CAP_TCP_CONNECT, CAP_UDP_OVER_STREAM, Frame, FrameType};
    use helios_transport::{ServerCrypto, authenticate_server};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::ffi::CString;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn snapshot() -> serde_json::Value {
        let mut bytes = vec![0; 65536];
        // SAFETY: the Vec provides the stated writable capacity.
        let length = unsafe { helios_tunnel_snapshot(bytes.as_mut_ptr(), bytes.len()) };
        serde_json::from_slice(&bytes[..length]).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn packet_api_uses_ipv6_node_for_dns_and_restarts() {
        let _test = crate::TUNNEL_TEST.lock().await;
        let root = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["node.test".into()]).unwrap();
        let crypto = Arc::new(
            ServerCrypto::new(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
            )
            .unwrap(),
        );
        let link = ConnectionLink::new(
            "iOS test".into(),
            listener.local_addr().unwrap(),
            "node.test".into(),
            cert.cert.der().as_ref(),
            "client".into(),
            [42; 32],
            TransportPreference::Tls,
        )
        .unwrap()
        .encode()
        .unwrap();
        let node = crate::node_store::import(root.path(), &link).unwrap();
        let node = CString::new(
            serde_json::json!({"node": node, "settings": {"dns": "[2606:4700:4700::1111]:5353"}})
                .to_string(),
        )
        .unwrap();
        let directory = CString::new(root.path().to_str().unwrap()).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut io = crypto.tls.accept(stream).await.unwrap();
            authenticate_server(&mut io, CAP_UDP_OVER_STREAM, |_| Some([42; 32]))
                .await
                .unwrap();
            let association = io.read_frame().await.unwrap();
            assert_eq!(association.frame_type, FrameType::UdpAssociate);
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
            drop(io);

            let (stream, _) = listener.accept().await.unwrap();
            let mut io = crypto.tls.accept(stream).await.unwrap();
            authenticate_server(&mut io, CAP_TCP_CONNECT, |_| Some([42; 32]))
                .await
                .unwrap();
            let request = io.read_frame().await.unwrap();
            assert_eq!(request.frame_type, FrameType::ConnectTcp);
            let request_id = request.request_id;
            let request = helios_protocol::ConnectTcp::decode(&request.payload).unwrap();
            assert_eq!(request.target.port, 5353);
            assert_eq!(
                request.target.address,
                helios_protocol::Address::Ip("2606:4700:4700::1111".parse().unwrap())
            );
            io.write_frame(&Frame::new(FrameType::ConnectOk, request_id, Vec::new()).unwrap())
                .await
                .unwrap();
            let mut raw = io.into_inner();
            let length = raw.read_u16().await.unwrap();
            let mut query = vec![0; usize::from(length)];
            raw.read_exact(&mut query).await.unwrap();
            query[2] |= 0x80;
            raw.write_u16(query.len() as u16).await.unwrap();
            raw.write_all(&query).await.unwrap();
            drop(raw);
            // A network-change check opens a fresh authenticated association.
            let (stream, _) = listener.accept().await.unwrap();
            let mut io = crypto.tls.accept(stream).await.unwrap();
            authenticate_server(&mut io, CAP_UDP_OVER_STREAM, |_| Some([42; 32]))
                .await
                .unwrap();
            let request = io.read_frame().await.unwrap();
            assert_eq!(request.frame_type, FrameType::UdpAssociate);
            io.write_frame(
                &Frame::new(
                    FrameType::UdpAssociateOk,
                    request.request_id,
                    2u32.to_be_bytes().to_vec(),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        });
        let outside_directory = tempfile::tempdir().unwrap();
        let outside = CString::new(outside_directory.path().to_str().unwrap()).unwrap();
        // SAFETY: live strings; credentials must not resolve outside the allowed container.
        assert_eq!(
            unsafe { helios_tunnel_start(node.as_ptr(), outside.as_ptr()) },
            -1
        );
        assert!(
            snapshot()["message"]
                .as_str()
                .unwrap()
                .contains("outside the shared container")
        );
        // SAFETY: both CStrings live for this call.
        assert_eq!(
            unsafe { helios_tunnel_start(node.as_ptr(), directory.as_ptr()) },
            0
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            while snapshot()["phase"] == 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(snapshot()["phase"], 2);
        let query = [0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let builder =
            etherparse::PacketBuilder::ipv4([10, 88, 0, 2], [10, 88, 0, 1], 64).udp(12345, 53);
        let mut packet = Vec::new();
        builder.write(&mut packet, &query).unwrap();
        // SAFETY: packet lives through the synchronous copy.
        assert_eq!(
            unsafe { helios_tunnel_push(packet.as_ptr(), packet.len()) },
            0
        );
        let response = tokio::time::timeout(Duration::from_secs(3), async {
            let mut bytes = vec![0; packet_device::MTU];
            loop {
                // SAFETY: the Vec provides MTU writable bytes.
                let count = unsafe { helios_tunnel_pop(bytes.as_mut_ptr(), bytes.len()) };
                if count > 0 {
                    bytes.truncate(count as usize);
                    break bytes;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let parsed = etherparse::SlicedPacket::from_ip(&response).unwrap();
        let etherparse::TransportSlice::Udp(udp) = parsed.transport.unwrap() else {
            panic!("expected UDP");
        };
        assert_eq!(&udp.payload()[..2], &query[..2]);
        assert_eq!(udp.payload()[2] & 0x80, 0x80);
        helios_tunnel_network_changed();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                // A routine healthy check must not make the UI flicker into reconnecting.
                assert_eq!(snapshot()["phase"], 2);
                let finished = ENGINE
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .health
                    .as_ref()
                    .unwrap()
                    .is_finished();
                if finished {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(snapshot()["phase"], 2);
        server.await.unwrap();
        tokio::task::spawn_blocking(|| helios_tunnel_stop())
            .await
            .unwrap();
        assert_eq!(snapshot()["phase"], 4);
        // SAFETY: same live CStrings; a stopped engine must be restartable.
        assert_eq!(
            unsafe { helios_tunnel_start(node.as_ptr(), directory.as_ptr()) },
            0
        );
        tokio::task::spawn_blocking(|| helios_tunnel_stop())
            .await
            .unwrap();
    }
}
