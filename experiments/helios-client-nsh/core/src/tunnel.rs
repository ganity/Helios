//! Packet-to-Helios forwarding. Hosts must supply platform-appropriate sockets.
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use helios_protocol::{Address, Target};
use helios_routing::{Network, RouteAction, RuleSet};
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::watch,
    task::JoinSet,
};

use crate::session::Session;

type ConnectFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;
type Error = Box<dyn std::error::Error + Send + Sync>;
const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_FLOWS: usize = if cfg!(target_os = "ios") { 64 } else { 512 };

struct Metered<D>(D);
impl<D: AsyncRead + Unpin> AsyncRead for Metered<D> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.0).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            crate::telemetry::upload(buf.filled().len() - before);
        }
        result
    }
}
impl<D: AsyncWrite + Unpin> AsyncWrite for Metered<D> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.0).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            crate::telemetry::download(*n);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Implementations must bypass the VPN for both node and direct sockets.
pub trait Connector: Send + Sync + 'static {
    fn tcp(&self, address: SocketAddr) -> ConnectFuture<'_, TcpStream>;
    fn udp(&self, ipv6: bool) -> ConnectFuture<'_, UdpSocket>;
}

pub struct TunnelHandle {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<(), Error>>,
}

impl TunnelHandle {
    pub async fn stop(self) -> Result<(), Error> {
        let _ = self.stop.send(true);
        self.task.await?
    }

    pub async fn wait(self) -> Result<(), Error> {
        self.task.await?
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use helios_config::{ConnectionLink, TransportPreference};
    use helios_routing::RuleConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Local;
    impl Connector for Local {
        fn tcp(&self, address: SocketAddr) -> ConnectFuture<'_, TcpStream> {
            Box::pin(TcpStream::connect(address))
        }
        fn udp(&self, ipv6: bool) -> ConnectFuture<'_, UdpSocket> {
            Box::pin(UdpSocket::bind(if ipv6 { "[::]:0" } else { "0.0.0.0:0" }))
        }
    }

    #[tokio::test]
    async fn direct_udp_packet_reaches_destination_and_tunnel_stops() {
        direct_udp_packet(false).await;
    }

    #[tokio::test]
    async fn ipv6_udp_packet_reaches_destination_and_tunnel_stops() {
        direct_udp_packet(true).await;
    }

    async fn direct_udp_packet(ipv6: bool) {
        let _test = crate::TUNNEL_TEST.lock().await;
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
        let echo = UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
            .await
            .unwrap();
        let port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let mut bytes = [0; 16];
            let (n, peer) = echo.recv_from(&mut bytes).await.unwrap();
            echo.send_to(&bytes[..n], peer).await.unwrap();
        });
        let rules = RuleSet::new(&[RuleConfig::Final {
            action: RouteAction::Direct,
        }])
        .unwrap();
        let tunnel = Arc::new(Tunnel {
            connector: Arc::new(Local),
            node: "127.0.0.1:443".parse().unwrap(),
            session: Arc::new(Session::from_node(&node).unwrap()),
            rules: Some(rules),
            dns_gateway: None,
        });
        let (mut client, device) = tokio::io::duplex(4096);
        let task = tunnel.start(device, 1280);
        let mut packet = Vec::new();
        if ipv6 {
            etherparse::PacketBuilder::ipv6(
                std::net::Ipv6Addr::LOCALHOST.octets(),
                std::net::Ipv6Addr::LOCALHOST.octets(),
                64,
            )
            .udp(12345, port)
            .write(&mut packet, b"ping")
            .unwrap();
        } else {
            etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [127, 0, 0, 1], 64)
                .udp(12345, port)
                .write(&mut packet, b"ping")
                .unwrap();
        }
        client.write_all(&packet).await.unwrap();
        let mut response = [0; 1280];
        let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        let parsed = etherparse::SlicedPacket::from_ip(&response[..n]).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Udp(udp) => assert_eq!(udp.payload(), b"ping"),
            _ => panic!("expected UDP response"),
        }
        let (uploaded, downloaded, active) = crate::telemetry::snapshot();
        assert!(uploaded >= packet.len() as u64);
        assert!(downloaded >= n as u64);
        assert_eq!(active, 1);
        task.stop().await.unwrap();
        assert_eq!(crate::telemetry::snapshot().2, 0);
        echo_task.await.unwrap();
    }
}

pub struct Tunnel<C> {
    pub connector: Arc<C>,
    pub node: SocketAddr,
    pub session: Arc<Session>,
    /// None forces all traffic through the server, as required on iOS.
    pub rules: Option<RuleSet>,
    /// Virtual DNS endpoint and upstream. DNS uses TCP inside Helios to avoid UDP payload limits.
    pub dns_gateway: Option<(SocketAddr, SocketAddr)>,
}

impl<C: Connector> Tunnel<C> {
    pub fn start<D>(self: Arc<Self>, device: D, mtu: u16) -> TunnelHandle
    where
        D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(self.run(device, mtu, receiver));
        TunnelHandle { stop, task }
    }

    fn route(&self, address: SocketAddr, network: Network) -> RouteAction {
        self.rules.as_ref().map_or(RouteAction::Proxy, |rules| {
            let target =
                Target::new(Address::Ip(address.ip()), address.port()).expect("socket address");
            rules.decide_for_network(&target, network)
        })
    }

    pub async fn run<D>(
        self: Arc<Self>,
        device: D,
        mtu: u16,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), Error>
    where
        D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut config = IpStackConfig::default();
        config.mtu(mtu)?;
        crate::telemetry::reset();
        let mut stack = IpStack::new(config, Metered(device));
        let mut tasks = JoinSet::new();
        loop {
            if *stop.borrow() {
                break;
            }
            tokio::select! {
                changed = stop.changed() => if changed.is_err() || *stop.borrow() { break; },
                Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                    match result {
                        Ok(Err(error)) => crate::telemetry::record(format!("转发失败：{error}")),
                        Err(error) => crate::telemetry::record(format!("转发任务失败：{error}")),
                        _ => {}
                    }
                },
                accepted = stack.accept() => {
                    let accepted = accepted?;
                    if tasks.len() >= MAX_FLOWS { drop(accepted); continue; }
                    let tunnel = self.clone();
                    match accepted {
                        IpStackStream::Tcp(stream) => { tasks.spawn(async move {
                            let _flow = crate::telemetry::Flow::new(); tunnel.tcp(stream).await
                        }); }
                        IpStackStream::Udp(stream) => { tasks.spawn(async move {
                            let _flow = crate::telemetry::Flow::new(); tunnel.udp(stream).await
                        }); }
                        _ => {}
                    }
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        crate::telemetry::record("隧道已停止".into());
        Ok(())
    }

    async fn tcp(&self, mut inbound: IpStackTcpStream) -> Result<(), Error> {
        let destination = self
            .dns_gateway
            .filter(|(gateway, _)| *gateway == inbound.peer_addr())
            .map_or(inbound.peer_addr(), |(_, upstream)| upstream);
        match self.route(destination, Network::Tcp) {
            RouteAction::Reject => Ok(()),
            RouteAction::Direct => {
                let mut outbound = self.connector.tcp(destination).await?;
                tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
                Ok(())
            }
            RouteAction::Proxy => {
                let target = Target::new(Address::Ip(destination.ip()), destination.port())?;
                let mut outbound = self
                    .session
                    .connect_tcp(self.connector.as_ref(), self.node, target, TIMEOUT)
                    .await?;
                tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
                Ok(())
            }
        }
    }

    async fn udp(&self, inbound: IpStackUdpStream) -> Result<(), Error> {
        let destination = inbound.peer_addr();
        if let Some((gateway, upstream)) = self.dns_gateway
            && gateway == destination
        {
            return self.dns_udp(inbound, upstream).await;
        }
        let route = self.route(destination, Network::Udp);
        if route == RouteAction::Reject {
            return Ok(());
        }
        let (mut input, mut output) = tokio::io::split(inbound);
        match route {
            RouteAction::Direct => {
                let socket = self.connector.udp(destination.is_ipv6()).await?;
                socket.connect(destination).await?;
                let send = async {
                    let mut buffer = vec![0; 65536];
                    loop {
                        let length = input.read(&mut buffer).await?;
                        if length == 0 {
                            return Ok::<(), Error>(());
                        }
                        socket.send(&buffer[..length]).await?;
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), Error>(())
                };
                let receive = async {
                    let mut buffer = vec![0; 65536];
                    loop {
                        let length = socket.recv(&mut buffer).await?;
                        if output.write(&buffer[..length]).await? != length {
                            return Err(io::Error::from(io::ErrorKind::WriteZero).into());
                        }
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), Error>(())
                };
                tokio::try_join!(send, receive)?;
                Ok(())
            }
            RouteAction::Proxy => {
                let (mut sender, mut receiver) = self
                    .session
                    .connect_udp(self.connector.as_ref(), self.node, TIMEOUT)
                    .await?;
                let target = Target::new(Address::Ip(destination.ip()), destination.port())?;
                let payload_limit = sender.payload_limit();
                let send = async {
                    let mut buffer = vec![0; payload_limit + 1];
                    let mut id = 0u32;
                    loop {
                        let length = input.read(&mut buffer).await?;
                        if length == 0 {
                            return Ok::<(), Error>(());
                        }
                        if length > payload_limit {
                            crate::telemetry::record(format!(
                                "UDP 报文超过协商上限 {payload_limit} 字节，已丢弃"
                            ));
                            continue;
                        }
                        id = id.wrapping_add(1);
                        sender
                            .send(id, target.clone(), buffer[..length].to_vec())
                            .await?;
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), Error>(())
                };
                let receive = async {
                    loop {
                        let response = receiver.receive().await?;
                        let header = if destination.is_ipv6() { 48 } else { 28 };
                        if response.payload.len() + header > crate::packet_device::MTU {
                            crate::telemetry::record("UDP 回复超过隧道 MTU，已丢弃".into());
                            continue;
                        }
                        if response.target == target
                            && output.write(&response.payload).await? != response.payload.len()
                        {
                            return Err(io::Error::from(io::ErrorKind::WriteZero).into());
                        }
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), Error>(())
                };
                tokio::try_join!(send, receive)?;
                Ok(())
            }
            RouteAction::Reject => Ok(()),
        }
    }

    async fn dns_udp(
        &self,
        mut inbound: IpStackUdpStream,
        upstream: SocketAddr,
    ) -> Result<(), Error> {
        let mut query = vec![0; 65535];
        loop {
            let length = inbound.read(&mut query).await?;
            if length == 0 {
                return Ok(());
            }
            if length < 12 || query[2] & 0x80 != 0 {
                continue;
            }
            let response = tokio::time::timeout(TIMEOUT, async {
                let target = Target::new(Address::Ip(upstream.ip()), upstream.port())?;
                let mut stream = self
                    .session
                    .connect_tcp(self.connector.as_ref(), self.node, target, TIMEOUT)
                    .await?;
                stream.write_u16(length as u16).await?;
                stream.write_all(&query[..length]).await?;
                let size = stream.read_u16().await?;
                let mut response = vec![0; usize::from(size)];
                stream.read_exact(&mut response).await?;
                if response.len() < 12 || response[..2] != query[..2] || response[2] & 0x80 == 0 {
                    return Err("invalid upstream DNS response".into());
                }
                Ok::<_, Error>(response)
            })
            .await??;
            // Force standard DNS-over-TCP retry when a UDP reply would exceed the IPv6 MTU.
            if response.len() > 1232 {
                let mut truncated = query[..12].to_vec();
                truncated[2] |= 0x82;
                truncated[3] &= 0xf0;
                truncated[4..12].fill(0);
                inbound.write_all(&truncated).await?;
            } else {
                inbound.write_all(&response).await?;
            }
        }
    }
}
