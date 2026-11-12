//! Outbound sockets that must be protected before use by an Android VPN.
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsRawFd, RawFd},
    time::Duration,
};

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// `protect` must call Android's VpnService.protect and return an error on failure.
pub async fn connect_tcp(
    destination: SocketAddr,
    deadline: Duration,
    protect: impl FnOnce(RawFd) -> io::Result<()>,
) -> io::Result<TcpStream> {
    let socket = if destination.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    protect(socket.as_raw_fd())?;
    socket.set_nodelay(true)?;
    let stream = tokio::time::timeout(deadline, socket.connect(destination))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    helios_transport::configure_tcp(&stream)?;
    Ok(stream)
}

/// Creates a protected UDP socket for the requested address family.
pub async fn bind_udp(
    ipv6: bool,
    protect: impl FnOnce(RawFd) -> io::Result<()>,
) -> io::Result<UdpSocket> {
    let address = if ipv6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    let socket = UdpSocket::bind((address, 0)).await?;
    protect(socket.as_raw_fd())?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::{net::TcpListener, time::timeout};

    use super::*;

    #[tokio::test]
    async fn tcp_protection_precedes_connection_and_failure_prevents_it() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let called = AtomicBool::new(false);
        let error = connect_tcp(address, Duration::from_secs(1), |_| {
            called.store(true, Ordering::SeqCst);
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(called.load(Ordering::SeqCst));
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );

        let stream = connect_tcp(address, Duration::from_secs(1), |_| Ok(()))
            .await
            .unwrap();
        let (peer, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        drop((stream, peer));
    }

    #[tokio::test]
    async fn udp_protection_failure_is_not_ignored() {
        let error = bind_udp(false, |_| Err(io::ErrorKind::PermissionDenied.into()))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let socket = bind_udp(false, |_| Ok(())).await.unwrap();
        assert!(socket.local_addr().unwrap().is_ipv4());
    }
}
