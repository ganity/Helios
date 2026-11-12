//! Android socket protection for a live VpnService instance.
use std::{
    io,
    net::SocketAddr,
    os::fd::{AsRawFd, OwnedFd, RawFd},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use jni::{Env, JValue, JavaVM, jni_sig, jni_str, objects::JObject, refs::Global};

struct ActivityBridge {
    vm: JavaVM,
    activity: Global<JObject<'static>>,
}
static ACTIVITY: std::sync::Mutex<Option<ActivityBridge>> = std::sync::Mutex::new(None);
static PENDING_LINK: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn take_pending_link() -> Option<String> {
    PENDING_LINK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_helios_mobile_MainActivity_nativeOpenLink<'local>(
    mut env: jni::EnvUnowned<'local>,
    _activity: JObject<'local>,
    link: jni::objects::JString<'local>,
) {
    env.with_env(|_| -> Result<(), NativeError> {
        let link = link.to_string();
        if link.len() <= 16384 {
            *PENDING_LINK.lock().unwrap_or_else(|e| e.into_inner()) = Some(link);
        }
        Ok(())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>();
}
static PROTECTOR: std::sync::Mutex<std::sync::Weak<VpnProtector>> =
    std::sync::Mutex::new(std::sync::Weak::new());

pub async fn probe_udp(ipv6: bool) -> io::Result<tokio::net::UdpSocket> {
    let protector = PROTECTOR
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .upgrade();
    if let Some(protector) = protector {
        protector.bind_udp(ipv6).await
    } else {
        crate::socket::bind_udp(ipv6, |_| Ok(())).await
    }
}

pub async fn probe_socket(address: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    let protector = PROTECTOR
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .upgrade();
    if let Some(protector) = protector {
        protector
            .connect_tcp(address, Duration::from_secs(10))
            .await
    } else {
        crate::socket::connect_tcp(address, Duration::from_secs(10), |_| Ok(())).await
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_helios_mobile_HeliosVpnService_nativeRecordError<'local>(
    mut env: jni::EnvUnowned<'local>,
    _service: JObject<'local>,
    message: jni::objects::JString<'local>,
) {
    env.with_env(|_| -> Result<(), NativeError> {
        crate::telemetry::record(message.to_string());
        Ok(())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_helios_mobile_MainActivity_nativeAttach<'local>(
    mut env: jni::EnvUnowned<'local>,
    activity: JObject<'local>,
) {
    env.with_env(|env| -> Result<(), NativeError> {
        let bridge = ActivityBridge {
            vm: env.get_java_vm()?,
            activity: env.new_global_ref(&activity)?,
        };
        *ACTIVITY.lock().unwrap_or_else(|e| e.into_inner()) = Some(bridge);
        Ok(())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_helios_mobile_MainActivity_nativeDetach<'local>(
    mut env: jni::EnvUnowned<'local>,
    activity: JObject<'local>,
) {
    env.with_env(|env| -> Result<(), NativeError> {
        let mut bridge = ACTIVITY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(current) = bridge.as_ref()
            && env.is_same_object(&current.activity, &activity)?
        {
            *bridge = None;
        }
        Ok(())
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>();
}

pub fn vpn_status() -> io::Result<String> {
    let bridge = ACTIVITY.lock().unwrap_or_else(|e| e.into_inner());
    let bridge = bridge
        .as_ref()
        .ok_or_else(|| io::Error::other("Android host unavailable"))?;
    bridge
        .vm
        .attach_current_thread(|env| -> jni::errors::Result<String> {
            let value = env
                .call_method(
                    &bridge.activity,
                    jni_str!("vpnStatus"),
                    jni_sig!("()Ljava/lang/String;"),
                    &[],
                )?
                .l()?;
            Ok(jni::objects::JString::cast_local(env, value)?.to_string())
        })
        .map_err(io::Error::other)
}

pub fn request_connect(node_json: &str) -> io::Result<()> {
    let bridge = ACTIVITY.lock().unwrap_or_else(|e| e.into_inner());
    let bridge = bridge
        .as_ref()
        .ok_or_else(|| io::Error::other("Android host unavailable"))?;
    bridge
        .vm
        .attach_current_thread(|env| -> jni::errors::Result<()> {
            let node = jni::objects::JString::from_str(env, node_json)?;
            env.call_method(
                &bridge.activity,
                jni_str!("requestConnect"),
                jni_sig!("(Ljava/lang/String;)V"),
                &[JValue::Object(&node)],
            )?;
            Ok(())
        })
        .map_err(io::Error::other)
}

pub fn request_disconnect() -> io::Result<()> {
    let bridge = ACTIVITY.lock().unwrap_or_else(|e| e.into_inner());
    let bridge = bridge
        .as_ref()
        .ok_or_else(|| io::Error::other("Android host unavailable"))?;
    bridge
        .vm
        .attach_current_thread(|env| -> jni::errors::Result<()> {
            env.call_method(
                &bridge.activity,
                jni_str!("requestDisconnect"),
                jni_sig!("()V"),
                &[],
            )?;
            Ok(())
        })
        .map_err(io::Error::other)
}

pub struct VpnProtector {
    vm: JavaVM,
    service: Global<JObject<'static>>,
}

#[derive(Debug)]
struct NativeError(Box<dyn std::error::Error + Send + Sync>);
impl std::fmt::Display for NativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for NativeError {}
impl From<jni::errors::Error> for NativeError {
    fn from(error: jni::errors::Error) -> Self {
        Self(Box::new(error))
    }
}

impl VpnProtector {
    fn stopping(&self) -> io::Result<bool> {
        self.vm
            .attach_current_thread(|env| {
                env.call_method(&self.service, jni_str!("isStopping"), jni_sig!("()Z"), &[])?
                    .z()
            })
            .map_err(io::Error::other)
    }
    pub fn new(env: &Env<'_>, service: &JObject<'_>) -> jni::errors::Result<Self> {
        Ok(Self {
            vm: env.get_java_vm()?,
            service: env.new_global_ref(service)?,
        })
    }

    pub fn protect(&self, fd: RawFd) -> io::Result<()> {
        let protected = self
            .vm
            .attach_current_thread(|env| {
                env.call_method(
                    &self.service,
                    jni_str!("protect"),
                    jni_sig!("(I)Z"),
                    &[JValue::Int(fd)],
                )?
                .z()
            })
            .map_err(|error| io::Error::other(format!("VpnService.protect failed: {error}")))?;
        if protected {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VpnService.protect returned false",
            ))
        }
    }

    pub async fn connect_tcp(
        &self,
        destination: SocketAddr,
        deadline: Duration,
    ) -> io::Result<tokio::net::TcpStream> {
        crate::socket::connect_tcp(destination, deadline, |fd| self.protect(fd)).await
    }

    pub async fn bind_udp(&self, ipv6: bool) -> io::Result<tokio::net::UdpSocket> {
        crate::socket::bind_udp(ipv6, |fd| self.protect(fd)).await
    }
}

/// Called on the service's worker thread; Java retains its descriptor until return.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_helios_mobile_HeliosVpnService_nativeRun<'local>(
    mut env: jni::EnvUnowned<'local>,
    service: JObject<'local>,
    fd: jni::sys::jint,
    node_json: jni::objects::JString<'local>,
) {
    env.with_env(|env| {
        (|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            use std::os::fd::BorrowedFd;
            if fd < 0 {
                return Err("invalid TUN descriptor".into());
            }
            // SAFETY: Java retains its ParcelFileDescriptor throughout this blocking call.
            let fd = unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?;
            let node: helios_client_model::NodeProfile =
                serde_json::from_str(&node_json.to_string())?;
            let protector = Arc::new(VpnProtector::new(env, &service)?);
            *PROTECTOR.lock().unwrap_or_else(|e| e.into_inner()) = Arc::downgrade(&protector);
            let tunnel = Arc::new(crate::tunnel::Tunnel {
                connector: protector.clone(),
                node: node.server.parse()?,
                session: Arc::new(crate::session::Session::from_node(&node)?),
                rules: None,
                dns_gateway: None,
            });
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async move {
                // Authenticate before reporting success; creating a TUN alone is not a connection.
                let preflight = async {
                    tunnel
                        .session
                        .check(protector.as_ref(), tunnel.node, Duration::from_secs(10))
                        .await?;
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                };
                tokio::pin!(preflight);
                loop {
                    tokio::select! {
                        result = &mut preflight => { result?; break; }
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {
                            if protector.stopping()? { return Ok(()); }
                        }
                    }
                }
                protector.vm.attach_current_thread(|env| {
                    env.call_method(
                        &protector.service,
                        jni_str!("connected"),
                        jni_sig!("()V"),
                        &[],
                    )
                    .map(|_| ())
                })?;
                let (stop, receiver) = tokio::sync::watch::channel(false);
                let run = run_tunnel(tunnel.clone(), fd, 1500, receiver);
                tokio::pin!(run);
                loop {
                    tokio::select! {
                        result = &mut run => return result,
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {
                            if protector.stopping()? {
                                let _ = stop.send(true);
                                return run.await;
                            }
                        }
                    }
                }
            })
        })()
        .map_err(NativeError)
    })
    .resolve::<jni::errors::ThrowRuntimeExAndDefault>();
}

impl crate::tunnel::Connector for VpnProtector {
    fn tcp(
        &self,
        address: SocketAddr,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = io::Result<tokio::net::TcpStream>> + Send + '_>,
    > {
        Box::pin(self.connect_tcp(address, Duration::from_secs(10)))
    }

    fn udp(
        &self,
        ipv6: bool,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = io::Result<tokio::net::UdpSocket>> + Send + '_>,
    > {
        Box::pin(self.bind_udp(ipv6))
    }
}

struct OwnedTun {
    device: tun::AsyncDevice,
    _fd: OwnedFd,
}

impl tokio::io::AsyncRead for OwnedTun {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.device).poll_read(cx, buffer)
    }
}

impl tokio::io::AsyncWrite for OwnedTun {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.device).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.device).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.device).poll_shutdown(cx)
    }
}

/// Takes ownership of the descriptor returned by VpnService.Builder.establish().
pub async fn run_tunnel(
    tunnel: Arc<crate::tunnel::Tunnel<VpnProtector>>,
    fd: OwnedFd,
    mtu: u16,
    stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut config = tun::Configuration::default();
    config
        .raw_fd(fd.as_raw_fd())
        .close_fd_on_drop(false)
        .mtu(mtu);
    let device = tun::create_as_async(&config)?;
    tunnel.run(OwnedTun { device, _fd: fd }, mtu, stop).await
}

/// Starts the tunnel on the current Tokio runtime and returns its stop handle.
pub fn start_tunnel(
    tunnel: Arc<crate::tunnel::Tunnel<VpnProtector>>,
    fd: OwnedFd,
    mtu: u16,
) -> Result<crate::tunnel::TunnelHandle, Box<dyn std::error::Error + Send + Sync>> {
    let mut config = tun::Configuration::default();
    config
        .raw_fd(fd.as_raw_fd())
        .close_fd_on_drop(false)
        .mtu(mtu);
    let device = tun::create_as_async(&config)?;
    Ok(tunnel.start(OwnedTun { device, _fd: fd }, mtu))
}
