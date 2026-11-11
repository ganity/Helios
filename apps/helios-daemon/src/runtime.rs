use super::*;

struct State {
    remote: Remote,
    health: Arc<DaemonMetrics>,
    config: DaemonConfig,
    revision: u64,
}

pub struct Runtime {
    state: RwLock<State>,
    apply: tokio::sync::Mutex<()>,
    metrics: Arc<DaemonMetrics>,
    closing: AtomicBool,
    config_path: Option<PathBuf>,
}

impl Runtime {
    pub fn new(remote: Remote, config: DaemonConfig, config_path: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            metrics: remote.metrics.clone(),
            state: RwLock::new(State {
                health: remote.metrics.clone(),
                remote,
                config,
                revision: 1,
            }),
            apply: tokio::sync::Mutex::new(()),
            closing: AtomicBool::new(false),
            config_path,
        })
    }

    pub async fn remote(&self) -> Remote {
        self.state.read().await.remote.clone()
    }
    pub async fn config(&self) -> DaemonConfig {
        self.state.read().await.config.clone()
    }
    pub fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
    }
    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::SeqCst)
    }

    async fn failover(&self) -> Result<bool, AnyError> {
        let state = self.state.read().await;
        let mut config = state.config.clone();
        let revision = state.revision;
        drop(state);
        let primary = config.node.clone();
        let candidates = config.backup_nodes.clone();
        for candidate in &candidates {
            if candidate == &primary {
                continue;
            }
            config.node = candidate.clone();
            config.backup_nodes = candidates
                .iter()
                .filter(|node| *node != candidate)
                .cloned()
                .collect();
            config.backup_nodes.push(primary.clone());
            match self.apply(revision, config.clone()).await {
                Ok(_) => {
                    info!(event = "backup_node_activated");
                    return Ok(true);
                }
                Err(error) => {
                    if self.state.read().await.revision != revision || self.is_closing() {
                        return Err(error);
                    }
                    debug!(event = "backup_node_unavailable", error = %error);
                }
            }
        }
        Ok(false)
    }

    pub async fn monitor(
        self: Arc<Self>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), AnyError> {
        let mut failures = 0u8;
        let mut cooldown = Instant::now();
        loop {
            let config = self.config().await;
            tokio::select! {
                _ = sleep(Duration::from_secs(config.timeouts.health_probe_seconds)) => {},
                changed = shutdown.changed() => { changed?; return Ok(()); }
            }
            if self.is_closing() {
                return Ok(());
            }
            let unhealthy = self.snapshot().await.state == ConnectionState::Unavailable;
            failures = if unhealthy {
                failures.saturating_add(1)
            } else {
                0
            };
            if failures >= 3 && Instant::now() >= cooldown && !config.backup_nodes.is_empty() {
                tokio::select! {
                    _ = timeout(Duration::from_secs(25), self.failover()) => {},
                    changed = shutdown.changed() => { changed?; return Ok(()); }
                }
                failures = 0;
                // Do not switch back automatically; wait a minute before another failover attempt.
                cooldown = Instant::now() + Duration::from_secs(60);
            }
        }
    }

    pub async fn snapshot(&self) -> StatusSnapshot {
        let state = self.state.read().await;
        let mut snapshot = self.metrics.snapshot();
        let health = state.health.snapshot();
        snapshot.state = health.state;
        snapshot.transport = health.transport;
        snapshot.quic_rtt_micros = health.quic_rtt_micros;
        snapshot.tls_rtt_micros = health.tls_rtt_micros;
        snapshot.config_revision = state.revision;
        snapshot.active_server = Some(state.config.node.server);
        snapshot.dns_cache = state.remote.fake_ips.as_ref().map(FakeIpPool::stats);
        snapshot
    }

    pub async fn update_rules(
        &self,
        configs: &[helios_routing::RuleConfig],
    ) -> Result<(), AnyError> {
        let updated = RuleSet::new(configs)?;
        let _apply = self.apply.lock().await;
        if self.closing.load(Ordering::SeqCst) {
            return Err("daemon is shutting down".into());
        }
        let mut state = self.state.write().await;
        let mut config = state.config.clone();
        config.rules = configs.to_vec();
        if let Some(path) = &self.config_path {
            config.save(path)?;
        }
        *state.remote.rules.write().await = updated;
        state.config = config;
        state.revision += 1;
        Ok(())
    }

    pub async fn apply(&self, revision: u64, config: DaemonConfig) -> Result<u64, AnyError> {
        config.validate()?;
        let _apply = self.apply.lock().await;
        if self.closing.load(Ordering::SeqCst) {
            return Err("daemon is shutting down".into());
        }
        let (old, fake_ips, rules) = {
            let state = self.state.read().await;
            if revision != state.revision {
                return Err("configuration changed; refresh status and retry".into());
            }
            (
                state.config.clone(),
                state.remote.fake_ips.clone(),
                state.remote.rules.clone(),
            )
        };
        // Listener and DNS leases belong to this process and require an explicit restart.
        if config.listen != old.listen
            || config.http_listen != old.http_listen
            || config.control_listen != old.control_listen
            || config.control_socket != old.control_socket
            || config.control_pipe != old.control_pipe
            || config.control_token_file != old.control_token_file
            || config.outbound != old.outbound
            || config.dns != old.dns
            || config.timeouts != old.timeouts
        {
            return Err(
                "listener, DNS, outbound binding, control identity or timeout changes require a daemon restart"
                    .into(),
            );
        }
        let updated_rules = RuleSet::new(&config.rules)?;
        let args = Args {
            outbound: outbound::Outbound::new(config.outbound.clone()),
            transport: config.node.preferred_transport,
            listen: config.listen,
            http_listen: config.http_listen,
            control_listen: config.control_listen,
            control_socket: config.control_socket.clone(),
            control_pipe: config.control_pipe.clone(),
            server: config.node.server,
            server_name: ServerName::try_from(config.node.server_name.clone())?,
            credential_id: Arc::from(config.node.credential_id.clone()),
            token: load_token(&config.node.token_file)?,
            socks_handshake_seconds: config.timeouts.socks_handshake_seconds,
            http_handshake_seconds: config.timeouts.http_handshake_seconds,
            connect_milliseconds: config.timeouts.connect_milliseconds.min(5_000),
            health_probe_seconds: config.timeouts.health_probe_seconds,
            udp_idle_seconds: config.timeouts.udp_idle_seconds,
            rules: updated_rules.clone(),
        };
        let crypto = ClientCrypto::new(load_roots(&config.node.ca_certificate)?)?;
        // Authenticate before committing so a bad certificate/token never replaces the working node.
        let tls_probe = timeout(
            Duration::from_secs(5),
            probe_tls(
                &crypto.tls,
                args.server,
                &args.server_name,
                &args.credential_id,
                &args.token,
                &args.outbound,
            ),
        )
        .await;
        let mut remote = build_remote(&args, crypto, fake_ips).await?;
        let health = remote.metrics.clone();
        match tls_probe {
            Ok(Ok(rtt)) => {
                health.tls_checked.store(true, Ordering::Relaxed);
                health.tls_healthy.store(true, Ordering::Relaxed);
                health
                    .tls_rtt_micros
                    .store(rtt.as_micros().max(1) as u64, Ordering::Relaxed);
            }
            _ if remote.quic.read().await.is_some() => {}
            _ => {
                return Err(
                    "new node authentication failed on both transports; active node preserved"
                        .into(),
                );
            }
        }
        remote.metrics = self.metrics.clone();
        remote.rules = rules.clone();
        remote.connect_milliseconds = config.timeouts.connect_milliseconds;
        let mut state = self.state.write().await;
        let mut rule_guard = rules.write().await;
        if self.closing.load(Ordering::SeqCst) {
            return Err("daemon is shutting down".into());
        }
        if let Some(proxy) = self
            .metrics
            .proxy
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_mut()
        {
            proxy.update_settings(helios_system_proxy::ProxySettings {
                endpoint: helios_system_proxy::ProxyEndpoint::new(
                    config.http_listen.ip().to_string(),
                    config.http_listen.port(),
                )?,
                bypass: config.proxy_bypass.clone(),
            })?;
        }
        if let Some(path) = &self.config_path
            && let Err(error) = config.save(path)
        {
            if let Some(proxy) = self
                .metrics
                .proxy
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_mut()
            {
                proxy.update_settings(helios_system_proxy::ProxySettings {
                    endpoint: helios_system_proxy::ProxyEndpoint::new(
                        old.http_listen.ip().to_string(),
                        old.http_listen.port(),
                    )?,
                    bypass: old.proxy_bypass,
                })?;
            }
            return Err(error.into());
        }
        *rule_guard = updated_rules;
        state.remote = remote;
        state.health = health;
        state.config = config;
        state.revision += 1;
        Ok(state.revision)
    }
}

pub async fn restore_proxy_after_wake(
    metrics: Arc<DaemonMetrics>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), AnyError> {
    #[cfg(target_os = "macos")]
    {
        use std::time::SystemTime;

        let mut ticks = interval(Duration::from_secs(2));
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut previous = SystemTime::now();
        loop {
            tokio::select! {
                _ = ticks.tick() => {
                    let now = SystemTime::now();
                    let resumed = now.duration_since(previous).is_ok_and(|gap| gap > Duration::from_secs(6));
                    previous = now;
                    if !resumed {
                        continue;
                    }
                    info!(event = "system_resume_detected");
                    for _ in 0..5 {
                        tokio::select! {
                            _ = sleep(Duration::from_secs(3)) => {},
                            changed = shutdown.changed() => { changed?; return Ok(()); }
                        }
                        let metrics = metrics.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            let mut proxy = metrics.proxy.lock().unwrap_or_else(|error| error.into_inner());
                            proxy.as_mut().filter(|proxy| proxy.status().0).map(|proxy| proxy.set(true)).transpose()
                        }).await?;
                        match result {
                            Ok(_) => break,
                            Err(error) => warn!(event = "system_proxy_resume_failed", error = %error),
                        }
                    }
                    previous = SystemTime::now();
                }
                changed = shutdown.changed() => { changed?; return Ok(()); }
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = metrics;
        shutdown.changed().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use helios_protocol::{Address, CAP_TCP_CONNECT};
    use helios_routing::RuleConfig;
    use helios_transport::{ServerCrypto, accept_tcp_frame, authenticate_server};
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::AsyncWriteExt;

    async fn node() -> (
        helios_config::NodeConfig,
        tokio::task::JoinHandle<()>,
        PathBuf,
    ) {
        let certified = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls = ServerCrypto::new(
            vec![certified.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                certified.signing_key.serialize_der(),
            )),
        )
        .unwrap()
        .tls;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let directory = std::env::temp_dir().join(format!(
            "helios-runtime-{}-{}",
            std::process::id(),
            address.port()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(certified.cert.der());
        let pem = format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n");
        std::fs::write(directory.join("ca.pem"), pem).unwrap();
        helios_config::ensure_control_token(&directory.join("token.hex")).unwrap();
        let token = load_token(directory.join("token.hex")).unwrap();
        let task = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let tls = tls.clone();
                tokio::spawn(async move {
                    let Ok(mut io) = tls.accept(tcp).await else {
                        return;
                    };
                    if authenticate_server(&mut io, CAP_TCP_CONNECT, |id| {
                        (id == "test").then_some(token)
                    })
                    .await
                    .is_err()
                    {
                        return;
                    }
                    let Ok(frame) = io.read_frame().await else {
                        return;
                    };
                    if frame.frame_type == FrameType::Ping {
                        let _ = io
                            .write_frame(
                                &Frame::new(FrameType::Pong, frame.request_id, frame.payload)
                                    .unwrap(),
                            )
                            .await;
                    } else if let Ok((mut client, mut target)) = accept_tcp_frame(io, frame).await {
                        let _ = copy_bidirectional(&mut client, &mut target).await;
                    }
                });
            }
        });
        (
            helios_config::NodeConfig {
                server: address,
                server_name: "localhost".into(),
                ca_certificate: directory.join("ca.pem"),
                credential_id: "test".into(),
                token_file: directory.join("token.hex"),
                preferred_transport: TransportPreference::Tls,
            },
            task,
            directory,
        )
    }

    #[tokio::test]
    async fn switching_authenticates_before_commit_preserves_old_streams_and_checks_revision() {
        let (first, server1, directory1) = node().await;
        let (second, server2, directory2) = node().await;
        let config = DaemonConfig {
            schema_version: 1,
            listen: "127.0.0.1:1080".parse().unwrap(),
            http_listen: "127.0.0.1:8080".parse().unwrap(),
            control_listen: "127.0.0.1:9090".parse().unwrap(),
            control_socket: None,
            control_pipe: None,
            control_token_file: None,
            proxy_bypass: vec![],
            dns: None,
            outbound: None,
            node: first,
            backup_nodes: Vec::new(),
            rules: vec![RuleConfig::Final {
                action: RouteAction::Proxy,
            }],
            timeouts: Default::default(),
        };
        let args = Args {
            outbound: Default::default(),
            transport: TransportPreference::Tls,
            listen: config.listen,
            http_listen: config.http_listen,
            control_listen: config.control_listen,
            control_socket: None,
            control_pipe: None,
            server: config.node.server,
            server_name: ServerName::try_from("localhost").unwrap(),
            credential_id: Arc::from("test"),
            token: load_token(&config.node.token_file).unwrap(),
            socks_handshake_seconds: 5,
            http_handshake_seconds: 5,
            connect_milliseconds: 1000,
            health_probe_seconds: 30,
            udp_idle_seconds: 60,
            rules: RuleSet::new(&config.rules).unwrap(),
        };
        let remote = build_remote(
            &args,
            ClientCrypto::new(load_roots(&config.node.ca_certificate).unwrap()).unwrap(),
            None,
        )
        .await
        .unwrap();
        let runtime = Runtime::new(remote, config.clone(), Some(directory1.join("daemon.toml")));
        *runtime.metrics.runtime.lock().unwrap() = Some(Arc::downgrade(&runtime));
        let draft_rules = vec![
            RuleConfig::IpCidr {
                value: "127.0.0.0/8".into(),
                action: RouteAction::Direct,
                resolve: true,
            },
            RuleConfig::IpCidr6 {
                value: "::1/128".into(),
                action: RouteAction::Direct,
                resolve: true,
            },
            RuleConfig::Final {
                action: RouteAction::Reject,
            },
        ];
        let request = ControlRequest {
            version: CONTROL_VERSION,
            token: [9; 32],
            command: ControlCommand::TestRoute {
                rules: draft_rules,
                host: "localhost".into(),
                port: 443,
                network: Network::Tcp,
            },
        };
        let (result, shutdown) = control_result(
            &request,
            &[9; 32],
            &runtime.metrics,
            &runtime.remote().await.rules,
        )
        .await;
        let ControlResult::RouteTest { report } = result else {
            panic!("expected runtime route report: {result:?}");
        };
        assert_eq!(report.action, RouteAction::Direct);
        assert!(!report.selected_ips.is_empty());
        assert!(!shutdown);
        assert_eq!(
            runtime.config().await.rules,
            config.rules,
            "testing a draft must not apply it"
        );
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            loop {
                let (mut stream, _) = target.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        let destination = Target::new(Address::Ip(address.ip()), address.port()).unwrap();
        let old_remote = runtime.remote().await;
        let mut old_stream = old_remote.open(destination.clone()).await.unwrap();
        let mut next = config.clone();
        next.node = second.clone();
        next.backup_nodes = vec![config.node.clone()];
        assert_eq!(runtime.apply(1, next.clone()).await.unwrap(), 2);
        assert_eq!(
            DaemonConfig::load(directory1.join("daemon.toml")).unwrap(),
            next
        );
        assert_eq!(runtime.remote().await.server, second.server);
        old_stream.write_all(b"old").await.unwrap();
        let mut bytes = [0; 3];
        old_stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"old");
        let mut new_stream = runtime.remote().await.open(destination).await.unwrap();
        new_stream.write_all(b"new").await.unwrap();
        new_stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"new");
        assert!(
            runtime
                .apply(1, config.clone())
                .await
                .unwrap_err()
                .to_string()
                .contains("configuration changed")
        );
        let mut bad = next.clone();
        bad.node.token_file = config.node.token_file.clone();
        assert!(
            runtime
                .apply(2, bad)
                .await
                .unwrap_err()
                .to_string()
                .contains("authentication failed")
        );
        assert_eq!(runtime.snapshot().await.config_revision, 2);
        assert_eq!(runtime.snapshot().await.active_server, Some(second.server));
        #[cfg(target_os = "linux")]
        {
            let mut changed_binding = next.clone();
            changed_binding.outbound = Some(helios_config::OutboundConfig {
                source_bypass: vec!["192.0.2.1".parse().unwrap()],
                dns_servers: vec!["192.0.2.53:53".parse().unwrap()],
            });
            assert!(
                runtime
                    .apply(2, changed_binding)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("restart")
            );
            assert_eq!(runtime.snapshot().await.config_revision, 2);
            assert_eq!(runtime.config().await.outbound, None);
        }
        let mut changed_listener = next;
        changed_listener.listen.set_port(11080);
        assert!(
            runtime
                .apply(2, changed_listener)
                .await
                .unwrap_err()
                .to_string()
                .contains("restart")
        );
        assert!(runtime.failover().await.unwrap());
        assert_eq!(
            runtime.snapshot().await.active_server,
            Some(config.node.server)
        );
        assert_eq!(runtime.snapshot().await.config_revision, 3);
        runtime.update_rules(&config.rules).await.unwrap();
        assert_eq!(runtime.snapshot().await.config_revision, 4);
        runtime.close();
        assert!(
            runtime
                .apply(4, config)
                .await
                .unwrap_err()
                .to_string()
                .contains("shutting down")
        );
        drop(old_stream);
        drop(new_stream);
        drop(old_remote);
        drop(runtime);
        echo.abort();
        server1.abort();
        server2.abort();
        std::fs::remove_dir_all(directory1).unwrap();
        std::fs::remove_dir_all(directory2).unwrap();
    }
}
