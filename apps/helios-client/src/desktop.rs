use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};

use eframe::egui::{
    self, Align, Color32, CornerRadius, FontId, Layout, Margin, RichText, Stroke, Vec2,
};
use helios_client_control::{DaemonClient, DaemonPresence, NodeProbeReport, probe_transports};
use helios_config::{TransportPreference, ensure_control_token};
use helios_control::{ConnectionState, StatusSnapshot};
use helios_routing::{Network, RouteAction};
#[cfg(target_os = "linux")]
use helios_system_proxy::LinuxProxyAdapter;
#[cfg(target_os = "macos")]
use helios_system_proxy::MacosProxyAdapter;
#[cfg(windows)]
use helios_system_proxy::WindowsProxyAdapter;
#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
use helios_system_proxy::{ReleaseOutcome, SystemProxyLease};
#[cfg(any(windows, target_os = "macos"))]
use tray_icon::{
    TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem},
};

type AnyError = Box<dyn std::error::Error + Send + Sync>;
#[cfg(target_os = "linux")]
#[path = "linux_tray.rs"]
mod linux_tray;
#[cfg(target_os = "linux")]
#[path = "linux_tun.rs"]
mod linux_tun;
#[cfg(any(test, target_os = "macos"))]
#[path = "tray_display.rs"]
mod tray_display;
use crate::i18n::{self, t};
#[cfg(any(windows, target_os = "macos"))]
use helios_client_model::tun_stop_file;
use helios_client_model::{
    DesktopProfile, Language, NodeProfile, RoutingMode, action_name, default_control_socket,
    default_state_dir, import_connection_link as import_link, import_node, load_profile,
    parse_proxy_bypass, parse_rules, render_rules, save_profile, test_route_for_network,
    tun_status_file,
};
const BG: Color32 = Color32::from_rgb(16, 23, 21);
const SIDEBAR: Color32 = Color32::from_rgb(11, 18, 16);
const PANEL: Color32 = Color32::from_rgb(22, 32, 27);
const PANEL_2: Color32 = Color32::from_rgb(28, 41, 31);
const LINE: Color32 = Color32::from_rgb(41, 52, 44);
const TEXT: Color32 = Color32::from_rgb(237, 241, 232);
const MUTED: Color32 = Color32::from_rgb(152, 166, 155);
const ACCENT: Color32 = Color32::from_rgb(212, 247, 130);
const GOOD: Color32 = Color32::from_rgb(140, 214, 173);
const WARN: Color32 = Color32::from_rgb(255, 177, 66);
const BAD: Color32 = Color32::from_rgb(255, 94, 94);
const TRAY_ICON: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../assets/helios-tray.png"
));
#[cfg(not(target_os = "macos"))]
const APP_ICON: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../assets/helios-icon-512.png"
));
#[cfg(target_os = "macos")]
const APP_ICON: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../assets/helios-icon-macos.png"
));

pub fn run() -> Result<(), AnyError> {
    let _instance = lock_desktop_at(&default_state_dir().join("desktop.lock"))?;
    ensure_control_token(&control_token_file())?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(t("Helios · 曜光"))
            .with_inner_size([980.0, 760.0])
            .with_min_inner_size([760.0, 600.0])
            .with_icon(eframe::icon_data::from_png_bytes(APP_ICON)?),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "Helios",
        options,
        Box::new(|cc| Ok(Box::new(HeliosApp::new(cc)))),
    )
    .map_err(|error| std::io::Error::other(error.to_string()).into())
}

fn lock_desktop_at(path: &Path) -> Result<std::fs::File, AnyError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    file.try_lock().map_err(|error| {
        std::io::Error::other(format!("{}: {error}", t("Helios 已在运行，请从托盘打开")))
    })?;
    // Keep the file in place so all later instances lock the same inode.
    Ok(file)
}

#[cfg(any(windows, target_os = "macos"))]
const TRAY_SHOW: &str = "show";
#[cfg(any(windows, target_os = "macos"))]
const TRAY_TOGGLE_DAEMON: &str = "toggle-daemon";
#[cfg(any(windows, target_os = "macos"))]
const TRAY_QUIT: &str = "quit";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Page {
    Overview,
    Node,
    Rules,
    Diagnostics,
    Settings,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DiagnosticTab {
    Connections,
    Dns,
    Logs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LogEntry {
    timestamp: String,
    level: String,
    event: String,
}

enum Event {
    RouteTest(u64, Result<helios_control::RouteTestReport, String>),
    #[cfg(target_os = "linux")]
    LinuxTunPrepared(u64, Result<helios_config::OutboundConfig, String>),
    #[cfg(target_os = "linux")]
    LinuxTunPipe(u64, std::process::ChildStdin),
    #[cfg(target_os = "linux")]
    LinuxTunReady(u64),
    #[cfg(target_os = "linux")]
    LinuxTunEnded(u64, Result<(), String>),
    #[cfg(target_os = "linux")]
    LinuxTunRecovered(Result<(), String>),
    ConfigApplied(u64, DesktopProfile, Result<u64, String>),
    Status(u64, Result<StatusSnapshot, String>),
    DaemonOffline(u64),
    Startup(Result<DaemonPresence, String>),
    Probe(usize, Result<NodeProbeReport, String>),
    RulesUpdated(Result<(), String>),
    FlowClosed(Result<(), String>),
    DnsPruned(Result<(), String>),
    #[cfg(target_os = "linux")]
    TrayReady(Result<linux_tray::LinuxTray, String>),
    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    TrayAction(TrayAction),
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrayAction {
    Show,
    ToggleDaemon,
    Quit,
}

#[derive(Clone, Debug, Default)]
enum ProbeState {
    #[default]
    Untested,
    Pending,
    Succeeded(NodeProbeReport),
    Failed(String),
}

struct NodeEditor {
    index: Option<usize>,
    node: NodeProfile,
    error: Option<String>,
}

struct HeliosApp {
    page: Page,
    diagnostic_tab: DiagnosticTab,
    connecting_since: Option<Instant>,
    profile_path: PathBuf,
    profile: DesktopProfile,
    rule_text: String,
    proxy_bypass_text: String,
    rule_test_host: String,
    rule_test_port: String,
    rule_test_network: Network,
    rule_test_generation: u64,
    rule_test_pending: bool,
    rule_test_input: Option<(RoutingMode, String, String, String, Network, u64)>,
    rule_test_result: Option<Result<helios_control::RouteTestReport, String>>,
    connection_link_text: String,
    node_exchange_text: String,
    open_node_import: bool,
    node_editor: Option<NodeEditor>,
    node_filter: String,
    status: Option<StatusSnapshot>,
    status_error: Option<String>,
    last_traffic: Option<(Instant, u64, u64)>,
    upload_rate: f64,
    download_rate: f64,
    traffic_history: VecDeque<(f64, f64)>,
    connection_filter: String,
    log_filter: String,
    log_level: String,
    probes: Vec<ProbeState>,
    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    system_proxy_enabled: bool,
    system_proxy_verified: bool,
    tun_enabled: bool,
    #[cfg(target_os = "linux")]
    linux_tun: Option<linux_tun::Session>,
    #[cfg(target_os = "linux")]
    linux_tun_serial: u64,
    #[cfg(target_os = "linux")]
    linux_exit_after_tun: bool,
    notice: Option<(String, bool)>,
    child: Option<Child>,
    daemon_profile: Option<DesktopProfile>,
    startup_checked: bool,
    daemon_revision: u64,
    unexpected_restarts: u8,
    recovering_connection: bool,
    applying_config: bool,
    events: Receiver<Event>,
    event_tx: Sender<Event>,
    last_poll: Instant,
    status_request_revision: Option<u64>,
    log_entries: Vec<LogEntry>,
    log_error: Option<String>,
    last_log_refresh: Instant,
    exit_requested: bool,
    #[cfg(any(windows, target_os = "macos"))]
    _tray: Option<TrayIcon>,
    #[cfg(target_os = "linux")]
    linux_tray: Option<linux_tray::LinuxTray>,
}

impl HeliosApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_style(&cc.egui_ctx);
        let profile_path = default_state_dir().join("desktop.json");
        let profile = load_profile(&profile_path).unwrap_or_default();
        i18n::set_language(profile.language);
        let mut app = Self::from_profile(profile_path, profile);
        app.tun_enabled = tun_is_running();
        #[cfg(any(windows, target_os = "macos"))]
        {
            let events = app.event_tx.clone();
            let ctx = cc.egui_ctx.clone();
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                let action = match event.id().0.as_str() {
                    TRAY_SHOW => TrayAction::Show,
                    TRAY_TOGGLE_DAEMON => TrayAction::ToggleDaemon,
                    TRAY_QUIT => TrayAction::Quit,
                    _ => return,
                };
                let _ = events.send(Event::TrayAction(action));
                ctx.request_repaint();
            }));
            app._tray = create_tray().ok();
        }
        #[cfg(target_os = "linux")]
        linux_tray::start(app.event_tx.clone());
        app.request_startup_check();
        app
    }

    fn from_profile(profile_path: PathBuf, profile: DesktopProfile) -> Self {
        let probes = vec![ProbeState::Untested; profile.nodes.len()];
        let rule_text = render_rules(&profile.rules);
        let proxy_bypass_text = profile.proxy_bypass.join("\n");
        let (event_tx, events) = mpsc::channel();
        Self {
            page: Page::Overview,
            diagnostic_tab: DiagnosticTab::Connections,
            connecting_since: None,
            profile_path,
            profile,
            rule_text,
            proxy_bypass_text,
            rule_test_host: "example.com".into(),
            rule_test_port: "443".into(),
            rule_test_network: Network::Tcp,
            rule_test_generation: 0,
            rule_test_pending: false,
            rule_test_input: None,
            rule_test_result: None,
            connection_link_text: String::new(),
            node_exchange_text: String::new(),
            open_node_import: false,
            node_editor: None,
            node_filter: String::new(),
            status: None,
            status_error: None,
            last_traffic: None,
            upload_rate: 0.0,
            download_rate: 0.0,
            traffic_history: VecDeque::new(),
            connection_filter: String::new(),
            log_filter: String::new(),
            log_level: String::new(),
            probes,
            #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
            system_proxy_enabled: false,
            system_proxy_verified: false,
            tun_enabled: false,
            #[cfg(target_os = "linux")]
            linux_tun: None,
            #[cfg(target_os = "linux")]
            linux_tun_serial: 0,
            #[cfg(target_os = "linux")]
            linux_exit_after_tun: false,
            notice: None,
            child: None,
            daemon_profile: None,
            startup_checked: false,
            daemon_revision: 0,
            unexpected_restarts: 0,
            recovering_connection: false,
            applying_config: false,
            events,
            event_tx,
            last_poll: Instant::now() - Duration::from_secs(5),
            status_request_revision: None,
            log_entries: Vec::new(),
            log_error: None,
            last_log_refresh: Instant::now() - Duration::from_secs(5),
            exit_requested: false,
            #[cfg(any(windows, target_os = "macos"))]
            _tray: None,
            #[cfg(target_os = "linux")]
            linux_tray: None,
        }
    }

    fn poll_events(&mut self, ctx: &egui::Context) {
        #[cfg(not(target_os = "linux"))]
        {
            self.tun_enabled = tun_is_running();
        }
        while let Ok(event) = self.events.try_recv() {
            if let Event::Status(revision, _) = &event
                && self.status_request_revision == Some(*revision)
            {
                self.status_request_revision = None;
            }
            match event {
                Event::RouteTest(generation, result) => {
                    if generation == self.rule_test_generation {
                        self.rule_test_pending = false;
                        self.rule_test_result = Some(result);
                    }
                }
                #[cfg(target_os = "linux")]
                Event::LinuxTunPrepared(id, result) => {
                    if self
                        .linux_tun
                        .as_ref()
                        .is_none_or(|session| session.id != id)
                    {
                        continue;
                    }
                    if self
                        .linux_tun
                        .as_ref()
                        .is_some_and(|session| session.stopping)
                    {
                        self.linux_tun = None;
                        continue;
                    }
                    match result {
                        Ok(outbound) => self.start_linux_tun_daemon(id, outbound),
                        Err(error) => {
                            self.linux_tun = None;
                            self.notice = Some((error, false));
                        }
                    }
                }
                #[cfg(target_os = "linux")]
                Event::LinuxTunPipe(id, input) => {
                    if let Some(session) = &mut self.linux_tun
                        && session.id == id
                        && !session.stopping
                    {
                        session.input = Some(input);
                    }
                }
                #[cfg(target_os = "linux")]
                Event::LinuxTunReady(id) => {
                    if self
                        .linux_tun
                        .as_ref()
                        .is_some_and(|session| session.id == id && !session.stopping)
                    {
                        self.tun_enabled = true;
                        self.notice = Some((t("虚拟网卡已开启").into(), true));
                    }
                }
                #[cfg(target_os = "linux")]
                Event::LinuxTunEnded(id, result) => {
                    if self
                        .linux_tun
                        .as_ref()
                        .is_none_or(|session| session.id != id)
                    {
                        continue;
                    }
                    self.linux_tun = None;
                    self.tun_enabled = false;
                    self.profile.tun_outbound = None;
                    // Rebuild the normal daemon config after the helper has finished recovery.
                    self.stop_daemon();
                    let saved = save_profile(&self.profile_path, &self.profile);
                    self.notice =
                        Some(match result.and(saved.map_err(|error| error.to_string())) {
                            Ok(()) => ("虚拟网卡已关闭，网络设置已恢复".into(), true),
                            Err(error) => (error, false),
                        });
                }
                #[cfg(target_os = "linux")]
                Event::LinuxTunRecovered(result) => {
                    self.notice = Some(match result {
                        Ok(()) => ("虚拟网卡路由与 DNS 已恢复，可重新开启".into(), true),
                        Err(error) => (error, false),
                    });
                }
                Event::ConfigApplied(revision, _, _) if revision != self.daemon_revision => {}
                Event::ConfigApplied(_, profile, result) => {
                    self.applying_config = false;
                    match result {
                        Ok(revision) => {
                            let saved = save_profile(&self.profile_path, &profile);
                            self.daemon_profile = Some(profile);
                            if let Some(status) = &mut self.status {
                                status.config_revision = revision;
                            }
                            self.notice = Some(match saved {
                                Ok(()) => (t("配置已应用").into(), true),
                                Err(error) => (format!("配置已生效，但保存失败：{error}"), false),
                            });
                        }
                        Err(error) => {
                            self.notice =
                                Some((format!("配置未生效，原节点继续运行：{error}"), false));
                        }
                    }
                    self.last_poll = Instant::now() - Duration::from_secs(5);
                }
                #[cfg(target_os = "linux")]
                Event::TrayReady(result) => match result {
                    Ok(tray) => self.linux_tray = Some(tray),
                    Err(error) => self.notice = Some((format!("系统托盘不可用：{error}"), false)),
                },
                #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
                Event::TrayAction(action) => self.handle_tray_action(action, ctx),
                Event::Status(revision, _) | Event::DaemonOffline(revision)
                    if revision != self.daemon_revision => {}
                Event::DaemonOffline(_) => {
                    self.handle_unexpected_daemon_exit();
                }
                Event::Status(_, Ok(status)) => {
                    if self
                        .status
                        .as_ref()
                        .is_some_and(|current| status.config_revision < current.config_revision)
                    {
                        continue;
                    }
                    if status.desktop_managed
                        && !self.applying_config
                        && self.daemon_profile.is_none()
                    {
                        if let Some(server) = status.active_server
                            && let Some(index) = self.profile.nodes.iter().position(|node| {
                                node.server.parse::<std::net::SocketAddr>().ok() == Some(server)
                            })
                        {
                            self.profile.active_node = index;
                        }
                        self.daemon_profile = Some(self.profile.clone());
                    }
                    self.system_proxy_enabled = status.system_proxy_enabled;
                    self.system_proxy_verified = status.system_proxy_verified;
                    if status.system_proxy_verified
                        || (self.tun_enabled && status.desktop_managed && node_ready(&status))
                    {
                        self.unexpected_restarts = 0;
                    }
                    if let Some(error) = &status.system_proxy_error {
                        self.notice = Some((error.clone(), false));
                    }
                    let now = Instant::now();
                    if let Some((previous_at, uploaded, downloaded)) = self.last_traffic {
                        if status.uploaded_bytes < uploaded || status.downloaded_bytes < downloaded
                        {
                            self.traffic_history.clear();
                        }
                        (self.upload_rate, self.download_rate) = traffic_rates(
                            uploaded,
                            downloaded,
                            status.uploaded_bytes,
                            status.downloaded_bytes,
                            now.duration_since(previous_at),
                        );
                    }
                    self.traffic_history
                        .push_back((self.upload_rate, self.download_rate));
                    if self.traffic_history.len() > 60 {
                        self.traffic_history.pop_front();
                    }
                    self.last_traffic = Some((now, status.uploaded_bytes, status.downloaded_bytes));
                    self.status = Some(status);
                    self.status_error = None;
                    #[cfg(target_os = "macos")]
                    self.update_tray_traffic();
                    if self.connecting_since.is_some()
                        && self.status.as_ref().is_some_and(node_ready)
                    {
                        self.set_system_proxy(true);
                    }
                }
                Event::Status(_, Err(error)) => {
                    self.status = None;
                    self.system_proxy_verified = false;
                    self.status_error = Some(error);
                    self.upload_rate = 0.0;
                    self.download_rate = 0.0;
                    self.last_traffic = None;
                    #[cfg(target_os = "macos")]
                    self.update_tray_traffic();
                }
                Event::Startup(Ok(DaemonPresence::Offline)) => {
                    self.startup_checked = true;
                    if let Err(error) = recover_system_proxy() {
                        self.notice = Some((error.to_string(), false));
                        continue;
                    }
                    if self.profile.auto_start_daemon {
                        self.start_daemon();
                    }
                }
                Event::Startup(Ok(DaemonPresence::Authenticated)) => {
                    self.startup_checked = true;
                }
                Event::Startup(Ok(DaemonPresence::Occupied)) => {
                    self.startup_checked = true;
                    self.notice = Some((t("控制端口被占用，且身份校验未通过").into(), false));
                }
                Event::Startup(Err(error)) => {
                    self.startup_checked = true;
                    self.notice = Some((format!("后台启动检查失败：{error}"), false));
                }
                Event::Probe(index, Ok(report)) => {
                    let available = report.quic.is_ok() || report.tls.is_ok();
                    if let Some(probe) = self.probes.get_mut(index) {
                        *probe = ProbeState::Succeeded(report);
                    }
                    self.notice = Some((
                        t(if available {
                            "节点测试成功"
                        } else {
                            "测试失败"
                        })
                        .into(),
                        available,
                    ));
                }
                Event::Probe(index, Err(error)) => {
                    if let Some(probe) = self.probes.get_mut(index) {
                        *probe = ProbeState::Failed(error.clone());
                    }
                    self.notice = Some((format!("节点测试失败：{error}"), false));
                }
                Event::RulesUpdated(Ok(())) => {
                    self.notice = Some((t("分流规则已保存并生效").into(), true));
                }
                Event::RulesUpdated(Err(error)) => {
                    self.notice = Some((format!("规则已保存，但应用失败：{error}"), false));
                }
                Event::FlowClosed(result) => {
                    self.notice = Some(match result {
                        Ok(()) => (t("已请求关闭连接").into(), true),
                        Err(error) => (format!("关闭连接失败：{error}"), false),
                    });
                    self.last_poll = Instant::now() - Duration::from_secs(5);
                }
                Event::DnsPruned(result) => {
                    self.notice = Some(match result {
                        Ok(()) => (
                            t("已清理真实 DNS 缓存及过期映射，保留有效 Fake-IP 映射").into(),
                            true,
                        ),
                        Err(error) => (format!("DNS 清理失败：{error}"), false),
                    });
                    self.last_poll = Instant::now() - Duration::from_secs(5);
                }
            }
        }
    }

    fn request_status(&mut self) {
        if self.last_poll.elapsed() < Duration::from_secs(1)
            || self.status_request_revision == Some(self.daemon_revision)
        {
            return;
        }
        self.last_poll = Instant::now();
        if !self.recovering_connection
            && self
                .connecting_since
                .is_some_and(|since| since.elapsed() > Duration::from_secs(20))
        {
            self.connecting_since = None;
            self.notice = Some((
                t("连接超时，请检查节点地址、网络或在高级设置中查看日志").into(),
                false,
            ));
        }
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        if self.system_proxy_enabled && self.child.is_some() {
            match owned_daemon_running(&mut self.child) {
                Ok(false) => {
                    self.handle_unexpected_daemon_exit();
                }
                Ok(true) => {}
                Err(error) => {
                    self.notice = Some((format!("无法检查后台进程：{error}"), false));
                }
            }
        }
        let Ok(address) = self.control_profile().control_listen.parse() else {
            self.status_error = Some(t("控制地址无效").into());
            return;
        };
        let token_file = control_token_file();
        let control_socket = default_control_socket();
        let tx = self.event_tx.clone();
        let revision = self.daemon_revision;
        self.status_request_revision = Some(revision);
        thread::spawn(move || {
            let client = DaemonClient::new(address, control_socket, token_file);
            let result = run_async(async move {
                let result = client.status().await.map_err(|error| error.to_string());
                let offline = result.is_err()
                    && matches!(client.presence().await, Ok(DaemonPresence::Offline));
                Ok((result, offline))
            });
            match result {
                Ok((result, offline)) => {
                    let _ = tx.send(Event::Status(revision, result));
                    if offline {
                        let _ = tx.send(Event::DaemonOffline(revision));
                    }
                }
                Err(error) => {
                    let _ = tx.send(Event::Status(revision, Err(error.to_string())));
                }
            }
        });
    }

    fn request_startup_check(&mut self) {
        let Ok(address) = self.control_profile().control_listen.parse() else {
            self.notice = Some((t("控制地址无效").into(), false));
            return;
        };
        let token_file = control_token_file();
        let control_socket = default_control_socket();
        let tx = self.event_tx.clone();
        thread::spawn(move || {
            let client = DaemonClient::new(address, control_socket, token_file);
            let result = run_async(async move { Ok(client.presence().await?) })
                .map_err(|error| error.to_string());
            let _ = tx.send(Event::Startup(result));
        });
    }

    fn save(&mut self) {
        match self
            .prepare_profile()
            .and_then(|()| save_profile(&self.profile_path, &self.profile))
        {
            Ok(()) => self.notice = Some((t("配置已保存").into(), true)),
            Err(error) => self.notice = Some((error.to_string(), false)),
        }
    }

    fn add_connection_link(&mut self) {
        self.add_connection_link_at(&default_state_dir());
    }

    fn add_connection_link_at(&mut self, state_dir: &Path) {
        let node = match import_link(&self.connection_link_text, state_dir) {
            Ok(node) => node,
            Err(error) => {
                self.notice = Some((error, false));
                return;
            }
        };
        let mut profile = self.profile.clone();
        profile.nodes.push(node);
        match save_profile(&self.profile_path, &profile) {
            Ok(()) => {
                self.profile = profile;
                self.probes.push(ProbeState::Untested);
                self.connection_link_text.clear();
                self.node_editor = None;
                self.notice = Some((t("节点链接已导入；选择“切换”后使用").into(), true));
            }
            Err(error) => self.notice = Some((error.to_string(), false)),
        }
    }

    fn prepare_profile(&mut self) -> Result<(), AnyError> {
        if self.profile.mode == RoutingMode::Rule {
            self.profile.rules = parse_rules(&self.rule_text)?;
        }
        self.profile.proxy_bypass = parse_proxy_bypass(&self.proxy_bypass_text)?;
        self.profile.daemon_config()?;
        Ok(())
    }

    fn save_rules(&mut self) {
        self.save();
        if self.notice.as_ref().is_some_and(|(_, success)| !success) || self.status.is_none() {
            return;
        }
        let Ok(address) = self.control_profile().control_listen.parse() else {
            return;
        };
        let token_file = control_token_file();
        let control_socket = default_control_socket();
        let rules = self.profile.effective_rules();
        let tx = self.event_tx.clone();
        thread::spawn(move || {
            let client = DaemonClient::new(address, control_socket, token_file);
            let result = run_async(async move { Ok(client.update_rules(rules).await?) })
                .map_err(|error| error.to_string());
            let _ = tx.send(Event::RulesUpdated(result));
        });
    }

    fn request_route_test(&mut self) {
        let prepared = (|| -> Result<_, String> {
            let rules = match self.profile.mode {
                RoutingMode::Rule => {
                    parse_rules(&self.rule_text).map_err(|error| error.to_string())?
                }
                RoutingMode::GlobalProxy => vec![helios_routing::RuleConfig::Final {
                    action: helios_routing::RouteAction::Proxy,
                }],
                RoutingMode::GlobalDirect => vec![helios_routing::RuleConfig::Final {
                    action: helios_routing::RouteAction::Direct,
                }],
            };
            let host = self.rule_test_host.trim().trim_matches(['[', ']']);
            let address = host
                .parse()
                .map(helios_protocol::Address::Ip)
                .unwrap_or_else(|_| helios_protocol::Address::Domain(host.into()));
            let port = self
                .rule_test_port
                .parse::<u16>()
                .map_err(|_| "端口无效".to_string())?;
            let target =
                helios_protocol::Target::new(address, port).map_err(|error| error.to_string())?;
            let address = self
                .control_profile()
                .control_listen
                .parse()
                .map_err(|_| "控制地址无效".to_string())?;
            Ok((rules, target, address))
        })();
        let (rules, target, address) = match prepared {
            Ok(value) => value,
            Err(error) => {
                self.rule_test_result = Some(Err(error));
                return;
            }
        };
        self.rule_test_pending = true;
        self.rule_test_result = None;
        let generation = self.rule_test_generation;
        let network = self.rule_test_network;
        let tx = self.event_tx.clone();
        thread::spawn(move || {
            let client = DaemonClient::new(address, default_control_socket(), control_token_file());
            let result =
                run_async(async move { Ok(client.test_route(rules, target, network).await?) })
                    .map_err(|error| error.to_string());
            let _ = tx.send(Event::RouteTest(generation, result));
        });
    }

    fn start_daemon(&mut self) {
        if !self.startup_checked {
            self.notice = Some((t("正在检查后台，请稍候").into(), true));
            return;
        }
        if self.owns_running_daemon() {
            return;
        }
        self.save();
        if self.notice.as_ref().is_some_and(|(_, success)| !success) {
            return;
        }
        self.spawn_daemon(t("后台已启动"));
        self.unexpected_restarts = 0;
    }

    fn handle_unexpected_daemon_exit(&mut self) {
        if self.daemon_profile.is_none() || self.owns_running_daemon() {
            return;
        }
        if let Err(error) = recover_system_proxy() {
            self.notice = Some((error.to_string(), false));
            return;
        }
        let was_system_proxy_enabled = self.system_proxy_enabled || self.recovering_connection;
        #[cfg(target_os = "linux")]
        if self.linux_tun.is_some() {
            self.stop_tun();
        }
        let reconnect = (was_system_proxy_enabled || self.tun_enabled)
            && !self.tun_transition_pending()
            && self.unexpected_restarts < 3;
        self.daemon_profile = None;
        self.status = None;
        self.system_proxy_enabled = false;
        self.system_proxy_verified = false;
        self.connecting_since = None;
        self.recovering_connection = false;
        self.notice = Some((t("后台已退出，系统代理已恢复").into(), false));
        if reconnect {
            self.unexpected_restarts += 1;
            self.spawn_daemon(t("后台已启动"));
            if self.child.is_some() && was_system_proxy_enabled {
                self.connecting_since = Some(Instant::now());
                self.recovering_connection = true;
            }
        }
    }

    fn toggle_connection(&mut self) {
        if self.tun_enabled || self.tun_transition_pending() {
            self.stop_daemon();
            return;
        }
        if !self.startup_checked {
            self.notice = Some((t("正在检查后台，请稍候").into(), true));
            return;
        }
        if self.system_proxy_enabled || self.connecting_since.is_some() {
            self.recovering_connection = false;
            self.connecting_since = None;
            self.stop_daemon();
            return;
        }
        if !self.owns_running_daemon() {
            if self.status.is_some() {
                self.notice = Some((
                    t("请先从托盘退出另一个 Helios 窗口，再点击连接").into(),
                    false,
                ));
                return;
            }
            self.start_daemon();
        }
        if self.owns_running_daemon() {
            self.connecting_since = Some(Instant::now());
            self.notice = None;
            self.last_poll = Instant::now() - Duration::from_secs(5);
        }
    }

    fn restart_daemon(&mut self) {
        if self.applying_config || self.tun_transition_pending() {
            return;
        }
        if !self.owns_running_daemon() {
            self.notice = Some((
                t("无法重启其他窗口启动的后台，请先退出另一个 Helios").into(),
                false,
            ));
            return;
        }
        if let Err(error) = self.prepare_profile() {
            self.notice = Some((error.to_string(), false));
            return;
        }
        let config = match self.profile.daemon_config() {
            Ok(config) => config,
            Err(error) => {
                self.notice = Some((error.to_string(), false));
                return;
            }
        };
        let previous = self
            .daemon_profile
            .as_ref()
            .and_then(|profile| profile.daemon_config().ok());
        if previous.as_ref().is_some_and(|old| {
            old.listen == config.listen
                && old.http_listen == config.http_listen
                && old.control_listen == config.control_listen
                && old.dns == config.dns
                && old.timeouts == config.timeouts
        }) {
            let Some(status) = &self.status else {
                self.notice = Some((t("正在检查后台，请稍候").into(), false));
                return;
            };
            if self.tun_enabled {
                self.notice = Some((t("请先关闭虚拟网卡").into(), false));
                return;
            }
            let Ok(address) = self.control_profile().control_listen.parse() else {
                return;
            };
            let expected_revision = status.config_revision;
            let generation = self.daemon_revision;
            let tx = self.event_tx.clone();
            let profile = self.profile.clone();
            self.applying_config = true;
            thread::spawn(move || {
                let client =
                    DaemonClient::new(address, default_control_socket(), control_token_file());
                let result =
                    run_async(
                        async move { Ok(client.apply_config(expected_revision, config).await?) },
                    )
                    .map_err(|error| error.to_string());
                let _ = tx.send(Event::ConfigApplied(generation, profile, result));
            });
            return;
        }
        self.save();
        if self.notice.as_ref().is_some_and(|(_, success)| !success) {
            return;
        }
        let reconnect = self.system_proxy_enabled || self.connecting_since.is_some();
        self.stop_daemon();
        if self.child.is_some()
            || self.daemon_profile.is_some()
            || self.notice.as_ref().is_some_and(|(_, success)| !success)
        {
            return;
        }
        self.spawn_daemon(t("配置已应用"));
        if reconnect && self.child.is_some() {
            self.connecting_since = Some(Instant::now());
        }
    }

    fn spawn_daemon(&mut self, success: &str) {
        let log = match open_daemon_log() {
            Ok(log) => log,
            Err(error) => {
                self.notice = Some((format!("无法打开日志：{error}"), false));
                return;
            }
        };
        #[cfg(target_os = "linux")]
        let stdin = if self.profile.tun_outbound.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        };
        #[cfg(not(target_os = "linux"))]
        let stdin = Stdio::null();
        match Command::new(&self.profile.daemon_binary)
            .args(["desktop-managed", "--config"])
            .arg(&self.profile.daemon_config)
            .arg("--proxy-lease")
            .arg(default_state_dir().join("system-proxy-lease.json"))
            .stdin(stdin)
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
        {
            Ok(child) => {
                self.daemon_revision = self.daemon_revision.wrapping_add(1);
                self.last_traffic = None;
                self.traffic_history.clear();
                self.upload_rate = 0.0;
                self.download_rate = 0.0;
                self.child = Some(child);
                self.daemon_profile = Some(self.profile.clone());
                self.status = None;
                self.last_poll = Instant::now() - Duration::from_secs(5);
                self.notice = Some((success.into(), true));
            }
            Err(error) => self.notice = Some((format!("启动后台失败：{error}"), false)),
        }
    }

    fn stop_daemon(&mut self) {
        if self.applying_config {
            self.notice = Some((t("正在应用配置，请稍候").into(), false));
            return;
        }
        self.daemon_revision = self.daemon_revision.wrapping_add(1);
        self.connecting_since = None;
        self.recovering_connection = false;
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        if self.tun_enabled || self.tun_transition_pending() {
            self.stop_tun();
            self.notice = Some((t("正在关闭虚拟网卡，请等待关闭后再停止后台").into(), true));
            return;
        }
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        if self.system_proxy_enabled {
            self.set_system_proxy(false);
            if self.system_proxy_enabled {
                return;
            }
        }
        let Some(child) = self.child.take() else {
            if self
                .status
                .as_ref()
                .is_some_and(|status| status.desktop_managed)
            {
                let profile = self.control_profile().clone();
                self.notice = Some(match stop_attached_daemon(&profile) {
                    Ok(()) => {
                        self.status = None;
                        self.daemon_profile = None;
                        (t("已断开连接").into(), true)
                    }
                    Err(error) => (format!("停止后台失败：{error}"), false),
                });
            } else {
                self.notice = Some((t("此后台不是当前窗口启动的").into(), false));
            }
            return;
        };
        match stop_owned_daemon(child, self.control_profile()) {
            Ok(graceful) => {
                self.status = None;
                self.daemon_profile = None;
                self.notice = Some((
                    if graceful {
                        t("已断开连接")
                    } else {
                        t("后台关闭超时，已停止")
                    }
                    .into(),
                    true,
                ));
            }
            Err((child, error)) => {
                self.child = Some(child);
                self.notice = Some((format!("停止后台失败：{error}"), false));
            }
        }
    }

    fn owns_running_daemon(&mut self) -> bool {
        if self.child.is_none() {
            return self
                .status
                .as_ref()
                .is_some_and(|status| status.desktop_managed);
        }
        match owned_daemon_running(&mut self.child) {
            Ok(running) => running,
            Err(error) => {
                self.notice = Some((format!("无法检查后台进程：{error}"), false));
                // An unknown process state must not allow another daemon to be started.
                true
            }
        }
    }

    fn control_profile(&self) -> &DesktopProfile {
        self.daemon_profile.as_ref().unwrap_or(&self.profile)
    }

    fn close_flow(&mut self, id: u64) {
        let profile = self.control_profile();
        let Ok(address) = profile.control_listen.parse() else {
            return;
        };
        let client = DaemonClient::new(address, default_control_socket(), control_token_file());
        let tx = self.event_tx.clone();
        thread::spawn(move || {
            let result = run_async(async move { Ok(client.close_flow(id).await?) })
                .map_err(|error| error.to_string());
            let _ = tx.send(Event::FlowClosed(result));
        });
    }

    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    fn set_system_proxy(&mut self, enabled: bool) {
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        if enabled && (self.tun_enabled || self.tun_transition_pending()) {
            self.stop_tun();
            self.notice = Some((t("正在关闭虚拟网卡，关闭后可启用系统代理").into(), true));
            return;
        }
        #[cfg(target_os = "linux")]
        if enabled && tun_needs_recovery() {
            linux_tun::recover(self.event_tx.clone());
            self.notice = Some(("正在恢复上次的虚拟网卡网络设置".into(), true));
            return;
        }
        #[cfg(any(windows, target_os = "macos"))]
        if enabled && tun_needs_recovery() {
            if let Err(error) = self.write_helper_config() {
                self.notice = Some((format!("虚拟网卡配置无效：{error}"), false));
                return;
            }
            let result = launch_helper_elevated(
                &self.profile.helper_binary,
                &self.profile.helper_config,
                true,
            );
            self.notice = Some(match result {
                Ok(()) => (t("正在恢复虚拟网卡路由，完成后可启用系统代理").into(), true),
                Err(error) => (format!("恢复虚拟网卡路由失败：{error}"), false),
            });
            return;
        }
        if enabled && !self.owns_running_daemon() {
            self.notice = Some((t("请先启动后台，再启用系统代理").into(), false));
            return;
        }
        let result = self
            .control_profile()
            .control_listen
            .parse()
            .map_err(AnyError::from)
            .and_then(|address| {
                let client =
                    DaemonClient::new(address, default_control_socket(), control_token_file());
                run_async(async move { Ok(client.set_system_proxy(enabled).await?) })
            });
        match result {
            Ok(enabled) => {
                self.connecting_since = None;
                self.recovering_connection = false;
                self.system_proxy_enabled = enabled;
                self.system_proxy_verified = enabled;
                self.notice = Some((
                    if enabled {
                        t("系统代理已开启")
                    } else {
                        t("系统代理已恢复")
                    }
                    .into(),
                    true,
                ));
            }
            Err(error) => self.notice = Some((error.to_string(), false)),
        }
    }

    fn tun_transition_pending(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.linux_tun.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    #[cfg(target_os = "linux")]
    fn start_tun(&mut self) {
        if self.linux_tun.is_some() || !self.startup_checked {
            return;
        }
        if tun_needs_recovery() {
            self.notice = Some(("正在请求授权并恢复上次的网络设置".into(), true));
            linux_tun::recover(self.event_tx.clone());
            return;
        }
        if self.system_proxy_enabled {
            self.set_system_proxy(false);
            if self.system_proxy_enabled {
                return;
            }
        }
        if let Err(error) = self.prepare_profile() {
            self.notice = Some((error.to_string(), false));
            return;
        }
        self.connecting_since = None;
        self.linux_tun_serial = self.linux_tun_serial.wrapping_add(1);
        let id = self.linux_tun_serial;
        self.linux_tun = Some(linux_tun::Session::new(id));
        self.notice = Some(("正在检查 Linux TUN 出口和 DNS".into(), true));
        linux_tun::prepare(id, self.profile.tun_ipv6_enabled, self.event_tx.clone());
    }

    #[cfg(target_os = "linux")]
    fn start_linux_tun_daemon(&mut self, id: u64, outbound: helios_config::OutboundConfig) {
        let mut profile = self.profile.clone();
        profile.tun_outbound = Some(outbound);
        if let Err(error) = profile.daemon_config() {
            self.linux_tun = None;
            self.notice = Some((error.to_string(), false));
            return;
        }
        // Temporarily take the session so stop_daemon can stop the old, unbound daemon.
        let session = self.linux_tun.take();
        self.stop_daemon();
        if self.child.is_some() || self.daemon_profile.is_some() {
            self.notice = Some(("无法停止旧后台，虚拟网卡尚未启动".into(), false));
            return;
        }
        self.profile = profile;
        if let Err(error) = save_profile(&self.profile_path, &self.profile) {
            self.profile.tun_outbound = None;
            self.notice = Some((error.to_string(), false));
            return;
        }
        self.spawn_daemon("正在启动绑定出口的后台");
        if self.child.is_none() {
            self.profile.tun_outbound = None;
            return;
        }
        let session = session.expect("TUN preparation has a live session");
        let cancel = session.cancel.clone();
        self.linux_tun = Some(session);
        self.notice = Some(("请在系统提示中授权虚拟网卡，随后执行网络自检".into(), true));
        linux_tun::launch(id, self.profile.clone(), cancel, self.event_tx.clone());
    }

    #[cfg(target_os = "linux")]
    fn stop_tun(&mut self) {
        if let Some(session) = &mut self.linux_tun {
            session.stop();
            self.notice = Some((t("正在关闭虚拟网卡").into(), true));
        }
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn start_tun(&mut self) {
        if self.tun_enabled {
            return;
        }
        if !self.owns_running_daemon() {
            self.notice = Some((t("请先启动后台，再启用虚拟网卡").into(), false));
            return;
        }
        if self.system_proxy_enabled {
            self.set_system_proxy(false);
            if self.system_proxy_enabled {
                return;
            }
        }
        if let Err(error) = self.write_helper_config() {
            self.notice = Some((format!("虚拟网卡配置无效：{error}"), false));
            return;
        }
        if tun_needs_recovery() {
            let result = launch_helper_elevated(
                &self.profile.helper_binary,
                &self.profile.helper_config,
                true,
            );
            self.notice = Some(match result {
                Ok(()) => (t("正在恢复虚拟网卡，完成后可重新开启").into(), true),
                Err(error) => (format!("恢复虚拟网卡失败：{error}"), false),
            });
            return;
        }
        let result = launch_helper_elevated(
            &self.profile.helper_binary,
            &self.profile.helper_config,
            false,
        );
        self.notice = Some(match result {
            Ok(()) => (t("请在系统提示中授权虚拟网卡").into(), true),
            Err(error) => (format!("启动虚拟网卡失败：{error}"), false),
        });
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn write_helper_config(&self) -> Result<(), AnyError> {
        let config = self.profile.helper_config_toml()?;
        write_atomic(&self.profile.helper_config, config.as_bytes())?;
        Ok(())
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn stop_tun(&mut self) {
        let result = write_atomic(&tun_stop_file(), b"stop");
        self.notice = Some(match result {
            Ok(()) => (t("正在关闭虚拟网卡").into(), true),
            Err(error) => (format!("关闭虚拟网卡失败：{error}"), false),
        });
    }

    fn probe_node(&mut self, index: usize) {
        if matches!(self.probes.get(index), Some(ProbeState::Pending)) {
            return;
        }
        let Ok(node) = self.profile.nodes[index].config() else {
            self.notice = Some((t("节点配置有误，请先检查地址和凭据").into(), false));
            return;
        };
        self.probes[index] = ProbeState::Pending;
        let tx = self.event_tx.clone();
        thread::spawn(move || {
            let result = run_async(async move { Ok(probe_transports(node).await) })
                .map_err(|error| error.to_string());
            let _ = tx.send(Event::Probe(index, result));
        });
    }

    fn probe_all_nodes(&mut self) {
        for index in 0..self.profile.nodes.len() {
            self.probe_node(index);
        }
    }

    fn probes_pending(&self) -> bool {
        self.probes
            .iter()
            .any(|probe| matches!(probe, ProbeState::Pending))
    }

    fn select_node(&mut self, index: usize) {
        if self.applying_config {
            return;
        }
        if self.tun_enabled {
            self.notice = Some((t("请先关闭虚拟网卡").into(), false));
            return;
        }
        if index == self.profile.active_node {
            return;
        }
        self.profile.active_node = index;
        if self.owns_running_daemon() {
            self.restart_daemon();
        } else {
            self.save();
        }
    }

    fn content(&mut self, ui: &mut egui::Ui) {
        egui::Panel::left("navigation")
            .exact_size(190.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(SIDEBAR)
                    .inner_margin(Margin::symmetric(16, 26)),
            )
            .show(ui, |ui| self.navigation(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG))
            .show(ui, |ui| {
                self.topbar(ui);
                ui.separator();
                if let Some((message, success)) = &self.notice {
                    let mut dismiss = false;
                    egui::Frame::new()
                        .fill(if *success {
                            Color32::from_rgb(29, 49, 35)
                        } else {
                            Color32::from_rgb(55, 36, 29)
                        })
                        .corner_radius(CornerRadius::same(6))
                        .inner_margin(Margin::symmetric(14, 9))
                        .outer_margin(Margin::symmetric(30, 10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.add_sized(
                                    [ui.available_width() - 36.0, 0.0],
                                    egui::Label::new(RichText::new(i18n::message(message)).color(
                                        if *success {
                                            GOOD
                                        } else {
                                            Color32::from_rgb(239, 184, 139)
                                        },
                                    ))
                                    .wrap(),
                                );
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    dismiss =
                                        ui.small_button("×").on_hover_text(t("关闭提示")).clicked();
                                });
                            });
                        });
                    if dismiss {
                        self.notice = None;
                    }
                }
                egui::ScrollArea::vertical()
                    .id_salt(self.page as u8)
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        egui::Frame::new()
                            .inner_margin(Margin::symmetric(30, 26))
                            .show(ui, |ui| match self.page {
                                Page::Overview => self.overview(ui),
                                Page::Node => self.node(ui),
                                Page::Rules => self.rules(ui),
                                Page::Diagnostics => self.diagnostics(ui),
                                Page::Settings => self.settings(ui),
                            });
                    });
            });
        self.node_dialogs(ui.ctx());
    }
}

impl eframe::App for HeliosApp {
    // Hidden windows skip ui; status sampling and tray actions must keep ticking here.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        i18n::set_language(self.profile.language);
        self.poll_events(ctx);
        self.request_status();
        ctx.request_repaint_after(Duration::from_millis(250));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.page == Page::Diagnostics
            && self.diagnostic_tab == DiagnosticTab::Logs
            && self.last_log_refresh.elapsed() >= Duration::from_secs(2)
        {
            self.refresh_logs();
        }
        if ui.ctx().input(|input| input.viewport().close_requested()) && !self.exit_requested {
            #[cfg(any(windows, target_os = "macos"))]
            if self._tray.is_some() {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Visible(false));
                self.notice = Some((t("Helios 已最小化到托盘").into(), true));
            }
            #[cfg(target_os = "linux")]
            if self
                .linux_tray
                .as_ref()
                .is_some_and(|tray| tray.is_available())
            {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Visible(false));
                self.notice = Some((t("Helios 已最小化到托盘").into(), true));
            }
        }
        #[cfg(target_os = "linux")]
        {
            let has_tray = self
                .linux_tray
                .as_ref()
                .is_some_and(|tray| tray.is_available());
            if ui.ctx().input(|input| input.viewport().close_requested())
                && !has_tray
                && self.linux_tun.is_some()
            {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.linux_exit_after_tun = true;
                self.stop_tun();
            }
            if self.linux_exit_after_tun && self.linux_tun.is_none() && !tun_status_file().exists()
            {
                self.stop_daemon();
                if self.child.is_none() && self.daemon_profile.is_none() {
                    self.exit_requested = true;
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
        self.content(ui);
    }
}

impl HeliosApp {
    #[cfg(target_os = "macos")]
    fn update_tray_traffic(&self) {
        if let Some(tray) = &self._tray {
            let proxy = self.system_proxy_enabled && self.system_proxy_verified;
            let connected =
                tray_connection_active(proxy, self.tun_enabled, self.connecting_since.is_some());
            tray_display::update(tray, connected, self.upload_rate, self.download_rate);
            let (label, _) = connection_label(
                self.status.as_ref(),
                proxy || self.tun_enabled,
                self.connecting_since.is_some(),
            );
            let _ = tray.set_tooltip(Some(format!("{} · {label}", t("Helios · 曜光"))));
        }
    }

    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    fn handle_tray_action(&mut self, action: TrayAction, ctx: &egui::Context) {
        match action {
            TrayAction::Show => {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                #[cfg(target_os = "macos")]
                if let Some(mtm) = objc2::MainThreadMarker::new() {
                    let app = objc2_app_kit::NSApplication::sharedApplication(mtm);
                    app.unhide(None);
                    #[allow(deprecated)]
                    app.activateIgnoringOtherApps(true);
                }
                ctx.request_repaint();
            }
            TrayAction::ToggleDaemon => self.toggle_connection(),
            TrayAction::Quit => {
                #[cfg(target_os = "linux")]
                if self.linux_tun.is_some() {
                    self.linux_exit_after_tun = true;
                    self.stop_tun();
                    return;
                }
                if self.owns_running_daemon() {
                    self.stop_daemon();
                    if self.child.is_some() || self.daemon_profile.is_some() {
                        return;
                    }
                } else if self.system_proxy_enabled {
                    self.set_system_proxy(false);
                    if self.system_proxy_enabled {
                        return;
                    }
                }
                self.exit_requested = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn navigation(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            icon(ui, Icon::Sun, 29.0, ACCENT);
            ui.vertical(|ui| {
                ui.label(RichText::new("helios").size(22.0).strong().color(TEXT));
                ui.label(RichText::new(t("曜光 · 自由连接")).size(9.0).color(MUTED));
            });
        });
        ui.add_space(34.0);
        nav_group_label(ui, t("工作空间"));
        if nav_button(ui, t("连接概览"), self.page == Page::Overview, Icon::Home) {
            self.page = Page::Overview;
        }
        if nav_button(ui, t("我的节点"), self.page == Page::Node, Icon::Nodes) {
            self.page = Page::Node;
        }
        ui.add_space(22.0);
        nav_group_label(ui, t("网络配置"));
        if nav_button(ui, t("分流规则"), self.page == Page::Rules, Icon::Rules) {
            self.page = Page::Rules;
        }
        ui.add_space(22.0);
        nav_group_label(ui, t("运行与诊断"));
        if nav_button(
            ui,
            t("诊断"),
            self.page == Page::Diagnostics,
            Icon::Activity,
        ) {
            self.page = Page::Diagnostics;
        }
        ui.add_space((ui.available_height() - 126.0).max(24.0));
        if nav_button(ui, t("设置"), self.page == Page::Settings, Icon::Settings) {
            self.page = Page::Settings;
        }
        ui.separator();
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            dot(ui, if self.status.is_some() { GOOD } else { MUTED });
            ui.label(
                RichText::new(if self.status.is_some() {
                    t("后台服务运行中")
                } else {
                    t("后台服务未运行")
                })
                .size(11.0)
                .color(MUTED),
            );
        });
        ui.label(
            RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                .size(10.0)
                .color(MUTED),
        );
    }

    fn topbar(&mut self, ui: &mut egui::Ui) {
        ui.allocate_ui_with_layout(
            Vec2::new(ui.available_width(), 58.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.add_space(28.0);
                ui.label(RichText::new(t("工作空间")).size(11.0).color(MUTED));
                ui.label(RichText::new("/").color(LINE));
                ui.label(RichText::new(page_label(self.page)).size(12.0).color(TEXT));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add_space(28.0);
                    let previous = self.profile.language;
                    ui.selectable_value(&mut self.profile.language, Language::English, "English");
                    ui.selectable_value(&mut self.profile.language, Language::Chinese, "中文");
                    if previous != self.profile.language {
                        i18n::set_language(self.profile.language);
                        #[cfg(target_os = "linux")]
                        if let Some(tray) = &self.linux_tray {
                            tray.refresh_menu();
                        }
                        #[cfg(any(windows, target_os = "macos"))]
                        {
                            self._tray = create_tray().ok();
                            #[cfg(target_os = "macos")]
                            self.update_tray_traffic();
                        }
                        if let Err(error) = save_profile(&self.profile_path, &self.profile) {
                            self.notice = Some((error.to_string(), false));
                        }
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Title(
                            t("Helios · 曜光").into(),
                        ));
                    }
                });
            },
        );
    }

    fn diagnostics(&mut self, ui: &mut egui::Ui) {
        ui.add_space(18.0);
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(
                &mut self.diagnostic_tab,
                DiagnosticTab::Connections,
                t("连接记录"),
            );
            ui.selectable_value(&mut self.diagnostic_tab, DiagnosticTab::Dns, "DNS");
            ui.selectable_value(&mut self.diagnostic_tab, DiagnosticTab::Logs, t("日志"));
        });
        ui.add_space(8.0);
        ui.separator();
        match self.diagnostic_tab {
            DiagnosticTab::Connections => self.connections(ui),
            DiagnosticTab::Dns => self.dns(ui),
            DiagnosticTab::Logs => self.logs(ui),
        }
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        let connected = self.system_proxy_enabled && self.system_proxy_verified;
        let pending = self.connecting_since.is_some();
        let (label, color) =
            connection_label(self.status.as_ref(), connected || self.tun_enabled, pending);
        let hero_width = ui.available_width();
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                Vec2::new((hero_width - 170.0).max(170.0), 154.0),
                Layout::top_down(Align::Min),
                |ui| {
                    ui.set_width((hero_width - 170.0).max(170.0));
                    ui.add_space(22.0);
                    ui.horizontal(|ui| {
                        dot(ui, color);
                        ui.label(
                            RichText::new(if pending {
                                "CONNECTING"
                            } else if connected || self.tun_enabled {
                                "CONNECTION ACTIVE"
                            } else {
                                "CONNECTION IDLE"
                            })
                            .size(10.0)
                            .color(MUTED),
                        );
                    });
                    ui.add_space(10.0);
                    ui.label(RichText::new(label).size(40.0).color(TEXT));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(if self.tun_enabled {
                            t("虚拟网卡已开启")
                        } else if connected {
                            t("系统代理已开启")
                        } else if pending {
                            t("正在连接节点")
                        } else {
                            t("系统代理未开启")
                        })
                        .size(12.0)
                        .color(MUTED),
                    );
                },
            );
            if power_control(ui, connected || self.tun_enabled, pending, label) {
                self.toggle_connection();
            }
        });

        let node = self.profile.active_node();
        let latency = self.status.as_ref().and_then(|s| match s.transport {
            helios_control::ActiveTransport::Quic => s.quic_rtt_micros,
            _ => s.tls_rtt_micros,
        });
        let node_name = node.name.clone();
        let node_server = node.server.clone();
        let family = if node_server.starts_with('[') {
            "IPv6"
        } else {
            "IPv4"
        };
        let mode_before = self.profile.mode;
        egui::Frame::new()
            .fill(PANEL_2)
            .stroke(Stroke::new(1.0, Color32::from_rgb(61, 81, 53)))
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::same(16))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    icon(ui, Icon::Globe, 29.0, ACCENT);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&node_name).strong().color(TEXT));
                            ui.label(
                                RichText::new(family)
                                    .size(9.0)
                                    .color(ACCENT)
                                    .background_color(Color32::from_rgb(38, 53, 29)),
                            );
                        });
                        ui.label(
                            RichText::new(&node_server)
                                .monospace()
                                .size(10.0)
                                .color(MUTED),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.button(t("切换节点 ›")).clicked() {
                            self.page = Page::Node;
                        }
                        ui.label(
                            RichText::new(format_rtt(latency))
                                .monospace()
                                .color(if latency.is_some() { GOOD } else { MUTED }),
                        );
                    });
                });
            });

        ui.add_space(22.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(t("流量路由")).size(11.0).strong().color(TEXT));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button(t("配置分流规则 ›")).clicked() {
                    self.page = Page::Rules;
                }
            });
        });
        egui::Frame::new()
            .fill(SIDEBAR)
            .stroke(Stroke::new(1.0, LINE))
            .corner_radius(CornerRadius::same(7))
            .inner_margin(Margin::same(3))
            .show(ui, |ui| {
                ui.columns(3, |columns| {
                    columns[0].selectable_value(
                        &mut self.profile.mode,
                        RoutingMode::Rule,
                        t("按规则分流"),
                    );
                    columns[1].selectable_value(
                        &mut self.profile.mode,
                        RoutingMode::GlobalProxy,
                        t("全部代理"),
                    );
                    columns[2].selectable_value(
                        &mut self.profile.mode,
                        RoutingMode::GlobalDirect,
                        t("全部直连"),
                    );
                });
            });
        if self.profile.mode != mode_before {
            self.save_rules();
        }
        ui.label(
            RichText::new(match self.profile.mode {
                RoutingMode::Rule => t("匹配直连规则的流量直连，其余流量经过代理。"),
                RoutingMode::GlobalProxy => t("所有流量都经过当前代理节点。"),
                RoutingMode::GlobalDirect => t("所有流量直接连接，不经过代理节点。"),
            })
            .size(10.0)
            .color(MUTED),
        );

        ui.add_space(15.0);
        let mut proxy = connected;
        let mut proxy_changed = false;
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        let mut tun_changed = false;
        egui::Frame::new()
            .stroke(Stroke::new(1.0, LINE))
            .inner_margin(Margin::symmetric(0, 12))
            .show(ui, |ui| {
                ui.columns(2, |columns| {
                    proxy_changed = takeover_item(
                        &mut columns[0],
                        Icon::Globe,
                        t("系统代理"),
                        t("浏览器与支持代理的应用"),
                        &mut proxy,
                        !pending,
                    );
                    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
                    {
                        let mut tun = self.tun_enabled || self.tun_transition_pending();
                        tun_changed = takeover_item(
                            &mut columns[1],
                            Icon::Adapter,
                            t("虚拟网卡 TUN"),
                            t("接管更多应用的流量"),
                            &mut tun,
                            true,
                        );
                    }
                    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
                    {
                        let mut tun = false;
                        takeover_item(
                            &mut columns[1],
                            Icon::Adapter,
                            t("虚拟网卡 TUN"),
                            t("Linux 暂未开放"),
                            &mut tun,
                            false,
                        );
                    }
                });
            });
        if proxy_changed {
            self.toggle_connection();
        }
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        if tun_changed {
            if self.tun_enabled || self.tun_transition_pending() {
                self.stop_tun();
            } else {
                self.start_tun();
            }
        }

        ui.add_space(22.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(t("流量趋势")).size(11.0).strong().color(TEXT));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new(t("最近 60 秒")).size(9.0).color(MUTED));
            });
        });
        ui.columns(3, |columns| {
            metric(
                &mut columns[0],
                t("下载速度"),
                &format!("{}/s", format_bytes(self.download_rate as u64)),
                ACCENT,
            );
            metric(
                &mut columns[1],
                t("上传速度"),
                &format!("{}/s", format_bytes(self.upload_rate as u64)),
                GOOD,
            );
            let (uploaded, downloaded) = self
                .status
                .as_ref()
                .map(|status| (status.uploaded_bytes, status.downloaded_bytes))
                .unwrap_or_default();
            columns[2].with_layout(Layout::right_to_left(Align::Min), |ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(format!("{} {}", t("累计下载"), format_bytes(downloaded)))
                            .size(10.0)
                            .color(MUTED),
                    );
                    ui.label(
                        RichText::new(format!("{} {}", t("累计上传"), format_bytes(uploaded)))
                            .size(10.0)
                            .color(MUTED),
                    );
                });
            });
        });
        traffic_chart(ui, &self.traffic_history);

        if self.profile.mode == RoutingMode::GlobalDirect && connected {
            ui.colored_label(WARN, t("当前为全部直连模式，网页不会经过代理"));
        }
        if pending {
            ui.horizontal(|ui| {
                ui.spinner();
                if ui.small_button(t("取消连接")).clicked() {
                    self.toggle_connection();
                }
            });
        }
    }

    fn node(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| heading(ui, t("我的节点"), t("一条链接，就能开始连接。")));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(primary_button(t("添加节点"))).clicked() {
                    self.open_node_import = true;
                }
            });
        });
        ui.add_space(24.0);
        ui.horizontal(|ui| {
            ui.add_sized(
                [(ui.available_width() - 110.0).max(80.0), 34.0],
                egui::TextEdit::singleline(&mut self.node_filter)
                    .hint_text(t("搜索节点名称或地址")),
            );
            if ui
                .add_enabled(!self.probes_pending(), secondary_button(t("测试全部")))
                .clicked()
            {
                self.probe_all_nodes();
            }
        });
        ui.add_space(8.0);
        let previous = self.profile.auto_failover;
        ui.checkbox(
            &mut self.profile.auto_failover,
            t("节点故障时自动切换备用节点"),
        );
        if previous != self.profile.auto_failover {
            if self.owns_running_daemon() {
                self.restart_daemon();
            } else {
                self.save();
            }
        }
        ui.add_space(14.0);
        let mut selected = None;
        let mut probe = None;
        let mut edit = None;
        let mut remove = None;
        let can_change =
            !self.applying_config && !self.tun_enabled && !self.tun_transition_pending();
        for (index, node) in self.profile.nodes.iter().enumerate() {
            if !matches_filter(&self.node_filter, &[&node.name, &node.server]) {
                continue;
            }
            let active = index == self.profile.active_node;
            egui::Frame::new()
                .fill(if active { PANEL_2 } else { BG })
                .stroke(Stroke::new(
                    1.0,
                    if active {
                        Color32::from_rgb(70, 90, 53)
                    } else {
                        LINE
                    },
                ))
                .corner_radius(CornerRadius::same(7))
                .inner_margin(Margin::same(14))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        icon(ui, Icon::Globe, 28.0, if active { ACCENT } else { MUTED });
                        ui.allocate_ui_with_layout(
                            Vec2::new((ui.available_width() - 236.0).max(70.0), 40.0),
                            Layout::top_down(Align::Min),
                            |ui| {
                                ui.set_width((ui.available_width()).max(70.0));
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&node.name).size(13.0).color(TEXT),
                                    )
                                    .truncate(),
                                );
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&node.server)
                                            .size(10.0)
                                            .monospace()
                                            .color(MUTED),
                                    )
                                    .truncate(),
                                );
                            },
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui
                                .add_enabled(
                                    can_change && !active,
                                    egui::Button::new(if active {
                                        t("当前节点")
                                    } else {
                                        t("切换")
                                    }),
                                )
                                .clicked()
                            {
                                selected = Some(index);
                            }
                            if ui.button(t("编辑")).clicked() {
                                edit = Some(index);
                            }
                            let pending = matches!(self.probes[index], ProbeState::Pending);
                            if ui
                                .add_enabled(
                                    !pending,
                                    egui::Button::new(if pending {
                                        t("测试中…")
                                    } else {
                                        t("测试延迟")
                                    }),
                                )
                                .clicked()
                            {
                                probe = Some(index);
                            }
                        });
                    });
                    let result = match &self.probes[index] {
                        ProbeState::Failed(_) => t("测试失败").to_owned(),
                        state => probe_state_label(state),
                    };
                    ui.horizontal_wrapped(|ui| {
                        dot(
                            ui,
                            match &self.probes[index] {
                                ProbeState::Succeeded(report)
                                    if report.quic.is_ok() || report.tls.is_ok() =>
                                {
                                    GOOD
                                }
                                ProbeState::Failed(_) => WARN,
                                _ => MUTED,
                            },
                        );
                        ui.label(RichText::new(result).size(10.0).color(MUTED))
                            .on_hover_text(probe_state_label(&self.probes[index]));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.add_enabled_ui(
                                !active && !self.probes_pending() && can_change,
                                |ui| {
                                    ui.menu_button(t("删除"), |ui| {
                                        ui.label(t("确认删除此节点？"));
                                        if ui.button(t("确认删除")).clicked() {
                                            remove = Some(index);
                                            ui.close();
                                        }
                                    });
                                },
                            )
                            .response
                            .on_hover_text(t("当前节点请先切换后再删除"));
                        });
                    });
                    if let ProbeState::Succeeded(report) = &self.probes[index] {
                        egui::CollapsingHeader::new(t("测试详情"))
                            .id_salt(("probe", index))
                            .show(ui, |ui| {
                                for (name, result) in [("QUIC", &report.quic), ("TLS", &report.tls)]
                                {
                                    match result {
                                        Ok(value) => {
                                            ui.label(format!(
                                                "{name} · RTT {:.1} ms · {} {:.1} ms",
                                                value.rtt.as_secs_f64() * 1000.,
                                                t("握手"),
                                                value.handshake.as_secs_f64() * 1000.
                                            ));
                                        }
                                        Err(error) => {
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(format!("{name}: {error}"))
                                                        .color(WARN),
                                                )
                                                .wrap(),
                                            );
                                        }
                                    }
                                }
                            });
                    }
                });
            ui.add_space(8.0);
        }
        if let Some(index) = probe {
            self.probe_node(index);
        }
        if let Some(index) = selected {
            self.select_node(index);
        }
        if let Some(index) = edit {
            self.node_editor = Some(NodeEditor {
                index: Some(index),
                node: self.profile.nodes[index].clone(),
                error: None,
            });
        }
        if let Some(index) = remove {
            let mut profile = self.profile.clone();
            profile.nodes.remove(index);
            if profile.active_node > index {
                profile.active_node -= 1;
            }
            match save_profile(&self.profile_path, &profile) {
                Ok(()) => {
                    self.profile = profile;
                    self.probes.remove(index);
                    self.notice = Some((t("配置已保存").into(), true));
                }
                Err(error) => self.notice = Some((error.to_string(), false)),
            }
        }
    }

    fn node_dialogs(&mut self, ctx: &egui::Context) {
        let width = (ctx.content_rect().width() - 90.0).min(480.0);
        if self.open_node_import {
            let mut import = false;
            let mut manual = false;
            let modal = egui::Modal::new(egui::Id::unique("helios-node-import")).show(ctx, |ui| {
                ui.set_width(width);
                heading(
                    ui,
                    t("添加节点"),
                    t("粘贴 helios:// 链接，证书和凭据会自动导入。"),
                );
                ui.add_space(18.0);
                ui.label(RichText::new(t("节点链接")).color(MUTED).size(11.0));
                ui.add_sized(
                    [width, 38.0],
                    egui::TextEdit::singleline(&mut self.connection_link_text)
                        .password(true)
                        .hint_text("helios://v1/..."),
                );
                let parsed = helios_config::ConnectionLink::decode(&self.connection_link_text);
                if !self.connection_link_text.trim().is_empty() {
                    ui.add_space(12.0);
                    match &parsed {
                        Ok(link) => {
                            card(ui, |ui| {
                                ui.label(RichText::new(&link.name).strong().color(ACCENT));
                                ui.label(
                                    RichText::new(link.server.to_string())
                                        .monospace()
                                        .color(MUTED),
                                );
                                ui.label(
                                    RichText::new(t("证书与凭据已包含在链接中"))
                                        .small()
                                        .color(MUTED),
                                );
                            });
                        }
                        Err(error) => {
                            ui.add(
                                egui::Label::new(RichText::new(error.to_string()).color(WARN))
                                    .wrap(),
                            );
                        }
                    }
                }
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    manual = ui.button(t("手动添加节点")).clicked();
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        import = ui
                            .add_enabled(
                                parsed.is_ok() && !self.probes_pending() && !self.applying_config,
                                primary_button(t("解析并添加")),
                            )
                            .clicked();
                        if ui.button(t("取消")).clicked() {
                            ui.close();
                        }
                    });
                });
            });
            if modal.should_close() {
                self.open_node_import = false;
            }
            if import {
                self.add_connection_link();
                if self.notice.as_ref().is_some_and(|notice| notice.1) {
                    self.open_node_import = false;
                }
            }
            if manual {
                self.open_node_import = false;
                self.node_editor = Some(NodeEditor {
                    index: None,
                    node: NodeProfile {
                        name: format!("{} {}", t("节点"), self.profile.nodes.len() + 1),
                        server: String::new(),
                        server_name: String::new(),
                        ..Default::default()
                    },
                    error: None,
                });
            }
        }
        if let Some(mut editor) = self.node_editor.take() {
            let mut save = false;
            let mut connect = false;
            let modal = egui::Modal::new(egui::Id::unique("helios-node-editor")).show(ctx, |ui| {
                ui.set_width(width);
                heading(ui, t("编辑节点配置"), t("先保存节点，需要时再连接。"));
                ui.add_space(16.0);
                egui::ScrollArea::vertical().max_height((ctx.content_rect().height()-210.0).max(240.0)).show(ui, |ui| {
                    field(ui, t("节点名称"), &mut editor.node.name);
                    field(ui, t("服务器地址"), &mut editor.node.server);
                    ui.label(RichText::new(t("IPv6 地址格式：[IPv6]:端口")).size(10.0).color(MUTED));
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(t("传输方式")).size(11.0).color(MUTED));
                        ui.selectable_value(&mut editor.node.preferred_transport, TransportPreference::Quic, "QUIC");
                        ui.selectable_value(&mut editor.node.preferred_transport, TransportPreference::Tls, "TLS");
                    });
                    egui::CollapsingHeader::new(t("证书与凭据")).default_open(editor.index.is_none()).show(ui, |ui| {
                        field(ui, t("证书对应域名 / IP"), &mut editor.node.server_name);
                        path_field(ui, t("受信证书文件"), &mut editor.node.ca_certificate);
                        field(ui, t("凭据标识"), &mut editor.node.credential_id);
                        path_field(ui, t("凭据文件"), &mut editor.node.token_file);
                        ui.add(egui::Label::new(RichText::new(t("填写本机 .pem 文件的完整路径，不是证书内容；证书对应域名 / IP 必须与证书匹配。")).small().color(MUTED)).wrap());
                    });
                    egui::CollapsingHeader::new(t("导入 / 导出")).show(ui, |ui| {
                        ui.label(RichText::new(t("不包含证书和凭据内容")).small().color(MUTED));
                        ui.add(egui::TextEdit::multiline(&mut self.node_exchange_text).font(egui::TextStyle::Monospace).desired_rows(5).desired_width(f32::INFINITY));
                        ui.horizontal(|ui| {
                            if ui.button(t("导出节点")).clicked() {
                                self.node_exchange_text = serde_json::to_string_pretty(&editor.node).unwrap_or_default();
                            }
                            if ui.button(t("导入节点")).clicked() {
                                match import_node(&self.node_exchange_text) {
                                    Ok(node) => { editor.node = node; editor.index = None; editor.error = None; }
                                    Err(error) => editor.error = Some(error),
                                }
                            }
                        });
                    });
                    if let Some(error) = &editor.error { ui.add(egui::Label::new(RichText::new(error).color(WARN)).wrap()); }
                });
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    if ui.button(t("取消")).clicked() { ui.close(); }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let idle = !self.probes_pending() && !self.applying_config;
                        connect = ui.add_enabled(idle && !self.tun_enabled && !self.tun_transition_pending(), primary_button(t("保存并连接"))).clicked();
                        save = ui.add_enabled(idle, secondary_button(t("仅保存"))).clicked();
                    });
                });
            });
            if save || connect {
                match self.save_node_draft(&editor, connect) {
                    Ok(()) => return,
                    Err(error) => editor.error = Some(error),
                }
            }
            if !modal.should_close() {
                self.node_editor = Some(editor);
            }
        }
    }

    fn save_node_draft(&mut self, editor: &NodeEditor, connect: bool) -> Result<(), String> {
        let node =
            import_node(&serde_json::to_string(&editor.node).map_err(|error| error.to_string())?)?;
        let mut candidate = self.profile.clone();
        let index = editor.index.unwrap_or(candidate.nodes.len());
        if index == candidate.nodes.len() {
            candidate.nodes.push(node);
        } else {
            candidate.nodes[index] = node;
        }
        let original = candidate.active_node;
        candidate.active_node = index;
        candidate
            .daemon_config()
            .map_err(|error| error.to_string())?;
        if !connect {
            candidate.active_node = original;
        }
        save_profile(&self.profile_path, &candidate).map_err(|error| error.to_string())?;
        self.profile = candidate;
        self.probes
            .resize(self.profile.nodes.len(), ProbeState::Untested);
        self.probes[index] = ProbeState::Untested;
        self.notice = Some((t("节点已保存，运行中的连接未更改").into(), true));
        if connect {
            if self.owns_running_daemon() {
                self.restart_daemon();
            } else {
                self.toggle_connection();
            }
        }
        Ok(())
    }

    fn rules(&mut self, ui: &mut egui::Ui) {
        heading(
            ui,
            t("分流规则"),
            t("每行一条规则，按顺序匹配，末尾需要最终规则。"),
        );
        ui.add_space(20.0);
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(t("代理模式")).size(10.0).color(MUTED));
                let previous = self.profile.mode;
                ui.selectable_value(&mut self.profile.mode, RoutingMode::Rule, t("按规则"));
                ui.selectable_value(
                    &mut self.profile.mode,
                    RoutingMode::GlobalProxy,
                    t("全部代理"),
                );
                ui.selectable_value(
                    &mut self.profile.mode,
                    RoutingMode::GlobalDirect,
                    t("全部直连"),
                );
                if self.profile.mode != previous {
                    self.save_rules();
                }
            });
        });
        ui.add_space(14.0);
        card(ui, |ui| {
            ui.label(RichText::new(t("规则")).size(10.0).color(MUTED));
            ui.add_enabled(
                self.profile.mode == RoutingMode::Rule,
                egui::TextEdit::multiline(&mut self.rule_text)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(14)
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        self.profile.mode == RoutingMode::Rule,
                        primary_button(t("保存并应用")),
                    )
                    .clicked()
                {
                    self.save_rules();
                }
                ui.label(
                    RichText::new("domain-suffix,example.cn,direct")
                        .color(MUTED)
                        .monospace(),
                );
            });
        });
        ui.add_space(14.0);
        card(ui, |ui| {
            ui.label(RichText::new(t("测试规则")).size(10.0).color(MUTED));
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(t("目标地址")).size(10.0).color(MUTED));
                ui.add(
                    egui::TextEdit::singleline(&mut self.rule_test_host)
                        .desired_width(200.0)
                        .hint_text(t("域名或 IP")),
                );
                ui.label(RichText::new(t("端口")).size(10.0).color(MUTED));
                ui.add(
                    egui::TextEdit::singleline(&mut self.rule_test_port)
                        .desired_width(80.0)
                        .hint_text("443"),
                );
                ui.selectable_value(&mut self.rule_test_network, Network::Tcp, "TCP");
                ui.selectable_value(&mut self.rule_test_network, Network::Udp, "UDP");
                let input = (
                    self.profile.mode,
                    self.rule_text.clone(),
                    self.rule_test_host.clone(),
                    self.rule_test_port.clone(),
                    self.rule_test_network,
                    self.daemon_revision,
                );
                if self.rule_test_input.as_ref() != Some(&input) {
                    self.rule_test_input = Some(input);
                    self.rule_test_generation += 1;
                    self.rule_test_pending = false;
                    self.rule_test_result = None;
                }
                if ui
                    .add_enabled(
                        !self.rule_test_pending && self.status.is_some(),
                        egui::Button::new(t("后台测试")),
                    )
                    .clicked()
                {
                    self.request_route_test();
                }
                if self.rule_test_pending {
                    ui.spinner();
                }
                match test_route_for_network(
                    self.profile.mode,
                    &self.rule_text,
                    &self.rule_test_host,
                    &self.rule_test_port,
                    self.rule_test_network,
                ) {
                    Ok(result) => {
                        ui.colored_label(
                            action_color(result.action),
                            RichText::new(action_name(result.action).to_uppercase()).strong(),
                        );
                        ui.label(RichText::new(result.rule).color(MUTED).monospace())
                    }
                    Err(error) if error.contains("runtime DNS") => ui.colored_label(
                        MUTED,
                        if self.rule_test_result.is_some() {
                            ""
                        } else {
                            t("需要启动后台并点击后台测试")
                        },
                    ),
                    Err(error) => ui.colored_label(BAD, error),
                };
            });
            if let Some(result) = &self.rule_test_result {
                match result {
                    Ok(report) => {
                        ui.colored_label(
                            action_color(report.action),
                            format!(
                                "{} · {}",
                                action_name(report.action).to_uppercase(),
                                report
                                    .rule_index
                                    .map(|index| format!("rule {}", index + 1))
                                    .unwrap_or_else(|| "implicit final".into())
                            ),
                        );
                        if !report.resolved_ips.is_empty() {
                            ui.label(format!("{}: {:?}", t("解析地址"), report.resolved_ips));
                        }
                        if !report.selected_ips.is_empty() {
                            ui.label(format!("{}: {:?}", t("规则匹配地址"), report.selected_ips));
                        }
                        if let Some(error) = &report.dns_error {
                            ui.colored_label(
                                WARN,
                                format!("{}: {error}", t("DNS 解析失败，已继续匹配后续规则")),
                            );
                        }
                    }
                    Err(error) => {
                        ui.colored_label(BAD, error);
                    }
                }
            }
        });
    }

    fn settings(&mut self, ui: &mut egui::Ui) {
        heading(ui, t("高级设置"), t("监听、路径与网络参数都可以直接编辑。"));
        ui.add_space(24.0);

        section_title(ui, t("常规"));
        let auto_start = self.profile.auto_start_daemon;
        setting_row(
            ui,
            t("打开软件时预启动后台"),
            t("缩短连接等待时间；系统代理仍需手动开启。"),
            |ui| {
                toggle_switch(
                    ui,
                    &mut self.profile.auto_start_daemon,
                    t("打开软件时预启动后台"),
                    true,
                );
            },
        );
        if auto_start != self.profile.auto_start_daemon {
            self.save();
        }
        setting_row(
            ui,
            t("界面语言"),
            t("可随时切换，设置会自动保存。"),
            |ui| {
                ui.label(match self.profile.language {
                    Language::Chinese => "简体中文",
                    Language::English => "English",
                });
            },
        );
        ui.add_space(24.0);

        section_title(ui, t("网络"));
        let ipv6_before = self.profile.tun_ipv6_enabled;
        setting_row(
            ui,
            t("TUN 接管 IPv6"),
            t("虚拟网卡开启时，同时接管 IPv6 流量。"),
            |ui| {
                toggle_switch(
                    ui,
                    &mut self.profile.tun_ipv6_enabled,
                    t("TUN 接管 IPv6"),
                    true,
                );
            },
        );
        if ipv6_before != self.profile.tun_ipv6_enabled {
            self.save();
        }
        ui.add_space(18.0);
        card(ui, |ui| {
            ui.label(RichText::new(t("本地监听")).size(13.0).strong().color(TEXT));
            ui.label(
                RichText::new(t("只允许本机回环地址；IPv6 使用 [::1]:端口。"))
                    .size(10.0)
                    .color(MUTED),
            );
            ui.add_space(14.0);
            ui.columns(2, |columns| {
                field(
                    &mut columns[0],
                    t("SOCKS5 监听地址"),
                    &mut self.profile.socks_listen,
                );
                field(
                    &mut columns[1],
                    t("HTTP 监听地址"),
                    &mut self.profile.http_listen,
                );
            });
            ui.add_space(8.0);
            field(ui, t("本地控制地址"), &mut self.profile.control_listen);
        });
        ui.add_space(12.0);

        egui::CollapsingHeader::new(t("后台与虚拟网卡程序"))
            .id_salt("service-paths")
            .show(ui, |ui| {
                card(ui, |ui| {
                    path_field(ui, t("后台程序路径"), &mut self.profile.daemon_binary);
                    path_field(ui, t("后台配置文件"), &mut self.profile.daemon_config);
                    #[cfg(not(target_os = "linux"))]
                    {
                        path_field(ui, t("虚拟网卡辅助程序"), &mut self.profile.helper_binary);
                        path_field(ui, t("虚拟网卡配置文件"), &mut self.profile.helper_config);
                    }
                    #[cfg(target_os = "linux")]
                    ui.label("Linux TUN：/usr/libexec/helios-helper（系统安装组件）");
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(t("运行日志")).size(10.0).color(MUTED));
                        ui.label(
                            RichText::new(daemon_log_path().display().to_string())
                                .monospace()
                                .color(TEXT),
                        );
                        if ui.button(t("打开目录")).clicked() {
                            match open_log_directory() {
                                Ok(()) => self.notice = Some((t("已打开日志目录").into(), true)),
                                Err(error) => {
                                    self.notice =
                                        Some((format!("打开日志目录失败：{error}"), false))
                                }
                            }
                        }
                    });
                });
            });
        ui.add_space(8.0);
        egui::CollapsingHeader::new(t("代理绕过与传输参数"))
            .id_salt("transport-settings")
            .show(ui, |ui| {
                card(ui, |ui| {
                    ui.label(
                        RichText::new(t("不使用系统代理的地址"))
                            .size(10.0)
                            .color(MUTED),
                    );
                    ui.add(
                        egui::TextEdit::multiline(&mut self.proxy_bypass_text)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(5)
                            .desired_width(f32::INFINITY),
                    );
                    ui.label(
                        RichText::new(t("每行一个域名、IP 或网段"))
                            .size(10.0)
                            .color(MUTED),
                    );
                    ui.columns(2, |columns| {
                        columns[0].add(
                            egui::Slider::new(&mut self.profile.udp_idle_seconds, 30..=300)
                                .text(t("UDP 空闲超时（秒）")),
                        );
                        columns[1].add(
                            egui::Slider::new(&mut self.profile.tun_mtu, 576..=1500)
                                .text("TUN MTU"),
                        );
                    });
                });
            });
        ui.add_space(8.0);
        egui::CollapsingHeader::new(t("平台控制"))
            .id_salt("platform-controls")
            .show(ui, |ui| {
                card(ui, |ui| {
                    self.system_proxy_control(ui);
                    self.tun_control(ui);
                });
            });
        ui.add_space(22.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(t("保存设置不会自动切换当前节点。"))
                    .size(10.0)
                    .color(MUTED),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(primary_button(t("保存设置"))).clicked() {
                    self.save();
                }
            });
        });
    }

    fn dns(&mut self, ui: &mut egui::Ui) {
        heading(ui, t("DNS 设置"), t("保留域名分流，避免本地解析污染。"));
        ui.add_space(20.0);
        card(ui, |ui| {
            ui.horizontal(|ui| {
                dot(
                    ui,
                    if self.profile.fake_ip_dns_enabled {
                        GOOD
                    } else {
                        MUTED
                    },
                );
                ui.label(RichText::new("Fake-IP DNS").strong().color(TEXT));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.toggle_value(&mut self.profile.fake_ip_dns_enabled, t("启用"));
                });
            });
            ui.add_space(12.0);
            field(ui, t("DNS 监听地址"), &mut self.profile.dns_listen);
            ui.add(
                egui::Slider::new(&mut self.profile.fake_ip_capacity, 1..=65_536)
                    .text(t("域名缓存数量")),
            );
            ui.add(
                egui::Slider::new(&mut self.profile.fake_ip_ttl_seconds, 30..=3600)
                    .text(t("缓存有效期（秒）")),
            );
            ui.add_space(8.0);
            ui.colored_label(WARN, t("应用内置的加密 DNS 可能绕过此设置"));
            if let Some(stats) = self
                .status
                .as_ref()
                .and_then(|status| status.dns_cache.as_ref())
            {
                ui.label(format!(
                    "{}: {} / {}",
                    t("有效映射"),
                    stats.entries,
                    stats.capacity
                ));
                ui.label(format!(
                    "{}: {} · {}: {} · {}: {}",
                    t("命中"),
                    stats.hits,
                    t("未命中"),
                    stats.misses,
                    t("已过期"),
                    stats.expired
                ));
            }
            if ui
                .add_enabled(self.status.is_some(), egui::Button::new(t("清理 DNS 缓存")))
                .clicked()
                && let Ok(address) = self.control_profile().control_listen.parse()
            {
                let tx = self.event_tx.clone();
                thread::spawn(move || {
                    let client =
                        DaemonClient::new(address, default_control_socket(), control_token_file());
                    let result = run_async(async move {
                        client.prune_dns_cache().await?;
                        Ok(())
                    })
                    .map_err(|error| error.to_string());
                    let _ = tx.send(Event::DnsPruned(result));
                });
            }
            ui.add_space(12.0);
            if ui.add(primary_button(t("保存 DNS 设置"))).clicked() {
                self.save();
                if self.notice.as_ref().is_some_and(|(_, success)| *success)
                    && self.owns_running_daemon()
                {
                    self.notice = Some((t("DNS 配置已保存，请应用配置生效").into(), true));
                }
            }
        });
    }

    fn refresh_logs(&mut self) {
        self.last_log_refresh = Instant::now();
        match read_daemon_log_tail(&daemon_log_path(), 128 * 1024, 200) {
            Ok(entries) => {
                self.log_entries = entries;
                self.log_error = None;
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                self.log_entries.clear();
                self.log_error = None;
            }
            Err(error) => self.log_error = Some(error.to_string()),
        }
    }

    fn connections(&mut self, ui: &mut egui::Ui) {
        heading(
            ui,
            t("当前连接"),
            "Current in-memory flows only · no connection history is stored",
        );
        ui.add_space(20.0);
        let Some(status) = &self.status else {
            ui.label(RichText::new(t("后台未运行")).color(MUTED));
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(format!(
                "{} ↑ {}   ↓ {}",
                t("本次后台累计"),
                format_bytes(status.uploaded_bytes),
                format_bytes(status.downloaded_bytes)
            ));
            ui.label(format!("{} {}", t("UDP 丢包"), status.udp_dropped_packets));
        });
        traffic_chart(ui, &self.traffic_history);
        ui.horizontal(|ui| {
            ui.label(t("筛选连接"));
            ui.text_edit_singleline(&mut self.connection_filter);
        });
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("{} {}", status.active_flows, t("个连接")))
                    .strong()
                    .color(ACCENT),
            );
            if status.active_flows as usize > status.active_flow_details.len() {
                ui.label(
                    RichText::new(t("仅显示前 256 个连接"))
                        .color(WARN)
                        .italics(),
                );
            }
        });
        ui.add_space(10.0);
        if status.active_flow_details.is_empty() {
            ui.label(RichText::new(t("暂无连接")).color(MUTED));
            return;
        }
        let mut close = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for flow in status.active_flow_details.iter().filter(|flow| {
                matches_filter(
                    &self.connection_filter,
                    &[&flow.target, &flow.inbound, &flow.decision, &flow.transport],
                )
            }) {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("#{:04}", flow.id))
                                .monospace()
                                .color(MUTED),
                        );
                        ui.label(RichText::new(&flow.inbound).strong().color(ACCENT));
                        ui.label(RichText::new(&flow.target).monospace().color(TEXT));
                        if ui.small_button(t("关闭连接")).clicked() {
                            close = Some(flow.id);
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "{} · {} · {}s",
                                flow.decision.to_uppercase(),
                                flow.transport.to_uppercase(),
                                flow.duration_seconds
                            ))
                            .size(10.0)
                            .color(MUTED),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!(
                                    "↓ {}   ↑ {}",
                                    format_bytes(flow.downloaded_bytes),
                                    format_bytes(flow.uploaded_bytes)
                                ))
                                .monospace()
                                .color(MUTED),
                            );
                        });
                    });
                });
                ui.add_space(6.0);
            }
        });
        if let Some(id) = close {
            self.close_flow(id);
        }
    }

    fn logs(&mut self, ui: &mut egui::Ui) {
        heading(
            ui,
            t("运行日志"),
            "Latest structured events from the local daemon",
        );
        ui.add_space(14.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(daemon_log_path().display().to_string())
                    .monospace()
                    .color(MUTED),
            );
            if ui.button(t("刷新")).clicked() {
                self.refresh_logs();
            }
            if ui.button(t("打开目录")).clicked() {
                self.notice = Some(match open_log_directory() {
                    Ok(()) => (t("已打开日志目录").into(), true),
                    Err(error) => (format!("打开日志目录失败：{error}"), false),
                });
            }
        });
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            egui::ComboBox::from_id_salt("log-level")
                .selected_text(if self.log_level.is_empty() {
                    t("全部级别")
                } else {
                    &self.log_level
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.log_level, String::new(), t("全部级别"));
                    for level in ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"] {
                        ui.selectable_value(&mut self.log_level, level.into(), level);
                    }
                });
            ui.label(t("筛选日志"));
            ui.text_edit_singleline(&mut self.log_filter);
            if ui.button(t("导出诊断")).clicked() {
                self.notice = Some(
                    match export_diagnostics(
                        self.status.as_ref(),
                        self.system_proxy_enabled && self.system_proxy_verified,
                        self.tun_enabled,
                    ) {
                        Ok(path) => (format!("{} {}", t("诊断已导出："), path.display()), true),
                        Err(error) => (format!("导出诊断失败：{error}"), false),
                    },
                );
            }
        });
        if let Some(error) = &self.log_error {
            ui.colored_label(BAD, error);
            return;
        }
        if self.log_entries.is_empty() {
            ui.label(RichText::new(t("暂无日志")).color(MUTED));
            return;
        }
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for entry in self.log_entries.iter().filter(|entry| {
                    (self.log_level.is_empty() || entry.level == self.log_level)
                        && matches_filter(&self.log_filter, &[&entry.event, &entry.timestamp])
                }) {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&entry.timestamp).monospace().color(MUTED));
                        ui.label(
                            RichText::new(&entry.level)
                                .monospace()
                                .strong()
                                .color(log_level_color(&entry.level)),
                        );
                        ui.label(RichText::new(&entry.event).monospace().color(TEXT));
                    });
                }
            });
    }

    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    fn system_proxy_control(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            dot(
                ui,
                if self.system_proxy_enabled && self.system_proxy_verified {
                    GOOD
                } else {
                    MUTED
                },
            );
            ui.label(RichText::new(t("系统代理")).strong().color(TEXT));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let mut enabled = self.system_proxy_enabled && self.system_proxy_verified;
                if ui.toggle_value(&mut enabled, t("开启系统代理")).changed() {
                    self.set_system_proxy(enabled);
                }
            });
        });
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    fn system_proxy_control(&mut self, ui: &mut egui::Ui) {
        capability(ui, t("系统代理"), false, t("此平台不支持"));
    }

    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    fn tun_control(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            dot(ui, if self.tun_enabled { GOOD } else { MUTED });
            ui.label(RichText::new(t("虚拟网卡")).strong().color(TEXT));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let mut enabled = self.tun_enabled || self.tun_transition_pending();
                if ui.toggle_value(&mut enabled, t("启用虚拟网卡")).changed() {
                    if enabled {
                        self.start_tun();
                    } else {
                        self.stop_tun();
                    }
                }
            });
        });
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    fn tun_control(&mut self, ui: &mut egui::Ui) {
        capability(ui, t("虚拟网卡"), false, t("Linux 暂未开放"));
    }
}

impl Drop for HeliosApp {
    fn drop(&mut self) {
        #[cfg(not(target_os = "linux"))]
        if self.exit_requested && self.tun_enabled {
            let _ = write_atomic(&tun_stop_file(), b"stop");
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn create_tray() -> Result<TrayIcon, AnyError> {
    let menu = Menu::new();
    menu.append(&MenuItem::with_id(TRAY_SHOW, t("显示 Helios"), true, None))?;
    menu.append(&MenuItem::with_id(
        TRAY_TOGGLE_DAEMON,
        t("连接 / 断开"),
        true,
        None,
    ))?;
    menu.append(&MenuItem::with_id(TRAY_QUIT, t("退出 Helios"), true, None))?;
    let (rgba, width, height) = tray_icon_rgba();
    let builder = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip(t("Helios · 曜光"))
        .with_icon(tray_icon::Icon::from_rgba(rgba, width, height)?);
    #[cfg(target_os = "macos")]
    let builder = builder.with_icon_as_template(true);
    let tray = builder.build()?;
    #[cfg(target_os = "macos")]
    tray_display::update(&tray, false, 0.0, 0.0);
    Ok(tray)
}

fn tray_icon_rgba() -> (Vec<u8>, u32, u32) {
    let icon = eframe::icon_data::from_png_bytes(TRAY_ICON)
        .expect("embedded tray icon must be a valid PNG");
    (icon.rgba, icon.width, icon.height)
}

#[cfg(windows)]
fn system_proxy_lease() -> SystemProxyLease<WindowsProxyAdapter> {
    SystemProxyLease::new(
        WindowsProxyAdapter,
        default_state_dir().join("system-proxy-lease.json"),
    )
}

#[cfg(target_os = "macos")]
fn system_proxy_lease() -> SystemProxyLease<MacosProxyAdapter> {
    SystemProxyLease::new(
        MacosProxyAdapter,
        default_state_dir().join("system-proxy-lease.json"),
    )
}

#[cfg(target_os = "linux")]
fn system_proxy_lease() -> SystemProxyLease<LinuxProxyAdapter> {
    SystemProxyLease::new(
        LinuxProxyAdapter,
        default_state_dir().join("system-proxy-lease.json"),
    )
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn recover_system_proxy() -> Result<(), AnyError> {
    let lock_path = default_state_dir().join("system-proxy-lease.lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    lock.try_lock()?;
    if matches!(
        system_proxy_lease().recover()?,
        ReleaseOutcome::Drifted { .. }
    ) {
        return Err(t("系统代理被其他程序修改，已保留你的设置").into());
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn recover_system_proxy() -> Result<(), AnyError> {
    Ok(())
}

fn stop_attached_daemon(profile: &DesktopProfile) -> Result<(), AnyError> {
    let client = DaemonClient::new(
        profile.control_listen.parse()?,
        default_control_socket(),
        control_token_file(),
    );
    run_async(async move {
        client.shutdown().await?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if client.presence().await? == DaemonPresence::Offline {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err("daemon shutdown timed out; process was not forcibly terminated".into())
    })
}

fn owned_daemon_running(child: &mut Option<Child>) -> std::io::Result<bool> {
    let Some(process) = child.as_mut() else {
        return Ok(false);
    };
    if process.try_wait()?.is_none() {
        return Ok(true);
    }
    *child = None;
    Ok(false)
}

fn stop_owned_daemon(
    mut child: Child,
    profile: &DesktopProfile,
) -> Result<bool, (Child, AnyError)> {
    let address = match profile.control_listen.parse::<std::net::SocketAddr>() {
        Ok(address) => address,
        Err(error) => return Err((child, error.into())),
    };
    let client = DaemonClient::new(address, default_control_socket(), control_token_file());
    let graceful = run_async(async move { Ok(client.shutdown().await?) }).is_ok();
    if graceful {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(true),
                Ok(None) => {}
                Err(error) => return Err((child, error.into())),
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    if let Err(error) = child.kill() {
        return Err((child, error.into()));
    }
    if let Err(error) = child.wait() {
        return Err((child, error.into()));
    }
    Ok(false)
}

fn run_async<T>(future: impl Future<Output = Result<T, AnyError>>) -> Result<T, AnyError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future)
}

fn control_token_file() -> PathBuf {
    default_state_dir().join("control-token.hex")
}

fn action_color(action: RouteAction) -> Color32 {
    match action {
        RouteAction::Proxy => ACCENT,
        RouteAction::Direct => GOOD,
        RouteAction::Reject => BAD,
    }
}

#[cfg(any(test, windows, target_os = "macos"))]
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AnyError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn daemon_log_path() -> PathBuf {
    default_state_dir().join("daemon.log")
}

fn read_daemon_log_tail(
    path: &Path,
    max_bytes: u64,
    max_entries: usize,
) -> Result<Vec<LogEntry>, AnyError> {
    let mut file = std::fs::File::open(path)?;
    let length = file.metadata()?.len();
    let start = length.saturating_sub(max_bytes);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    let lines = if start == 0 {
        text.as_ref()
    } else {
        text.split_once('\n').map_or("", |(_, tail)| tail)
    };
    let mut entries = lines
        .lines()
        .filter_map(parse_log_entry)
        .rev()
        .take(max_entries)
        .collect::<Vec<_>>();
    entries.reverse();
    Ok(entries)
}

fn parse_log_entry(line: &str) -> Option<LogEntry> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    Some(LogEntry {
        timestamp: value.get("timestamp")?.as_str()?.to_owned(),
        level: value.get("level")?.as_str()?.to_owned(),
        event: value.get("fields")?.get("event")?.as_str()?.to_owned(),
    })
}

fn log_level_color(level: &str) -> Color32 {
    match level {
        "ERROR" => BAD,
        "WARN" => WARN,
        "INFO" => GOOD,
        _ => MUTED,
    }
}

fn open_daemon_log() -> Result<std::fs::File, AnyError> {
    open_daemon_log_at(&daemon_log_path())
}

fn open_daemon_log_at(path: &Path) -> Result<std::fs::File, AnyError> {
    let parent = path.parent().ok_or("daemon log path has no parent")?;
    std::fs::create_dir_all(parent)?;
    if std::fs::metadata(path).is_ok_and(|metadata| metadata.len() >= 5 * 1024 * 1024) {
        let rotated = path.with_extension("log.1");
        let _ = std::fs::remove_file(&rotated);
        std::fs::rename(path, rotated)?;
    }
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn open_log_directory() -> Result<(), AnyError> {
    let path = daemon_log_path();
    let directory = path.parent().ok_or("daemon log path has no parent")?;
    std::fs::create_dir_all(directory)?;
    #[cfg(windows)]
    let status = Command::new("explorer").arg(directory).status()?;
    #[cfg(target_os = "macos")]
    let status = Command::new("open").arg(directory).status()?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = Command::new("xdg-open").arg(directory).status()?;
    if status.success() {
        Ok(())
    } else {
        Err("system file manager failed".into())
    }
}

fn tun_is_running() -> bool {
    #[cfg(target_os = "linux")]
    {
        false
    } // Only this window's verified readiness event establishes an active session.
    #[cfg(not(target_os = "linux"))]
    {
        status_is_fresh(&tun_status_file())
    }
}

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
fn tun_needs_recovery() -> bool {
    status_needs_recovery(&tun_status_file())
}

#[cfg(any(test, windows, target_os = "macos", target_os = "linux"))]
fn status_needs_recovery(path: &Path) -> bool {
    path.exists() && !status_is_fresh(path)
}

fn status_is_fresh(path: &Path) -> bool {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
        .is_ok_and(|age| age < Duration::from_secs(2))
}

#[cfg(windows)]
fn launch_helper_elevated(binary: &Path, config: &Path, recover: bool) -> Result<(), AnyError> {
    let mut command = Command::new("powershell.exe");
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Start-Process -FilePath $args[0] -ArgumentList @($args[1..($args.Length-1)]) -Verb RunAs",
    ]);
    command.arg(binary);
    if recover {
        command.arg("--recover");
    }
    let status = command.arg(config).status()?;
    if status.success() {
        Ok(())
    } else {
        Err("UAC launch was rejected".into())
    }
}

#[cfg(target_os = "macos")]
fn launch_helper_elevated(binary: &Path, config: &Path, recover: bool) -> Result<(), AnyError> {
    let script = r#"on run argv
set helperArgs to ""
repeat with i from 2 to count of argv
set helperArgs to helperArgs & " " & quoted form of item i of argv
end repeat
do shell script (quoted form of item 1 of argv & helperArgs & " >/dev/null 2>&1 &") with administrator privileges
end run"#;
    let mut command = Command::new("osascript");
    command.arg("-e").arg(script).arg(binary);
    if recover {
        command.arg("--recover");
    }
    let status = command.arg(config).status()?;
    if status.success() {
        Ok(())
    } else {
        Err("administrator authorization was rejected".into())
    }
}

fn configure_style(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    if let Some(font) = chinese_font() {
        let mut fonts = egui::FontDefinitions::default();
        fonts
            .font_data
            .insert("chinese".into(), std::sync::Arc::new(font));
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .push("chinese".into());
        }
        ctx.set_fonts(fonts);
    }
    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.visuals.dark_mode = true;
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.widgets.inactive.bg_fill = PANEL_2;
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    style.visuals.widgets.inactive.corner_radius = CornerRadius::same(6);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(37, 49, 38);
    style.visuals.widgets.hovered.corner_radius = CornerRadius::same(6);
    style.visuals.widgets.active.bg_fill = ACCENT;
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::BLACK);
    style.visuals.widgets.active.corner_radius = CornerRadius::same(6);
    style.visuals.selection.bg_fill = Color32::from_rgb(35, 48, 32);
    style.visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    style.visuals.window_corner_radius = CornerRadius::same(10);
    style.spacing.item_spacing = Vec2::new(9.0, 9.0);
    style.spacing.button_padding = Vec2::new(12.0, 8.0);
    style.spacing.scroll.floating = false;
    style
        .text_styles
        .insert(egui::TextStyle::Body, FontId::proportional(13.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, FontId::proportional(12.0));
    ctx.set_style_of(egui::Theme::Dark, style);
}

fn chinese_font() -> Option<egui::FontData> {
    [
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
    ]
    .into_iter()
    .map(PathBuf::from)
    .chain(std::env::var_os("WINDIR").map(|root| PathBuf::from(root).join("Fonts/msyh.ttc")))
    .find_map(|path| std::fs::read(path).ok().map(egui::FontData::from_owned))
}

fn node_ready(status: &StatusSnapshot) -> bool {
    matches!(
        status.state,
        ConnectionState::Connected | ConnectionState::Degraded
    )
}

fn connection_label(
    status: Option<&StatusSnapshot>,
    proxy: bool,
    pending: bool,
) -> (&'static str, Color32) {
    if pending {
        (t("连接中"), WARN)
    } else if proxy && status.is_some_and(node_ready) {
        (t("已连接"), GOOD)
    } else if proxy {
        (t("节点暂不可用"), BAD)
    } else {
        (t("未连接"), MUTED)
    }
}

#[cfg(any(test, target_os = "macos"))]
fn tray_connection_active(proxy: bool, tun: bool, connecting: bool) -> bool {
    (proxy || tun) && !connecting
}

fn page_label(page: Page) -> &'static str {
    match page {
        Page::Overview => t("连接"),
        Page::Node => t("节点"),
        Page::Rules => t("分流规则"),
        Page::Diagnostics => t("诊断"),
        Page::Settings => t("设置"),
    }
}

fn nav_group_label(ui: &mut egui::Ui, label: &str) {
    ui.label(
        RichText::new(label)
            .size(9.0)
            .color(Color32::from_rgb(117, 135, 121)),
    );
    ui.add_space(5.0);
}

#[derive(Clone, Copy)]
enum Icon {
    Sun,
    Home,
    Nodes,
    Rules,
    Activity,
    Settings,
    Globe,
    Adapter,
}

fn icon(ui: &mut egui::Ui, symbol: Icon, size: f32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    paint_icon(ui.painter(), rect, symbol, color);
}

fn paint_icon(painter: &egui::Painter, rect: egui::Rect, symbol: Icon, color: Color32) {
    let p = |x: f32, y: f32| rect.min + egui::vec2(x, y) * (rect.width() / 24.0);
    let stroke = Stroke::new(1.4, color);
    let line = |points: &[(f32, f32)]| {
        painter.add(egui::Shape::line(
            points.iter().map(|&(x, y)| p(x, y)).collect(),
            stroke,
        ));
    };
    match symbol {
        Icon::Sun => {
            painter.circle_filled(p(12.0, 12.0), rect.width() * 0.18, color);
            for n in 0..8 {
                let direction = Vec2::angled(n as f32 * std::f32::consts::TAU / 8.0);
                painter.line_segment(
                    [
                        rect.center() + direction * rect.width() * 0.32,
                        rect.center() + direction * rect.width() * 0.47,
                    ],
                    stroke,
                );
            }
        }
        Icon::Home => {
            line(&[
                (3., 10.),
                (12., 3.),
                (21., 10.),
                (21., 21.),
                (3., 21.),
                (3., 10.),
            ]);
            line(&[(9., 21.), (9., 13.), (15., 13.), (15., 21.)]);
        }
        Icon::Nodes => {
            for y in [3.0, 14.0] {
                painter.rect_stroke(
                    egui::Rect::from_min_max(p(4., y), p(20., y + 7.)),
                    2.0,
                    stroke,
                    egui::StrokeKind::Inside,
                );
                painter.circle_filled(p(8., y + 3.5), 1.0, color);
                line(&[(14., y + 3.5), (17., y + 3.5)]);
            }
        }
        Icon::Rules => {
            line(&[(5., 3.), (5., 21.)]);
            line(&[(5., 7.), (13., 7.), (19., 3.)]);
            line(&[(5., 12.), (20., 12.), (17., 9.)]);
            line(&[(5., 17.), (13., 17.), (19., 21.)]);
        }
        Icon::Activity => {
            line(&[
                (2., 12.),
                (6., 12.),
                (9., 4.),
                (14., 20.),
                (18., 10.),
                (22., 10.),
            ]);
        }
        Icon::Settings => {
            for (x, y) in [(8., 6.), (16., 12.), (10., 18.)] {
                line(&[(3., y), (21., y)]);
                painter.circle(p(x, y), 2.5, SIDEBAR, stroke);
            }
        }
        Icon::Globe => {
            painter.circle_stroke(rect.center(), rect.width() * 0.4, stroke);
            line(&[(2.5, 12.), (21.5, 12.)]);
            for sign in [-1., 1.] {
                line(&[
                    (12., 2.5),
                    (12. + sign * 4., 6.),
                    (12. + sign * 4.5, 12.),
                    (12. + sign * 4., 18.),
                    (12., 21.5),
                ]);
            }
        }
        Icon::Adapter => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(3., 4.), p(21., 16.)),
                2.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            line(&[(12., 16.), (12., 21.)]);
            line(&[(8., 21.), (16., 21.)]);
            line(&[(7., 9.), (17., 9.)]);
            line(&[(7., 12.), (13., 12.)]);
        }
    }
}

fn nav_button(ui: &mut egui::Ui, label: &str, selected: bool, symbol: Icon) -> bool {
    let response = ui.add_sized(
        [ui.available_width(), 39.0],
        egui::Button::new("")
            .fill(if selected { PANEL_2 } else { SIDEBAR })
            .stroke(Stroke::NONE)
            .corner_radius(CornerRadius::same(7)),
    );
    let color = if selected { ACCENT } else { MUTED };
    paint_icon(
        ui.painter(),
        egui::Rect::from_min_size(
            response.rect.left_center() + egui::vec2(12., -9.),
            Vec2::splat(18.),
        ),
        symbol,
        color,
    );
    ui.painter().text(
        response.rect.left_center() + egui::vec2(42., 0.),
        egui::Align2::LEFT_CENTER,
        label,
        FontId::proportional(12.),
        color,
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::accesskit::Role::Button,
            ui.is_enabled(),
            selected,
            label,
        )
    });
    response.clicked()
}

fn power_control(ui: &mut egui::Ui, active: bool, pending: bool, state: &str) -> bool {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(150.0, 150.0), egui::Sense::click());
    let center = rect.center();
    let ring = if active {
        Color32::from_rgb(64, 87, 49)
    } else {
        LINE
    };
    ui.painter()
        .circle_stroke(center, 70.0, Stroke::new(1.0, ring));
    ui.painter()
        .circle_stroke(center, 58.0, Stroke::new(1.0, ring));
    ui.painter().circle_filled(
        center,
        45.0,
        if active {
            ACCENT
        } else {
            Color32::from_rgb(37, 56, 43)
        },
    );
    let icon_color = if active {
        Color32::from_rgb(38, 59, 23)
    } else {
        ACCENT
    };
    if pending {
        ui.painter().text(
            center + egui::vec2(0.0, -8.0),
            egui::Align2::CENTER_CENTER,
            "...",
            FontId::proportional(18.0),
            icon_color,
        );
    } else {
        let icon_center = center + egui::vec2(0.0, -9.0);
        ui.painter()
            .circle_stroke(icon_center, 10.0, Stroke::new(2.0, icon_color));
        ui.painter().line_segment(
            [
                icon_center + egui::vec2(0.0, -13.0),
                icon_center + egui::vec2(0.0, -2.0),
            ],
            Stroke::new(2.5, icon_color),
        );
    }
    ui.painter().text(
        center + egui::vec2(0.0, 18.0),
        egui::Align2::CENTER_CENTER,
        if pending {
            t("连接中")
        } else if active {
            t("断开连接")
        } else {
            t("开始连接")
        },
        FontId::proportional(10.0),
        if active {
            Color32::from_rgb(38, 59, 23)
        } else {
            ACCENT
        },
    );
    response.on_hover_text(state).clicked()
}

fn takeover_item(
    ui: &mut egui::Ui,
    symbol: Icon,
    label: &str,
    note: &str,
    enabled: &mut bool,
    available: bool,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.add_space(13.0);
        icon(ui, symbol, 18.0, MUTED);
        ui.vertical(|ui| {
            ui.label(RichText::new(label).size(11.0).color(TEXT));
            ui.label(RichText::new(note).size(9.0).color(MUTED));
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.add_space(13.0);
            changed = toggle_switch(ui, enabled, label, available);
        });
    });
    changed
}

fn toggle_switch(ui: &mut egui::Ui, enabled: &mut bool, label: &str, available: bool) -> bool {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(32.0, 19.0), egui::Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::accesskit::Role::Switch, available, *enabled, label)
    });
    let changed = available && response.clicked();
    if changed {
        *enabled = !*enabled;
    }
    ui.painter().rect_filled(
        rect,
        10.0,
        if *enabled {
            ACCENT
        } else {
            Color32::from_rgb(57, 69, 58)
        },
    );
    ui.painter().circle_filled(
        egui::pos2(
            if *enabled {
                rect.right() - 9.5
            } else {
                rect.left() + 9.5
            },
            rect.center().y,
        ),
        7.0,
        if *enabled {
            Color32::from_rgb(45, 66, 28)
        } else {
            MUTED
        },
    );
    changed
}

fn heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(
        RichText::new(title)
            .font(FontId::proportional(21.0))
            .color(TEXT),
    );
    if !subtitle.is_empty() {
        ui.label(RichText::new(subtitle).size(11.0).color(MUTED));
    }
}

fn section_title(ui: &mut egui::Ui, title: &str) {
    ui.label(RichText::new(title).size(13.0).strong().color(TEXT));
    ui.add_space(8.0);
}

fn setting_row(ui: &mut egui::Ui, label: &str, note: &str, control: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .stroke(Stroke::new(1.0, LINE))
        .inner_margin(Margin::symmetric(16, 13))
        .show(ui, |ui| {
            let text_width = (ui.available_width() - 72.0).max(120.0);
            ui.horizontal(|ui| {
                ui.allocate_ui_with_layout(
                    Vec2::new(text_width, 34.0),
                    Layout::top_down(Align::Min),
                    |ui| {
                        ui.label(RichText::new(label).size(12.0).color(TEXT));
                        ui.add(
                            egui::Label::new(RichText::new(note).size(9.0).color(MUTED)).truncate(),
                        );
                    },
                );
                ui.with_layout(Layout::right_to_left(Align::Center), control);
            });
        });
}

fn card(ui: &mut egui::Ui, body: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, LINE))
        .corner_radius(CornerRadius::same(7))
        .inner_margin(Margin::same(18))
        .show(ui, body);
}

fn metric(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    ui.vertical(|ui| {
        ui.label(RichText::new(label).size(13.0).color(MUTED));
        ui.add_space(6.0);
        ui.label(RichText::new(value).size(22.0).strong().color(color));
    });
}

fn traffic_rates(
    previous_uploaded: u64,
    previous_downloaded: u64,
    uploaded: u64,
    downloaded: u64,
    elapsed: Duration,
) -> (f64, f64) {
    let seconds = elapsed.as_secs_f64();
    if seconds == 0.0 {
        return (0.0, 0.0);
    }
    (
        uploaded.saturating_sub(previous_uploaded) as f64 / seconds,
        downloaded.saturating_sub(previous_downloaded) as f64 / seconds,
    )
}

fn field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(RichText::new(label).size(10.0).color(MUTED));
    ui.add(egui::TextEdit::singleline(value).desired_width(f32::INFINITY));
}

fn path_field(ui: &mut egui::Ui, label: &str, value: &mut PathBuf) {
    let mut text = value.to_string_lossy().into_owned();
    field(ui, label, &mut text);
    *value = PathBuf::from(text);
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn capability(ui: &mut egui::Ui, label: &str, enabled: bool, note: &str) {
    ui.horizontal(|ui| {
        dot(ui, if enabled { GOOD } else { MUTED });
        ui.label(RichText::new(label).strong().color(TEXT));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(note).color(MUTED));
        });
    });
}

fn dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, color);
}

fn primary_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).strong().color(Color32::BLACK))
        .fill(ACCENT)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(3))
        .min_size(Vec2::new(124.0, 34.0))
}

fn secondary_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).strong().color(TEXT))
        .fill(PANEL_2)
        .stroke(Stroke::new(1.0, Color32::from_rgb(62, 73, 75)))
        .corner_radius(CornerRadius::same(3))
        .min_size(Vec2::new(82.0, 34.0))
}

fn format_rtt(value: Option<u64>) -> String {
    value
        .map(|micros| format!("{:.1} ms", micros as f64 / 1000.0))
        .unwrap_or_else(|| "—".into())
}

fn probe_state_label(state: &ProbeState) -> String {
    match state {
        ProbeState::Untested => t("未测试").into(),
        ProbeState::Pending => t("测试中…").into(),
        ProbeState::Succeeded(report) => [(&report.quic, "QUIC"), (&report.tls, "TLS")]
            .into_iter()
            .filter_map(|(result, name)| result.as_ref().ok().map(|value| (value.rtt, name)))
            .min_by_key(|(rtt, _)| *rtt)
            .map(|(rtt, name)| format!("{:.1} ms · {name}", rtt.as_secs_f64() * 1000.0))
            .unwrap_or_else(|| t("测试失败").into()),
        ProbeState::Failed(error) => i18n::message(&format!("失败：{error}")),
    }
}

fn matches_filter(query: &str, fields: &[&str]) -> bool {
    let query = query.trim().to_lowercase();
    fields
        .iter()
        .any(|field| field.to_lowercase().contains(&query))
}

fn traffic_chart(ui: &mut egui::Ui, samples: &VecDeque<(f64, f64)>) {
    let (rect, _) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 68.0), egui::Sense::hover());
    for part in 0..=4 {
        let y = egui::lerp(rect.y_range(), part as f32 / 4.0);
        ui.painter().line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            Stroke::new(0.5, LINE),
        );
    }
    let maximum = samples
        .iter()
        .flat_map(|(up, down)| [*up, *down])
        .fold(1.0_f64, f64::max);
    for (download, color) in [(false, GOOD), (true, ACCENT)] {
        let mut points = samples
            .iter()
            .enumerate()
            .map(|(index, (up, down))| {
                let value = if download { down } else { up };
                egui::pos2(
                    rect.left() + rect.width() * index as f32 / 59.0,
                    rect.bottom() - 3.0 - (rect.height() - 6.0) * (value / maximum) as f32,
                )
            })
            .collect::<Vec<_>>();
        if points.is_empty() {
            points = vec![
                egui::pos2(rect.left(), rect.bottom() - 3.0),
                egui::pos2(rect.right(), rect.bottom() - 3.0),
            ];
        }
        if points.len() > 1 {
            ui.painter()
                .add(egui::Shape::line(points, Stroke::new(1.5, color)));
        }
    }
    ui.add_space(8.0);
}

fn export_diagnostics(
    status: Option<&StatusSnapshot>,
    proxy: bool,
    tun: bool,
) -> Result<PathBuf, AnyError> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let path = default_state_dir().join(format!("diagnostics-{timestamp}.json"));
    export_diagnostics_at(&path, status, proxy, tun)?;
    Ok(path)
}

fn export_diagnostics_at(
    path: &Path,
    status: Option<&StatusSnapshot>,
    proxy: bool,
    tun: bool,
) -> Result<(), AnyError> {
    // Export an explicit allowlist; flow targets, credentials, config paths and raw errors stay local.
    let status = status.map(|status| serde_json::json!({
        "state": status.state, "transport": status.transport,
        "quic_rtt_micros": status.quic_rtt_micros, "tls_rtt_micros": status.tls_rtt_micros,
        "active_flows": status.active_flows, "uploaded_bytes": status.uploaded_bytes,
        "downloaded_bytes": status.downloaded_bytes, "udp_dropped_packets": status.udp_dropped_packets,
        "desktop_managed": status.desktop_managed,
    }));
    let bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "format_version": 1, "client_version": env!("CARGO_PKG_VERSION"),
        "control_version": helios_control::CONTROL_VERSION,
        "platform": std::env::consts::OS, "architecture": std::env::consts::ARCH,
        "system_proxy_verified": proxy, "tun_active": tun, "status": status,
    }))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn format_bytes(value: u64) -> String {
    if value >= 1_048_576 {
        format!("{:.1} MiB", value as f64 / 1_048_576.0)
    } else if value >= 1024 {
        format!("{:.1} KiB", value as f64 / 1024.0)
    } else {
        format!("{value} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_runtime_rule_test_cannot_replace_the_current_result() {
        let ctx = egui::Context::default();
        let mut app = preview_app();
        app.rule_test_generation = 2;
        app.rule_test_pending = true;
        app.event_tx
            .send(Event::RouteTest(1, Err("old result".into())))
            .unwrap();
        app.poll_events(&ctx);
        assert!(app.rule_test_pending);
        assert!(app.rule_test_result.is_none());
        app.event_tx
            .send(Event::RouteTest(2, Err("current result".into())))
            .unwrap();
        app.poll_events(&ctx);
        assert!(!app.rule_test_pending);
        assert_eq!(app.rule_test_result, Some(Err("current result".into())));
    }

    fn preview_app() -> HeliosApp {
        let directory = std::env::temp_dir().join(format!("helios-ui-test-{}", std::process::id()));
        let mut profile = DesktopProfile {
            auto_start_daemon: false,
            daemon_binary: directory.join("missing-daemon"),
            daemon_config: directory.join("daemon.toml"),
            helper_binary: directory.join("missing-helper"),
            helper_config: directory.join("helper.toml"),
            control_listen: "127.0.0.1:9".into(),
            ..Default::default()
        };
        profile.nodes[0].name = "Personal VPS".into();
        profile.nodes[0].ca_certificate = directory.join("ca.pem");
        profile.nodes[0].token_file = directory.join("token.hex");
        HeliosApp::from_profile(directory.join("desktop.json"), profile)
    }

    #[test]
    fn hidden_window_keeps_sampling_and_handles_show_without_painting_ui() {
        let ctx = egui::Context::default();
        let mut frame = eframe::Frame::_new_kittest();
        let mut app = preview_app();
        app.last_poll = Instant::now();
        let status: StatusSnapshot = serde_json::from_value(serde_json::json!({
            "state": "connected", "transport": "quic",
            "quic_rtt_micros": 100, "tls_rtt_micros": null,
            "active_flows": 1, "uploaded_bytes": 1124, "downloaded_bytes": 2248,
            "udp_dropped_packets": 0
        }))
        .unwrap();
        app.last_traffic = Some((Instant::now() - Duration::from_secs(1), 100, 200));
        app.event_tx
            .send(Event::Status(0, Ok(status.clone())))
            .unwrap();
        let mut input = egui::RawInput::default();
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .unwrap()
            .minimized = Some(true);
        let _ = ctx.run_logic(&input, |ctx| eframe::App::logic(&mut app, ctx, &mut frame));
        assert_eq!(app.status.as_ref().map(|s| s.uploaded_bytes), Some(1124));
        assert!(app.upload_rate > 0.0 && app.download_rate > 0.0);

        // An idle sample must clear the previous rate, even without a visible window.
        app.event_tx.send(Event::Status(0, Ok(status))).unwrap();
        app.event_tx
            .send(Event::TrayAction(TrayAction::Show))
            .unwrap();
        let output = ctx.run_logic(&input, |ctx| eframe::App::logic(&mut app, ctx, &mut frame));
        assert_eq!((app.upload_rate, app.download_rate), (0.0, 0.0));
        let commands = &output.viewport_commands[&egui::ViewportId::ROOT];
        assert!(
            commands
                .iter()
                .any(|c| matches!(c, egui::ViewportCommand::Visible(true)))
        );
        assert!(
            commands
                .iter()
                .any(|c| matches!(c, egui::ViewportCommand::Minimized(false)))
        );
        assert!(
            commands
                .iter()
                .any(|c| matches!(c, egui::ViewportCommand::Focus))
        );
        assert!(!app.profile_path.exists());
    }

    #[test]
    fn status_sampling_never_overlaps_or_clears_a_new_request_with_an_old_reply() {
        let mut app = preview_app();
        let ctx = egui::Context::default();
        app.daemon_revision = 1;
        app.status_request_revision = Some(1);
        let last_poll = app.last_poll;
        app.request_status();
        assert_eq!(app.last_poll, last_poll);
        app.event_tx
            .send(Event::Status(0, Err("old reply".into())))
            .unwrap();
        app.poll_events(&ctx);
        assert_eq!(app.status_request_revision, Some(1));
        app.event_tx
            .send(Event::Status(1, Err("current reply".into())))
            .unwrap();
        app.poll_events(&ctx);
        assert_eq!(app.status_request_revision, None);
    }

    #[test]
    fn compact_pages_fit_without_starting_network_services() {
        let ctx = egui::Context::default();
        configure_style(&ctx);
        let mut app = preview_app();
        app.notice = Some(("Example error: ".repeat(30), false));
        for size in [Vec2::new(760.0, 600.0), Vec2::new(980.0, 760.0)] {
            for (page, diagnostic_tab) in [
                (Page::Overview, DiagnosticTab::Connections),
                (Page::Node, DiagnosticTab::Connections),
                (Page::Rules, DiagnosticTab::Connections),
                (Page::Diagnostics, DiagnosticTab::Connections),
                (Page::Diagnostics, DiagnosticTab::Dns),
                (Page::Diagnostics, DiagnosticTab::Logs),
                (Page::Settings, DiagnosticTab::Connections),
            ] {
                app.page = page;
                app.diagnostic_tab = diagnostic_tab;
                let mut output = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        ..Default::default()
                    },
                    |ui| {
                        app.content(ui);
                    },
                );
                assert!(!output.shapes.is_empty());
                let bounds = output
                    .shapes
                    .iter()
                    .fold(egui::Rect::NOTHING, |bounds, shape| {
                        bounds.union(
                            shape
                                .shape
                                .visual_bounding_rect()
                                .intersect(shape.clip_rect),
                        )
                    });
                assert!(
                    bounds.left() >= -2.0 && bounds.right() <= size.x + 2.0,
                    "{page:?}: {bounds:?}"
                );
                output.textures_delta.clear();
            }
        }
        assert!(app.child.is_none());
        assert!(!app.system_proxy_enabled);
        assert!(!app.profile_path.exists());
    }

    #[test]
    fn selecting_the_current_node_is_a_noop() {
        let mut app = preview_app();
        app.select_node(0);
        assert!(app.notice.is_none());
        assert!(app.child.is_none());
        assert!(!app.profile_path.exists());
    }

    #[test]
    fn desktop_instance_lock_is_exclusive_and_released_with_handle() {
        let path = std::env::temp_dir().join(format!("helios-ui-lock-{}", std::process::id()));
        let first = lock_desktop_at(&path).unwrap();
        assert!(lock_desktop_at(&path).is_err());
        drop(first);
        drop(lock_desktop_at(&path).unwrap());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn old_status_events_cannot_reset_new_daemon_state_or_credentials() {
        let mut app = preview_app();
        app.daemon_profile = Some(app.profile.clone());
        let original = app.control_profile().active_node().token_file.clone();
        let original_http = app.control_profile().http_listen.clone();
        app.profile.nodes[0].token_file = PathBuf::from("changed-token.hex");
        app.profile.http_listen = "127.0.0.1:18080".into();
        assert_eq!(app.control_profile().active_node().token_file, original);
        assert_eq!(app.control_profile().http_listen, original_http);
        app.daemon_revision = 2;
        app.event_tx
            .send(Event::Status(1, Err("stale".into())))
            .unwrap();
        app.event_tx.send(Event::DaemonOffline(1)).unwrap();
        app.poll_events(&egui::Context::default());
        assert!(app.daemon_profile.is_some());
        assert!(app.status_error.is_none());
        assert!(app.notice.is_none());
    }

    #[test]
    fn filters_are_case_insensitive_and_diagnostics_are_private_and_redacted() {
        assert!(matches_filter("  QUIC ", &["example.com:443", "quic"]));
        assert!(matches_filter("", &["anything"]));
        assert!(!matches_filter("tls", &["quic", "direct"]));
        let status: StatusSnapshot = serde_json::from_value(serde_json::json!({
            "state": "connected", "transport": "tls", "quic_rtt_micros": null, "tls_rtt_micros": 100,
            "active_flows": 1, "uploaded_bytes": 10, "downloaded_bytes": 20, "udp_dropped_packets": 0,
            "active_flow_details": [{"id": 1, "inbound": "socks5", "target": "PRIVATE-TARGET:443",
                "decision": "proxy", "transport": "tls", "duration_seconds": 1, "uploaded_bytes": 10, "downloaded_bytes": 20}],
        })).unwrap();
        let path = std::env::temp_dir().join(format!(
            "helios-diagnostic-test-{}.json",
            std::process::id()
        ));
        export_diagnostics_at(&path, Some(&status), true, false).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let report: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(report["status"]["uploaded_bytes"], 10);
        assert_eq!(report["system_proxy_verified"], true);
        for private in [
            "PRIVATE-TARGET",
            "active_flow_details",
            "token",
            "certificate",
            "credential",
        ] {
            assert!(!content.contains(private));
        }
        assert!(export_diagnostics_at(&path, None, false, false).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn navigation_and_new_node_editor_follow_the_action() {
        fn draw(
            ctx: &egui::Context,
            app: &mut HeliosApp,
            events: Vec<egui::Event>,
        ) -> egui::FullOutput {
            ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(980.0, 760.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ui| app.content(ui),
            )
        }
        fn click(ctx: &egui::Context, app: &mut HeliosApp, label: &str) {
            click_nth(ctx, app, label, 0);
        }
        fn click_nth(ctx: &egui::Context, app: &mut HeliosApp, label: &str, index: usize) {
            let mut output = draw(ctx, app, Vec::new());
            let pos = output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::Shape::Text(text) if text.galley.text() == label => {
                        Some(text.pos + text.galley.rect.center().to_vec2())
                    }
                    _ => None,
                })
                .nth(index);
            output.textures_delta.clear();
            let pos = pos.expect("control must be visible");
            for pressed in [true, false] {
                let mut output = draw(
                    ctx,
                    app,
                    vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                );
                output.textures_delta.clear();
            }
        }
        let ctx = egui::Context::default();
        configure_style(&ctx);
        ctx.style_mut_of(egui::Theme::Dark, |style| style.animation_time = 0.0);
        let mut app = preview_app();
        app.page = Page::Settings;
        click(&ctx, &mut app, t("我的节点"));
        assert!(app.page == Page::Node);
        click(&ctx, &mut app, t("诊断"));
        assert!(app.page == Page::Diagnostics);
        click(&ctx, &mut app, "DNS");
        assert!(app.diagnostic_tab == DiagnosticTab::Dns);
        click(&ctx, &mut app, t("我的节点"));
        app.profile.nodes.push(NodeProfile {
            server: String::new(),
            ..Default::default()
        });
        app.probes.push(ProbeState::Untested);
        click_nth(&ctx, &mut app, t("测试延迟"), 1);
        assert_eq!(app.profile.active_node, 0);
        assert_eq!(app.notice.as_ref().map(|notice| notice.1), Some(false));
        app.profile.nodes.pop();
        app.probes.pop();
        click(&ctx, &mut app, t("添加节点"));
        click(&ctx, &mut app, t("手动添加节点"));
        assert_eq!(app.profile.nodes.len(), 1);
        assert_eq!(app.profile.active_node, 0);
        assert!(app.node_editor.is_some());
        let mut output = draw(&ctx, &mut app, Vec::new());
        output.textures_delta.clear();
        output = draw(&ctx, &mut app, Vec::new());
        output.textures_delta.clear();
        output = draw(&ctx, &mut app, Vec::new());
        let labels = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some(text.galley.text().to_owned()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            labels.iter().any(|label| label == t("服务器地址")),
            "{labels:?}"
        );
        output.textures_delta.clear();
        click(&ctx, &mut app, t("取消"));
        assert!(app.node_editor.is_none());
        assert_eq!(app.profile.nodes.len(), 1);
        assert!(!app.profile_path.exists());
    }

    #[test]
    fn daemon_events_do_not_discard_the_node_being_edited() {
        let mut app = preview_app();
        app.daemon_profile = Some(app.profile.clone());
        app.profile.nodes.push(NodeProfile {
            name: "Draft VPS".into(),
            ..Default::default()
        });
        app.probes.push(ProbeState::Untested);
        app.profile.active_node = 1;
        let ctx = egui::Context::default();
        let status = StatusSnapshot {
            dns_cache: None,
            config_revision: 1,
            active_server: app.profile.nodes[0].server.parse().ok(),
            system_proxy_enabled: false,
            system_proxy_verified: false,
            system_proxy_error: None,
            desktop_managed: true,
            state: ConnectionState::Connected,
            transport: helios_control::ActiveTransport::Tls,
            quic_rtt_micros: None,
            tls_rtt_micros: None,
            active_flows: 0,
            uploaded_bytes: 0,
            downloaded_bytes: 0,
            udp_dropped_packets: 0,
            active_flow_details: Vec::new(),
        };
        app.event_tx.send(Event::Status(0, Ok(status))).unwrap();
        app.poll_events(&ctx);
        assert_eq!(app.profile.active_node, 1);

        app.event_tx
            .send(Event::ConfigApplied(
                0,
                app.profile.clone(),
                Err("authentication failed".into()),
            ))
            .unwrap();
        app.poll_events(&ctx);
        assert_eq!(app.profile.active_node, 1);
        assert_eq!(app.profile.active_node().name, "Draft VPS");
    }

    #[test]
    fn connection_link_adds_and_saves_without_switching_the_active_node() {
        let root =
            std::env::temp_dir().join(format!("helios-desktop-link-import-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let certificate =
            rcgen::generate_simple_self_signed(vec!["node-a1.helios.invalid".to_owned()])
                .unwrap()
                .cert;
        let link = helios_config::ConnectionLink::new(
            "Imported VPS".into(),
            "203.0.113.10:4800".parse().unwrap(),
            "node-a1.helios.invalid".into(),
            certificate.der(),
            "desktop-main".into(),
            [5; 32],
            TransportPreference::Tls,
        )
        .unwrap()
        .encode()
        .unwrap();
        let mut app = preview_app();
        app.profile_path = root.join("desktop.json");
        app.profile.daemon_config = root.join("daemon.toml");
        app.connection_link_text = link;

        app.add_connection_link_at(&root);

        assert_eq!(app.profile.nodes.len(), 2);
        assert_eq!(app.profile.active_node, 0);
        assert_eq!(app.profile.nodes[1].name, "Imported VPS");
        assert!(app.connection_link_text.is_empty());
        assert!(app.profile_path.is_file());
        assert!(app.profile.nodes[1].ca_certificate.is_file());
        assert!(app.profile.nodes[1].token_file.is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn saving_a_node_draft_does_not_switch_the_active_node() {
        let root = std::env::temp_dir().join(format!(
            "helios-node-draft-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut app = preview_app();
        app.profile_path = root.join("desktop.json");
        app.profile.daemon_config = root.join("daemon.toml");
        let mut node = app.profile.nodes[0].clone();
        node.name = "Saved draft".into();
        node.server = "203.0.113.11:443".into();

        app.save_node_draft(
            &NodeEditor {
                index: None,
                node,
                error: None,
            },
            false,
        )
        .unwrap();

        assert_eq!(app.profile.active_node, 0);
        assert_eq!(app.profile.nodes[1].name, "Saved draft");
        assert!(app.child.is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn daemon_online_alone_is_not_a_connected_system_proxy() {
        let mut status = StatusSnapshot {
            dns_cache: None,
            config_revision: 1,
            active_server: None,
            system_proxy_enabled: false,
            system_proxy_verified: false,
            system_proxy_error: None,
            desktop_managed: false,
            state: ConnectionState::Connected,
            transport: helios_control::ActiveTransport::Tls,
            quic_rtt_micros: None,
            tls_rtt_micros: Some(150_000),
            active_flows: 0,
            uploaded_bytes: 0,
            downloaded_bytes: 0,
            udp_dropped_packets: 0,
            active_flow_details: Vec::new(),
        };
        assert_eq!(connection_label(Some(&status), false, false).0, t("未连接"));
        assert_eq!(connection_label(Some(&status), true, false).0, t("已连接"));
        assert_eq!(connection_label(Some(&status), false, true).0, t("连接中"));
        status.state = ConnectionState::Unavailable;
        assert!(!node_ready(&status));
        assert!(tray_connection_active(true, false, false));
        assert_eq!(
            connection_label(Some(&status), true, false).0,
            t("节点暂不可用")
        );
        status.state = ConnectionState::Degraded;
        assert!(node_ready(&status));
    }

    #[test]
    fn chinese_font_covers_primary_controls_when_installed() {
        if chinese_font().is_none() {
            return;
        }
        let ctx = egui::Context::default();
        configure_style(&ctx);
        let mut output = ctx.run_ui(egui::RawInput::default(), |_| {
            ctx.fonts_mut(|fonts| {
                assert!(fonts.has_glyphs(
                    &FontId::proportional(15.0),
                    "系统代理虚拟网卡连接节点设置中文"
                ));
            });
        });
        output.textures_delta.clear();
    }

    #[cfg(unix)]
    #[test]
    fn owned_daemon_detection_reaps_exit_without_losing_live_child() {
        let mut child = Some(Command::new("sleep").arg("30").spawn().unwrap());
        assert!(owned_daemon_running(&mut child).unwrap());
        assert!(child.is_some());
        child.as_mut().unwrap().kill().unwrap();
        child.as_mut().unwrap().wait().unwrap();
        assert!(!owned_daemon_running(&mut child).unwrap());
        assert!(child.is_none());
        assert!(!owned_daemon_running(&mut child).unwrap());
    }

    #[test]
    fn stale_tun_status_is_not_reported_as_running() {
        let path =
            std::env::temp_dir().join(format!("helios-missing-status-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(!status_is_fresh(&path));
        assert!(!status_needs_recovery(&path));
    }

    #[test]
    fn daemon_log_rotates_at_limit_and_is_private() {
        use std::io::Write as _;

        let directory =
            std::env::temp_dir().join(format!("helios-log-test-{}", std::process::id()));
        let path = directory.join("daemon.log");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(&path, vec![b'x'; 5 * 1024 * 1024]).unwrap();
        let mut log = open_daemon_log_at(&path).unwrap();
        log.write_all(b"new\n").unwrap();
        drop(log);
        assert_eq!(std::fs::read(&path).unwrap(), b"new\n");
        assert_eq!(
            std::fs::metadata(path.with_extension("log.1"))
                .unwrap()
                .len(),
            5 * 1024 * 1024
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn daemon_log_tail_is_bounded_and_omits_error_details() {
        let path =
            std::env::temp_dir().join(format!("helios-log-tail-test-{}", std::process::id()));
        let old = serde_json::json!({
            "timestamp": "old",
            "level": "INFO",
            "fields": { "event": "old_event" }
        });
        let recent = serde_json::json!({
            "timestamp": "now",
            "level": "DEBUG",
            "fields": { "event": "connection_failed", "error": "sensitive.example" }
        });
        std::fs::write(&path, format!("{old}\n{}\n{recent}\n", "x".repeat(256))).unwrap();
        let entries = read_daemon_log_tail(&path, 160, 10).unwrap();
        assert_eq!(
            entries,
            vec![LogEntry {
                timestamp: "now".into(),
                level: "DEBUG".into(),
                event: "connection_failed".into(),
            }]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn traffic_rates_handle_counter_reset_and_elapsed_time() {
        assert_eq!(
            traffic_rates(100, 200, 300, 500, Duration::from_secs(2)),
            (100.0, 150.0)
        );
        assert_eq!(
            traffic_rates(300, 500, 10, 20, Duration::from_secs(2)),
            (0.0, 0.0)
        );
        assert_eq!(traffic_rates(0, 0, 1, 1, Duration::ZERO), (0.0, 0.0));
    }

    #[test]
    fn probe_states_have_stable_node_list_labels() {
        assert_eq!(probe_state_label(&ProbeState::Untested), t("未测试"));
        assert_eq!(probe_state_label(&ProbeState::Pending), t("测试中…"));
        assert_eq!(
            probe_state_label(&ProbeState::Succeeded(NodeProbeReport {
                checked_at_unix_ms: 0,
                quic: Err("UDP blocked".into()),
                tls: Ok(helios_client_control::ProbeMeasurement {
                    handshake: Duration::from_millis(50),
                    rtt: Duration::from_micros(12_345)
                }),
            })),
            "12.3 ms · TLS"
        );
        assert_eq!(
            probe_state_label(&ProbeState::Failed("timeout".into())),
            t("失败：timeout")
        );
    }

    #[test]
    fn app_icon_is_valid_png() {
        let icon = eframe::icon_data::from_png_bytes(APP_ICON).unwrap();
        #[cfg(not(target_os = "macos"))]
        assert_eq!((icon.width, icon.height), (512, 512));
        #[cfg(target_os = "macos")]
        assert_eq!((icon.width, icon.height), (1024, 1024));
    }

    #[test]
    fn macos_icon_preserves_transparent_dock_margins() {
        let icon = eframe::icon_data::from_png_bytes(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/helios-icon-macos.png"
        )))
        .unwrap();
        assert_eq!((icon.width, icon.height), (1024, 1024));
        for (index, pixel) in icon.rgba.chunks_exact(4).enumerate() {
            let (x, y) = (index % 1024, index / 1024);
            if !(100..924).contains(&x) || !(100..924).contains(&y) {
                assert_eq!(pixel[3], 0, "Dock margin must be transparent");
            }
        }
        assert_eq!(icon.rgba[(512 * 1024 + 512) * 4 + 3], 255);
    }

    #[test]
    fn tray_icon_is_valid_rgba() {
        let (rgba, width, height) = tray_icon_rgba();
        assert_eq!((width, height), (64, 64));
        assert_eq!(rgba.len(), width as usize * height as usize * 4);
        assert_eq!(&rgba[0..4], &[0, 0, 0, 0]);
        let center = ((height as usize / 2 * width as usize) + width as usize / 2) * 4;
        assert_eq!(&rgba[center..center + 4], &[255, 205, 61, 255]);
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires disposable real TUN, resolve1, polkitd and an isolated authorization rule"]
    fn isolated_linux_tun_desktop_pkexec_lifecycle() {
        assert_eq!(
            std::env::var("HELIOS_ISOLATED_DESKTOP_TUN").as_deref(),
            Ok("1")
        );
        assert_eq!(std::env::var("HOME").as_deref(), Ok("/tmp/helios-gui"));
        assert!(Path::new("/.dockerenv").exists());
        assert_eq!(
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim(),
            "helios-tun-client"
        );
        let directory = default_state_dir();
        std::fs::create_dir_all(&directory).unwrap();
        let token = directory.join("node-token.hex");
        write_atomic(&token, "07".repeat(32).as_bytes()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        ensure_control_token(&control_token_file()).unwrap();
        let profile = DesktopProfile {
            daemon_binary: "/daemon".into(),
            daemon_config: directory.join("daemon.toml"),
            socks_listen: "127.0.0.1:11080".into(),
            http_listen: "127.0.0.1:11081".into(),
            control_listen: "127.0.0.1:11082".into(),
            nodes: vec![NodeProfile {
                server: "198.51.100.10:24443".into(),
                server_name: "localhost".into(),
                ca_certificate: "/cert.pem".into(),
                credential_id: "test".into(),
                token_file: token,
                ..NodeProfile::default()
            }],
            ..DesktopProfile::default()
        };
        let path = directory.join("desktop.json");
        let mut app = HeliosApp::from_profile(path.clone(), profile);
        app.startup_checked = true;
        let ctx = egui::Context::default();
        let pump = |app: &mut HeliosApp, active: bool| {
            let deadline = Instant::now() + Duration::from_secs(25);
            loop {
                app.poll_events(&ctx);
                if if active {
                    app.tun_enabled
                } else {
                    app.linux_tun.is_none()
                } {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "desktop state stalled: {:?}",
                    app.notice
                );
                if active {
                    assert!(
                        app.linux_tun.is_some(),
                        "desktop start failed: {:?}",
                        app.notice
                    );
                }
                thread::sleep(Duration::from_millis(20));
            }
        };
        if std::env::var("HELIOS_EXPECT_TUN_DENIAL").as_deref() == Ok("1") {
            app.start_tun();
            pump(&mut app, false);
            assert!(!app.tun_enabled && app.child.is_none() && app.profile.tun_outbound.is_none());
            assert!(!tun_status_file().exists());
            assert!(app.notice.as_ref().is_some_and(|(_, success)| !success));
            return;
        }
        // Cancelling during preparation must not leave a bound daemon or pending root state.
        app.start_tun();
        app.stop_tun();
        pump(&mut app, false);
        assert!(!app.tun_enabled && app.child.is_none() && !tun_status_file().exists());
        app.start_tun();
        pump(&mut app, true);
        assert!(app.child.is_some());
        assert!(app.profile.tun_outbound.is_some());
        assert_eq!(
            std::fs::read_to_string(tun_status_file()).unwrap(),
            "ready\n"
        );
        app.stop_tun();
        // Closing waits for root cleanup before reaping the daemon and resetting its policy.
        assert!(app.linux_tun.is_some());
        pump(&mut app, false);
        assert!(!app.tun_enabled && app.child.is_none() && app.profile.tun_outbound.is_none());
        assert!(!tun_status_file().exists());
        let stored = load_profile(&path).unwrap();
        assert!(stored.tun_outbound.is_none());
        let daemon: helios_config::DaemonConfig =
            toml::from_str(&std::fs::read_to_string(&stored.daemon_config).unwrap()).unwrap();
        assert!(daemon.outbound.is_none() && daemon.dns.is_none());
        // An abrupt desktop exit closes the same pipe; root must recover independently.
        app.start_tun();
        pump(&mut app, true);
        let mut child = app.child.take().unwrap();
        child.stdin.take();
        let profile = app.profile.clone();
        drop(app);
        let deadline = Instant::now() + Duration::from_secs(10);
        while tun_status_file().exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(!tun_status_file().exists());
        assert!(stop_owned_daemon(child, &profile).is_ok());
    }
}
