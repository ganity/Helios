use std::{
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use gpui::{
    App, AppContext, Bounds, Context, InteractiveElement, IntoElement, PathPromptOptions, Render,
    Window, WindowBounds, WindowOptions, div, prelude::*, px, rgb, size,
};
use gpui_platform::application;
use helios_client_control::{DaemonClient, DaemonPresence, probe_node};
use helios_client_model::{
    DesktopProfile, RoutingMode, default_control_socket, default_state_dir, import_node,
    load_profile, save_profile,
};
use std::process::{Child, Command, Stdio};

struct Dashboard {
    profile_path: PathBuf,
    profile: DesktopProfile,
    runtime: RuntimeSnapshot,
    refreshing: bool,
    applying_mode: bool,
    mode_notice: Option<(String, bool)>,
    probes: Vec<ProbeState>,
    probe_error: Option<String>,
    add_node_error: Option<String>,
    active_child: Option<Child>,
    node_action: Option<(String, bool)>,
    node_action_pending: bool,
}

struct RuntimeSnapshot {
    status: String,
    transport: String,
    active_flows: String,
    traffic: String,
}

#[derive(Clone, Debug, Default)]
enum ProbeState {
    #[default]
    Untested,
    Pending,
    Succeeded(std::time::Duration),
    Failed,
}

impl Dashboard {
    fn start_daemon_action(&mut self, cx: &mut Context<Self>) {
        if self.node_action_pending || self.active_child.is_some() {
            return;
        }
        let profile = self.profile.clone();
        let path = self.profile_path.clone();
        self.node_action_pending = true;
        self.node_action = Some(("Connecting…".into(), true));
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move { ensure_daemon(&path, &profile) })
                .await;
            this.update(cx, |this, cx| {
                this.node_action_pending = false;
                match result {
                    Ok((child, message)) => {
                        this.active_child = child;
                        this.node_action = Some((message, true));
                        this.runtime.status = "CONNECTING".into();
                    }
                    Err(error) => this.node_action = Some((error, false)),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn stop_daemon_action(&mut self, cx: &mut Context<Self>) {
        if self.node_action_pending {
            return;
        }
        let Some(child) = self.active_child.take() else {
            self.node_action = Some(("This window does not own the daemon".into(), false));
            cx.notify();
            return;
        };
        let profile = self.profile.clone();
        self.node_action_pending = true;
        self.node_action = Some(("Stopping daemon…".into(), true));
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move { stop_owned_daemon(child, &profile) })
                .await;
            this.update(cx, |this, cx| {
                this.node_action_pending = false;
                match result {
                    Ok(()) => {
                        this.runtime.status = "OFFLINE".into();
                        this.node_action = Some(("Daemon stopped".into(), true));
                    }
                    Err((child, error)) => {
                        this.active_child = Some(child);
                        this.node_action = Some((error, false));
                    }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn import_node_file(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Import Helios node JSON".into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            let result = match receiver.await {
                Ok(Ok(Some(paths))) => paths
                    .first()
                    .ok_or_else(|| "No node file was selected".to_owned())
                    .and_then(|path| load_node_file(path)),
                Ok(Ok(None)) => return,
                Ok(Err(error)) => Err(error.to_string()),
                Err(error) => Err(error.to_string()),
            };
            this.update_in(cx, |this, window, cx| {
                match result {
                    Ok(node) => {
                        let previous = this.profile.clone();
                        this.profile.nodes.push(node);
                        this.probes.push(ProbeState::Untested);
                        if let Err(error) = save_profile(&this.profile_path, &this.profile) {
                            this.profile = previous;
                            this.probes.pop();
                            this.add_node_error = Some(error.to_string());
                        } else {
                            this.add_node_error = None;
                            this.node_action = Some(("Node imported".into(), true));
                        }
                    }
                    Err(error) => this.add_node_error = Some(error),
                }
                cx.notify();
                window.refresh();
            })
            .ok();
        })
        .detach();
    }

    fn select_node(&mut self, index: usize, cx: &mut Context<Self>) {
        if self.node_action_pending || self.profile.active_node == index {
            return;
        }
        if index >= self.profile.nodes.len() {
            return;
        }
        let previous = self.profile.clone();
        self.profile.active_node = index;
        let profile = self.profile.clone();
        let path = self.profile_path.clone();
        let child = self.active_child.take();
        let previous_for_switch = previous.clone();
        self.node_action_pending = true;
        self.node_action = Some(("Applying node…".into(), true));
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(
                    async move { switch_node(path, previous_for_switch, profile, child) },
                )
                .await;
            this.update(cx, |this, cx| {
                this.node_action_pending = false;
                match result {
                    Ok((child, message)) => {
                        this.active_child = child;
                        this.node_action = Some((message, true));
                        this.runtime = RuntimeSnapshot {
                            status: "CONNECTING".into(),
                            transport: "—".into(),
                            active_flows: "0".into(),
                            traffic: "Waiting for daemon status".into(),
                        };
                        this.refreshing = false;
                    }
                    Err((child, error)) => {
                        this.active_child = child;
                        this.profile = previous;
                        this.node_action = Some((error, false));
                    }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn delete_node(&mut self, index: usize, cx: &mut Context<Self>) {
        if self.node_action_pending
            || !can_delete_node(&self.probes, index, self.profile.active_node)
        {
            return;
        }
        let mut updated = self.profile.clone();
        updated.nodes.remove(index);
        if index < updated.active_node {
            updated.active_node -= 1;
        }
        let previous = self.profile.clone();
        self.profile = updated;
        self.probes.remove(index);
        if let Err(error) = save_profile(&self.profile_path, &self.profile) {
            self.profile = previous;
            self.probes = vec![ProbeState::Untested; self.profile.nodes.len()];
            self.node_action = Some((format!("Node was not deleted: {error}"), false));
        } else {
            self.node_action = Some(("Node deleted".into(), true));
        }
        cx.notify();
    }

    fn probe(&mut self, index: usize, cx: &mut Context<Self>) {
        if matches!(self.probes.get(index), Some(ProbeState::Pending)) {
            return;
        }
        let Some(node) = self.profile.nodes.get(index) else {
            return;
        };
        let node = match node.config() {
            Ok(node) => node,
            Err(error) => {
                self.probes[index] = ProbeState::Failed;
                self.probe_error = Some(error.to_string());
                cx.notify();
                return;
            }
        };
        self.probes[index] = ProbeState::Pending;
        self.probe_error = None;
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move { probe_snapshot(node) })
                .await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(duration) => this.probes[index] = ProbeState::Succeeded(duration),
                    Err(error) => {
                        this.probes[index] = ProbeState::Failed;
                        this.probe_error = Some(error);
                    }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn apply_mode(&mut self, mode: RoutingMode, cx: &mut Context<Self>) {
        if self.applying_mode || self.profile.mode == mode {
            return;
        }
        let previous = self.profile.mode;
        self.profile.mode = mode;
        self.applying_mode = true;
        self.mode_notice = Some(("Applying routing mode…".into(), true));
        cx.notify();
        let path = self.profile_path.clone();
        let profile = self.profile.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move { persist_and_apply_mode(&path, &profile) })
                .await;
            this.update(cx, |this, cx| {
                this.applying_mode = false;
                this.mode_notice = Some(match result {
                    Ok(()) => ("Routing mode saved and applied".into(), true),
                    Err((saved, error)) => {
                        if !saved {
                            this.profile.mode = previous;
                        }
                        (
                            if saved {
                                format!("Mode saved; live update failed: {error}")
                            } else {
                                format!("Mode was not saved: {error}")
                            },
                            false,
                        )
                    }
                });
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        if self.refreshing {
            return;
        }
        self.refreshing = true;
        cx.notify();
        let profile = self.profile.clone();
        cx.spawn(async move |this, cx| {
            let runtime = cx
                .background_spawn(async move { runtime_snapshot(&profile) })
                .await;
            this.update(cx, |this, cx| {
                this.runtime = runtime;
                this.refreshing = false;
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn start_polling(&mut self, cx: &mut Context<Self>) {
        if self.profile.auto_start_daemon && self.runtime.status == "OFFLINE" {
            self.start_daemon_action(cx);
        }
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_secs(2))
                    .await;
                let profile = match this.update(cx, |this, cx| {
                    if this.refreshing {
                        return None;
                    }
                    let exited = match this.active_child.as_mut() {
                        Some(child) => match child.try_wait() {
                            Ok(Some(status)) => Some(status.to_string()),
                            Ok(None) => None,
                            Err(error) => {
                                this.node_action = Some((
                                    format!("Could not check daemon process: {error}"),
                                    false,
                                ));
                                None
                            }
                        },
                        None => None,
                    };
                    if let Some(status) = exited {
                        this.active_child.take();
                        this.node_action =
                            Some((format!("Daemon exited unexpectedly ({status})"), false));
                    }
                    this.refreshing = true;
                    cx.notify();
                    Some(this.profile.clone())
                }) {
                    Ok(Some(profile)) => profile,
                    Ok(None) => continue,
                    Err(_) => break,
                };
                let runtime = cx
                    .background_spawn(async move { runtime_snapshot(&profile) })
                    .await;
                if this
                    .update(cx, |this, cx| {
                        this.runtime = runtime;
                        this.refreshing = false;
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
    }
}

impl Render for Dashboard {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let node = self.profile.active_node();
        let node_rows = self
            .profile
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let (probe, color) = probe_label(&self.probes[index]);
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px_4()
                    .py_3()
                    .bg(rgb(if index == self.profile.active_node {
                        0x181f24
                    } else {
                        0x12181c
                    }))
                    .border_b_1()
                    .border_color(rgb(0x263137))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(node.name.clone())
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(0x7e8f8f))
                                    .child(node.server.clone()),
                            ),
                    )
                    .child(
                        div()
                            .id(format!("probe-{index}"))
                            .px_3()
                            .py_2()
                            .rounded_md()
                            .bg(rgb(0x263137))
                            .hover(|style| style.bg(rgb(0x344149)))
                            .cursor_pointer()
                            .text_sm()
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_color(rgb(color))
                            .on_click(cx.listener(move |this, _, _, cx| this.probe(index, cx)))
                            .child(probe),
                    )
                    .child(
                        node_action_control(
                            format!("use-{index}"),
                            if index == self.profile.active_node {
                                "ACTIVE"
                            } else {
                                "USE"
                            },
                            index != self.profile.active_node && !self.node_action_pending,
                        )
                        .on_click(cx.listener(move |this, _, _, cx| this.select_node(index, cx))),
                    )
                    .child(
                        node_action_control(
                            format!("delete-{index}"),
                            "DELETE",
                            !self.node_action_pending
                                && can_delete_node(&self.probes, index, self.profile.active_node),
                        )
                        .on_click(cx.listener(move |this, _, _, cx| this.delete_node(index, cx))),
                    )
            })
            .collect::<Vec<_>>();
        let refresh_label = if self.refreshing {
            "REFRESHING…"
        } else {
            "REFRESH"
        };
        let mode_disabled = self.applying_mode;
        div()
            .id("dashboard-scroll")
            .flex()
            .flex_col()
            .size_full()
            .overflow_y_scroll()
            .bg(rgb(0x0b0f12))
            .text_color(rgb(0xdee6e3))
            .p_8()
            .gap_6()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(
                                div()
                                    .text_3xl()
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .child("Helios"),
                            )
                            .child(
                                div()
                                    .text_color(rgb(0x7e8f8f))
                                    .child("GPUI desktop prototype · shared client model"),
                            ),
                    )
                    .child(
                        div()
                            .id("refresh")
                            .px_4()
                            .py_2()
                            .rounded_md()
                            .bg(rgb(0x263137))
                            .hover(|style| style.bg(rgb(0x344149)))
                            .cursor_pointer()
                            .text_sm()
                            .font_weight(gpui::FontWeight::BOLD)
                            .on_click(cx.listener(|this, _, _, cx| this.refresh(cx)))
                            .child(refresh_label),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        node_action_control(
                            "daemon-start".into(),
                            "CONNECT",
                            !self.node_action_pending && self.active_child.is_none(),
                        )
                        .on_click(cx.listener(|this, _, _, cx| this.start_daemon_action(cx))),
                    )
                    .child(
                        node_action_control(
                            "daemon-stop".into(),
                            "STOP",
                            !self.node_action_pending && self.active_child.is_some(),
                        )
                        .on_click(cx.listener(|this, _, _, cx| this.stop_daemon_action(cx))),
                    )
                    .when_some(self.node_action.as_ref(), |element, (message, success)| {
                        element.child(
                            div()
                                .text_sm()
                                .text_color(rgb(if *success { 0x4fd697 } else { 0xff5e5e }))
                                .child(message.clone()),
                        )
                    }),
            )
            .child(
                div()
                    .flex()
                    .gap_4()
                    .child(metric("STATUS", self.runtime.status.clone(), 0x4fd697))
                    .child(metric("MODE", routing_mode(self.profile.mode), 0xe0ff56))
                    .child(metric(
                        "TRANSPORT",
                        self.runtime.transport.clone(),
                        0xdee6e3,
                    )),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x7e8f8f))
                            .child("ROUTING MODE"),
                    )
                    .child(
                        mode_control(
                            "RULE",
                            self.profile.mode == RoutingMode::Rule,
                            mode_disabled,
                        )
                        .on_click(
                            cx.listener(|this, _, _, cx| this.apply_mode(RoutingMode::Rule, cx)),
                        ),
                    )
                    .child(
                        mode_control(
                            "GLOBAL PROXY",
                            self.profile.mode == RoutingMode::GlobalProxy,
                            mode_disabled,
                        )
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.apply_mode(RoutingMode::GlobalProxy, cx)
                        })),
                    )
                    .child(
                        mode_control(
                            "GLOBAL DIRECT",
                            self.profile.mode == RoutingMode::GlobalDirect,
                            mode_disabled,
                        )
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.apply_mode(RoutingMode::GlobalDirect, cx)
                        })),
                    )
                    .when_some(self.mode_notice.as_ref(), |element, (message, success)| {
                        element.child(
                            div()
                                .ml_3()
                                .text_sm()
                                .text_color(rgb(if *success { 0x4fd697 } else { 0xff5e5e }))
                                .child(message.clone()),
                        )
                    }),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .p_6()
                    .bg(rgb(0x12181c))
                    .border_1()
                    .border_color(rgb(0x263137))
                    .rounded_md()
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x7e8f8f))
                            .child("ACTIVE NODE"),
                    )
                    .child(
                        div()
                            .text_xl()
                            .font_weight(gpui::FontWeight::BOLD)
                            .child(node.name.clone()),
                    )
                    .child(format!("Server · {}", node.server))
                    .child(format!("TLS name · {}", node.server_name))
                    .child(format!(
                        "Preferred transport · {:?}",
                        node.preferred_transport
                    ))
                    .child(format!("Active flows · {}", self.runtime.active_flows))
                    .child(format!("Traffic · {}", self.runtime.traffic)),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(0x263137))
                    .child(
                        div()
                            .px_4()
                            .py_3()
                            .text_sm()
                            .text_color(rgb(0x7e8f8f))
                            .child("NODES · AUTHENTICATED LATENCY"),
                    )
                    .children(node_rows)
                    .when_some(self.probe_error.as_ref(), |element, error| {
                        element.child(
                            div()
                                .px_4()
                                .py_2()
                                .text_sm()
                                .text_color(rgb(0xff5e5e))
                                .child(error.clone()),
                        )
                    }),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(
                        node_action_control("import-node-json".into(), "IMPORT NODE JSON", true)
                            .on_click(
                                cx.listener(|this, _, window, cx| {
                                    this.import_node_file(window, cx)
                                }),
                            ),
                    )
                    .when_some(self.add_node_error.as_ref(), |element, error| {
                        element.child(
                            div()
                                .text_sm()
                                .text_color(rgb(0xff5e5e))
                                .child(error.clone()),
                        )
                    }),
            )
            .child(
                div()
                    .mt_auto()
                    .text_sm()
                    .text_color(rgb(0x7e8f8f))
                    .child("Shared model · authenticated status · live routing mode control"),
            )
    }
}

fn probe_label(state: &ProbeState) -> (String, u32) {
    match state {
        ProbeState::Untested => ("TEST".into(), 0xdee6e3),
        ProbeState::Pending => ("TESTING…".into(), 0xe0ff56),
        ProbeState::Succeeded(duration) => (format!("{} ms", duration.as_millis()), 0x4fd697),
        ProbeState::Failed => ("FAILED".into(), 0xff5e5e),
    }
}

fn node_action_control(
    id: String,
    label: &'static str,
    enabled: bool,
) -> gpui::Stateful<gpui::Div> {
    div()
        .id(id)
        .px_3()
        .py_2()
        .rounded_md()
        .bg(rgb(0x263137))
        .text_color(rgb(if enabled { 0xdee6e3 } else { 0x7e8f8f }))
        .when(enabled, |element| {
            element
                .hover(|style| style.bg(rgb(0x344149)))
                .cursor_pointer()
        })
        .text_sm()
        .font_weight(gpui::FontWeight::BOLD)
        .child(label.to_owned())
}

fn load_node_file(path: &Path) -> Result<helios_client_model::NodeProfile, String> {
    let mut json = String::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(64 * 1024 + 1)
        .read_to_string(&mut json)
        .map_err(|error| error.to_string())?;
    if json.len() > 64 * 1024 {
        return Err("Node JSON exceeds the 64 KiB import limit".into());
    }
    import_node(&json)
}

fn mode_control(label: &str, selected: bool, disabled: bool) -> gpui::Stateful<gpui::Div> {
    div()
        .id(label.to_owned())
        .px_3()
        .py_2()
        .rounded_md()
        .bg(rgb(if selected { 0x39450d } else { 0x263137 }))
        .text_color(rgb(if selected { 0xe0ff56 } else { 0xdee6e3 }))
        .when(!disabled, |element| {
            element
                .hover(|style| style.bg(rgb(0x344149)))
                .cursor_pointer()
        })
        .text_sm()
        .font_weight(gpui::FontWeight::BOLD)
        .child(label.to_owned())
}

fn metric(label: &str, value: impl Into<String>, color: u32) -> impl IntoElement {
    div()
        .flex_1()
        .flex()
        .flex_col()
        .gap_2()
        .p_5()
        .bg(rgb(0x181f24))
        .rounded_md()
        .child(
            div()
                .text_sm()
                .text_color(rgb(0x7e8f8f))
                .child(label.to_owned()),
        )
        .child(
            div()
                .text_xl()
                .font_weight(gpui::FontWeight::BOLD)
                .text_color(rgb(color))
                .child(value.into()),
        )
}

fn routing_mode(mode: RoutingMode) -> &'static str {
    match mode {
        RoutingMode::Rule => "RULE",
        RoutingMode::GlobalProxy => "GLOBAL PROXY",
        RoutingMode::GlobalDirect => "GLOBAL DIRECT",
    }
}

fn switch_node(
    path: PathBuf,
    previous: DesktopProfile,
    profile: DesktopProfile,
    child: Option<Child>,
) -> Result<(Option<Child>, String), (Option<Child>, String)> {
    let was_running = child.is_some();
    let presence = match check_presence(&previous) {
        Ok(presence) => presence,
        Err(error) => return Err((child, error)),
    };
    match presence {
        DaemonPresence::Occupied => Err((
            child,
            "Control endpoint is occupied by a daemon that did not authenticate".into(),
        )),
        DaemonPresence::Authenticated if !was_running => {
            if let Err(error) = save_profile(&path, &profile) {
                return Err((child, error.to_string()));
            }
            Ok((
                None,
                "Node saved; restart the externally managed daemon to apply it".into(),
            ))
        }
        DaemonPresence::Authenticated | DaemonPresence::Offline => {
            if let Some(child) = child
                && let Err((child, error)) = stop_owned_daemon(child, &previous)
            {
                return Err((Some(child), error));
            }
            if let Err(error) = save_profile(&path, &profile) {
                let child = start_daemon(&previous).ok().flatten();
                return Err((child, error.to_string()));
            }
            let child = match start_daemon(&profile) {
                Ok(child) => child,
                Err(error) => {
                    let _ = save_profile(&path, &previous);
                    let child = start_daemon(&previous).ok().flatten();
                    return Err((child, error));
                }
            };
            Ok((child, "Node selected and daemon started".into()))
        }
    }
}

fn check_presence(profile: &DesktopProfile) -> Result<DaemonPresence, String> {
    let address = profile
        .control_listen
        .parse::<SocketAddr>()
        .map_err(|error| error.to_string())?;
    let client = DaemonClient::new(
        address,
        default_control_socket(),
        profile.active_node().token_file.clone(),
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(client.presence())
        .map_err(|error| error.to_string())
}

fn ensure_daemon(path: &Path, profile: &DesktopProfile) -> Result<(Option<Child>, String), String> {
    match check_presence(profile)? {
        DaemonPresence::Authenticated => Ok((None, "Connected to existing daemon".into())),
        DaemonPresence::Occupied => Err("Control endpoint is occupied by another service".into()),
        DaemonPresence::Offline => {
            save_profile(path, profile).map_err(|error| error.to_string())?;
            Ok((start_daemon(profile)?, "Daemon started".into()))
        }
    }
}

fn start_daemon(profile: &DesktopProfile) -> Result<Option<Child>, String> {
    let log_path = default_state_dir().join("daemon.log");
    let mut log_options = std::fs::OpenOptions::new();
    log_options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        log_options.mode(0o600);
        if log_path.exists() {
            std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|error| error.to_string())?;
        }
    }
    // shortcut: this experimental launcher appends without rotation; use the desktop's bounded log writer before production.
    let log = log_options
        .open(log_path)
        .map_err(|error| error.to_string())?;
    Command::new(&profile.daemon_binary)
        .arg(&profile.daemon_config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .map(Some)
        .map_err(|error| error.to_string())
}

fn stop_owned_daemon(mut child: Child, profile: &DesktopProfile) -> Result<(), (Child, String)> {
    let address = match profile.control_listen.parse::<SocketAddr>() {
        Ok(address) => address,
        Err(error) => return Err((child, error.to_string())),
    };
    let client = DaemonClient::new(
        address,
        default_control_socket(),
        profile.active_node().token_file.clone(),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let runtime = match runtime {
        Ok(runtime) => runtime,
        Err(error) => return Err((child, error.to_string())),
    };
    if let Err(error) = runtime.block_on(client.shutdown()) {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => return Err((child, error.to_string())),
            Err(wait_error) => return Err((child, wait_error.to_string())),
        }
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(error) => return Err((child, error.to_string())),
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if let Err(error) = child.kill() {
        return Err((child, error.to_string()));
    }
    if let Err(error) = child.wait() {
        return Err((child, error.to_string()));
    }
    Ok(())
}

fn runtime_snapshot(profile: &DesktopProfile) -> RuntimeSnapshot {
    // shortcut: each refresh creates a small runtime, replace it before high-frequency polling.
    let result = profile
        .control_listen
        .parse()
        .map_err(|error| format!("invalid control address: {error}"))
        .and_then(|address| {
            let client = DaemonClient::new(
                address,
                default_control_socket(),
                profile.active_node().token_file.clone(),
            );
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(client.status())
                .map_err(|error| error.to_string())
        });
    match result {
        Ok(snapshot) => RuntimeSnapshot {
            status: format!("{:?}", snapshot.state).to_uppercase(),
            transport: format!("{:?}", snapshot.transport).to_uppercase(),
            active_flows: snapshot.active_flows.to_string(),
            traffic: format!(
                "{} up / {} down",
                format_bytes(snapshot.uploaded_bytes),
                format_bytes(snapshot.downloaded_bytes)
            ),
        },
        Err(error) => RuntimeSnapshot {
            status: "OFFLINE".into(),
            transport: "—".into(),
            active_flows: "0".into(),
            traffic: error,
        },
    }
}

fn persist_and_apply_mode(path: &Path, profile: &DesktopProfile) -> Result<(), (bool, String)> {
    save_profile(path, profile).map_err(|error| (false, error.to_string()))?;
    let address = profile
        .control_listen
        .parse()
        .map_err(|error| (true, format!("invalid control address: {error}")))?;
    let client = DaemonClient::new(
        address,
        default_control_socket(),
        profile.active_node().token_file.clone(),
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| (true, error.to_string()))?
        .block_on(client.update_rules(profile.effective_rules()))
        .map_err(|error| (true, error.to_string()))
}

fn probe_snapshot(node: helios_config::NodeConfig) -> Result<std::time::Duration, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(probe_node(node))
        .map_err(|error| error.to_string())
}

fn can_delete_node(probes: &[ProbeState], index: usize, active: usize) -> bool {
    probes.len() > 1
        && index < probes.len()
        && index != active
        && !probes
            .iter()
            .any(|probe| matches!(probe, ProbeState::Pending))
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

fn main() {
    let profile_path = default_state_dir().join("desktop.json");
    let profile = load_profile(&profile_path).unwrap_or_default();
    let node_count = profile.nodes.len();
    let runtime = runtime_snapshot(&profile);
    application().run(move |cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(980.0), px(760.0)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            |_, cx| {
                let dashboard = cx.new(|_| Dashboard {
                    profile_path,
                    profile,
                    runtime,
                    refreshing: false,
                    applying_mode: false,
                    mode_notice: None,
                    probes: vec![ProbeState::Untested; node_count],
                    probe_error: None,
                    add_node_error: None,
                    active_child: None,
                    node_action: None,
                    node_action_pending: false,
                });
                dashboard.update(cx, |dashboard, cx| dashboard.start_polling(cx));
                dashboard
            },
        )
        .expect("failed to open Helios GPUI window");
        cx.activate(true);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_cannot_shift_in_flight_probe_indices() {
        assert!(!can_delete_node(
            &[ProbeState::Untested, ProbeState::Pending],
            0,
            1
        ));
        assert!(!can_delete_node(
            &[ProbeState::Pending, ProbeState::Untested],
            1,
            0
        ));
        assert!(can_delete_node(
            &[ProbeState::Untested, ProbeState::Failed],
            1,
            0
        ));
        assert!(!can_delete_node(&[ProbeState::Untested], 0, 0));
        assert!(!can_delete_node(
            &[ProbeState::Untested, ProbeState::Failed],
            0,
            0
        ));
        assert!(!can_delete_node(
            &[ProbeState::Untested, ProbeState::Failed],
            2,
            0
        ));
    }

    #[test]
    fn dashboard_formats_modes_and_traffic() {
        assert_eq!(routing_mode(RoutingMode::Rule), "RULE");
        assert_eq!(routing_mode(RoutingMode::GlobalProxy), "GLOBAL PROXY");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(2048), "2.0 KiB");
        assert_eq!(format_bytes(2 * 1_048_576), "2.0 MiB");
        assert_eq!(
            probe_label(&ProbeState::Succeeded(std::time::Duration::from_micros(
                12_900
            )))
            .0,
            "12 ms"
        );
    }
}
