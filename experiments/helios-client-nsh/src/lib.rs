//! Shared NSH mobile UI with a platform-provided VPN host.
use helios_config::ConnectionLink;
use nsh_base::{button, input, theme};
use nsh_core::prelude::*;

#[cfg(target_os = "android")]
pub mod android;
#[cfg(any(test, target_os = "ios"))]
pub mod ios;
#[cfg(unix)]
pub use helios_mobile_core::socket;
pub use helios_mobile_core::{node_store, session, telemetry, tunnel};

pub fn node_label(link: &str) -> Result<String, String> {
    ConnectionLink::decode(link)
        .map(|node| format!("{} ({})", node.name, node.server))
        .map_err(|error| error.to_string())
}

#[derive(Clone, PartialEq)]
struct NodeChoice {
    id: String,
    name: String,
    server: String,
}

fn node_list(nodes: &[helios_client_model::NodeProfile]) -> Vec<NodeChoice> {
    nodes
        .iter()
        .map(|node| NodeChoice {
            id: node.token_file.to_string_lossy().into_owned(),
            name: node.name.clone(),
            server: node.server.clone(),
        })
        .collect()
}

fn field(label: &'static str, value: Signal<String>) -> impl IntoElement {
    view()
        .gap_2()
        .child(
            text(label)
                .text_xs()
                .text_color(move || theme().muted_foreground),
        )
        .child(
            input()
                .value(move || value.get())
                .on_change(move |v: &str| value.set(v.to_owned()))
                .px_3()
                .py_3()
                .rounded_xl()
                .border_1()
                .border_color(move || theme().border)
                .text_color(move || theme().foreground),
        )
}

fn setting_toggle(label: &'static str, value: Signal<bool>) -> impl IntoElement {
    button()
        .on_press(move || value.set(!value.get_untracked()))
        .py_3()
        .child(
            text(move || format!("{} {label}", if value.get() { "●" } else { "○" }))
                .text_color(move || theme().primary),
        )
}

fn selected_node(
    path: Option<&std::path::Path>,
    id: &str,
) -> Result<helios_client_model::NodeProfile, String> {
    let path = path.ok_or_else(|| "应用存储尚未初始化".to_owned())?;
    node_store::load(path)?
        .into_iter()
        .find(|node| node.token_file.to_string_lossy() == id)
        .ok_or_else(|| "请先选择节点".to_owned())
}

struct ProbeSockets;
impl tunnel::Connector for ProbeSockets {
    fn tcp(
        &self,
        address: std::net::SocketAddr,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<tokio::net::TcpStream>> + Send + '_>,
    > {
        #[cfg(target_os = "android")]
        {
            Box::pin(android::probe_socket(address))
        }
        #[cfg(not(target_os = "android"))]
        {
            Box::pin(socket::connect_tcp(
                address,
                std::time::Duration::from_secs(10),
                |_| Ok(()),
            ))
        }
    }
    fn udp(
        &self,
        ipv6: bool,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<tokio::net::UdpSocket>> + Send + '_>,
    > {
        #[cfg(target_os = "android")]
        {
            Box::pin(android::probe_udp(ipv6))
        }
        #[cfg(not(target_os = "android"))]
        {
            Box::pin(socket::bind_udp(ipv6, |_| Ok(())))
        }
    }
}

async fn probe_node(node: helios_client_model::NodeProfile) -> Result<String, String> {
    let start = std::time::Instant::now();
    let address = node
        .server
        .parse()
        .map_err(|e| format!("服务器地址无效：{e}"))?;
    session::Session::from_node(&node)
        .map_err(|e| e.to_string())?
        .check(&ProbeSockets, address, std::time::Duration::from_secs(10))
        .await
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "{} · 认证延迟 {:.0} ms（含握手及可能的回退）",
        node.name,
        start.elapsed().as_secs_f64() * 1000.0
    ))
}

#[native_module("helios/prototype")]
fn native(registry: &mut Registry) {
    registry.register::<App>();
}

#[component]
pub fn App() -> impl IntoElement {
    set_tokens(
        nsh_base::tokens_of(Some(include_str!("../theme.json"))).expect("valid bundled theme"),
    );
    let draft = signal(String::new());
    let state_dir = data_dir();
    let loaded_settings = state_dir
        .as_deref()
        .map(helios_mobile_core::settings::Settings::load)
        .transpose();
    let settings_error = loaded_settings.as_ref().err().cloned();
    let settings = loaded_settings.ok().flatten().unwrap_or_default();
    let dns = signal(settings.dns.to_string());
    let auto_reconnect = signal(settings.auto_reconnect);
    let auto_failover = signal(settings.auto_failover);
    let settings_dir = state_dir.clone();
    let (initial_nodes, initial_result) = match &state_dir {
        Some(path) => match node_store::load(path) {
            Ok(nodes) => (nodes, String::new()),
            Err(error) => (Vec::new(), format!("读取节点失败：{error}")),
        },
        None => (Vec::new(), "应用存储尚未初始化".into()),
    };
    let result = signal(settings_error.unwrap_or(initial_result));
    let nodes = signal(node_list(&initial_nodes));
    let initial_node = state_dir
        .as_deref()
        .and_then(|path| node_store::selection(path, &initial_nodes));
    let selected = signal(
        initial_node
            .map(|n| n.token_file.to_string_lossy().into_owned())
            .unwrap_or_default(),
    );
    let edit_quic = signal(
        initial_node
            .is_some_and(|n| n.preferred_transport == helios_config::TransportPreference::Quic),
    );
    let edit_name = signal(initial_node.map(|n| n.name.clone()).unwrap_or_default());
    let edit_server = signal(initial_node.map(|n| n.server.clone()).unwrap_or_default());
    let edit_identity = signal(
        initial_node
            .map(|n| n.server_name.clone())
            .unwrap_or_default(),
    );
    let edit_credential = signal(
        initial_node
            .map(|n| n.credential_id.clone())
            .unwrap_or_default(),
    );
    let confirming_delete = signal(false);
    let testing = signal(false);
    let connection_status = signal(String::from("未连接"));
    let traffic = signal(String::from("↑ 0 B/s   ↓ 0 B/s"));
    let totals = signal(String::from("上传 0 B / 下载 0 B · 0 个连接"));
    let diagnostics = signal(telemetry::logs());
    let previous = stored((std::time::Instant::now(), 0u64, 0u64));
    set_interval(std::time::Duration::from_millis(500), move || {
        #[cfg(target_os = "ios")]
        connection_status.set(ios::status());
        #[cfg(target_os = "android")]
        connection_status
            .set(android::vpn_status().unwrap_or_else(|e| format!("状态读取失败：{e}")));
        #[cfg(any(target_os = "android", target_os = "ios"))]
        if let Some(link) = {
            #[cfg(target_os = "android")]
            {
                android::take_pending_link()
            }
            #[cfg(target_os = "ios")]
            {
                ios::take_pending_link()
            }
        } {
            match node_label(&link) {
                Ok(label) => {
                    draft.set(link);
                    result.set(format!("收到 {label}，请点击添加节点确认导入"));
                }
                Err(error) => result.set(format!("无效的节点链接：{error}")),
            }
        }
        let (up, down, active) = telemetry::snapshot();
        let now = std::time::Instant::now();
        let (last, last_up, last_down) = previous.replace((now, up, down));
        let elapsed = now.duration_since(last).as_secs_f64().max(0.001);
        traffic.set(format!(
            "↑ {}/s   ↓ {}/s",
            telemetry::bytes((up.saturating_sub(last_up) as f64 / elapsed) as u64),
            telemetry::bytes((down.saturating_sub(last_down) as f64 / elapsed) as u64)
        ));
        totals.set(format!(
            "上传 {} / 下载 {} · {active} 个连接",
            telemetry::bytes(up),
            telemetry::bytes(down)
        ));
        diagnostics.set(telemetry::logs());
    });
    let connect_dir = state_dir.clone();
    let select_dir = state_dir.clone();
    let import_dir = state_dir.clone();
    let save_dir = state_dir.clone();
    let delete_dir = state_dir.clone();
    let probe_dir = state_dir;
    view().flex_1().bg(move || theme().background).child(
        scroll().flex_1().scrollbar(false).child(
            view()
                .gap_4()
                .p_6()
                .child(
                    text("HELIOS / 曜光")
                        .text_sm()
                        .text_color(move || theme().primary),
                )
                .child(
                    text(move || connection_status.get())
                        .text_2xl()
                        .text_color(move || theme().foreground),
                )
                .child(
                    text("安全连接，由你掌控。IPv4 + IPv6 / QUIC + TLS")
                        .text_sm()
                        .text_color(move || theme().muted_foreground),
                )
                .child(
                    text(move || traffic.get())
                        .text_xl()
                        .text_color(move || theme().primary),
                )
                .child(
                    text(move || totals.get())
                        .text_xs()
                        .text_color(move || theme().muted_foreground),
                )
                .child(
                    view()
                        .flex_row()
                        .gap_3()
                        .child(
                            button()
                                .on_press(move || {
                                    result.set(
                                        match selected_node(
                                            connect_dir.as_deref(),
                                            &selected.get_untracked(),
                                        )
                                        .and_then(|node| request_connect(&node, connect_dir.as_deref()))
                                        {
                                            Ok(()) => "已请求连接所选节点".into(),
                                            Err(error) => error,
                                        },
                                    );
                                })
                                .px_4()
                                .py_3()
                                .rounded_xl()
                                .bg(move || theme().primary)
                                .child(text("连接").text_color(move || theme().primary_foreground)),
                        )
                        .child(
                            button()
                                .on_press(move || {
                                    result.set(match request_disconnect() {
                                        Ok(()) => "已请求断开".into(),
                                        Err(error) => error,
                                    });
                                })
                                .px_4()
                                .py_3()
                                .rounded_xl()
                                .bg(move || theme().secondary)
                                .child(text("断开").text_color(move || theme().foreground)),
                        ),
                )
                .child(
                    text(move || result.get())
                        .text_sm()
                        .text_color(move || theme().muted_foreground),
                )
                .child(
                    text("我的节点")
                        .text_xl()
                        .text_color(move || theme().foreground),
                )
                .child(each(
                    move || nodes.get(),
                    |node| node.id.clone(),
                    move |node, _| {
                        let path = select_dir.clone();
                        button()
                            .on_press(move || {
                                let choice = node.get_untracked();
                                match selected_node(path.as_deref(), &choice.id) {
                                    Ok(saved) => {
                                        if let Some(path) = &path
                                            && let Err(error) =
                                                node_store::select(path, &saved.token_file)
                                        {
                                            result.set(format!("记住选择失败：{error}"));
                                            return;
                                        }
                                        selected.set(choice.id);
                                        edit_quic.set(saved.preferred_transport == helios_config::TransportPreference::Quic);
                                        edit_name.set(saved.name);
                                        edit_server.set(saved.server);
                                        edit_identity.set(saved.server_name);
                                        edit_credential.set(saved.credential_id);
                                        confirming_delete.set(false);
                                    }
                                    Err(e) => result.set(e),
                                }
                            })
                            .p_4()
                            .rounded_xl()
                            .border_1()
                            .border_color(move || {
                                if selected.get() == node.get().id {
                                    theme().primary
                                } else {
                                    theme().border
                                }
                            })
                            .bg(move || theme().card)
                            .child(
                                view()
                                    .gap_2()
                                    .child(
                                        text(move || node.get().name)
                                            .text_color(move || theme().foreground),
                                    )
                                    .child(
                                        text(move || node.get().server)
                                            .text_xs()
                                            .text_color(move || theme().muted_foreground),
                                    ),
                            )
                    },
                ))
                .child(
                    button()
                        .on_press(move || {
                            if testing.get_untracked() {
                                return;
                            }
                            match selected_node(probe_dir.as_deref(), &selected.get_untracked()) {
                                Ok(node) => {
                                    testing.set(true);
                                    result.set("正在测试所选节点…".into());
                                    spawn(async move {
                                        result.set(match background(probe_node(node)).await {
                                            Ok(Ok(message)) => message,
                                            Ok(Err(error)) => format!("测试失败：{error}"),
                                            Err(error) => format!("测试任务失败：{error}"),
                                        });
                                        testing.set(false);
                                    });
                                }
                                Err(error) => result.set(error),
                            }
                        })
                        .py_3()
                        .child(
                            text(move || {
                                if testing.get() {
                                    "正在测试…"
                                } else {
                                    "测试所选节点延迟"
                                }
                            })
                            .text_color(move || theme().primary),
                        ),
                )
                .child(
                    text("导入节点")
                        .text_xl()
                        .text_color(move || theme().foreground),
                )
                .child(
                    input()
                        .placeholder("helios://v1/...")
                        .value(move || draft.get())
                        .on_change(move |value: &str| draft.set(value.to_owned()))
                        .px_3()
                        .py_2()
                        .border_1()
                        .border_color(move || theme().input)
                        .text_color(move || theme().foreground),
                )
                .child(
                    button()
                        .on_press(move || {
                            let imported = import_dir
                                .as_ref()
                                .ok_or_else(|| "应用存储尚未初始化".to_owned())
                                .and_then(|path| {
                                    let node = node_store::import(path, &draft.get_untracked())?;
                                    node_store::select(path, &node.token_file)?;
                                    selected.set(node.token_file.to_string_lossy().into_owned());
                                    edit_quic.set(node.preferred_transport == helios_config::TransportPreference::Quic);
                                    edit_name.set(node.name);
                                    edit_server.set(node.server);
                                    edit_identity.set(node.server_name);
                                    edit_credential.set(node.credential_id);
                                    confirming_delete.set(false);
                                    node_store::load(path)
                                });
                            match imported {
                                Ok(saved_nodes) => {
                                    nodes.set(node_list(&saved_nodes));
                                    result.set("节点已保存".into());
                                    draft.set(String::new());
                                }
                                Err(error) => result.set(format!("保存节点失败：{error}")),
                            }
                        })
                        .px_4()
                        .py_2()
                        .bg(move || theme().primary)
                        .child(text("添加节点").text_color(move || theme().primary_foreground)),
                )
                .child(
                    text("编辑所选节点")
                        .text_xl()
                        .text_color(move || theme().foreground),
                )
                .child(field("节点名称", edit_name))
                .child(field("服务器地址（IPv6 使用 [地址]:端口）", edit_server))
                .child(field("证书名称（应与导入证书匹配）", edit_identity))
                .child(field("凭据标识", edit_credential))
                .child(setting_toggle("优先 QUIC（失败时回退 TLS）", edit_quic))
                .child(
                    text("证书与 token 已随链接导入，无需手动填写。修改将在下次连接生效。")
                        .text_xs()
                        .text_color(move || theme().muted_foreground),
                )
                .child(
                    button()
                        .on_press(move || {
                            let saved = (|| {
                                let mut node =
                                    selected_node(save_dir.as_deref(), &selected.get_untracked())?;
                                node.preferred_transport = if edit_quic.get_untracked() { helios_config::TransportPreference::Quic } else { helios_config::TransportPreference::Tls };
                                node.name = edit_name.get_untracked();
                                node.server = edit_server.get_untracked();
                                node.server_name = edit_identity.get_untracked();
                                node.credential_id = edit_credential.get_untracked();
                                let path = save_dir.as_deref().ok_or("应用存储尚未初始化")?;
                                node_store::update(path, &node)?;
                                nodes.set(node_list(&node_store::load(path)?));
                                Ok::<_, String>(())
                            })();
                            result.set(match saved {
                                Ok(()) => "修改已保存，下次连接生效".into(),
                                Err(e) => format!("保存失败：{e}"),
                            });
                        })
                        .py_3()
                        .child(text("保存修改").text_color(move || theme().primary)),
                )
                .child(
                    button()
                        .on_press(move || {
                            if !confirming_delete.get_untracked() {
                                confirming_delete.set(true);
                                return;
                            }
                            let removed = (|| {
                                let path = delete_dir.as_deref().ok_or("应用存储尚未初始化")?;
                                node_store::remove(
                                    path,
                                    std::path::Path::new(&selected.get_untracked()),
                                )?;
                                nodes.set(node_list(&node_store::load(path)?));
                                selected.set(String::new());
                                edit_name.set(String::new());
                                edit_server.set(String::new());
                                edit_identity.set(String::new());
                                edit_credential.set(String::new());
                                confirming_delete.set(false);
                                Ok::<_, String>(())
                            })();
                            result.set(match removed {
                                Ok(()) => "节点已删除；当前连接不受影响".into(),
                                Err(e) => format!("删除失败：{e}"),
                            });
                        })
                        .py_3()
                        .child(
                            text(move || {
                                if confirming_delete.get() {
                                    "再次点击确认删除节点"
                                } else {
                                    "删除所选节点"
                                }
                            })
                            .text_color(move || theme().destructive),
                        ),
                )
                .child(if cfg!(target_os = "ios") { Some(view().gap_3()
                    .child(text("连接设置 · iOS").text_xl().text_color(move || theme().foreground))
                    .child(field("DNS 上游（经服务端访问，支持 IPv6）", dns))
                    .child(setting_toggle("自动重连 / 系统按需连接", auto_reconnect))
                    .child(setting_toggle("节点故障时切换备用节点", auto_failover))
                    .child(text("保存后点击连接生效。切换节点会重建 VPN，已有连接需要重新建立。").text_xs().text_color(move || theme().muted_foreground))
                    .child(button().on_press(move || {
                        let saved = (|| {
                            let root = settings_dir.as_deref().ok_or("应用存储尚未初始化")?;
                            let settings = helios_mobile_core::settings::Settings {
                                dns: dns.get_untracked().trim().parse().map_err(|_| "DNS 地址无效".to_owned())?,
                                auto_reconnect: auto_reconnect.get_untracked(), auto_failover: auto_failover.get_untracked(),
                            };
                            settings.save(root)
                        })();
                        result.set(match saved { Ok(()) => "连接设置已保存，点击连接生效".into(), Err(e) => e });
                    }).py_3().child(text("保存连接设置").text_color(move || theme().primary)))) } else { None })
                .child(
                    text("诊断日志")
                        .text_xl()
                        .text_color(move || theme().foreground),
                )
                .child(
                    text(move || diagnostics.get())
                        .text_xs()
                        .text_color(move || theme().muted_foreground),
                )
                .child(
                    button()
                        .on_press(move || {
                            telemetry::clear();
                            #[cfg(target_os = "ios")]
                            if let Err(error) = ios::request_clear_logs() {
                                result.set(error);
                            }
                            diagnostics.set(String::new());
                        })
                        .py_3()
                        .child(text("清空日志").text_color(move || theme().muted_foreground)),
                ),
        ),
    )
}

fn request_connect(
    node: &helios_client_model::NodeProfile,
    root: Option<&std::path::Path>,
) -> Result<(), String> {
    let _ = root;
    #[cfg(target_os = "ios")]
    {
        ios::request_connect(node, root.ok_or("应用存储尚未初始化")?)
    }
    #[cfg(target_os = "android")]
    {
        android::request_connect(&serde_json::to_string(node).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let _ = node;
        Err("此平台尚未接入 VPN 宿主".into())
    }
}

fn request_disconnect() -> Result<(), String> {
    #[cfg(target_os = "ios")]
    {
        ios::request_disconnect()
    }
    #[cfg(target_os = "android")]
    {
        android::request_disconnect().map_err(|e| e.to_string())
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        Err("此平台尚未接入 VPN 宿主".into())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn bundled_theme_parses() {
        nsh_base::tokens_of(Some(include_str!("../theme.json"))).unwrap();
    }

    #[test]
    fn rejects_non_helios_links() {
        assert!(super::node_label("https://example.com").is_err());
    }
}
