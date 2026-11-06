// Keep preview rendering on the native main thread, without starting app services.
#![allow(dead_code)]
#[path = "../src/i18n.rs"]
mod i18n;

mod preview {
    include!("../src/desktop.rs");

    pub fn show() -> Result<(), AnyError> {
        struct Preview(HeliosApp, Instant);
        impl eframe::App for Preview {
            fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
                i18n::set_language(self.0.profile.language);
                self.0.content(ui);
                ui.ctx().request_repaint_after(Duration::from_millis(100));
                if self.1.elapsed() > Duration::from_secs(120) {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
        let directory = std::env::temp_dir().join(format!("helios-preview-{}", std::process::id()));
        let mut profile = DesktopProfile {
            auto_start_daemon: false,
            daemon_binary: directory.join("missing-daemon"),
            daemon_config: directory.join("daemon.toml"),
            helper_binary: directory.join("missing-helper"),
            helper_config: directory.join("helper.toml"),
            ..Default::default()
        };
        let mut ipv6 = profile.nodes[0].clone();
        ipv6.name = "IPv6 VPS · Toronto".into();
        ipv6.server = "[2a12:bec0:16e:6d0::]:24443".into();
        profile.nodes.push(ipv6);
        eframe::run_native(
            "Helios UI preview",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size([980.0, 760.0])
                    .with_min_inner_size([760.0, 600.0]),
                renderer: eframe::Renderer::Glow,
                ..Default::default()
            },
            Box::new(move |cc| {
                configure_style(&cc.egui_ctx);
                let mut app = HeliosApp::from_profile(directory.join("desktop.json"), profile);
                match std::env::var("HELIOS_PREVIEW_PAGE").as_deref() {
                    Ok("nodes") => app.page = Page::Node,
                    Ok("rules") => app.page = Page::Rules,
                    Ok("diagnostics") => app.page = Page::Diagnostics,
                    Ok("settings") => app.page = Page::Settings,
                    _ => {}
                }
                if std::env::var_os("HELIOS_PREVIEW_IMPORT").is_some() {
                    app.page = Page::Node;
                    app.open_node_import = true;
                }
                if std::env::var_os("HELIOS_PREVIEW_EDITOR").is_some() {
                    app.page = Page::Node;
                    app.node_editor = Some(NodeEditor {
                        index: Some(0),
                        node: app.profile.nodes[0].clone(),
                        error: None,
                    });
                }
                Ok(Box::new(Preview(app, Instant::now())))
            }),
        )
        .map_err(|error| std::io::Error::other(error.to_string()).into())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    preview::show()
}
