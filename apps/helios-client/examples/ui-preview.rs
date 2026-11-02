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
        let profile = DesktopProfile {
            auto_start_daemon: false,
            daemon_binary: directory.join("missing-daemon"),
            daemon_config: directory.join("daemon.toml"),
            helper_binary: directory.join("missing-helper"),
            helper_config: directory.join("helper.toml"),
            ..Default::default()
        };
        eframe::run_native(
            "Helios UI preview",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size([660.0, 660.0])
                    .with_min_inner_size([520.0, 540.0]),
                renderer: eframe::Renderer::Glow,
                ..Default::default()
            },
            Box::new(move |cc| {
                configure_style(&cc.egui_ctx);
                Ok(Box::new(Preview(
                    HeliosApp::from_profile(directory.join("desktop.json"), profile),
                    Instant::now(),
                )))
            }),
        )
        .map_err(|error| std::io::Error::other(error.to_string()).into())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    preview::show()
}
