use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::Sender,
};

use ksni::{Tray, blocking::TrayMethods};

use super::{Event, TrayAction};
use crate::i18n::t;

pub(super) struct LinuxTray {
    handle: ksni::blocking::Handle<TrayState>,
    available: Arc<AtomicBool>,
}

impl LinuxTray {
    pub(super) fn refresh_menu(&self) {
        self.handle.update(|_| {});
    }
    pub(super) fn is_available(&self) -> bool {
        self.available.load(Ordering::Acquire) && !self.handle.is_closed()
    }
}

impl Drop for LinuxTray {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

struct TrayState {
    events: Sender<Event>,
    available: Arc<AtomicBool>,
}

impl TrayState {
    fn send(&self, action: TrayAction) {
        let _ = self.events.send(Event::TrayAction(action));
    }
}

impl Tray for TrayState {
    fn id(&self) -> String {
        "helios-client".into()
    }

    fn title(&self) -> String {
        t("Helios · 曜光").into()
    }

    fn icon_name(&self) -> String {
        "helios".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let (mut data, width, height) = super::tray_icon_rgba();
        for pixel in data.chunks_exact_mut(4) {
            pixel.rotate_right(1);
        }
        vec![ksni::Icon {
            width: width as i32,
            height: height as i32,
            data,
        }]
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(TrayAction::Show);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        [
            (t("显示 Helios"), TrayAction::Show),
            (t("连接 / 断开"), TrayAction::ToggleDaemon),
            (t("退出 Helios"), TrayAction::Quit),
        ]
        .into_iter()
        .map(|(label, action)| {
            ksni::menu::StandardItem {
                label: label.into(),
                activate: Box::new(move |tray: &mut Self| tray.send(action)),
                ..Default::default()
            }
            .into()
        })
        .collect()
    }

    fn watcher_online(&self) {
        self.available.store(true, Ordering::Release);
    }

    fn watcher_offline(&self, _reason: ksni::OfflineReason) -> bool {
        self.available.store(false, Ordering::Release);
        self.send(TrayAction::Show);
        true
    }
}

pub(super) fn start(events: Sender<Event>) {
    std::thread::spawn(move || {
        let available = Arc::new(AtomicBool::new(true));
        let tray = TrayState {
            events: events.clone(),
            available: available.clone(),
        };
        let result = tray
            .spawn()
            .map(|handle| LinuxTray { handle, available })
            .map_err(|error| error.to_string());
        let _ = events.send(Event::TrayReady(result));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Watcher(Sender<String>);

    #[zbus::interface(name = "org.kde.StatusNotifierWatcher")]
    impl Watcher {
        fn register_status_notifier_item(&self, service: String) {
            self.0.send(service).unwrap();
        }

        #[zbus(property)]
        fn is_status_notifier_host_registered(&self) -> bool {
            true
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires HELIOS_ISOLATED_TRAY_TEST=1 and a private dbus-run-session"]
    async fn isolated_sni_registration_activation_and_host_loss() {
        assert_eq!(
            std::env::var("HELIOS_ISOLATED_TRAY_TEST").as_deref(),
            Ok("1")
        );
        let (events, receiver) = std::sync::mpsc::channel();
        start(events.clone());
        assert!(matches!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap(),
            Event::TrayReady(Err(_))
        ));

        let (registered, registrations) = std::sync::mpsc::channel();
        let watcher = zbus::connection::Builder::session()
            .unwrap()
            .name("org.kde.StatusNotifierWatcher")
            .unwrap()
            .serve_at("/StatusNotifierWatcher", Watcher(registered))
            .unwrap()
            .build()
            .await
            .unwrap();
        start(events);
        let Event::TrayReady(Ok(tray)) = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap()
        else {
            panic!("tray did not register")
        };
        assert!(tray.is_available());
        let service = registrations
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        let connection = zbus::Connection::session().await.unwrap();
        let proxy = zbus::Proxy::new(
            &connection,
            service.as_str(),
            "/StatusNotifierItem",
            "org.kde.StatusNotifierItem",
        )
        .await
        .unwrap();
        let _: () = proxy.call("Activate", &(0i32, 0i32)).await.unwrap();
        assert!(matches!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap(),
            Event::TrayAction(TrayAction::Show)
        ));
        let menu_path: zbus::zvariant::OwnedObjectPath = proxy.get_property("Menu").await.unwrap();
        let menu = zbus::Proxy::new(
            &connection,
            service.clone(),
            menu_path,
            "com.canonical.dbusmenu",
        )
        .await
        .unwrap();
        let items: Vec<(
            i32,
            std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
        )> = menu
            .call("GetGroupProperties", &(Vec::<i32>::new(), vec!["label"]))
            .await
            .unwrap();
        for (label, action) in [
            (t("显示 Helios"), TrayAction::Show),
            (t("连接 / 断开"), TrayAction::ToggleDaemon),
            (t("退出 Helios"), TrayAction::Quit),
        ] {
            let (id, _) = items
                .iter()
                .find(|(_, properties)| {
                    properties
                        .get("label")
                        .and_then(|value| <&str>::try_from(value).ok())
                        == Some(label)
                })
                .expect("missing menu action");
            let _: () = menu
                .call(
                    "Event",
                    &(*id, "clicked", zbus::zvariant::Value::from(0i32), 0u32),
                )
                .await
                .unwrap();
            assert!(matches!(
                receiver.recv_timeout(std::time::Duration::from_secs(10)).unwrap(),
                Event::TrayAction(received) if received == action
            ));
        }
        watcher.close().await.unwrap();
        assert!(matches!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap(),
            Event::TrayAction(TrayAction::Show)
        ));
        assert!(!tray.is_available());
        tokio::task::spawn_blocking(move || {
            tray.handle.shutdown().wait();
        })
        .await
        .unwrap();
        assert!(
            proxy
                .call::<_, _, ()>("Activate", &(0i32, 0i32))
                .await
                .is_err()
        );
    }

    #[test]
    fn menu_and_activation_use_the_same_actions_and_offline_restores_window() {
        let (events, receiver) = std::sync::mpsc::channel();
        let available = Arc::new(AtomicBool::new(true));
        let mut tray = TrayState { events, available };
        let icon = tray.icon_pixmap().remove(0);
        assert_eq!(icon.data.len(), (icon.width * icon.height * 4) as usize);
        let center = ((icon.height / 2 * icon.width + icon.width / 2) * 4) as usize;
        assert_eq!(&icon.data[center..center + 4], &[255, 255, 205, 61]);
        tray.activate(0, 0);
        assert!(matches!(
            receiver.recv().unwrap(),
            Event::TrayAction(TrayAction::Show)
        ));
        for (item, expected) in tray.menu().into_iter().zip([
            TrayAction::Show,
            TrayAction::ToggleDaemon,
            TrayAction::Quit,
        ]) {
            let ksni::MenuItem::Standard(item) = item else {
                panic!("expected action item")
            };
            (item.activate)(&mut tray);
            assert!(
                matches!(receiver.recv().unwrap(), Event::TrayAction(action) if action == expected)
            );
        }
        assert!(tray.watcher_offline(ksni::OfflineReason::No));
        assert!(!tray.available.load(Ordering::Acquire));
        assert!(matches!(
            receiver.recv().unwrap(),
            Event::TrayAction(TrayAction::Show)
        ));
        tray.watcher_online();
        assert!(tray.available.load(Ordering::Acquire));
    }
}
