//! Main-app bridge. Swift owns system VPN preferences and the extension lifecycle.
use std::{
    ffi::{CStr, CString, c_char},
    sync::Mutex,
};

type Command = extern "C" fn(*const c_char);
static COMMAND: Mutex<Option<Command>> = Mutex::new(None);
static STATUS: Mutex<String> = Mutex::new(String::new());
static LINK: Mutex<Option<String>> = Mutex::new(None);

#[unsafe(no_mangle)]
pub extern "C" fn helios_ios_register(callback: Option<Command>) {
    *COMMAND.lock().unwrap_or_else(|e| e.into_inner()) = callback;
}

fn command(value: serde_json::Value) -> Result<(), String> {
    let callback = COMMAND
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .copied()
        .ok_or("iOS VPN 宿主尚未初始化")?;
    let json = CString::new(value.to_string()).map_err(|e| e.to_string())?;
    callback(json.as_ptr());
    Ok(())
}
pub fn request_connect(
    node: &helios_client_model::NodeProfile,
    root: &std::path::Path,
) -> Result<(), String> {
    let settings = helios_mobile_core::settings::Settings::load(root)?;
    let nodes = crate::node_store::load(root)?;
    command(
        serde_json::json!({"command": "connect", "node": node, "settings": settings, "nodes": nodes}),
    )
}
pub fn request_disconnect() -> Result<(), String> {
    command(serde_json::json!({"command": "disconnect"}))
}
pub fn request_clear_logs() -> Result<(), String> {
    command(serde_json::json!({"command": "clearLogs"}))
}
pub fn status() -> String {
    let status = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    if status.is_empty() {
        "正在读取系统 VPN 状态".into()
    } else {
        status.clone()
    }
}
pub fn take_pending_link() -> Option<String> {
    LINK.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// # Safety
/// `json` must point to a valid UTF-8, NUL-terminated string for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn helios_ios_update(json: *const c_char) {
    if json.is_null() {
        return;
    }
    // SAFETY: Swift keeps the C string alive for this call.
    let Ok(json) = unsafe { CStr::from_ptr(json) }.to_str() else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return;
    };
    if let Some(status) = value["status"].as_str() {
        *STATUS.lock().unwrap_or_else(|e| e.into_inner()) = status.chars().take(256).collect();
    }
    if let Some(link) = value["link"].as_str().filter(|link| link.len() <= 16384) {
        *LINK.lock().unwrap_or_else(|e| e.into_inner()) = Some(link.into());
    }
    if let Some(snapshot) = value.get("snapshot") {
        crate::telemetry::remote_snapshot(
            snapshot["uploaded"].as_u64().unwrap_or(0),
            snapshot["downloaded"].as_u64().unwrap_or(0),
            snapshot["active"].as_u64().unwrap_or(0) as usize,
            snapshot["logs"].as_str().unwrap_or_default(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static REQUEST: Mutex<String> = Mutex::new(String::new());
    extern "C" fn receive(pointer: *const c_char) {
        // SAFETY: command borrows a live CString for this callback.
        *REQUEST.lock().unwrap() = unsafe { CStr::from_ptr(pointer) }.to_str().unwrap().into();
    }
    #[test]
    fn bridge_copies_commands_and_accepts_status_and_links() {
        helios_ios_register(Some(receive));
        request_disconnect().unwrap();
        let command: serde_json::Value = serde_json::from_str(&REQUEST.lock().unwrap()).unwrap();
        assert_eq!(command["command"], "disconnect");
        let status = CString::new(r#"{"status":"已连接","link":"helios://test"}"#).unwrap();
        // SAFETY: the CString lives for the synchronous call.
        unsafe {
            helios_ios_update(status.as_ptr());
        }
        assert_eq!(super::status(), "已连接");
        assert_eq!(take_pending_link().as_deref(), Some("helios://test"));
        assert!(take_pending_link().is_none());
        helios_ios_register(None);
        assert!(request_disconnect().is_err());
    }
}
