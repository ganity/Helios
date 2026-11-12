//! Process-local counters and bounded diagnostics; never records credentials.
use std::sync::{
    Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

static UPLOADED: AtomicU64 = AtomicU64::new(0);
static DOWNLOADED: AtomicU64 = AtomicU64::new(0);
static FLOWS: AtomicUsize = AtomicUsize::new(0);
static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub fn reset() {
    UPLOADED.store(0, Ordering::Relaxed);
    DOWNLOADED.store(0, Ordering::Relaxed);
    record("隧道已启动".into());
}
pub fn snapshot() -> (u64, u64, usize) {
    (
        UPLOADED.load(Ordering::Relaxed),
        DOWNLOADED.load(Ordering::Relaxed),
        FLOWS.load(Ordering::Relaxed),
    )
}

/// The iOS app receives counters from its separate Packet Tunnel process.
pub fn remote_snapshot(up: u64, down: u64, active: usize, logs: &str) {
    UPLOADED.store(up, Ordering::Relaxed);
    DOWNLOADED.store(down, Ordering::Relaxed);
    FLOWS.store(active, Ordering::Relaxed);
    *LOG.lock().unwrap_or_else(|e| e.into_inner()) = logs
        .lines()
        .rev()
        .take(32)
        .map(|line| line.chars().take(256).collect())
        .collect::<Vec<String>>()
        .into_iter()
        .rev()
        .collect();
}
pub(crate) fn upload(bytes: usize) {
    UPLOADED.fetch_add(bytes as u64, Ordering::Relaxed);
}
pub(crate) fn download(bytes: usize) {
    DOWNLOADED.fetch_add(bytes as u64, Ordering::Relaxed);
}
pub(crate) struct Flow;
impl Flow {
    pub fn new() -> Self {
        FLOWS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}
impl Drop for Flow {
    fn drop(&mut self) {
        FLOWS.fetch_sub(1, Ordering::Relaxed);
    }
}
pub fn record(message: String) {
    let mut log = LOG.lock().unwrap_or_else(|e| e.into_inner());
    if log.len() == 32 {
        log.remove(0);
    }
    log.push(message.chars().take(256).collect());
}
pub fn logs() -> String {
    LOG.lock().unwrap_or_else(|e| e.into_inner()).join("\n")
}
pub fn clear() {
    LOG.lock().unwrap_or_else(|e| e.into_inner()).clear();
}
pub fn bytes(value: u64) -> String {
    if value < 1024 {
        format!("{value} B")
    } else if value < 1024 * 1024 {
        format!("{:.1} KB", value as f64 / 1024.0)
    } else if value < 1024 * 1024 * 1024 {
        format!("{:.1} MB", value as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", value as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn traffic_units_are_readable() {
        assert_eq!(super::bytes(0), "0 B");
        assert_eq!(super::bytes(1536), "1.5 KB");
        assert_eq!(super::bytes(2 * 1024 * 1024), "2.0 MB");
    }
}
