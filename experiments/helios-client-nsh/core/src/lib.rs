//! Mobile data plane without a UI framework dependency.
#[cfg(feature = "ios-ffi")]
pub mod ios_ffi;

#[cfg(test)]
pub(crate) static TUNNEL_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
pub mod connection;
pub mod node_store;
pub mod packet_device;
pub mod session;
pub mod settings;
#[cfg(unix)]
pub mod socket;
pub mod telemetry;
pub mod tunnel;
