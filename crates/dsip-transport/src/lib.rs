//! `dsip-transport` — the `ws/1.0` signaling binding and the endpoint agent.
//!
//! Spec: sections owned by this crate — §13.1 (binding requirements), §13.2
//! (`ws/1.0`: wss only, one envelope per text frame, 65,536-byte cap, `hello`
//! binding with `in_reply_to` anti-splicing, keepalive, reconnection), §20.5
//! (connection binding), §8.1/§7.2 (`did:web` fetching behind the resolver).
//!
//! [`agent::Agent`] joins a verified connection to a `dsip_session::Endpoint`:
//! it turns the engine's abbreviated [`dsip_session::Emission::Send`]s into
//! signed payloads and every inbound frame into a verified
//! [`dsip_session::Message`]. The relay binary reuses [`verify`] and [`tls`].

#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "cli")]
pub mod admin;
pub mod agent;
#[cfg(feature = "cli")]
pub mod config_file;
pub mod conn;
pub mod error;
pub mod hints;
pub mod identity;
#[cfg(feature = "cli")]
pub mod logging;
pub mod resolver;
#[cfg(feature = "cli")]
pub mod shutdown;
pub mod status;
pub mod tls;
pub mod turn;
pub mod wake;
pub mod waker;
/// Inbound verification (re-exported from `dsip-endpoint`, where it is shared with the WASM build).
pub use dsip_endpoint::verify;
pub use dsip_endpoint::{calls, AnswerPolicy, CallCommand, CallEvent, CallsConfig, Command, Invite, InvitePatch, MediaRequest, MediaResult, PresenceSealing};
pub use error::{Error, HelloFailure, Result};
pub use resolver::{Chain, DidResolver, DidWebResolver};

/// Seconds of inactivity before the client sends a WebSocket Ping. Spec: §13.2 (RECOMMENDED 30 s).
pub const PING_IDLE_S: u64 = 30;
/// Seconds without traffic or Pong after which either side MAY close. Spec: §13.2 (90 s).
pub const DEAD_AFTER_S: u64 = 90;
/// Seconds a relay waits for a verified `hello` before closing. Spec: §13.2 (RECOMMENDED 10 s).
pub const HELLO_TIMEOUT_S: u64 = 10;
/// Reconnect backoff: initial, factor, max (seconds). Spec: §13.2 (1 s, ×2, 60 s, full jitter).
pub const BACKOFF: (u64, u32, u64) = (1, 2, 60);
/// The binding identifier.
pub const BINDING: &str = "ws/1.0";

/// Current Unix time in whole seconds.
pub fn now_s() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
