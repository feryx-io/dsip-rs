//! `dsip-core` — identifiers, DIDs, keys, and the DSIP-JOSE envelope.
//!
//! Spec: sections owned by this crate — §7.2–§7.4 (DID usage, device
//! delegation), §8.1 (resolution authority), §10.2–§10.3 (signature semantics,
//! payload rules), §11 (version negotiation), §12.9 (replay window),
//! §15.1/§15.4 (reason registry), §20.6 (glare-backdating guard).
//!
//! This crate never depends on schema or session logic. A message leaving
//! [`envelope::verify`] has passed signature, binding, replay, and wire-format
//! checks and nothing else; shape (schema) and state come later, in that order.
//!
//! Verdict codes and stage order are defined by `impl/vectors/README.md` and
//! mirrored by [`verdict::RejectCode`].

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod b64;
pub mod delegation;
pub mod did;
pub mod envelope;
pub mod grant;
pub mod hpke;
pub mod keys;
pub mod pkarr;
pub mod presence_seal;
pub mod profile_card;
pub mod registry;
pub mod trust;
pub mod ulid;
pub mod verdict;
pub mod version;
pub mod webvh;
pub mod wire;

pub use envelope::{Context, Envelope, Verified};
pub use verdict::{RejectCode, Verdict};

/// Replay window in seconds.
///
/// Spec: §12.9 — envelopes with `issued_at` older than the window MUST be
/// rejected; ids are tracked for deduplication within it.
pub const REPLAY_WINDOW_S: i64 = 300;

/// Tolerance between the ULID timestamp component and `issued_at`.
///
/// Spec: §20.6. Impl (spec-gap 6): the spec says "consistent … within the
/// replay window"; this PoC rejects beyond 300 s.
pub const ULID_TOLERANCE_S: i64 = 300;

/// Maximum validity (`expires_at − issued_at`) of an `introduction`.
///
/// Spec: §19.4 — introductions MAY be valid up to 604,800 s because they are
/// store-and-forward friendly. Impl (spec-gap 31): enforced at envelope stage 9,
/// where it bounds how long a held introduction's id stays replay-tracked.
pub const INTRODUCTION_MAX_VALIDITY_S: i64 = 604_800;

/// Maximum validity of a `reachability-hint`, in seconds.
///
/// Spec: §12.9 (v0.8, spec-gap 96), DHT profile §2 — a hint's age is bounded by its
/// own `expires_at` under this cap, not by the 300 s replay window.
pub const HINT_MAX_VALIDITY_S: i64 = 3_600;

/// Maximum validity of a `presence` record, in seconds.
///
/// Spec: §12.9 (v0.17, spec-gap 134), Presence Profile P§3, P§8 — the authority keeps a record and forwards it in
/// `notify` bodies for its whole lifetime, so its age is bounded by its own `expires_at` under this cap.
pub const PRESENCE_MAX_VALIDITY_S: i64 = 3_600;

/// Whether `a` is a presence audience token: `[a-z][a-z0-9-]*`, at most 64 characters (the schemas check the same
/// pattern on a record's `audience` and a grant's `presence_audience`).
///
/// Spec: Presence Profile P§6 (spec-gap 145).
pub fn is_presence_audience(a: &str) -> bool {
    a.len() <= 64 && a.starts_with(|c: char| c.is_ascii_lowercase()) && a.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Maximum encoded envelope size on `ws/1.0`, a fixed binding constant.
///
/// Spec: §13.2.
pub const WS_MAX_ENVELOPE_BYTES: usize = 65_536;

/// Maximum encoded size of an `introduction` envelope.
///
/// Spec: §19.4 — a core constant, deliberately far below the transport cap.
pub const INTRODUCTION_MAX_BYTES: usize = 4_096;
