//! `dsip-media` — the native media endpoint (Phase 2): WebRTC DTLS-SRTP audio.
//!
//! Spec: sections owned by this crate — §14.1 (no media without a signed
//! answer: a leg only starts sending once the DSIP session is ACTIVE), §16.3
//! (SDP as a transport binding object — spec-gap 16), §12.12 (ICE candidates
//! ride in signed `info` after ACTIVE; gathered candidates are handed to the
//! host as they appear so it can buffer them), §14.4 (screening: a `recvonly`
//! leg exposes no local media), §17.1 (Opus audio), B§3.4 (video: coded frames in and out, [`video`]). The
//! normative shapes are
//! in the WebRTC Media Binding draft (`v1.0/dsip-webrtc-media-binding-v1.0.md`).
//!
//! Impl: two interchangeable backends behind one [`MediaLeg`] surface, chosen
//! at runtime by [`Backend`]; both are compiled in by default:
//! - `forge` (feature; the default backend) — forge-media's `forge-webrtc` 0.3
//!   endpoint peer connection, the project's own stack
//!   (`impl/docs/forge-media-plan.md`);
//! - `webrtc-rs` (feature) — plan §7's named fallback, kept compiled in as the
//!   reference peer: three forge interop bugs were only visible against it.
//!
//! The agent and CLI never see which backend is in use; a cross-backend test
//! (`tests/cross_backend.rs`) proves a forge leg and a webrtc-rs leg exchange
//! SRTP. No sound card is used: the source is a generated tone or an Ogg/Opus
//! file and inbound audio is recorded to Ogg, which proves the DTLS-SRTP path
//! end to end headlessly.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(not(any(feature = "webrtc-rs", feature = "forge")))]
compile_error!("dsip-media needs at least one backend feature: `webrtc-rs` or `forge`");

pub mod backend;
pub mod error;
pub mod leg;
pub mod ogg;
pub mod source;
pub mod video;

pub use error::{Error, Result};

pub use leg::{Backend, Candidate, MediaConfig, MediaEvent, MediaLeg, Stats, TurnConfig};
pub use source::{Feed, Source};
pub use video::{VideoConfig, VideoFeed, VideoFrame, VideoRequest};
/// Opus frames as the taps and feeds carry them.
pub use bytes::Bytes;
