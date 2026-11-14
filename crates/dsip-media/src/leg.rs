//! One media leg: a WebRTC peer connection with a single audio track, behind
//! a backend-neutral surface.
//!
//! Spec: §14.1 (sending starts only when the host says the session is
//! ACTIVE — [`MediaLeg::start_sending`]), §12.12 (local candidates are
//! surfaced as [`MediaEvent::Candidate`] in the DSIP `info.data.candidates`
//! shape, `None` = end of candidates), §14.2 (offer/answer: the answer is an
//! SDP answer to the received offer, never a second offer), §12.8 (re-offers
//! for renegotiation reuse the same leg and transport), §14.4 (a screening
//! leg is `recvonly`; escalation adds the source and re-offers).
//!
//! Impl: [`MediaLeg`] is an enum over the compiled backends so one binary can
//! run either and the demos can pair them (binding Appendix C: "demos run
//! against both backends").

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::source::Source;

/// Which media stack a leg runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// webrtc-rs (`webrtc` crate) — the plan §7 fallback and the reference peer
    /// the cross-backend test checks forge against.
    WebRtcRs,
    /// forge-media `forge-webrtc` — the project's own stack; the default.
    Forge,
}

impl Backend {
    /// Parse `webrtc-rs` | `forge`.
    pub fn parse(s: &str) -> Result<Backend> {
        match s {
            "webrtc-rs" | "webrtc" => Ok(Backend::WebRtcRs),
            "forge" | "forge-media" => Ok(Backend::Forge),
            other => Err(Error::UnknownBackend(other.to_string())),
        }
    }

    /// Canonical name.
    pub fn name(&self) -> &'static str {
        match self {
            Backend::WebRtcRs => "webrtc-rs",
            Backend::Forge => "forge",
        }
    }

    /// Backends compiled into this build.
    #[allow(clippy::vec_init_then_push)] // each push is behind its own feature; `vec![]` takes no `#[cfg]`
    pub fn available() -> Vec<Backend> {
        let mut v = vec![];
        #[cfg(feature = "webrtc-rs")]
        v.push(Backend::WebRtcRs);
        #[cfg(feature = "forge")]
        v.push(Backend::Forge);
        v
    }
}

impl Default for Backend {
    /// forge when compiled in (plan step 4, 2026-08-21); otherwise the fallback.
    fn default() -> Self {
        #[cfg(feature = "forge")]
        {
            Backend::Forge
        }
        #[cfg(not(feature = "forge"))]
        {
            Backend::WebRtcRs
        }
    }
}

/// An ICE candidate in the DSIP `info.data.candidates[]` shape (§12.12 example;
/// binding Appendix A).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Candidate {
    /// `candidate:` attribute value.
    pub candidate: String,
    /// SDP mid.
    #[serde(default)]
    pub sdp_mid: Option<String>,
    /// m-line index.
    #[serde(default)]
    pub sdp_m_line_index: Option<u16>,
}

/// A TURN server for relay candidates (RFC 8656): the fallback path when STUN
/// cannot punch a route (symmetric NAT on both ends).
#[derive(Debug, Clone)]
pub struct TurnConfig {
    /// `turn:host:port` (or a bare `host:port`).
    pub uri: String,
    /// Long-term-credential username.
    pub username: String,
    /// Long-term-credential password.
    pub password: String,
}

/// Leg configuration.
#[derive(Debug, Clone)]
pub struct MediaConfig {
    /// What to transmit.
    pub source: Source,
    /// Record inbound audio to this Ogg/Opus file.
    pub record: Option<PathBuf>,
    /// STUN servers (empty for loopback demos).
    pub stun: Vec<String>,
    /// TURN servers for relay candidates (empty = STUN-only).
    pub turn: Vec<TurnConfig>,
    /// Media stack.
    pub backend: Backend,
    /// Offer and send only, receiving nothing (Recording Profile C§6: a recorder leg is `sendonly`).
    pub send_only: bool,
    /// Every inbound Opus payload is also sent here (C§6: the far side's voice, for the recorder leg).
    pub tap_in: Option<tokio::sync::mpsc::UnboundedSender<bytes::Bytes>>,
    /// Every outbound Opus frame is also sent here (C§6: this side's voice, for the recorder leg).
    pub tap_out: Option<tokio::sync::mpsc::UnboundedSender<bytes::Bytes>>,
    /// A video section as well as the audio one (B§3.4); `None` offers audio only and refuses offered video (its
    /// section answered with port 0).
    pub video: Option<crate::video::VideoConfig>,
}

impl Default for MediaConfig {
    /// Sends nothing, records nothing, no STUN or TURN, the default backend.
    fn default() -> MediaConfig {
        MediaConfig { source: Source::None, record: None, stun: vec![], turn: vec![], backend: Backend::default(), send_only: false,
                      tap_in: None, tap_out: None, video: None }
    }
}

/// Events from the leg to its host.
#[derive(Debug, Clone)]
pub enum MediaEvent {
    /// A local candidate (`None` = end of candidates).
    Candidate(Option<Candidate>),
    /// Peer connection state changed.
    State(String),
    /// First inbound RTP packet decoded/recorded.
    FirstPacket,
}

/// Counters.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    /// Inbound RTP packets.
    pub packets_in: u64,
    /// Inbound RTP payload bytes.
    pub bytes_in: u64,
    /// Outbound Opus frames.
    pub frames_out: u64,
    /// Inbound video frames, whole, handed to the sink.
    pub video_frames_in: u64,
    /// Outbound video frames.
    pub video_frames_out: u64,
    /// Keyframe requests sent (PLI).
    pub keyframes_asked: u64,
}

/// A peer connection with one audio track, on whichever backend was asked for.
pub enum MediaLeg {
    /// webrtc-rs.
    #[cfg(feature = "webrtc-rs")]
    WebRtcRs(crate::backend::webrtc_rs::WebRtcRsLeg),
    /// forge-media.
    #[cfg(feature = "forge")]
    Forge(crate::backend::forge::ForgeLeg),
}

macro_rules! dispatch {
    ($self:expr, $leg:ident => $body:expr) => {
        match $self {
            #[cfg(feature = "webrtc-rs")]
            MediaLeg::WebRtcRs($leg) => $body,
            #[cfg(feature = "forge")]
            MediaLeg::Forge($leg) => $body,
        }
    };
}

impl MediaLeg {
    /// Build the peer connection and local track on `cfg.backend`; nothing is
    /// sent until [`MediaLeg::start_sending`].
    pub async fn new(cfg: MediaConfig) -> Result<MediaLeg> {
        match cfg.backend {
            #[cfg(feature = "webrtc-rs")]
            Backend::WebRtcRs => Ok(MediaLeg::WebRtcRs(crate::backend::webrtc_rs::WebRtcRsLeg::new(cfg).await?)),
            #[cfg(feature = "forge")]
            Backend::Forge => Ok(MediaLeg::Forge(crate::backend::forge::ForgeLeg::new(cfg).await?)),
            #[allow(unreachable_patterns)]
            other => Err(Error::NotCompiled { backend: other.name(), available: Backend::available().iter().map(Backend::name).collect() }),
        }
    }

    /// The backend this leg runs on.
    pub fn backend(&self) -> Backend {
        match self {
            #[cfg(feature = "webrtc-rs")]
            MediaLeg::WebRtcRs(_) => Backend::WebRtcRs,
            #[cfg(feature = "forge")]
            MediaLeg::Forge(_) => Backend::Forge,
        }
    }

    /// Add a local audio source to a leg that was created receive-only (screening →
    /// user escalation, §14.4 step 3); the next [`MediaLeg::create_offer`] re-offers
    /// `sendrecv`. No-op if a source exists.
    pub async fn add_source(&mut self, source: Source) -> Result<()> {
        dispatch!(self, l => l.add_source(source).await)
    }

    /// Create an SDP offer (also used for re-offers, §12.8).
    pub async fn create_offer(&self) -> Result<String> {
        dispatch!(self, l => l.create_offer().await)
    }

    /// Apply a remote offer and produce the SDP answer (§14.2).
    pub async fn accept_offer(&self, sdp: &str) -> Result<String> {
        dispatch!(self, l => l.accept_offer(sdp).await)
    }

    /// Apply the remote answer.
    pub async fn set_answer(&self, sdp: &str) -> Result<()> {
        dispatch!(self, l => l.set_answer(sdp).await)
    }

    /// Add a remote candidate (from a verified `info`, §12.12).
    pub async fn add_remote_candidate(&self, c: &Candidate) -> Result<()> {
        dispatch!(self, l => l.add_remote_candidate(c).await)
    }

    /// Next leg event.
    pub async fn next_event(&mut self) -> Option<MediaEvent> {
        dispatch!(self, l => l.next_event().await)
    }

    /// Take the leg's events, for a host that reads them on another task while it keeps using the leg; afterwards
    /// [`MediaLeg::next_event`] returns `None`.
    pub fn take_events(&mut self) -> tokio::sync::mpsc::UnboundedReceiver<MediaEvent> {
        dispatch!(self, l => std::mem::replace(&mut l.events, tokio::sync::mpsc::unbounded_channel().1))
    }

    /// Begin transmitting the configured source. Spec §14.1: the host calls this only once ACTIVE.
    pub fn start_sending(&self) {
        dispatch!(self, l => l.start_sending())
    }

    /// Stop transmitting until the next `start_sending`. Recording Profile C§4: a counterparty holds its media
    /// until it accepts being recorded.
    pub fn hold_sending(&self) {
        dispatch!(self, l => l.hold_sending())
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        dispatch!(self, l => l.stats())
    }

    /// Stop sending and close the peer connection.
    pub async fn close(&self) {
        dispatch!(self, l => l.close().await)
    }
}
