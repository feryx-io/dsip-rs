//! A leg's video: coded frames in from the host's encoder, coded frames out to its decoder, and what the far end
//! asks of the encoder (a keyframe, a bitrate).
//!
//! Spec: B§3.4 (the codecs: H.264 constrained baseline is the one every endpoint doing video supports, VP8 the
//! recommended second; spec-gap 181), B§2.1 (the video `m=` section follows the audio one), B§5.3 (video added
//! later is an `update` that appends a section).
//!
//! Impl: the leg moves coded frames, never pictures: capture, encoding, decoding and display are the host's (the
//! app's camera and codecs). A frame is H.264 as an Annex B byte stream or one VP8 frame, with its RTP timestamp at
//! 90 kHz. Losses are repaired with NACK and retransmission, and a frame that cannot be repaired asks the sender for
//! a keyframe (PLI), at most once per [`KEYFRAME_INTERVAL`].

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, Mutex};

/// The video codecs a leg can carry, as DSIP names them (Core §16.2, B§3.4).
pub const H264: &str = "codec:video/h264";
/// VP8 (B§3.4).
pub const VP8: &str = "codec:video/vp8";

/// The least time between two keyframe requests a leg sends, however many frames it loses.
pub const KEYFRAME_INTERVAL: Duration = Duration::from_millis(500);

/// One coded video frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrame {
    /// H.264 as an Annex B byte stream (start codes, SPS and PPS before a keyframe's IDR), or one VP8 frame.
    pub data: Bytes,
    /// An IDR (H.264) or a key frame (VP8): one a decoder can start from.
    pub keyframe: bool,
    /// The RTP timestamp, 90 kHz: when the frame was captured.
    pub timestamp: u32,
}

/// What the far end asks of this side's encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoRequest {
    /// A keyframe, now: the far end lost a frame it could not repair, or has just started (PLI or FIR).
    Keyframe,
    /// The most the far end can take, in kb/s (REMB): encode at or below it.
    Bitrate(u32),
}

/// What the host's encoder gives the leg to send.
#[derive(Clone)]
pub struct VideoFeed(pub Arc<Mutex<mpsc::UnboundedReceiver<VideoFrame>>>);

impl VideoFeed {
    /// A feed and the sender the host's encoder writes to.
    pub fn channel() -> (mpsc::UnboundedSender<VideoFrame>, VideoFeed) {
        let (tx, rx) = mpsc::unbounded_channel();
        (tx, VideoFeed(Arc::new(Mutex::new(rx))))
    }
}

impl std::fmt::Debug for VideoFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VideoFeed")
    }
}

/// A leg's video section.
#[derive(Debug, Clone)]
pub struct VideoConfig {
    /// The codecs offered, or accepted, in preference order, as DSIP ids ([`H264`], [`VP8`]). An answer takes the
    /// first the offer lists.
    pub codecs: Vec<String>,
    /// Frames to send. `None` receives only.
    pub source: Option<VideoFeed>,
    /// Where the frames received go. `None` sends only.
    pub sink: Option<mpsc::UnboundedSender<VideoFrame>>,
    /// Where the far end's requests go ([`VideoRequest`]), for the host's encoder.
    pub requests: Option<mpsc::UnboundedSender<VideoRequest>>,
    /// The most this side takes, kb/s, said in the offer or answer (`b=AS`). `None` says nothing.
    pub max_kbps: Option<u32>,
}

impl Default for VideoConfig {
    /// H.264 then VP8, sending and receiving nothing yet.
    fn default() -> VideoConfig {
        VideoConfig { codecs: vec![H264.into(), VP8.into()], source: None, sink: None, requests: None, max_kbps: None }
    }
}
