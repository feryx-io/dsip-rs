//! The errors this crate returns. Each message names what failed and includes its cause; the cause is also kept as
//! [`std::error::Error::source`].
//!
//! Spec: none (infrastructure)

use std::path::PathBuf;

/// Why a media call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A backend name that is not `webrtc-rs` or `forge`.
    #[error("unknown media backend {0} (webrtc-rs | forge)")]
    UnknownBackend(String),
    /// A backend this build was compiled without.
    #[error("media backend {backend} is not compiled into this build (features: {available:?})")]
    NotCompiled {
        /// The backend asked for.
        backend: &'static str,
        /// The backends this build has.
        available: Vec<&'static str>,
    },
    /// A leg asked for video on a backend that does not carry it yet.
    #[error("media backend {backend} does not carry video yet")]
    VideoUnsupported {
        /// The backend.
        backend: &'static str,
    },
    /// A media source that does not parse.
    #[error("unknown media source {0} (none | tone[:hz] | file:<path.ogg>)")]
    UnknownSource(String),
    /// A file holds no Opus frames.
    #[error("{}: no Opus audio frames (not an Ogg/Opus file?)", .0.display())]
    NotOggOpus(PathBuf),
    /// Reading a file failed.
    #[error("{}: {source}", path.display())]
    File {
        /// The file.
        path: PathBuf,
        /// The I/O failure.
        source: std::io::Error,
    },
    /// The Opus encoder failed.
    #[error("opus {what}: {source}")]
    Opus {
        /// The step that failed.
        what: &'static str,
        /// The encoder's error.
        source: audiopus::Error,
    },
    /// The webrtc-rs backend failed.
    #[cfg(feature = "webrtc-rs")]
    #[error("webrtc-rs {what}: {source}")]
    WebRtcRs {
        /// The step that failed.
        what: &'static str,
        /// The backend's error.
        source: webrtc::Error,
    },
    /// The forge backend failed.
    #[cfg(feature = "forge")]
    #[error("forge {what}: {source}")]
    Forge {
        /// The step that failed.
        what: &'static str,
        /// The backend's error.
        source: forge_webrtc::WebRtcError,
    },
}

/// `Result` with [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Label a backend or codec failure with the step that failed: `pc.create_offer().await.at("create offer")?`.
pub(crate) trait At<T> {
    fn at(self, what: &'static str) -> Result<T>;
}

impl<T> At<T> for std::result::Result<T, audiopus::Error> {
    fn at(self, what: &'static str) -> Result<T> {
        self.map_err(|source| Error::Opus { what, source })
    }
}

#[cfg(feature = "webrtc-rs")]
impl<T> At<T> for std::result::Result<T, webrtc::Error> {
    fn at(self, what: &'static str) -> Result<T> {
        self.map_err(|source| Error::WebRtcRs { what, source })
    }
}

#[cfg(feature = "forge")]
impl<T> At<T> for std::result::Result<T, forge_webrtc::WebRtcError> {
    fn at(self, what: &'static str) -> Result<T> {
        self.map_err(|source| Error::Forge { what, source })
    }
}
