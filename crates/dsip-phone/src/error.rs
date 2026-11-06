//! The errors a phone returns. Each names what failed, so `{e}` alone is a complete log line.
//!
//! Spec: none (infrastructure)

/// Why a phone call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The agent or its connection failed.
    #[error(transparent)]
    Transport(#[from] dsip_transport::Error),
    /// The builder lacks something it needs.
    #[error("the phone needs {0}")]
    Missing(&'static str),
    /// A media leg failed.
    #[cfg(feature = "media")]
    #[error("media: {0}")]
    Media(#[from] dsip_media::Error),
    /// A request to the relay got no answer in time.
    #[error("{0} got no answer from the relay")]
    NoAnswer(&'static str),
    /// The relay's answer to a request did not verify.
    #[error(transparent)]
    Wake(#[from] dsip_transport::wake::WakeError),
    /// The phone has closed.
    #[error("the phone has closed")]
    Closed,
}

/// A phone result.
pub type Result<T> = std::result::Result<T, Error>;
