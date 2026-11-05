//! The errors a messenger returns. Each names what failed, so `{e}` alone is a complete line.
//!
//! Spec: none (infrastructure)

/// Why a messenger call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The connection, its `hello`, TLS or a file failed.
    #[error(transparent)]
    Transport(#[from] dsip_transport::Error),
    /// The engine refused the request.
    #[error("{0}")]
    Engine(#[from] dsip_messaging_device::messenger::Error),
    /// Reading or writing the device's state failed.
    #[error("state: {0}")]
    Store(#[from] dsip_mls::MlsError),
    /// A frame that is not an envelope.
    #[error("frame: {0}")]
    Frame(String),
    /// No connection to the mailbox.
    #[error("offline")]
    Offline,
    /// A request had no answer in time, or a peer mailbox none at all.
    #[error("no answer")]
    NoAnswer,
    /// The mailbox closed the connection while a request waited.
    #[error("mailbox closed")]
    Closed,
    /// A mailbox answered as another service.
    #[error("mailbox is {got} not {expected}")]
    WrongMailbox {
        /// The DID it was dialled as.
        expected: String,
        /// The DID that answered.
        got: String,
    },
    /// An identity's mailbox could not be found (M§4.2).
    #[error("{0}")]
    NoMailbox(String),
    /// A peer mailbox refused, or a step needs what it did not give.
    #[error("{0}")]
    Refused(String),
    /// A blob could not be handled.
    #[error("blob: {0}")]
    Blob(String),
    /// A local file failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The mailbox's answer to `wake-register` did not verify (W§4.2).
    #[error(transparent)]
    Wake(#[from] dsip_transport::wake::WakeError),
    /// HTTPS failed.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
}

/// A messenger result.
pub type Result<T> = std::result::Result<T, Error>;
