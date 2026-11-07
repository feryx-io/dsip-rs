//! The errors this crate returns. Each message names what failed and includes its cause, so `{e}` alone is a
//! complete log line; the cause is also kept as [`std::error::Error::source`].
//!
//! Spec: none (infrastructure)

use std::path::PathBuf;

use dsip_core::verdict::RejectCode;

/// Why a transport, identity, TLS or resolver call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The endpoint core refused the request.
    #[error(transparent)]
    Core(#[from] dsip_endpoint::Error),
    /// A relay URL that is not `wss://`: `ws/1.0` has no plaintext form (§13.2).
    #[error("ws/1.0 requires a wss:// URL (spec §13.2); refusing {0}")]
    NotWss(String),
    /// Dialing the relay failed.
    #[error("connecting to {url}: {source}")]
    Connect {
        /// The relay URL.
        url: String,
        /// The WebSocket or TLS failure.
        source: Box<tokio_tungstenite::tungstenite::Error>,
    },
    /// The relay did not complete the `hello` exchange.
    #[error("{0}")]
    Hello(HelloFailure),
    /// An envelope over the `ws/1.0` cap, refused before sending (§13.2).
    #[error("envelope is {len} bytes; ws/1.0 cap is {cap}")]
    Oversize {
        /// The frame length.
        len: usize,
        /// The cap.
        cap: usize,
    },
    /// The peer broke the binding (§13.2): an oversize or binary frame. The connection is closed.
    #[error("peer sent {0}")]
    PeerViolation(&'static str),
    /// The WebSocket failed after binding.
    #[error("websocket: {0}")]
    WebSocket(Box<tokio_tungstenite::tungstenite::Error>),
    /// A frame that does not parse as an envelope.
    #[error("not an envelope: {0:?}")]
    Envelope(Option<RejectCode>),
    /// A DID that is not a `did:web` where one is required.
    #[error("{0} is not a did:web DID")]
    NotDidWeb(String),
    /// Fetching a `did:web` document failed.
    #[error("GET {url}: {source}")]
    Fetch {
        /// The document URL.
        url: String,
        /// The HTTP failure.
        source: reqwest::Error,
    },
    /// A fetched DID document names a different DID.
    #[error("document id {got} does not match {did}")]
    DocumentMismatch {
        /// The DID asked for.
        did: String,
        /// The document's `id`.
        got: String,
    },
    /// The identity key is not on this device (a device that joined holds only its own key, its delegation and the
    /// key agreement key, §7.3): what needs it is done on a device that holds it.
    #[error("this device does not hold the identity key")]
    NoIdentityKey,
    /// A key file that is not 32 bytes of hex.
    #[error("{0}: expected 64 hex characters")]
    BadKey(PathBuf),
    /// Reading or writing a file failed.
    #[error("{}: {source}", path.display())]
    File {
        /// The file.
        path: PathBuf,
        /// The I/O failure.
        source: std::io::Error,
    },
    /// Any other I/O failure (sockets).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON that does not parse or serialize.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// TLS configuration failed.
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    /// Generating a certificate failed.
    #[error("certificate: {0}")]
    Certificate(#[from] rcgen::Error),
    /// A call operation on an agent that does not run the call glue (`AgentConfig::calls` is `None`).
    #[error("the agent runs no call glue (AgentConfig::calls)")]
    NoCalls,
    /// A PEM file holds no private key.
    #[error("{0}: no private key")]
    NoPrivateKey(PathBuf),
    /// The relay closed this connection because this device bound there again on another one (§13.2,
    /// `transport.replaced`): the agent does not reconnect, which would replace that one in turn.
    #[error("relay {relay} replaced this connection: this device bound there on another one (transport.replaced, §13.2); not reconnecting")]
    Replaced {
        /// The relay's DID.
        relay: String,
    },
}

/// How the `hello` exchange failed (§13.2, §20.5).
#[derive(Debug)]
#[non_exhaustive]
pub enum HelloFailure {
    /// The relay closed the connection.
    Closed(String),
    /// The relay sent a binary frame.
    NonText,
    /// The connection ended.
    Ended,
    /// No `hello` within [`crate::HELLO_TIMEOUT_S`].
    Timeout,
    /// The relay's `hello` failed verification.
    Rejected {
        /// The rejection code.
        code: Option<RejectCode>,
        /// Human detail.
        detail: String,
    },
    /// The relay answered with an `error`.
    Refused {
        /// Its `reason` token.
        reason: String,
        /// Its `detail`.
        detail: String,
    },
    /// The first frame was another type.
    NotHello(String),
}

impl std::fmt::Display for HelloFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelloFailure::Closed(c) => write!(f, "relay closed during hello: {c}"),
            HelloFailure::NonText => f.write_str("relay sent a non-text frame during hello"),
            HelloFailure::Ended => f.write_str("connection ended during hello"),
            HelloFailure::Timeout => write!(f, "no relay hello within {} s", crate::HELLO_TIMEOUT_S),
            HelloFailure::Rejected { code, detail } => write!(f, "relay hello rejected: {code:?} ({detail})"),
            HelloFailure::Refused { reason, detail } => write!(f, "hello refused: {reason} {detail}"),
            HelloFailure::NotHello(t) => write!(f, "first frame from relay was {t}, not hello"),
        }
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for Error {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Error {
        Error::WebSocket(Box::new(e))
    }
}

impl From<dsip_core::verdict::Verdict> for Error {
    fn from(v: dsip_core::verdict::Verdict) -> Error {
        Error::Envelope(v.code)
    }
}

/// `Result` with [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Attach the file path to an I/O result.
pub(crate) fn file<T>(path: impl Into<PathBuf>, r: std::io::Result<T>) -> Result<T> {
    r.map_err(|source| Error::File { path: path.into(), source })
}
