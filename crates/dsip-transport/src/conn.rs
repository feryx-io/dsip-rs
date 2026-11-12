//! A client `ws/1.0` connection: dial, `hello` exchange, framed send/receive.
//!
//! Spec: §13.2 — connections are client-initiated over `wss`; the first
//! envelope MUST be a `hello`; the relay's `hello` MUST echo our id in
//! `in_reply_to` (close on mismatch, §20.5) and carry `capabilities` with
//! `max_envelope_bytes = 65536`; one envelope per text frame; frames over
//! 65,536 bytes are rejected (close 1009); Ping/Pong keepalive.
//!
//! Impl: a connection runs over a TLS socket ([`Connection::connect`]) or over any byte stream the host already holds
//! ([`Connection::over`]): an in-process pipe to an embedded relay, which is how `dsip-testkit` runs a network
//! without sockets. The `wss` rule is the dialer's; a stream handed in is the host's to secure.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::Connector;

use dsip_core::did::Resolver;
use dsip_core::envelope::{sign_bytes, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::ulid::Ulid;
use dsip_core::version::Supported;
use dsip_core::WS_MAX_ENVELOPE_BYTES;

/// What [`Error::PeerViolation`] says of a received frame over the cap (§13.2), closed with 1009; a caller that must act
/// on it (a device whose mailbox sent it, M§5.4) matches this.
pub const OVERSIZE_FRAME: &str = "an oversize frame";
use dsip_schema::SemanticContext;

use crate::error::{Error, HelloFailure, Result};
use crate::verify::{verify_frame, SeenIds};
use crate::{now_s, BINDING, PING_IDLE_S};

/// WebSocket configuration enforcing the §13.2 size cap at the framing layer.
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(WS_MAX_ENVELOPE_BYTES))
        .max_frame_size(Some(WS_MAX_ENVELOPE_BYTES))
}

/// What we learned from the relay's `hello`.
#[derive(Debug, Clone)]
pub struct RelayInfo {
    /// Relay identity DID (from the verified `hello`).
    pub did: String,
    /// Advertised capabilities object.
    pub capabilities: Value,
}

/// Parameters for dialing a relay.
pub struct ConnectParams<'a> {
    /// `wss://host:port/path`.
    pub url: String,
    /// Explicit trust anchor (self-signed relay); `None` = native roots.
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// Device key that signs `hello` and all session messages.
    pub device: &'a KeyPair,
    /// Identity the device acts for (`on_behalf_of`), if different from the device.
    pub on_behalf_of: Option<String>,
    /// Delegations to present inline in the `hello` header (so the relay can verify `on_behalf_of`).
    pub delegations: Vec<Envelope>,
    /// Supported versions.
    pub supported: Supported,
}

/// A byte stream a connection can run over: anything async, readable and writable, such as
/// `tokio::io::DuplexStream`.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// What a [`Dialer`] returns: a fresh stream to the relay.
pub type DialFuture = std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Box<dyn Io>>> + Send>>;

/// How a host reaches its relay when the connection does not dial `wss` itself: each call opens one fresh stream,
/// for the first connection and for every reconnect (§13.2). `dsip-testkit` dials an embedded relay over a pipe.
pub trait Dialer: Send + Sync {
    /// Open a stream to the relay.
    fn dial(&self) -> DialFuture;
}

/// A WebSocket, whatever it runs over.
trait Socket:
    futures_util::Stream<Item = std::result::Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
    + futures_util::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error>
    + Unpin
    + Send
{
}
impl<T> Socket for T where
    T: futures_util::Stream<Item = std::result::Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin
        + Send
{
}

/// A bound client connection.
pub struct Connection {
    ws: Box<dyn Socket>,
    /// Relay identity and capabilities.
    pub relay: RelayInfo,
    last_activity: std::time::Instant,
}

impl Connection {
    /// Dial, send `hello`, verify the relay's `hello`. Fails closed on any binding error.
    pub async fn connect(p: &ConnectParams<'_>, resolver: &dyn Resolver, seen: &mut SeenIds) -> Result<Connection> {
        if !p.url.starts_with("wss://") {
            return Err(Error::NotWss(p.url.clone()));
        }
        let connector = p.tls.clone().map(Connector::Rustls);
        let (ws, _) =
            tokio_tungstenite::connect_async_tls_with_config(p.url.as_str(), Some(ws_config()), false, connector)
                .await
                .map_err(|e| Error::Connect { url: p.url.clone(), source: Box::new(e) })?;
        Self::bind(Box::new(ws), p, resolver, seen).await
    }

    /// Connect through `dialer`'s stream ([`Connection::over`]), or dial `p.url` over `wss` when there is none
    /// ([`Connection::connect`]).
    pub async fn dial(dialer: Option<&dyn Dialer>, p: &ConnectParams<'_>, resolver: &dyn Resolver, seen: &mut SeenIds) -> Result<Connection> {
        match dialer {
            None => Self::connect(p, resolver, seen).await,
            Some(d) => Self::over(d.dial().await?, p, resolver, seen).await,
        }
    }

    /// Run the WebSocket handshake for `p.url` over `stream`, send `hello`, verify the relay's `hello`. Fails closed on
    /// any binding error. `p.tls` is not used: the stream is the host's.
    pub async fn over<S: Io>(stream: S, p: &ConnectParams<'_>, resolver: &dyn Resolver, seen: &mut SeenIds) -> Result<Connection> {
        let (ws, _) = tokio_tungstenite::client_async_with_config(p.url.as_str(), stream, Some(ws_config()))
            .await
            .map_err(|e| Error::Connect { url: p.url.clone(), source: Box::new(e) })?;
        Self::bind(Box::new(ws), p, resolver, seen).await
    }

    async fn bind(mut ws: Box<dyn Socket>, p: &ConnectParams<'_>, resolver: &dyn Resolver, seen: &mut SeenIds) -> Result<Connection> {

        // Client hello (§13.2)
        let now = now_s();
        let id = Ulid::generate();
        let mut hello = json!({
            "dsip": dsip_core::version::version_block(&p.supported, &[]),
            "type": "hello", "id": id.as_str(), "from": p.device.did(),
            "bindings": [BINDING], "issued_at": now, "expires_at": now + 30,
        });
        if let Some(obo) = &p.on_behalf_of {
            hello["on_behalf_of"] = obo.clone().into();
        }
        let env = sign_bytes(&serde_json::to_vec(&hello)?, p.device, &p.device.kid(), p.delegations.clone());
        ws.send(WsMessage::Text(env.frame().into())).await?;

        // Relay hello: first text frame, verified, bound via in_reply_to (§20.5)
        let frame = loop {
            match tokio::time::timeout(Duration::from_secs(crate::HELLO_TIMEOUT_S), ws.next()).await {
                Ok(Some(Ok(WsMessage::Text(t)))) => break t.to_string(),
                Ok(Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_)))) => continue,
                Ok(Some(Ok(WsMessage::Close(c)))) => return Err(Error::Hello(HelloFailure::Closed(format!("{c:?}")))),
                Ok(Some(Ok(_))) => return Err(Error::Hello(HelloFailure::NonText)),
                Ok(Some(Err(e))) => return Err(e.into()),
                Ok(None) => return Err(Error::Hello(HelloFailure::Ended)),
                Err(_) => return Err(Error::Hello(HelloFailure::Timeout)),
            }
        };
        let sem = SemanticContext { supported: p.supported.clone(), sent_hello_id: Some(id.to_string()), ..Default::default() };
        let inbound = verify_frame(&frame, now_s(), resolver, &[], seen, &sem).map_err(|v| {
            Error::Hello(HelloFailure::Rejected { code: v.code, detail: v.detail.unwrap_or_default() })
        })?;
        if inbound.verified.msg_type() != "hello" {
            let _ = ws.send(WsMessage::Close(None)).await;
            let p = &inbound.verified.payload;
            if inbound.verified.msg_type() == "error" {
                return Err(Error::Hello(HelloFailure::Refused {
                    reason: p["reason"].as_str().unwrap_or("").to_string(),
                    detail: p["detail"].as_str().unwrap_or("").to_string(),
                }));
            }
            return Err(Error::Hello(HelloFailure::NotHello(inbound.verified.msg_type().to_string())));
        }
        // The schema enforces relay form (in_reply_to ⇔ capabilities, max_envelope_bytes const).
        let caps = inbound.verified.payload["capabilities"].clone();
        Ok(Connection {
            ws,
            relay: RelayInfo { did: inbound.verified.identity.clone(), capabilities: caps },
            last_activity: std::time::Instant::now(),
        })
    }

    /// Send one envelope as one text frame. Enforces the size cap before sending.
    pub async fn send(&mut self, env: &Envelope) -> Result<()> {
        let frame = env.frame();
        if frame.len() > WS_MAX_ENVELOPE_BYTES {
            return Err(Error::Oversize { len: frame.len(), cap: WS_MAX_ENVELOPE_BYTES });
        }
        self.ws.send(WsMessage::Text(frame.into())).await?;
        self.last_activity = std::time::Instant::now();
        Ok(())
    }

    /// Receive the next text frame (handles Ping/Pong and idle keepalive). `None` when closed.
    pub async fn recv(&mut self) -> Result<Option<String>> {
        loop {
            let idle = Duration::from_secs(PING_IDLE_S).saturating_sub(self.last_activity.elapsed());
            tokio::select! {
                msg = self.ws.next() => match msg {
                    Some(Ok(WsMessage::Text(t))) => {
                        self.last_activity = std::time::Instant::now();
                        if t.len() > WS_MAX_ENVELOPE_BYTES {
                            self.close(CloseCode::Size, "envelope too large").await;
                            return Err(Error::PeerViolation(OVERSIZE_FRAME));
                        }
                        return Ok(Some(t.to_string()));
                    }
                    Some(Ok(WsMessage::Binary(_))) => {
                        // §13.2: text frames only
                        self.close(CloseCode::Unsupported, "text frames only").await;
                        return Err(Error::PeerViolation("a binary frame"));
                    }
                    Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_))) => {
                        self.last_activity = std::time::Instant::now();
                    }
                    Some(Ok(WsMessage::Close(_))) | None => return Ok(None),
                    Some(Err(tokio_tungstenite::tungstenite::Error::Capacity(_))) => {
                        self.close(CloseCode::Size, "envelope too large").await;
                        return Err(Error::PeerViolation(OVERSIZE_FRAME));
                    }
                    Some(Err(e)) => return Err(e.into()),
                },
                _ = tokio::time::sleep(idle) => {
                    self.ws.send(WsMessage::Ping(Vec::new().into())).await?;
                    self.last_activity = std::time::Instant::now();
                }
            }
        }
    }

    /// Close with a status code.
    pub async fn close(&mut self, code: CloseCode, reason: &str) {
        let _ = self.ws.send(WsMessage::Close(Some(CloseFrame { code, reason: reason.to_string().into() }))).await;
    }
}
