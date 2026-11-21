//! `dsip-relay` — the relay as a library: `hello` binding, routing, per-leg forking, store-and-forward, the presence
//! and broadcast authority. The `dsip-relay` binary is a thin host of [`RelayServer`]; an application embeds one the
//! same way, over TLS ([`RelayServer::serve_tls`]) or over any byte stream ([`RelayServer::accept`]).
//!
//! Spec: §13.2 (connection binding — the first envelope MUST be a verified
//! `hello`; the relay answers with its own signed `hello` echoing the client
//! id; unbound connections receive no session traffic and close after 10 s;
//! no silent drops on a live connection — refusals are signed `error`s),
//! §12.7 rules 3 and 6 (leg tracking, per-leg cancel, attempt outcome, legs
//! added mid-attempt — all via `dsip_session::Relay`), §13.3 (store-and-forward:
//! envelopes for known-but-offline recipients are held until
//! `min(expires_at, offline_retention_s)` and flushed on the next `hello`;
//! never-seen recipients get `transport.unknown-recipient` — spec-gap 17),
//! §19.4 (introductions: mandatory per-sender and per-inbox rate limits; unknown
//! and offline recipients treated identically — Impl, spec-gap 14), §13.6
//! (service scope: open by default, private with [`RelayConfig::served`] — spec-gap 100), Presence Profile P§3 (a served
//! device's `presence` record goes to this relay's authority, and notify bodies carry the signed record), Wake Profile
//! W§4–W§6 (draft: with [`RelayConfig::wake`], `wake-register` and the wakes for held invites — [`wake`]).
//!
//! Envelopes are forwarded as the exact text frames received (§10.2: the
//! signature covers the bytes; a relay never re-serializes).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::ulid::Ulid;
use dsip_core::version::{version_block, Supported};
use dsip_broadcast::Authority;
use dsip_session::fork::{RelayAction, RelayEvent};
use dsip_session::{Emission, Message, Relay};
use dsip_transport::conn::ws_config;
use dsip_transport::resolver::{Over, WebDocuments};
use dsip_transport::verify::{verify_frame_with, Inbound, SeenIds};
use dsip_transport::{now_s, HELLO_TIMEOUT_S};

mod error;
mod status;

/// The admin commands the status port answers (`dsip-relay admin …`: `bindings`).
pub use status::ADMIN_COMMANDS;
pub mod store;
pub mod wake;
pub mod www;

pub use error::{Error, Result};

/// How a relay behaves. The defaults are the binary's.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Introductions allowed per sender identity and per recipient inbox within [`RelayConfig::intro_window`] (§19.4
    /// mandatory rate limit).
    pub intro_limit: usize,
    /// The introduction rate-limit window, seconds.
    pub intro_window: i64,
    /// T-Presence-Grace: seconds a device's presence record outlives its unbind (P§8: 0–300; 0 drops it at the unbind).
    pub presence_grace: i64,
    /// Identities whose presence anyone may watch: this relay's own policy for them (P§6 rule 4). Every other
    /// identity's presence is private (P§6, §9.2).
    pub presence_public: Vec<String>,
    /// Maximum queued envelopes per recipient (§13.3 store-and-forward boundary).
    pub inbox_cap: usize,
    /// Maximum bytes of queued envelopes across all recipients; beyond it new envelopes for offline recipients are
    /// refused `transport.routing-refused` (§13.3).
    pub queue_budget_bytes: usize,
    /// The identities a *private* relay serves (§13.6): only traffic to or from them is routed, held or published.
    /// `None`: an *open* relay that serves every identity that binds.
    pub served: Option<HashSet<String>>,
    /// Maximum seconds an envelope is held for an offline recipient (advertised as `offline_retention_s`).
    pub offline_retention: i64,
    /// Fetch the `did:web` documents of identities binding here over HTTPS (§7.2, §8.1), after the documents given to
    /// [`RelayServer::new`]. `None`: only those documents (and `did:key`) verify.
    pub did_web: Option<Arc<WebDocuments>>,
    /// Keep the store-and-forward queue, and the recipients the relay knows, on disk, so a restarted relay delivers
    /// what it held (§13.3). `None`: in memory only, lost on a restart.
    pub queue_store: Option<Arc<store::QueueStore>>,
    /// Wake sleeping devices through their push gateways (Wake Profile, draft): `wake-register` is answered and the
    /// relay advertises `wake` in its `hello`. `None`: neither.
    pub wake: Option<wake::WakeConfig>,
}

impl Default for RelayConfig {
    fn default() -> RelayConfig {
        RelayConfig {
            intro_limit: 5,
            intro_window: 3600,
            presence_grace: dsip_broadcast::authority::PRESENCE_GRACE_S,
            presence_public: vec![],
            inbox_cap: 100,
            queue_budget_bytes: 67_108_864,
            served: None,
            offline_retention: 86_400,
            did_web: None,
            queue_store: None,
            wake: None,
        }
    }
}

/// A relay: the state every connection shares. Cheap to clone; clones share it.
#[derive(Clone)]
pub struct RelayServer {
    state: Arc<Mutex<State>>,
    did: String,
    /// The wakes to send, taken by the sender task [`RelayServer::spawn_clock`] starts.
    wake_rx: Arc<std::sync::Mutex<Option<mpsc::UnboundedReceiver<wake::Outgoing>>>>,
}

impl RelayServer {
    /// A relay signing as `key`, verifying `did:web` identities against the documents `resolver` holds, then those
    /// [`RelayConfig::did_web`] fetches (§8.1: without either only `did:key` identities can bind). Its clock does not run until [`RelayServer::spawn_clock`].
    pub fn new(key: KeyPair, resolver: StaticResolver, cfg: RelayConfig) -> RelayServer {
        let did = key.did();
        let mut authority = Authority::new(now_s(), HashMap::new());
        authority.presence_grace = cfg.presence_grace;
        for d in &cfg.presence_public {
            authority.set_policy(d, "public", vec![]);
        }
        let mut tracker = Relay::with_retention(now_s(), cfg.offline_retention);
        let mut frames = HashMap::new();
        if let Some(store) = &cfg.queue_store {
            match store.load() {
                Ok(held) => {
                    let n: usize = held.inbox.values().map(Vec::len).sum();
                    tracing::info!("queue store: {n} envelopes held for {} recipients, {} recipients known", held.inbox.len(), held.known.len());
                    tracker.restore(held.inbox, held.known);
                    frames = held.frames;
                }
                Err(e) => tracing::warn!("{e}: starting with an empty queue"),
            }
        }
        let (wakes, wake_rx) = match cfg.wake {
            Some(w) => {
                let (w, rx) = wake::Wakes::new(w, now_s());
                (Some(w), Some(rx))
            }
            None => (None, None),
        };
        let state = State {
            wakes,
            key,
            supported: Supported::all_known(),
            resolver,
            web: cfg.did_web.clone(),
            seen: SeenIds::default(),
            devices: HashMap::new(),
            identities: HashMap::new(),
            bound_at: HashMap::new(),
            tracker,
            queue_store: cfg.queue_store,
            touched: BTreeSet::new(),
            known_touched: false,
            reject_frames: HashMap::new(),
            frames,
            intro_log: HashMap::new(),
            intro_limit: cfg.intro_limit,
            intro_window: cfg.intro_window,
            inbox_cap: cfg.inbox_cap,
            queue_budget_bytes: cfg.queue_budget_bytes,
            served: cfg.served,
            offline_retention: cfg.offline_retention,
            authority,
            records: HashMap::new(),
            statements: HashMap::new(),
            presence_frames: HashMap::new(),
            revocations: vec![],
            stats: status::Stats::new(now_s()),
        };
        RelayServer { state: Arc::new(Mutex::new(state)), did, wake_rx: Arc::new(std::sync::Mutex::new(wake_rx)) }
    }

    /// The relay's DID: the `from` of its `hello` and the address of what it is the authority for.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Run the relay's clock once a second, without traffic too: a leg that never answered expires with its invite
    /// and the initiator is told `transport.no-response` within a second of it (§12.7 rule 6, spec-gap 132).
    /// With [`RelayConfig::wake`] it also starts sending wakes to gateways, each on its own task (W§5.2).
    pub fn spawn_clock(&self) -> tokio::task::JoinHandle<()> {
        if let Some(mut rx) = self.wake_rx.lock().ok().and_then(|mut r| r.take()) {
            let state = self.state.clone();
            tokio::spawn(async move {
                while let Some(out) = rx.recv().await {
                    let Some(client) = state.lock().await.wakes.as_ref().map(|w| w.client.clone()) else { return };
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Some(reason) = wake::send(&client, &out).await {
                            let mut st = state.lock().await;
                            let State { wakes, key, .. } = &mut *st;
                            if let Some(w) = wakes.as_mut() {
                                w.answered(&out.device, &reason, key, now_s());
                            }
                        }
                    });
                }
            });
        }
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(1));
            loop {
                every.tick().await;
                state.lock().await.advance();
            }
        })
    }

    /// Serve `GET /status` and `GET /metrics` on `addr`, plain HTTP (keep it on loopback).
    pub fn spawn_status(&self, addr: std::net::SocketAddr) -> tokio::task::JoinHandle<()> {
        let state = self.state.clone();
        tokio::spawn(async move {
            if let Err(e) = dsip_transport::status::serve(addr, move |p| status::render(state.clone(), p)).await {
                tracing::warn!("status port {addr}: {e}");
            }
        })
    }

    /// Accept connections on `listener` for ever: TLS, then a WebSocket upgrade served as a connection, or an HTTP
    /// request answered from `routes` (the browser client, `/config.json`, `/turn`, the hints proxy).
    pub async fn serve_tls(&self, listener: TcpListener, acceptor: tokio_rustls::TlsAcceptor, routes: Arc<www::Routes>) -> Result<()> {
        loop {
            let (tcp, peer) = listener.accept().await?;
            let (acceptor, relay, routes) = (acceptor.clone(), self.clone(), routes.clone());
            tokio::spawn(async move {
                match acceptor.accept(tcp).await {
                    Ok(tls_stream) => match www::dispatch(tls_stream, &routes, peer.ip()).await {
                        Ok(www::First::WebSocket(stream)) => {
                            if let Err(e) = relay.accept(stream, &peer.to_string()).await {
                                tracing::info!("{peer}: {e}");
                            }
                        }
                        Ok(www::First::Served) => {}
                        Err(e) => tracing::info!("{peer}: {e}"),
                    },
                    Err(e) => {
                        relay.state.lock().await.stats.tls_failed();
                        tracing::info!("{peer}: TLS handshake failed: {e}");
                    }
                }
            });
        }
    }

    /// Serve one connection over `stream` (already through TLS, or an in-process pipe): the WebSocket upgrade, then
    /// [`RelayServer::connection`]. `peer` names it in log lines.
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(&self, stream: S, peer: &str) -> Result<()> {
        let ws = tokio_tungstenite::accept_async_with_config(stream, Some(ws_config())).await?;
        self.connection(ws, peer).await
    }
}

type Tx = mpsc::UnboundedSender<String>;

struct State {
    /// Wake Profile (draft): registrations and the wakes for held invites; `None` without [`RelayConfig::wake`].
    wakes: Option<wake::Wakes>,
    key: KeyPair,
    supported: Supported,
    resolver: StaticResolver,
    web: Option<Arc<WebDocuments>>,
    seen: SeenIds,
    devices: HashMap<String, Tx>,
    identities: HashMap<String, HashSet<String>>,
    /// Each bound device's identity, the address it bound from and when (`dsip-relay admin bindings`).
    bound_at: HashMap<String, (String, String, i64)>,
    tracker: Relay,
    queue_store: Option<Arc<store::QueueStore>>,
    /// Recipients whose queues changed since the store was last written.
    touched: BTreeSet<String>,
    /// Whether a binding began or ended, or the clock advanced, since then (the known recipients may have changed).
    known_touched: bool,
    /// Per (session, leg): the leg's reject frame, forwarded if chosen as the attempt outcome.
    reject_frames: HashMap<(String, String), String>,
    /// Every verified frame within the retention window, by envelope id (served for queued deliveries).
    frames: HashMap<String, (String, i64)>,
    /// §19.4 rate limiting: key (sender identity or recipient) → recent introduction times.
    intro_log: HashMap<String, Vec<i64>>,
    intro_limit: usize,
    intro_window: i64,
    inbox_cap: usize,
    queue_budget_bytes: usize,
    /// §13.6: the identities a private relay serves; `None` = open.
    served: Option<HashSet<String>>,
    offline_retention: i64,
    /// §9.3/§22: this relay is the authority for identities bound to it.
    authority: Authority,
    /// Publication record frames by publication id (notify bodies carry them for third-party verification).
    records: HashMap<String, String>,
    /// Provenance statement frames by publication id (statements reference a specific record, §22.3).
    statements: HashMap<String, Vec<String>>,
    /// Presence record frames by record id, with their `expires_at` (P§3: notify bodies carry the signed record).
    presence_frames: HashMap<String, (String, i64)>,
    /// `delegation-revocation` records handed to this relay (§7.4, v0.8; spec-gap 57): applied to every later
    /// `hello` and frame. A `did:key` identity has no document, so this is where its revocations reach the relay.
    revocations: Vec<Envelope>,
    /// Counters and the sessions followed for the status page (`--status-listen`).
    stats: status::Stats,
}

impl State {
    /// Act on authority emissions: sign and deliver notifies/rejects.
    fn apply_authority(&mut self, em: Vec<Value>) {
        for e in em {
            if let Some(send) = e.get("send") {
                let to = send["to"].as_str().unwrap_or("").to_string();
                let now = now_s();
                let mut p = json!({
                    "dsip": {"core": "1.0", "min_core": "1.0", "profiles": [dsip_broadcast::PROFILE], "extensions": [], "critical": []},
                    "type": send["type"], "id": Ulid::generate().as_str(), "from": self.key.did(), "to": to,
                    "issued_at": now, "expires_at": now + 30,
                });
                if send["type"] == "notify" {
                    let mut body = send["body"].clone();
                    // Impl (spec-gap 21): the record and provenance statements ride in the body so the
                    // subscriber can verify the publisher independently of this relay (§9.3 RECOMMENDED).
                    if let Some(pid) = body["publication"].as_str().map(String::from) {
                        if let Some(f) = self.records.get(&pid) {
                            body["record"] = f.clone().into();
                        }
                        if let Some(st) = self.statements.get(&pid) {
                            body["statements"] = json!(st);
                        }
                    }
                    // P§3: each presence record rides as the device's signed envelope beside its fields
                    if let Some(recs) = body.get_mut("records").and_then(Value::as_array_mut) {
                        for r in recs {
                            if let Some((f, _)) = r["id"].as_str().and_then(|id| self.presence_frames.get(id)) {
                                r["frame"] = f.clone().into();
                            }
                        }
                    }
                    p["subscription"] = send["subscription"].clone();
                    p["seq"] = send["seq"].clone();
                    p["state"] = send["state"].clone();
                    if let Some(r) = send.get("reason") {
                        p["reason"] = r.clone();
                    }
                    p["body"] = body;
                } else if send["type"] == "error" {
                    // P§3: a refused presence record is answered in reply to it, with `retry_after` when rate-limited
                    for k in ["in_reply_to", "reason", "retry_after"] {
                        if let Some(v) = send.get(k) {
                            p[k] = v.clone();
                        }
                    }
                } else {
                    p["session"] = send["session"].clone();
                    p["reason"] = send["reason"].clone();
                }
                let f = sign(&p, &self.key, &self.key.kid()).frame();
                self.deliver(&to, &f);
            } else {
                tracing::info!("authority: {e}");
            }
        }
    }

    /// P§6 (spec-gap 144): the grants a `subscribe` presents in `claims`, each verified as a credential (§19.4: its
    /// signature and its signer's delegation, now; not its delivery window) and summarised for the authority as
    /// `{type: dsip-grant, grant: {id, from, identity, to, scope, valid_until, presence_audience?}}`. One that does not
    /// verify is left out: it could not admit.
    fn presented_grants(&self, p: &Value) -> Value {
        let resolver = Over(&self.resolver, self.web.as_deref());
        let mut ctx = dsip_core::envelope::Context::new(now_s(), &resolver);
        ctx.revocations = self.revocations.clone();
        let out: Vec<Value> = p["claims"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["type"] == "dsip-grant")
            .filter_map(|c| {
                let env = dsip_core::envelope::Envelope::from_value(&c["grant"]).ok()?;
                let g = dsip_core::grant::credential(&env, &ctx)?;
                let mut summary = json!({"id": g["id"], "from": g["from"], "identity": g["from"], "to": g["to"],
                                         "scope": g["scope"], "valid_until": g["valid_until"]});
                if let Some(a) = g.get("presence_audience") {
                    summary["presence_audience"] = a.clone();
                }
                Some(json!({"type": "dsip-grant", "grant": summary}))
            })
            .collect();
        Value::Array(out)
    }

    fn error_frame(&mut self, to: &str, reason: &str, in_reply_to: Option<&str>, session: Option<&str>, detail: Option<&str>) -> String {
        self.stats.refused(reason, detail);
        let now = now_s();
        let mut p = json!({
            "dsip": version_block(&self.supported, &[]), "type": "error", "id": Ulid::generate().as_str(),
            "from": self.key.did(), "to": to, "reason": reason, "issued_at": now, "expires_at": now + 30,
        });
        if let Some(i) = in_reply_to {
            p["in_reply_to"] = i.into();
        }
        if let Some(s) = session {
            p["session"] = s.into();
        }
        if let Some(d) = detail {
            p["detail"] = d.into();
        }
        sign(&p, &self.key, &self.key.kid()).frame()
    }

    /// Whether this relay serves `identity`: every identity for an open relay, the configured ones for a private one.
    ///
    /// Spec: §13.6.
    fn serves(&self, identity: &str) -> bool {
        self.served.as_ref().is_none_or(|s| s.contains(identity))
    }

    /// The identity behind a `to` that may name a device bound here.
    fn identity_of(&self, to: &str) -> String {
        self.tracker.devices.get(to).cloned().unwrap_or_else(|| to.to_string())
    }

    /// Why a private relay refuses this envelope, if it does (§13.6); `None` for an open relay or allowed traffic.
    /// Introductions refused here are dropped silently by the caller (§19.4).
    fn private_refusal(&self, t: &str, sender_identity: &str, to: &str, p: &Value) -> Option<&'static str> {
        self.served.as_ref()?;
        match t {
            // §9.3/§22: the relay is the authority only for the identities it serves
            "publish" | "unpublish" | "provenance" | "presence" if !self.serves(sender_identity) => Some("relay does not serve this identity"),
            "subscribe" if !self.serves(p["target"].as_str().unwrap_or("")) => Some("relay does not serve the target"),
            "publish" | "unpublish" | "provenance" | "subscribe" | "presence" => None,
            _ => {
                let recipient = self.identity_of(to);
                if !self.serves(&recipient) && !self.serves(sender_identity) {
                    Some("relay serves neither party")
                } else if !self.serves(&recipient) && self.tracker.legs_for(to).is_empty() {
                    Some("relay holds envelopes only for the identities it serves")
                } else {
                    None
                }
            }
        }
    }

    /// A `delegation-revocation` handed to this relay (§7.4, v0.8; spec-gap 57). The frame passed verification like
    /// any other; here its signer must be the subject itself (the semantic signer rule needs the kid, which the
    /// pipeline does not supply). Held for every later verification; the named device's binding ends at once (its
    /// connection loop ends when its channel is dropped) and its next `hello` is refused (`transport.hello-rejected`,
    /// `delegation-revoked`). Impl (spec-gap 113): the record itself is the carriage, on any bound connection, not
    /// only the subject's own: a validly signed record can only remove authority, "so its source does not matter"
    /// (§7.4); nothing acknowledges it.
    fn revoke(&mut self, sender: &str, inb: &Inbound) {
        let p = &inb.verified.payload;
        let subject = p["subject"].as_str().unwrap_or("").to_string();
        let revoked = p["device"].as_str().unwrap_or("").to_string();
        if subject.is_empty() || revoked.is_empty() || inb.verified.signer_did != subject {
            let f = self.error_frame(sender, "transport.routing-refused", p["id"].as_str(), None, Some("revocation-signer-not-subject"));
            self.deliver(sender, &f);
            return;
        }
        tracing::info!("delegation of {revoked} revoked by {subject} ({})", p["reason"].as_str().unwrap_or(""));
        if !self.revocations.contains(&inb.envelope) {
            self.revocations.push(inb.envelope.clone());
        }
        if self.devices.remove(&revoked).is_some() {
            tracing::info!("closed the binding of revoked device {revoked}");
        }
        let State { wakes, key, .. } = self;
        if let Some(w) = wakes.as_mut() {
            w.revoked(&revoked, key, now_s()); // W§4.3
        }
    }

    /// Bytes of the envelopes currently queued for offline recipients (their frames are held in `frames`).
    fn queued_bytes(&self) -> usize {
        self.tracker
            .inbox
            .values()
            .flatten()
            .filter_map(|q| self.frames.get(&q.message.id))
            .map(|(frame, _)| frame.len())
            .sum()
    }

    fn deliver(&self, device: &str, frame: &str) -> bool {
        if tracing::enabled!(tracing::Level::TRACE) {
            // What this relay can read of what it routes (§20.7; with §10.4 sealing, only the routing fields).
            if let Some(p) = Envelope::from_frame(frame).ok().and_then(|e| dsip_core::b64::decode(&e.payload)) {
                tracing::trace!("routed payload → {device}: {}", String::from_utf8_lossy(&p));
            }
        }
        match self.devices.get(device) {
            Some(tx) => tx.send(frame.to_string()).is_ok(),
            None => false,
        }
    }

    /// §19.4: sliding-window rate limit; returns seconds until a slot frees, or 0 if allowed (and records it).
    fn intro_rate(&mut self, key: &str) -> i64 {
        let now = now_s();
        let log = self.intro_log.entry(key.to_string()).or_default();
        log.retain(|t| *t + self.intro_window > now);
        if log.len() >= self.intro_limit {
            return log[0] + self.intro_window - now;
        }
        log.push(now);
        0
    }

    /// Advance the tracker's clock to now (expires queues) and forget frames past retention.
    fn tick(&mut self) -> Vec<Emission> {
        let now = now_s();
        self.stats.prune(now);
        self.frames.retain(|_, (_, deadline)| *deadline > now);
        let delta = now - self.tracker.now;
        if delta > 0 {
            let em = self.tracker.step(&RelayEvent::Advance { advance: delta });
            self.forget(now);
            self.known_touched = true;
            em
        } else {
            vec![]
        }
    }

    /// Advance the clock and act on what that emits: queue expiry, legs expiring with their invite and the attempt
    /// outcome that follows (§12.7 rule 6, spec-gap 132), what the relay forgets (spec-gap 131).
    fn advance(&mut self) {
        let em = self.tick();
        self.apply(em, None, None, "");
        // P§3, §22.1: presence records past expires_at or their unbind grace, and lapsed subscriptions, end with notifies
        let em = self.authority.advance_to(now_s());
        self.apply_authority(em);
        let State { wakes, key, .. } = self;
        if let Some(w) = wakes.as_mut() {
            w.settle(now_s(), key);
        }
    }

    /// This binary's own tables follow what the tracker and the authority still hold, at most once a second (spec-gap
    /// 131: the relay's memory follows live traffic). Nothing here is observable: a reject frame is kept only while its
    /// attempt is (the outcome is chosen from it), an introduction rate-limit key only while it has a time inside the
    /// window, a publication record and its statements only while the publication is the stream's current one.
    ///
    /// Spec: none (infrastructure).
    fn forget(&mut self, now: i64) {
        let tracker = &self.tracker;
        self.reject_frames.retain(|(sid, _), _| tracker.attempt_initiator(sid).is_some());
        let window = self.intro_window;
        self.intro_log.retain(|_, log| {
            log.retain(|t| *t + window > now);
            !log.is_empty()
        });
        let current: HashSet<&str> = self.authority.publications.values().map(|p| p.publication.as_str()).collect();
        self.records.retain(|id, _| current.contains(id.as_str()));
        self.statements.retain(|id, _| current.contains(id.as_str()));
    }

    /// Write what changed to the queue store: the queues touched and, after a binding change or a clock advance, the
    /// known recipients. A failure is logged; the relay goes on from memory.
    fn persist(&mut self) {
        let Some(store) = &self.queue_store else { return };
        let known = if std::mem::take(&mut self.known_touched) {
            Some(self.tracker.known_recipients()).filter(|k| store.known_changed(k))
        } else {
            None
        };
        if self.touched.is_empty() && known.is_none() {
            return;
        }
        let touched = std::mem::take(&mut self.touched);
        let (inbox, frames) = (&self.tracker.inbox, &self.frames);
        let queues = touched.iter().map(|to| (to.as_str(), inbox.get(to)));
        if let Err(e) = store.write(queues, known.as_ref(), |id| frames.get(id).map(|(f, _)| f.as_str())) {
            tracing::warn!("{e}");
        }
    }

    /// Act on tracker emissions for a frame that just arrived (or `None` on bind/advance).
    fn apply(&mut self, em: Vec<Emission>, sender: Option<&str>, inbound: Option<&Inbound>, sid: &str) {
        for e in em {
            match e {
                Emission::Deliver { leg, msg_type, id: Some(id), .. } => {
                    // A queued envelope, or an invite for a leg added mid-attempt: served from the frame store.
                    if let Some((frame, _)) = self.frames.get(&id).cloned() {
                        tracing::info!("deliver stored {msg_type} {id} → {leg}");
                        self.deliver(&leg, &frame);
                    }
                }
                Emission::Deliver { leg, msg_type, id: None, .. } => {
                    if let Some(inb) = inbound {
                        tracing::info!("{msg_type} {sid} → leg {leg}");
                        self.deliver(&leg, &inb.frame);
                    }
                }
                Emission::Forward { msg_type, from, session, .. } => {
                    // the emission names its attempt: an outcome reached on a clock advance has no frame in hand
                    let sid = session.as_str();
                    let Some(initiator) = self.tracker.attempt_initiator(sid).map(String::from) else { continue };
                    if msg_type == "reject" {
                        // §12.7 rule 6: forward the most informative leg's reject as the attempt outcome
                        if let Some(f) = self.reject_frames.get(&(sid.to_string(), from.clone())).cloned() {
                            tracing::info!("attempt {sid} outcome: reject from {from}");
                            self.stats.attempt_failed(sid, "reject");
                            self.deliver(&initiator, &f);
                        }
                    } else if let Some(inb) = inbound {
                        self.deliver(&initiator, &inb.frame);
                    }
                }
                Emission::Queue { to, msg_type } => {
                    tracing::info!("queued {msg_type} for {to} (§13.3)");
                    self.touched.insert(to);
                }
                Emission::Dequeue { to, msg_type, why } => {
                    tracing::info!("dequeued {msg_type} for {to}: {why}");
                    self.touched.insert(to);
                }
                Emission::Send(m) if m.msg_type == "error" => {
                    // The relay's own signed error. Usually it answers the sender of the frame in hand; the attempt
                    // outcome `transport.no-response` (§12.7 rule 6, spec-gap 76) goes to the initiator and may come
                    // from a timer, with no frame in hand at all.
                    let to = if m.to.is_empty() { sender.map(String::from) } else { Some(m.to.clone()) };
                    if let Some(to) = to {
                        let reason = m.reason.as_deref().unwrap_or("transport.routing-refused");
                        let f = self.error_frame(&to, reason, m.in_reply_to.as_deref(), m.session.as_deref(), None);
                        if reason == "transport.no-response" {
                            let sid = m.session.as_deref().unwrap_or(sid);
                            tracing::info!("attempt {sid} outcome: no leg responded");
                            self.stats.attempt_failed(sid, "no-response");
                        }
                        self.deliver(&to, &f);
                    }
                }
                Emission::Drop(why) => tracing::info!("dropped on {sid}: {why}"),
                _ => {}
            }
        }
        self.persist();
    }

    /// Route one verified frame from `sender` (a bound device) acting for `sender_identity`.
    fn route(&mut self, sender: &str, sender_identity: &str, inbound: &Inbound) {
        let p = &inbound.verified.payload;
        let t = inbound.verified.msg_type().to_string();
        let id = p["id"].as_str().unwrap_or("").to_string();
        let to = p["to"].as_str().unwrap_or("").to_string();
        let Some(msg) = Message::from_payload(p) else { return };
        let sid = msg.session_id().to_string();
        self.advance();
        self.stats.frame_in(&t);

        if t == "introduction" {
            // §19.4: relays MUST rate-limit introductions per sender identity and per recipient inbox.
            let wait = self.intro_rate(&format!("from:{sender_identity}")).max(self.intro_rate(&format!("to:{to}")));
            if wait > 0 {
                let mut f = self.error_frame(sender, "policy.rate-limited", Some(&id), None, None);
                if let Ok(mut env) = Envelope::from_frame(&f) {
                    if let Some(mut payload) = dsip_core::b64::decode(&env.payload).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
                        payload["retry_after"] = wait.into();
                        env = sign(&payload, &self.key, &self.key.kid());
                        f = env.frame();
                    }
                }
                self.deliver(sender, &f);
                return;
            }
        }
        // §13.6 private relay: only traffic to or from a served identity, and nothing held for anyone else.
        if let Some(refusal) = self.private_refusal(&t, sender_identity, &to, p) {
            tracing::info!("private relay: refusing {t} from {sender_identity} for {to}: {refusal}");
            if t != "introduction" {
                let f = self.error_frame(sender, "transport.routing-refused", Some(&id), None, Some(refusal));
                self.deliver(sender, &f);
            }
            return;
        }
        // A cancel for an invite still queued for this recipient only shrinks the queue (§12.11): neither bound
        // below refuses it.
        let shrinks_queue = t == "cancel"
            && self.tracker.inbox.get(&to).is_some_and(|q| q.iter().any(|m| m.message.msg_type == "invite" && m.message.id == sid));
        // Inbox cap (§13.3 boundary): refuse when the recipient's queue is full.
        if !shrinks_queue && self.tracker.legs_for(&to).is_empty() && self.tracker.inbox.get(&to).map(|q| q.len()).unwrap_or(0) >= self.inbox_cap {
            if t != "introduction" {
                let f = self.error_frame(sender, "transport.routing-refused", Some(&id), None, Some("recipient inbox full"));
                self.deliver(sender, &f);
            }
            return;
        }
        // Memory budget across all recipients (§13.3: refuse, never drop silently). Impl (spec-gap 99): a relay holds
        // queued envelopes in memory, so the per-recipient cap alone lets traffic to many recipients grow it without
        // bound. Introductions are dropped silently, as at the inbox cap, so a full relay reveals nothing (§19.4).
        if !shrinks_queue && self.tracker.legs_for(&to).is_empty() && self.queued_bytes() + inbound.frame.len() > self.queue_budget_bytes {
            tracing::warn!("queue budget of {} bytes reached: refusing {t} for {to}", self.queue_budget_bytes);
            if t != "introduction" {
                let f = self.error_frame(sender, "transport.routing-refused", Some(&id), None, Some("relay queue full"));
                self.deliver(sender, &f);
            }
            return;
        }
        // Keep the frame within retention so queued deliveries and mid-attempt legs can be served.
        let deadline = p["expires_at"].as_i64().unwrap_or(now_s()).min(now_s() + self.offline_retention);
        self.frames.insert(id.clone(), (inbound.frame.clone(), deadline));
        if t == "reject" && self.tracker.attempt_initiator(&sid).is_some_and(|i| i != sender) {
            self.reject_frames.insert((sid.clone(), sender.to_string()), inbound.frame.clone());
        }
        if matches!(t.as_str(), "publish" | "unpublish" | "subscribe" | "provenance" | "presence" | "grant-revocation") {
            // §9.3/§22: addressed to this relay as the target's authority (publish/unpublish carry no `to`);
            // P§3: a device publishes its presence record to the relay it binds to; P§7: and revokes its grants there.
            if matches!(t.as_str(), "subscribe" | "presence" | "grant-revocation") && to != self.key.did() {
                let why = format!("{t} must address this relay");
                let why = why.as_str();
                let f = self.error_frame(sender, "transport.routing-refused", Some(&id), None, Some(why));
                self.deliver(sender, &f);
                return;
            }
            if t == "presence" {
                let now = now_s();
                self.presence_frames.retain(|_, (_, exp)| *exp > now);
                self.presence_frames.insert(id.clone(), (inbound.frame.clone(), p["expires_at"].as_i64().unwrap_or(now)));
            }
            let mut m = p.clone();
            m["from"] = sender.into();
            if t == "subscribe" {
                m["claims"] = self.presented_grants(p);
                m["profiles"] = p["dsip"]["profiles"].clone(); // P§12.6: whether it reads sealed records
            }
            self.authority.learn_identity(sender, sender_identity);
            if t == "publish" {
                self.records.insert(id.clone(), inbound.frame.clone());
            }
            if t == "provenance" {
                self.statements.entry(p["original_publication"].as_str().unwrap_or("").to_string()).or_default().push(inbound.frame.clone());
            }
            let em = self.authority.advance_to(now_s());
            self.apply_authority(em);
            let em = self.authority.recv_value(&m);
            self.apply_authority(em);
            return;
        }
        let to_identity = self.identity_of(&to);
        self.stats.observe(&t, &sid, sender_identity, &to_identity, now_s());
        let em = self.tracker.step(&RelayEvent::Recv { recv: msg });
        self.apply(em, Some(sender), Some(inbound), &sid);
        self.wake_on(&t, &sid, &to, sender, sender_identity, p);
    }

    /// W§5.1: an invite this relay now holds (an attempt, or a queued envelope) wakes the registered devices it is
    /// held for; an initiator's `cancel` ends the call it woke them for.
    fn wake_on(&mut self, t: &str, sid: &str, to: &str, sender: &str, sender_identity: &str, p: &Value) {
        let held = t == "invite"
            && (self.tracker.attempt_initiator(sid).is_some()
                || self.tracker.inbox.get(to).is_some_and(|q| q.iter().any(|m| m.message.msg_type == "invite" && m.message.id == sid)));
        let State { wakes, key, .. } = self;
        let Some(w) = wakes.as_mut() else { return };
        if held {
            let devices = w.devices_for(to);
            w.hold(now_s(), sid, &devices, p["expires_at"].as_i64().unwrap_or(0), (sender, sender_identity), key);
        } else if t == "cancel" {
            w.drop_invite(now_s(), sid, key);
        }
    }

    /// A `wake-register` from bound `device` of `identity` (W§4.2): verified by stages 1–11 here, the profile's checks
    /// by [`wake::Wakes::register`], answered `wake-accepted` or a signed `error`.
    fn wake_register(&mut self, device: &str, identity: &str, frame: &str) {
        let now = now_s();
        let verdict = {
            let State { resolver, web, seen, revocations, .. } = &mut *self;
            dsip_transport::verify::verify_profile_frame(frame, now, &Over(resolver, web.as_deref()), revocations, seen)
        };
        let inb = match verdict {
            Ok(inb) => inb,
            Err(v) => {
                let code = v.to_expect()["code"].as_str().unwrap_or("rejected").to_string();
                let f = self.error_frame(device, v.reason.unwrap_or("transport.routing-refused"), None, None, Some(&code));
                self.deliver(device, &f);
                return;
            }
        };
        let p = &inb.verified.payload;
        let id = p["id"].as_str().unwrap_or("").to_string();
        if inb.verified.signer_did != device || p["to"] != self.key.did() {
            let f = self.error_frame(device, "transport.routing-refused", Some(&id), None, Some("wake-register is from the bound device to this relay"));
            self.deliver(device, &f);
            return;
        }
        let relay = self.key.did();
        let Some(w) = self.wakes.as_mut() else { return };
        match w.register(p, device, identity, &relay, now) {
            Ok(()) => {
                let a = dsip_wake::accepted_message(&relay, device, &id, None, now);
                let f = sign(&a, &self.key, &self.key.kid()).frame();
                self.deliver(device, &f);
            }
            Err(reason) => {
                let f = self.error_frame(device, reason, Some(&id), None, None);
                self.deliver(device, &f);
            }
        }
    }
}

/// The `type` a frame's payload claims, before it is verified (to choose the verification path).
fn claimed_type(frame: &str) -> Option<String> {
    let env = Envelope::from_frame(frame).ok()?;
    let p: Value = serde_json::from_slice(&dsip_core::b64::decode(&env.payload)?).ok()?;
    p["type"].as_str().map(String::from)
}

/// The grants an unverified `subscribe` frame presents in `claims`, as frames; empty for anything else.
fn presented_grant_frames(frame: &str) -> Vec<String> {
    let Ok(env) = Envelope::from_frame(frame) else { return vec![] };
    let Some(p) = dsip_core::b64::decode(&env.payload).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else { return vec![] };
    if p["type"] != "subscribe" {
        return vec![];
    }
    p["claims"].as_array().into_iter().flatten().filter(|c| c["type"] == "dsip-grant").map(|c| c["grant"].to_string()).collect()
}

impl RelayServer {
    /// Fetch the `did:web` documents `frame` names that the relay does not hold, before it is verified under the
    /// lock (a fetch must not hold it): the signer, its delegations' issuers, and for a `subscribe` the signers of the
    /// grants it presents (P§6). Without [`RelayConfig::did_web`], nothing.
    async fn fetch_documents(&self, frame: &str) {
        let (web, dids) = {
            let st = self.state.lock().await;
            let Some(web) = st.web.clone() else { return };
            let mut dids = web.missing(frame, &st.resolver);
            for grant in presented_grant_frames(frame) {
                for d in web.missing(&grant, &st.resolver) {
                    if !dids.contains(&d) {
                        dids.push(d);
                    }
                }
            }
            dids.truncate(WebDocuments::PER_FRAME);
            (web, dids)
        };
        if !dids.is_empty() {
            web.fetch(&dids).await;
        }
    }

    /// Serve one WebSocket connection until it closes: its `hello` binds a device (§13.2), then every frame is verified
    /// and routed. `peer` names it in log lines.
    pub async fn connection<S: AsyncRead + AsyncWrite + Unpin>(&self, mut ws: WebSocketStream<S>, peer: &str) -> Result<()> {
        let state = &self.state;

        // --- hello phase (§13.2): first envelope, within HELLO_TIMEOUT_S
        let first = match tokio::time::timeout(Duration::from_secs(HELLO_TIMEOUT_S), ws.next()).await {
            Ok(Some(Ok(WsMessage::Text(t)))) => t.to_string(),
            Ok(Some(Ok(_))) | Ok(None) => return Err(Error::NoHello),
            Ok(Some(Err(e))) => return Err(e.into()),
            Err(_) => {
                let _ = ws.close(None).await;
                return Err(Error::HelloTimeout(HELLO_TIMEOUT_S));
            }
        };
        self.fetch_documents(&first).await;
        let (device, identity, hello_id) = {
            let mut st = state.lock().await;
            let sem = dsip_schema::SemanticContext { supported: st.supported.clone(), ..Default::default() };
            let State { resolver, web, seen, revocations, .. } = &mut *st;
            match verify_frame_with(&first, now_s(), &Over(resolver, web.as_deref()), &[], revocations, seen, &sem) {
                Ok(inb) if inb.verified.msg_type() == "hello" && inb.verified.payload.get("in_reply_to").is_none() => {
                    let p = &inb.verified.payload;
                    (inb.verified.signer_did.clone(), inb.verified.identity.clone(), p["id"].as_str().unwrap_or("").to_string())
                }
                Ok(inb) => {
                    let to = inb.verified.signer_did.clone();
                    let f = st.error_frame(&to, "transport.hello-required", Some(inb.verified.payload["id"].as_str().unwrap_or("")), None, None);
                    let _ = ws.send(WsMessage::Text(f.into())).await;
                    let _ = ws.close(None).await;
                    return Err(Error::NotHello(inb.verified.msg_type().to_string()));
                }
                Err(v) => {
                    // We cannot address the sender before verification; close with the reason in the close frame: the
                    // reason token and the verdict's code token as the vectors spell it (`delegation-revoked`, …).
                    let code = v.to_expect()["code"].as_str().unwrap_or("rejected").to_string();
                    st.stats.refused("transport.hello-rejected", Some(&code));
                    let _ = ws
                        .close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
                            reason: format!("transport.hello-rejected: {code}").into(),
                        }))
                        .await;
                    return Err(Error::HelloRejected { code, detail: v.detail.unwrap_or_default() });
                }
            }
        };

        // --- bind and answer with the relay hello
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        // a weak handle: it does not keep the channel open, so a replaced connection still sees its queue close
        let mine = tx.downgrade();
        {
            let mut st = state.lock().await;
            if let Some(old) = st.devices.insert(device.clone(), tx) {
                // §13.2: a new verified hello from an already-bound device replaces the prior connection, and the relay
                // says so on it (spec-gap 158) so that its client does not reconnect and replace this one in turn. The
                // old connection sends what is queued, this last, then sees its queue end and closes.
                tracing::info!("{peer}: rebinding {device} (replacing prior connection)");
                let f = st.error_frame(&device, "transport.replaced", None, None, Some("this device bound here on another connection"));
                let _ = old.send(f);
            }
            st.identities.entry(identity.clone()).or_default().insert(device.clone());
            let now = now_s();
            st.bound_at.insert(device.clone(), (identity.clone(), peer.to_string(), now));
            let hello = json!({
                "dsip": version_block(&st.supported, &[]), "type": "hello", "id": Ulid::generate().as_str(),
                "in_reply_to": hello_id, "from": st.key.did(),
                "capabilities": {"max_envelope_bytes": dsip_core::WS_MAX_ENVELOPE_BYTES, "store_and_forward": true,
                                 "offline_retention_s": st.offline_retention,
                                 // §19.4 (profile-card/1.0): this relay holds the larger introductions
                                 "introduction_max_bytes": dsip_core::profile_card::INTRODUCTION_CARD_MAX_BYTES,
                                 "rate_limit": {"envelopes_per_minute": 600, "invites_per_minute": 30}},
                "issued_at": now, "expires_at": now + 30,
            });
            let mut hello = hello;
            if st.wakes.is_some() {
                // W§4.4: the profile and the kinds this relay sends
                hello["capabilities"]["wake"] = json!({"profiles": [dsip_wake::PROFILE], "kinds": wake::KINDS});
            }
            let env: Envelope = sign(&hello, &st.key, &st.key.kid());
            ws.send(WsMessage::Text(env.frame().into())).await?;
            tracing::info!("{peer}: bound device {device} for identity {identity}");
            st.stats.bound();
            // §13.3: binding flushes the store-and-forward queues and adds this device as a leg to live attempts (§12.7 rule 3)
            st.advance();
            let em = st.tracker.step(&RelayEvent::Relay(RelayAction::Bind { device: device.clone(), identity: identity.clone() }));
            // the bind flushed both queues (§13.3), and the device and its identity are known
            st.touched.insert(identity.clone());
            st.touched.insert(device.clone());
            st.known_touched = true;
            st.apply(em, None, None, "");
            if let Some(w) = st.wakes.as_mut() {
                w.bound(&device, true);
            }
            let em = st.authority.advance_to(now_s());
            st.apply_authority(em);
            let em = st.authority.step(&dsip_broadcast::AuthorityEvent::Relay(dsip_broadcast::authority::Binding::Bind { device: device.clone(), identity: identity.clone() }));
            st.apply_authority(em);
        }

        // --- steady state
        let result: Result<()> = async {
            loop {
                tokio::select! {
                    inbound = ws.next() => match inbound {
                        Some(Ok(WsMessage::Text(t))) => {
                            self.fetch_documents(&t).await;
                            let mut st = state.lock().await;
                            if st.wakes.is_some() && claimed_type(&t).as_deref() == Some("wake-register") {
                                st.wake_register(&device, &identity, &t);
                                continue;
                            }
                            let sem = dsip_schema::SemanticContext { supported: st.supported.clone(), ..Default::default() };
                            let verdict = {
                                let State { resolver, web, seen, revocations, .. } = &mut *st;
                                verify_frame_with(&t, now_s(), &Over(resolver, web.as_deref()), &[], revocations, seen, &sem)
                            };
                            match verdict {
                                Ok(inb) => {
                                    if inb.verified.msg_type() == "hello" {
                                        tracing::info!("{peer}: re-hello ignored (binding unchanged)");
                                    } else if inb.verified.msg_type() == "delegation-revocation" {
                                        // signed by the identity key, not the bound device: handled before the signer check
                                        st.revoke(&device, &inb);
                                    } else if inb.verified.signer_did != device {
                                        let f = st.error_frame(&device, "transport.routing-refused", Some(inb.verified.payload["id"].as_str().unwrap_or("")), None, Some("signer is not the bound device"));
                                        st.deliver(&device, &f);
                                    } else {
                                        st.route(&device, &identity, &inb);
                                    }
                                }
                                Err(v) => {
                                    // §13.2: no silent drops on a live connection
                                    // A verdict that names a reason token (e.g. `policy.subscription-lifetime`, §9.3 v0.7) is
                                    // answered with that token; otherwise the generic routing refusal.
                                    // The detail is the verdict's code token (`schema-invalid`, …) and its detail, as the
                                    // vectors spell them, so a client can show why its frame was refused.
                                    let expect = v.to_expect();
                                    let code = expect["code"].as_str().unwrap_or("rejected").to_string();
                                    let detail = match &v.detail {
                                        Some(d) if !d.is_empty() => format!("{code}: {d}"),
                                        _ => code,
                                    };
                                    let f = st.error_frame(&device, v.reason.unwrap_or("transport.routing-refused"), None, None, Some(&detail));
                                    st.deliver(&device, &f);
                                }
                            }
                        }
                        Some(Ok(WsMessage::Ping(p))) => ws.send(WsMessage::Pong(p)).await?,
                        Some(Ok(WsMessage::Pong(_))) => {}
                        Some(Ok(WsMessage::Close(_))) | None => break,
                        Some(Ok(_)) => {
                            let _ = ws.close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Unsupported,
                                reason: "text frames only".into() })).await;
                            break;
                        }
                        Some(Err(tokio_tungstenite::tungstenite::Error::Capacity(_))) => {
                            // §13.2: oversize → close 1009
                            let _ = ws.close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size,
                                reason: "transport.envelope-too-large".into() })).await;
                            break;
                        }
                        Some(Err(e)) => return Err(e.into()),
                    },
                    outbound = rx.recv() => match outbound {
                        Some(frame) => ws.send(WsMessage::Text(frame.into())).await?,
                        None => {
                            // replaced (§13.2) or revoked: the binding has moved on, close cleanly
                            let _ = ws.close(None).await;
                            break;
                        }
                    },
                }
            }
            Ok(())
        }
        .await;

        let mut st = state.lock().await;
        st.stats.unbound();
        // §13.2: a connection replaced by a newer hello leaves the binding to it: removing the device here would drop the
        // new connection's queue (closing it too) and unbind a device that is still bound
        let replaced = st.devices.get(&device).is_some_and(|t| mine.upgrade().is_none_or(|m| !m.same_channel(t)));
        if replaced {
            tracing::info!("{peer}: replaced connection of {device} closed");
            return result;
        }
        st.devices.remove(&device);
        st.bound_at.remove(&device);
        if let Some(set) = st.identities.get_mut(&identity) {
            set.remove(&device);
            if set.is_empty() {
                st.identities.remove(&identity);
            }
        }
        let _ = st.tracker.step(&RelayEvent::Relay(RelayAction::Unbind { device: device.clone(), identity: identity.clone() }));
        if let Some(w) = st.wakes.as_mut() {
            w.bound(&device, false);
        }
        st.known_touched = true;
        st.persist();
        // P§3: every device's unbind, not only the identity's last: its own record's grace starts from it
        let em = st.authority.step(&dsip_broadcast::AuthorityEvent::Relay(dsip_broadcast::authority::Binding::Unbind { device: device.clone(), identity: identity.clone() }));
        st.apply_authority(em);
        tracing::info!("{peer}: unbound {device}");
        result
    }
}
