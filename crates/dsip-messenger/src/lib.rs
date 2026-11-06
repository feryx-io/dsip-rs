//! `dsip-messenger` — a messaging device for native applications: the
//! [`dsip_messaging_device::messenger::Messenger`] (the [`Engine`], which decides everything the Messaging Profile asks
//! of a device) together with what a native host does around it: the `wss` connection to the device's mailbox and
//! its reconnects, requests that wait for their answers, KeyPackages fetched from other identities' mailboxes, blobs
//! fetched and retried, successor groups created when a hub is gone, and the state written after every step.
//!
//! The application implements [`Host`]: every [`Output`] reaches it in order, as it happens, with the engine to read
//! from. It drives the device with [`Messenger::recv`] (a frame from the mailbox, `None` while offline),
//! [`Messenger::on_frame`], [`Messenger::tick`] once a second, and [`Messenger::settle`] after anything that set
//! deposits going; it acts with the engine ([`Messenger::engine_mut`]) and sends what the engine returns
//! ([`Messenger::send_frames`]). dsip-msg is such a host.
//!
//! Spec: M§4.2 (the mailbox is found in the DID document), M§4.3 (bind with `hello`; rebinding re-sends what the
//! last binding took with it, M§9.3), M§5.4–M§5.5 (sync, KeyPackage fetch), M§7.5 and M§9.4 (successors of a group
//! whose hub is gone, retried with backoff), M§8.4 (blob fetch, verification, retries; spec-gap 106), §13.2
//! (reconnect with exponential backoff and full jitter: 1 s, ×2, 60 s).
//!
//! M§4.2 discovery of another identity's mailbox, in §8.1's order: the DID document files, then the identity's
//! `did:web` document fetched ([`Messenger::with_did_web`]), then, for an identity with no document, its reachability
//! hint on the hints nodes ([`Messenger::with_hints`]); a hint is reused for [`HINT_REUSE_S`] at most.
//!
//! Impl: the state is written under the engine's keys (`messenger`, and `resume`, which the item transactions write
//! too, spec-gap 44) and one key of the host's ([`Config::host_key`]): the blob fetches still to retry, beside what
//! the host adds ([`Host::saved`]).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use dsip_core::did::StaticResolver;
use dsip_core::envelope::Envelope;
use dsip_core::keys::KeyPair;
use dsip_core::version::Supported;
use dsip_messaging::wire;
use dsip_messaging_device::events::SuccessorDue;
use dsip_messaging_device::{blob, Event, Store, Ui};
use dsip_transport::conn::{ConnectParams, Connection};
use dsip_transport::now_s;
use dsip_transport::verify::SeenIds;

mod error;

pub use dsip_messaging_device::messenger::Messenger as Engine;
pub use error::{Error, Result};

/// Seconds a request waits for its answer.
pub const REQUEST_TIMEOUT_S: u64 = 20;
/// Seconds [`Messenger::settle`] waits at most.
pub const SETTLE_S: u64 = 60;
/// Seconds a mailbox found through a hint is used before the hint is looked up again: an identity that moves publishes
/// a newer hint (§8.3), and what is sent to it follows soon after (as the mailbox service does).
pub const HINT_REUSE_S: i64 = 60;

/// Who the device is and where its mailbox is.
pub struct Config {
    /// The identity DID.
    pub identity: String,
    /// The device key: signs everything on the wire.
    pub device: KeyPair,
    /// The identity's delegation to the device (§7.4), presented in every `hello`.
    pub delegation: Envelope,
    /// The device's mailbox: `(DID, wss URI)` ([`mailbox_of`]).
    pub mailbox: (String, String),
    /// DID documents the device resolves from, re-read before each step: a revocation published since is seen (§8.1,
    /// spec-gap 57).
    pub resolver_files: Vec<PathBuf>,
    /// Trust anchor for the mailboxes and blob sources; native roots when `None`.
    pub ca: Option<PathBuf>,
    /// Where fetched blobs are written, decrypted.
    pub media_dir: PathBuf,
    /// The store key the host's state is written under.
    pub host_key: String,
}

/// Something the application hears about, in the order it happened.
#[derive(Debug)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)] // an output is built once and handed over at once, as the engine's events are
pub enum Output {
    /// An event of the engine's, other than the frames and syncs the messenger sends itself.
    Event(Event),
    /// Bound to the mailbox.
    Connected {
        /// The identity.
        identity: String,
        /// The mailbox DID.
        mailbox: String,
    },
    /// The mailbox closed the connection; a redial is scheduled.
    Disconnected,
    /// The connection failed; a redial is scheduled.
    ConnectionError(String),
    /// A scheduled redial failed (§13.2).
    ReconnectFailed {
        /// Why.
        error: String,
        /// Seconds until the next attempt.
        wait_s: i64,
    },
    /// Something the messenger did failed (a frame not sent, a step's work).
    Error(String),
    /// A received content's blob, fetched, verified and decrypted (M§8.4 rule 7).
    Blob {
        /// The sender.
        sender: String,
        /// The content object.
        object: Value,
        /// The decrypted file.
        path: PathBuf,
        /// The plaintext's SHA-256.
        sha256: String,
        /// The source it came from.
        from: String,
    },
    /// No blob source had it yet: tried again later (spec-gap 106).
    BlobPending {
        /// The content id.
        id: String,
        /// The attempt that found nothing.
        attempt: i64,
        /// Seconds until the next.
        retry_in: i64,
    },
    /// One source refused or served other bytes.
    BlobSourceRejected {
        /// The source.
        uri: String,
        /// Why.
        why: String,
    },
    /// A blob fetch was given up.
    BlobGaveUp {
        /// The content id.
        id: Value,
        /// Why (`mismatch`, `unavailable`, or nothing).
        why: String,
    },
    /// The successor of a group whose hub is gone: one this device had converged on (M§7.5).
    SuccessorExists {
        /// The successor.
        group: String,
        /// The dead group.
        of: String,
    },
    /// The successor this device created (M§7.5).
    SuccessorCreated {
        /// The successor.
        group: String,
        /// The dead group.
        of: String,
    },
    /// Creating the successor failed; it is retried with backoff and the items stay pending (M§9.4, spec-gap 72).
    SuccessorRetry {
        /// The dead group.
        of: String,
        /// Why.
        error: String,
    },
}

/// The application around a [`Messenger`].
#[allow(async_fn_in_trait)] // a host is driven on one task; its futures need not be `Send`
pub trait Host<S: Store> {
    /// One output, with the engine as it stands after it.
    async fn output(&mut self, engine: &Engine<S>, out: Output);

    /// What the host saves with the device's state, written under [`Config::host_key`] beside the messenger's own
    /// fields. Its object's keys are the host's; `pending_blobs` is the messenger's.
    fn saved(&self) -> Value {
        Value::Null
    }

    /// A frame from the mailbox is about to be processed, with its payload.
    fn frame_in(&mut self, _engine: &Engine<S>, _payload: &Value) {}

    /// ... and it has been.
    fn frame_done(&mut self, _engine: &Engine<S>) {}
}

/// Work an event asks for that needs the network, done after the frame or tick that asked for it.
enum Job {
    /// Fetch a received content's blob (M§8.4); `attempt` from 1.
    Blob { sender: String, object: Value, blobs: Value, attempt: i64 },
    /// Create (or use) the successor of a group whose hub is gone (M§7.5, M§9.4).
    Successor(String),
}

/// What fetching a content's blob came to (M§8.4, spec-gap 106).
enum Fetched {
    Played(PathBuf, String, String),
    Retry,
    GaveUp(String),
}

/// A messaging device: the engine, its mailbox connection, and the work it does on the network.
pub struct Messenger<S: Store> {
    m: Engine<S>,
    cfg: Config,
    tls: Option<Arc<rustls::ClientConfig>>,
    conn: Option<Connection>,
    /// Taken offline on purpose: the clock leaves it there until something connects again.
    held_offline: bool,
    /// Unexpected connection loss: redial at this time (§13.2 backoff).
    reconnect_at: Option<i64>,
    /// The current backoff ceiling, seconds (§13.2: initial 1, factor 2, max 60).
    reconnect_ceiling: i64,
    seen: SeenIds,
    /// Answers awaited by request id, taken off the connection before the engine sees them.
    replies: HashMap<String, Option<(Value, String)>>,
    jobs: Vec<Job>,
    /// Blob fetches to try again (spec-gap 106): `{object, blobs, sender, attempt, next_at}`, persisted.
    pending_blobs: Vec<Value>,
    http: reqwest::Client,
    /// `did:web` documents fetched for discovery (§7.2), after the files.
    web: Option<Arc<dsip_transport::resolver::WebDocuments>>,
    /// The hints tier, for identities with no document (M§4.2, §8.1 rule 6).
    hints: Option<dsip_transport::hints::HintsClient>,
    /// Mailboxes found through hints: `(DID, URI, reuse until)`.
    hinted: HashMap<String, (String, String, i64)>,
}

/// The documents in `files` (each a DID document as JSON; unreadable ones are skipped).
pub fn resolver(files: &[PathBuf]) -> StaticResolver {
    let mut r = StaticResolver::default();
    for f in files {
        if let Ok(text) = std::fs::read_to_string(f) {
            if let Ok(doc) = serde_json::from_str(&text) {
                r.insert(doc);
            }
        }
    }
    r
}

/// The mailbox an identity advertises, chosen by the profile's rules: `(DID, URI)`.
///
/// Spec: M§4.2.
pub fn mailbox_of(identity: &str, resolver: &StaticResolver) -> Result<(String, String)> {
    let doc = dsip_core::did::Resolver::resolve(resolver, identity).ok_or_else(|| Error::NoMailbox(format!("no document for {identity}")))?;
    let entries: Vec<Value> =
        doc.service.iter().filter(|s| s.service_type == "DSIPMailbox").map(|s| s.service_endpoint.clone()).collect();
    let choice = dsip_messaging::client::select_mailbox(&json!({"document_entries": entries}));
    let did = choice["selected"].as_str().ok_or_else(|| Error::NoMailbox(format!("no usable mailbox for {identity}: {choice}")))?.to_string();
    let uri = entries.iter().find(|e| e["mailbox"] == json!(did)).and_then(|e| e["uri"].as_str())
        .ok_or_else(|| Error::NoMailbox(format!("{identity}'s mailbox entry has no uri")))?
        .to_string();
    Ok((did, uri))
}

/// The DID document an identity serves (§7.2, as `did:web` does) to be reachable for messaging: its controller key as
/// `#key-1`, the X25519 key sealed introductions are encrypted to (M§6.9; spec-gap 55: derived from the controller
/// key), and one `DSIPMailbox` service naming its mailbox (M§4.2).
///
/// Spec: M§4.2, M§6.9.
pub fn did_document(identity: &str, controller: &KeyPair, mailbox_did: &str, mailbox_uri: &str) -> Value {
    let x25519 = dsip_messaging::first_contact::x25519_public(&dsip_messaging::first_contact::x25519_from_ed25519_seed(&controller.seed()));
    json!({
        "keyAgreement": [{
            "id": format!("{identity}#key-agreement-1"), "type": "Multikey", "controller": identity,
            "publicKeyMultibase": dsip_core::did::multibase_x25519(&x25519),
        }],
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": identity,
        "verificationMethod": [{
            "id": format!("{identity}#key-1"), "type": "Multikey", "controller": identity,
            "publicKeyMultibase": dsip_core::did::multibase_ed25519(&controller.public()),
        }],
        "authentication": [format!("{identity}#key-1")],
        "assertionMethod": [format!("{identity}#key-1")],
        "service": [{
            "id": format!("{identity}#dsip-mailbox"), "type": "DSIPMailbox",
            "serviceEndpoint": {
                "uri": mailbox_uri, "bindings": ["ws/1.0"], "mailbox": mailbox_did, "priority": 0,
                "profiles": [wire::PROFILE], "accepts": ["text", "audio", "image", "file"],
                "voicemail": {"max_duration_s": 180},
            },
        }],
    })
}

/// The identity JSON [`Engine::open`] takes: the identity, its device and controller seeds, the delegation to the
/// device and a display name.
pub fn engine_identity(identity: &str, device: &KeyPair, controller: &KeyPair, delegation: &Envelope, display_name: &str) -> String {
    engine_identity_with(identity, device, controller, delegation, display_name, None)
}

/// As [`engine_identity`], with the X25519 secret of a key agreement key the identity delegated (core §7.3,
/// spec-gap 179): sealed introductions open with it first.
pub fn engine_identity_with(
    identity: &str,
    device: &KeyPair,
    controller: &KeyPair,
    delegation: &Envelope,
    display_name: &str,
    key_agreement: Option<&[u8; 32]>,
) -> String {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let mut v = json!({"identity": identity, "device_seed_hex": hex(&device.seed()), "delegation": delegation.frame(),
           "controller_seed_hex": hex(&controller.seed()), "display_name": display_name});
    if let Some(sk) = key_agreement {
        v["key_agreement_secret_hex"] = json!(hex(sk));
    }
    v.to_string()
}

/// HTTPS for blobs, trusting the same anchors as the `wss` connections (M§5.6: TLS as in §13.2).
pub fn http_client(ca: Option<&std::path::Path>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder().use_rustls_tls().https_only(true);
    if let Some(ca) = ca {
        for cert in reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)? {
            b = b.add_root_certificate(cert);
        }
    }
    Ok(b.build()?)
}

fn frame_id(frame: &str) -> String {
    Envelope::from_frame(frame).ok().and_then(|e| wire::payload_of(&e)).and_then(|p| p["id"].as_str().map(String::from)).unwrap_or_default()
}

fn envelope(frame: &str) -> Result<Envelope> {
    Envelope::from_frame(frame).map_err(|v| Error::Frame(format!("{:?}", v.code)))
}

/// Send one request on a connection to another identity's mailbox and return its answer, closing the connection.
pub async fn peer_exchange(conn: &mut Connection, frame: &str) -> Result<Value> {
    conn.send(&envelope(frame)?).await?;
    let reply = conn.recv().await?.ok_or(Error::NoAnswer)?;
    conn.close(tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal, "done").await;
    wire::payload_of(&envelope(&reply)?).ok_or_else(|| Error::Frame("an answer with no payload".into()))
}

impl<S: Store> Messenger<S> {
    /// A messenger around `engine`, not yet connected ([`Messenger::connect`]). `pending_blobs` is what
    /// [`Config::host_key`] held when the device last stopped.
    pub fn new(engine: Engine<S>, cfg: Config, pending_blobs: Vec<Value>) -> Result<Messenger<S>> {
        let tls = dsip_transport::tls::client_config(cfg.ca.as_deref())?;
        let http = http_client(cfg.ca.as_deref())?;
        let mut mx = Messenger { m: engine, cfg, tls, conn: None, held_offline: false, reconnect_at: None, reconnect_ceiling: 1,
                                 seen: SeenIds::default(), replies: HashMap::new(), jobs: vec![], pending_blobs, http,
                                 web: None, hints: None, hinted: HashMap::new() };
        mx.refresh_docs();
        Ok(mx)
    }

    /// Fetch the `did:web` documents of identities the files do not hold, to find their mailboxes (M§4.2, §7.2).
    pub fn with_did_web(mut self, web: Arc<dsip_transport::resolver::WebDocuments>) -> Messenger<S> {
        self.web = Some(web);
        self
    }

    /// Look up the reachability hint of an identity with no document on these hints nodes (M§4.2, §8.1 rule 6).
    pub fn with_hints(mut self, hints: dsip_transport::hints::HintsClient) -> Messenger<S> {
        self.hints = Some(hints);
        self
    }

    /// The mailbox of `identity`, `(DID, URI)` (M§4.2): from its DID document (the files, then fetched when it is a
    /// `did:web`), else from its hint; a document's entries are never passed over for a hint (§8.1 rule 6).
    pub async fn discover_mailbox(&mut self, identity: &str) -> Result<(String, String)> {
        let files = resolver(&self.cfg.resolver_files);
        let mut doc = dsip_core::did::Resolver::resolve(&files, identity);
        if doc.is_none() && identity.starts_with("did:web:") {
            if let Some(web) = &self.web {
                web.fetch(&[identity.to_string()]).await;
                doc = web.held(identity);
                if let Some(d) = &doc {
                    self.m.add_document(d.clone()); // §7.4: its delegations verify against it
                }
            }
        }
        if let Some(d) = doc {
            let mut r = StaticResolver::default();
            r.insert(d);
            return mailbox_of(identity, &r);
        }
        let now = now_s();
        if let Some((did, uri, until)) = self.hinted.get(identity) {
            if *until > now {
                return Ok((did.clone(), uri.clone()));
            }
        }
        let hints = self.hints.as_ref().ok_or_else(|| Error::NoMailbox(format!("no document for {identity}, and no hints nodes")))?;
        let hint = hints.lookup(identity, &files, now).await.ok_or_else(|| {
            Error::NoMailbox(format!("no document for {identity}, and no verified hint on {} node(s)", hints.nodes().len()))
        })?;
        // the key agreement delegation it carries: introductions to it are sealed to that key (core §7.3)
        if let Some(ka) = &hint.key_agreement {
            self.m.hold_key_agreement(ka, now);
        }
        let entries = dsip_transport::hints::mailbox_entries(&hint);
        let choice = dsip_messaging::client::select_mailbox(&json!({"hint_entries": entries}));
        let did = choice["selected"].as_str().ok_or_else(|| Error::NoMailbox(format!("{identity}'s hint names no usable mailbox: {choice}")))?.to_string();
        let uri = entries.iter().find(|e| e["mailbox"] == json!(did)).and_then(|e| e["uri"].as_str())
            .ok_or_else(|| Error::NoMailbox(format!("{identity}'s hinted mailbox has no uri")))?
            .to_string();
        self.hinted.insert(identity.to_string(), (did.clone(), uri.clone(), hint.expires_at.min(now + HINT_REUSE_S)));
        Ok((did, uri))
    }

    /// The engine.
    pub fn engine(&self) -> &Engine<S> {
        &self.m
    }

    /// The engine, to act with; send what it returns ([`Messenger::send_frames`]).
    pub fn engine_mut(&mut self) -> &mut Engine<S> {
        &mut self.m
    }

    /// Who the device is and where its mailbox is.
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// The HTTPS client blobs go over (uploads too).
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// The connection to the mailbox, when bound.
    pub fn connection(&self) -> Option<&Connection> {
        self.conn.as_ref()
    }

    fn now() -> f64 {
        now_s() as f64
    }

    /// Hold every DID document the device resolves from, as the files say now.
    pub fn refresh_docs(&mut self) {
        for f in &self.cfg.resolver_files {
            if let Ok(text) = std::fs::read_to_string(f) {
                if let Ok(doc) = serde_json::from_str(&text) {
                    self.m.add_document(doc);
                }
            }
        }
    }

    /// Write the engine's state and the host's, in one transaction (spec-gap 44).
    pub fn save(&self, host: &impl Host<S>) -> Result<()> {
        let st = self.m.state();
        let mut saved = match host.saved() {
            Value::Object(o) => Value::Object(o),
            _ => json!({}),
        };
        saved["pending_blobs"] = json!(self.pending_blobs);
        let db = self.m.store();
        db.atomically(|| {
            db.put("messenger", &st)?;
            // the item transactions write the delivery state under its own key too: this keeps the two equal
            db.put("resume", &st["resume"])?;
            db.put(&self.cfg.host_key, &saved)
        })?;
        Ok(())
    }

    /// Bind to the mailbox, unless bound: the `hello` (M§4.3), then what the binding that ended took with it, the same
    /// bytes (M§9.3). No sync until asked for.
    pub async fn connect(&mut self, host: &mut impl Host<S>) -> Result<()> {
        if self.conn.is_some() {
            return Ok(());
        }
        let params = ConnectParams {
            url: self.cfg.mailbox.1.clone(),
            tls: self.tls.clone(),
            device: &self.cfg.device,
            on_behalf_of: Some(self.cfg.identity.clone()),
            delegations: vec![self.cfg.delegation.clone()],
            supported: Supported::all_known(),
        };
        let conn = {
            let r = resolver(&self.cfg.resolver_files);
            Connection::connect(&params, &r, &mut self.seen).await?
        };
        if conn.relay.did != self.cfg.mailbox.0 {
            return Err(Error::WrongMailbox { expected: self.cfg.mailbox.0.clone(), got: conn.relay.did.clone() });
        }
        host.output(&self.m, Output::Connected { identity: self.cfg.identity.clone(), mailbox: self.cfg.mailbox.0.clone() }).await;
        self.conn = Some(conn);
        self.held_offline = false;
        self.reconnect_at = None;
        self.reconnect_ceiling = 1;
        for f in self.m.rebind(Self::now()) {
            self.conn.as_mut().ok_or(Error::Offline)?.send(&envelope(&f)?).await?;
        }
        self.save(host)
    }

    /// Drop the connection and stay offline until [`Messenger::connect`] (what is pending goes at the next binding).
    pub fn go_offline(&mut self) {
        self.conn = None;
        self.held_offline = true;
    }

    /// Stay offline once the connection ends, without dropping it now (a `release` the mailbox closes the binding for).
    pub fn hold_offline(&mut self) {
        self.held_offline = true;
    }

    /// The connection dropped without being asked to: schedule a redial (§13.2).
    pub fn lost_connection(&mut self) {
        self.conn = None;
        self.schedule_reconnect();
    }

    fn schedule_reconnect(&mut self) -> i64 {
        let wait = (rand::random::<u64>() % (self.reconnect_ceiling as u64 + 1)) as i64;
        self.reconnect_at = Some(now_s() + wait);
        self.reconnect_ceiling = (self.reconnect_ceiling * 2).min(60);
        wait
    }

    /// The clock's redial: connect when due, then sync what arrived while away (M§5.4).
    pub async fn check_reconnect(&mut self, host: &mut impl Host<S>) -> Result<()> {
        match self.reconnect_at {
            Some(at) if self.conn.is_none() && !self.held_offline && now_s() >= at => {}
            _ => return Ok(()),
        }
        match self.connect(host).await {
            Ok(()) => self.sync(host, false).await,
            Err(e) => {
                let wait_s = self.schedule_reconnect();
                host.output(&self.m, Output::ReconnectFailed { error: e.to_string(), wait_s }).await;
                Ok(())
            }
        }
    }

    /// Send one frame to the mailbox, connecting first if need be.
    pub async fn send_frame(&mut self, host: &mut impl Host<S>, frame: &str) -> Result<()> {
        if self.conn.is_none() {
            Box::pin(self.connect(host)).await?;
        }
        let env = envelope(frame)?;
        Ok(self.conn.as_mut().ok_or(Error::Offline)?.send(&env).await?)
    }

    /// Send each frame.
    pub async fn send_frames(&mut self, host: &mut impl Host<S>, frames: &[String]) -> Result<()> {
        for f in frames {
            self.send_frame(host, f).await?;
        }
        Ok(())
    }

    /// Sync (M§5.4); `live` keeps the mailbox pushing.
    pub async fn sync(&mut self, host: &mut impl Host<S>, live: bool) -> Result<()> {
        let frame = self.m.sync_frame(live, Self::now());
        self.send_frame(host, &frame).await
    }

    /// Send `frame`, a request to this device's own mailbox, and wait for its answer, processing every other frame as
    /// it comes.
    pub async fn request(&mut self, host: &mut impl Host<S>, frame: &str) -> Result<Value> {
        Ok(self.request_frame(host, frame).await?.0)
    }

    /// [`Messenger::request`], with the answer's frame as it came beside its payload, for a caller that verifies it.
    async fn request_frame(&mut self, host: &mut impl Host<S>, frame: &str) -> Result<(Value, String)> {
        let id = frame_id(frame);
        self.replies.insert(id.clone(), None);
        let answer = async {
            self.send_frame(host, frame).await?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(REQUEST_TIMEOUT_S);
            loop {
                if let Some(Some(p)) = self.replies.get(&id) {
                    return Ok(p.clone());
                }
                let conn = self.conn.as_mut().ok_or(Error::Offline)?;
                let frame = tokio::time::timeout_at(deadline, conn.recv()).await.map_err(|_| Error::NoAnswer)??.ok_or(Error::Closed)?;
                self.on_frame(host, &frame).await;
            }
        }
        .await;
        self.replies.remove(&id);
        answer
    }

    /// What our mailbox said of waking devices in its `hello` (`{"profiles": ["wake/0.1"], "kinds": ["message"]}`), or
    /// `None` when it does not wake them, or this messenger is not connected: then it is sent no `wake-register`.
    /// Spec: W§4.4.
    pub fn mailbox_wake(&self) -> Option<&Value> {
        self.conn.as_ref().and_then(|c| c.relay.capabilities.get("wake"))
    }

    /// Register this device with our mailbox to be woken for messages (W§4.2; the mailbox's owner operation, spec-gap
    /// 176): `registration` is the device's signed `WakeRegistration` naming the mailbox, `kinds` the kinds wanted (none:
    /// every kind). A mailbox seals no hint, so no seal key goes. Returns its verified answer: `Accepted`, or `Refused` with
    /// its reason. Spec: W§4.2, W§4.3.
    pub async fn wake_register(&mut self, host: &mut impl Host<S>, registration: Value, kinds: Option<Vec<String>>)
        -> Result<dsip_transport::wake::Answer> {
        let kinds: Option<Vec<&str>> = kinds.as_ref().map(|k| k.iter().map(String::as_str).collect());
        let msg = dsip_wake::register_message(&self.cfg.device.did(), &self.cfg.mailbox.0, &registration, None, kinds.as_deref(), Self::now() as i64);
        self.wake_request(host, msg).await
    }

    /// End this device's registration at our mailbox (`remove: true`, W§4.2).
    pub async fn wake_remove(&mut self, host: &mut impl Host<S>) -> Result<dsip_transport::wake::Answer> {
        let msg = dsip_wake::remove_message(&self.cfg.device.did(), &self.cfg.mailbox.0, Self::now() as i64);
        self.wake_request(host, msg).await
    }

    async fn wake_request(&mut self, host: &mut impl Host<S>, msg: Value) -> Result<dsip_transport::wake::Answer> {
        let id = msg["id"].as_str().unwrap_or_default().to_string();
        let frame = dsip_core::envelope::sign(&msg, &self.cfg.device, &self.cfg.device.kid()).frame();
        let (_, answer) = self.request_frame(host, &frame).await?;
        let r = resolver(&self.cfg.resolver_files);
        Ok(dsip_transport::wake::read_reply(&self.cfg.mailbox.0, &r, &answer, &id, Self::now() as i64)?)
    }

    /// The next frame from the mailbox, or `None` for a closed connection; pending for ever while offline. Cancel-safe:
    /// a frame not yet returned stays on the connection.
    pub async fn recv(&mut self) -> Option<Result<Option<String>>> {
        match self.conn.as_mut() {
            Some(c) => Some(c.recv().await.map_err(Error::from)),
            None => std::future::pending().await,
        }
    }

    /// What [`Messenger::recv`] returned: a frame processed, or the connection's end handled.
    pub async fn received(&mut self, host: &mut impl Host<S>, r: Result<Option<String>>) {
        match r {
            Ok(Some(text)) => self.on_frame(host, &text).await,
            Ok(None) => {
                host.output(&self.m, Output::Disconnected).await;
                self.lost_connection();
            }
            Err(e) => {
                host.output(&self.m, Output::ConnectionError(e.to_string())).await;
                self.lost_connection();
            }
        }
    }

    /// One frame from the mailbox: an answer a request waits for, or the engine's to process.
    pub async fn on_frame(&mut self, host: &mut impl Host<S>, frame: &str) {
        let p = Envelope::from_frame(frame).ok().and_then(|e| wire::payload_of(&e)).unwrap_or_default();
        if let Some(slot) = p["in_reply_to"].as_str().and_then(|id| self.replies.get_mut(id)) {
            if slot.is_none() && p["type"] != "items" {
                *slot = Some((p, frame.to_string()));
                return;
            }
        }
        self.refresh_docs();
        host.frame_in(&self.m, &p);
        let out = self.m.inbound(frame, Self::now());
        host.frame_done(&self.m);
        if let Err(e) = self.handle(host, out).await {
            host.output(&self.m, Output::Error(e.to_string())).await;
        }
    }

    /// The engine's clock (M§9.4 retries and outages, M§10.3, M§11.2, M§6.5 gaps), and blob fetches that are due again
    /// (spec-gap 106); the engine's clock waits while there is no connection. Call once a second.
    pub async fn tick(&mut self, host: &mut impl Host<S>) {
        if self.conn.is_some() {
            self.refresh_docs();
            let out = self.m.tick(Self::now());
            if let Err(e) = self.handle(host, out).await {
                host.output(&self.m, Output::Error(e.to_string())).await;
            }
        }
    }

    /// Queue the blob fetches that are due again (spec-gap 106); they run at the next [`Messenger::settle`].
    pub fn retry_blobs(&mut self, host: &impl Host<S>) -> Result<()> {
        let now = now_s();
        let (due, later): (Vec<Value>, Vec<Value>) =
            std::mem::take(&mut self.pending_blobs).into_iter().partition(|p| p["next_at"].as_i64().unwrap_or(0) <= now);
        self.pending_blobs = later;
        if due.is_empty() {
            return Ok(());
        }
        for p in due {
            self.jobs.push(Job::Blob { sender: p["sender"].as_str().unwrap_or("").to_string(), object: p["object"].clone(),
                                       blobs: p["blobs"].clone(), attempt: p["attempt"].as_i64().unwrap_or(2) });
        }
        self.save(host)
    }

    /// Wait until what was set going is settled (every deposit answered), processing frames and the clock as they
    /// come, and running the work events asked for; at most [`SETTLE_S`], and not at all without a connection.
    pub async fn settle(&mut self, host: &mut impl Host<S>) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(SETTLE_S);
        loop {
            self.run_jobs(host).await;
            if self.m.settled() || tokio::time::Instant::now() >= deadline {
                return;
            }
            let Some(conn) = self.conn.as_mut() else { return };
            tokio::select! {
                frame = conn.recv() => {
                    let r = frame.map_err(Error::from);
                    self.received(host, r).await;
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => self.tick(host).await,
            }
        }
    }

    /// Act on what the engine emitted: frames to the mailbox, syncs, work queued, the rest to the host.
    pub async fn handle(&mut self, host: &mut impl Host<S>, out: Vec<Event>) -> Result<()> {
        for e in out {
            match e {
                Event::Send { send } => {
                    if let Err(err) = self.send_frame(host, &send).await {
                        host.output(&self.m, Output::Error(err.to_string())).await;
                    }
                }
                Event::Sync { .. } => {
                    // spec-gap 58: a refused commit syncs past the winning one before anything is re-proposed
                    if let Err(err) = self.sync(host, false).await {
                        host.output(&self.m, Output::Error(err.to_string())).await;
                    }
                }
                Event::KeyPackages { .. } => {}
                e => {
                    match &e {
                        Event::Ui(Ui::Message { from, object, blobs, .. }) if object.get("blob").is_some() => {
                            // the item is committed; a fetch that finds nothing is tried again (spec-gap 106)
                            self.jobs.push(Job::Blob { sender: from.clone(), object: object.clone(), blobs: blobs.clone(), attempt: 1 });
                        }
                        Event::SuccessorDue { successor_due: SuccessorDue { group, .. } } => self.jobs.push(Job::Successor(group.clone())),
                        _ => {}
                    }
                    host.output(&self.m, Output::Event(e)).await;
                }
            }
        }
        self.save(host)
    }

    async fn run_jobs(&mut self, host: &mut impl Host<S>) {
        while !self.jobs.is_empty() {
            let result = match self.jobs.remove(0) {
                Job::Blob { sender, object, blobs, attempt } => self.blob_in(host, &sender, &object, &blobs, attempt).await,
                Job::Successor(dead) => match self.successor(host, &dead).await {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        // M§9.4 (spec-gap 72): the hand-over is retried with the §13.2 backoff; the items stay pending
                        self.m.successor_failed(&dead);
                        host.output(&self.m, Output::SuccessorRetry { of: dead, error: e.to_string() }).await;
                        Ok(())
                    }
                },
            };
            if let Err(e) = result {
                host.output(&self.m, Output::Error(e.to_string())).await;
            }
        }
    }

    /// Create the successor of `dead`, whose hub is gone: same conversation, this mailbox as hub, the last known roster
    /// re-added (M§7.5); or use the one this device converged on. The pending items follow (M§9.4). The messenger does
    /// this itself when the engine says a successor is due.
    pub async fn successor(&mut self, host: &mut impl Host<S>, dead: &str) -> Result<()> {
        let now = Self::now();
        if let Some(w) = self.m.successor(dead) {
            host.output(&self.m, Output::SuccessorExists { group: w, of: dead.into() }).await;
            let frames = self.m.create_successor(dead, &BTreeMap::new(), now)?;
            return self.send_frames(host, &frames).await;
        }
        let me = self.cfg.identity.clone();
        let members: Vec<String> = self.m.conversations(now).into_iter().find(|c| c.group == dead).map(|c| c.members).unwrap_or_default();
        let mut answers = BTreeMap::new();
        for peer in members.into_iter().filter(|p| *p != me) {
            // M§7.5 (spec-gap 61): the peer's mailbox serves a successor's creator without a grant
            let a = self.fetch_key_packages(host, &peer, Some(dead)).await.map_err(|e| Error::Refused(format!("{peer}'s KeyPackages: {e}")))?;
            answers.insert(peer, a);
        }
        let frames = self.m.create_successor(dead, &answers, Self::now())?;
        let gid = frames.first().and_then(|f| Envelope::from_frame(f).ok()).and_then(|e| wire::payload_of(&e))
            .and_then(|p| p["groups"][0]["group"].as_str().map(String::from)).unwrap_or_default();
        host.output(&self.m, Output::SuccessorCreated { group: gid, of: dead.into() }).await;
        self.save(host)?;
        self.send_frames(host, &frames).await
    }

    /// A short-lived connection to another identity's mailbox (M§5.5 fetch, M§14.1 first contact).
    pub async fn peer_connect(&mut self, identity: &str) -> Result<Connection> {
        let (did, uri) = self.discover_mailbox(identity).await?;
        let r = resolver(&self.cfg.resolver_files);
        let params = ConnectParams {
            url: uri,
            tls: self.tls.clone(),
            device: &self.cfg.device,
            on_behalf_of: Some(self.cfg.identity.clone()),
            delegations: vec![self.cfg.delegation.clone()],
            supported: Supported::all_known(),
        };
        let conn = Connection::connect(&params, &r, &mut self.seen).await?;
        if conn.relay.did != did {
            return Err(Error::WrongMailbox { expected: did, got: conn.relay.did.clone() });
        }
        Ok(conn)
    }

    /// The `key-packages` answer for `target` (M§5.5): from its mailbox, or this identity's own over the bound
    /// connection, so no second binding displaces it. `successor_of` names the dead group a successor is created for
    /// (M§7.5, spec-gap 61). A grant held from `target` is presented (M§14.2).
    pub async fn fetch_key_packages(&mut self, host: &mut impl Host<S>, target: &str, successor_of: Option<&str>) -> Result<Value> {
        let so = successor_of.map(String::from);
        let payload = if target == self.cfg.identity {
            let mailbox = self.cfg.mailbox.0.clone();
            let frame = self.m.fetch_frame(&mailbox, target, Self::now(), so);
            self.request(host, &frame).await?
        } else {
            let mut conn = self.peer_connect(target).await?;
            let did = conn.relay.did.clone();
            let frame = self.m.fetch_frame(&did, target, Self::now(), so);
            peer_exchange(&mut conn, &frame).await?
        };
        if payload["type"] != "key-packages" {
            return Err(Error::Refused(format!("key-package-fetch refused: {} {}", payload["type"], payload["reason"])));
        }
        Ok(payload)
    }

    /// Fetch, verify and decrypt a content object's blob into [`Config::media_dir`] (M§8.4 rule 7), from the sources
    /// the pinned rule names: this identity's mailbox's copy first, then the content's own `uri` (M§8.4 rule 6).
    async fn fetch_blob(&self, host: &mut impl Host<S>, object: &Value, manifest: &Value, attempt: i64) -> Result<Fetched> {
        let key = object["blob"]["key"].as_str().and_then(dsip_core::b64::decode).unwrap_or_default();
        if key.len() != 32 {
            return Err(Error::Blob("no blob key".into()));
        }
        let mut tried = vec![];
        for uri in &blob::sources(object, manifest) {
            let uri = uri.as_str();
            let stored = match self.http.get(uri).send().await {
                Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                    Ok(body) => body,
                    Err(e) => {
                        host.output(&self.m, Output::BlobSourceRejected { uri: uri.into(), why: e.to_string() }).await;
                        tried.push(blob::tried(uri, 0, None));
                        continue;
                    }
                },
                Ok(resp) => {
                    host.output(&self.m, Output::BlobSourceRejected { uri: uri.into(), why: resp.status().to_string() }).await;
                    tried.push(blob::tried(uri, resp.status().as_u16(), None));
                    continue;
                }
                Err(e) => {
                    host.output(&self.m, Output::BlobSourceRejected { uri: uri.into(), why: e.to_string() }).await;
                    tried.push(blob::tried(uri, 0, None));
                    continue;
                }
            };
            // M§8.4 rule 7: whichever source, the hash and size must match before decrypting
            match blob::open(object, &stored) {
                Ok(plain) => {
                    std::fs::create_dir_all(&self.cfg.media_dir)?;
                    let path = self.cfg.media_dir.join(format!("{}.ogg", object["id"].as_str().unwrap_or("blob")));
                    std::fs::write(&path, &plain)?;
                    return Ok(Fetched::Played(path, dsip_mls::digest(&plain), uri.to_string()));
                }
                Err(c) => {
                    host.output(&self.m, Output::BlobSourceRejected { uri: uri.into(), why: c.to_string() }).await;
                    // a 200 that is not the content's blob: other bytes (M§8.4 rule 7)
                    tried.push(blob::tried(uri, 200, Some(&stored)));
                }
            }
        }
        // M§8.4 "Fetching" (spec-gap 106): try again when a source had nothing to serve; never when all served other bytes
        Ok(match blob::fetch_decision(object, &tried, attempt) {
            blob::Fetch::Retry => Fetched::Retry,
            blob::Fetch::GiveUp(reason) => Fetched::GaveUp(reason),
            // a source served the content's size and hash but it did not decrypt: nothing to play
            blob::Fetch::Play(_) => Fetched::GaveUp(String::new()),
        })
    }

    /// Fetch a received content's blob now; a fetch that found nothing is kept and tried again (spec-gap 106).
    async fn blob_in(&mut self, host: &mut impl Host<S>, sender: &str, object: &Value, blobs: &Value, attempt: i64) -> Result<()> {
        match self.fetch_blob(host, object, blobs, attempt).await? {
            Fetched::Played(path, sha256, from) => {
                host.output(&self.m, Output::Blob { sender: sender.into(), object: object.clone(), path, sha256, from }).await;
            }
            Fetched::Retry => {
                let retry_in = blob::retry_delay_s(attempt);
                let id = object["id"].as_str().unwrap_or("").to_string();
                host.output(&self.m, Output::BlobPending { id, attempt, retry_in }).await;
                self.pending_blobs.push(json!({"object": object, "blobs": blobs, "sender": sender, "attempt": attempt + 1,
                                               "next_at": now_s() + retry_in}));
                self.save(host)?;
            }
            Fetched::GaveUp(why) => host.output(&self.m, Output::BlobGaveUp { id: object["id"].clone(), why }).await,
        }
        Ok(())
    }
}
