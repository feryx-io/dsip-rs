//! The native agent: a [`dsip_endpoint::Core`] over a live `ws/1.0` connection with file persistence.
//!
//! Spec: §13.2 (one connection, many sessions; reconnection with a fresh
//! `hello`), §19.4 (grants persist across restarts). All protocol logic lives in
//! `dsip-endpoint`; this module adds the socket, the wall clock, and the disk.

use std::time::Duration;


use dsip_core::did::StaticResolver;
use dsip_core::version::Supported;
use dsip_endpoint::{CallCommand, CallEvent, CallOut, Calls, CallsConfig, Command, ContactFile, Core, CoreConfig, CoreEvent, IdentityKeys,
                    Invite, MediaRequest, MediaResult, PresenceSealing};
use dsip_session::{Emission, Endpoint, LocalEvent, Message, SessionState};

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::conn::{ConnectParams, Connection, DialFuture, Dialer};
use crate::resolver::{DidResolver, DidWebResolver};
use crate::identity::Identity;
use crate::verify::SeenIds;
use crate::error::Result;
use crate::{now_s, BACKOFF};

/// Interactive Media Profile identifier. Spec: §17.
pub const PROFILE: &str = dsip_endpoint::core::PROFILE;

/// Something the application should know about.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // an event is built once and consumed at once; boxing the message would cost an allocation per event
pub enum AgentEvent {
    /// An engine emission that is not a send (timers, ui, media, drops, refusals).
    Emission(Emission),
    /// We sent an envelope (type, session, to).
    Sent {
        /// Message type.
        msg_type: String,
        /// Session.
        session: String,
        /// Destination.
        to: String,
    },
    /// We issued a grant and sent it through our relay: one that follows a grant we issued, with new presence keys
    /// (P§12.5), or answers an introduction that came through the relay. A grantee reached another way (its mailbox,
    /// M§14.1) gets it from the host, `grant` being its compact serialization (`protected.payload.signature`).
    GrantIssued {
        /// The grantee identity.
        to: String,
        /// The signed grant, compact.
        grant: String,
    },
    /// Our relay answered a request sent with [`Agent::request`]: the answer's frame, for the host to verify and read
    /// (a profile's answer the engine does not know, such as `wake-accepted`, W§4.2).
    Reply {
        /// The request's id, which the answer names in `in_reply_to`.
        in_reply_to: String,
        /// The answer, as it came.
        frame: String,
    },
    /// A verified inbound message was handed to the engine.
    Received {
        /// The abbreviated message.
        message: Message,
        /// The signer's identity.
        identity: String,
        /// Display name claim, if any.
        display_name: Option<String>,
        /// Full decoded payload (SDP, candidates, policy live here).
        payload: serde_json::Value,
    },
    /// An inbound frame was rejected (code, detail).
    Rejected(String, String),
    /// Connection dropped and was re-established after `attempts` tries.
    Reconnected {
        /// Attempts.
        attempts: u32,
    },
    /// Media work for the host, from the call glue ([`AgentConfig::calls`]); SDP results go back through
    /// [`Agent::media`].
    Media(MediaRequest),
    /// Something about a call, from the call glue.
    Call(CallEvent),
}

/// Agent configuration.
pub struct AgentConfig {
    /// Relay URL.
    pub relay_url: String,
    /// TLS trust.
    pub tls: Option<std::sync::Arc<rustls::ClientConfig>>,
    /// Offer video in invites.
    pub video: bool,
    /// Timer overrides (seconds).
    pub t_establish: Option<i64>,
    /// T-Ring override.
    pub t_ring: Option<i64>,
    /// T-Ring-Local override.
    pub t_ring_local: Option<i64>,
    /// §19.4: reject invites from identities holding no grant.
    pub first_contact_required: bool,
    /// §10.4: seal outbound session bodies (`sealed-body/1.0`). Inbound sealed bodies are opened either way.
    pub seal: bool,
    /// §8.1: how to fetch a `did:web` document an inbound frame needs and the agent does not hold. `None` fetches
    /// over HTTPS ([`DidWebResolver`]).
    pub did_resolver: Option<Arc<dyn DidResolver>>,
    /// Run the call glue ([`dsip_endpoint::calls`]): the agent then answers by policy and asks for media work with
    /// [`AgentEvent::Media`]; calls are placed with [`Agent::place`] and driven with [`Agent::call`]. `None` leaves
    /// all of that to the host.
    pub calls: Option<CallsConfig>,
    /// How to reach the relay: `None` dials [`AgentConfig::relay_url`] over `wss`; a [`Dialer`] supplies the stream
    /// instead (an embedded relay; `dsip-testkit`), for the first connection and every reconnect.
    pub dialer: Option<Arc<dyn Dialer>>,
    /// P§12: seal this device's presence records for these scopes (`main` and audience tags, [`audience_tag`]) and put
    /// keys in the grants it issues. `None` seals nothing; the keys of grants held open either way.
    pub presence: Option<PresenceSealing>,
    /// How to reach another relay a call goes through ([`Agent::place_via`]): `None`, or a dialer that has no stream
    /// for that URL, dials it over `wss` (an embedded relay; `dsip-testkit`).
    pub peer_dialer: Option<Arc<dyn PeerDialer>>,
}

/// Streams to relays other than the host's own, by URL ([`AgentConfig::peer_dialer`]).
pub trait PeerDialer: Send + Sync {
    /// A fresh stream to the relay at `url`, or `None` to dial it over `wss`.
    fn dial(&self, url: &str) -> Option<DialFuture>;
}

/// Seconds a connection to another relay may take to bind before the call goes through the host's own relay instead.
pub const PEER_BIND_S: u64 = 8;
/// Seconds a route waits for its session to exist (with media, the invite waits for the host's offer).
pub const ROUTE_GRACE_S: i64 = 60;

/// The wire tag of the audience `id`'s identity labels `label` (P§12.1): the label stays on the subject's devices.
pub fn audience_tag(id: &Identity, label: &str) -> String {
    dsip_core::presence_seal::audience_tag(&id.key_agreement_secret(), &id.meta.identity, label)
}

type Resolution = (String, std::result::Result<dsip_core::did::DidDocument, dsip_core::did::ResolveError>);

/// The agent.
pub struct Agent {
    id: Identity,
    cfg: AgentConfig,
    supported: Supported,
    resolver: StaticResolver,
    conn: Connection,
    core: Core,
    calls: Option<Calls>,
    events: Vec<AgentEvent>,
    did_resolver: Arc<dyn DidResolver>,
    resolved_tx: mpsc::UnboundedSender<Resolution>,
    resolved_rx: mpsc::UnboundedReceiver<Resolution>,
    /// §13.2: the relay said `transport.replaced` on this connection; its close is then not an unexpected loss
    replaced: bool,
    /// ... and the connection has closed: [`Agent::next`] returns [`Error::Replaced`] once its events are handed over
    replaced_closed: bool,
    /// Wakes [`Agent::next`] for the host ([`Agent::waker`]).
    wake: Arc<tokio::sync::Notify>,
    /// Connections to other relays, by URL: this device bound there for the calls placed through them (§8.1).
    peers: std::collections::HashMap<String, Connection>,
    /// The sessions placed through another relay: its URL, when the route was made, and whether the session has been
    /// seen in the endpoint (an ended session is forgotten there).
    routes: std::collections::HashMap<String, (String, i64, bool)>,
    /// Connections to other relays the host keeps open with no call through them ([`Agent::keep_peer`]).
    kept: std::collections::HashSet<String>,
    /// The ids of requests sent with [`Agent::request`] whose answers go to the host, not the engine.
    awaiting: std::collections::HashSet<String>,
}

impl Agent {
    /// Connect and bind.
    pub async fn connect(id: Identity, cfg: AgentConfig, resolver: StaticResolver) -> Result<Agent> {
        let supported = Supported::all_known();
        let mut seen = SeenIds::default();
        let conn = Connection::dial(cfg.dialer.as_deref(), &Self::params(&id, &cfg, &supported), &resolver, &mut seen).await?;
        let keys = IdentityKeys {
            identity: id.meta.identity.clone(),
            device: id.device.clone(),
            delegation: id.delegation.clone(),
            display_name: id.meta.display_name.clone(),
        };
        let core_cfg = CoreConfig {
            video: cfg.video,
            t_establish: cfg.t_establish,
            t_ring: cfg.t_ring,
            t_ring_local: cfg.t_ring_local,
            first_contact_required: cfg.first_contact_required,
            seal: cfg.seal,
            resolve_on_demand: true,
            presence: cfg.presence.clone(),
            // the identity's key agreement secrets, the delegated one first (P§12.1's `s`, §7.3), then the device's
            unseal_keys: id
                .key_agreement_secrets()
                .into_iter()
                .map(|sk| (id.meta.identity.clone(), sk))
                .chain([(id.device.did(), dsip_core::hpke::x25519_from_ed25519_seed(&id.device.seed()))])
                .collect(),
        };
        let mut core = Core::new(keys, core_cfg, resolver.clone(), now_s());
        // Seed persisted contacts (§19.4) so grants survive restarts.
        let file: ContactFile =
            std::fs::read(id.dir.join("contacts.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        core.load_contacts(&file);
        // P§7, P§12.5: our relay is the presence authority; the core sends it the revocations a share's end needs
        core.set_authority(Some(conn.relay.did.clone()));
        let did_resolver = cfg.did_resolver.clone().unwrap_or_else(|| Arc::new(DidWebResolver::new()));
        let (resolved_tx, resolved_rx) = mpsc::unbounded_channel();
        let calls = cfg.calls.map(Calls::new);
        Ok(Agent { id, cfg, supported, resolver, conn, core, calls, events: vec![], did_resolver, resolved_tx, resolved_rx, replaced: false, replaced_closed: false,
                   wake: Arc::new(tokio::sync::Notify::new()), peers: Default::default(), routes: Default::default(),
                   kept: Default::default(), awaiting: Default::default() })
    }

    fn params<'a>(id: &'a Identity, cfg: &AgentConfig, supported: &Supported) -> ConnectParams<'a> {
        ConnectParams {
            url: cfg.relay_url.clone(),
            tls: cfg.tls.clone(),
            device: &id.device,
            on_behalf_of: Some(id.meta.identity.clone()),
            delegations: vec![id.delegation.clone()],
            supported: supported.clone(),
        }
    }

    /// Persist first-contact state to the identity directory.
    pub fn save_contacts(&self) -> Result<()> {
        let path = self.id.dir.join("contacts.json");
        crate::error::file(&path, std::fs::write(&path, serde_json::to_string_pretty(&self.core.contacts())?))
    }

    /// Pending introductions (id → identity).
    pub fn requests(&self) -> Vec<(String, String)> {
        self.core.requests()
    }

    /// Relay identity and capabilities.
    pub fn relay(&self) -> &crate::conn::RelayInfo {
        &self.conn.relay
    }

    /// Our device DID.
    pub fn device_did(&self) -> &str {
        &self.id.meta.device
    }

    /// Our identity DID.
    pub fn identity_did(&self) -> &str {
        &self.id.meta.identity
    }

    /// Read-only engine access (for printing state).
    pub fn endpoint(&self) -> &Endpoint {
        self.core.endpoint()
    }

    /// Close the connection gracefully (WebSocket close + TLS close_notify).
    pub async fn close(&mut self) {
        self.conn.close(tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal, "bye").await;
    }

    // ------------------------------------------------------------ local actions

    /// Place a call; returns the new session id.
    pub async fn place_call(&mut self, to: &str) -> Result<String> {
        self.place_call_with(to, Invite::default()).await
    }

    /// Place a call with what the host adds to the invite (SDP, claims, patch); returns the new session id.
    pub async fn place_call_with(&mut self, to: &str, invite: Invite) -> Result<String> {
        let sid = self.core.new_id(now_s());
        self.command(Command::PlaceCall { session: sid.clone(), to: to.to_string(), invite }).await?;
        Ok(sid)
    }

    /// A fresh ULID.
    pub fn new_id(&mut self) -> String {
        self.core.new_id(now_s())
    }

    /// Sign and send an application-built payload (publish / subscribe / provenance, …).
    pub async fn send_payload(&mut self, payload: serde_json::Value, ttl: i64) -> Result<String> {
        let frame = self.core.sign_payload(payload, now_s(), ttl)?;
        let env = dsip_core::envelope::Envelope::from_frame(&frame)?;
        self.conn.send(&env).await?;
        Ok(frame)
    }

    /// Verify a record carried inside another message (a presence record in a `notify` body): its payload and the
    /// identity its signer acts for. Spec: P§3.
    pub fn verify_record(&self, frame: &str) -> Option<(serde_json::Value, String)> {
        self.core.verify_record(frame, now_s())
    }

    /// Withdraw a grant we issued (§19.4): the core sends a signed `grant-revocation` to our relay, the authority, for
    /// it and every grant of its rotation chain, so the relay ends what they admitted there (P§7, P§12.5), and rotates
    /// the keys it carried. Returns whether we had issued it.
    pub async fn revoke_grant(&mut self, grant: &str) -> Result<bool> {
        if !self.core.endpoint().contacts.grants_issued.contains_key(grant) {
            return Ok(false);
        }
        self.local(LocalEvent::Revoke { grant: grant.to_string() }).await?;
        Ok(true)
    }

    /// Replace a live grant we issued with one that follows it (§19.4, spec-gap 150): the old grant's revocation to our
    /// relay, which ends what it admitted there (P§7), then the new grant, sent to the same grantee. Returns `false`,
    /// sending nothing, when we issued no live grant `grant` or `presence_audience` is not a P§6 token.
    pub async fn regrant(&mut self, grant: &str, id: String, scope: Vec<String>, valid_until: i64, presence_audience: Option<String>) -> Result<bool> {
        let live = self.endpoint().contacts.grants_issued.get(grant).is_some_and(|g| g.valid_until > now_s());
        if !live || presence_audience.as_deref().is_some_and(|a| !dsip_core::is_presence_audience(a)) {
            return Ok(false);
        }
        // the core revokes the old grant and its chain at our relay before the new grant goes (P§7)
        self.local(LocalEvent::Regrant { grant: grant.to_string(), id, scope, valid_until, presence_audience }).await?;
        Ok(true)
    }

    /// Answer an introduction from `requester` that reached us at our mailbox (M§14.1) with a grant of `scope` until
    /// `valid_until`, issued as one answering an introduction through the relay is ([`Core::grant_request`]), and
    /// saved. Returns the signed grant for the host to deposit at the requester's mailbox, or `None` when the engine
    /// refused it. Spec: §19.4, M§14.1, P§6.
    pub async fn grant_request(&mut self, introduction: &str, requester: &str, scope: Vec<String>, valid_until: i64,
                               presence_audience: Option<String>) -> Result<Option<String>> {
        let id = self.core.new_id(now_s());
        let (grant, rest) = self.core.grant_request(introduction, requester, id, scope, valid_until, presence_audience, now_s())?;
        self.dispatch(rest).await?;
        self.save_contacts()?;
        Ok(grant)
    }

    /// Hold a grant that reached us at our mailbox (M§14.1), as one received through the relay is, and save it:
    /// presented when watching the granter's presence ([`Agent::presence_claims`]), its presence keys opened. Returns
    /// whether it verified and is held ([`Core::hold_grant`]). Spec: §19.4, P§6, P§12.3.
    pub async fn hold_grant(&mut self, compact: &str) -> Result<bool> {
        let (held, out) = self.core.hold_grant(compact, now_s())?;
        self.dispatch(out).await?;
        if held {
            self.save_contacts()?;
        }
        Ok(held)
    }

    /// The held grants from `target` to present when watching its presence (`subscribe` `claims`). Spec: P§6.
    pub fn presence_claims(&self, target: &str) -> Vec<serde_json::Value> {
        self.core.presence_claims(target, now_s())
    }

    /// Whether `device` presented a delegation granting `capability` (Recording Profile C§6).
    pub fn peer_has_capability(&self, device: &str, capability: &str) -> bool {
        self.core.peer_has_capability(device, capability, crate::now_s())
    }

    /// This side's recording declaration from now on (Recording Profile C§3).
    pub fn set_recording(&mut self, declaration: Option<serde_json::Value>) {
        self.core.set_recording(declaration);
    }

    /// Sign and send one of this device's presence records (a `Publisher` payload), sealed when its scope is
    /// ([`AgentConfig::presence`]). Returns the frame. Spec: P§3, P§12.2.
    pub async fn send_presence(&mut self, payload: serde_json::Value, ttl: i64) -> Result<String> {
        let frame = self.core.sign_presence(payload, now_s(), ttl)?;
        self.conn.send(&dsip_core::envelope::Envelope::from_frame(&frame)?).await?;
        Ok(frame)
    }

    /// The key `kid` of `subject`'s presence records: ours derived, a grantor's from its grants (P§12.4).
    pub fn presence_key(&self, subject: &str, kid: &str) -> Option<[u8; 32]> {
        self.core.presence_key(subject, kid)
    }

    /// Whether this device seals its records for `audience` (`None`: the records with no audience). Spec: P§12.6.
    pub fn presence_sealed(&self, audience: Option<&str>) -> bool {
        self.core.presence_sealed(audience)
    }

    /// The wire tag of the audience our identity labels `label` (P§12.1).
    pub fn audience_tag(&self, label: &str) -> String {
        audience_tag(&self.id, label)
    }

    /// A verified record of our own identity, from our own watch: a sibling's higher epoch is adopted and the grants
    /// that carry it are re-granted (P§12.5).
    pub async fn own_record(&mut self, record: &serde_json::Value) -> Result<()> {
        let out = self.core.own_record(record, now_s())?;
        self.dispatch(out).await
    }

    /// Seal outbound session bodies from now on, or stop (§10.4).
    pub fn set_seal(&mut self, on: bool) {
        self.core.set_seal(on);
    }

    /// Place a call through the call glue; returns the new session id. With media, the invite goes once the host
    /// answers the [`MediaRequest::Offer`].
    pub async fn place(&mut self, to: &str, invite: Invite) -> Result<String> {
        let Some(calls) = self.calls.as_mut() else { return Err(crate::Error::NoCalls) };
        let (sid, out) = calls.place(&mut self.core, to, invite, now_s())?;
        self.act(out).await?;
        Ok(sid)
    }

    /// Place a call through the relay at `relay_url`, the one the callee's hint names (§8.1: the hints tier says where
    /// to try; it is not authority): this device binds there on a connection of its own, shared by every call placed
    /// through it, and the session's envelopes go over it. Our own relay's URL, or a relay that does not bind us within
    /// [`PEER_BIND_S`], places it as [`Agent::place`] does.
    pub async fn place_via(&mut self, to: &str, invite: Invite, relay_url: &str) -> Result<String> {
        if relay_url != self.cfg.relay_url {
            if let Err(e) = self.peer(relay_url).await {
                tracing::warn!("their relay {relay_url} did not bind us ({e}); calling through our own relay");
            }
        }
        let routed = self.peers.contains_key(relay_url);
        let Some(calls) = self.calls.as_mut() else { return Err(crate::Error::NoCalls) };
        let (sid, out) = calls.place(&mut self.core, to, invite, now_s())?;
        if routed {
            tracing::info!("call {sid} to {to} through their relay {relay_url}");
            self.routes.insert(sid.clone(), (relay_url.to_string(), now_s(), false));
        }
        self.act(out).await?;
        Ok(sid)
    }

    /// Sign an application-built payload without sending it (a `subscribe` for another relay, [`Agent::send_frame`]).
    pub fn sign(&mut self, payload: serde_json::Value, ttl: i64) -> Result<String> {
        Ok(self.core.sign_payload(payload, now_s(), ttl)?)
    }

    /// Bind at the relay at `url` unless bound there (our own relay's URL is ours), and return its DID: what a payload
    /// addressed to it names in `to`. Spec: §13.2, §9.3.
    pub async fn relay_at(&mut self, url: &str) -> Result<String> {
        if url == self.cfg.relay_url {
            return Ok(self.conn.relay.did.clone());
        }
        self.peer(url).await?;
        Ok(self.peers[url].relay.did.clone())
    }

    /// Send a signed frame to the relay at `via` — bound there first ([`Agent::place_via`]'s connection, shared with
    /// the calls through it) — or, with `None` or our own relay's URL, to ours. Returns the DID of the relay it went
    /// to. A connection made for it closes once nothing uses it, unless kept ([`Agent::keep_peer`]).
    /// Spec: §9.3 (spec-gap 143: a subscription at the relay that answers for the target), §8.1.
    pub async fn send_frame(&mut self, frame: &str, via: Option<&str>) -> Result<String> {
        let env = dsip_core::envelope::Envelope::from_frame(frame)?;
        match via.filter(|u| *u != self.cfg.relay_url) {
            Some(url) => {
                self.peer(url).await?;
                let c = self.peers.get_mut(url).expect("bound above");
                c.send(&env).await?;
                Ok(c.relay.did.clone())
            }
            None => {
                self.conn.send(&env).await?;
                Ok(self.conn.relay.did.clone())
            }
        }
    }

    /// Send `payload`, a request to our own relay that the engine does not make (a profile's, such as `wake-register`,
    /// W§4.2), signed as our device with its delegation; its answer comes back as [`AgentEvent::Reply`] rather than to
    /// the engine. Returns the request's id. `payload` keeps its own `id`, `issued_at` and `expires_at` when it has them.
    /// Spec: §13.2 (a request on the binding), W§4.2.
    pub async fn request(&mut self, payload: serde_json::Value, ttl: i64) -> Result<String> {
        let frame = self.sign(payload, ttl)?;
        let env = dsip_core::envelope::Envelope::from_frame(&frame)?;
        let id = payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)).unwrap_or_default();
        self.awaiting.insert(id.clone());
        if let Err(e) = self.conn.send(&env).await {
            self.awaiting.remove(&id);
            return Err(e);
        }
        Ok(id)
    }

    /// Verify and read `frame`, our relay's answer to request `id` ([`AgentEvent::Reply`]): `wake-accepted`, or a core
    /// `error`. Spec: W§4.2, §10.2.
    pub fn read_reply(&self, id: &str, frame: &str) -> std::result::Result<crate::wake::Answer, crate::wake::WakeError> {
        crate::wake::read_reply(&self.conn.relay.did, &self.resolver, frame, id, now_s())
    }

    /// Stop waiting for the answer to request `id` (the host gave up on it).
    pub fn forget_request(&mut self, id: &str) {
        self.awaiting.remove(id);
    }

    /// `frame` from our relay, when it answers a request sent with [`Agent::request`]: the event to give the host.
    fn reply_to_request(&mut self, frame: &str) -> Option<AgentEvent> {
        if self.awaiting.is_empty() {
            return None;
        }
        let env = dsip_core::envelope::Envelope::from_frame(frame).ok()?;
        let p = payload_of(&env)?;
        let id = p["in_reply_to"].as_str()?;
        self.awaiting.remove(id).then(|| AgentEvent::Reply { in_reply_to: id.to_string(), frame: frame.to_string() })
    }

    /// Keep our connection to the relay at `url` open while no call uses it (`true`: a presence watch there), or let it
    /// close once none does (`false`). A kept connection that drops is not redialled: it leaves
    /// [`Agent::peer_relays`], and the host sends there again to bind anew.
    pub fn keep_peer(&mut self, url: &str, keep: bool) {
        if keep {
            self.kept.insert(url.to_string());
        } else {
            self.kept.remove(url);
        }
    }

    /// The other relays this device is bound at, for calls or kept ([`Agent::keep_peer`]), by URL.
    pub fn peer_relays(&self) -> Vec<String> {
        let mut v: Vec<String> = self.peers.keys().cloned().collect();
        v.sort();
        v
    }

    /// The URL of the relay `session`'s envelopes go through, when it is not our own.
    pub fn route_of(&self, session: &str) -> Option<&str> {
        self.routes.get(session).map(|(u, _, _)| u.as_str())
    }

    /// Bind to the relay at `url`, unless bound there.
    async fn peer(&mut self, url: &str) -> Result<()> {
        if self.peers.contains_key(url) {
            return Ok(());
        }
        let mut params = Self::params(&self.id, &self.cfg, &self.supported);
        params.url = url.to_string();
        let mut seen = SeenIds::default();
        let stream = self.cfg.peer_dialer.as_ref().and_then(|d| d.dial(url));
        let bind = async {
            match stream {
                Some(s) => Connection::over(s.await?, &params, &self.resolver, &mut seen).await,
                None => Connection::connect(&params, &self.resolver, &mut seen).await,
            }
        };
        let conn = tokio::time::timeout(Duration::from_secs(PEER_BIND_S), bind)
            .await
            .map_err(|_| crate::Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{url} did not bind in {PEER_BIND_S} s"))))??;
        tracing::info!("bound at their relay {url} ({})", conn.relay.did);
        self.peers.insert(url.to_string(), conn);
        Ok(())
    }

    /// Forget the routes of sessions that ended, and close the connections no call uses any more.
    async fn prune_routes(&mut self) {
        let now = now_s();
        let ep = self.core.endpoint();
        self.routes.retain(|sid, (_, since, seen)| match ep.session(sid) {
            Some(s) => {
                *seen = true;
                s.state != SessionState::Ended
            }
            // gone: ended and forgotten, or never made (an invite that waited for an offer that never came)
            None => !*seen && now - *since < ROUTE_GRACE_S,
        });
        let used: std::collections::HashSet<String> = self.routes.values().map(|(u, _, _)| u.clone()).collect();
        let idle: Vec<String> = self.peers.keys().filter(|u| !used.contains(*u) && !self.kept.contains(*u)).cloned().collect();
        for url in idle {
            if let Some(mut c) = self.peers.remove(&url) {
                tracing::info!("closing our connection to their relay {url}: no call uses it");
                c.close(tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal, "done").await;
            }
        }
    }

    /// Do what the application asks of a call, through the call glue.
    pub async fn call(&mut self, cmd: CallCommand) -> Result<()> {
        let Some(calls) = self.calls.as_mut() else { return Err(crate::Error::NoCalls) };
        let out = calls.command(&mut self.core, cmd, now_s())?;
        self.act(out).await
    }

    /// Hand the call glue the result of a [`MediaRequest`], or a local ICE candidate.
    pub async fn media(&mut self, result: MediaResult) -> Result<()> {
        let Some(calls) = self.calls.as_mut() else { return Err(crate::Error::NoCalls) };
        let out = calls.media(&mut self.core, result, now_s())?;
        self.act(out).await
    }

    /// Drive a local event through the core and act on its output.
    pub async fn local(&mut self, ev: LocalEvent) -> Result<()> {
        self.command(Command::Engine(ev)).await
    }

    /// Drive a host request through the core and act on its output.
    pub async fn command(&mut self, cmd: Command) -> Result<()> {
        let out = self.core.command(cmd, now_s())?;
        self.dispatch(out).await
    }

    /// Advance the engine clock to wall time (fires due timers) and act on emissions.
    pub async fn tick_and_handle(&mut self) -> Result<()> {
        let out = self.core.tick(now_s())?;
        self.dispatch(out).await
    }

    /// Act on the core's output, through the call glue when it runs.
    async fn dispatch(&mut self, out: Vec<CoreEvent>) -> Result<()> {
        let out = match self.calls.as_mut() {
            Some(calls) => calls.observe(&mut self.core, out, now_s())?,
            None => out.into_iter().map(CallOut::Core).collect(),
        };
        self.act(out).await
    }

    async fn act(&mut self, out: Vec<CallOut>) -> Result<()> {
        for o in out {
            let e = match o {
                CallOut::Core(e) => e,
                CallOut::Media(m) => {
                    self.events.push(AgentEvent::Media(m));
                    continue;
                }
                CallOut::Call(c) => {
                    self.events.push(AgentEvent::Call(c));
                    continue;
                }
            };
            match e {
                CoreEvent::Send { frame, msg_type, session, to } => {
                    let env = dsip_core::envelope::Envelope::from_frame(&frame)?;
                    // a session placed through another relay goes over our connection there (§8.1)
                    let peer = self.routes.get(&session).and_then(|(u, _, _)| self.peers.get_mut(u));
                    match peer {
                        Some(c) => c.send(&env).await?,
                        None => self.conn.send(&env).await?,
                    }
                    if msg_type == "grant" {
                        let grant = format!("{}.{}.{}", env.protected, env.payload, env.signature);
                        self.events.push(AgentEvent::GrantIssued { to: to.clone(), grant });
                    }
                    self.events.push(AgentEvent::Sent { msg_type, session, to });
                }
                CoreEvent::Emission(em) => self.events.push(AgentEvent::Emission(em)),
                CoreEvent::Received { message, identity, display_name, payload } => {
                    if payload["type"] == "error" && payload["reason"] == "transport.replaced" && identity == self.conn.relay.did {
                        self.replaced = true; // §13.2: our relay is about to close this connection
                    }
                    self.events.push(AgentEvent::Received { message, identity, display_name, payload })
                }
                CoreEvent::Rejected { code, detail } => self.events.push(AgentEvent::Rejected(code, detail)),
                CoreEvent::Resolve { did } => {
                    // Fetched off the loop; the outcome comes back through `next`.
                    let (r, tx) = (Arc::clone(&self.did_resolver), self.resolved_tx.clone());
                    tokio::spawn(async move {
                        let result = r.resolve(&did).await;
                        if let Err(e) = &result {
                            tracing::warn!("resolving {did}: {e}");
                        }
                        let _ = tx.send((did, result));
                    });
                }
            }
        }
        Ok(())
    }

    /// A handle that makes [`Agent::next`] return what it holds, even nothing, so the host can act (a command from
    /// another task, a media event). A wake before `next` is waiting is kept for it. Waking is how a host interrupts
    /// `next` without cancelling it mid-step, as dropping it in a `select!` could.
    pub fn waker(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.wake)
    }

    /// Wait for the next thing to happen (inbound frame, timer, connection loss, or a [`Agent::waker`] wake) and
    /// return the accumulated application events. Reconnects with backoff on connection loss.
    pub async fn next(&mut self) -> Result<Vec<AgentEvent>> {
        loop {
            if !self.routes.is_empty() || !self.peers.is_empty() {
                self.prune_routes().await;
            }
            if !self.events.is_empty() {
                return Ok(std::mem::take(&mut self.events));
            }
            if self.replaced_closed {
                return Err(crate::Error::Replaced { relay: self.conn.relay.did.clone() });
            }
            let wait = self.core.next_deadline().map(|d| (d - now_s()).max(0) as u64).unwrap_or(3600);
            tokio::select! {
                frame = self.conn.recv() => match frame {
                    Ok(Some(text)) => match self.reply_to_request(&text) {
                        Some(reply) => self.events.push(reply),
                        None => {
                            let out = self.core.inbound(&text, now_s())?;
                            self.dispatch(out).await?;
                        }
                    },
                    // §13.2: a connection the relay replaced is not reconnected; that would replace the other one
                    Ok(None) | Err(_) if self.replaced => {
                        self.replaced_closed = true;
                        continue;
                    }
                    Ok(None) => self.reconnect().await?,
                    Err(e) => {
                        tracing::warn!("connection error: {e}");
                        self.reconnect().await?;
                    }
                },
                (url, frame) = Self::peer_recv(&mut self.peers), if !self.peers.is_empty() => match frame {
                    Ok(Some(text)) => {
                        let out = self.core.inbound(&text, now_s())?;
                        self.dispatch(out).await?;
                    }
                    // a connection to another relay is not redialled: its calls go on, or end, by their timers
                    Ok(None) | Err(_) => {
                        tracing::info!("their relay {url} closed our connection");
                        self.peers.remove(&url);
                        self.routes.retain(|_, (u, _, _)| *u != url);
                    }
                },
                Some((did, result)) = self.resolved_rx.recv() => {
                    if let Ok(doc) = &result {
                        self.resolver.insert(doc.clone()); // held for reconnects too (relay hello)
                    }
                    let out = self.core.resolved(&did, result, now_s())?;
                    self.dispatch(out).await?;
                }
                _ = tokio::time::sleep(Duration::from_secs(wait.max(1))) => {}
                _ = self.wake.notified() => return Ok(std::mem::take(&mut self.events)),
            }
            self.tick_and_handle().await?;
        }
    }

    /// The next frame from any connection to another relay, with its URL.
    async fn peer_recv(peers: &mut std::collections::HashMap<String, Connection>) -> (String, Result<Option<String>>) {
        let recvs = peers.iter_mut().map(|(u, c)| Box::pin(async move { (u.clone(), c.recv().await) }));
        futures_util::future::select_all(recvs).await.0
    }

    async fn reconnect(&mut self) -> Result<()> {
        // §13.2: exponential backoff with jitter, fresh hello; sessions are unaffected.
        let (mut delay, factor, max) = BACKOFF;
        let mut attempts = 0u32;
        let mut seen = SeenIds::default();
        loop {
            attempts += 1;
            let jitter = Duration::from_millis((now_s() as u64 * 7919 + attempts as u64 * 104_729) % (delay * 1000));
            tokio::time::sleep(jitter).await;
            match Connection::dial(self.cfg.dialer.as_deref(), &Self::params(&self.id, &self.cfg, &self.supported), &self.resolver, &mut seen).await {
                Ok(c) => {
                    self.conn = c;
                    self.core.set_authority(Some(self.conn.relay.did.clone()));
                    self.events.push(AgentEvent::Reconnected { attempts });
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("reconnect attempt {attempts} failed: {e}");
                    delay = (delay * factor as u64).min(max);
                }
            }
        }
    }
}

/// The decoded payload of an envelope, unverified: only to match a reply to its request.
fn payload_of(env: &dsip_core::envelope::Envelope) -> Option<serde_json::Value> {
    serde_json::from_slice(&dsip_core::b64::decode(&env.payload)?).ok()
}
