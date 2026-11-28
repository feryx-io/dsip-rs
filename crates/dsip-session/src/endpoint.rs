//! The endpoint state engine: every session this device participates in.
//!
//! Spec: §12.4 (states and transitions), §12.5 (cancel/answer race), §12.6
//! (glare), §12.7 (forked answers, initiator side), §12.8 (renegotiation),
//! §12.9 (timers), §12.10 (`progress`/queued timing), §12.11 (`cancel`),
//! §12.12 (`info`), §14.3–§14.4 (`answered_by`, screening), P§12.3–P§12.5 (presence keys in the grants this device
//! issues and holds, rotation and re-granting).
//!
//! Every `Impl (spec-gap N)` comment has an entry in `impl/docs/spec-gaps.md`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use dsip_core::presence_seal::MAIN;
use dsip_core::registry::{effective_answered_by, effective_progress_status, resolve_reason, INFO_ABOUT};

use crate::event::{DropReason, Emission, Event, KeysAction, LocalEvent, MediaCommand, Refusal, SendMsg, TimerAction, TimerName, UiEvent};
use crate::message::Message;

/// T-Establish default and bounds (seconds). Spec: §12.9.
pub const T_ESTABLISH: (i64, i64, i64) = (15, 5, 60);
/// T-Ring default and bounds (seconds). Spec: §12.9.
pub const T_RING: (i64, i64, i64) = (120, 30, 300);
/// T-Queue hard cap (seconds). Spec: §12.9, §12.10.
pub const T_QUEUE_CAP: i64 = 1800;
/// T-Ring-Local default and bounds (seconds). Spec: §12.9.
pub const T_RING_LOCAL: (i64, i64, i64) = (120, 30, 300);
/// T-Presence-Rotate default and bounds (seconds). Spec: P§8.
pub const T_PRESENCE_ROTATE: (i64, i64, i64) = (60, 0, 3600);
/// Consecutive re-queue limit. Spec: §12.10 (RECOMMENDED: 3).
pub const MAX_CONSECUTIVE_REQUEUES: u32 = 3;
/// An `update`'s validity, seconds, unless its sender chooses another (§12.9): unanswered at its end, it lapses
/// (§12.8 rule 7).
pub const UPDATE_VALIDITY_S: i64 = 30;

fn clamp(v: i64, (_, lo, hi): (i64, i64, i64)) -> i64 {
    v.clamp(lo, hi)
}

/// Which side of the session this endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Sent the invite.
    Initiator,
    /// Received the invite.
    Responder,
}

/// Session states.
///
/// Spec: §12.4 — initiator: IDLE, INVITING, PROCEEDING, ACTIVE, ENDING, ENDED;
/// responder: IDLE, OFFERED, ALERTING, ACTIVE, ENDED. IDLE is the absence of a
/// session. Impl (spec-gap 13): ENDING is collapsed into ENDED.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[allow(missing_docs)]
pub enum SessionState {
    Inviting,
    Proceeding,
    Offered,
    Alerting,
    Active,
    Ended,
}

/// Direction of an outstanding update relative to this endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// We sent it (RENEGOTIATING sub-state, §12.8 rule 2).
    Outbound,
    /// The peer sent it; we owe an answer/reject.
    Inbound,
}

/// The one outstanding update a session may have (§12.8 rule 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outstanding {
    /// Update id.
    pub id: String,
    /// Direction.
    pub direction: Direction,
}

/// Per-session state.
#[derive(Debug, Clone)]
pub struct Session {
    /// Session id (= invite id, §12.2).
    pub id: String,
    /// Role.
    pub role: Role,
    /// State.
    pub state: SessionState,
    /// DID we address session messages to.
    pub peer: String,
    /// Initiator: the identity/device the invite addressed.
    pub invite_to: Option<String>,
    /// Responder: the invite's `expires_at`.
    pub invite_expires_at: Option<i64>,
    /// Initiator: the device whose answer was accepted.
    pub answered_device: Option<String>,
    /// Outstanding update, if any.
    pub outstanding: Option<Outstanding>,
    /// The outstanding update's `expires_at`: unanswered then, it lapses (§12.8 rule 7).
    pub update_expires_at: i64,
    cancelled: bool,
    was_active: bool,
    post_answer_seen: bool,
    queue_count: u32,
}

impl Session {
    fn new(id: &str, role: Role, state: SessionState, peer: &str) -> Session {
        Session {
            id: id.into(),
            role,
            state,
            peer: peer.into(),
            invite_to: None,
            invite_expires_at: None,
            answered_device: None,
            outstanding: None,
            update_expires_at: 0,
            cancelled: false,
            was_active: false,
            post_answer_seen: false,
            queue_count: 0,
        }
    }

    /// RENEGOTIATING sub-state: our update is outstanding (§12.8 rule 2).
    pub fn renegotiating(&self) -> bool {
        matches!(&self.outstanding, Some(o) if o.direction == Direction::Outbound)
    }

    /// The README snapshot shape.
    pub fn snapshot(&self) -> Value {
        json!({
            "role": self.role,
            "state": self.state,
            "renegotiating": self.renegotiating(),
            "outstanding_update": self.outstanding,
        })
    }
}

#[derive(Debug, Clone)]
struct Timer {
    name: TimerName,
    session: String,
    deadline: i64,
    seq: u64,
}

/// Endpoint configuration.
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    /// This device's DID.
    pub device: String,
    /// The identity this device acts for.
    pub identity: String,
    /// Known device→identity mapping (for glare detection, §12.6).
    pub identities: HashMap<String, String>,
    /// Clock at construction.
    pub start: i64,
    /// T-Establish (clamped to bounds).
    pub t_establish: i64,
    /// T-Ring (clamped to bounds).
    pub t_ring: i64,
    /// T-Ring-Local (clamped to bounds).
    pub t_ring_local: i64,
    /// §19.4: reject invites from identities holding no grant.
    pub first_contact_required: bool,
    /// §19.4: identities admitted without a grant.
    pub allow: BTreeSet<String>,
    /// P§12.3, P§12.5: presence keys; `None` keeps no key state.
    pub presence_keys: Option<PresenceKeysConfig>,
}

/// What this device seals, and how often it may rotate (P§8, P§12.5, P§12.6).
#[derive(Debug, Clone, Default)]
pub struct PresenceKeysConfig {
    /// The scopes it seals: `main` and audience tags.
    pub sealed: BTreeSet<String>,
    /// T-Presence-Rotate (clamped to bounds).
    pub t_rotate: i64,
    /// Ids for the grants it issues on its own (re-grants), in order. A host that mints ids sets
    /// [`Endpoint::set_grant_ids`] instead.
    pub grant_ids: Vec<String>,
}

impl EndpointConfig {
    /// From a state vector's `context`.
    pub fn from_vector(ctx: &Value) -> EndpointConfig {
        let t = |k: &str, d: (i64, i64, i64)| clamp(ctx.pointer(&format!("/timers/{k}")).and_then(Value::as_i64).unwrap_or(d.0), d);
        EndpointConfig {
            device: ctx.pointer("/self/device").and_then(Value::as_str).unwrap_or("").into(),
            identity: ctx.pointer("/self/identity").and_then(Value::as_str).unwrap_or("").into(),
            identities: ctx
                .get("identities")
                .and_then(Value::as_object)
                .map(|o| o.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect())
                .unwrap_or_default(),
            start: ctx.get("start").and_then(Value::as_i64).unwrap_or(0),
            t_establish: t("t_establish", T_ESTABLISH),
            t_ring: t("t_ring", T_RING),
            t_ring_local: t("t_ring_local", T_RING_LOCAL),
            first_contact_required: ctx.pointer("/policy/first_contact_required").and_then(Value::as_bool).unwrap_or(false),
            allow: ctx
                .pointer("/policy/allow")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                .unwrap_or_default(),
            presence_keys: ctx.get("presence_keys").map(|pk| PresenceKeysConfig {
                sealed: pk["sealed"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default(),
                t_rotate: clamp(pk["t_rotate"].as_i64().unwrap_or(T_PRESENCE_ROTATE.0), T_PRESENCE_ROTATE),
                grant_ids: pk["grant_ids"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default(),
            }),
        }
    }
}

/// A contact grant (§19.4), issued or held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Grant {
    /// Grantee (issued) or grantor (held) identity.
    pub identity: String,
    /// Scopes.
    pub scope: Vec<String>,
    /// Lifetime.
    pub valid_until: i64,
    /// The presence audience it names (issued grants; P§6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence_audience: Option<String>,
    /// The scopes it carried presence keys for (issued grants; P§12.3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    /// The grants it follows by re-granting, newest first: its rotation chain (P§12.5, spec-gap 159).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
    /// It ended and made its scopes due (P§12.5): a grant ends once.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ended: bool,
}

/// This device's presence key state: epochs per scope, rotations waiting, keys held from grantors.
///
/// Spec: P§12.4, P§12.5.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceKeys {
    /// The current epoch per scope.
    pub epochs: BTreeMap<String, i64>,
    /// When each scope was last rotated by this device.
    pub last_rotated: BTreeMap<String, i64>,
    /// Scopes waiting to rotate, and when.
    pub due: BTreeMap<String, i64>,
    /// Grantor identity → scope → the (at most two) highest epochs held (P§12.4).
    pub held: BTreeMap<String, BTreeMap<String, BTreeSet<i64>>>,
}

impl PresenceKeys {
    /// The key id of `scope` at its current epoch.
    pub fn kid(&self, scope: &str) -> String {
        format!("{scope}.{}", self.epochs.get(scope).copied().unwrap_or(0))
    }

    /// README snapshot shape, with `chains` from the issued grants.
    pub fn snapshot(&self, contacts: &Contacts) -> Value {
        let chains: serde_json::Map<String, Value> =
            contacts.grants_issued.iter().filter(|(_, g)| !g.chain.is_empty()).map(|(id, g)| (id.clone(), json!(g.chain))).collect();
        let held: serde_json::Map<String, Value> = self
            .held
            .iter()
            .map(|(by, scopes)| (by.clone(), json!(scopes.iter().flat_map(|(sc, es)| es.iter().map(move |e| format!("{sc}.{e}"))).collect::<Vec<_>>())))
            .collect();
        json!({"epochs": self.epochs, "due": self.due, "chains": chains, "held": held})
    }
}

/// Split a key id into scope and epoch (P§12.1).
fn split_kid(kid: &str) -> Option<(&str, i64)> {
    let (scope, epoch) = kid.rsplit_once('.')?;
    if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((scope, epoch.parse().ok()?))
}

/// First-contact state (§19.4): allowlist, grants, requests, pending introductions, tokens.
#[derive(Debug, Default, Clone)]
pub struct Contacts {
    /// Identities admitted without a grant.
    pub allow: BTreeSet<String>,
    /// Grants we issued, by id.
    pub grants_issued: BTreeMap<String, Grant>,
    /// Grants we hold, by id.
    pub grants_held: BTreeMap<String, Grant>,
    /// Pending introductions received: id → (identity, device).
    pub requests: BTreeMap<String, (String, String)>,
    /// Introductions we sent: id → recipient.
    pub pending_sent: BTreeMap<String, String>,
    /// Contact tokens we issued: token → grant id.
    pub tokens: HashMap<String, String>,
    seen_introductions: HashSet<String>,
}

impl Contacts {
    /// README snapshot shape.
    pub fn snapshot(&self) -> Value {
        json!({
            "allow": self.allow,
            "grants_issued": self.grants_issued.keys().collect::<Vec<_>>(),
            "grants_held": self.grants_held.keys().collect::<Vec<_>>(),
            "requests": self.requests.keys().collect::<Vec<_>>(),
            "pending_sent": self.pending_sent.keys().collect::<Vec<_>>(),
        })
    }

    /// §19.4: a live `dsip.invite` grant issued to `identity`. An invite's `grant` reference is a hint for finding
    /// the grant: it never admits and never refuses on its own (spec-gap 151).
    pub fn admits(&self, identity: &str, now: i64) -> bool {
        self.grants_issued
            .values()
            .any(|g| g.identity == identity && g.valid_until > now && g.scope.iter().any(|s| s == "dsip.invite"))
    }

    /// A live grant we hold from `identity`, if any (lowest id first).
    pub fn held_from(&self, identity: &str, now: i64) -> Option<String> {
        self.grants_held
            .iter()
            .find(|(_, g)| g.identity == identity && g.valid_until > now && g.scope.iter().any(|s| s == "dsip.invite"))
            .map(|(gid, _)| gid.clone())
    }
}

/// The endpoint: sessions, timers, clock.
///
/// Spec: §12.4 "each endpoint maintains a per-session state machine; there is no shared network state."
pub struct Endpoint {
    cfg: EndpointConfig,
    /// Current clock (seconds).
    pub now: i64,
    sessions: HashMap<String, Session>,
    timers: Vec<Timer>,
    seq: u64,
    out: Vec<Emission>,
    /// First-contact state.
    pub contacts: Contacts,
    /// Presence key state (P§12.4, P§12.5).
    pub keys: PresenceKeys,
    grant_ids: VecDeque<String>,
    mint: Option<Box<dyn FnMut() -> String + Send>>,
}

impl Endpoint {
    /// Create an endpoint.
    pub fn new(cfg: EndpointConfig) -> Endpoint {
        let now = cfg.start;
        let contacts = Contacts { allow: cfg.allow.clone(), ..Default::default() };
        let mut keys = PresenceKeys::default();
        let mut grant_ids = VecDeque::new();
        if let Some(pk) = &cfg.presence_keys {
            keys.epochs.insert(MAIN.into(), 0);
            keys.epochs.extend(pk.sealed.iter().map(|s| (s.clone(), 0)));
            grant_ids.extend(pk.grant_ids.iter().cloned());
        }
        Endpoint { cfg, now, sessions: HashMap::new(), timers: vec![], seq: 0, out: vec![], contacts, keys, grant_ids, mint: None }
    }

    /// Where ids for the grants this endpoint issues on its own come from, in place of
    /// [`PresenceKeysConfig::grant_ids`]: a host minting ULIDs.
    pub fn set_grant_ids(&mut self, mint: Box<dyn FnMut() -> String + Send>) {
        self.mint = Some(mint);
    }

    /// The presence key configuration, if keys are on.
    pub fn presence_keys_config(&self) -> Option<&PresenceKeysConfig> {
        self.cfg.presence_keys.as_ref()
    }

    /// Look up a session.
    pub fn session(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Record that `device` acts for `identity` (learned from a verified delegation). Spec: §7.4, §12.6.
    pub fn learn_identity(&mut self, device: &str, identity: &str) {
        self.cfg.identities.insert(device.into(), identity.into());
    }

    /// Known device → identity mapping.
    pub fn identities(&self) -> &HashMap<String, String> {
        &self.cfg.identities
    }

    /// Is the first-contact policy on?
    pub fn first_contact_required(&self) -> bool {
        self.cfg.first_contact_required
    }

    /// Snapshot of the named sessions (`null` for unknown), README shape.
    pub fn snapshot(&self, ids: impl IntoIterator<Item = String>) -> Value {
        let mut m = serde_json::Map::new();
        for id in ids {
            m.insert(id.clone(), self.sessions.get(&id).map(Session::snapshot).unwrap_or(Value::Null));
        }
        Value::Object(m)
    }

    /// When the next timer fires, a keyed grant ends or a scope rotates, if any (for a real scheduler).
    pub fn next_deadline(&self) -> Option<i64> {
        self.instants().into_iter().min()
    }

    /// Every instant at which [`Endpoint::advance`] has something to do.
    fn instants(&self) -> Vec<i64> {
        let mut v: Vec<i64> = self.timers.iter().map(|t| t.deadline).collect();
        v.extend(self.contacts.grants_issued.values().filter(|g| !g.keys.is_empty() && !g.ended).map(|g| g.valid_until));
        v.extend(self.keys.due.values().copied());
        v.extend(self.sessions.values().filter(|s| s.outstanding.is_some()).map(|s| s.update_expires_at));
        v
    }

    /// Drive one event; returns the emissions in order.
    pub fn step(&mut self, event: &Event) -> Vec<Emission> {
        self.out.clear();
        match event {
            Event::Advance { advance } => self.advance(*advance),
            Event::Recv { recv } => self.recv(recv),
            Event::Local(l) => self.local(l),
        }
        std::mem::take(&mut self.out)
    }

    // ------------------------------------------------------------ helpers

    fn identity_of<'a>(&'a self, did: &'a str) -> &'a str {
        self.cfg.identities.get(did).map(String::as_str).unwrap_or(did)
    }

    fn emit(&mut self, e: Emission) {
        self.out.push(e);
    }

    fn send(&mut self, m: SendMsg) {
        self.out.push(Emission::Send(m));
    }

    fn send_simple(&mut self, msg_type: &str, to: &str, session: &str, reason: Option<&str>) {
        self.send(SendMsg {
            msg_type: msg_type.into(),
            to: to.into(),
            session: Some(session.into()),
            reason: reason.map(String::from),
            ..Default::default()
        });
    }

    fn error(&mut self, m: &Message, reason: &str) {
        self.send(SendMsg {
            msg_type: "error".into(),
            to: m.from.clone(),
            session: Some(m.session.clone().unwrap_or_default()),
            reason: Some(reason.into()),
            in_reply_to: Some(m.id.clone()),
            ..Default::default()
        });
    }

    fn ui(&mut self, ui: UiEvent) {
        self.emit(Emission::Ui(ui));
    }

    fn running(&self, sid: &str, name: TimerName) -> bool {
        self.timers.iter().any(|t| t.session == sid && t.name == name)
    }

    fn start_timer(&mut self, sid: &str, name: TimerName, seconds: i64) {
        self.timers.retain(|t| !(t.session == sid && t.name == name));
        self.seq += 1;
        self.timers.push(Timer { name, session: sid.into(), deadline: self.now + seconds, seq: self.seq });
        self.emit(Emission::Timer { action: TimerAction::Start { seconds }, name });
    }

    fn stop_timer(&mut self, sid: &str, name: TimerName) {
        if self.running(sid, name) {
            self.timers.retain(|t| !(t.session == sid && t.name == name));
            self.emit(Emission::Timer { action: TimerAction::Stop, name });
        }
    }

    fn stop_all(&mut self, sid: &str) {
        for name in [TimerName::Establish, TimerName::Ring, TimerName::Queue, TimerName::RingLocal] {
            self.stop_timer(sid, name);
        }
    }

    /// Terminal transition: stop timers, discard any pending update (§12.8 rule 6), optional media stop, ui ended.
    fn end(&mut self, sid: &str, ui_reason: Option<&str>, media_stop: bool) {
        self.stop_all(sid);
        if let Some(s) = self.sessions.get_mut(sid) {
            s.outstanding = None;
            s.state = SessionState::Ended;
        }
        if media_stop {
            self.emit(Emission::Media(MediaCommand::Stop));
        }
        if let Some(r) = ui_reason {
            self.ui(UiEvent::Ended { reason: r.into() });
        }
    }

    // ------------------------------------------------------------ clock

    /// Advance the clock. Instants are taken in order: at each, the due timers fire in deadline order (ties by start
    /// order), then the updates whose `expires_at` it is lapse, in session id order (§12.8 rule 7), then the keyed
    /// grants whose `valid_until` it is end, in id order, then the scopes due rotate (P§12.5).
    pub fn advance(&mut self, seconds: i64) {
        let target = self.now + seconds;
        while let Some(at) = self.instants().into_iter().filter(|t| *t <= target).min() {
            self.now = self.now.max(at);
            while let Some(t) = self.timers.iter().filter(|t| t.deadline <= self.now).min_by_key(|t| (t.deadline, t.seq)).cloned() {
                self.timers.retain(|x| x.seq != t.seq);
                self.fire(&t);
            }
            // §12.8 rule 7 (spec-gap 191): an update neither answered nor rejected at its expires_at is no longer
            // outstanding. Its sender treats it as rejected, `session.expired`; its receiver may no longer answer it.
            let mut lapsing: Vec<(String, Direction)> = self
                .sessions
                .values()
                .filter(|s| s.update_expires_at <= self.now)
                .filter_map(|s| s.outstanding.as_ref().map(|o| (s.id.clone(), o.direction)))
                .collect();
            lapsing.sort_by(|a, b| a.0.cmp(&b.0));
            for (sid, direction) in lapsing {
                self.sessions.get_mut(&sid).expect("exists").outstanding = None;
                self.ui(match direction {
                    Direction::Outbound => UiEvent::UpdateRejected { reason: "session.expired".into() },
                    Direction::Inbound => UiEvent::UpdateLapsed,
                });
            }
            // P§12.5: a share reaching its valid_until (spec-gap 141: at that instant) ends
            let ending: Vec<String> = self
                .contacts
                .grants_issued
                .iter()
                .filter(|(_, g)| !g.keys.is_empty() && !g.ended && g.valid_until <= self.now)
                .map(|(id, _)| id.clone())
                .collect();
            for id in ending {
                self.end_grant(&id, &[]);
            }
            self.rotate_due();
        }
        self.now = target;
    }

    fn fire(&mut self, t: &Timer) {
        self.emit(Emission::Timer { action: TimerAction::Fire, name: t.name });
        let Some(s) = self.sessions.get(&t.session).cloned() else { return };
        match (t.name, s.state) {
            (TimerName::Establish | TimerName::Ring | TimerName::Queue, SessionState::Inviting | SessionState::Proceeding) => {
                // §12.9: on expiry, cancel with reason session.timeout
                self.stop_all(&s.id);
                self.send_simple("cancel", s.invite_to.as_deref().unwrap_or(""), &s.id, Some("session.timeout"));
                self.sessions.get_mut(&s.id).expect("exists").cancelled = true;
                self.end(&s.id, Some("session.timeout"), false);
            }
            (TimerName::RingLocal, SessionState::Alerting) => {
                // §12.9: on expiry, reject with reason user.no-answer
                self.send_simple("reject", &s.peer, &s.id, Some("user.no-answer"));
                self.end(&s.id, Some("user.no-answer"), false);
            }
            _ => {}
        }
    }

    /// P§12.3: the scopes a grant carries keys for: `main` and its audience, when it admits presence and either is
    /// sealed.
    fn key_scopes(&self, scope: &[String], audience: Option<&str>) -> Vec<String> {
        let Some(pk) = &self.cfg.presence_keys else { return vec![] };
        if !scope.iter().any(|s| s == "dsip.subscribe") || !(pk.sealed.contains(MAIN) || audience.is_some_and(|a| pk.sealed.contains(a))) {
            return vec![];
        }
        std::iter::once(MAIN.to_string()).chain(audience.map(String::from)).collect()
    }

    /// §19.4 outcome 1: a signed contact grant — the consent receipt (§19.3) in message form; P§6: it may name the
    /// presence audience it admits to; P§12.3: it carries the keys of its scopes at their current epochs. `session` is
    /// the introduction it answers, or the grant it follows (spec-gap 150).
    fn issue_grant(&mut self, gid: &str, grantee: &str, scope: Vec<String>, valid_until: i64, session: &str, presence_audience: Option<&str>) {
        self.issue_grant_in_chain(gid, grantee, scope, valid_until, session, presence_audience, vec![]);
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_grant_in_chain(
        &mut self,
        gid: &str,
        grantee: &str,
        scope: Vec<String>,
        valid_until: i64,
        session: &str,
        presence_audience: Option<&str>,
        chain: Vec<String>,
    ) {
        let keys = self.key_scopes(&scope, presence_audience);
        for sc in &keys {
            self.keys.epochs.entry(sc.clone()).or_insert(0);
        }
        let kids: Vec<String> = keys.iter().map(|sc| self.keys.kid(sc)).collect();
        self.contacts.grants_issued.insert(
            gid.into(),
            Grant {
                identity: grantee.into(),
                scope: scope.clone(),
                valid_until,
                presence_audience: presence_audience.map(String::from),
                keys,
                chain,
                ended: false,
            },
        );
        let mut extra = vec![("scope", json!(scope)), ("valid_until", json!(valid_until))];
        if let Some(a) = presence_audience {
            extra.push(("presence_audience", json!(a)));
        }
        if !kids.is_empty() {
            extra.push(("presence_keys", json!(kids)));
        }
        self.send(SendMsg {
            msg_type: "grant".into(),
            to: grantee.into(),
            session: Some(session.into()),
            id: Some(gid.into()),
            extra,
            ..Default::default()
        });
    }

    /// P§12.5 (spec-gap 161): grant `id` ends; the scopes it carried keys for become due, except those in `keep`. A
    /// grant ends once.
    fn end_grant(&mut self, id: &str, keep: &[String]) {
        let Some(g) = self.contacts.grants_issued.get_mut(id) else { return };
        if g.ended {
            return;
        }
        g.ended = true;
        let scopes = g.keys.clone();
        self.make_due(scopes.iter().filter(|s| !keep.contains(s)));
    }

    /// P§12.5: each scope rotates at once if never rotated or T-Presence-Rotate has passed since, else when it has; a
    /// scope already waiting keeps its time.
    fn make_due<'a>(&mut self, scopes: impl Iterator<Item = &'a String>) {
        let t_rotate = self.cfg.presence_keys.as_ref().map_or(T_PRESENCE_ROTATE.0, |pk| pk.t_rotate);
        for sc in scopes {
            if self.keys.due.contains_key(sc) {
                continue;
            }
            let at = match self.keys.last_rotated.get(sc) {
                Some(last) if self.now < last + t_rotate => last + t_rotate,
                _ => self.now,
            };
            self.keys.due.insert(sc.clone(), at);
        }
    }

    /// P§12.5: every scope due now rotates together (`main` first, then tags in order), then the live grants carrying
    /// any of them are re-granted.
    fn rotate_due(&mut self) {
        let mut scopes: Vec<String> = self.keys.due.iter().filter(|(_, t)| **t <= self.now).map(|(s, _)| s.clone()).collect();
        scopes.sort_by_key(|s| (s != MAIN, s.clone()));
        for sc in &scopes {
            self.keys.due.remove(sc);
            let e = self.keys.epochs.entry(sc.clone()).or_insert(0);
            *e += 1;
            let epoch = *e;
            self.keys.last_rotated.insert(sc.clone(), self.now);
            self.emit(Emission::Keys { action: KeysAction::Rotated, scope: sc.clone(), epoch });
        }
        self.regrant_carrying(&scopes);
    }

    /// P§12.5: a grant that follows each live grant carrying a key of `scopes`, with the same scope, `valid_until` and
    /// audience and the current keys. The followed grant heads the new one's chain and is not revoked (spec-gap 159).
    fn regrant_carrying(&mut self, scopes: &[String]) {
        if scopes.is_empty() {
            return;
        }
        let ids: Vec<String> = self
            .contacts
            .grants_issued
            .iter()
            .filter(|(_, g)| g.valid_until > self.now && g.keys.iter().any(|k| scopes.contains(k)))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let g = self.contacts.grants_issued.remove(&id).expect("listed above");
            let new = match self.grant_ids.pop_front() {
                Some(n) => n,
                None => self.mint.as_mut().map(|m| m()).expect("an id for a re-grant: PresenceKeysConfig::grant_ids or set_grant_ids"),
            };
            let chain = std::iter::once(id.clone()).chain(g.chain.iter().cloned()).collect();
            self.issue_grant_in_chain(&new, &g.identity, g.scope.clone(), g.valid_until, &id, g.presence_audience.as_deref(), chain);
        }
    }

    // ------------------------------------------------------------ local events

    fn local(&mut self, ev: &LocalEvent) {
        match ev {
            LocalEvent::PlaceCall { session, to } => {
                if self.sessions.contains_key(session) {
                    // spec-gap 90: a session id is used once (§12.9); a held session, live or ended, is never overwritten
                    self.emit(Emission::Refused(Refusal::InvalidState));
                    return;
                }
                let mut s = Session::new(session, Role::Initiator, SessionState::Inviting, to);
                s.invite_to = Some(to.clone());
                self.sessions.insert(session.clone(), s);
                // §19.4: the grantee MAY reference a held grant in a future invite to aid stateless relays
                let held = self.contacts.held_from(self.identity_of(to), self.now);
                self.send(SendMsg {
                    msg_type: "invite".into(),
                    to: to.clone(),
                    session: Some(session.clone()),
                    extra: held.map(|g| vec![("grant", json!(g))]).unwrap_or_default(),
                    ..Default::default()
                });
                let t = self.cfg.t_establish;
                self.start_timer(session, TimerName::Establish, t); // §12.9: started on sending invite
                return;
            }
            LocalEvent::Introduce { id, to, purpose, contact_token } => {
                // §19.4: media-less, session-less request for permission to contact
                self.contacts.pending_sent.insert(id.clone(), to.clone());
                let mut extra = vec![];
                if let Some(p) = purpose {
                    extra.push(("purpose", json!(p)));
                }
                if let Some(t) = contact_token {
                    extra.push(("contact_token", json!(t)));
                }
                self.send(SendMsg { msg_type: "introduction".into(), to: to.clone(), id: Some(id.clone()), extra, ..Default::default() });
                return;
            }
            LocalEvent::Grant { introduction, id, scope, valid_until, presence_audience } => {
                if !self.contacts.requests.contains_key(introduction) {
                    self.emit(Emission::Refused(Refusal::UnknownIntroduction));
                    return;
                }
                if presence_audience.as_deref().is_some_and(|a| !dsip_core::is_presence_audience(a)) {
                    // P§6: an audience is a token; nothing is sent and the request stays pending
                    self.emit(Emission::Refused(Refusal::InvalidAudience));
                    return;
                }
                let (identity, _) = self.contacts.requests.remove(introduction).expect("checked above");
                let scope = if scope.is_empty() { vec!["dsip.invite".to_string()] } else { scope.clone() };
                self.issue_grant(id, &identity, scope, *valid_until, introduction, presence_audience.as_deref());
                return;
            }
            LocalEvent::Regrant { grant, id, scope, valid_until, presence_audience } => {
                // §19.4 (spec-gap 150): a grant may follow a live grant we issued, without an introduction
                let Some(old) = self.contacts.grants_issued.get(grant).filter(|g| g.valid_until > self.now).cloned() else {
                    self.emit(Emission::Refused(Refusal::UnknownGrant));
                    return;
                };
                if presence_audience.as_deref().is_some_and(|a| !dsip_core::is_presence_audience(a)) {
                    self.emit(Emission::Refused(Refusal::InvalidAudience)); // P§6, as for a grant: the old grant is kept
                    return;
                }
                // P§7 (spec-gap 159): the followed grant and its rotation chain are revoked at the authority
                self.emit(Emission::Revoke(std::iter::once(grant.clone()).chain(old.chain.iter().cloned()).collect()));
                self.contacts.grants_issued.remove(grant); // issuing the new grant withdraws the one it follows
                let scope = if scope.is_empty() { vec!["dsip.invite".to_string()] } else { scope.clone() };
                self.issue_grant(id, &old.identity, scope, *valid_until, grant, presence_audience.as_deref());
                // P§12.5 (spec-gap 161): what the grantee keeps through the new grant is not rotated
                let kept = self.contacts.grants_issued.get(id).map(|g| g.keys.clone()).unwrap_or_default();
                if !old.ended {
                    self.make_due(old.keys.iter().filter(|s| !kept.contains(s)));
                }
                self.rotate_due();
                return;
            }
            LocalEvent::RegrantCard { grant, id } => {
                // §19.4 (spec-gap 192): a grant that follows a live grant we issued only to carry a changed profile
                // card permits what the followed grant did
                let Some(old) = self.contacts.grants_issued.get(grant).filter(|g| g.valid_until > self.now).cloned() else {
                    self.emit(Emission::Refused(Refusal::UnknownGrant));
                    return;
                };
                // so the followed grant is not revoked at the authority (a revocation would end the subscription it
                // admitted, P§7); withdrawn here, it heads the new grant's chain, as in a rotation (spec-gap 159)
                self.contacts.grants_issued.remove(grant);
                let chain = std::iter::once(grant.clone()).chain(old.chain.iter().cloned()).collect();
                self.issue_grant_in_chain(id, &old.identity, old.scope.clone(), old.valid_until, grant, old.presence_audience.as_deref(), chain);
                return;
            }
            LocalEvent::RejectIntroduction { introduction, reason } => {
                let Some((identity, _)) = self.contacts.requests.remove(introduction) else {
                    self.emit(Emission::Refused(Refusal::UnknownIntroduction));
                    return;
                };
                // §19.4 outcome 2: reject naming the introduction id; a policy choice, not an obligation.
                // spec-gap 74: like a grant, it is addressed to the introducing identity.
                self.send_simple("reject", &identity, introduction, Some(reason.as_deref().unwrap_or("user.declined")));
                return;
            }
            LocalEvent::Revoke { grant } => {
                let Some(g) = self.contacts.grants_issued.remove(grant) else {
                    self.emit(Emission::Refused(Refusal::UnknownGrant));
                    return;
                };
                // P§7 (spec-gap 159): with its rotation chain
                self.emit(Emission::Revoke(std::iter::once(grant.clone()).chain(g.chain.iter().cloned()).collect()));
                if !g.ended {
                    self.make_due(g.keys.iter());
                }
                self.rotate_due();
                return;
            }
            LocalEvent::IssueToken { token, grant_id } => {
                self.contacts.tokens.insert(token.clone(), grant_id.clone());
                return;
            }
            _ => {}
        }
        let Some(s) = self.sessions.get(ev.session()).cloned() else {
            self.emit(Emission::Refused(Refusal::UnknownSession));
            return;
        };
        let sid = s.id.clone();
        match ev {
            LocalEvent::PlaceCall { .. }
            | LocalEvent::Introduce { .. }
            | LocalEvent::Grant { .. }
            | LocalEvent::Regrant { .. }
            | LocalEvent::RegrantCard { .. }
            | LocalEvent::RejectIntroduction { .. }
            | LocalEvent::Revoke { .. }
            // handled before the session lookup, which returned for each of them
            | LocalEvent::IssueToken { .. } => self.emit(Emission::Refused(Refusal::InvalidState)),
            LocalEvent::Cancel { .. } => {
                if s.role == Role::Initiator && matches!(s.state, SessionState::Inviting | SessionState::Proceeding) {
                    self.stop_all(&sid);
                    self.send_simple("cancel", s.invite_to.as_deref().unwrap_or(""), &sid, Some("user.cancelled"));
                    let m = self.sessions.get_mut(&sid).expect("exists");
                    m.cancelled = true;
                    m.state = SessionState::Ended;
                } else {
                    self.emit(Emission::Refused(Refusal::InvalidState));
                }
            }
            LocalEvent::Hangup { reason, .. } => {
                if s.state == SessionState::Active {
                    // Impl (spec-gap 13): ENDING collapsed into ENDED
                    self.stop_all(&sid);
                    self.sessions.get_mut(&sid).expect("exists").outstanding = None;
                    let reason = reason.as_deref().unwrap_or("user.hangup");
                    self.send_simple("bye", &s.peer, &sid, Some(reason));
                    self.emit(Emission::Media(MediaCommand::Stop));
                    self.sessions.get_mut(&sid).expect("exists").state = SessionState::Ended;
                } else {
                    self.emit(Emission::Refused(Refusal::InvalidState));
                }
            }
            LocalEvent::Alert { ring_timeout, .. } => {
                if s.role == Role::Responder && s.state == SessionState::Offered {
                    if self.now >= s.invite_expires_at.unwrap_or(i64::MAX) {
                        // §12.4/§12.9: the invite expired (from expires_at, spec-gap 141) before alerting began
                        self.send_simple("reject", &s.peer, &sid, Some("session.expired"));
                        self.end(&sid, None, false);
                        return;
                    }
                    self.send(SendMsg {
                        msg_type: "progress".into(),
                        to: s.peer.clone(),
                        session: Some(sid.clone()),
                        status: Some("ringing".into()),
                        ring_timeout: *ring_timeout,
                        ..Default::default()
                    });
                    self.sessions.get_mut(&sid).expect("exists").state = SessionState::Alerting;
                    // §12.9: T-Ring-Local SHOULD be ≤ the advertised ring_timeout
                    let secs = ring_timeout.map(|r| clamp(r, T_RING_LOCAL)).unwrap_or(self.cfg.t_ring_local);
                    self.start_timer(&sid, TimerName::RingLocal, secs);
                } else {
                    self.emit(Emission::Refused(Refusal::InvalidState));
                }
            }
            LocalEvent::AutoReject { reason, .. } => {
                if s.role == Role::Responder && s.state == SessionState::Offered {
                    self.send_simple("reject", &s.peer, &sid, Some(reason));
                    self.end(&sid, None, false);
                } else {
                    self.emit(Emission::Refused(Refusal::InvalidState));
                }
            }
            LocalEvent::Accept { answered_by, .. } => {
                if s.role == Role::Responder && s.state == SessionState::Alerting {
                    self.stop_all(&sid);
                    self.send(SendMsg {
                        msg_type: "answer".into(),
                        to: s.peer.clone(),
                        session: Some(sid.clone()),
                        answered_by: Some(answered_by.clone().unwrap_or_else(|| "user".into())),
                        ..Default::default()
                    });
                    let m = self.sessions.get_mut(&sid).expect("exists");
                    m.state = SessionState::Active;
                    m.was_active = true;
                    self.emit(Emission::Media(MediaCommand::Start));
                } else {
                    self.emit(Emission::Refused(Refusal::InvalidState));
                }
            }
            LocalEvent::Decline { reason, .. } => {
                if s.role == Role::Responder && s.state == SessionState::Alerting {
                    self.stop_all(&sid);
                    self.send_simple("reject", &s.peer, &sid, Some(reason.as_deref().unwrap_or("user.declined")));
                    self.end(&sid, None, false);
                } else {
                    self.emit(Emission::Refused(Refusal::InvalidState));
                }
            }
            LocalEvent::Update { id, answered_by, validity, .. } => {
                if s.state != SessionState::Active {
                    self.emit(Emission::Refused(Refusal::InvalidState));
                } else if s.outstanding.is_some() {
                    self.emit(Emission::Refused(Refusal::UpdatePending)); // §12.8 rule 2: one outstanding, both directions
                } else {
                    self.send(SendMsg {
                        msg_type: "update".into(),
                        to: s.peer.clone(),
                        session: Some(sid.clone()),
                        id: Some(id.clone()),
                        answered_by: answered_by.clone(),
                        ..Default::default()
                    });
                    let s = self.sessions.get_mut(&sid).expect("exists");
                    s.outstanding = Some(Outstanding { id: id.clone(), direction: Direction::Outbound });
                    // §12.9: the update's validity, 30 s unless the host names one
                    s.update_expires_at = self.now + validity.unwrap_or(UPDATE_VALIDITY_S);
                }
            }
            LocalEvent::AnswerUpdate { in_reply_to, .. } | LocalEvent::RejectUpdate { in_reply_to, .. } => {
                let pending_inbound = s.state == SessionState::Active
                    && matches!(&s.outstanding, Some(o) if o.direction == Direction::Inbound && &o.id == in_reply_to);
                if !pending_inbound {
                    self.emit(Emission::Refused(Refusal::NoPendingUpdate));
                    return;
                }
                match ev {
                    LocalEvent::AnswerUpdate { answered_by, .. } => {
                        self.send(SendMsg {
                            msg_type: "answer".into(),
                            to: s.peer.clone(),
                            session: Some(sid.clone()),
                            answered_by: Some(answered_by.clone().unwrap_or_else(|| "user".into())),
                            in_reply_to: Some(in_reply_to.clone()),
                            ..Default::default()
                        });
                        self.emit(Emission::Media(MediaCommand::ApplyUpdate));
                    }
                    LocalEvent::RejectUpdate { reason, .. } => {
                        self.send(SendMsg {
                            msg_type: "reject".into(),
                            to: s.peer.clone(),
                            session: Some(sid.clone()),
                            reason: Some(reason.clone()),
                            in_reply_to: Some(in_reply_to.clone()),
                            ..Default::default()
                        });
                    }
                    // the outer arm admits only these two
                    _ => {
                        self.emit(Emission::Refused(Refusal::InvalidState));
                        return;
                    }
                }
                self.sessions.get_mut(&sid).expect("exists").outstanding = None;
            }
            LocalEvent::Info { .. } => {
                if s.state == SessionState::Active {
                    self.send_simple("info", &s.peer, &sid, None);
                } else {
                    self.emit(Emission::Refused(Refusal::InvalidState));
                }
            }
        }
    }

    // ------------------------------------------------------------ received messages

    fn recv(&mut self, m: &Message) {
        let t = m.msg_type.as_str();
        if t == "invite" {
            return self.recv_invite(m);
        }
        if t == "error" {
            let r = m.reason.clone().unwrap_or_default();
            // §12.7 rule 6 (spec-gap 76): the relay's own `transport.no-response` is the attempt outcome when
            // every leg stayed silent; no cancel follows — the relay has closed every leg
            let attempt = m.session.as_ref().filter(|sid| {
                self.sessions.get(*sid).is_some_and(|s| {
                    s.role == Role::Initiator && matches!(s.state, SessionState::Inviting | SessionState::Proceeding)
                })
            });
            if let (true, Some(sid)) = (r == "transport.no-response", attempt) {
                let sid = sid.clone();
                self.end(&sid, Some("transport.no-response"), false);
                return;
            }
            self.ui(UiEvent::Error { reason: r.clone() });
            return;
        }
        if t == "introduction" {
            return self.recv_introduction(m);
        }
        if t == "grant" {
            return self.recv_grant(m);
        }
        if t == "presence" {
            return self.recv_own_record(m);
        }
        if t == "reject" && m.session.as_ref().is_some_and(|sid| self.contacts.pending_sent.contains_key(sid)) {
            // §19.4 outcome 2: rejection addressed to the introduction id
            self.contacts.pending_sent.remove(m.session.as_deref().unwrap_or(""));
            let reason = resolve_reason(m.reason.as_deref().unwrap_or(""), "reject").effective;
            self.ui(UiEvent::IntroductionRejected { reason: reason.clone() });
            return;
        }
        let Some(s) = m.session.as_ref().and_then(|sid| self.sessions.get(sid)).cloned() else {
            self.error(m, "session.unknown-session"); // §12.2
            return;
        };
        if s.state == SessionState::Ended {
            if t == "answer" && s.role == Role::Initiator && m.in_reply_to.is_none() {
                // §12.5 rule 3 / §12.7 rule 4: late answers to a finished attempt
                let reason = if s.cancelled {
                    "session.cancelled"
                } else if s.was_active {
                    "session.already-answered"
                } else {
                    "session.failed" // Impl (spec-gap 12)
                };
                self.send_simple("bye", &m.from, &s.id, Some(reason));
            } else {
                self.emit(Emission::Drop(DropReason::EndedSession));
            }
            return;
        }
        if s.role == Role::Responder && s.state == SessionState::Active && t != "cancel" {
            self.sessions.get_mut(&s.id).expect("exists").post_answer_seen = true;
        }
        match t {
            "progress" => self.recv_progress(&s, m),
            "answer" => self.recv_answer(&s, m),
            "reject" => self.recv_reject(&s, m),
            "cancel" => self.recv_cancel(&s, m),
            "update" => self.recv_update(&s, m),
            "info" => self.recv_info(&s, m),
            "bye" => self.recv_bye(&s, m),
            _ => self.error(m, "session.invalid-state"),
        }
    }

    fn recv_introduction(&mut self, m: &Message) {
        if !self.contacts.seen_introductions.insert(m.id.clone()) {
            self.emit(Emission::Drop(DropReason::DuplicateIntroduction));
            return;
        }
        let identity = self.identity_of(&m.from).to_string();
        if let Some(gid) = m.contact_token.as_ref().and_then(|t| self.contacts.tokens.remove(t)) {
            // §19.4: a valid out-of-band contact token MAY be auto-granted per recipient policy (single use)
            self.ui(UiEvent::IntroductionReceived { from: identity.clone(), token: true });
            let until = self.now + 31_536_000;
            self.issue_grant(&gid, &identity, vec!["dsip.invite".into()], until, &m.id, None);
            return;
        }
        // §19.4 UX requirement: a distinct requests surface — never a ring, never call history
        self.contacts.requests.insert(m.id.clone(), (identity.clone(), m.from.clone()));
        self.ui(UiEvent::IntroductionReceived { from: identity.clone(), token: false });
    }

    fn recv_grant(&mut self, m: &Message) {
        let by = self.identity_of(&m.from).to_string();
        let session = m.session.clone().unwrap_or_default();
        let follows = self.contacts.grants_held.get(&session).is_some_and(|g| g.identity == by && g.valid_until > self.now);
        if self.contacts.pending_sent.remove(&session).is_none() {
            if !follows {
                self.emit(Emission::Drop(DropReason::UnknownIntroduction));
                return;
            }
            // §19.4 (spec-gap 150): it follows a live grant we hold from the same identity, and replaces it
            self.contacts.grants_held.remove(&session);
        }
        self.contacts.grants_held.insert(
            m.id.clone(),
            Grant { identity: by.clone(), scope: m.scope.clone().unwrap_or_default(), valid_until: m.valid_until.unwrap_or(0), ..Default::default() },
        );
        // P§12.4: per scope, the keys of the two highest epochs
        for (scope, epoch) in m.presence_keys.iter().flatten().filter_map(|k| split_kid(k)) {
            let epochs = self.keys.held.entry(by.clone()).or_default().entry(scope.into()).or_default();
            epochs.insert(epoch);
            while epochs.len() > 2 {
                epochs.pop_first();
            }
        }
        self.ui(UiEvent::Granted { by: by.clone() });
    }

    /// P§12.5: a record of our own identity from a sibling, seen through our own watch. A higher epoch is adopted and
    /// our live grants carrying that scope are re-granted; anything else is ignored.
    fn recv_own_record(&mut self, m: &Message) {
        if self.cfg.presence_keys.is_none() || m.subject.as_deref() != Some(self.cfg.identity.as_str()) {
            return;
        }
        let Some((scope, epoch)) = m.kid.as_deref().and_then(split_kid) else { return };
        if self.keys.epochs.get(scope).is_some_and(|e| epoch <= *e) {
            return;
        }
        self.keys.epochs.insert(scope.into(), epoch);
        self.emit(Emission::Keys { action: KeysAction::Seen, scope: scope.into(), epoch });
        self.regrant_carrying(&[scope.to_string()]);
    }

    fn recv_invite(&mut self, m: &Message) {
        let sid = m.id.clone();
        let from_identity = self.identity_of(&m.from).to_string();
        if self.cfg.first_contact_required
            && !self.contacts.allow.contains(&from_identity)
            && !self.contacts.admits(&from_identity, self.now)
        {
            // §19.4: an invite from an identity holding no grant (and matching no allow policy) is rejected with
            // policy.first-contact-required. §12.4 responder: "Policy: auto-reject → send reject → ENDED" — no alerting.
            self.send_simple("reject", &m.from, &sid, Some("policy.first-contact-required"));
            self.sessions.insert(sid.clone(), Session::new(&sid, Role::Responder, SessionState::Ended, &m.from));
            return;
        }
        // §12.6 glare: an outbound invite to the identity this invite comes from
        // Every live attempt of ours to that identity is a rival; the smallest id of all the invites wins.
        let mut rivals: Vec<Session> = self
            .sessions
            .values()
            .filter(|s| {
                s.role == Role::Initiator
                    && matches!(s.state, SessionState::Inviting | SessionState::Proceeding)
                    && self.identity_of(s.invite_to.as_deref().unwrap_or("")) == from_identity
            })
            .cloned()
            .collect();
        rivals.sort_by(|a, b| a.id.cmp(&b.id));
        if rivals.is_empty() {
            if let Some(existing) = self.sessions.get(&sid) {
                if existing.state == SessionState::Ended {
                    self.emit(Emission::Drop(DropReason::EndedSession));
                } else {
                    let probe = Message { session: Some(sid.clone()), ..m.clone() };
                    self.error(&probe, "session.invalid-state");
                }
                return;
            }
        }
        if let Some(first) = rivals.first().map(|g| g.id.clone()) {
            if first < sid {
                // We win: reject the inbound losing invite; proceed as initiator.
                self.send_simple("reject", &m.from, &sid, Some("session.glare"));
                self.sessions.insert(sid.clone(), Session::new(&sid, Role::Responder, SessionState::Ended, &m.from));
                return;
            }
            // We lose (or pathological equal id): each of our invites lost, so each is withdrawn, in id order.
            // Impl (spec-gap 2): the loser withdraws via `cancel session.glare`.
            for g in &rivals {
                self.stop_all(&g.id);
                self.send_simple("cancel", g.invite_to.as_deref().unwrap_or(""), &g.id, Some("session.glare"));
                let gm = self.sessions.get_mut(&g.id).expect("exists");
                gm.cancelled = true;
                gm.state = SessionState::Ended;
                self.ui(UiEvent::Ended { reason: "session.glare".into() });
            }
            if first == sid {
                // §12.6: equal ids — both invites rejected; MAY retry after 1–4 s
                self.send_simple("reject", &m.from, &sid, Some("session.glare"));
                self.ui(UiEvent::GlareRetry);
                return;
            }
        }
        let mut s = Session::new(&sid, Role::Responder, SessionState::Offered, &m.from);
        s.invite_to = m.to.clone();
        s.invite_expires_at = m.expires_at;
        self.sessions.insert(sid, s);
        self.ui(UiEvent::Offered);
    }

    fn recv_progress(&mut self, s: &Session, m: &Message) {
        if s.role != Role::Initiator || !matches!(s.state, SessionState::Inviting | SessionState::Proceeding) {
            return self.error(m, "session.invalid-state");
        }
        let sid = s.id.clone();
        let status = effective_progress_status(m.status.as_deref().unwrap_or("")).to_string();
        self.stop_timer(&sid, TimerName::Establish); // §12.9: stopped by first progress
        self.sessions.get_mut(&sid).expect("exists").state = SessionState::Proceeding;
        self.ui(UiEvent::Progress { status: status.clone() });
        match status.as_str() {
            "ringing" => {
                self.sessions.get_mut(&sid).expect("exists").queue_count = 0;
                self.stop_timer(&sid, TimerName::Queue); // §12.10: subsequent ringing cancels T-Queue
                if let Some(rt) = m.ring_timeout {
                    // §12.9: responder MAY extend via ring_timeout; honored up to the upper bound.
                    // Impl (spec-gap 4): a ringing progress carrying ring_timeout (re)starts T-Ring.
                    self.start_timer(&sid, TimerName::Ring, clamp(rt, T_RING));
                } else if !self.running(&sid, TimerName::Ring) {
                    let t = self.cfg.t_ring;
                    self.start_timer(&sid, TimerName::Ring, t);
                }
            }
            "queued" => {
                let sm = self.sessions.get_mut(&sid).expect("exists");
                sm.queue_count += 1;
                if sm.queue_count > MAX_CONSECUTIVE_REQUEUES {
                    // Impl (spec-gap 11): exceeding the re-queue limit is treated as T-Queue expiry.
                    self.stop_all(&sid);
                    self.send_simple("cancel", s.invite_to.as_deref().unwrap_or(""), &sid, Some("session.timeout"));
                    self.sessions.get_mut(&sid).expect("exists").cancelled = true;
                    self.end(&sid, Some("session.timeout"), false);
                    return;
                }
                self.stop_timer(&sid, TimerName::Ring); // §12.10: queued suspends T-Ring
                self.start_timer(&sid, TimerName::Queue, m.queue_timeout.unwrap_or(T_QUEUE_CAP).min(T_QUEUE_CAP));
            }
            _ => {
                // Impl (spec-gap 4): trying/forwarded start T-Ring as the backstop.
                if !self.running(&sid, TimerName::Ring) && !self.running(&sid, TimerName::Queue) {
                    let t = self.cfg.t_ring;
                    self.start_timer(&sid, TimerName::Ring, t);
                }
            }
        }
    }

    fn recv_answer(&mut self, s: &Session, m: &Message) {
        let sid = s.id.clone();
        if s.role != Role::Initiator && !(s.state == SessionState::Active && m.in_reply_to.is_some()) {
            // Responders only ever receive answers to their own updates (§12.8 rule 1)
            return self.error(m, "session.invalid-state");
        }
        match s.state {
            SessionState::Inviting | SessionState::Proceeding => {
                if m.in_reply_to.is_some() {
                    return self.error(m, "session.invalid-state");
                }
                // §12.7 rule 2: first accepted answer establishes the session
                self.stop_all(&sid);
                {
                    let sm = self.sessions.get_mut(&sid).expect("exists");
                    sm.state = SessionState::Active;
                    sm.was_active = true;
                    sm.answered_device = Some(m.from.clone());
                    sm.peer = m.from.clone();
                }
                self.emit(Emission::Media(MediaCommand::Start));
                let ab = effective_answered_by(m.answered_by.as_deref().unwrap_or("")).to_string();
                self.ui(UiEvent::Answered { answered_by: ab.clone() });
                if s.invite_to.as_deref() != Some(m.from.as_str()) {
                    // §12.4/§12.7 rule 3; Impl (spec-gap 5): forked inferred from answer.from ≠ invite.to
                    self.send_simple("cancel", s.invite_to.as_deref().unwrap_or(""), &sid, Some("session.answered-elsewhere"));
                }
            }
            SessionState::Active => {
                if let Some(irt) = &m.in_reply_to {
                    if matches!(&s.outstanding, Some(o) if o.direction == Direction::Outbound && &o.id == irt) {
                        self.sessions.get_mut(&sid).expect("exists").outstanding = None;
                        self.emit(Emission::Media(MediaCommand::ApplyUpdate));
                    } else {
                        self.emit(Emission::Drop(DropReason::StaleUpdateReply));
                    }
                } else if s.answered_device.as_deref() != Some(m.from.as_str()) {
                    // §12.7 rule 4: later answer from another leg
                    self.send_simple("bye", &m.from, &sid, Some("session.already-answered"));
                } else {
                    self.error(m, "session.invalid-state");
                }
            }
            _ => self.error(m, "session.invalid-state"),
        }
    }

    fn recv_reject(&mut self, s: &Session, m: &Message) {
        let sid = s.id.clone();
        let reason = resolve_reason(m.reason.as_deref().unwrap_or(""), "reject").effective;
        if s.role == Role::Initiator
            && matches!(s.state, SessionState::Inviting | SessionState::Proceeding)
            && m.in_reply_to.is_none()
        {
            self.end(&sid, Some(&reason), false);
            return;
        }
        if s.state == SessionState::Active {
            if let Some(irt) = &m.in_reply_to {
                if matches!(&s.outstanding, Some(o) if o.direction == Direction::Outbound && &o.id == irt) {
                    // §12.8 rule 5: rejected update leaves the session in its prior state
                    self.sessions.get_mut(&sid).expect("exists").outstanding = None;
                    self.ui(UiEvent::UpdateRejected { reason: reason.clone() });
                } else {
                    self.emit(Emission::Drop(DropReason::StaleUpdateReply));
                }
                return;
            }
        }
        self.error(m, "session.invalid-state");
    }

    fn recv_cancel(&mut self, s: &Session, m: &Message) {
        let sid = s.id.clone();
        let reason = resolve_reason(m.reason.as_deref().unwrap_or(""), "cancel").effective;
        if s.role != Role::Responder {
            return self.error(m, "session.invalid-state");
        }
        match s.state {
            SessionState::Offered => self.end(&sid, Some(&reason), false),
            SessionState::Alerting => {
                self.stop_all(&sid);
                if reason != "session.answered-elsewhere" {
                    // §12.4/§12.11: answered-elsewhere MUST NOT surface as a missed call
                    self.ui(UiEvent::MissedCall);
                }
                self.end(&sid, Some(&reason), false);
            }
            SessionState::Active => {
                if reason != "session.answered-elsewhere" && !s.post_answer_seen {
                    // §12.5 rule 2: crossed cancel — teardown, no error. Impl (spec-gap 1): only a
                    // withdrawal of intent can be "crossed"; answered-elsewhere at the answering leg is misrouted.
                    self.end(&sid, Some(&reason), true);
                } else {
                    // §12.4/§12.11: cancel for an ACTIVE session
                    self.error(m, "session.invalid-state");
                }
            }
            _ => self.error(m, "session.invalid-state"),
        }
    }

    fn recv_update(&mut self, s: &Session, m: &Message) {
        let sid = s.id.clone();
        if s.state != SessionState::Active {
            return self.error(m, "session.invalid-state");
        }
        if let Some(o) = &s.outstanding {
            match o.direction {
                Direction::Outbound => {
                    // §12.8 rule 3: update glare → smaller id proceeds
                    if o.id < m.id {
                        self.send(SendMsg {
                            msg_type: "reject".into(),
                            to: m.from.clone(),
                            session: Some(sid),
                            reason: Some("session.glare".into()),
                            in_reply_to: Some(m.id.clone()),
                            ..Default::default()
                        });
                        return;
                    }
                    self.ui(UiEvent::UpdateRejected { reason: "session.glare".into() });
                    self.sessions.get_mut(&sid).expect("exists").outstanding = None;
                }
                Direction::Inbound => {
                    // §12.8 rule 4; Impl (spec-gap 3): both discarded
                    self.sessions.get_mut(&sid).expect("exists").outstanding = None;
                    self.error(m, "session.update-pending");
                    return;
                }
            }
        }
        let now = self.now;
        let s = self.sessions.get_mut(&sid).expect("exists");
        s.outstanding = Some(Outstanding { id: m.id.clone(), direction: Direction::Inbound });
        // Impl: a trace's `update` may leave `expires_at` out; it is then 30 s after its receipt (vectors README).
        s.update_expires_at = m.expires_at.unwrap_or(now + UPDATE_VALIDITY_S);
        self.ui(UiEvent::UpdateOffered);
        if let Some(ab) = &m.answered_by {
            // §14.4 step 3: escalation signal
            let ab = effective_answered_by(ab).to_string();
            self.ui(UiEvent::Answered { answered_by: ab.clone() });
        }
    }

    fn recv_info(&mut self, s: &Session, m: &Message) {
        if s.state != SessionState::Active {
            return self.error(m, "session.invalid-state"); // §12.12: ACTIVE-only
        }
        match m.about.as_deref() {
            Some(a) if INFO_ABOUT.contains(&a) => self.emit(Emission::Info { about: a.to_string() }),
            _ => self.emit(Emission::Drop(DropReason::UnknownAbout)), // §12.12: never critical
        }
    }

    fn recv_bye(&mut self, s: &Session, m: &Message) {
        if s.state != SessionState::Active {
            return self.error(m, "session.invalid-state");
        }
        let reason = resolve_reason(m.reason.as_deref().unwrap_or(""), "bye").effective;
        self.end(&s.id.clone(), Some(&reason), true);
    }
}
