//! Forking relay: per-leg attempt tracking and attempt-outcome signaling.
//!
//! Spec: §12.7 rule 3 (track delivered legs; deliver `cancel` per-leg to every
//! leg that has not terminated), rule 4 (an `answer` is never withheld: the
//! initiator alone ends an answered leg) and rule 6 (when the final outstanding
//! leg terminates without an answer, forward the most informative `reject`:
//! `user.declined` > `user.no-answer` > `endpoint.busy` > `endpoint.unavailable`).
//!
//! This is the data model `dsip-relay` uses; it has no I/O so the vector
//! suite can drive it directly.
//!
//! §13.3 (v0.16, spec-gap 131): what the relay stops holding, so its memory follows live traffic rather than every call
//! and device it has ever seen — see [`Relay::forget`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::event::{DequeueReason, DropReason, Emission};
use crate::message::Message;

/// §12.7 rule 6 preference order. Other tokens rank after these, first-seen first.
pub const REASON_RANK: &[&str] = &["user.declined", "user.no-answer", "endpoint.busy", "endpoint.unavailable"];

/// Per-leg state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs)]
pub enum LegState {
    Delivered,
    Answered,
    Rejected,
    Expired,
    Cancelled,
}

impl LegState {
    fn terminated(self) -> bool {
        self != LegState::Delivered
    }
}

/// One forked invite attempt.
#[derive(Debug, Clone)]
pub struct Attempt {
    /// Session id.
    pub session: String,
    /// Initiator device DID.
    pub initiator: String,
    /// Addressed identity.
    pub identity: String,
    /// Leg → state (ordered for deterministic output).
    pub legs: BTreeMap<String, LegState>,
    /// Leg → reject reason (insertion order matters for ties).
    pub reasons: Vec<(String, String)>,
    /// `None` | `answered` | `rejected` | `cancelled`.
    pub outcome: Option<&'static str>,
    /// When the relay last forked, flushed or added a leg for it, or received one of its messages from a leg or the
    /// initiator (spec-gap 131: [`Relay::forget`]).
    pub last: i64,
    /// Legs that have sent `progress`, `answer` or `reject` (spec-gap 132: only a silent leg expires with the invite).
    pub heard: std::collections::BTreeSet<String>,
}

impl Attempt {
    /// README snapshot shape.
    pub fn snapshot(&self) -> Value {
        json!({ "legs": self.legs, "outcome": self.outcome })
    }
}

/// Relay-side events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)] // an event is built once and consumed at once; boxing the message would cost an allocation per event
pub enum RelayEvent {
    /// Clock advance (no relay timers in this model; kept for trace symmetry).
    Advance {
        /// Seconds.
        advance: i64,
    },
    /// A message from a leg or the initiator.
    Recv {
        /// The message.
        recv: Message,
    },
    /// A relay-internal action.
    Relay(RelayAction),
}

/// Relay-internal actions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "relay", rename_all = "snake_case")]
pub enum RelayAction {
    /// Fork an invite to the listed device legs.
    Invite {
        /// Session id.
        session: String,
        /// Initiator device.
        from: String,
        /// Addressed identity.
        to: String,
        /// Device legs.
        legs: Vec<String>,
    },
    /// The relay's own delivery expiry for a leg.
    LegExpired {
        /// Session id.
        session: String,
        /// Leg device.
        leg: String,
    },
    /// A device bound via `hello` (§13.2); flushes queued introductions for the identity.
    Bind {
        /// Device DID.
        device: String,
        /// Identity DID.
        identity: String,
    },
    /// A device unbound.
    Unbind {
        /// Device DID.
        device: String,
        /// Identity DID.
        identity: String,
    },
}

/// The relay's attempt tracker.
pub struct Relay {
    /// Clock.
    pub now: i64,
    attempts: BTreeMap<String, Attempt>,
    out: Vec<Emission>,
    /// identity → bound devices (§13.2). A key, even with an empty set, marks a *known* identity.
    pub bindings: BTreeMap<String, std::collections::BTreeSet<String>>,
    /// device → identity for every device bound here and not yet forgotten (spec-gap 131).
    pub devices: BTreeMap<String, String>,
    /// recipient → queued envelopes with deadlines (§13.3 store-and-forward; §19.4 introductions).
    pub inbox: BTreeMap<String, Vec<Queued>>,
    /// Envelopes queued so far: each queued one takes the next number (spec-gap 98).
    pub arrivals: u64,
    /// Maximum seconds an envelope is held (`offline_retention_s`).
    pub retention: i64,
    /// session → invite (for legs added mid-attempt, §12.7 rule 3).
    invites: BTreeMap<String, Message>,
    /// identity or device with nothing bound → when its last binding ended (spec-gap 131).
    last_bound: BTreeMap<String, i64>,
}

/// A queued envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Queued {
    /// The message.
    pub message: Message,
    /// Drop at this time.
    pub deadline: i64,
    /// Arrival order across every queue of this relay: a flush delivers in it (spec-gap 98).
    pub arrival: u64,
}

/// A recipient the relay knows (§13.3), as kept across a restart: an identity, or a device and its identity.
///
/// Spec: §13.3 (a recipient is known while bound, and within the retention window after its last binding ends;
/// spec-gap 131).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Known {
    /// The identity or device DID.
    pub who: String,
    /// For a device, the identity it was bound for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// When its last binding ended; `None` while one is bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_bound: Option<i64>,
}

impl Relay {
    /// Create a relay tracker.
    pub fn new(start: i64) -> Relay {
        Relay::with_retention(start, 86_400)
    }

    /// Create a relay tracker with an explicit retention cap (seconds).
    pub fn with_retention(start: i64, retention: i64) -> Relay {
        Relay {
            now: start,
            attempts: BTreeMap::new(),
            out: vec![],
            bindings: BTreeMap::new(),
            devices: BTreeMap::new(),
            inbox: BTreeMap::new(),
            arrivals: 0,
            retention,
            invites: BTreeMap::new(),
            last_bound: BTreeMap::new(),
        }
    }

    /// Spec: §13.3 — a recipient is known while a device is bound for it here, and until [`Relay::forget`] drops it
    /// (v0.16, spec-gap 131: the window runs from the end of its last binding).
    pub fn known(&self, to: &str) -> bool {
        self.bindings.contains_key(to) || self.devices.contains_key(to)
    }

    /// Expire the legs that have sent nothing — no `progress`, `answer` or `reject` — once the invite has expired
    /// (from `expires_at`, spec-gap 141), and complete the attempt when that leaves no leg outstanding.
    ///
    /// Spec: §12.7 rules 3 and 6 (a leg terminates by answering, rejecting or expiring; the relay signals the
    /// outcome, `transport.no-response` when every leg expired), §12.9 (expired from `expires_at`, spec-gap 141; T-Ring-Local).
    /// §12.7 rule 3 (v0.16, spec-gap 132): a responder acts only on an unexpired invite and acts at once, so a leg still silent past
    /// the invite's expiry never processed it; a leg that rang ends itself with `reject user.no-answer` at
    /// T-Ring-Local. Attempts in id order, legs in device order (spec-gap 89). An attempt with no invite on record
    /// (forked by a `RelayAction::Invite` alone) is expired only by `RelayAction::LegExpired`.
    pub fn expire_silent_legs(&mut self) {
        let now = self.now;
        let sids: Vec<String> = self.attempts.keys().cloned().collect();
        for sid in sids {
            if !self.invites.get(&sid).and_then(|inv| inv.expires_at).is_some_and(|e| e <= now) {
                continue;
            }
            let att = self.attempts.get_mut(&sid).expect("listed");
            let silent: Vec<String> = att
                .legs
                .iter()
                .filter(|(l, st)| **st == LegState::Delivered && !att.heard.contains(*l))
                .map(|(l, _)| l.clone())
                .collect();
            for leg in &silent {
                att.legs.insert(leg.clone(), LegState::Expired);
            }
            if !silent.is_empty() {
                self.check_complete(&sid);
            }
        }
    }

    /// What the relay stops holding, on every clock advance. Nothing is emitted.
    ///
    /// Spec: §13.3 (known = bound "within the relay's retention window"; a relay holding no attempt for a session
    /// routes its traffic by `to`, spec-gap 82), §12.9/§12.10 (the T-Queue hard cap). §13.3 (v0.16, spec-gap 131): an attempt
    /// and its invite once more than [`crate::endpoint::T_QUEUE_CAP`] has passed since [`Attempt::last`] — every pre-answer wait in
    /// the core ends within that of the last `progress`, so nothing still expected needs the record; an identity or
    /// device with nothing bound and nothing held, once its last binding ended more than `retention`
    /// (`offline_retention_s`) ago.
    pub fn forget(&mut self) {
        let now = self.now;
        let done: Vec<String> = self.attempts.iter().filter(|(_, a)| a.last + crate::endpoint::T_QUEUE_CAP < now).map(|(sid, _)| sid.clone()).collect();
        for sid in done {
            self.invites.remove(&sid);
            self.attempts.remove(&sid);
        }
        let gone: Vec<String> = self
            .last_bound
            .iter()
            .filter(|(who, t)| **t + self.retention < now && !self.inbox.contains_key(*who))
            .map(|(who, _)| who.clone())
            .collect();
        for who in gone {
            self.last_bound.remove(&who);
            if let Some(identity) = self.devices.get(&who).cloned() {
                if !self.bindings.get(&identity).is_some_and(|b| b.contains(&who)) {
                    self.devices.remove(&who);
                }
            } else if self.bindings.get(&who).is_none_or(|b| b.is_empty()) {
                self.bindings.remove(&who);
            }
        }
    }

    fn enqueue(&mut self, m: &Message) {
        let to = m.to.clone().unwrap_or_default();
        let deadline = m.expires_at.unwrap_or(self.now + self.retention).min(self.now + self.retention);
        self.arrivals += 1;
        let arrival = self.arrivals;
        self.inbox.entry(to.clone()).or_default().push(Queued { message: m.clone(), deadline, arrival });
        self.out.push(Emission::Queue { to, msg_type: m.msg_type.clone() });
    }

    fn flush_to(&mut self, device: &str, m: Message) {
        if m.msg_type == "invite" {
            // A queued invite becomes a tracked leg on delivery (§12.7 rule 3)
            let sid = m.id.clone();
            let att = self.attempts.entry(sid.clone()).or_insert_with(|| Attempt {
                session: sid.clone(),
                initiator: m.from.clone(),
                identity: m.to.clone().unwrap_or_default(),
                legs: BTreeMap::new(),
                reasons: vec![],
                outcome: None,
                last: self.now,
                heard: Default::default(),
            });
            att.legs.insert(device.to_string(), LegState::Delivered);
            att.last = self.now;
            self.invites.entry(sid.clone()).or_insert(m);
            self.out.push(Emission::Deliver { leg: device.into(), msg_type: "invite".into(), reason: None, id: Some(sid) });
        } else {
            self.out.push(Emission::Deliver { leg: device.into(), msg_type: m.msg_type.clone(), reason: None, id: Some(m.id.clone()) });
        }
    }

    /// Every recipient this relay knows, identities and devices, by DID: what a relay keeps across a restart, with
    /// [`Relay::inbox`].
    ///
    /// Spec: none (infrastructure).
    pub fn known_recipients(&self) -> BTreeMap<String, Known> {
        let mut out = BTreeMap::new();
        for who in self.bindings.keys() {
            out.insert(who.clone(), Known { who: who.clone(), identity: None, last_bound: self.last_bound.get(who).copied() });
        }
        for (device, identity) in &self.devices {
            let k = Known { who: device.clone(), identity: Some(identity.clone()), last_bound: self.last_bound.get(device).copied() };
            out.insert(device.clone(), k);
        }
        out
    }

    /// Take back what a relay kept across a restart: its queues and the recipients it knew. Nothing is bound after a
    /// restart, so a recipient bound when the relay stopped counts as unbound from now: it stays known for the
    /// retention window (§13.3, spec-gap 131), and its queue is flushed when it binds again. Queues past their
    /// deadline are dropped at the next clock advance ([`Relay::expire_queues`]).
    ///
    /// Spec: §13.3 (store-and-forward until `min(expires_at, offline_retention_s)`; spec-gap 98: arrival order).
    pub fn restore(&mut self, inbox: BTreeMap<String, Vec<Queued>>, known: impl IntoIterator<Item = Known>) {
        let now = self.now;
        for k in known {
            match &k.identity {
                Some(identity) => {
                    self.devices.insert(k.who.clone(), identity.clone());
                    self.bindings.entry(identity.clone()).or_default();
                }
                None => {
                    self.bindings.entry(k.who.clone()).or_default();
                }
            }
            self.last_bound.insert(k.who, k.last_bound.unwrap_or(now));
        }
        for (to, mut q) in inbox {
            q.sort_by_key(|e| e.arrival);
            self.arrivals = self.arrivals.max(q.last().map_or(0, |e| e.arrival));
            if !q.is_empty() {
                self.inbox.insert(to, q);
            }
        }
    }

    /// Drop queued envelopes past their deadline (§13.3 boundary; nothing is signaled — spec-gap 17).
    pub fn expire_queues(&mut self) {
        let now = self.now;
        let mut empties = vec![];
        let keys: Vec<String> = self.inbox.keys().cloned().collect();
        for to in keys {
            let q = self.inbox.get_mut(&to).expect("key");
            let (expired, keep): (Vec<Queued>, Vec<Queued>) = q.drain(..).partition(|e| e.deadline <= now);
            *q = keep;
            for e in expired {
                self.out.push(Emission::Dequeue { to: to.clone(), msg_type: e.message.msg_type.clone(), why: DequeueReason::Expired });
            }
            if q.is_empty() {
                empties.push(to);
            }
        }
        for to in empties {
            self.inbox.remove(&to);
        }
    }

    /// The initiator device of a tracked attempt.
    pub fn attempt_initiator(&self, session: &str) -> Option<&str> {
        self.attempts.get(session).map(|a| a.initiator.as_str())
    }

    /// Attempts held and invites on record, for an operator's status page (`attempts`, `invites`).
    ///
    /// Spec: none (infrastructure).
    pub fn held(&self) -> (usize, usize) {
        (self.attempts.len(), self.invites.len())
    }

    /// Invite on record for a session (for delivering to legs added mid-attempt).
    pub fn invite(&self, session: &str) -> Option<&Message> {
        self.invites.get(session)
    }

    /// README `inbox` snapshot: identity → queued count (non-empty only).
    pub fn inbox_snapshot(&self) -> Value {
        let m: serde_json::Map<String, Value> =
            self.inbox.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| (k.clone(), json!(v.len()))).collect();
        Value::Object(m)
    }

    /// Devices an identity (or device) DID routes to.
    pub fn legs_for(&self, to: &str) -> Vec<String> {
        if let Some(identity) = self.devices.get(to) {
            return if self.bindings.get(identity).is_some_and(|s| s.contains(to)) { vec![to.to_string()] } else { vec![] };
        }
        self.bindings.get(to).map(|s| s.iter().cloned().collect()).unwrap_or_default()
    }

    /// Snapshot of named attempts.
    pub fn snapshot(&self, ids: impl IntoIterator<Item = String>) -> Value {
        let mut m = serde_json::Map::new();
        for id in ids {
            m.insert(id.clone(), self.attempts.get(&id).map(Attempt::snapshot).unwrap_or(Value::Null));
        }
        Value::Object(m)
    }

    /// Drive one event.
    pub fn step(&mut self, ev: &RelayEvent) -> Vec<Emission> {
        self.out.clear();
        match ev {
            RelayEvent::Advance { advance } => {
                self.now += advance;
                self.expire_queues();
                self.expire_silent_legs();
                self.forget();
            }
            RelayEvent::Relay(a) => self.action(a),
            RelayEvent::Recv { recv } => self.recv(recv),
        }
        std::mem::take(&mut self.out)
    }

    fn action(&mut self, a: &RelayAction) {
        match a {
            RelayAction::Invite { session, from, to, legs } => {
                let mut att = Attempt {
                    session: session.clone(),
                    initiator: from.clone(),
                    identity: to.clone(),
                    legs: BTreeMap::new(),
                    reasons: vec![],
                    outcome: None,
                last: self.now,
                heard: Default::default(),
                };
                for leg in legs {
                    att.legs.insert(leg.clone(), LegState::Delivered);
                    self.out.push(Emission::Deliver { leg: leg.clone(), msg_type: "invite".into(), reason: None, id: None });
                }
                self.attempts.insert(session.clone(), att);
            }
            RelayAction::Bind { device, identity } => {
                self.bindings.entry(identity.clone()).or_default().insert(device.clone());
                self.devices.insert(device.clone(), identity.clone());
                self.last_bound.remove(identity);
                self.last_bound.remove(device);
                // §13.3: flush the identity's and the device's queues together, in the order the envelopes
                // arrived (spec-gap 98) — not the identity's queue first
                let mut queued = self.inbox.remove(identity).unwrap_or_default();
                queued.extend(self.inbox.remove(device).unwrap_or_default());
                queued.sort_by_key(|q| q.arrival);
                for q in queued {
                    self.flush_to(device, q.message);
                }
                // §12.7 rule 3: a device binding while an attempt for its identity is live becomes a new leg
                let live: Vec<String> = self
                    .attempts
                    .values()
                    .filter(|a| &a.identity == identity && a.outcome.is_none() && !a.legs.contains_key(device))
                    .map(|a| a.session.clone())
                    .collect();
                for sid in live {
                    let fresh = self.invites.get(&sid).map(|inv| inv.expires_at.unwrap_or(self.now + 1) > self.now).unwrap_or(false); // `expired` from expires_at (§12.9, spec-gap 141)
                    if fresh {
                        let att = self.attempts.get_mut(&sid).expect("live");
                        att.legs.insert(device.clone(), LegState::Delivered);
                        att.last = self.now;
                        self.out.push(Emission::Deliver { leg: device.clone(), msg_type: "invite".into(), reason: None, id: Some(sid) });
                    }
                }
            }
            RelayAction::Unbind { device, identity } => {
                if let Some(set) = self.bindings.get_mut(identity) {
                    set.remove(device);
                }
                self.last_bound.insert(device.clone(), self.now);
                if self.bindings.get(identity).is_none_or(|b| b.is_empty()) {
                    self.last_bound.insert(identity.clone(), self.now);
                }
            }
            RelayAction::LegExpired { session, leg } => {
                if let Some(att) = self.attempts.get_mut(session) {
                    if att.legs.get(leg) == Some(&LegState::Delivered) {
                        att.legs.insert(leg.clone(), LegState::Expired);
                        let sid = session.clone();
                        self.check_complete(&sid);
                    }
                }
            }
        }
    }

    fn recv(&mut self, m: &Message) {
        let to = m.to.clone().unwrap_or_default();
        if m.msg_type == "introduction" {
            // §19.4 anti-enumeration: unknown and offline identities are treated identically — queued, no error.
            // Impl (spec-gap 14): §13.2 "no silent drops" yields to §19.4 for this one message type.
            let devices = self.legs_for(&to);
            if devices.is_empty() {
                self.enqueue(m);
            } else {
                for d in devices {
                    self.out.push(Emission::Deliver { leg: d, msg_type: "introduction".into(), reason: None, id: None });
                }
            }
            return;
        }
        if m.msg_type == "invite" {
            let legs = self.legs_for(&to);
            if legs.is_empty() {
                if self.known(&to) {
                    self.enqueue(m); // §13.3: known but offline → store-and-forward
                } else {
                    // Session traffic to an identity this relay has never seen is refused with a signed error (§13.2).
                    self.out.push(Emission::Send(crate::event::SendMsg {
                        msg_type: "error".into(),
                        to: m.from.clone(),
                        reason: Some("transport.unknown-recipient".into()),
                        in_reply_to: Some(m.id.clone()),
                        ..Default::default()
                    }));
                }
                return;
            }
            self.invites.insert(m.id.clone(), m.clone());
            let act = RelayAction::Invite { session: m.id.clone(), from: m.from.clone(), to, legs };
            return self.action(&act);
        }
        let sid = m.session.clone().unwrap_or_default();
        let attempt_scoped = matches!(m.msg_type.as_str(), "progress" | "answer" | "reject" | "cancel") && m.in_reply_to.is_none();
        if self.attempts.contains_key(&sid) && !attempt_scoped {
            // Post-answer and renegotiation traffic is not attempt-scoped: plain routing by `to` (§13.2/§13.3).
            return self.route_plain(m);
        }
        if !self.attempts.contains_key(&sid) {
            if m.msg_type == "cancel" {
                // A cancel for an invite that is still queued drops the queued invite (§12.11)
                if let Some(q) = self.inbox.get_mut(&to) {
                    let before = q.len();
                    q.retain(|e| !(e.message.msg_type == "invite" && e.message.id == sid));
                    if q.len() != before {
                        if q.is_empty() {
                            self.inbox.remove(&to);
                        }
                        self.out.push(Emission::Dequeue { to, msg_type: "invite".into(), why: DequeueReason::Cancelled });
                        return;
                    }
                }
            }
            return self.route_plain(m);
        }
        let now = self.now;
        let att = self.attempts.get_mut(&sid).expect("checked");
        if m.msg_type == "cancel" && m.from == att.initiator {
            // §12.7 rule 3: per-leg cancel to every leg that has not terminated — or, addressed to a device, to
            // that leg alone (§12.11: "a specific device DID (targeted cancel of one leg)")
            let only = m.to.clone().filter(|to| att.legs.contains_key(to));
            if only.is_none() && m.to.as_ref().is_some_and(|to| *to != att.identity) {
                // addressed to a device that is no leg of this attempt: not the attempt's business, and so not a
                // message that keeps it held (§13.3, spec-gap 187)
                return self.route_plain(m);
            }
            att.last = now;
            let live: Vec<String> = att
                .legs
                .iter()
                .filter(|(l, s)| !s.terminated() && only.as_ref().is_none_or(|o| o == *l))
                .map(|(l, _)| l.clone())
                .collect();
            for leg in live {
                att.legs.insert(leg.clone(), LegState::Cancelled);
                self.out.push(Emission::Deliver { leg, msg_type: "cancel".into(), reason: m.reason.clone(), id: None });
            }
            if att.outcome.is_none() && att.legs.values().all(|s| s.terminated()) {
                att.outcome = Some("cancelled");
            }
            return;
        }
        let leg = m.from.clone();
        let Some(&state) = att.legs.get(&leg) else {
            // spec-gap 82: not a leg of this attempt — routed like any envelope, never dropped
            return self.route_plain(m);
        };
        att.last = now;
        att.heard.insert(leg.clone());
        if m.msg_type == "answer" {
            // Never withheld, whatever the leg's state (spec-gap 86): only the initiator ends a leg that has
            // answered — bye already-answered / cancelled / failed (§12.7 rule 4, §12.5 rule 3, §12.4). The
            // record changes only for a leg that was still outstanding: a cancelled, expired or rejected leg
            // that answers stays recorded as such.
            if state == LegState::Delivered {
                att.legs.insert(leg.clone(), LegState::Answered);
                if att.outcome.is_none() {
                    att.outcome = Some("answered");
                }
            }
            self.out.push(Emission::Forward { msg_type: "answer".into(), status: None, reason: None, from: leg, session: sid });
            return;
        }
        if state.terminated() {
            // A stale progress or a second reject from a leg that is done would read, at an initiator that
            // cannot see legs, as the attempt's own; nobody needs it, so the relay screens it (spec-gap 86).
            self.out.push(Emission::Drop(DropReason::LegTerminated));
            return;
        }
        match m.msg_type.as_str() {
            "progress" => self.out.push(Emission::Forward {
                msg_type: "progress".into(),
                status: m.status.clone(),
                reason: None,
                from: leg,
                session: sid.clone(),
            }),
            "reject" => {
                att.legs.insert(leg.clone(), LegState::Rejected);
                att.reasons.push((leg, m.reason.clone().unwrap_or_default()));
                self.check_complete(&sid);
            }
            _ => self.out.push(Emission::Drop(DropReason::NotAttemptScoped)),
        }
    }

    /// Plain routing by `to`: deliver to bound devices, queue for a known-offline recipient, else drop.
    fn route_plain(&mut self, m: &Message) {
        let to = m.to.clone().unwrap_or_default();
        let legs = self.legs_for(&to);
        if !legs.is_empty() {
            for d in legs {
                self.out.push(Emission::Deliver { leg: d, msg_type: m.msg_type.clone(), reason: None, id: Some(m.id.clone()) });
            }
        } else if self.known(&to) {
            self.enqueue(m);
        } else {
            // spec-gap 82: §13.2 — a relay MUST NOT silently drop an envelope on a live connection. Traffic for a
            // session it holds no attempt for is routed like any envelope; with no route, the sender is told so.
            self.out.push(Emission::Send(crate::event::SendMsg {
                msg_type: "error".into(),
                to: m.from.clone(),
                reason: Some("transport.unknown-recipient".into()),
                in_reply_to: Some(m.id.clone()),
                ..Default::default()
            }));
        }
    }

    /// §12.7 rule 6: when the final outstanding leg terminates without an answer,
    /// forward the most informative reject as the attempt outcome.
    fn check_complete(&mut self, sid: &str) {
        let Some(att) = self.attempts.get_mut(sid) else { return };
        if att.outcome.is_some() || att.legs.values().any(|s| !s.terminated()) {
            return;
        }
        if att.reasons.is_empty() {
            // spec-gap 76: no leg said anything — nothing to forward, and the relay may not invent a reject in a
            // leg's name (§15.2): it speaks for itself, in its own signed error
            att.outcome = Some("no-response");
            let to = att.initiator.clone();
            self.out.push(Emission::Send(crate::event::SendMsg {
                msg_type: "error".into(),
                to,
                session: Some(sid.to_string()),
                reason: Some("transport.no-response".into()),
                in_reply_to: Some(sid.to_string()),
                ..Default::default()
            }));
            return;
        }
        att.outcome = Some("rejected");
        let best = REASON_RANK
            .iter()
            .find(|r| att.reasons.iter().any(|(_, x)| x == *r))
            .map(|r| r.to_string())
            .unwrap_or_else(|| att.reasons[0].1.clone());
        let from = att.reasons.iter().find(|(_, r)| *r == best).map(|(l, _)| l.clone()).unwrap_or_default();
        self.out.push(Emission::Forward { msg_type: "reject".into(), status: None, reason: Some(best), from, session: sid.to_string() });
    }
}
