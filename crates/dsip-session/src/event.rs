//! Events into, and emissions out of, the state engine.
//!
//! Spec: none (infrastructure) — the vocabulary is fixed by
//! `impl/vectors/README.md` ("Kind: state"); [`Emission::to_json`] produces
//! exactly those shapes so Rust and Python traces compare byte-for-byte.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::message::Message;

/// A local (application) request to the endpoint.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify))]
#[serde(tag = "local", rename_all = "snake_case")]
pub enum LocalEvent {
    /// Send an `invite` with id `session` to `to`.
    PlaceCall {
        /// Session (= invite) id.
        session: String,
        /// Addressed identity or device DID.
        to: String,
    },
    /// Abandon an attempt (`cancel user.cancelled`).
    Cancel {
        /// Session id.
        session: String,
    },
    /// End an ACTIVE session (`bye`, reason `user.hangup` unless given — the media layer
    /// ends a failed path with `media.failed`, WebRTC Media Binding B§8).
    Hangup {
        /// Session id.
        session: String,
        /// Reason token override.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Policy admits the invite: alert the user (`progress ringing`).
    Alert {
        /// Session id.
        session: String,
        /// Advertised ring timeout.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ring_timeout: Option<i64>,
    },
    /// Policy rejects at OFFERED.
    AutoReject {
        /// Session id.
        session: String,
        /// Reason token.
        reason: String,
    },
    /// User/service accepts (`answer`).
    Accept {
        /// Session id.
        session: String,
        /// `answered_by` (default `user`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answered_by: Option<String>,
    },
    /// User declines (`reject user.declined`, or the given reason, e.g. `policy.recording-declined`, Recording Profile C§4).
    Decline {
        /// Session id.
        session: String,
        /// The reject's reason; `user.declined` when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Send an `update`.
    Update {
        /// Session id.
        session: String,
        /// Update id.
        id: String,
        /// Optional role-transition signal (§14.4).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answered_by: Option<String>,
        /// Seconds until the update expires, and lapses if unanswered (§12.8 rule 7); 30 when absent (§12.9).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        validity: Option<i64>,
    },
    /// Answer the inbound outstanding update.
    AnswerUpdate {
        /// Session id.
        session: String,
        /// The update id.
        in_reply_to: String,
        /// `answered_by` (default `user`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answered_by: Option<String>,
    },
    /// Reject the inbound outstanding update.
    RejectUpdate {
        /// Session id.
        session: String,
        /// The update id.
        in_reply_to: String,
        /// Reason token.
        reason: String,
    },
    /// Send an `info`.
    Info {
        /// Session id.
        session: String,
    },
    /// Send an `introduction` (§19.4).
    Introduce {
        /// Introduction id.
        id: String,
        /// Recipient identity.
        to: String,
        /// Stated purpose (a claim).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
        /// Out-of-band contact token.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        contact_token: Option<String>,
    },
    /// Issue a grant for a pending introduction.
    Grant {
        /// Introduction id.
        introduction: String,
        /// Grant id.
        id: String,
        /// Scopes.
        #[serde(default)]
        scope: Vec<String>,
        /// Grant lifetime.
        valid_until: i64,
        /// The presence audience the grant admits to (P§6, spec-gap 145).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presence_audience: Option<String>,
    },
    /// Issue a grant that follows (and replaces) the live grant `grant` we issued, without an introduction (§19.4,
    /// spec-gap 150).
    Regrant {
        /// The grant this one follows.
        grant: String,
        /// The new grant's id.
        id: String,
        /// Scopes.
        #[serde(default)]
        scope: Vec<String>,
        /// Grant lifetime.
        valid_until: i64,
        /// The presence audience the grant admits to (P§6, spec-gap 145).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presence_audience: Option<String>,
    },
    /// Decline a pending introduction.
    RejectIntroduction {
        /// Introduction id.
        introduction: String,
        /// Reason token.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Revoke an issued grant.
    Revoke {
        /// Grant id.
        grant: String,
    },
    /// Pre-authorize a contact token.
    IssueToken {
        /// Token.
        token: String,
        /// Grant id to issue on match.
        grant_id: String,
    },
}

impl LocalEvent {
    /// The session the event targets (`PlaceCall` creates it); empty for contact events.
    pub fn session(&self) -> &str {
        match self {
            LocalEvent::Introduce { .. }
            | LocalEvent::Grant { .. }
            | LocalEvent::Regrant { .. }
            | LocalEvent::RejectIntroduction { .. }
            | LocalEvent::Revoke { .. }
            | LocalEvent::IssueToken { .. } => "",
            LocalEvent::PlaceCall { session, .. }
            | LocalEvent::Cancel { session }
            | LocalEvent::Hangup { session, .. }
            | LocalEvent::Alert { session, .. }
            | LocalEvent::AutoReject { session, .. }
            | LocalEvent::Accept { session, .. }
            | LocalEvent::Decline { session, .. }
            | LocalEvent::Update { session, .. }
            | LocalEvent::AnswerUpdate { session, .. }
            | LocalEvent::RejectUpdate { session, .. }
            | LocalEvent::Info { session } => session,
        }
    }
}

/// An event into an [`crate::Endpoint`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)] // an event is built once and consumed at once; boxing the message would cost an allocation per event
pub enum Event {
    /// Advance the clock by seconds; due timers fire.
    Advance {
        /// Seconds.
        advance: i64,
    },
    /// A verified message arrived.
    Recv {
        /// The message.
        recv: Message,
    },
    /// A local request.
    Local(LocalEvent),
}

/// An outbound message the engine wants sent (abbreviated; the transport builds the payload).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SendMsg {
    /// Message type.
    pub msg_type: String,
    /// Destination DID.
    pub to: String,
    /// Session id (absent on `introduction`).
    pub session: Option<String>,
    /// Message id, when chosen by the caller (updates, introductions, grants).
    pub id: Option<String>,
    /// Reason token.
    pub reason: Option<String>,
    /// Progress status.
    pub status: Option<String>,
    /// Ring timeout advertised.
    pub ring_timeout: Option<i64>,
    /// `answered_by`.
    pub answered_by: Option<String>,
    /// `in_reply_to`.
    pub in_reply_to: Option<String>,
    /// Other fields (`grant`, `purpose`, `contact_token`, `scope`, `valid_until`), in emission order.
    pub extra: Vec<(&'static str, Value)>,
}

/// The engine's timers (§12.9).
///
/// Spec: §12.9 — the names are the engine's own vocabulary, fixed by `impl/vectors/README.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TimerName {
    /// `T-Establish`: the initiator's bound on reaching an answer.
    Establish,
    /// `T-Ring`: the initiator's bound once the callee rings.
    Ring,
    /// `T-Queue`: the initiator's bound while queued.
    Queue,
    /// `T-Ring-Local`: the responder's own ring bound.
    RingLocal,
}

impl TimerName {
    /// The name as the vectors write it.
    pub fn as_str(self) -> &'static str {
        match self {
            TimerName::Establish => "T-Establish",
            TimerName::Ring => "T-Ring",
            TimerName::Queue => "T-Queue",
            TimerName::RingLocal => "T-Ring-Local",
        }
    }
}

impl std::fmt::Display for TimerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What happened to a timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerAction {
    /// Started (or restarted) for this many seconds.
    Start {
        /// Seconds until it fires.
        seconds: i64,
    },
    /// Stopped before firing.
    Stop,
    /// Fired.
    Fire,
}

impl TimerAction {
    /// `start` | `stop` | `fire`, as the vectors write it.
    pub fn as_str(self) -> &'static str {
        match self {
            TimerAction::Start { .. } => "start",
            TimerAction::Stop => "stop",
            TimerAction::Fire => "fire",
        }
    }
}

/// A media-layer instruction (§14.1).
///
/// Spec: §14.1 — media starts only after the signed answer; §12.8 — an accepted update is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MediaCommand {
    /// Start sending media.
    Start,
    /// Stop media.
    Stop,
    /// Apply the media of an accepted update.
    ApplyUpdate,
}

impl MediaCommand {
    /// `start` | `stop` | `apply_update`, as the vectors write it.
    pub fn as_str(self) -> &'static str {
        match self {
            MediaCommand::Start => "start",
            MediaCommand::Stop => "stop",
            MediaCommand::ApplyUpdate => "apply_update",
        }
    }
}

impl std::fmt::Display for MediaCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the application should show. Registry-governed values (`status`, `answered_by`, reason tokens) stay
/// strings: registries grow, so unknown values pass through.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UiEvent {
    /// A `progress` arrived (§12.10).
    Progress {
        /// The `progress.status` token.
        status: String,
    },
    /// The session was answered (§14.3).
    Answered {
        /// The `answered_by` token.
        answered_by: String,
    },
    /// An invite is offered to the user (§12.4).
    Offered,
    /// The peer offered an update (§12.8).
    UpdateOffered,
    /// An update was rejected (§12.8), or lapsed unanswered at its `expires_at` (`session.expired`, rule 7).
    UpdateRejected {
        /// The reason token.
        reason: String,
    },
    /// The peer's update was not answered by its `expires_at`: it may no longer be (§12.8 rule 7).
    UpdateLapsed,
    /// The caller gave up before the user answered (§12.11).
    MissedCall,
    /// The session ended (§12.4).
    Ended {
        /// The reason token.
        reason: String,
    },
    /// Glare: this side withdraws and may retry (§12.6).
    GlareRetry,
    /// A signed `error` arrived (§15).
    Error {
        /// The reason token.
        reason: String,
    },
    /// An introduction arrived (§19.4).
    IntroductionReceived {
        /// The introducing identity.
        from: String,
        /// It carried a contact token this endpoint issued.
        token: bool,
    },
    /// A grant arrived (§19.4).
    Granted {
        /// The granting identity.
        by: String,
    },
    /// An introduction was rejected (§19.4).
    IntroductionRejected {
        /// The reason token.
        reason: String,
    },
}

impl UiEvent {
    /// The kind, as the vectors write it.
    pub fn kind(&self) -> &'static str {
        match self {
            UiEvent::Progress { .. } => "progress",
            UiEvent::Answered { .. } => "answered",
            UiEvent::Offered => "offered",
            UiEvent::UpdateOffered => "update_offered",
            UiEvent::UpdateRejected { .. } => "update_rejected",
            UiEvent::UpdateLapsed => "update_lapsed",
            UiEvent::MissedCall => "missed_call",
            UiEvent::Ended { .. } => "ended",
            UiEvent::GlareRetry => "glare_retry",
            UiEvent::Error { .. } => "error",
            UiEvent::IntroductionReceived { .. } => "introduction_received",
            UiEvent::Granted { .. } => "granted",
            UiEvent::IntroductionRejected { .. } => "introduction_rejected",
        }
    }

    /// The named fields, in emission order.
    pub fn fields(&self) -> Vec<(&'static str, Value)> {
        match self {
            UiEvent::Progress { status } => vec![("status", status.as_str().into())],
            UiEvent::Answered { answered_by } => vec![("answered_by", answered_by.as_str().into())],
            UiEvent::UpdateRejected { reason }
            | UiEvent::Ended { reason }
            | UiEvent::Error { reason }
            | UiEvent::IntroductionRejected { reason } => vec![("reason", reason.as_str().into())],
            UiEvent::IntroductionReceived { from, token: true } => vec![("from", from.as_str().into()), ("token", true.into())],
            UiEvent::IntroductionReceived { from, token: false } => vec![("from", from.as_str().into())],
            UiEvent::Granted { by } => vec![("by", by.as_str().into())],
            UiEvent::Offered | UiEvent::UpdateOffered | UiEvent::UpdateLapsed | UiEvent::MissedCall | UiEvent::GlareRetry => vec![],
        }
    }
}

/// Why the engine refused a local request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// Not allowed in the session's current state.
    InvalidState,
    /// No such session.
    UnknownSession,
    /// No such introduction.
    UnknownIntroduction,
    /// A grant's `presence_audience` is not an audience token (P§6).
    InvalidAudience,
    /// No such grant.
    UnknownGrant,
    /// §12.8 rule 2: an update is already outstanding, in either direction.
    UpdatePending,
    /// No update to answer.
    NoPendingUpdate,
}

impl Refusal {
    /// The refusal, as the vectors write it.
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::InvalidState => "invalid-state",
            Refusal::UnknownSession => "unknown-session",
            Refusal::UnknownIntroduction => "unknown-introduction",
            Refusal::InvalidAudience => "invalid-audience",
            Refusal::UnknownGrant => "unknown-grant",
            Refusal::UpdatePending => "update-pending",
            Refusal::NoPendingUpdate => "no-pending-update",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why the engine silently ignored a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropReason {
    /// The session has ended.
    EndedSession,
    /// The introduction was already received.
    DuplicateIntroduction,
    /// No such introduction.
    UnknownIntroduction,
    /// A reply to an update that is no longer outstanding.
    StaleUpdateReply,
    /// §12.12: an `info` for a binding this endpoint does not know; never critical.
    UnknownAbout,
    /// Relay: the leg has already terminated.
    LegTerminated,
    /// Relay: the message is not scoped to an attempt.
    NotAttemptScoped,
}

impl DropReason {
    /// The reason, as the vectors write it.
    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::EndedSession => "ended-session",
            DropReason::DuplicateIntroduction => "duplicate-introduction",
            DropReason::UnknownIntroduction => "unknown-introduction",
            DropReason::StaleUpdateReply => "stale-update-reply",
            DropReason::UnknownAbout => "unknown-about",
            DropReason::LegTerminated => "leg-terminated",
            DropReason::NotAttemptScoped => "not-attempt-scoped",
        }
    }
}

impl std::fmt::Display for DropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a relay dropped a queued envelope (§13.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DequeueReason {
    /// Its `expires_at` passed.
    Expired,
    /// The attempt it belonged to was cancelled.
    Cancelled,
}

impl DequeueReason {
    /// `expired` | `cancelled`, as the vectors write it.
    pub fn as_str(self) -> &'static str {
        match self {
            DequeueReason::Expired => "expired",
            DequeueReason::Cancelled => "cancelled",
        }
    }
}

impl std::fmt::Display for DequeueReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything the engine can emit.
#[derive(Debug, Clone, PartialEq)]
pub enum Emission {
    /// Send a message.
    Send(SendMsg),
    /// Timer lifecycle.
    Timer {
        /// Started, stopped or fired.
        action: TimerAction,
        /// Which timer.
        name: TimerName,
    },
    /// Media-layer instruction.
    Media(MediaCommand),
    /// What the application should show.
    Ui(UiEvent),
    /// Relay queued a message for an identity with no bound device (§19.4 anti-enumeration).
    Queue {
        /// Identity.
        to: String,
        /// Message type.
        msg_type: String,
    },
    /// `info` handed to the binding named by `about`.
    Info {
        /// The `about` namespace.
        about: String,
    },
    /// A local request was refused.
    Refused(Refusal),
    /// The grants whose `grant-revocation` the host sends its authority: a grant, then its rotation chain newest first
    /// (P§7, spec-gap 159).
    Revoke(Vec<String>),
    /// A presence key scope's epoch rose (P§12.5): by our own rotation, or seen in a sibling's record.
    Keys {
        /// `rotated` or `seen`.
        action: KeysAction,
        /// `main` or an audience tag.
        scope: String,
        /// The new epoch.
        epoch: i64,
    },
    /// A message was silently ignored.
    Drop(DropReason),
    /// Relay: deliver to a specific leg.
    Deliver {
        /// Leg device DID.
        leg: String,
        /// Message type.
        msg_type: String,
        /// Reason (cancel).
        reason: Option<String>,
        /// Envelope id, when delivering a queued envelope or a leg added mid-attempt (§13.3).
        id: Option<String>,
    },
    /// Relay: a queued envelope was dropped (`expired` | `cancelled`).
    Dequeue {
        /// Recipient.
        to: String,
        /// Message type.
        msg_type: String,
        /// Why.
        why: DequeueReason,
    },
    /// Relay: forward a leg's message to the initiator.
    Forward {
        /// Message type.
        msg_type: String,
        /// Status (progress).
        status: Option<String>,
        /// Reason (reject).
        reason: Option<String>,
        /// Originating leg.
        from: String,
        /// The attempt it belongs to: what a host needs to find the initiator when no frame is in hand (an outcome
        /// reached on a clock advance, spec-gap 132). Not part of the vector emission shape.
        session: String,
    },
}

/// How a presence key scope's epoch rose (P§12.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysAction {
    /// This device rotated it.
    Rotated,
    /// A sibling's record carried it.
    Seen,
}

impl KeysAction {
    /// The README token.
    pub fn as_str(self) -> &'static str {
        match self {
            KeysAction::Rotated => "rotated",
            KeysAction::Seen => "seen",
        }
    }
}

/// The README JSON shape ([`Emission::to_json`]). Its TypeScript declaration is written by hand beside the browser
/// build (`dsip-wasm`), since the shape is flattened per kind, and is checked against the state vectors' emissions.
impl Serialize for Emission {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(serializer)
    }
}

impl Emission {
    /// The README JSON shape.
    pub fn to_json(&self) -> Value {
        match self {
            Emission::Send(m) => {
                let mut o = Map::new();
                o.insert("type".into(), m.msg_type.clone().into());
                o.insert("to".into(), m.to.clone().into());
                if let Some(s) = &m.session {
                    o.insert("session".into(), s.clone().into());
                }
                let mut opt = |k: &str, v: Option<Value>| {
                    if let Some(v) = v {
                        o.insert(k.into(), v);
                    }
                };
                opt("id", m.id.clone().map(Value::from));
                opt("reason", m.reason.clone().map(Value::from));
                opt("status", m.status.clone().map(Value::from));
                opt("ring_timeout", m.ring_timeout.map(Value::from));
                opt("answered_by", m.answered_by.clone().map(Value::from));
                opt("in_reply_to", m.in_reply_to.clone().map(Value::from));
                for (k, v) in &m.extra {
                    o.insert((*k).into(), v.clone());
                }
                json!({ "send": o })
            }
            Emission::Timer { action, name } => match action {
                TimerAction::Start { seconds } => json!({"timer": action.as_str(), "name": name.as_str(), "seconds": seconds}),
                _ => json!({"timer": action.as_str(), "name": name.as_str()}),
            },
            Emission::Media(m) => json!({ "media": m.as_str() }),
            Emission::Ui(ui) => {
                let mut o = Map::new();
                o.insert("ui".into(), ui.kind().into());
                for (k, v) in ui.fields() {
                    o.insert(k.into(), v);
                }
                Value::Object(o)
            }
            Emission::Queue { to, msg_type } => json!({"queue": {"to": to, "type": msg_type}}),
            Emission::Info { about } => json!({"info": {"about": about}}),
            Emission::Refused(r) => json!({ "refused": r.as_str() }),
            Emission::Revoke(ids) => json!({ "revoke": ids }),
            Emission::Keys { action, scope, epoch } => json!({"keys": action.as_str(), "scope": scope, "epoch": epoch}),
            Emission::Drop(r) => json!({ "drop": r.as_str() }),
            Emission::Deliver { leg, msg_type, reason, id } => {
                let mut o = Map::new();
                o.insert("leg".into(), leg.clone().into());
                o.insert("type".into(), msg_type.clone().into());
                if let Some(r) = reason {
                    o.insert("reason".into(), r.clone().into());
                }
                if let Some(i) = id {
                    o.insert("id".into(), i.clone().into());
                }
                json!({ "deliver": o })
            }
            Emission::Dequeue { to, msg_type, why } => json!({"dequeue": {"to": to, "type": msg_type, "why": why.as_str()}}),
            Emission::Forward { msg_type, status, reason, from, .. } => {
                let mut o = Map::new();
                o.insert("type".into(), msg_type.clone().into());
                if let Some(s) = status {
                    o.insert("status".into(), s.clone().into());
                }
                if let Some(r) = reason {
                    o.insert("reason".into(), r.clone().into());
                }
                o.insert("from".into(), from.clone().into());
                json!({ "forward": o })
            }
        }
    }
}
