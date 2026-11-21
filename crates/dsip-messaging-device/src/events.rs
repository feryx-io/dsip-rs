//! What a [`crate::messenger::Messenger`] returns from a step: the frames to send to the mailbox and the events for its host to
//! show, in order (dsip-rs B3, `impl/docs/dsip-stack-design.md` §6). They serialize as the JSON the hosts read before
//! these types existed: `{send}`, `{ui: …, …}`, `{sync}`, `{refused}`, `{error}`, `{drop}`, `{rejected}`,
//! `{key_packages}`, `{successor_due}`.
//!
//! Spec: none (infrastructure). The sections each event reports are cited on its variant.

use serde::Serialize;
use serde_json::Value;

/// One output of a step, in order.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
#[serde(untagged)]
// tsify does not follow `untagged`
#[cfg_attr(feature = "ts", tsify(type = "{ send: string } | Ui | { sync: boolean } | { refused: string; group?: string; item?: string; pending?: boolean } | { error: string; group?: string; reason?: unknown; detail?: unknown } | { drop: string } | { rejected: Rejected } | { key_packages: unknown } | { successor_due: SuccessorDue }"))]
// made and consumed within one step, a few at a time: boxing the large `Ui` would only complicate matching
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// A frame for the mailbox; empty when the deposit was queued behind an unreachable hub or kept for a successor
    /// (M§9.4).
    Send {
        /// The frame.
        send: String,
    },
    /// Something for the host to show.
    Ui(Ui),
    /// A refused deposit asks for a sync before anything is proposed again (M§6.5, spec-gap 58; M§7.4).
    Sync {
        /// `true`.
        sync: bool,
    },
    /// A deposit, or what a call asked for, was refused for good, or is pending behind an outage (M§9.4, M§16).
    Refused {
        /// What was refused, and why.
        refused: String,
        /// The group, for an application message.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(optional))]
        group: Option<String>,
        /// The outbox item, for an application message.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(optional))]
        item: Option<String>,
        /// Whether it stays pending (M§9.4: the hub is unreachable).
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(optional))]
        pending: Option<bool>,
    },
    /// Something went wrong here, or the mailbox said so outside an answer to a deposit of ours.
    Error {
        /// What.
        error: String,
        /// The group it concerns.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(optional))]
        group: Option<String>,
        /// The mailbox's reason, as it came.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(type = "unknown", optional))]
        reason: Option<Value>,
        /// The mailbox's detail, as it came.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(type = "unknown", optional))]
        detail: Option<Value>,
    },
    /// A frame passed over: not the mailbox's, or of a type with no handler (M§4.1).
    Drop {
        /// Why.
        drop: String,
    },
    /// A frame that did not verify (§10.2).
    Rejected {
        /// The verdict.
        rejected: Rejected,
    },
    /// A `key-packages` answer arrived on this binding (M§5.5): the host passes it to the call that asked.
    KeyPackages {
        /// The payload.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        key_packages: Value,
    },
    /// A group's hub has been unreachable past the threshold: the host fetches the roster's KeyPackages and creates
    /// the successor (M§9.4, M§7.5).
    SuccessorDue {
        /// What the successor needs.
        successor_due: SuccessorDue,
    },
}

impl Event {
    /// A frame for the mailbox.
    pub fn send(frame: impl Into<String>) -> Event {
        Event::Send { send: frame.into() }
    }

    /// A refusal with no group.
    pub fn refused(what: impl Into<String>) -> Event {
        Event::Refused { refused: what.into(), group: None, item: None, pending: None }
    }

    /// An error with no group.
    pub fn error(what: impl Into<String>) -> Event {
        Event::Error { error: what.into(), group: None, reason: None, detail: None }
    }

    /// The frame, when this is one to send.
    pub fn frame(&self) -> Option<&str> {
        match self {
            Event::Send { send } => Some(send),
            _ => None,
        }
    }
}

impl From<Ui> for Event {
    fn from(ui: Ui) -> Event {
        Event::Ui(ui)
    }
}

/// A frame's verdict (§10.2).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct Rejected {
    /// The reject code.
    pub code: String,
    /// The reason token, when the spec defines one.
    pub reason: Option<String>,
}

/// What creating a successor needs (M§9.4, M§7.5).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct SuccessorDue {
    /// The dead group.
    pub group: String,
    /// The other identities of its roster, which the successor re-adds (spec-gap 139).
    pub peers: Vec<String>,
    /// The conversation kind.
    pub kind: Option<String>,
    /// The successor this device already converged on, if any.
    pub existing: Option<String>,
    /// The items handed over to it.
    pub pending: Vec<HandedOver>,
}

/// An object handed over to a successor: its outbox item there (`None`: kept until the successor exists), and the
/// object's `id` (M§9.4).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct HandedOver {
    /// The outbox item.
    pub item: Option<String>,
    /// The object's `id`.
    #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
    pub id: Value,
}

/// What a membership commit does, for the host to say (no key material).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum OpInfo {
    /// Devices of `peer` added; `device` names one of this identity's own (M§12.3).
    Add {
        /// The identity whose devices are added.
        peer: String,
        /// This identity's device added, if that is what it is.
        device: Option<String>,
        /// How many devices.
        devices: usize,
    },
    /// A join by external commit (M§6.8).
    Rejoin,
    /// The Remove proposals by which `identity` leaves (M§7.3).
    Leave {
        /// Who leaves.
        identity: String,
    },
    /// Every leaf of `identity` removed (M§7.3).
    Remove {
        /// Who is removed.
        identity: String,
    },
    /// The group moved to `hub` (M§7.4).
    MoveHub {
        /// `{did, uri}`.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        hub: Value,
    },
    /// This device's own leaf refreshed.
    Update,
    /// The leaves naming `device` removed (M§7.3, M§12.4).
    RemoveDevice {
        /// The device.
        device: String,
    },
}

/// A recorder device newly in a conversation (C§5).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
pub struct NewRecorder {
    /// The recorder device.
    #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
    pub device: Value,
    /// The identity it records for.
    #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
    pub subject: Value,
    /// Whether it is this identity's own.
    pub own: bool,
}

/// What the host shows, by kind.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify), tsify(hashmap_as_object, missing_as_null))]
#[serde(tag = "ui", rename_all = "snake_case")]
pub enum Ui {
    /// A member's activity (M§11.1).
    Activity {
        /// The group.
        group: String,
        /// Who.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        from: Value,
        /// Typing, uploading, recording.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        activity: Value,
        /// `active` or `stopped`.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        state: Value,
    },
    /// A member's activity expired (M§11.2).
    ActivityCleared {
        /// The group.
        group: String,
        /// Who.
        from: String,
        /// Which.
        activity: String,
    },
    /// This device's activity was not sent: the policy keeps it, or the pace holds it back (M§11.1).
    ActivityNotSent {
        /// The group.
        group: String,
        /// Which.
        activity: String,
        /// `active` or `stopped`.
        state: String,
    },
    /// This device's activity went out (M§11.1).
    ActivitySent {
        /// The group.
        group: String,
        /// Which.
        activity: String,
        /// `active` or `stopped`.
        state: String,
    },
    /// An archive record deposited (M§12.2).
    Archive {
        /// The group.
        group: String,
        /// The seq it is archived under.
        seq: i64,
        /// The archive key.
        akid: String,
        /// The object's type.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        object: Value,
    },
    /// An archive record kept sealed until its key arrives (M§12.3 step 5).
    ArchiveHeld {
        /// Its cursor.
        cursor: String,
        /// The key it waits for.
        akid: String,
    },
    /// An archive key arrived (M§12.1); `fresh` when it was new here.
    ArchiveKey {
        /// The key's id.
        akid: String,
        /// Who sent it.
        from: String,
        /// New here.
        fresh: bool,
    },
    /// This device created an archive key (M§12.1, M§12.4).
    ArchiveKeyCreated {
        /// The personal group.
        group: String,
        /// The key's id.
        akid: String,
    },
    /// The mailbox accepted an archive record (M§12.2).
    Archived {
        /// Whether it held that record already.
        duplicate: Option<bool>,
    },
    /// A call event of this identity, from a device or from the archive (M§13.3).
    CallEvent {
        /// The session.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        session: Value,
        /// The other party.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        peer: Value,
        /// `missed`, `declined`, …
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        outcome: Value,
        /// `inbound` or `outbound`.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        direction: Value,
        /// The device that sent it.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(optional))]
        from_device: Option<String>,
        /// An entry for its session was there already (spec-gap 63).
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(optional))]
        collapsed: Option<bool>,
        /// Read back from the archive.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(optional))]
        from_archive: Option<bool>,
    },
    /// As a record-keeper, a call record received (C§9).
    CallRecord {
        /// Who sent it.
        from: String,
        /// The session.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        session: Value,
        /// The leg's outcome.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        outcome: Value,
        /// The first for its leg.
        fresh: bool,
    },
    /// A commit of ours was accepted and merged (M§6.5).
    Committed {
        /// The group.
        group: String,
        /// The new epoch.
        epoch: u64,
        /// The hub's seq.
        seq: Option<i64>,
        /// The identity whose devices it added.
        added: Option<String>,
        /// The device of ours it added.
        device: Option<String>,
        /// Whether the group is the personal group.
        personal: bool,
        /// What it did.
        op: Option<OpInfo>,
    },
    /// A commit of ours lost to another (M§6.5): a sync follows.
    Conflict {
        /// The group.
        group: String,
        /// The hub's reason.
        reason: String,
        /// The epoch now.
        epoch: Option<u64>,
        /// What it did.
        op: Option<OpInfo>,
    },
    /// Something passed over, with why.
    Dropped {
        /// Why.
        why: String,
    },
    /// An item delivered again (M§8.5).
    Duplicate {
        /// Its class.
        class: String,
        /// Its cursor.
        cursor: Option<String>,
    },
    /// Content shown already, from the other copy (M§8.5).
    DuplicateContent {
        /// Its seq.
        seq: i64,
    },
    /// Another member's commit merged (M§7.3).
    Epoch {
        /// The group.
        group: String,
        /// The new epoch.
        epoch: u64,
        /// The committing identity.
        by: String,
        /// `identity#device` of each leaf added.
        added: Vec<String>,
        /// `identity#device` of each leaf removed.
        removed: Vec<String>,
    },
    /// A seq gap did not fill in time: this device re-joins (M§6.5, spec-gap 69).
    GapTimeout {
        /// The group.
        group: String,
        /// What was held behind the gap.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        held: Value,
    },
    /// A grant arrived through the mailbox (M§14.1).
    Granted {
        /// Who granted.
        by: String,
        /// Its scope.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        scope: Value,
        /// The introduction it answers.
        request: String,
        /// The grantor's profile card as taken, its own unverified claim (§19.4, `profile-card/1.0`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(type = "unknown", optional))]
        profile: Option<Value>,
        /// Whether the grant carried a `profile` at all; one without leaves what is held (§19.4).
        #[serde(default)]
        profile_sent: bool,
        /// Whether the grantor lists `profile-card/1.0`: it may be sent a card (§19.4).
        #[serde(default)]
        profile_cards: bool,
    },
    /// Objects handed over to a successor were sent there (M§9.4).
    HandedOver {
        /// The successor.
        group: String,
        /// How many.
        items: usize,
        /// Each one's new outbox item.
        sent: Vec<HandedOver>,
    },
    /// Content read back from the archive (M§12.3).
    History {
        /// The group.
        group: String,
        /// Its seq.
        seq: i64,
        /// The sender.
        from: String,
        /// The content kind.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        kind: Value,
        /// The text.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        text: Value,
    },
    /// Restored content and receipts applied to a conversation joined since (spec-gap 64).
    HistoryApplied {
        /// The group.
        group: String,
        /// How many.
        items: usize,
    },
    /// A receipt read back from the archive (M§12.2).
    HistoryReceipt {
        /// The group.
        group: String,
        /// Its seq.
        seq: i64,
        /// The sender.
        from: String,
        /// The receipt kind.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        kind: Value,
        /// The content ids.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        targets: Value,
        /// The read watermark.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        through: Value,
    },
    /// A handshake beyond a seq gap waits for it (M§6.5, spec-gap 69).
    Hold {
        /// Its class.
        class: String,
        /// Its seq.
        seq: Option<i64>,
    },
    /// The hub a group moved to never came to host it (M§7.4, spec-gap 129).
    HubArrivalExpired {
        /// The group.
        group: String,
    },
    /// The hub a group moved to does not host it yet: the deposit goes again in `in` seconds (M§7.4, spec-gap 129).
    HubArriving {
        /// The group.
        group: String,
        /// Seconds.
        #[serde(rename = "in")]
        in_s: i64,
    },
    /// An unreachable hub answered again (M§9.4).
    HubBack {
        /// The group.
        group: String,
    },
    /// A group's hub became unreachable (M§9.4).
    HubDown {
        /// The group.
        group: String,
        /// The threshold before a successor, seconds.
        hub_timeout: i64,
    },
    /// The group moved to another hub (M§7.4), rendered like a roster change.
    HubMoved {
        /// The group.
        group: String,
        /// The moving commit's seq.
        seq: i64,
        /// The epoch.
        epoch: u64,
        /// The committing identity.
        by: String,
        /// Nobody.
        added: Vec<String>,
        /// Nobody.
        removed: Vec<String>,
        /// Nobody.
        left: Vec<String>,
        /// The new hub's DID.
        hub: String,
    },
    /// The outage's head is deposited again in `in` seconds (M§9.4).
    HubRetry {
        /// The group.
        group: String,
        /// Seconds.
        #[serde(rename = "in")]
        in_s: i64,
        /// The head item.
        item: Option<String>,
    },
    /// This device joined a group: by welcome, or by external commit (M§6.6, M§6.8).
    Joined {
        /// The group.
        group: String,
        /// The conversation.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        conversation: Value,
        /// Its kind.
        kind: String,
        /// The member identities.
        members: Vec<String>,
        /// The epoch joined at.
        epoch: u64,
        /// Joined by external commit.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(optional))]
        external: Option<bool>,
        /// The external commit's seq.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(optional))]
        seq: Option<Option<i64>>,
        /// The dead group a successor's welcome names (M§7.5).
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(type = "unknown", optional))]
        successor_of: Option<Value>,
    },
    /// KeyPackages uploaded (M§5.5).
    KeyPackagesUploaded {
        /// How many.
        count: usize,
    },
    /// This device commits another identity's leave (M§7.3).
    LeaveCommitting {
        /// The group.
        group: String,
        /// Who leaves.
        identity: String,
    },
    /// A leave proposal of ours was refused: proposed again at the next epoch (M§7.3).
    LeaveProposalRefused {
        /// The group.
        group: String,
        /// The hub's reason.
        reason: String,
    },
    /// Another identity's leave proposals, and what this device decided about them (M§7.3).
    LeaveProposals {
        /// The group.
        group: String,
        /// Who leaves.
        identity: String,
        /// The pinned decision.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        decision: Value,
    },
    /// The hub sequenced a leave proposal of ours (M§7.3).
    LeaveProposed {
        /// The group.
        group: String,
        /// Its seq.
        seq: Option<i64>,
    },
    /// Another device of this identity left the conversation (M§7.3).
    Left {
        /// The group.
        group: String,
        /// The device.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        by_device: Value,
    },
    /// A content message (M§8.1).
    Message {
        /// The group.
        group: String,
        /// The sender.
        from: String,
        /// Its seq.
        seq: i64,
        /// The content kind.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        kind: Value,
        /// The text.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        text: Value,
        /// When it was sent.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        sent_at: Value,
        /// The content id.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        id: Value,
        /// The deposit's blob manifest (M§8.4).
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        blobs: Value,
        /// The sending device.
        from_device: String,
        /// The content object.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        object: Value,
    },
    /// An item refused `mailbox.unknown-group`: a sync shows whether the group moved (M§7.4).
    MovedCheck {
        /// The group.
        group: String,
        /// The item.
        item: String,
    },
    /// A refused commit is no longer needed after the winning one (M§6.5).
    NoLongerNeeded {
        /// The group.
        group: String,
        /// What it did.
        op: OpInfo,
    },
    /// The personal group holds its first archive key (M§7.1).
    Personal {
        /// The group.
        group: String,
    },
    /// An item from before this device joined, passed over (M§12.3).
    Prejoin {
        /// Its class.
        class: String,
        /// Its seq.
        seq: Option<i64>,
    },
    /// An undisclosed read watermark kept on this device: there is no personal group (M§10.5).
    ReadPrivateKept {
        /// The group.
        group: String,
    },
    /// A receipt (M§10.2).
    Receipt {
        /// The group it arrived in.
        group: String,
        /// The sender.
        from: String,
        /// The receipt kind.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        kind: Value,
        /// The content ids.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        targets: Value,
        /// The read watermark.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        through: Value,
    },
    /// A receipt of ours sent (M§10.2, M§10.5).
    ReceiptSent {
        /// The conversation's group.
        group: String,
        /// The receipt kind.
        kind: String,
        /// The content ids.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        targets: Option<Value>,
        /// The read watermark.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        through: Option<Value>,
        /// `conversation` or `personal group`.
        via: String,
    },
    /// A receipt withheld: a recorder is not accepted yet (C§5).
    ReceiptWithheld {
        /// The group.
        group: String,
        /// The receipt kind.
        kind: String,
    },
    /// Content from a recorder leaf, dropped (C§5).
    RecorderContent {
        /// The recorder device.
        device: String,
        /// The content id.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        id: Value,
    },
    /// A conversation became recorded by a new recorder, or is no longer recorded (C§5).
    Recording {
        /// The group.
        group: String,
        /// The conversation.
        conversation: String,
        /// The recorders new since it was last shown.
        new: Vec<NewRecorder>,
        /// No recorder is left.
        ended: bool,
        /// Whether content may be sent.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        may_send: Value,
    },
    /// This identity accepted recorders, on this device or another (C§5).
    RecordingAccepted {
        /// The conversation.
        conversation: String,
        /// The recorder devices.
        recorders: Vec<String>,
        /// The device that accepted.
        from_device: String,
    },
    /// What was held behind a gap is processed now (M§6.5, spec-gap 69).
    Released {
        /// Its class.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        class: Value,
        /// Its seq.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        seq: Value,
    },
    /// This device was removed from a group (M§7.3).
    Removed {
        /// The group.
        group: String,
        /// Who removed it.
        by: String,
        /// The conversation.
        conversation: Option<String>,
        /// Its kind.
        kind: Option<String>,
        /// Whether this identity was leaving.
        left: bool,
    },
    /// A refused commit proposed again after the sync (M§6.5).
    Repropose {
        /// The group.
        group: String,
        /// What it does.
        op: OpInfo,
        /// The attempt.
        attempt: i64,
        /// The epoch now.
        epoch: Option<u64>,
    },
    /// An introduction delivered through the mailbox (M§14.1).
    Request {
        /// Its id.
        id: String,
        /// Who.
        from: String,
        /// Its purpose, opened when sealed.
        purpose: String,
        /// Whether the purpose was sealed (M§6.9).
        sealed: bool,
        /// Whether a purpose travelled in clear.
        purpose_on_wire: bool,
        /// The introducer's profile card as taken, its own unverified claim (§19.4, `profile-card/1.0`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "ts", tsify(type = "unknown", optional))]
        profile: Option<Value>,
        /// Whether the introducer lists `profile-card/1.0`: the grant answering it may carry our card (§19.4).
        #[serde(default)]
        profile_cards: bool,
    },
    /// The cursor was invalid: syncing from the start (M§5.4).
    Resync,
    /// A roster change by identity (M§7.3), attributed to the committing identity.
    Roster {
        /// The group.
        group: String,
        /// The commit's seq.
        seq: Option<i64>,
        /// The epoch.
        epoch: u64,
        /// The committing identity.
        by: String,
        /// Identities added.
        added: Vec<String>,
        /// Identities removed.
        removed: Vec<String>,
        /// Identities that left by their own proposals.
        left: Vec<String>,
    },
    /// Our own deposit fanned back (M§6.5 rule 5, spec-gap 47).
    #[serde(rename = "self")]
    Own {
        /// Its class.
        class: String,
        /// Its seq.
        seq: Option<i64>,
    },
    /// An application message of ours accepted (M§9.2).
    Sent {
        /// The group.
        group: String,
        /// The outbox item.
        item: String,
        /// The hub's seq.
        seq: Option<i64>,
        /// The hub held it already (M§9.3).
        duplicate: Option<bool>,
        /// It went after an outage (M§9.4).
        after_outage: bool,
    },
    /// A welcome for another device of this identity (M§12.3 step 5).
    SiblingWelcome {
        /// Its cursor.
        cursor: Option<String>,
    },
    /// This device joined a successor (M§7.5).
    Successor {
        /// The successor.
        group: String,
        /// The dead group.
        of: String,
        /// Who created it.
        creator: String,
    },
    /// A successor's welcome declined (M§7.5).
    SuccessorDeclined {
        /// The successor declined.
        group: String,
        /// The dead group.
        of: String,
        /// Why.
        why: String,
    },
    /// A successor left for a lower one (M§7.5).
    SuccessorLeft {
        /// The successor left.
        group: String,
        /// The dead group.
        of: String,
    },
    /// Content from a leaf whose delegation no longer verifies (M§6.2).
    Unauthenticated {
        /// What.
        what: String,
    },
    /// An item that could not be processed, committed as handled (spec-gap 138).
    Unprocessable {
        /// Its class.
        class: String,
        /// Its cursor.
        cursor: Option<String>,
        /// Why.
        why: String,
    },
}
