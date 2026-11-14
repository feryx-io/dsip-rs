//! The typed values that cross the browser boundary (dsip-rs B1, B2, `impl/docs/dsip-stack-design.md` §6): what the
//! page passes in and gets back as JavaScript objects, with TypeScript declarations generated from these types and
//! from the library types they carry (`tsify`, `Ts<T>` on every parameter and return).
//!
//! Spec: none (infrastructure).
//!
//! Impl: values in the vectors' JSON shapes (`impl/vectors/README.md`) — the engine's `Emission`, flattened per kind,
//! the session and contacts snapshots (kind `state`) and the verifier's verdict (kind `envelope`) — are built as
//! JSON by the libraries and cannot be derived; their declarations below are written by hand, and `web/test/types`
//! checks them with `tsc` against every such value in the vectors. The other JSON values the libraries build (the
//! recording consent, the mailbox selection, the voicemail offer) are declared by hand beside their builders' shapes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tsify::Tsify;
use wasm_bindgen::prelude::*;

use dsip_endpoint::{CallOut, Command, InvitePatch};
use dsip_session::LocalEvent;

#[wasm_bindgen(typescript_custom_section)]
const EMISSION: &'static str = r#"
/** An engine emission, in the vectors' shape (README, kind `state`). Tokens a registry governs are `string`. */
export type Emission =
    | { send: SendEmission }
    | { timer: "start"; name: TimerName; seconds: number }
    | { timer: "stop" | "fire"; name: TimerName }
    | { media: "start" | "stop" | "apply_update" }
    | UiEmission
    | { queue: { to: string; type: string } }
    | { info: { about: string } }
    | { refused: "invalid-state" | "unknown-session" | "unknown-introduction" | "invalid-audience" | "unknown-grant" | "update-pending" | "no-pending-update" }
    | { revoke: string[] }
    | { keys: "rotated" | "seen"; scope: string; epoch: number }
    | { drop: "ended-session" | "duplicate-introduction" | "unknown-introduction" | "stale-update-reply" | "unknown-about" | "leg-terminated" | "not-attempt-scoped" }
    | { deliver: { leg: string; type: string; reason?: string; id?: string } }
    | { dequeue: { to: string; type: string; why: "expired" | "cancelled" } }
    | { forward: { type: string; status?: string; reason?: string; from: string } };

/** The §12.9 timers. */
export type TimerName = "T-Establish" | "T-Ring" | "T-Queue" | "T-Ring-Local";

/** A message the engine sends: its type, addressee and the fields its transitions set. */
export interface SendEmission {
    type: string;
    to: string;
    session?: string;
    id?: string;
    reason?: string;
    status?: string;
    ring_timeout?: number;
    answered_by?: string;
    in_reply_to?: string;
    grant?: string;
    scope?: string[];
    valid_until?: number;
    purpose?: string;
    contact_token?: string;
    presence_audience?: string;
    presence_keys?: unknown;
}

/** What the application shows. */
export type UiEmission =
    | { ui: "progress"; status: string }
    | { ui: "answered"; answered_by: string }
    | { ui: "offered" | "update_offered" | "missed_call" | "glare_retry" }
    | { ui: "update_rejected" | "ended" | "error" | "introduction_rejected"; reason: string }
    | { ui: "introduction_received"; from: string; token?: true }
    | { ui: "granted"; by: string };

/** A session's snapshot (README, kind `state`: `sessions`). */
export interface SessionSnapshot {
    role: "initiator" | "responder";
    state: string;
    renegotiating: boolean;
    outstanding_update: { id: string; direction: "outbound" | "inbound" } | null;
}

/** The first-contact state's snapshot (README, kind `state`: `contacts`): ids and identities. */
export interface ContactsSnapshot {
    allow: string[];
    grants_issued: string[];
    grants_held: string[];
    requests: string[];
    pending_sent: string[];
}

/** A frame's verdict, as the vectors' `expect` (README, kind `envelope`): an accept carries the verifier's extras
 *  (`type`, `signer`, `identity`, …) and, from `verify_frame`, the payload. */
export type FrameVerdict =
    | { verdict: "accept"; payload?: unknown; [extra: string]: unknown }
    | { verdict: "reject"; code: string; reason?: string };

/** The other side's recording in a call, as consent sees it (C§4). */
export interface RecordingConsent {
    disclosure: unknown;
    pending: boolean;
    hold_media: boolean;
    accepted: string[];
    ended: string | null;
}

/** An endpoint a reachability hint advertises (DHT Hints Profile §2): the signaling relay (`service` absent), or
 *  another service's entry with its fields. `bindings` defaults to `["ws/1.0"]` when a hint is signed. */
export interface HintEndpoint {
    uri: string;
    bindings: string[];
    service?: string;
    [field: string]: unknown;
}

/** A peer's mailbox, chosen (M§4.2): `entry` is the selected `DSIPMailbox` entry, `uri` its URI. */
export interface MailboxSelection {
    source: "did-document" | "hint" | null;
    selected: string | null;
    order: string[];
    sync_targets: string[];
    discarded: unknown[];
    uri: string | null;
    entry: { [field: string]: unknown } | null;
}

/** Whether a voicemail may be offered (M§13.2). */
export type VoicemailOffer = { offer: false } | { offer: true; kind: "audio" | "video"; max_duration_s?: number };
"#;

/// A JSON value with a declared TypeScript type, crossing the boundary as it is.
macro_rules! json_as {
    ($(#[$doc:meta])* $name:ident, $ts:literal) => {
        $(#[$doc])*
        #[derive(Serialize, Deserialize, Tsify, Default)]
        #[serde(transparent)]
        #[tsify(type = $ts, hashmap_as_object, missing_as_null)]
        pub struct $name(pub Value);
    };
}

json_as!(
    /// A JSON value the boundary does not look into: a payload, a claim, a DID document, a policy.
    Json, "unknown"
);
json_as!(
    /// The named sessions' snapshots, `null` for an unknown id.
    Sessions, "Record<string, SessionSnapshot | null>"
);
json_as!(
    /// The first-contact state's snapshot.
    Contacts, "ContactsSnapshot"
);
json_as!(
    /// A frame's verdict.
    Verdict, "FrameVerdict"
);
json_as!(
    /// The other side's recording in a call.
    Consent, "RecordingConsent"
);
json_as!(
    /// Endpoints to sign into a hint.
    HintEndpoints, "(Omit<HintEndpoint, 'bindings'> & { bindings?: string[] })[]"
);
json_as!(
    /// A chosen mailbox.
    Mailbox, "MailboxSelection"
);
json_as!(
    /// A voicemail offer, or none.
    Voicemail, "VoicemailOffer"
);

/// What a call-path method returns: the call glue's outputs, in order.
#[derive(Serialize, Tsify)]
#[tsify(hashmap_as_object, missing_as_null)]
pub struct CallOuts(pub Vec<CallOut>);

/// What [`crate::Endpoint::place`] returns: the session id at once, and the first outputs (the request for the SDP
/// offer; the invite goes out when the page hands it back).
#[derive(Serialize, Tsify)]
#[tsify(hashmap_as_object, missing_as_null)]
pub struct Placed {
    /// The session (= invite) id.
    pub session: String,
    /// The outputs.
    pub events: Vec<CallOut>,
}

/// A local event (README vocabulary), with what the host supplies for its message beside it.
#[derive(Deserialize, Tsify)]
// tsify writes a flattened union as `interface … extends`, which TypeScript refuses
#[tsify(type = "LocalEvent & { sdp?: string; claims?: unknown[]; patch?: InvitePatch; data?: unknown }")]
pub struct LocalCommand {
    /// The engine event.
    #[serde(flatten)]
    pub event: LocalEvent,
    /// The SDP (`place_call`, `accept`, `update`, `answer_update`).
    #[serde(default)]
    #[tsify(optional)]
    pub sdp: Option<String>,
    /// `identity.claims` (`place_call`, §18.1).
    #[serde(default)]
    #[tsify(type = "unknown[]", optional)]
    pub claims: Vec<Value>,
    /// Changes to the offer (`place_call`: C§6, N§4.1).
    #[serde(default)]
    #[tsify(optional)]
    pub patch: Option<InvitePatch>,
    /// The `info` data (B§4); without it, an empty `info`.
    #[serde(default)]
    #[tsify(type = "unknown", optional)]
    pub data: Option<Value>,
}

impl LocalCommand {
    /// As the core's [`Command`].
    pub fn into_command(self) -> Command {
        let LocalCommand { event, sdp, claims, patch, data } = self;
        match event {
            LocalEvent::PlaceCall { session, to } => {
                Command::PlaceCall { session, to, invite: dsip_endpoint::Invite { sdp, claims, patch: patch.unwrap_or_default() } }
            }
            LocalEvent::Accept { session, answered_by } => Command::Accept { session, answered_by, sdp },
            LocalEvent::Update { session, id, answered_by } => Command::Update { session, id, answered_by, sdp },
            LocalEvent::AnswerUpdate { session, in_reply_to, answered_by } => Command::AnswerUpdate { session, in_reply_to, answered_by, sdp },
            LocalEvent::Info { session } => match data {
                Some(data) => Command::Info { session, data },
                None => Command::Engine(LocalEvent::Info { session }),
            },
            other => Command::Engine(other),
        }
    }
}

/// An [`crate::Endpoint`]'s configuration; every field may be left out.
#[derive(Deserialize, Tsify, Default)]
#[serde(default)]
pub struct EndpointConfig {
    /// Whether offers carry video.
    #[tsify(optional)]
    pub video: Option<bool>,
    /// Whether an unknown caller must introduce themselves first (§19.4).
    #[tsify(optional)]
    pub first_contact_required: Option<bool>,
    /// T-Establish, seconds (§12.9).
    #[tsify(optional)]
    pub t_establish: Option<i64>,
    /// T-Ring, seconds (§12.9).
    #[tsify(optional)]
    pub t_ring: Option<i64>,
    /// T-Ring-Local, seconds (§12.9).
    #[tsify(optional)]
    pub t_ring_local: Option<i64>,
    /// Whether outbound session bodies are sealed (§10.4).
    #[tsify(optional)]
    pub seal: Option<bool>,
    /// What an incoming call does: `ring` when left out or not one of these.
    #[tsify(optional, type = "\"ring\" | \"accept\" | \"screen\" | \"decline\" | \"silent\"")]
    pub answer: Option<String>,
    /// Whether the other side's recording is accepted (C§4): `ask` when left out or not one of these.
    #[tsify(optional, type = "\"ask\" | \"always\" | \"never\"")]
    pub recording: Option<String>,
    /// One call at a time.
    #[tsify(optional)]
    pub one_call: Option<bool>,
    /// Whether this device seals its presence records (P§12).
    #[tsify(optional)]
    pub seal_presence: Option<bool>,
    /// The labels of the audiences sealed beside `main` (P§12.1).
    #[tsify(optional)]
    pub presence_audiences: Vec<String>,
    /// The presence key rotation interval, seconds (P§12.5).
    #[tsify(optional)]
    pub t_presence_rotate: Option<i64>,
}

/// Our DIDs and display name.
#[derive(Serialize, Tsify)]
pub struct Whoami {
    /// The identity.
    pub identity: String,
    /// This device.
    pub device: String,
    /// The name shown.
    pub display_name: String,
}

/// The relay's `hello`, verified or not (§13.2, §20.5).
#[derive(Serialize, Tsify)]
#[serde(untagged)]
#[tsify(hashmap_as_object, missing_as_null)]
pub enum RelayHello {
    /// Verified.
    Ok {
        /// `true`.
        #[tsify(type = "true")]
        ok: bool,
        /// The relay's DID.
        did: String,
        /// What it advertises.
        #[tsify(type = "unknown")]
        capabilities: Value,
    },
    /// Refused.
    Refused {
        /// `false`.
        #[tsify(type = "false")]
        ok: bool,
        /// The verdict's code.
        #[tsify(type = "unknown")]
        code: Value,
        /// Why.
        #[tsify(type = "string | null")]
        detail: Option<String>,
    },
}

/// Whether this device seals its presence records (P§12.1, P§12.6).
#[derive(Serialize, Tsify)]
#[tsify(hashmap_as_object)]
pub struct SealingStatus {
    /// Whether records with no audience are sealed.
    pub sealed: bool,
    /// The sealed audiences' labels, to their wire tags.
    pub audiences: BTreeMap<String, String>,
    /// Why sealing that was asked for cannot be done.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[tsify(optional)]
    pub reason: Option<String>,
}

/// The presence states being published, by audience (`""`: no audience).
#[derive(Serialize, Tsify)]
#[serde(transparent)]
#[tsify(hashmap_as_object)]
pub struct PresenceStates(pub BTreeMap<String, String>);

/// A signed presence `subscribe` (§9.3).
#[derive(Serialize, Tsify)]
pub struct PresenceSubscription {
    /// The frame to send.
    pub frame: String,
    /// The subscription's id.
    pub subscription: String,
    /// How many grants it presents (P§6).
    pub grants: usize,
}

/// A watched identity's presence (P§4, P§12.4).
#[derive(Serialize, Tsify)]
pub struct Presence {
    /// The identity watched.
    pub target: String,
    /// The effective state (a `dsip-presence-state` value).
    pub state: String,
    /// The token that won, shown raw when unknown (P§5).
    pub token: String,
    /// `record`, `assertion` (the authority's claim) or `none`.
    pub source: String,
    /// How many verified records are held.
    pub records: usize,
    /// The devices whose sealed records we hold no key for.
    pub unreadable: Vec<String>,
    /// Whether the subscription ended.
    pub terminated: bool,
}

/// Our own watch's `notify`, which may raise our epochs: the events, driven like [`crate::Endpoint::local`]'s.
#[derive(Serialize, Tsify)]
#[tsify(hashmap_as_object, missing_as_null)]
pub struct OwnPresence {
    /// `true`.
    #[tsify(type = "true")]
    pub own: bool,
    /// Our identity.
    pub target: String,
    /// The outputs.
    pub events: Vec<CallOut>,
    /// Whether the subscription ended.
    pub terminated: bool,
}

/// What a presence `notify` gives.
#[derive(Serialize, Tsify)]
#[serde(untagged)]
#[tsify(hashmap_as_object, missing_as_null)]
pub enum Notified {
    /// Another identity's presence.
    Presence(Presence),
    /// Our own watch.
    Own(OwnPresence),
}

/// Every watched identity's presence.
#[derive(Serialize, Tsify)]
#[serde(transparent)]
pub struct Presences(pub Vec<Presence>);

/// The pending introductions, `[id, identity]` each.
#[derive(Serialize, Tsify)]
#[serde(transparent)]
pub struct Requests(pub Vec<(String, String)>);

/// The stored contacts the N§5 check reads.
#[derive(Deserialize, Tsify)]
#[serde(transparent)]
pub struct NumberContacts(pub Vec<dsip_number::Contact>);

/// A hint, folded to its winner (§8.3): never authority (§8.1 rule 6).
#[derive(Serialize, Tsify)]
#[tsify(hashmap_as_object, missing_as_null)]
pub struct HintSelection {
    /// The winner, if one verifies for the DID.
    #[tsify(type = "SelectedHint | null")]
    pub hint: Option<SelectedHint>,
    /// Every candidate's verdict, in order.
    #[tsify(type = "FrameVerdict[]")]
    pub report: Vec<Value>,
}

/// The winning hint.
#[derive(Serialize, Tsify)]
pub struct SelectedHint {
    /// The signaling endpoint's URI (profile §2: `service` absent), else the first endpoint's.
    #[tsify(type = "string | null")]
    pub uri: Option<String>,
    /// Its bindings.
    #[tsify(type = "string[] | null")]
    pub bindings: Option<Vec<String>>,
    /// Every endpoint.
    #[tsify(type = "HintEndpoint[]")]
    pub endpoints: Vec<dsip_dht::record::Endpoint>,
    /// The publisher's sequence number.
    pub seq: i64,
    /// Issued at.
    pub issued_at: i64,
    /// Expires at.
    pub expires_at: i64,
    /// The signing DID (device or subject).
    pub signer: String,
}

/// A [`crate::messaging::Messenger`] step's outputs, in order: frames to send and events (dsip-rs B3a).
#[derive(Serialize, Tsify)]
#[serde(transparent)]
#[tsify(hashmap_as_object, missing_as_null)]
pub struct Events(pub Vec<dsip_messaging_device::Event>);

/// Groups whose hub is unreachable, by group (M§9.4).
#[derive(Serialize, Tsify)]
#[serde(transparent)]
#[tsify(hashmap_as_object, missing_as_null)]
pub struct Outages(pub BTreeMap<String, dsip_messaging_device::Outage>);

/// Grants held from others, `{identity: compact envelope}` (§19.4).
#[derive(Deserialize, Tsify, Default)]
#[serde(transparent)]
#[tsify(hashmap_as_object)]
pub struct Grants(pub BTreeMap<String, String>);

/// JSON values by identity or id: `key-packages` answers, introductions.
#[derive(Serialize, Deserialize, Tsify, Default)]
#[serde(transparent)]
#[tsify(type = "Record<string, unknown>", hashmap_as_object, missing_as_null)]
pub struct ByIdentity(pub BTreeMap<String, Value>);
