//! The messaging device, sans-I/O: this identity's device key under its delegation, its MLS groups and the state
//! the Messaging Profile asks a device to keep, emitting frames and typed [`Event`]s (dsip-rs B3a; its other inputs
//! and results are still JSON text until B3b). The host moves frames between it and the mailbox and keeps the clock. The browser (`dsip-wasm`) and dsip-msg are its hosts,
//! which set its timeouts and nothing else of its behaviour.
//!
//! Spec: M§4.2 (the mailbox a `did:key` identity names in its reachability hint; the peer's found the same way),
//! M§4.3 (bind with a verified `hello`; the delegation carries `dsip.messaging`), M§5.2–M§5.5 (`deposit`,
//! `accepted`, `sync`/`items`, `key-packages`/`key-package-fetch`), M§6.2 (every leaf authenticated), M§6.4 (wire
//! forms), M§6.5 (a commit is applied only on the hub's `accepted`; refusals as the vector-pinned `CommitRetry`
//! decides, spec-gap 58; seq gaps held by `GapTracker`, spec-gap 69), M§6.6 (`mailbox-config` `joined`/`left`),
//! M§6.7 (KeyPackages uploaded), M§7.1 (the personal group and the first archive key), M§7.2 (a direct
//! conversation: the peer's devices and our own in one commit, hubbed at our mailbox, the held grant presented),
//! M§8.1 (content objects checked before rendering), M§8.5 (seq dedup and the ack cursor — `Resume`, spec-gap 44),
//! M§9.2–M§9.3 (pending until `accepted`; the same bytes re-deposited), M§10.2 (delivered receipts decided per sync
//! batch by the vector-pinned `Client`), M§12.1 (the archive key, kept for the device that will read history),
//! M§14.2 (a grant presented to the peer's mailbox), M§8.4 and M§5.6 (a blob sealed under a single-use key, uploaded
//! with a signed `blob-put`, named with its key in the content and without it in the manifest; fetched from the
//! sources the pinned rule orders and verified before it is opened), M§8.2 (`audio` content), M§10.4 (`played`, under
//! the same opt-in as `read`), M§13.2–M§13.3 (voicemail as caller-recorded audio carrying the session; a callee
//! leg's call event to the personal group, collapsed by session, interleaved into the peer's timeline), M§9.4 (a hub
//! that stops answering: content kept pending and retried by the pinned outbox, and past the device's threshold handed
//! to a successor), M§7.5 (the successor created at this identity's mailbox, re-adding the dead group's roster;
//! a successor welcome checked and converged on by the pinned tracker), M§12.1–M§12.3 (archive keys, archive records written for what
//! is shown and read back as history by a device added later, every live key re-sent to a new sibling), M§10.3 and
//! M§10.5 (a read watermark per conversation, disclosed only with the opt-in, else to the personal group).
//!
//! Impl: MLS state lives in the host's [`Store`]: in the browser OpenMLS's memory storage, exported with the delivery
//! state in one `save()` that the host writes as one record after each step — the atomic commit of spec-gap 44 in a
//! browser; natively a SQLite database, where each item's MLS writes and delivery state commit in one transaction and
//! the host writes [`Messenger::state`] after each step. A reload restores both. Pending deposits (not yet `accepted`) are kept with their bytes and re-deposited on the next bind (M§9.3:
//! idempotent at the hub by digest). The no-answer timeout (M§9.4) is the host's to set: spec-gap 72 counts a deposit
//! with no answer as the hub unreachable without saying after how long.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde_json::{json, Value};

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::version::Supported;
use dsip_endpoint::hello::{client_hello, verify_relay_hello, RelayHello};
use dsip_endpoint::verify::SeenIds;
use dsip_endpoint::IdentityKeys;
use crate::commits::{self, Answer, Change, Synced};
use crate::history::{self, Decision, Restored};
use crate::receipts::{self, Emission};
use crate::successors::{self, Converge, Create, Successors};
use crate::{archive, blob, calls, first_contact, key_packages, CallLog, process, recording, Deposit, Deposits, History, Inbound, MemoryStore, Outbox, Outcome,
    Receipts, Retry, Route};
use crate::Store;
use crate::events::{Event, HandedOver, NewRecorder, OpInfo, Rejected, SuccessorDue, Ui};
use crate::types::{Available, ArchiveKey, BlobRef, CallEnded, CallLeg, CallRecorded, Conversation, FetchDecision, Granted, Hub, Introduction,
    KeyPackageDevice, Outage, ReceiptPolicy, RecordingAccepted, SealedBlob, Sent};
use dsip_messaging::client::{registration_on_removal, GapTracker, MoveArrival, Resume};
use dsip_messaging::verify::verify_frame;
use dsip_messaging::mls_wire::{open, seal, SealUse};
use dsip_messaging::wire;
use dsip_mls::{authenticate_key_package, conversation_extension, digest, member_identity, Device, MlsError};
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;


fn b64(bytes: &[u8]) -> String {
    dsip_core::b64::encode(bytes)
}

fn unb64(v: &Value) -> Vec<u8> {
    v.as_str().and_then(dsip_core::b64::decode).unwrap_or_default()
}

fn s_of(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn compact(e: &Envelope) -> String {
    format!("{}.{}.{}", e.protected, e.payload, e.signature)
}

/// Seconds before a deposit with no answer at all counts as the hub unreachable (M§9.4), until the host sets it.
///
/// Impl: spec-gap 72 sets no time; 60 s covers a slow mobile link (the browser's), dsip-msg sets 20.
const NO_ANSWER_S: i64 = 60;

/// One group this device is in.
struct Conv {
    group: MlsGroup,
    conversation: String,
    kind: String,
    /// `(did, uri)` of the hub.
    hub: (String, String),
    /// The other identity of a direct conversation, once known.
    peer: Option<String>,
    /// M§10 receipts for this conversation (vector-pinned).
    receipts: Receipts,
    /// The epoch this device joined at: items from before are history (M§12.3), not for this device's MLS state.
    joined_epoch: u64,
}

/// A membership change this device proposes (M§6.5): re-proposed after a lost conflict while still needed.
#[derive(Clone)]
enum Op {
    /// Add `peer`'s devices (and our own others) from these TLS-serialized KeyPackages, with the grants that
    /// authorize the add (M§14.2). `device` names one device of our own identity when that is what is added (M§12.3).
    Add { peer: String, kps: Vec<Vec<u8>>, grants: Vec<String>, device: Option<String> },
    /// Join the group by external commit from the latest GroupInfo this identity's mailbox delivered (M§6.8).
    Rejoin,
    /// Commit the pending Remove proposals by which `identity` leaves (M§7.3 "Leaving", spec-gap 125).
    Leave { identity: String },
    /// Remove every leaf of another member identity (M§7.3: any member identity MAY remove another).
    Remove { identity: String },
    /// Move the group to another hub, `{did, uri}`: a commit changing `dsip_conversation.hub` and nothing else (M§7.4).
    MoveHub { hub: Value },
    /// Refresh this device's own leaf key material (post-compromise security).
    Update,
    /// Remove the leaves whose credential names `device`, whether or not they still authenticate (M§7.3, M§12.4:
    /// a revoked device's leaf no longer does, spec-gap 57). `rotate`: a new archive key follows the merge (M§12.4).
    RemoveDevice { device: String, rotate: bool },
}

/// A deposit awaiting the hub's answer, by deposit id (M§9.2).
#[derive(Clone)]
enum Pending {
    /// A commit staged in the group: merged on `accepted`, discarded on refusal (M§6.5). `fields` are the deposit's,
    /// re-deposited as the same MLS bytes when the answer is lost (M§9.3).
    Commit { gid: String, op: Option<Op>, fields: Value },
    /// A GroupInfo for the hub (M§6.5 rule 6); `then` is proposed once it is accepted.
    GroupInfo { gid: String, then: Option<Op> },
    /// An application message of this device's own, in the outbox until accepted (M§9.2).
    Application { gid: String, item: String },
    /// The archive key is sent to the personal group once its GroupInfo is accepted (M§7.1).
    PersonalReady { gid: String },
    /// A KeyPackage upload (M§5.5).
    KeyPackages { count: usize },
    /// A `mailbox-config` (M§6.6) with these fields.
    Config { fields: Value },
    /// An archive record deposited to our mailbox (M§12.2) with these fields; acknowledged, nothing else to do.
    Archive { fields: Value },
    /// A Remove proposal of this device's leave (M§7.3): sequenced by the hub, nothing to merge.
    Proposal { gid: String },
}

impl Op {
    /// What the commit does, for the host to say (no key material).
    fn describe(&self) -> OpInfo {
        match self {
            Op::Add { peer, device, kps, .. } => OpInfo::Add { peer: peer.clone(), device: device.clone(), devices: kps.len() },
            Op::Rejoin => OpInfo::Rejoin,
            Op::Leave { identity } => OpInfo::Leave { identity: identity.clone() },
            Op::Remove { identity } => OpInfo::Remove { identity: identity.clone() },
            Op::MoveHub { hub } => OpInfo::MoveHub { hub: hub.clone() },
            Op::Update => OpInfo::Update,
            Op::RemoveDevice { device, .. } => OpInfo::RemoveDevice { device: device.clone() },
        }
    }

    fn to_json(&self) -> Value {
        match self {
            Op::Add { peer, kps, grants, device } => {
                json!({"add": {"peer": peer, "kps": kps.iter().map(|k| b64(k)).collect::<Vec<_>>(), "grants": grants, "device": device}})
            }
            Op::Rejoin => json!("rejoin"),
            Op::Leave { identity } => json!({"leave": identity}),
            Op::Remove { identity } => json!({"remove": identity}),
            Op::MoveHub { hub } => json!({"move_hub": hub}),
            Op::Update => json!("update"),
            Op::RemoveDevice { device, rotate } => json!({"remove_device": device, "rotate": rotate}),
        }
    }

    fn from_json(v: &Value) -> Option<Op> {
        if v == "rejoin" {
            return Some(Op::Rejoin);
        }
        if v == "update" {
            return Some(Op::Update);
        }
        if let Some(d) = v.get("remove_device").and_then(Value::as_str) {
            return Some(Op::RemoveDevice { device: d.to_string(), rotate: v["rotate"].as_bool().unwrap_or(false) });
        }
        if let Some(i) = v.get("leave").and_then(Value::as_str) {
            return Some(Op::Leave { identity: i.to_string() });
        }
        if let Some(i) = v.get("remove").and_then(Value::as_str) {
            return Some(Op::Remove { identity: i.to_string() });
        }
        if let Some(h) = v.get("move_hub") {
            return Some(Op::MoveHub { hub: h.clone() });
        }
        let a = v.get("add")?;
        Some(Op::Add {
            peer: s_of(&a["peer"]),
            kps: a["kps"].as_array()?.iter().map(unb64).collect(),
            grants: serde_json::from_value(a["grants"].clone()).unwrap_or_default(),
            device: a["device"].as_str().map(String::from),
        })
    }
}

impl Pending {
    /// The group a deposit was for, if any.
    fn gid(&self) -> Option<&str> {
        match self {
            Pending::Commit { gid, .. } | Pending::GroupInfo { gid, .. } | Pending::Application { gid, .. } | Pending::PersonalReady { gid }
            | Pending::Proposal { gid } => Some(gid),
            Pending::KeyPackages { .. } | Pending::Config { .. } | Pending::Archive { .. } => None,
        }
    }

    /// What survives a restart: everything but application items, which the outbox holds (M§9.2), and key package
    /// uploads, made afresh.
    fn to_json(&self) -> Option<Value> {
        Some(match self {
            Pending::Commit { gid, op, fields } => json!({"commit": {"gid": gid, "op": op.as_ref().map(Op::to_json), "fields": fields}}),
            Pending::GroupInfo { gid, then } => json!({"group_info": {"gid": gid, "then": then.as_ref().map(Op::to_json)}}),
            Pending::PersonalReady { gid } => json!({"personal_ready": gid}),
            Pending::Config { fields } => json!({"config": fields}),
            Pending::Archive { fields } => json!({"archive": fields}),
            Pending::Application { .. } | Pending::KeyPackages { .. } | Pending::Proposal { .. } => return None,
        })
    }

    fn from_json(v: &Value) -> Option<Pending> {
        let op = |o: &Value| if o.is_null() { None } else { Op::from_json(o) };
        if let Some(c) = v.get("commit") {
            return Some(Pending::Commit { gid: s_of(&c["gid"]), op: op(&c["op"]), fields: c["fields"].clone() });
        }
        if let Some(g) = v.get("group_info") {
            return Some(Pending::GroupInfo { gid: s_of(&g["gid"]), then: op(&g["then"]) });
        }
        if let Some(g) = v.get("personal_ready") {
            return Some(Pending::PersonalReady { gid: s_of(g) });
        }
        if let Some(f) = v.get("config") {
            return Some(Pending::Config { fields: f.clone() });
        }
        v.get("archive").map(|f| Pending::Archive { fields: f.clone() })
    }
}

/// A messaging device: this identity's device key under its delegation, its MLS groups, and the state the
/// Messaging Profile asks a device to keep (M§5.4, M§8.5). The host moves frames between it and the mailbox.
pub struct Messenger<S: Store = MemoryStore> {
    keys: IdentityKeys,
    /// The identity's X25519 key agreement secrets, the delegated key's first (core §7.3, spec-gap 179).
    key_agreement_secrets: Vec<[u8; 32]>,
    /// Verified key agreement delegations of other identities, from their hints (core §7.3): introductions to them are
    /// sealed to the key the current one names.
    key_agreements: Vec<Value>,
    mls: Device<S>,
    mailbox: (String, String),
    resolver: StaticResolver,
    seen: SeenIds,
    supported: Supported,
    /// Hello ids sent and not yet answered: one per connection being opened (§20.5 anti-splicing).
    hello_ids: BTreeSet<String>,
    counter: u64,
    convs: BTreeMap<String, Conv>,
    /// Content and receipts of the sync being processed, per group (M§10.2 decides per batch).
    batch: receipts::Batch,
    personal: Option<String>,
    resume: Resume,
    /// Digests of this device's own deposits: the hub fans them back and MLS cannot decrypt them (spec-gap 47).
    own: HashSet<String>,
    /// Deposits awaiting their answer, by deposit id: what each was, the hub it went to, when an application deposit
    /// went out (M§9.4), and those the group's new hub refused before it hosted the group, due again (spec-gap 129).
    pending: Deposits<Pending>,
    /// Application items not yet accepted, per group, oldest first: `{id, mls, obj}` (M§9.2).
    outbox: Outbox,
    /// The thread, every content object shown, in arrival order: `{group, key, sender, sender_device, object, seq, mine}`.
    messages: Vec<Value>,
    /// Object keys shown (M§8.5: the archive and MLS copies are one message).
    shown: BTreeSet<String>,
    /// Grants other identities issued to this one, by granter: compact envelopes (§19.4; presented at M§14.2).
    grants_held: BTreeMap<String, String>,
    /// Archive keys by `akid`: `(key, created_at)` (M§12.1).
    archive_keys: BTreeMap<String, (Vec<u8>, i64)>,
    /// The latest GroupInfo per group (M§6.8), base64url.
    group_info: BTreeMap<String, String>,
    /// Call events of this identity's devices, in personal-group order, one per `session` (M§13.3, spec-gap 63).
    calls: CallLog,
    /// Seq gaps per group (M§6.5, spec-gap 69), and the items held behind them.
    gaps: BTreeMap<String, GapTracker>,
    held_items: BTreeMap<String, Vec<Value>>,
    /// Membership changes refused by the hub and waiting for a sync before re-proposal (spec-gap 58).
    retries: BTreeMap<String, (Retry, Op)>,
    /// The hub that answered a deposit `mailbox.unknown-group`, by group: after the sync, a different hub means the
    /// group moved (M§7.4 "A member that missed the move").
    unknown_at: BTreeMap<String, String>,
    /// Application items refused `mailbox.unknown-group`, by group, held until the sync shows whether the group moved:
    /// re-encrypted and re-sent to the new hub if it did, refused for good if not (M§7.4).
    moved_items: BTreeMap<String, Vec<String>>,
    /// M§7.4 (spec-gap 129): per group that moved, the vector-pinned wait for its new hub to host it, and the deposits
    /// it answered `mailbox.unknown-group` before then, due again at a time (the same bytes, M§9.3).
    arrivals: BTreeMap<String, MoveArrival>,
    /// Introductions delivered through the mailbox, by id (M§14.1: requests, never messages).
    requests: BTreeMap<String, Value>,
    want_live: bool,
    gap_timeout: i64,
    /// History (M§12): archive keys and join epochs, what to archive, records held until their key arrives.
    history: History,
    /// Archive records under a key this device does not hold yet, by cursor, still sealed (M§12.3 step 5).
    held_archive: BTreeMap<String, Value>,
    /// Content and receipts opened from archive and waiting for their conversation to be joined (spec-gap 64).
    restored: Restored,
    /// M§10.5: whether read watermarks are disclosed to the conversation (opt-in) or kept in the personal group.
    read_disclosed: bool,
    /// What this device discloses (M§10.5, M§11): the receipts machine's policy, `{delivered, read, played, activity}`.
    policy: Value,
    /// M§7.5: the successor groups this device knows of and converged on (vector-pinned, spec-gap 61).
    successors: Successors,
    /// Objects of an abandoned group's outbox, by the group they go to: the dead group until its successor exists,
    /// then the successor until it holds its members (M§9.4: re-encrypted for the successor, spec-gap 72).
    handover: BTreeMap<String, Vec<Value>>,
    /// The mailbox this state was saved at; a different one at start is a move. Spec: M§4.1 "Moving to another
    /// mailbox" (v0.13, spec-gap 122): the device registers every group it is in at the new mailbox and syncs it from
    /// the start.
    moved_from: Option<String>,
    /// Whether this device's delegation carries `dsip.record` (C§5): a recorder device, receive-only, never in its
    /// identity's personal group; as a record-keeper it keeps the `call-record`s parties send it (C§9).
    recorder: bool,
    /// This device's call records not yet handed to the conversation with its record-keeper, oldest first (C§9: held
    /// until that conversation exists, spec-gap 123).
    records_held: Vec<Value>,
    /// TEST ONLY: a recorder device that sends content anyway, so members can be shown dropping it (C§5). Not saved.
    recorder_sends: bool,
    /// The recorder devices each conversation was last shown with (C§5): a change is rendered. Not saved: what a
    /// conversation is recorded by at start is in [`Messenger::conversations`].
    recording_seen: BTreeMap<String, BTreeSet<String>>,
    /// As a record-keeper: the records received, `{group, from, device, received_at, record}`, one per session leg.
    records: Vec<Value>,
    /// Recorder devices this identity accepted, by conversation id: this device's acceptances and its siblings', from
    /// the `recording-acceptance` objects in the personal group (C§5: the union).
    recording_accepted: BTreeMap<String, BTreeSet<String>>,
    /// Groups this identity is leaving (M§7.3): nothing is sent there and they are not listed; the device proposes its
    /// identity's removal again at each new epoch until a commit removes it.
    leaving: BTreeSet<String>,
    /// Each group's roster changes by identity, oldest first: `{seq, epoch, by, added, removed, left}` (M§7.3: every
    /// roster change rendered, attributed to the committing identity).
    roster_log: BTreeMap<String, Vec<Value>>,
    /// Object keys of the messages this device's user deleted ([`Messenger::forget_message`]): kept out of `shown`'s
    /// rebuild, so a copy from the archive or MLS is not shown again.
    forgotten: BTreeSet<String>,
}

impl Messenger<MemoryStore> {
    /// The browser's device: `identity_json` as returned by `create_identity`; `mailbox_did`/`mailbox_uri` this
    /// identity's mailbox (M§4.2: the operator's, from `config.json`, or the person's); `saved_json` what
    /// [`Messenger::save`] returned, or null for a fresh device.
    pub fn new(identity_json: &str, mailbox_did: &str, mailbox_uri: &str, saved_json: Option<String>, now: f64) -> Result<Messenger, Error> {
        let saved: Value = saved_json.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
        // the MLS storage as saved: `{b64url key: b64url value}`
        let store = MemoryStore::from_mls_json(&saved["mls"]);
        Messenger::open(identity_json, mailbox_did, mailbox_uri, store, &saved["state"], now)
    }

    /// Everything to keep: the MLS storage and this device's delivery state, as one JSON record. The host writes it
    /// after every step that returned something (spec-gap 44: MLS state and delivery state committed together).
    pub fn save(&self) -> String {
        json!({"mls": self.mls.provider().mls_json(), "state": self.state()}).to_string()
    }
}

impl<S: Store> Messenger<S> {
    /// A device over `store`, which holds its MLS state, with the delivery state `state` that [`Messenger::state`]
    /// returned (null for a fresh device).
    pub fn open(identity_json: &str, mailbox_did: &str, mailbox_uri: &str, store: S, state: &Value, now: f64) -> Result<Messenger<S>, Error> {
        let id: Value = serde_json::from_str(identity_json).map_err(err)?;
        let device = KeyPair::from_seed(unhex(id["device_seed_hex"].as_str().unwrap_or(""))?);
        let delegation = Envelope::from_frame(id["delegation"].as_str().unwrap_or("")).map_err(|v| Error::from(format!("{:?}", v.code)))?;
        let keys = IdentityKeys {
            identity: id["identity"].as_str().unwrap_or("").to_string(),
            device: device.clone(),
            delegation: delegation.clone(),
            display_name: id["display_name"].as_str().unwrap_or("").to_string(),
        };
        let controller_seed = id["controller_seed_hex"].as_str().and_then(|h| unhex(h).ok());
        let key_agreement_secrets: Vec<[u8; 32]> = id["key_agreement_secret_hex"]
            .as_str()
            .and_then(|h| unhex(h).ok())
            .into_iter()
            .chain(controller_seed.map(|s| dsip_messaging::first_contact::x25519_from_ed25519_seed(&s)))
            .collect();
        let mls = Device::with_provider(device, compact(&delegation), store);
        let st = state;
        let now_i = now as i64;
        let mut m = Messenger {
            keys,
            key_agreement_secrets,
            key_agreements: vec![],
            mls,
            mailbox: (mailbox_did.to_string(), mailbox_uri.to_string()),
            resolver: StaticResolver::default(),
            seen: SeenIds::default(),
            supported: Supported::all_known(),
            hello_ids: BTreeSet::new(),
            counter: 0,
            convs: BTreeMap::new(),
            batch: receipts::Batch::default(),
            personal: st["personal"].as_str().map(String::from),
            resume: Resume::new(if st["resume"].is_object() { &st["resume"] } else { &Value::Null }),
            own: st["own"].as_array().into_iter().flatten().map(s_of).collect(),
            // M§9.3: deposits awaiting an answer are sent again at the next binding (redeposit_pending)
            pending: {
                let mut d = Deposits::new(NO_ANSWER_S);
                for (id, p) in st["pending"].as_object().into_iter().flatten() {
                    if let Some(p) = Pending::from_json(p) {
                        d.insert(id.clone(), p);
                    }
                }
                d
            },
            outbox: Outbox { items: serde_json::from_value(st["outbox"].clone()).unwrap_or_default(), ..Outbox::new(dsip_messaging::client::HUB_TIMEOUT_S) },
            // a key saved by the browser before the sender was in it (`conversation:id`) is made again (M§8.5)
            messages: st["messages"].as_array().cloned().unwrap_or_default().into_iter()
                .map(|mut m| { m["key"] = json!(history::object_key(&m["object"])); m }).collect(),
            shown: st["messages"].as_array().into_iter().flatten().map(|m| history::object_key(&m["object"]))
                .chain(st["forgotten"].as_array().into_iter().flatten().filter_map(|k| k.as_str().map(String::from))).collect(),
            grants_held: serde_json::from_value(st["grants_held"].clone()).unwrap_or_default(),
            archive_keys: st["archive_keys"].as_object().into_iter().flatten()
                .map(|(a, v)| (a.clone(), (unb64(&v["key"]), v["created_at"].as_i64().unwrap_or(0)))).collect(),
            group_info: serde_json::from_value(st["group_info"].clone()).unwrap_or_default(),
            calls: serde_json::from_value(st["calls"].clone()).unwrap_or_default(),
            gaps: BTreeMap::new(),
            held_items: serde_json::from_value(st["held_items"].clone()).unwrap_or_default(),
            retries: BTreeMap::new(),
            unknown_at: BTreeMap::new(),
            moved_items: BTreeMap::new(),
            arrivals: BTreeMap::new(),
            requests: serde_json::from_value(st["requests"].clone()).unwrap_or_default(),
            want_live: false,
            gap_timeout: dsip_messaging::client::GAP_TIMEOUT_S,
            history: History::default(),
            held_archive: serde_json::from_value(st["held_archive"].clone()).unwrap_or_default(),
            restored: Restored::from_items(st["restored"].as_array().cloned().unwrap_or_default()),
            read_disclosed: st["read_disclosed"].as_bool().unwrap_or(false),
            policy: st.get("policy").filter(|p| p.is_object()).cloned().unwrap_or_else(|| {
                let d = st["read_disclosed"].as_bool().unwrap_or(false);
                json!({"delivered": true, "read": d, "played": d})
            }),
            successors: serde_json::from_value(st["successors"].clone()).unwrap_or_default(),
            handover: serde_json::from_value(st["handover"].clone()).unwrap_or_default(),
            moved_from: st["mailbox"].as_str().filter(|d| *d != mailbox_did).map(String::from),
            recorder: dsip_core::delegation::capabilities(&delegation).iter().any(|c| c == "dsip.record"),
            records_held: st["records_held"].as_array().cloned().unwrap_or_default(),
            recorder_sends: false,
            recording_seen: BTreeMap::new(),
            records: st["records"].as_array().cloned().unwrap_or_default(),
            recording_accepted: serde_json::from_value(st["recording_accepted"].clone()).unwrap_or_default(),
            leaving: serde_json::from_value(st["leaving"].clone()).unwrap_or_default(),
            roster_log: serde_json::from_value(st["roster_log"].clone()).unwrap_or_default(),
            forgotten: serde_json::from_value(st["forgotten"].clone()).unwrap_or_default(),
        };
        if let Some(t) = st["hub_timeout"].as_i64() {
            m.outbox.hub_timeout = t;
        }
        if m.moved_from.is_some() {
            // spec-gap 122: the cursors were the old mailbox's; the new one delivers from its own beginning
            m.resume.cursor_invalid();
        }
        // M§9.4: an outage survives a restart; its first retry is due at once
        for (gid, down_since) in st["outages"].as_object().into_iter().flatten() {
            m.outbox.restore_outage(gid, down_since.as_i64(), now_i);
        }
        // the history machine from what this device holds: its keys and the epochs it joined at
        let keys = m.archive_keys.iter().map(|(a, (_, at))| (a.as_str(), *at));
        let joined = st["convs"].as_object().into_iter().flatten().map(|(g, c)| (g.as_str(), c["joined_epoch"].as_u64().unwrap_or(0)));
        m.history = History::new(keys, joined);
        // the groups: reloaded from the MLS storage by id, with what this device knew about each
        for (gid, c) in st["convs"].as_object().into_iter().flatten() {
            let Some(group) = m.mls.load_group(&dsip_core::b64::decode(gid).unwrap_or_default()).ok().flatten() else { continue };
            let conv = Conv {
                group,
                conversation: s_of(&c["conversation"]),
                kind: s_of(&c["kind"]),
                hub: (s_of(&c["hub"]["did"]), s_of(&c["hub"]["uri"])),
                peer: c["peer"].as_str().map(String::from),
                receipts: m.new_receipts(now_i),
                joined_epoch: c["joined_epoch"].as_u64().unwrap_or(0),
            };
            m.convs.insert(gid.clone(), conv);
        }
        let _ = m.recording_changes(now_i); // what each conversation is recorded by at start is not a change
        Ok(m)
    }

    /// This device's delivery state, to keep with its MLS state after every step that returned something (spec-gap
    /// 44: the two committed together); [`Messenger::open`] takes it back.
    pub fn state(&self) -> Value {
        let convs: serde_json::Map<String, Value> = self.convs.iter().map(|(g, c)| (g.clone(), json!({
            "conversation": c.conversation, "kind": c.kind, "hub": {"did": c.hub.0, "uri": c.hub.1}, "peer": c.peer, "joined_epoch": c.joined_epoch,
        }))).collect();
        let archive: serde_json::Map<String, Value> = self.archive_keys.iter().map(|(a, (k, at))| (a.clone(), json!({"key": b64(k), "created_at": at}))).collect();
        json!({
            "convs": convs, "personal": self.personal, "resume": self.resume.snapshot(), "own": self.own, "outbox": self.outbox.items,
            "messages": self.messages, "grants_held": self.grants_held, "archive_keys": archive, "group_info": self.group_info,
            "held_items": self.held_items, "requests": self.requests, "held_archive": self.held_archive, "restored": self.restored.items(),
            "read_disclosed": self.read_disclosed, "policy": self.policy, "calls": self.calls,
            "outages": self.outbox.outages.iter().filter(|(_, o)| o.is_down()).map(|(g, o)| (g.clone(), json!(o.down_since()))).collect::<serde_json::Map<_, _>>(),
            "hub_timeout": self.outbox.hub_timeout, "successors": self.successors, "handover": self.handover, "mailbox": self.mailbox.0,
            "pending": self.pending.iter().filter_map(|(id, p)| Some((id.clone(), p.to_json()?))).collect::<serde_json::Map<_, _>>(),
            "records_held": self.records_held, "records": self.records, "recording_accepted": self.recording_accepted, "leaving": self.leaving,
            "roster_log": self.roster_log, "forgotten": self.forgotten,
        })
    }

    /// Seconds a seq gap may stay open before the group counts as lost (M§6.5, spec-gap 69).
    pub fn set_gap_timeout(&mut self, seconds: i64) {
        self.gap_timeout = seconds;
    }

    /// Seconds after which a deposit with no answer at all counts as the hub unreachable (M§9.4, spec-gap 72), 60 unless
    /// set.
    pub fn set_no_answer_timeout(&mut self, seconds: i64) {
        self.pending.no_answer = seconds;
    }

    /// Whether this device's delegation carries `dsip.messaging` (M§4.3): without it the mailbox refuses the binding.
    pub fn delegation_ok(&self) -> bool {
        dsip_core::delegation::capabilities(&self.keys.delegation).iter().any(|c| c == "dsip.messaging")
    }

    /// The identity's mailbox `{did, uri}`.
    pub fn mailbox(&self) -> Hub {
        Hub { did: self.mailbox.0.clone(), uri: self.mailbox.1.clone() }
    }

    /// Grants held from others, `{identity: compact}` (from the calling engine's contact file, §19.4): what is
    /// presented to the peer's mailbox (M§14.2), beside grants that arrive through this mailbox.
    pub fn set_grants(&mut self, grants: &BTreeMap<String, String>) {
        for (k, v) in grants {
            self.grants_held.insert(k.clone(), v.clone());
        }
    }

    /// The signed grant held from `identity` (compact), as received through the mailbox or set with
    /// [`Messenger::set_grants`]: what a calling engine holds too, to present it where a grant admits (§19.4, P§6).
    pub fn grant_held(&self, identity: &str) -> Option<&str> {
        self.grants_held.get(identity).map(String::as_str)
    }

    /// M§10.5: disclose read watermarks to the conversation (`true`) or keep them in the personal group (`false`,
    /// the default). Applies to every conversation's receipts machine.
    pub fn set_read_disclosed(&mut self, disclosed: bool, now: f64) {
        if self.read_disclosed == disclosed {
            return;
        }
        self.read_disclosed = disclosed;
        self.policy["read"] = json!(disclosed);
        self.policy["played"] = json!(disclosed);
        self.rebuild_receipts(now as i64);
    }

    /// What this device discloses to other identities (M§10.5, M§11). A recorder discloses nothing (C§5).
    pub fn set_receipt_policy(&mut self, policy: ReceiptPolicy, now: f64) {
        self.policy = json!(policy);
        self.read_disclosed = policy.read;
        self.rebuild_receipts(now as i64);
    }

    /// The policy is the machine's construction (vector context): each conversation gets a fresh machine, and the
    /// content it had shown is restored into it as history (spec-gap 64: nothing is sent or archived again).
    /// Receipts booked so far are not carried over; they arrive again only if re-sent, so the marks reset.
    fn rebuild_receipts(&mut self, now: i64) {
        let me = self.keys.identity.clone();
        let policy = self.policy.clone();
        for (gid, c) in self.convs.iter_mut() {
            let mut fresh = Receipts::new(&me, &policy, now);
            let items: Vec<Value> = self.messages.iter().filter(|m| m["group"] == *gid && m["seq"].is_i64())
                .map(|m| json!({"seq": m["seq"], "object": m["object"]})).collect();
            let _ = fresh.restore(now, items);
            c.receipts = fresh;
        }
    }

    /// The user has read a conversation through `content_id` (M§10.3): the receipts machine decides whether a
    /// watermark goes out, to the conversation or to the personal group (M§10.5), at most one per 5 s. Frames and
    /// events, as `inbound` returns them.
    pub fn read_through(&mut self, gid: &str, content_id: &str, now: f64) -> Vec<Event> {
        let now_i = now as i64;
        let Some(c) = self.convs.get_mut(gid) else { return vec![] };
        let emissions = c.receipts.read(now_i, &json!(content_id));
        self.receipt_sends(gid, emissions, now_i)
    }

    /// Advance every conversation's clock (M§10.3: a read held back by the 5 s interval goes out when it passes).
    pub fn tick(&mut self, now: f64) -> Vec<Event> {
        let now_i = now as i64;
        let mut out = self.advance_receipts(now_i);
        // M§9.4: a deposit with no answer at all counts as the hub unreachable
        for (_, p) in self.pending.silent(now_i) {
            if let Pending::Application { gid, item } = p {
                out.extend(self.hub_unreachable(&gid, &item, true, now_i));
            }
        }
        // M§7.4 (spec-gap 129): deposits the new hub refused before it hosted the group, due again
        for pending in self.pending.due(now_i) {
            out.extend(self.redeposit(pending, now_i));
        }
        for (gid, ems) in self.outbox.due(now_i) {
            out.extend(self.outage_emissions(&gid, ems, now_i));
        }
        // M§6.5 (spec-gap 69): a gap that has not filled in time makes this device re-join (M§6.8)
        for (gid, held) in self.delivery().gap_timeouts(now_i) {
            out.push(Ui::GapTimeout { group: gid.clone(), held }.into());
            match self.external_commit(&gid, now_i) {
                Ok(frame) => {
                    self.retries.insert(gid, (Retry::default(), Op::Rejoin));
                    out.push(Event::send(frame));
                }
                Err(e) => out.push(Event::Error { error: e.0, group: Some(gid), reason: None, detail: None }),
            }
        }
        out.extend(self.recording_changes(now_i));
        out
    }

    /// This device's hub-outage threshold, seconds (M§9.4: the client's own; 24 h RECOMMENDED).
    pub fn set_hub_timeout(&mut self, seconds: f64) {
        self.outbox.hub_timeout = seconds as i64;
    }

    /// Groups whose hub is unreachable, by group (M§9.4).
    pub fn outages(&self) -> BTreeMap<String, Outage> {
        self.outbox.outages.iter().map(|(g, o)| (g.clone(), Outage { down_since: o.down_since(), pending: o.pending().len(),
            abandoned: o.is_abandoned(), successor: self.successors.successor(g).map(String::from) })).collect()
    }

    /// Create the successor of `dead` (M§7.5) once its hub has been unreachable past the threshold: a group for the
    /// same conversation hubbed at this identity's mailbox, `successor_of` naming the dead group, re-adding the dead
    /// group's last roster from `key_packages` (`{identity: key-packages answer}`, fetched with `successor_of`,
    /// M§7.5 spec-gap 61). When this device already converged on a successor, that one is used. The pending items
    /// follow once the successor holds its members (M§9.4). Frames.
    pub fn create_successor(&mut self, dead: &str, key_packages: &BTreeMap<String, Value>, now: f64) -> Result<Vec<String>, Error> {
        let now_i = now as i64;
        self.track_rosters();
        let me = self.keys.identity.clone();
        let peers = match self.successors.create(dead, &me) {
            Create::Use(w) => {
                let moved = self.handover.remove(dead).unwrap_or_default();
                self.handover.entry(w.clone()).or_default().extend(moved);
                let out = self.flush_handover(&w, now_i);
                return Ok(out.iter().filter_map(|e| e.frame().map(String::from)).collect());
            }
            Create::Refuse(why) => return Err(Error::from(format!("successor refused: {}", json!(why)))),
            Create::Create { peers } => peers,
        };
        let (conversation, kind) = self.convs.get(dead).map(|c| (c.conversation.clone(), c.kind.clone())).ok_or_else(|| Error::from("not a member of that group"))?;
        let mut kps = vec![];
        let mut grants = vec![];
        for peer in &peers {
            if let Some(answer) = key_packages.get(peer) {
                kps.extend(self.pick_key_packages(peer, answer, now_i).unwrap_or_default());
                grants.extend(self.grants_held.get(peer).cloned());
            }
        }
        let (gid, frames) = self.new_group_for(Some(conversation), &kind, Some(dead), now_i)?;
        let peer = self.convs.get(dead).and_then(|c| c.peer.clone());
        if let Some(c) = self.convs.get_mut(&gid) {
            c.peer = peer;
        }
        let decisions = self.successors.created(&gid, dead);
        let moved = self.handover.remove(dead).unwrap_or_default();
        self.handover.entry(gid.clone()).or_default().extend(moved);
        if kind == "personal" {
            self.personal = Some(gid.clone());
        }
        let op = (!kps.is_empty()).then(|| Op::Add { peer: peers.first().cloned().unwrap_or_default(), kps, grants, device: None });
        let gi_id = frames.last().and_then(|f| Envelope::from_frame(f).ok()).and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
        self.pending.insert(gi_id, Pending::GroupInfo { gid: gid.clone(), then: op });
        if kind == "personal" {
            // M§12.1: the personal group's successor gets an archive key of its own, as a new personal group does
            self.pending.insert(format!("personal:{gid}"), Pending::PersonalReady { gid: gid.clone() });
        }
        let mut out: Vec<String> = frames;
        for d in decisions {
            if let Converge::Leave(g) = d {
                out.extend(self.leave_group(&g, now_i));
            }
        }
        Ok(out)
    }

    /// The hand-over to a successor could not be done (the peers' KeyPackages could not be fetched): retried with the
    /// §13.2 backoff (M§9.4, spec-gap 72).
    pub fn successor_failed(&mut self, dead: &str) {
        if let Some(o) = self.outbox.outages.get_mut(dead) {
            o.handover_failed();
        }
    }

    /// Add one device of this identity (M§12.3, M§6.7) to `gid` from its mailbox's `key-packages` answer (only the
    /// package of `device` is used): the commit to deposit. After the personal group's add is accepted, every live
    /// archive key is re-sent there ([`Messenger::resend_archive_keys`]). The groups to add it to, in order, are
    /// [`Messenger::groups_for_new_device`].
    pub fn add_device(&mut self, gid: &str, device: &str, payload: &Value, now: f64) -> Result<String, Error> {
        let now_i = now as i64;
        let ctx = self.ctx(now_i);
        let candidates = payload["key_packages"].as_array().cloned().unwrap_or_default().into_iter().chain(payload.get("last_resort").cloned());
        let mut kps = vec![];
        let mut seen = vec![];
        let mut recorder = false;
        for c in candidates {
            let bytes = unb64(&c);
            if let Ok((_, who)) = authenticate_key_package(&bytes, self.mls.provider(), &ctx) {
                seen.push(format!("{}#{}", who.identity, who.device));
                if who.identity == self.keys.identity && who.device == device {
                    recorder |= who.is_recorder();
                    kps.push(bytes);
                }
            }
        }
        if kps.is_empty() {
            return Err(Error::from(format!("no KeyPackage of device {device} in the answer (it holds: {})", seen.join(", "))));
        }
        if recorder && self.personal.as_deref() == Some(gid) {
            // Recording Profile C§5: a recorder device joins conversations only — never the personal group, so it holds
            // no archive key and records only what is sent while it is a visible member
            return Err(Error::from(format!("{device} is a recorder device: conversations only, never the personal group (C§5)")));
        }
        kps.truncate(1);
        let op = Op::Add { peer: self.keys.identity.clone(), kps, grants: vec![], device: Some(device.to_string()) };
        self.propose(gid, &op, now_i)
    }

    /// The groups a new device of this identity joins, in order: the personal group first (M§12.3 step 3), then
    /// every conversation it is not in yet (M§6.7); `[]` when it is everywhere already.
    pub fn groups_for_new_device(&self, device: &str, now: f64) -> Vec<String> {
        let ctx = Context::new(now as i64, &self.resolver);
        let in_group = |c: &Conv| c.group.members().any(|m| member_identity(&c.group, m.index, &ctx).ok().is_some_and(|w| w.device == device));
        let mut order: Vec<String> = vec![];
        if let Some(p) = &self.personal {
            if self.convs.get(p).is_some_and(|c| !in_group(c)) {
                order.push(p.clone());
            }
        }
        for (g, c) in &self.convs {
            if c.kind != "personal" && !in_group(c) {
                order.push(g.clone());
            }
        }
        order
    }

    /// M§12.3 step 3: every live archive key, as `archive-key` objects to the personal group, so a device just added
    /// can read the archive. Frames to send.
    pub fn resend_archive_keys(&mut self, now: f64) -> Vec<String> {
        let now_i = now as i64;
        let Some(personal) = self.personal.clone() else { return vec![] };
        let keys: Vec<(String, Vec<u8>, i64)> = self.archive_keys.iter().map(|(a, (k, t))| (a.clone(), k.clone(), *t)).collect();
        let mut frames = vec![];
        for (akid, key, at) in keys {
            let obj = json!({"object": "archive-key", "akid": akid, "key": b64(&key), "created_at": at});
            if let Ok(f) = self.send_object(&personal, &obj, now_i) {
                frames.push(f);
            }
        }
        frames
    }

    /// Archive keys this device holds, newest current (M§12.1).
    pub fn archive_keys(&self) -> Vec<ArchiveKey> {
        self.archive_keys.iter().map(|(a, (_, at))| ArchiveKey { akid: a.clone(), created_at: *at }).collect()
    }

    /// Groups this identity's mailbox delivered a GroupInfo for that this device is not in (M§6.8): what it can join by
    /// external commit, the personal group first.
    pub fn available(&self) -> Vec<Available> {
        let mut out: Vec<Available> = self.group_info.iter().filter(|(g, _)| !self.convs.contains_key(*g)).filter_map(|(g, gi)| {
            let conv = dsip_mls::group_info_conversation(&unb64(&json!(gi)))?;
            Some(Available { group: g.clone(), conversation: s_of(&conv["conversation"]), kind: s_of(&conv["kind"]),
                             hub: serde_json::from_value(conv["hub"].clone()).unwrap_or_default() })
        }).collect();
        out.sort_by_key(|c| c.kind != "personal");
        out
    }

    /// Join `gid` by external commit (M§6.8): a device of an identity that has a leaf there, or the identity's own
    /// personal group, with no sibling online to add it. The commit goes to the hub; a `commit-conflict` or
    /// `stale-epoch` refusal discards the joined state, syncs and joins again from the newer GroupInfo (the pinned
    /// `CommitRetry`, spec-gap 58). No archive key comes with it: history waits for a sibling (M§12.3). Frames.
    pub fn external_join(&mut self, gid: &str, now: f64) -> Result<Vec<String>, Error> {
        if self.convs.contains_key(gid) {
            return Err(Error::from("this device is in that group already"));
        }
        let frame = self.external_commit(gid, now as i64)?;
        self.retries.insert(gid.to_string(), (Retry::default(), Op::Rejoin));
        Ok(vec![frame])
    }

    /// A callee leg of this device ended (M§13.3): whether it sends a `call-event` to the personal group, by the
    /// vector-pinned decision (spec-gap 63) — alerted here and not answered here, never `session.answered-elsewhere`;
    /// `declined` when this device ended it with `user.declined`, else `missed`. Frames to send (`[]` when none).
    pub fn call_ended(&mut self, leg: &CallLeg, now: f64) -> Result<Vec<String>, Error> {
        let r = self.call_ended_item(leg, now)?;
        Ok(if r.event.is_none() { vec![] } else { vec![r.send] })
    }

    /// [`Messenger::call_ended`] for a host that says what it did: the `call-event` sent (none when the decision is to
    /// send none), the outbox item it went out under (named by its `sent`), the frame (`""` while the hub is down), and
    /// whether it is the first entry for its session on this identity (spec-gap 63: a sibling may have reported the
    /// call first).
    ///
    /// Spec: M§13.3.
    pub fn call_ended_item(&mut self, leg: &CallLeg, now: f64) -> Result<CallEnded, Error> {
        let ended = calls::Ended { session: &leg.session, peer: &leg.peer, alerted: leg.alerted, answered_here: leg.answered_here,
            ended_by: &leg.ended_by, reason: &leg.reason };
        let Some(obj) = calls::call_event(&ended, now as i64) else {
            return Ok(CallEnded { event: None, item: None, send: String::new(), fresh: false });
        };
        let personal = self.personal.clone().ok_or_else(|| Error::from("no personal group yet"))?;
        let fresh = self.calls.record(&obj);
        let (item, send) = self.send_item(&personal, &obj, now as i64)?;
        Ok(CallEnded { event: Some(obj), item, send, fresh })
    }

    /// One leg's `call-record` for this identity's record-keeper `keeper` (C§9), built from what the host saw of the
    /// leg: `leg` is `{session, direction, peer, relay?, invited_at, answered, answered_at?, ended_by, reason?,
    /// media?, evidence?}`. The outcome is the pinned order (`call-record-outcome`); `answered_at` goes in exactly when
    /// it is `answered`; `ended_at` is now. A record the record-keeper would drop (`check: "object"`) is never sent.
    /// The record is held, then everything held goes to the conversation with `keeper` if it exists
    /// ([`Messenger::flush_records`]).
    ///
    /// Spec: C§9 (v0.13, spec-gaps 121 and 123).
    pub fn call_record(&mut self, keeper: &str, leg: &Value, now: f64) -> Result<CallRecorded, Error> {
        let record = calls::call_record(leg, &self.keys.device.did(), now as i64)
            .map_err(|code| Error::from(format!("call record not sent: {code}")))?;
        self.records_held.push(record.clone());
        let frames = self.flush_records(keeper, now)?;
        Ok(CallRecorded { record, frames })
    }

    /// The held call records, sent to the direct conversation with `keeper` when there is one (C§9: the record-keeper
    /// opens it, spec-gap 123); frames to send, `[]` while there is none.
    pub fn flush_records(&mut self, keeper: &str, now: f64) -> Result<Vec<String>, Error> {
        let Some(gid) = self.convs.iter().find(|(_, c)| c.kind == "direct" && c.peer.as_deref() == Some(keeper)).map(|(g, _)| g.clone()) else {
            return Ok(vec![]);
        };
        let gid = self.live(&gid);
        let mut frames = vec![];
        while let Some(rec) = self.records_held.first().cloned() {
            let f = self.send_object(&gid, &rec, now as i64)?;
            self.records_held.remove(0);
            if !f.is_empty() {
                frames.push(f);
            }
        }
        Ok(frames)
    }

    /// Leave the conversation `gid` for this identity (M§7.3 "Leaving", spec-gap 125): a Remove proposal for each of
    /// its leaves goes to the hub, another member commits them, and until then nothing is sent there and it is not
    /// listed. The personal group is never left. Returns the frames to send.
    pub fn leave(&mut self, gid: &str, now: f64) -> Result<Vec<Event>, Error> {
        let gid = self.live(gid);
        if !self.convs.contains_key(&gid) {
            return Err(Error::from("not a member of that group"));
        }
        if self.personal.as_deref() == Some(gid.as_str()) {
            return Err(Error::from("the personal group is not left (M§7.1)"));
        }
        self.leaving.insert(gid.clone());
        Ok(self.propose_leave(&gid, now as i64))
    }

    /// The Remove proposals for every leaf of this identity in `gid`, deposited: this device's own by `leave_group`
    /// (MLS lets a member propose, never commit, its own removal), a sibling's by `propose_remove_member`.
    fn propose_leave(&mut self, gid: &str, now: i64) -> Vec<Event> {
        let ctx = Context::new(now, &self.resolver);
        let (provider, signer) = (self.mls.provider(), self.mls.signer());
        let me = self.keys.identity.clone();
        let mut bytes = vec![];
        let mut errors = vec![];
        if let Some(c) = self.convs.get_mut(gid) {
            let own = c.group.own_leaf_index();
            let mine = commits::identity_leaves(&c.group, &ctx, &me);
            for idx in mine {
                let msg = if idx == own {
                    c.group.leave_group(provider, &signer).map_err(|e| format!("{e:?}"))
                } else {
                    c.group.propose_remove_member(provider, &signer, idx).map(|(m, _)| m).map_err(|e| format!("{e:?}"))
                };
                match msg.and_then(|m| m.tls_serialize_detached().map_err(|e| format!("{e:?}"))) {
                    Ok(b) => bytes.push(b),
                    Err(e) => errors.push(e),
                }
            }
        }
        let mut out: Vec<Event> = errors.into_iter().map(|e| Event::error(format!("leave proposal in {gid}: {e}"))).collect();
        for b in bytes {
            let frame = self.hub_deposit(gid, "handshake", json!({"mls": b64(&b)}), now);
            let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
            self.pending.insert(id, Pending::Proposal { gid: gid.to_string() });
            out.push(Event::send(frame));
        }
        out
    }

    /// The user accepted the recording of `gid` (C§5): every recorder now in it is accepted for this conversation, and
    /// a `recording-acceptance` goes to the personal group so this identity's other devices accept them too. Content
    /// may then be sent there. A recorder that joins later asks again.
    ///
    /// Spec: C§5 "Acceptance is the person's, not one device's".
    pub fn accept_recording(&mut self, gid: &str, now: f64) -> Result<RecordingAccepted, Error> {
        let now_i = now as i64;
        let gid = &self.live(gid);
        let conversation = self.convs.get(gid).map(|c| c.conversation.clone()).ok_or_else(|| Error::from("not a member of that group"))?;
        let rec = self.recording_of(&self.leaves_of(gid, now_i), &conversation);
        let devices: Vec<String> = rec["pending"].as_array().into_iter().flatten().filter_map(|r| r["device"].as_str().map(String::from)).collect();
        if devices.is_empty() {
            return Err(Error::from("no recorder to accept in this conversation"));
        }
        self.recording_accepted.entry(conversation.clone()).or_default().extend(devices.iter().cloned());
        let mut frames = vec![];
        if let Some(personal) = self.personal.clone() {
            let obj = json!({"object": "recording-acceptance", "conversation": conversation, "recorders": devices, "accepted_at": now_i});
            let f = self.send_object(&personal, &obj, now_i)?;
            if !f.is_empty() {
                frames.push(f);
            }
        }
        Ok(RecordingAccepted { accepted: devices, frames })
    }

    /// How many of this device's call records wait for the conversation with the record-keeper (C§9).
    pub fn held_records(&self) -> usize {
        self.records_held.len()
    }

    /// As a record-keeper: the records received (C§9), `[{group, from, device, received_at, record}]`.
    pub fn records(&self) -> &[Value] {
        &self.records
    }

    /// Whether this device is a recorder (its delegation carries `dsip.record`, C§5).
    pub fn is_recorder(&self) -> bool {
        self.recorder
    }

    /// The call log, one entry per session (M§13.3).
    pub fn calls(&self) -> &CallLog {
        &self.calls
    }

    /// One conversation's timeline (M§13.3, the pinned `peer_timeline`): its messages with this identity's call events
    /// for the peer interleaved — `{"call": {…}}` or the message as [`Messenger::thread`] gives it.
    pub fn timeline(&self, gid: &str) -> Vec<Value> {
        let thread = self.thread(gid);
        let peer = self.convs.get(gid).and_then(|c| c.peer.clone());
        let calls = peer.as_deref().map(|p| self.calls.with_peer(p)).unwrap_or_default();
        if calls.is_empty() {
            return thread;
        }
        let content: Vec<Value> = thread.iter().enumerate().map(|(i, m)| json!({"id": i.to_string(), "at": m["object"]["sent_at"]})).collect();
        let order = dsip_messaging::client::peer_timeline(&json!({"content": content, "calls": calls}));
        let out: Vec<Value> = order["timeline"].as_array().into_iter().flatten().filter_map(Value::as_str).filter_map(|e| {
            if let Some(i) = e.strip_prefix("content:") {
                i.parse::<usize>().ok().and_then(|i| thread.get(i).cloned())
            } else {
                let sess = e.strip_prefix("call:").unwrap_or("");
                calls.iter().find(|c| c["session"] == sess).map(|c| json!({"call": c}))
            }
        }).collect();
        out
    }

    /// Whether this device can send to `peer` (M§13.2 condition 2): a direct conversation exists, or a grant from them
    /// is held that would let one be created (M§14.2).
    pub fn can_send(&self, peer: &str) -> bool {
        self.convs.values().any(|c| c.kind == "direct" && c.peer.as_deref() == Some(peer)) || self.grants_held.contains_key(peer)
    }

    /// Seal a payload for upload (M§8.4 rule 1): a fresh single-use 32-byte key, AES-256-GCM, no AAD, stored as
    /// `nonce ‖ ciphertext ‖ tag`.
    pub fn seal_blob(&self, plain_b64: &str) -> SealedBlob {
        let plain = dsip_core::b64::decode(plain_b64).unwrap_or_default();
        let key = KeyPair::generate().seed();
        let nonce: [u8; 12] = KeyPair::generate().seed()[..12].try_into().expect("12 bytes");
        let sealed = blob::seal_blob(&key, &nonce, &plain);
        SealedBlob { sealed: b64(&sealed.bytes), key: b64(&key), sha256: sealed.sha256, size: sealed.bytes.len() }
    }

    /// The `blob-put` that authorizes one upload of `sha256`/`size` to this identity's mailbox (M§5.6), as the compact
    /// envelope for `Authorization: DSIP …`, carrying the device's delegation (M§5.1).
    pub fn blob_put(&self, sha256: &str, size: f64, now: f64) -> String {
        let env = wire::message_delegated(&self.keys.device, vec![self.keys.delegation.clone()], "blob-put", &self.mailbox.0, now as i64,
            wire::TTL_S, json!({"sha256": sha256, "size": size as u64}));
        compact(&env)
    }

    /// An `audio` content object (M§8.2) for a blob already uploaded, `blob` from [`Messenger::seal_blob`] and the upload; `purpose` `voice-message` or `voicemail` (with `session`). The deposit
    /// carries the manifest without the key (M§8.4 rule 4). The frame to send.
    pub fn send_audio(&mut self, gid: &str, b: &BlobRef, duration_ms: f64, purpose: &str, session: Option<String>, now: f64) -> Result<String, Error> {
        let now_i = now as i64;
        let gid = &self.live(gid);
        let conversation = self.convs.get(gid).map(|c| c.conversation.clone()).ok_or_else(|| Error::from("not a member of that group"))?;
        self.may_send_content(gid, now_i)?;
        let id = self.fresh_id(now_i);
        let uploaded = blob::Uploaded { uri: &b.uri, sha256: &b.sha256, size: b.size, key: &b.key, content_type: &b.content_type };
        let obj = blob::audio_content(&id, &conversation, &self.keys.identity, now_i, purpose, duration_ms as i64, &uploaded, session.as_deref());
        self.send_object(gid, &obj, now_i)
    }

    /// Where to fetch a content's blob from, in order (M§8.4 rules 6–7, the pinned `blob_sources`): the manifest's copy
    /// at another `uri` for the same `sha256` and `size`, then the content's own. `object` is the content object,
    /// `manifest` the item's `blobs` (or null).
    pub fn blob_sources(&self, object: &Value, manifest: &Value) -> Vec<String> {
        blob::sources(object, manifest)
    }

    /// Open a fetched blob for a content object (M§8.4 rule 7): the size and SHA-256 must match the content's `blob`
    /// before it is decrypted under the key the content carries. The plaintext, base64url, or the refusal code.
    pub fn open_blob(&self, object: &Value, stored_b64: &str) -> Result<String, Error> {
        let stored = dsip_core::b64::decode(stored_b64).unwrap_or_default();
        let plain = blob::open(object, &stored).map_err(|c| Error::from(if c == "blob-key" { "blob key" } else { c }))?;
        Ok(b64(&plain))
    }

    /// One source's answer as the fetch decision takes it (`status` 0: not reached; `stored_b64`, bytes a 200 served
    /// that did not open, or empty) (M§8.4 rule 7, spec-gap 106).
    pub fn blob_tried(&self, uri: &str, status: u16, stored_b64: &str) -> blob::Tried {
        let stored = dsip_core::b64::decode(stored_b64).filter(|_| !stored_b64.is_empty());
        blob::tried(uri, status, stored.as_deref())
    }

    /// Seconds before fetch `attempt` is tried again (spec-gap 67's schedule: 4 s doubling, at most 60 s).
    pub fn blob_retry_delay_s(&self, attempt: f64) -> f64 {
        blob::retry_delay_s(attempt as i64) as f64
    }

    /// What a device does after its blob sources answered (the pinned `blob_fetch`, spec-gap 106).
    pub fn blob_fetch_decision(&self, object: &Value, tried: &[blob::Tried], attempt: f64) -> FetchDecision {
        blob::fetch_decision(object, tried, attempt as i64).into()
    }

    /// The user played an `audio` or `video` content (M§10.4): a `played` receipt under the same opt-in as `read`
    /// (M§10.5). Frames and events, as `inbound` returns them.
    pub fn played(&mut self, gid: &str, content_id: &str, now: f64) -> Vec<Event> {
        let now_i = now as i64;
        let Some(c) = self.convs.get_mut(gid) else { return vec![] };
        let emissions = c.receipts.play(now_i, content_id);
        self.receipt_sends(gid, emissions, now_i)
    }

    /// A DID document to hold (§8.1), for `did:web` peers.
    pub fn add_document(&mut self, doc: dsip_core::did::DidDocument) {
        self.resolver.insert(doc);
    }

    /// The client `hello` to send first on a connection to a mailbox (§13.2, M§4.3); one per connection.
    pub fn hello_frame(&mut self, now: f64) -> String {
        let id = self.fresh_id(now as i64);
        self.hello_ids.insert(id.clone());
        client_hello(&self.keys, &self.supported, &id, now as i64).frame()
    }

    /// Verify a service's `hello` (must echo one of ours, §20.5): its DID and capabilities, or the reject code
    /// (`hello-not-ours` when it echoes none of ours).
    pub fn relay_hello(&mut self, frame: &str, now: f64) -> Result<RelayHello, String> {
        let answered = Envelope::from_frame(frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["in_reply_to"])).unwrap_or_default();
        if !self.hello_ids.remove(&answered) {
            return Err("hello-not-ours".into());
        }
        verify_relay_hello(frame, &answered, now as i64, &self.resolver, &mut self.seen, &self.supported)
            .map_err(|v| v.code.and_then(|c| serde_json::to_value(c).ok()).and_then(|c| c.as_str().map(String::from)).unwrap_or_default())
    }

    /// A `sync` for this identity's mailbox (M§5.4): `since`/`ack_through` from the durable state, `live` once asked.
    pub fn sync_frame(&mut self, live: bool, now: f64) -> String {
        self.want_live |= live;
        let mut fields = self.resume.sync_fields();
        fields["live"] = json!(self.want_live);
        wire::message(&self.keys.device, "sync", &self.mailbox.0, now as i64, wire::TTL_S, fields).frame()
    }

    /// A `key-packages` upload of `n` fresh KeyPackages and a last-resort one (M§5.5, M§6.7).
    pub fn key_packages_frame(&mut self, n: usize, now: f64) -> Result<String, Error> {
        let mut packages = vec![];
        for _ in 0..n {
            packages.push(json!(b64(&self.mls.key_package().map_err(|e| err(e.0))?)));
        }
        let last = b64(&self.mls.key_package().map_err(|e| err(e.0))?);
        let env = wire::message(&self.keys.device, "key-packages", &self.mailbox.0, now as i64, wire::TTL_S,
            json!({"subject": self.keys.identity, "key_packages": packages, "last_resort": last}));
        self.pending.insert(wire::payload_of(&env).map(|p| s_of(&p["id"])).unwrap_or_default(), Pending::KeyPackages { count: n + 1 });
        Ok(env.frame())
    }

    /// What to send on a fresh binding: pending application items again (M§9.3, the same bytes), then a sync.
    pub fn on_bound(&mut self, now: f64) -> Vec<String> {
        let mut frames = self.rebind(now);
        frames.push(self.sync_frame(true, now));
        frames
    }

    /// [`Messenger::on_bound`] without the sync, for a host that syncs when its user asks: deposits whose answer the
    /// ended binding took with it, and the outbox's pending items, again (M§9.3: the same bytes).
    pub fn rebind(&mut self, now: f64) -> Vec<String> {
        let mut frames = vec![];
        let moved = self.moved_from.is_some();
        if let Some(old) = self.moved_from.take() {
            // spec-gap 122: a mailbox this identity moved to learns its groups, so hubs' fan-out is admitted (M§6.6)
            let groups: Vec<Value> = self.convs.iter().map(|(g, c)| json!({"group": g, "state": "joined", "hub": c.hub.0, "hub_uri": c.hub.1})).collect();
            if !groups.is_empty() {
                let env = self.config_env(json!({"subject": self.keys.identity, "groups": groups}), now as i64);
                frames.push(env.frame());
            }
            let _ = old;
        }
        frames.extend(self.redeposit_pending(moved, now as i64));
        for (gid, items) in self.outbox.items.clone() {
            if self.outbox.is_down(&gid) || self.outbox.is_abandoned(&gid) {
                continue; // M§9.4: the outage's own backoff re-deposits the head (tick)
            }
            for it in items {
                frames.push(self.deposit_item(&gid, &it, now as i64));
            }
        }
        frames
    }

    /// Deposits whose answer a binding that ended took with it, sent again under fresh envelopes: a GroupInfo as a new
    /// export, a commit as the same MLS bytes (the hub answers a duplicate digest with its seq, M§6.5), a
    /// `mailbox-config` or archive record with the same fields. Application items go again from the outbox.
    ///
    /// Spec: M§9.3; M§4.1 step 3 (v0.13, spec-gap 122): after a move the new mailbox's registration of every group
    /// supersedes a pending `mailbox-config` at the old one. Impl: an archive record goes to the new mailbox, the
    /// identity's mailbox now; key packages are uploaded afresh by the host at every binding.
    fn redeposit_pending(&mut self, moved: bool, now: i64) -> Vec<String> {
        let mut frames = vec![];
        for (id, p) in self.pending.iter().map(|(id, p)| (id.clone(), p.clone())).collect::<Vec<_>>() {
            let frame = match &p {
                Pending::GroupInfo { gid, .. } if self.convs.contains_key(gid) && !(self.outbox.is_down(gid) || self.outbox.is_abandoned(gid)) => {
                    self.group_info_frame(gid, now).ok()
                }
                Pending::Commit { gid, fields, .. } if self.convs.contains_key(gid) => Some(self.hub_deposit(gid, "handshake", fields.clone(), now)),
                Pending::Config { fields } if !moved => Some(wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now, wire::TTL_S, fields.clone()).frame()),
                Pending::Archive { fields } => {
                    let gid = s_of(&fields["ref_group"]);
                    Some(wire::deposit_delegated(&self.keys.device, vec![self.keys.delegation.clone()], &self.mailbox.0, now, &gid, "archive", fields.clone()).frame())
                }
                Pending::GroupInfo { .. } | Pending::Commit { .. } | Pending::Config { .. } | Pending::KeyPackages { .. } | Pending::Proposal { .. } => None,
                Pending::Application { .. } | Pending::PersonalReady { .. } => continue,
            };
            self.pending.remove(&id);
            if let Some(f) = frame {
                let nid = Envelope::from_frame(&f).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
                self.pending.insert(nid, p);
                frames.push(f);
            }
        }
        frames
    }

    /// A `mailbox-config` to this device's mailbox (M§6.6), pending until answered.
    fn config_env(&mut self, fields: Value, now: i64) -> Envelope {
        let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now, wire::TTL_S, fields.clone());
        self.pending.insert(wire::payload_of(&env).map(|p| s_of(&p["id"])).unwrap_or_default(), Pending::Config { fields });
        env
    }

    /// Create this identity's personal group at its mailbox (M§7.1): the `mailbox-config` that registers it and the
    /// GroupInfo deposit; the first archive key follows once the hub holds the group (M§12.1). Frames to send.
    pub fn create_personal(&mut self, now: f64) -> Result<Vec<String>, Error> {
        if self.personal.is_some() {
            return Err(Error::from("this identity already has a personal group here"));
        }
        let (gid, frames) = self.new_group("personal", now as i64)?;
        self.personal = Some(gid.clone());
        // the GroupInfo deposit is the last frame: its accepted leads to the archive key
        if let Some(id) = frames.last().and_then(|f| Envelope::from_frame(f).ok()).and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])) {
            self.pending.insert(id, Pending::GroupInfo { gid: gid.clone(), then: None });
            self.pending.insert(format!("personal:{gid}"), Pending::PersonalReady { gid });
        }
        Ok(frames)
    }

    /// A `key-package-fetch` for `target` to send on a connection to `to_mailbox` (M§5.5), presenting the grant
    /// held from `target` if any (M§14.2).
    /// `successor_of` names the dead group a successor is created for: the target's mailbox serves it without a
    /// grant when that group is registered for the target (M§7.5, spec-gap 61).
    pub fn fetch_frame(&mut self, to_mailbox: &str, target: &str, now: f64, successor_of: Option<String>) -> String {
        let mut fields = json!({"target": target});
        if let Some(g) = successor_of {
            fields["successor_of"] = json!(g);
        }
        if let Some(g) = self.grants_held.get(target) {
            fields["grant"] = json!(g);
        }
        wire::message(&self.keys.device, "key-package-fetch", to_mailbox, now as i64, wire::TTL_S, fields).frame()
    }

    /// Create a direct conversation with `target` from its mailbox's `key-packages` answer (M§7.2): every device of
    /// the target the vector-pinned rule picks (C§5), plus this identity's own other devices from `own` (the
    /// same answer shape), in one commit once the group is hubbed. Returns the frames to send, or the refusal.
    pub fn create_direct(&mut self, target: &str, key_packages: &Value, own: Option<&Value>, now: f64) -> Result<Vec<String>, Error> {
        if let Some(gid) = self.convs.iter().find(|(_, c)| c.kind == "direct" && c.peer.as_deref() == Some(target)).map(|(g, _)| g.clone()) {
            return Err(Error::from(format!("a conversation with {target} exists: {gid}")));
        }
        let now_i = now as i64;
        let mut kps = self.pick_key_packages(target, key_packages, now_i)?;
        if let Some(own) = own {
            let me = self.keys.identity.clone();
            kps.extend(self.pick_key_packages(&me, own, now_i).unwrap_or_default());
        }
        let (gid, frames) = self.new_group("direct", now_i)?;
        if let Some(c) = self.convs.get_mut(&gid) {
            c.peer = Some(target.to_string());
        }
        let grants: Vec<String> = self.grants_held.get(target).cloned().into_iter().collect();
        let op = Op::Add { peer: target.to_string(), kps, grants, device: None };
        if let Some(id) = frames.last().and_then(|f| Envelope::from_frame(f).ok()).and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])) {
            self.pending.insert(id, Pending::GroupInfo { gid, then: Some(op) });
        }
        Ok(frames)
    }

    /// Create a group conversation (M§7.3, `kind: group`) with the identities of `targets`, `{identity: its
    /// mailbox's key-packages answer}`, plus this identity's own other devices from `own`: every device
    /// the vector-pinned rule picks, added in one commit once the group is hubbed at this identity's mailbox, with the
    /// grants held from them (M§14.2). Returns the frames to send.
    pub fn create_group(&mut self, targets: &BTreeMap<String, Value>, own: Option<&Value>, now: f64) -> Result<Vec<String>, Error> {
        let now_i = now as i64;
        if targets.is_empty() {
            return Err(Error::from("a group needs at least one other identity"));
        }
        let (mut kps, mut grants) = (vec![], vec![]);
        for (target, answer) in targets {
            kps.extend(self.pick_key_packages(target, answer, now_i)?);
            grants.extend(self.grants_held.get(target).cloned());
        }
        if let Some(own) = own {
            let me = self.keys.identity.clone();
            kps.extend(self.pick_key_packages(&me, own, now_i).unwrap_or_default());
        }
        let (gid, frames) = self.new_group("group", now_i)?;
        let peer = targets.keys().next().cloned().unwrap_or_default();
        let op = Op::Add { peer, kps, grants, device: None };
        if let Some(id) = frames.last().and_then(|f| Envelope::from_frame(f).ok()).and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])) {
            self.pending.insert(id, Pending::GroupInfo { gid, then: Some(op) });
        }
        Ok(frames)
    }

    /// Add `target`'s devices to the group conversation `gid` from its mailbox's `key-packages` answer (M§7.3: any
    /// member identity MAY add another, holding its grant, M§14.2): the commit to deposit.
    pub fn add_member(&mut self, gid: &str, target: &str, key_packages: &Value, now: f64) -> Result<String, Error> {
        let now_i = now as i64;
        if self.member_identities(gid, now_i).iter().any(|i| i == target) {
            return Err(Error::from(format!("{target} is a member already")));
        }
        let kps = self.pick_key_packages(target, key_packages, now_i)?;
        let grants: Vec<String> = self.grants_held.get(target).cloned().into_iter().collect();
        self.propose(gid, &Op::Add { peer: target.to_string(), kps, grants, device: None }, now_i)
    }

    /// Remove the member identity `target` from the conversation `gid`, every leaf of it (M§7.3: any member identity
    /// MAY remove another; this identity leaves with [`Messenger::leave`] instead): the commit to deposit.
    pub fn remove_member(&mut self, gid: &str, target: &str, now: f64) -> Result<String, Error> {
        if target == self.keys.identity {
            return Err(Error::from("this identity leaves instead (M§7.3: no commit removes its committer)"));
        }
        if self.personal.as_deref() == Some(gid) {
            return Err(Error::from("the personal group holds this identity's devices only (M§7.1)"));
        }
        self.propose(gid, &Op::Remove { identity: target.to_string() }, now as i64)
    }

    /// Move the conversation `gid` to this identity's own mailbox as its hub (M§7.4: while the hub is alive, any member
    /// MAY move the group): the commit to deposit at the current hub. On `accepted` this device's mailbox follows and
    /// the new hub is bootstrapped with the GroupInfo and `handover_seq`.
    pub fn move_hub(&mut self, gid: &str, now: f64) -> Result<String, Error> {
        let (did, uri) = self.mailbox.clone();
        if self.convs.get(&self.live(gid)).is_some_and(|c| c.hub.0 == did) {
            return Err(Error::from("the conversation is already hubbed at this identity's mailbox"));
        }
        self.move_hub_to(gid, &did, &uri, now)
    }

    /// Move a conversation to the hub `did` at `uri` (M§7.4: a commit changing `dsip_conversation.hub` and nothing
    /// else, ordered by the old hub). The commit frame to send.
    pub fn move_hub_to(&mut self, gid: &str, did: &str, uri: &str, now: f64) -> Result<String, Error> {
        let gid = self.live(gid);
        let c = self.convs.get(&gid).ok_or_else(|| Error::from("not a member of that group"))?;
        if c.hub.0 == did {
            return Err(Error::from("the conversation is hubbed there already"));
        }
        self.propose(&gid, &Op::MoveHub { hub: json!({"did": did, "uri": uri}) }, now as i64)
    }

    /// Refresh this device's own leaf key material in `gid` (post-compromise security): an Update commit. The frame.
    pub fn rekey(&mut self, gid: &str, now: f64) -> Result<String, Error> {
        let gid = self.live(gid);
        if !self.convs.contains_key(&gid) {
            return Err(Error::from("not a member of that group"));
        }
        self.propose(&gid, &Op::Update, now as i64)
    }

    /// Remove another member's leaf whose delegation no longer verifies, by its credential (M§7.3, M§12.4: any member
    /// MAY). Refused while it still verifies: then only its own identity may remove it. The commit frame.
    pub fn remove_lapsed_leaf(&mut self, gid: &str, device: &str, now: f64) -> Result<String, Error> {
        let now = now as i64;
        let gid = self.live(gid);
        let ctx = Context::new(now, &self.resolver);
        let c = self.convs.get(&gid).ok_or_else(|| Error::from("not a member of that group"))?;
        let leaves = commits::device_leaves(&c.group, device);
        if leaves.is_empty() {
            return Err(Error::from("no leaf for that device"));
        }
        if leaves.iter().any(|l| member_identity(&c.group, *l, &ctx).is_ok()) {
            return Err(Error::from("the leaf's delegation still verifies: only its own identity may remove it (M§7.3)"));
        }
        self.propose(&gid, &Op::RemoveDevice { device: device.to_string(), rotate: false }, now)
    }

    /// Remove a device of this identity from every group it is in, by credential (a revoked device's leaf no longer
    /// authenticates, spec-gap 57), and rotate the archive key once the personal group no longer holds it (M§12.4).
    /// Frames to send: one commit per group (and the new archive key at once when the personal group never held it).
    pub fn remove_device(&mut self, device: &str, now: f64) -> Result<Vec<Event>, Error> {
        let now = now as i64;
        let personal = self.personal.clone().ok_or_else(|| Error::from("no personal group yet"))?;
        let groups: Vec<String> = self.convs.iter().filter(|(_, c)| !commits::device_leaves(&c.group, device).is_empty()).map(|(g, _)| g.clone()).collect();
        if groups.is_empty() {
            return Err(Error::from(format!("no group holds a leaf of {device}")));
        }
        let mut out = vec![];
        for gid in &groups {
            let op = Op::RemoveDevice { device: device.to_string(), rotate: *gid == personal };
            out.push(match self.propose(gid, &op, now) {
                Ok(f) => Event::send(f),
                Err(e) => Event::refused(format!("remove {device} from {gid}: {}", e.0)),
            });
        }
        if !groups.contains(&personal) {
            out.extend(self.new_archive_key(&personal, now));
        }
        Ok(out)
    }

    /// A fresh archive key, current from now on, sent to the personal group `personal` as an object (M§12.1).
    fn new_archive_key(&mut self, personal: &str, now: i64) -> Vec<Event> {
        let akid = self.fresh_id(now);
        let key = KeyPair::generate().seed(); // 32 random bytes (M§12.1)
        self.archive_keys.insert(akid.clone(), (key.to_vec(), now));
        self.history.archive_key(&akid, now); // the current key, from now on
        let obj = json!({"object": "archive-key", "akid": akid, "key": b64(&key), "created_at": now});
        let mut out = vec![match self.send_object(personal, &obj, now) {
            Ok(f) => Event::send(f),
            Err(e) => Event::error(e.0),
        }];
        out.push(Ui::ArchiveKeyCreated { group: personal.to_string(), akid }.into());
        out
    }

    /// The roster changes of a conversation and its predecessors, oldest first: `[{group, seq, epoch, by, added,
    /// removed, left}]` (M§7.3: rendered, attributed to the committing identity).
    pub fn roster_log(&self, gid: &str) -> Vec<Value> {
        let groups = self.lineage(gid);
        self.roster_log.iter().filter(|(g, _)| groups.contains(*g))
            .flat_map(|(g, es)| es.iter().map(move |e| { let mut e = e.clone(); e["group"] = json!(g); e })).collect()
    }

    /// A text message to a conversation (M§8.1 `content`, kind `text`): the deposit to send, pending until the hub's
    /// `accepted` (M§9.2).
    pub fn send_text(&mut self, gid: &str, text: &str, now: f64) -> Result<String, Error> {
        let now_i = now as i64;
        let gid = &self.live(gid);
        let conversation = self.convs.get(gid).map(|c| c.conversation.clone()).ok_or_else(|| Error::from("not a member of that group"))?;
        self.may_send_content(gid, now_i)?;
        let obj = json!({"object": "content", "id": self.fresh_id(now_i), "conversation": conversation, "sender": self.keys.identity,
            "sent_at": now_i, "kind": "text", "purpose": "message", "content_type": "text/plain", "text": text});
        self.send_object(gid, &obj, now_i)
    }

    /// Send any object to `gid` as an application message (M§8): content is sent only where it may be (C§5, M§7.3).
    pub fn send(&mut self, gid: &str, obj: &Value, now: f64) -> Result<Sent, Error> {
        let now = now as i64;
        let gid = self.live(gid);
        if !self.convs.contains_key(&gid) {
            return Err(Error::from("not a member of that group"));
        }
        if obj["object"] == "content" {
            self.may_send_content(&gid, now)?;
        }
        let (item, send) = self.send_item(&gid, obj, now)?;
        Ok(Sent { item, send })
    }

    /// The conversations this device is in, not being left and not succeeded by one it is in (M§6.2, M§7.5, C§5).
    pub fn conversations(&self, now: f64) -> Vec<Conversation> {
        let ctx = Context::new(now as i64, &self.resolver);
        self.convs.iter().filter(|(g, _)| !self.leaving.contains(*g))
            .filter(|(g, _)| !self.successors.successor(g).is_some_and(|w| self.convs.contains_key(w) && w != g.as_str())).map(|(g, c)| {
            let leaves: Vec<_> = c.group.members().filter_map(|m| member_identity(&c.group, m.index, &ctx).ok()).collect();
            let recording = self.recording_of(&leaves, &c.conversation);
            let mut members: Vec<String> = leaves.into_iter().map(|w| w.identity).collect();
            members.sort();
            members.dedup();
            Conversation { group: g.clone(), conversation: c.conversation.clone(), kind: c.kind.clone(), peer: c.peer.clone(), members,
                epoch: c.group.epoch().as_u64(), recorded: recording["recorded"] == json!(true),
                recorders: serde_json::from_value(recording["recorders"].clone()).unwrap_or_default(),
                may_send: recording["may_send"] == json!(true),
                recorders_pending: serde_json::from_value(recording["pending"].clone()).unwrap_or_default(),
                hub: Hub { did: c.hub.0.clone(), uri: c.hub.1.clone() }, pending: self.outbox.pending(g) + self.handover.get(g).map_or(0, Vec::len),
                hub_down: self.outbox.is_down(g), predecessors: self.lineage(g).into_iter().filter(|x| x != g).collect() }
        }).collect()
    }

    /// The thread of one group in `seq` order (M§8.5): `[{key, sender, sender_device, object, seq, mine, delivered,
    /// from_archive}]`; `read_through` of the whole thread is `{identity: content id}` (M§10.3), in
    /// [`Messenger::read_marks`].
    pub fn thread(&self, gid: &str) -> Vec<Value> {
        let snap = self.convs.get(gid).map(|c| c.receipts.snapshot()).unwrap_or(Value::Null);
        let groups = self.lineage(gid);
        let mut list: Vec<Value> = self.messages.iter().filter(|m| m["group"].as_str().is_some_and(|g| groups.contains(g))).map(|m| {
            let mut m = m.clone();
            m["delivered"] = snap["delivered"][s_of(&m["object"]["id"])].clone();
            m["played"] = snap["played"][s_of(&m["object"]["id"])].clone();
            m
        }).collect();
        // predecessors first, each in seq order (a successor's numbering starts afresh)
        let order: Vec<String> = { let mut v: Vec<String> = groups.iter().cloned().collect(); v.sort_by_key(|g| (g == gid, self.lineage(g).len())); v };
        list.sort_by_key(|m| (order.iter().position(|g| m["group"] == g.as_str()).unwrap_or(0), m["seq"].as_i64().unwrap_or(i64::MAX), s_of(&m["key"])));
        list
    }

    /// Delete the message `content_id` from `gid`'s thread on this device. Nothing is sent: the other members, and
    /// this identity's other devices, keep their copies. A copy arriving again (from the archive, or MLS) is not shown.
    /// Whether there was such a message. (M§8.5 and M§12 say what a device shows; what its user removes from it is
    /// the device's own business.)
    pub fn forget_message(&mut self, gid: &str, content_id: &str) -> bool {
        let groups = self.lineage(gid);
        self.forget(|m| m["group"].as_str().is_some_and(|g| groups.contains(g)) && m["object"]["id"] == content_id) > 0
    }

    /// Delete every message of `gid`'s thread (with its predecessors') on this device, as [`Messenger::forget_message`]
    /// does one; the conversation itself stays. How many there were.
    pub fn forget_thread(&mut self, gid: &str) -> usize {
        let groups = self.lineage(gid);
        self.forget(|m| m["group"].as_str().is_some_and(|g| groups.contains(g)))
    }

    fn forget(&mut self, which: impl Fn(&Value) -> bool) -> usize {
        let before = self.messages.len();
        let forgotten = &mut self.forgotten;
        self.messages.retain(|m| {
            let gone = which(m);
            if gone {
                forgotten.insert(history::object_key(&m["object"]));
            }
            !gone
        });
        before - self.messages.len()
    }

    /// Each identity's read watermark in a conversation, `{identity: content id}` (M§10.3; a sibling's undisclosed
    /// one reaches us through the personal group, M§10.5).
    pub fn read_marks(&self, gid: &str) -> Value {
        self.convs.get(gid).map(|c| c.receipts.snapshot()["read_through"].clone()).unwrap_or_else(|| json!({}))
    }

    /// Introductions delivered through the mailbox and not yet answered (M§14.1), `{id: {from, purpose, sealed,
    /// expires_at, identity}}`; `identity` is the introduction's own (§19.4), its `display_name` a claim.
    pub fn requests(&self) -> &BTreeMap<String, Value> {
        &self.requests
    }

    /// The personal group's id, once created.
    pub fn personal(&self) -> Option<String> {
        self.personal.clone()
    }

    /// The store holding this device's MLS state, for a host that writes [`Messenger::state`] beside it (spec-gap 44).
    pub fn store(&self) -> &S {
        self.mls.provider()
    }

    /// Whether nothing this device did is still in flight: no deposit awaiting its answer or waiting to go again, no
    /// refused commit waiting for a sync, no item refused by a hub the group may have left (M§5.3, M§6.5, M§7.4). A
    /// host whose commands complete one at a time waits for this.
    pub fn settled(&self) -> bool {
        // the personal group's archive key waits for its GroupInfo's answer under a placeholder, never answered itself
        let waiting = self.pending.iter().any(|(_, p)| !matches!(p, Pending::PersonalReady { .. }));
        !waiting && self.pending.deferred() == 0 && self.retries.is_empty() && self.moved_items.is_empty()
    }

    /// The successor of `gid` this device converged on and is in (M§7.5), if any.
    pub fn successor(&self, gid: &str) -> Option<String> {
        self.successors.successor(gid).filter(|w| self.convs.contains_key(*w)).map(String::from)
    }

    /// One conversation's receipt state (M§10): what each identity has been delivered, read and played, and the
    /// activity shown, as the receipts machine keeps it; null for a group this device is not in.
    pub fn receipt_state(&self, gid: &str) -> Value {
        self.convs.get(gid).map(|c| c.receipts.snapshot()).unwrap_or(Value::Null)
    }

    /// The devices a mailbox's `key-packages` answer for `target` would add, as the vector-pinned rule picks them
    /// (M§5.5, M§6.2, C§5), or why none would be.
    pub fn key_package_devices(&self, target: &str, payload: &Value, now: f64) -> Result<Vec<KeyPackageDevice>, Error> {
        if payload["type"] != "key-packages" {
            return Err(Error::from(format!("key-package-fetch refused: {} {}", payload["reason"], payload["detail"])));
        }
        let me = key_packages::Me { identity: &self.keys.identity, device: &self.keys.device.did() };
        let picked = key_packages::select(payload, target, &me, "conversation", self.mls.provider(), &self.ctx(now as i64))
            .map_err(|why| Error::from(format!("no device of {target} to add: {why} (C§5)")))?;
        let ctx = self.ctx(now as i64);
        Ok(picked.iter().filter_map(|(bytes, _)| authenticate_key_package(bytes, self.mls.provider(), &ctx).ok())
            .map(|(_, w)| KeyPackageDevice { recorder: w.is_recorder(), device: w.device }).collect())
    }

    /// TEST ONLY: let this recorder device send content anyway (C§5 forbids it), so a demo can show members dropping
    /// it.
    pub fn set_recorder_sends(&mut self, on: bool) {
        self.recorder_sends = on;
    }

    /// Process one frame from the mailbox. Returns the emissions: `{send: frame}` (to the mailbox), `{ui: …}`
    /// events, `{sync: true}` when a refused commit asks for one (spec-gap 58), `{refused: …}`, `{error: …}`.
    pub fn inbound(&mut self, frame: &str, now: f64) -> Vec<Event> {
        let now_i = now as i64;
        let mut out = vec![];
        self.seen.sweep(now_i);
        let inb = {
            let mut ctx = Context::new(now_i, &self.resolver);
            ctx.seen_ids = self.seen.set();
            ctx.supported = self.supported.clone();
            match verify_frame(frame, &ctx) {
                Ok(i) => i,
                Err(r) => return vec![Event::Rejected { rejected: Rejected { code: r.code, reason: r.reason } }],
            }
        };
        let p = inb.payload().clone();
        self.seen.insert(&s_of(&p["id"]), now_i, now_i);
        let answers_ours = p["in_reply_to"].as_str().is_some_and(|id| self.pending.contains(id));
        if inb.device() != self.mailbox.0 && !(matches!(inb.msg_type(), "key-packages" | "error") || (inb.msg_type() == "accepted" && answers_ours)) {
            // Everything on this binding is the mailbox's (M§4.1), except what it relays unchanged: a hub's `accepted`
            // or `error` to a deposit it forwarded (M§5.2), and a peer mailbox's answer to a key-package-fetch (M§5.5).
            out.push(Event::Drop { drop: format!("frame from {}, not the mailbox", inb.device()) });
            return out;
        }
        match inb.msg_type() {
            "items" => {
                for item in p["items"].as_array().into_iter().flatten() {
                    match self.item(item, now_i) {
                        Ok(more) => out.extend(more),
                        Err(e) => out.push(Event::error(format!("item {}: {}", item["cursor"], e.0))),
                    }
                }
                out.extend(self.receipts_batch(now_i));
                out.extend(self.apply_restored(now_i));
                if p["next"].is_string() {
                    out.push(Event::send(self.sync_frame(false, now)));
                } else if p["in_reply_to"].is_string() {
                    // caught up: membership changes refused for a conflict are re-proposed while still needed, and what a
                    // moved group's old hub refused goes to the new one (M§7.4). Only the answer to a sync says so: a live
                    // push (no in_reply_to, M§5.4) can arrive first, from before the winning commit or the move
                    out.extend(self.after_sync(now_i));
                }
            }
            "accepted" => out.extend(self.accepted(&p, now_i)),
            "error" if p["reason"] == "mailbox.cursor-invalid" => {
                // M§5.4: re-sync from null; seq positions make the redelivery collapse (M§8.5)
                self.resume.cursor_invalid();
                out.push(Ui::Resync.into());
                out.push(Event::send(self.sync_frame(false, now)));
            }
            "error" => out.extend(self.refused(&p, now_i)),
            "key-packages" => out.push(Event::KeyPackages { key_packages: p }),
            other => out.push(Event::Drop { drop: format!("no handler for {other}") }),
        }
        out.extend(self.recording_changes(now_i));
        out
    }

    /// A fresh ULID (§12.9: timestamp-consistent with `now`).
    pub fn new_id(&mut self, now: f64) -> String {
        self.fresh_id(now as i64)
    }
}

impl<S: Store> Messenger<S> {
    fn fresh_id(&mut self, now: i64) -> String {
        self.counter += 1;
        dsip_core::ulid::Ulid::generate_at((now.max(0) as u64) * 1000 + self.counter % 1000).as_str().to_string()
    }

    fn ctx(&self, now: i64) -> Context<'_> {
        Context::new(now, &self.resolver)
    }

    fn new_receipts(&self, now: i64) -> Receipts {
        Receipts::new(&self.keys.identity, &self.policy, now)
    }


    /// Authenticate a `key-packages` answer and pick the devices to add for `target` (M§5.5, M§6.2, C§5).
    fn pick_key_packages(&self, target: &str, payload: &Value, now: i64) -> Result<Vec<Vec<u8>>, Error> {
        if payload["type"] != "key-packages" {
            return Err(Error::from(format!("key-package-fetch refused: {} {}", payload["reason"], payload["detail"])));
        }
        let me = key_packages::Me { identity: &self.keys.identity, device: &self.keys.device.did() };
        let picked = key_packages::select(payload, target, &me, "conversation", self.mls.provider(), &self.ctx(now))
            .map_err(|why| Error::from(format!("no device of {target} to add: {why} (C§5)")))?;
        Ok(picked.into_iter().map(|(bytes, _)| bytes).collect())
    }

    /// A group of `kind` hubbed at this identity's mailbox (M§6.5 rule 6, M§6.6): registered with `mailbox-config`,
    /// its GroupInfo deposited. Returns the group id and the frames, GroupInfo last.
    fn new_group(&mut self, kind: &str, now: i64) -> Result<(String, Vec<String>), Error> {
        self.new_group_for(None, kind, None, now)
    }

    /// As [`Self::new_group`], for an existing `conversation` and with `successor_of` (M§7.5).
    fn new_group_for(&mut self, conversation: Option<String>, kind: &str, successor_of: Option<&str>, now: i64) -> Result<(String, Vec<String>), Error> {
        let conversation = conversation.unwrap_or_else(|| self.fresh_id(now));
        let group_id = self.fresh_id(now).into_bytes();
        let conv = json!({"conversation": conversation, "kind": kind, "hub": {"did": self.mailbox.0, "uri": self.mailbox.1}, "successor_of": successor_of});
        let group = self.mls.create_group(&group_id, &serde_json::to_vec(&conv).map_err(err)?).map_err(|e| err(e.0))?;
        let gid = b64(group.group_id().as_slice());
        let epoch = group.epoch().as_u64();
        self.convs.insert(gid.clone(), Conv {
            group, conversation, kind: kind.to_string(), hub: (self.mailbox.0.clone(), self.mailbox.1.clone()), peer: None,
            receipts: self.new_receipts(now), joined_epoch: epoch,
        });
        let config = self.config_env(json!({"subject": self.keys.identity, "groups": [{"group": gid, "state": "joined", "hub": self.mailbox.0}]}), now);
        let gi = self.group_info_frame(&gid, now)?;
        Ok((gid, vec![config.frame(), gi]))
    }

    /// The GroupInfo deposit for the hub (M§6.5 rule 6).
    fn group_info_frame(&mut self, gid: &str, now: i64) -> Result<String, Error> {
        self.group_info_frame_at(gid, None, now)
    }

    /// As [`Self::group_info_frame`]; `handover_seq` bootstraps a group's new hub, which continues the numbering after
    /// the seq the old hub gave the moving commit (M§7.4).
    fn group_info_frame_at(&mut self, gid: &str, handover_seq: Option<i64>, now: i64) -> Result<String, Error> {
        let c = self.convs.get(gid).ok_or_else(|| Error::from("group"))?;
        let gi = c.group.export_group_info(self.mls.provider().crypto(), &self.mls.signer(), true).map_err(|e| err(format!("{e:?}")))?;
        let bytes = gi.tls_serialize_detached().map_err(|e| err(format!("{e:?}")))?;
        let mut fields = json!({"mls": b64(&bytes)});
        if let Some(h) = handover_seq {
            fields["handover_seq"] = json!(h);
        }
        Ok(self.hub_deposit(gid, "group-info", fields, now))
    }

    /// The group moved to `hub` (`{did, uri}`) by the commit at `seq`: deposits go there from now on, and this
    /// identity's mailbox is told, so it admits the new hub's fan-out and forwards to it (M§7.4 "Member mailboxes follow
    /// their owner's devices"). The same `did` at a new `uri` is not a move: no `handover_seq`, nothing logged.
    fn hub_moved(&mut self, gid: &str, hub: &Value, (seq, epoch): (i64, u64), by: &str, now: i64) -> Vec<Event> {
        let (did, uri) = (s_of(&hub["did"]), s_of(&hub["uri"]));
        let Some(c) = self.convs.get_mut(gid) else { return vec![] };
        let moved = c.hub.0 != did;
        c.hub = (did.clone(), uri.clone());
        let mut g = json!({"group": gid, "state": "joined", "hub": did});
        if uri.starts_with("wss://") {
            g["hub_uri"] = json!(uri);
        }
        let mut out = vec![];
        if moved {
            // spec-gap 129: until the new hub accepts a deposit, its mailbox.unknown-group means "not set up yet"
            let a = self.arrivals.entry(gid.to_string()).or_insert_with(|| MoveArrival::new(&json!({"now": now})));
            a.set_now(now);
            a.moved(&did);
            g["handover_seq"] = json!(seq);
            // rendered in the thread like a roster change, attributed to the committing identity
            let entry = json!({"seq": seq, "epoch": epoch, "by": by, "added": [], "removed": [], "left": [], "hub": did});
            self.roster_log.entry(gid.to_string()).or_default().push(entry);
            out.push(Ui::HubMoved { group: gid.to_string(), seq, epoch, by: by.to_string(), added: vec![], removed: vec![], left: vec![], hub: did }.into());
        }
        let env = self.config_env(json!({"subject": self.keys.identity, "groups": [g]}), now);
        out.insert(0, Event::send(env.frame()));
        out
    }

    /// A deposit to a group's hub through this device's mailbox, the delegation in the header (M§5.1, M§5.2).
    fn hub_deposit(&mut self, gid: &str, class: &str, fields: Value, now: i64) -> String {
        let hub = self.convs.get(gid).map(|c| c.hub.0.clone()).unwrap_or_default();
        if let Some(bytes) = fields["mls"].as_str().and_then(dsip_core::b64::decode) {
            self.own.insert(digest(&bytes));
        }
        let env = wire::deposit_delegated(&self.keys.device, vec![self.keys.delegation.clone()], &hub, now, gid, class, fields);
        if let Some(p) = wire::payload_of(&env) {
            self.pending.addressed(s_of(&p["id"]), hub);
        }
        env.frame()
    }

    /// Stage a commit for `op` and deposit it (M§6.5); merged on `accepted`.
    fn propose(&mut self, gid: &str, op: &Op, now: i64) -> Result<String, Error> {
        let ctx = Context::new(now, &self.resolver);
        if matches!(op, Op::Rejoin) {
            return self.external_commit(gid, now);
        }
        let c = self.convs.get_mut(gid).ok_or_else(|| Error::from("group"))?;
        // M§7.3: another identity is removed whole, every leaf of it (the rule every member checks, spec-gap 126)
        let leaves = match op {
            Op::Remove { identity } => commits::identity_leaves(&c.group, &ctx, identity),
            Op::RemoveDevice { device, .. } => commits::device_leaves(&c.group, device),
            _ => vec![],
        };
        let mut packages = vec![];
        let (change, grants) = match op {
            Op::Rejoin => unreachable!("handled above"),
            // M§7.3 "Leaving": the leaver's Remove proposals, committed by reference
            Op::Leave { .. } => (Change::Proposals, &[][..]),
            Op::Remove { identity } if leaves.is_empty() => return Err(Error::from(format!("{identity} is not a member"))),
            Op::Remove { .. } => (Change::Remove(&leaves), &[][..]),
            Op::RemoveDevice { device, .. } if leaves.is_empty() => return Err(Error::from(format!("no leaf of {device} in that group"))),
            Op::RemoveDevice { .. } => (Change::Remove(&leaves), &[][..]),
            Op::Update => (Change::Update, &[][..]),
            // M§7.4: a GroupContextExtensions commit changing the hub and nothing else, ordered by the old hub
            Op::MoveHub { hub } => (Change::MoveHub(hub), &[][..]),
            Op::Add { kps, grants, .. } => {
                for bytes in kps {
                    let (kp, _) = authenticate_key_package(bytes, self.mls.provider(), &ctx).map_err(|e| err(e.0))?;
                    packages.push(kp);
                }
                (Change::Add(&packages), grants.as_slice())
            }
        };
        // M§7.2: a welcome, whatever commit produced it, goes with the commit, or a member it adds is left out
        let built = commits::build(&self.mls, &mut c.group, change).map_err(err)?;
        let fields = built.fields(grants);
        let frame = self.hub_deposit(gid, "handshake", fields.clone(), now);
        let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
        self.pending.insert(id, Pending::Commit { gid: gid.to_string(), op: Some(op.clone()), fields });
        Ok(frame)
    }

    /// Whether a conversation is recorded and by whom, from its members' leaves (C§5, the pinned `conversation`
    /// check), with the recorders accepted: this identity's own (C§5: they need none) and those its devices accepted
    /// for this conversation. `pending` lists the recorders still to accept: a new one asks again.
    fn recording_of(&self, leaves: &[dsip_messaging::mls_wire::LeafIdentity], conversation: &str) -> Value {
        recording::state(leaves, &self.keys.identity, self.recording_accepted.get(conversation).unwrap_or(&BTreeSet::new()))
    }

    /// C§5: a conversation that became recorded by a new recorder device, or is no longer recorded, since it was last
    /// shown: `{ui: "recording", group, conversation, new: [{device, subject, own}], ended, may_send}`. A recorder
    /// device itself renders nothing; nor does the personal group, which a recorder never joins.
    fn recording_changes(&mut self, now: i64) -> Vec<Event> {
        let mut out = vec![];
        if self.recorder {
            return out;
        }
        self.recording_seen.retain(|g, _| self.convs.contains_key(g));
        let gids: Vec<String> = self.convs.iter().filter(|(_, c)| c.kind != "personal").map(|(g, _)| g.clone()).collect();
        for gid in gids {
            let conversation = self.convs.get(&gid).map(|c| c.conversation.clone()).unwrap_or_default();
            let st = self.recording_of(&self.leaves_of(&gid, now), &conversation);
            let recorders: Vec<&Value> = st["recorders"].as_array().into_iter().flatten().collect();
            let devices: BTreeSet<String> = recorders.iter().filter_map(|r| r["device"].as_str().map(String::from)).collect();
            let before = self.recording_seen.get(&gid).cloned().unwrap_or_default();
            if devices == before {
                continue;
            }
            let new: Vec<NewRecorder> = recorders.iter().filter(|r| r["device"].as_str().is_some_and(|d| !before.contains(d)))
                .map(|r| NewRecorder { device: r["device"].clone(), subject: r["subject"].clone(), own: r["subject"] == json!(self.keys.identity) }).collect();
            out.push(Ui::Recording { group: gid.clone(), conversation, new, ended: devices.is_empty(), may_send: st["may_send"].clone() }.into());
            self.recording_seen.insert(gid, devices);
        }
        out
    }

    /// The members' leaves of a group this device is in, authenticated at `now` (M§6.2).
    fn leaves_of(&self, gid: &str, now: i64) -> Vec<dsip_messaging::mls_wire::LeafIdentity> {
        let ctx = Context::new(now, &self.resolver);
        self.convs.get(gid).map(|c| c.group.members().filter_map(|m| member_identity(&c.group, m.index, &ctx).ok()).collect()).unwrap_or_default()
    }

    /// Content may go to `gid` (C§5): this device is not a recorder, which never speaks, and every recorder in the
    /// conversation is accepted.
    fn may_send_content(&self, gid: &str, now: i64) -> Result<(), Error> {
        if self.recorder && !self.recorder_sends {
            return Err(Error::from("this device is a recorder: it never sends content (C§5)"));
        }
        if self.leaving.contains(gid) {
            return Err(Error::from("this identity has left the conversation (M§7.3)"));
        }
        let conversation = self.convs.get(gid).map(|c| c.conversation.clone()).ok_or_else(|| Error::from("not a member of that group"))?;
        if self.recording_of(&self.leaves_of(gid, now), &conversation)["may_send"] != json!(true) {
            return Err(Error::from("this conversation is recorded and a recorder is not accepted: no content is sent (C§5)"));
        }
        Ok(())
    }

    /// Encrypt an application object and deposit it; pending until accepted (M§9.2).
    fn send_object(&mut self, gid: &str, obj: &Value, now: i64) -> Result<String, Error> {
        self.send_item(gid, obj, now).map(|(_, frame)| frame)
    }

    /// As [`Messenger::send_object`], with the outbox item id the object went out under (`None`: kept for a
    /// successor, M§9.4).
    fn send_item(&mut self, gid: &str, obj: &Value, now: i64) -> Result<(Option<String>, String), Error> {
        let (provider, signer) = (self.mls.provider(), self.mls.signer());
        let c = self.convs.get_mut(gid).ok_or_else(|| Error::from("not a member of that group"))?;
        let bytes = c.group.create_message(provider, &signer, &serde_json::to_vec(obj).map_err(err)?)
            .map_err(|e| err(format!("{e:?}")))?.tls_serialize_detached().map_err(|e| err(format!("{e:?}")))?;
        let mut item = json!({"id": self.fresh_id(now), "mls": b64(&bytes), "obj": obj});
        if let Some(b) = obj.get("blob") {
            // M§8.4 rule 4: the deposit's manifest names the blob without its key
            item["blobs"] = json!([{"uri": b["uri"], "sha256": b["sha256"], "size": b["size"]}]);
        }
        let queued = match self.outbox.deposit(gid, item.clone()) {
            Deposit::Abandoned => {
                // M§9.4: the dead group takes no more content; it goes to the successor once there is one
                self.handover.entry(gid.to_string()).or_default().push(obj.clone());
                return Ok((None, String::new()));
            }
            Deposit::Queued => true,
            Deposit::Send => false,
        };
        if obj["object"] == "content" {
            // shown at once as ours; its seq is filled in by the hub's accepted (M§8.5)
            let key = history::object_key(obj);
            self.shown.insert(key.clone());
            self.messages.push(json!({"group": gid, "key": key, "sender": self.keys.identity, "sender_device": self.keys.device.did(),
                "object": obj, "seq": null, "mine": true, "item": item["id"]}));
        }
        let id = Some(s_of(&item["id"]));
        if queued {
            return Ok((id, String::new())); // M§9.4: queued behind the pending head while the hub is down
        }
        Ok((id, self.deposit_item(gid, &item, now)))
    }

    /// The deposit of a pending item, under a fresh envelope but the same item id and bytes (M§9.3).
    fn deposit_item(&mut self, gid: &str, item: &Value, now: i64) -> String {
        let mut fields = json!({"mls": item["mls"]});
        if let Some(b) = item.get("blobs") {
            fields["blobs"] = b.clone();
        }
        let frame = self.hub_deposit(gid, "application", fields, now);
        let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
        self.pending.watch(id.clone(), now);
        self.pending.insert(id, Pending::Application { gid: gid.to_string(), item: s_of(&item["id"]) });
        frame
    }

    /// The hub or mailbox accepted a deposit of ours (M§5.3).
    fn accepted(&mut self, p: &Value, now: i64) -> Vec<Event> {
        let mut out = vec![];
        let id = s_of(&p["in_reply_to"]);
        let Some((pending, hub)) = self.pending.answer(&id) else { return out };
        if let (Some(gid), Some(hub)) = (pending.gid(), hub) {
            if let Some(a) = self.arrivals.get_mut(gid) {
                a.set_now(now);
                a.answer(&hub, None); // M§7.4 (spec-gap 129): an accepted shows the new hub hosts the group
            }
        }
        match pending {
            Pending::Proposal { gid } => {
                if let Some(seq) = p["seq"].as_i64() {
                    self.resume.sent(&gid, seq);
                    self.gap_of_from(&gid, seq, now).step(&json!({"item": {"seq": seq, "class": "handshake"}}));
                }
                out.push(Ui::LeaveProposed { group: gid, seq: p["seq"].as_i64() }.into());
            }
            Pending::Commit { gid, op: Some(Op::Rejoin), .. } => {
                // M§6.8: the external commit is already applied locally (OpenMLS stores it merged)
                let Some(c) = self.convs.get(&gid) else { return out };
                let (epoch, kind, conversation) = (c.group.epoch().as_u64(), c.kind.clone(), c.conversation.clone());
                let members = self.member_identities(&gid, now);
                if kind == "personal" {
                    self.personal = Some(gid.clone());
                }
                self.history.joined(&gid, epoch);
                if let Some(seq) = p["seq"].as_i64() {
                    self.resume.sent(&gid, seq);
                    self.gap_of_from(&gid, seq, now).step(&json!({"item": {"seq": seq, "class": "handshake"}}));
                }
                self.retries.remove(&gid);
                let env = self.config_env(json!({"subject": self.keys.identity, "groups": [{"group": gid, "state": "joined"}]}), now);
                out.push(Event::send(env.frame()));
                out.push(Ui::Joined { group: gid.clone(), conversation: json!(conversation), kind, members, epoch, external: Some(true),
                    seq: Some(p["seq"].as_i64()), successor_of: None }.into());
                // M§6.5 rule 6: the hub gets the GroupInfo of the new epoch
                if let Ok(f) = self.group_info_frame(&gid, now) {
                    let id = Envelope::from_frame(&f).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
                    self.pending.insert(id, Pending::GroupInfo { gid, then: None });
                    out.push(Event::send(f));
                }
            }
            Pending::Commit { gid, op, .. } => {
                let before_ids = self.member_identities(&gid, now);
                let left: Vec<String> = match &op {
                    Some(Op::Leave { identity }) => vec![identity.clone()],
                    _ => vec![],
                };
                if let Some(c) = self.convs.get_mut(&gid) {
                    if let Err(e) = c.group.merge_pending_commit(self.mls.provider()) {
                        out.push(Event::error(format!("merge commit: {e:?}")));
                        return out;
                    }
                    let epoch = c.group.epoch().as_u64();
                    let (added, device) = match &op { Some(Op::Add { peer, device, .. }) => (Some(peer.clone()), device.clone()), _ => (None, None) };
                    out.push(Ui::Committed { group: gid.clone(), epoch, seq: p["seq"].as_i64(), added, device,
                        personal: self.personal.as_deref() == Some(gid.as_str()), op: op.as_ref().map(Op::describe) }.into());
                }
                if let Some(epoch) = self.convs.get(&gid).map(|c| c.group.epoch().as_u64()) {
                    let me = self.keys.identity.clone();
                    out.extend(self.log_roster(&gid, (p["seq"].as_i64(), epoch), &me, &before_ids, &left, now));
                }
                if let Some(seq) = p["seq"].as_i64() {
                    self.resume.sent(&gid, seq);
                    self.gap_of_from(&gid, seq, now).step(&json!({"item": {"seq": seq, "class": "handshake"}}));
                }
                self.retries.remove(&gid);
                self.unknown_at.remove(&gid);
                // M§7.4: the committer's mailbox follows on `accepted`, and the new hub is bootstrapped by the GroupInfo
                // carrying the seq the old hub gave the moving commit
                let mut handover_seq = None;
                if let (Some(Op::MoveHub { hub }), Some(seq), Some(epoch)) = (&op, p["seq"].as_i64(), self.convs.get(&gid).map(|c| c.group.epoch().as_u64())) {
                    let me = self.keys.identity.clone();
                    out.extend(self.hub_moved(&gid, hub, (seq, epoch), &me, now));
                    handover_seq = Some(seq);
                }
                out.extend(self.flush_handover(&gid, now)); // M§9.4: the successor holds its members: the pending items go in
                if let Some(Op::RemoveDevice { rotate: true, .. }) = &op {
                    // M§12.4: the new archive key goes out in the epoch the removed device is no longer in
                    out.extend(self.new_archive_key(&gid, now));
                }
                match self.group_info_frame_at(&gid, handover_seq, now) {
                    Ok(f) => {
                        let id = Envelope::from_frame(&f).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
                        self.pending.insert(id, Pending::GroupInfo { gid, then: None });
                        out.push(Event::send(f));
                    }
                    Err(e) => out.push(Event::error(e.0)),
                }
            }
            Pending::GroupInfo { gid, then } => {
                if then.is_none() {
                    out.extend(self.flush_handover(&gid, now)); // a successor with nobody to add (M§9.4)
                }
                if let Some(op) = then {
                    match self.propose(&gid, &op, now) {
                        Ok(f) => out.push(Event::send(f)),
                        Err(e) => out.push(Event::refused(format!("add: {}", e.0))),
                    }
                }
                if let Some(Pending::PersonalReady { gid: g }) = self.pending.remove(&format!("personal:{gid}")) {
                    // M§7.1, M§12.1: the first archive key
                    out.extend(self.new_archive_key(&g, now));
                    out.push(Ui::Personal { group: g }.into());
                }
            }
            Pending::Application { gid, item } => {
                let obj = self.outbox.item(&gid, &item).map(|i| i["obj"].clone());
                let after_outage = self.outbox.item(&gid, &item).is_some_and(|i| i["forwarded"] == json!(true));
                self.outbox.remove(&gid, &item);
                if let (Some(obj), Some(seq)) = (obj, p["seq"].as_i64()) {
                    // M§10.2: our own content enters the receipts machine at its hub seq, so receipts for it are booked
                    let emissions = self.convs.get_mut(&gid).map(|c| c.receipts.own(now, seq, &obj)).unwrap_or_default();
                    out.extend(self.receipt_sends(&gid, emissions, now));
                    // M§12.2: our own content is archived under the seq of its accepted (spec-gap 51); our read watermark
                    // (spec-gap 68) and call events (spec-gap 63) too, as state for a device added later
                    let decisions = self.history.sent(&gid, seq, &history::object_key(&obj), &obj);
                    let (me, dev) = (self.keys.identity.clone(), self.keys.device.did());
                    out.extend(self.archive_requests(&gid, &decisions, &obj, &me, &dev, seq, now));
                }
                if let Some(seq) = p["seq"].as_i64() {
                    // spec-gap 47: our own copy is processed by its accepted seq
                    self.resume.sent(&gid, seq);
                    self.gap_of_from(&gid, seq, now).step(&json!({"item": {"seq": seq, "class": "application"}}));
                    for m in self.messages.iter_mut().filter(|m| m["item"] == item) {
                        m["seq"] = json!(seq);
                    }
                }
                out.push(Ui::Sent { group: gid.clone(), item: item.clone(), seq: p["seq"].as_i64(), duplicate: p["duplicate"].as_bool(), after_outage }.into());
                // M§9.4: an accepted ends an outage and flushes the queue in order
                let ems = self.outbox.answered(&gid, &item, None);
                if ems.iter().any(|e| e.get("forward").is_some()) {
                    out.push(Ui::HubBack { group: gid.clone() }.into());
                }
                out.extend(self.outage_emissions(&gid, ems, now));
            }
            Pending::PersonalReady { .. } => {}
            Pending::KeyPackages { count } => out.push(Ui::KeyPackagesUploaded { count }.into()),
            Pending::Config { .. } => {}
            Pending::Archive { .. } => out.push(Ui::Archived { duplicate: p["duplicate"].as_bool() }.into()),
        }
        out
    }

    /// The hub or mailbox refused a deposit of ours (M§16): a commit as `CommitRetry` decides (spec-gap 58).
    fn refused(&mut self, p: &Value, now: i64) -> Vec<Event> {
        let mut out = vec![];
        let reason = s_of(&p["reason"]);
        let id = s_of(&p["in_reply_to"]);
        let Some((pending, hub)) = self.pending.answer(&id) else {
            // not an answer to a deposit of ours (a sync's, or none): the mailbox's reason and detail as they came
            out.push(Event::Error { error: format!("{reason} {}", p["detail"]), group: None, reason: Some(p["reason"].clone()), detail: Some(p["detail"].clone()) });
            return out;
        };
        if matches!(pending, Pending::Commit { .. } | Pending::Application { .. }) {
            let gid = pending.gid().unwrap_or_default().to_string();
            let ems = match (self.arrivals.get_mut(&gid), &hub) {
                (Some(a), Some(hub)) => {
                    a.set_now(now);
                    a.answer(hub, Some(&reason))
                }
                _ => vec![],
            };
            if let Some(d) = ems.iter().find_map(|e| e["retry_in"].as_i64()) {
                // M§7.4 (spec-gap 129): the hub the group moved to is not set up yet: the same deposit again later
                self.pending.defer(pending, now + d);
                out.push(Ui::HubArriving { group: gid, in_s: d }.into());
                return out;
            }
            if ems.iter().any(|e| e.get("expired").is_some()) {
                out.push(Ui::HubArrivalExpired { group: gid }.into());
            }
        }
        match pending {
            Pending::Commit { gid, op, .. } => {
                let mut retry = self.retries.remove(&gid).map(|(r, _)| r).unwrap_or_default();
                if let Answer::Discard { surface } = retry.answer(Some(&reason)) {
                    if matches!(op, Some(Op::Rejoin)) {
                        // M§6.8: the joined state from a GroupInfo that was not the latest is discarded
                        if let Some(mut c) = self.convs.remove(&gid) {
                            let _ = c.group.delete(self.mls.provider().storage());
                        }
                    } else if let Some(c) = self.convs.get_mut(&gid) {
                        let _ = c.group.clear_pending_commit(self.mls.provider().storage());
                    }
                    if let Some(r) = surface {
                        out.push(Event::refused(format!("commit in {gid}: {r}")));
                    } else {
                        if reason == "mailbox.unknown-group" {
                            // M§7.4: the group may have moved; the sync shows whether it did
                            if let Some(c) = self.convs.get(&gid) {
                                self.unknown_at.insert(gid.clone(), c.hub.0.clone());
                            }
                        }
                        let epoch = self.convs.get(&gid).map(|c| c.group.epoch().as_u64());
                        out.push(Ui::Conflict { group: gid.clone(), reason: reason.clone(), epoch, op: op.as_ref().map(Op::describe) }.into());
                        if let Some(op) = op.clone() {
                            self.retries.insert(gid.clone(), (retry.clone(), op));
                        }
                        out.push(Event::Sync { sync: true });
                    }
                }
            }
            Pending::GroupInfo { gid, .. } => out.push(Event::refused(format!("group-info for {gid}: {reason}"))),
            // M§7.3: a refused proposal (a stale epoch) is proposed again at the next epoch
            Pending::Proposal { gid } => out.push(Ui::LeaveProposalRefused { group: gid, reason }.into()),
            Pending::Application { gid, item } if reason == "mailbox.unknown-group" && self.convs.contains_key(&gid) => {
                // M§7.4 "A member that missed the move": sync; re-encrypted and re-sent to the new hub if the group moved
                let hub = self.convs.get(&gid).map(|c| c.hub.0.clone()).unwrap_or_default();
                self.unknown_at.insert(gid.clone(), hub);
                self.moved_items.entry(gid.clone()).or_default().push(item.clone());
                out.push(Ui::MovedCheck { group: gid, item }.into());
                out.push(Event::Sync { sync: true });
            }
            Pending::Application { gid, item } => {
                let down = is_outage(&reason);
                if !down {
                    // M§9.4: unreachable keeps it pending; any other refusal is final
                    self.outbox.remove(&gid, &item);
                    self.messages.retain(|m| m["item"] != item);
                    self.outbox.answered(&gid, &item, Some(&reason));
                } else {
                    out.extend(self.hub_unreachable(&gid, &item, false, now));
                }
                out.push(Event::Refused { refused: format!("message {item}: {reason}"), group: Some(gid), item: Some(item), pending: Some(down) });
            }
            Pending::PersonalReady { .. } => {}
            Pending::KeyPackages { .. } => out.push(Event::refused(format!("key packages: {reason}"))),
            Pending::Config { .. } => out.push(Event::refused(format!("mailbox-config: {reason}"))),
            Pending::Archive { .. } => out.push(Event::refused(format!("archive record: {reason}"))),
        }
        out
    }

    /// After a sync caught up: re-propose membership changes that lost a conflict and are still needed (M§6.5).
    fn after_sync(&mut self, now: i64) -> Vec<Event> {
        let mut out = vec![];
        for gid in self.retries.keys().cloned().collect::<Vec<_>>() {
            let (mut retry, op) = self.retries.remove(&gid).expect("present");
            let needed = match &op {
                // M§6.8: still needed while this device is not in the group
                Op::Rejoin => !self.convs.contains_key(&gid),
                // M§7.3: the proposals lapsed with the epoch the conflict moved past; the leaver proposes again
                Op::Leave { .. } => false,
                // M§7.3: still needed while any leaf of the identity remains
                Op::Remove { identity } => self.member_identities(&gid, now).contains(identity),
                // M§7.4: still needed while the group is hubbed elsewhere
                Op::MoveHub { hub } => self.convs.get(&gid).is_some_and(|c| c.hub.0 != s_of(&hub["did"])),
                // fresh key material is always still wanted
                Op::Update => true,
                // M§12.4: still needed while a leaf names the device
                Op::RemoveDevice { device, .. } => self.convs.get(&gid).is_some_and(|c| !commits::device_leaves(&c.group, device).is_empty()),
                Op::Add { peer, device, .. } => {
                    let ctx = self.ctx(now);
                    self.convs.get(&gid).is_some_and(|c| commits::add_needed(&c.group, &ctx, peer, device.as_deref()))
                }
            };
            let moved = self.hub_moved_since(&gid);
            match retry.synced(needed, moved) {
                Synced::Done => out.push(Ui::NoLongerNeeded { group: gid.clone(), op: op.describe() }.into()),
                Synced::Surface(r) => out.push(Event::refused(format!("commit in {gid}: {r}"))),
                Synced::Repropose(attempt) => match self.propose(&gid, &op, now) {
                    Ok(f) => {
                        self.retries.insert(gid.clone(), (retry.clone(), op.clone()));
                        let epoch = self.convs.get(&gid).map(|c| c.group.epoch().as_u64());
                        out.push(Ui::Repropose { group: gid.clone(), op: op.describe(), attempt, epoch }.into());
                        out.push(Event::send(f));
                    }
                    Err(e) => out.push(Event::refused(e.0)),
                },
            }
        }
        for (gid, items) in std::mem::take(&mut self.moved_items) {
            let moved = self.hub_moved_since(&gid);
            for item in items {
                if moved {
                    // M§7.4: re-encrypted at the current epoch and re-sent to the new hub
                    match self.reencrypt_item(&gid, &item, now) {
                        Some(f) => out.push(Event::send(f)),
                        None => out.push(Event::Refused { refused: format!("message {item}: no longer in the outbox"), group: Some(gid.clone()), item: Some(item), pending: None }),
                    }
                } else {
                    // spec-gap 60: no move, so mailbox.unknown-group is final
                    self.outbox.remove(&gid, &item);
                    self.messages.retain(|m| m["item"] != item);
                    out.push(Event::Refused { refused: format!("message {item}: mailbox.unknown-group"), group: Some(gid.clone()), item: Some(item), pending: Some(false) });
                }
            }
        }
        let waiting: BTreeSet<String> = self.retries.keys().cloned().collect();
        self.unknown_at.retain(|g, _| waiting.contains(g));
        out
    }

    /// Whether the group's hub is no longer the one that answered `mailbox.unknown-group` (M§7.4, spec-gap 60).
    fn hub_moved_since(&self, gid: &str) -> bool {
        match (self.unknown_at.get(gid), self.convs.get(gid)) {
            (Some(at), Some(c)) => c.hub.0 != *at,
            _ => false,
        }
    }

    /// An outbox item encrypted afresh at the group's current epoch and deposited to its current hub (M§7.4).
    fn reencrypt_item(&mut self, gid: &str, item_id: &str, now: i64) -> Option<String> {
        let obj = self.outbox.item(gid, item_id)?["obj"].clone();
        let (provider, signer) = (self.mls.provider(), self.mls.signer());
        let c = self.convs.get_mut(gid)?;
        let bytes = c.group.create_message(provider, &signer, &serde_json::to_vec(&obj).ok()?).ok()?.tls_serialize_detached().ok()?;
        let item = self.outbox.item_mut(gid, item_id)?;
        item["mls"] = json!(b64(&bytes));
        let item = item.clone();
        Some(self.deposit_item(gid, &item, now))
    }

    fn gap_of_from(&mut self, gid: &str, first_seq: i64, now: i64) -> &mut GapTracker {
        self.delivery().gap_of_from(gid, first_seq, now)
    }

    /// The delivery state inbound routing reads and writes (M§5.4).
    fn delivery(&mut self) -> Inbound<'_> {
        Inbound { resume: &mut self.resume, own: &self.own, gaps: &mut self.gaps, held_items: &mut self.held_items, gap_timeout: self.gap_timeout }
    }

    /// One `items[]` element (M§5.4): committed with the MLS change it caused (spec-gap 44).
    fn item(&mut self, item: &Value, now: i64) -> Result<Vec<Event>, MlsError> {
        let mut out = vec![];
        let class = s_of(&item["class"]);
        let gid = s_of(&item["group"]);
        let joined = self.convs.get(&gid).map(|c| c.joined_epoch);
        // M§12.3: items from before this device joined are history; a group it is not in is skipped
        let route = self.delivery().route(item, joined.is_some(), |epoch| joined.is_some_and(|j| epoch < j), now);
        let (bytes, released) = match route {
            Route::Ephemeral => {
                out.extend(self.activity_in(item, now));
                return Ok(out);
            }
            Route::Other => return Ok(out),
            Route::Duplicate => {
                out.push(Ui::Duplicate { class, cursor: item["cursor"].as_str().map(String::from) }.into());
                return Ok(out);
            }
            Route::FirstContact => {
                out.extend(self.first_contact_in(item, now));
                self.resume.commit(item, false);
                return Ok(out);
            }
            Route::Archive => {
                out.extend(self.archive_in(item, now));
                self.resume.commit(item, false);
                return Ok(out);
            }
            Route::GroupInfo { group, mls } => {
                self.group_info.insert(group, s_of(&mls));
                return Ok(out);
            }
            Route::Own { released } => {
                // our own deposit fanned back (M§6.5 rule 5), arriving before its accepted (spec-gap 47) or instead of it
                out.push(Ui::Own { class, seq: item["seq"].as_i64() }.into());
                out.extend(self.released(released, now)?);
                return Ok(out);
            }
            Route::PreJoin => {
                out.push(Ui::Prejoin { class, seq: item["seq"].as_i64() }.into());
                return Ok(out);
            }
            Route::Held => {
                // M§6.5 (spec-gap 69): a handshake beyond a seq gap, and anything after a held item, waits for the gap
                out.push(Ui::Hold { class, seq: item["seq"].as_i64() }.into());
                return Ok(out);
            }
            Route::Process { bytes, released, .. } => (bytes, released),
        };
        let before_ids = self.member_identities(&gid, now);
        let result = {
            let ctx = Context::new(now, &self.resolver);
            let me = self.keys.identity.clone();
            let target = self.convs.get_mut(&gid).filter(|_| class != "welcome").map(|c| (&mut c.group, c.conversation.as_str(), c.kind.as_str()));
            let mls = &self.mls;
            let mut delivery = Inbound { resume: &mut self.resume, own: &self.own, gaps: &mut self.gaps, held_items: &mut self.held_items,
                                         gap_timeout: self.gap_timeout };
            // committed: the delivery state records the item with its MLS effect (the host saves both together)
            delivery.commit_processed(mls.provider(), item, || process(mls, target, &class, &bytes, &ctx, &me))
        };
        let outcome = match result {
            Ok(o) => o,
            Err(e) => {
                // rolled back, and committed as handled (spec-gap 138): the in-memory group may be ahead of the store
                if let Some(c) = self.convs.get_mut(&gid) {
                    if let Some(g) = self.mls.load_group(&dsip_core::b64::decode(&gid).unwrap_or_default())? {
                        c.group = g;
                    }
                }
                out.push(Ui::Unprocessable { class, cursor: item["cursor"].as_str().map(String::from), why: e.0 }.into());
                out.extend(self.released(released, now)?);
                return Ok(out);
            }
        };
        match outcome {
            Outcome::Joined { members, group, conv, epoch, by } => {
                let joined = self.mls.load_group(&dsip_core::b64::decode(&group).unwrap_or_default())?.ok_or_else(|| MlsError("joined group not stored".into()))?;
                let kind = s_of(&conv["kind"]);
                let peer = members.iter().find(|m| **m != self.keys.identity).cloned();
                self.convs.insert(group.clone(), Conv {
                    group: joined, conversation: s_of(&conv["conversation"]), kind: kind.clone(),
                    hub: (s_of(&conv["hub"]["did"]), s_of(&conv["hub"]["uri"])), peer: if kind == "direct" { peer } else { None },
                    receipts: self.new_receipts(now), joined_epoch: epoch,
                });
                if kind == "personal" {
                    self.personal = Some(group.clone());
                }
                self.history.joined(&group, epoch);
                // M§6.6: confirm the pending registration
                let env = self.config_env(json!({"subject": self.keys.identity, "groups": [{"group": group, "state": "joined"}]}), now);
                out.push(Event::send(env.frame()));
                out.push(Ui::Joined { group: group.clone(), conversation: conv["conversation"].clone(), kind: kind.clone(), members, epoch,
                    external: None, seq: None, successor_of: Some(conv["successor_of"].clone()) }.into());
                if kind != "personal" && by != self.keys.identity {
                    // M§7.3: the joiner renders its own add, attributed to the identity whose commit added it
                    let me = self.keys.identity.clone();
                    out.push(self.roster_entry(&group, (item["seq"].as_i64(), epoch), &by, vec![me], vec![], vec![]));
                }
                if let Some(pred) = conv["successor_of"].as_str().map(String::from) {
                    out.extend(self.successor_welcome(&group, &pred, now));
                }
            }
            Outcome::Object { sender, sender_device, object } => out.extend(self.object_in(&gid, item, &sender, &sender_device, object, now)),
            Outcome::Dropped(why) => out.push(Ui::Dropped { why }.into()),
            Outcome::Unauthenticated(what) => out.push(Ui::Unauthenticated { what }.into()),
            Outcome::RecorderContent { device, id } => out.push(Ui::RecorderContent { device, id }.into()),
            Outcome::NotForDevice => out.push(Ui::SiblingWelcome { cursor: item["cursor"].as_str().map(String::from) }.into()),
            Outcome::Epoch { epoch, by, added, removed, left, hub } => {
                if let Some(h) = hub {
                    // M§7.4: a device that processes the moving commit tells its mailbox
                    out.extend(self.hub_moved(&gid, &h, (item["seq"].as_i64().unwrap_or(0), epoch), &by, now));
                }
                out.extend(self.log_roster(&gid, (item["seq"].as_i64(), epoch), &by, &before_ids, &left, now));
                out.push(Ui::Epoch { group: gid.clone(), epoch, by, added, removed }.into());
                if self.leaving.contains(&gid) {
                    // M§7.3: a proposal lapses with its epoch; still a member, the leave is proposed again
                    out.extend(self.propose_leave(&gid, now));
                }
            }
            Outcome::Removed { by, remaining } => {
                let was_leaving = self.leaving.remove(&gid);
                // spec-gap 127: a member may add this identity back with a new welcome; its seq gaps here start afresh
                self.delivery().removed(&gid);
                let mut c = self.convs.remove(&gid);
                if let Some(c) = c.as_mut() {
                    // spec-gap 127: the group's MLS state goes too, so a welcome back into the same group id can be joined
                    let _ = c.group.delete(self.mls.provider().storage());
                }
                if self.personal.as_deref() == Some(gid.as_str()) {
                    self.personal = None;
                }
                let kind = c.as_ref().map(|c| c.kind.clone());
                out.push(Ui::Removed { group: gid.clone(), by, conversation: c.map(|c| c.conversation), kind, left: was_leaving }.into());
                let decision = registration_on_removal(&json!({"me": self.keys.identity, "remaining_identities": remaining}));
                if decision["left"] == json!(true) {
                    let env = self.config_env(json!({"subject": self.keys.identity, "groups": [{"group": gid, "state": "left"}]}), now);
                    out.push(Event::send(env.frame()));
                }
            }
            Outcome::Proposal { proposer, removes, others, roster } => {
                let d = dsip_messaging::checks::leave_proposals(&json!({"me": self.keys.identity, "proposer": proposer, "removes": removes,
                    "others": others, "roster": roster}));
                let who = s_of(&proposer["identity"]);
                match d["action"].as_str() {
                    Some("commit") => match self.propose(&gid, &Op::Leave { identity: who.clone() }, now) {
                        Ok(f) => {
                            out.push(Event::send(f));
                            out.push(Ui::LeaveCommitting { group: gid.clone(), identity: who }.into());
                        }
                        Err(e) => out.push(Event::error(format!("committing the leave of {who}: {}", e.0))),
                    },
                    Some("left") => {
                        // a sibling device left for this identity: nothing more is sent; the commit removing us follows
                        self.leaving.insert(gid.clone());
                        out.push(Ui::Left { group: gid.clone(), by_device: proposer["device"].clone() }.into());
                    }
                    _ => out.push(Ui::LeaveProposals { group: gid.clone(), identity: who, decision: d }.into()),
                }
            }
            Outcome::Nothing => {}
        }
        out.extend(self.released(released, now)?);
        Ok(out)
    }

    /// The gap filled: what was held behind it is processed now, in seq order (M§6.5, spec-gap 69).
    fn released(&mut self, released: Vec<Value>, now: i64) -> Result<Vec<Event>, MlsError> {
        let mut out = vec![];
        for held in released {
            out.push(Ui::Released { class: held["class"].clone(), seq: held["seq"].clone() }.into());
            out.extend(self.item(&held, now)?);
        }
        Ok(out)
    }

    /// A decrypted application object, already committed (M§8.1).
    fn object_in(&mut self, gid: &str, item: &Value, sender: &str, sender_device: &str, object: Value, now: i64) -> Vec<Event> {
        let mut out = vec![];
        let seq = item["seq"].as_i64().unwrap_or(0);
        match object["object"].as_str() {
            Some("archive-key") => {
                let akid = s_of(&object["akid"]);
                let created = object["created_at"].as_i64().unwrap_or(0);
                let arrival = archive::take_key(&mut self.archive_keys, &akid, unb64(&object["key"]), created);
                let fresh = arrival == archive::KeyArrival::Fresh;
                if arrival == archive::KeyArrival::Conflict {
                    out.push(Ui::Dropped { why: format!("archive-key {akid} from {sender_device}: another key under an akid already held; the first is kept (spec-gap 140)") }.into());
                }
                // M§12.3 step 5 (spec-gap 51): records kept for this key open now
                // what the machine held for this key is released from held_archive below
                let _ = self.history.archive_key(&akid, created);
                let release: Vec<String> = self.held_archive.iter().filter(|(_, h)| h["akid"] == json!(akid)).map(|(c, _)| c.clone()).collect();
                for c in release {
                    if let Some(h) = self.held_archive.remove(&c) {
                        out.extend(self.open_archive(&h, now));
                    }
                }
                out.push(Ui::ArchiveKey { akid, from: sender.to_string(), fresh }.into());
            }
            Some("call-event") => {
                // M§13.3: every device of the identity shows one entry per call, whichever device sent it
                let key = history::object_key(&object);
                let epoch = self.convs.get(gid).map(|c| c.group.epoch().as_u64()).unwrap_or(0);
                let decisions = self.history.mls(gid, seq, epoch, &key, &object);
                out.extend(self.archive_requests(gid, &decisions, &object, sender, sender_device, seq, now));
                let fresh = self.calls.record(&object);
                out.push(Ui::CallEvent { session: object["session"].clone(), peer: object["peer"].clone(), outcome: object["outcome"].clone(),
                    direction: object["direction"].clone(), from_device: Some(sender_device.to_string()), collapsed: Some(!fresh), from_archive: None }.into());
            }
            Some("recording-acceptance") => {
                // C§5: each device accepts the union of its own acceptances and those in its personal group
                let conv = s_of(&object["conversation"]);
                let devices: Vec<String> = object["recorders"].as_array().into_iter().flatten().filter_map(|d| d.as_str().map(String::from)).collect();
                self.recording_accepted.entry(conv.clone()).or_default().extend(devices.iter().cloned());
                out.push(Ui::RecordingAccepted { conversation: conv, recorders: devices, from_device: sender_device.to_string() }.into());
            }
            Some("call-record") if self.recorder => {
                // C§9: a record-keeper keeps one record per session leg (the sending device's)
                let fresh = !self.records.iter().any(|r| r["record"]["session"] == object["session"] && r["device"] == sender_device);
                if fresh {
                    self.records.push(json!({"group": gid, "from": sender, "device": sender_device, "received_at": now, "record": object}));
                }
                out.push(Ui::CallRecord { from: sender.to_string(), session: object["session"].clone(), outcome: object["outcome"].clone(), fresh }.into());
            }
            Some("receipt") => {
                // a sibling's undisclosed watermark describes another conversation (spec-gap 52)
                let personal = self.personal.as_deref() == Some(gid);
                let target = receipts::receipt_target(gid, personal, &object, self.convs.iter().map(|(g, c)| (g.as_str(), c.conversation.as_str())));
                if let Some(t) = target {
                    self.batch.receipt(gid, &t, seq, &object, sender_device);
                }
                out.push(Ui::Receipt { group: gid.to_string(), from: sender.to_string(), kind: object["kind"].clone(), targets: object["targets"].clone(),
                    through: object["through"].clone() }.into());
            }
            Some("content") => {
                let key = history::object_key(&object);
                if !self.shown.insert(key.clone()) {
                    out.push(Ui::DuplicateContent { seq }.into());
                    return out;
                }
                // a sibling device's content is this identity's own (M§12.3: sent messages reach every device)
                self.messages.push(json!({"group": gid, "key": key, "sender": sender, "sender_device": sender_device, "object": object,
                    "seq": seq, "mine": sender == self.keys.identity, "item": null, "blobs": item["blobs"]}));
                self.batch.content(gid, seq, &object);
                // M§12.2: what is shown from MLS is archived under the current key
                let epoch = self.convs.get(gid).map(|c| c.group.epoch().as_u64()).unwrap_or(0);
                let decisions = self.history.mls(gid, seq, epoch, &key, &object);
                out.extend(self.archive_requests(gid, &decisions, &object, sender, sender_device, seq, now));
                out.push(Ui::Message { group: gid.to_string(), from: sender.to_string(), seq, kind: object["kind"].clone(), text: object["text"].clone(),
                    sent_at: object["sent_at"].clone(), id: object["id"].clone(), blobs: item["blobs"].clone(), from_device: sender_device.to_string(), object }.into());
            }
            _ => {}
        }
        out
    }

    /// Build the external commit from the latest GroupInfo held for `gid` and deposit it at the group's hub (M§6.8).
    fn external_commit(&mut self, gid: &str, now: i64) -> Result<String, Error> {
        let gi = self.group_info.get(gid).cloned().ok_or_else(|| Error::from("no GroupInfo for that group from this mailbox; sync first"))?;
        if let Some(mut old) = self.convs.remove(gid) {
            let _ = old.group.delete(self.mls.provider().storage()); // superseded: the resync removes the old leaf
        }
        let (group, commit) = self.mls.external_join(&unb64(&json!(gi))).map_err(|e| err(e.0))?;
        let conv: Value = conversation_extension(&group).and_then(|b| serde_json::from_slice(&b).ok()).ok_or_else(|| Error::from("no dsip_conversation"))?;
        let epoch = group.epoch().as_u64();
        let kind = s_of(&conv["kind"]);
        self.convs.insert(gid.to_string(), Conv {
            group, conversation: s_of(&conv["conversation"]), kind: kind.clone(), hub: (s_of(&conv["hub"]["did"]), s_of(&conv["hub"]["uri"])),
            peer: None, receipts: self.new_receipts(now), joined_epoch: epoch,
        });
        if kind == "direct" {
            let me = self.keys.identity.clone();
            let peer = self.member_identities(gid, now).into_iter().find(|m| *m != me);
            if let Some(c) = self.convs.get_mut(gid) {
                c.peer = peer;
            }
        }
        let bytes = commit.tls_serialize_detached().map_err(|e| err(format!("{e:?}")))?;
        let fields = json!({"mls": b64(&bytes)});
        let frame = self.hub_deposit(gid, "handshake", fields.clone(), now);
        let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
        self.pending.insert(id, Pending::Commit { gid: gid.to_string(), op: Some(Op::Rejoin), fields });
        Ok(frame)
    }

    /// The identities with a verified leaf in `gid`, sorted.
    /// Record a merged commit's roster change by identity, from the member identities before it, and say so to the UI
    /// (M§7.3: every roster change rendered, attributed to the committing identity). Nothing when no identity came or
    /// went (a device of a member added or removed, a path update).
    fn log_roster(&mut self, gid: &str, (seq, epoch): (Option<i64>, u64), by: &str, before: &[String], left: &[String], now: i64) -> Vec<Event> {
        let after = self.member_identities(gid, now);
        let added: Vec<String> = after.iter().filter(|i| !before.contains(i)).cloned().collect();
        let gone: Vec<String> = before.iter().filter(|i| !after.contains(i)).cloned().collect();
        if added.is_empty() && gone.is_empty() {
            return vec![];
        }
        let (left, removed): (Vec<String>, Vec<String>) = gone.into_iter().partition(|i| left.contains(i));
        vec![self.roster_entry(gid, (seq, epoch), by, added, removed, left)]
    }

    /// One roster change, kept in the group's log and said to the host (M§7.3).
    fn roster_entry(&mut self, gid: &str, (seq, epoch): (Option<i64>, u64), by: &str, added: Vec<String>, removed: Vec<String>, left: Vec<String>) -> Event {
        let entry = json!({"seq": seq, "epoch": epoch, "by": by, "added": added, "removed": removed, "left": left});
        self.roster_log.entry(gid.to_string()).or_default().push(entry);
        Ui::Roster { group: gid.to_string(), seq, epoch, by: by.to_string(), added, removed, left }.into()
    }

    fn member_identities(&self, gid: &str, now: i64) -> Vec<String> {
        let ctx = Context::new(now, &self.resolver);
        let mut ids: Vec<String> = self.convs.get(gid).map(|c| c.group.members().filter_map(|m| member_identity(&c.group, m.index, &ctx).ok())
            .map(|w| w.identity).collect()).unwrap_or_default();
        ids.sort();
        ids.dedup();
        ids
    }

    /// A deposit the group's new hub refused before it hosted the group, made again to the group's hub: an application
    /// item's same bytes under a fresh envelope (M§9.3), a commit's same MLS bytes (M§7.4, spec-gap 129).
    fn redeposit(&mut self, pending: Pending, now: i64) -> Vec<Event> {
        match pending {
            Pending::Application { gid, item } => {
                match self.outbox.item(&gid, &item).cloned() {
                    Some(item) => vec![Event::send(self.deposit_item(&gid, &item, now))],
                    None => vec![],
                }
            }
            Pending::Commit { gid, op, fields } if self.convs.contains_key(&gid) => {
                let frame = self.hub_deposit(&gid, "handshake", fields.clone(), now);
                let id = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).map(|p| s_of(&p["id"])).unwrap_or_default();
                self.pending.insert(id, Pending::Commit { gid, op, fields });
                vec![Event::send(frame)]
            }
            _ => vec![],
        }
    }

    /// A deposit for `gid` met an unreachable hub (or no answer): the outage starts or continues (M§9.4).
    fn hub_unreachable(&mut self, gid: &str, item: &str, silent: bool, now: i64) -> Vec<Event> {
        let (started, ems) = self.outbox.unreachable(gid, item, silent, now);
        let mut out = vec![];
        if started {
            out.push(Ui::HubDown { group: gid.to_string(), hub_timeout: self.outbox.hub_timeout }.into());
        }
        out.extend(self.outage_emissions(gid, ems, now));
        out
    }

    /// Act on the outbox's emissions (M§9.4): re-deposit the head, or hand the group to its successor at the threshold.
    fn outage_emissions(&mut self, gid: &str, ems: Vec<Value>, now: i64) -> Vec<Event> {
        let mut out = vec![];
        for e in ems {
            if let Some(id) = e["forward"].as_str() {
                if let Some(item) = self.outbox.item_mut(gid, id) {
                    item["forwarded"] = json!(true); // its accepted ends the outage for it (M§9.4)
                    let item = item.clone();
                    out.push(Event::send(self.deposit_item(gid, &item, now)));
                }
            } else if let Some(d) = e["retry_in"].as_i64() {
                let head = self.outbox.outages.get(gid).and_then(|o| o.pending().first().cloned());
                out.push(Ui::HubRetry { group: gid.to_string(), in_s: d, item: head }.into());
            } else if e.get("successor").is_some() || e.get("handover").is_some() {
                // M§9.4: the threshold passed: the dead group takes no more content; its pending items are re-encrypted
                // for the successor, which the host creates once it has the members' KeyPackages (M§7.5)
                let items = self.outbox.take(gid);
                let ids: Vec<Value> = items.iter().map(|i| i["id"].clone()).collect();
                let pending: Vec<HandedOver> = items.iter().map(|i| HandedOver { item: i["id"].as_str().map(String::from), id: i["obj"]["id"].clone() }).collect();
                self.messages.retain(|m| !ids.contains(&m["item"]));
                for i in &items {
                    self.shown.remove(&history::object_key(&i["obj"]));
                }
                self.handover.entry(gid.to_string()).or_default().extend(items.into_iter().map(|i| i["obj"].clone()));
                self.track_rosters();
                let me = self.keys.identity.clone();
                // M§7.5: the roster the members check it against (spec-gap 139), so it adds nobody they would refuse
                let roster: Vec<String> = self.convs.get(gid).and_then(|c| commits::roster(&c.group)).unwrap_or_default()
                    .into_iter().filter(|i| *i != me).collect();
                out.push(Event::SuccessorDue { successor_due: SuccessorDue { group: gid.to_string(), peers: roster, kind: self.convs.get(gid).map(|c| c.kind.clone()),
                    existing: self.successors.successor(gid).map(String::from), pending } });
            }
        }
        out
    }

    /// A welcome to a successor group (M§7.5): the pinned check (its creator, leaf 0, was in the predecessor's last
    /// roster this device processed, and it adds nobody who was not) and convergence on the lowest `group_id`.
    fn successor_welcome(&mut self, group: &str, pred: &str, now: i64) -> Vec<Event> {
        let mut out = vec![];
        let roster = self.member_identities(group, now);
        let creator = {
            let ctx = Context::new(now, &self.resolver);
            self.convs.get(group).map(|c| successors::creator(&c.group, &ctx)).unwrap_or_default()
        };
        // the predecessor's roster as this device last processed it; the new group itself is not tracked yet
        self.track_rosters_but(Some(group));
        for d in self.successors.welcome(group, pred, &creator, &roster) {
            if let Converge::Join(_) = d {
                out.push(Ui::Successor { group: group.to_string(), of: pred.to_string(), creator: creator.clone() }.into());
                // M§9.4: what this device still had pending for the dead group goes to the successor, re-encrypted
                let items = self.outbox.take(pred);
                let ids: Vec<Value> = items.iter().map(|i| i["id"].clone()).collect();
                self.messages.retain(|m| !ids.contains(&m["item"]));
                for i in &items {
                    self.shown.remove(&history::object_key(&i["obj"]));
                }
                let mut waiting = self.handover.remove(pred).unwrap_or_default();
                waiting.extend(items.into_iter().map(|i| i["obj"].clone()));
                self.handover.entry(group.to_string()).or_default().extend(waiting);
                self.outbox.forget(pred);
                out.extend(self.flush_handover(group, now));
            } else if let Converge::Decline(g) | Converge::FirstContact(g) = &d {
                let why = if matches!(d, Converge::FirstContact(_)) { "not a valid successor: first contact (M§7.5)" } else { "a lower successor exists (M§7.5)" };
                out.push(Ui::SuccessorDeclined { group: g.clone(), of: pred.to_string(), why: why.to_string() }.into());
                out.extend(self.leave_group(g, now).into_iter().map(Event::send));
            } else if let Converge::Leave(g) = &d {
                out.push(Ui::SuccessorLeft { group: g.clone(), of: pred.to_string() }.into());
                out.extend(self.leave_group(g, now).into_iter().map(Event::send));
            }
        }
        out
    }

    /// The group a conversation lives in now: `gid`, or the successor this device converged on (M§7.5).
    fn live(&self, gid: &str) -> String {
        self.successors.live(gid, |g| self.convs.contains_key(g))
    }

    /// Send what waits for `gid` (a successor) as new objects (M§9.4: re-encrypted, never the dead group's bytes).
    fn flush_handover(&mut self, gid: &str, now: i64) -> Vec<Event> {
        let objs = self.handover.remove(gid).unwrap_or_default();
        let mut out = vec![];
        let mut sent = vec![];
        for obj in objs {
            match self.send_item(gid, &obj, now) {
                Ok((item, f)) => {
                    if !f.is_empty() {
                        out.push(Event::send(f));
                    }
                    // the object's new outbox item: its `sent` names it (queued behind an outage of this hub too)
                    sent.push(HandedOver { item, id: obj["id"].clone() });
                }
                Err(e) => out.push(Event::error(e.0)),
            }
        }
        if !sent.is_empty() {
            out.push(Ui::HandedOver { group: gid.to_string(), items: sent.len(), sent }.into());
        }
        out
    }

    /// Record every group's roster by identity for the successor checks (M§7.5: the last roster this device processed).
    fn track_rosters(&mut self) {
        self.track_rosters_but(None);
    }

    /// [`Self::track_rosters`], except for `skip`.
    fn track_rosters_but(&mut self, skip: Option<&str>) {
        let rosters: Vec<(String, Vec<String>)> = self.convs.iter().filter(|(g, _)| Some(g.as_str()) != skip)
            .filter_map(|(g, c)| commits::roster(&c.group).map(|r| (g.clone(), r))).collect();
        for (g, r) in rosters {
            self.successors.member_of(&g, &r);
        }
    }

    /// Stop using a group (M§7.5: a higher successor, or one that fails the check): `mailbox-config` `left`. Frames.
    fn leave_group(&mut self, gid: &str, now: i64) -> Vec<String> {
        if self.convs.remove(gid).is_none() {
            return vec![];
        }
        self.outbox.forget(gid);
        let env = self.config_env(json!({"subject": self.keys.identity, "groups": [{"group": gid, "state": "left"}]}), now);
        vec![env.frame()]
    }

    /// The groups whose messages make up `gid`'s thread: it and the predecessors it succeeds (M§7.5: the dead group
    /// stays readable and the conversation continues in the successor).
    fn lineage(&self, gid: &str) -> BTreeSet<String> {
        self.successors.lineage(gid, self.convs.keys().map(String::as_str))
    }

    /// M§10.2: delivered receipts are decided once per sync batch, per conversation; each is sent as an object.
    fn receipts_batch(&mut self, now: i64) -> Vec<Event> {
        let mut out = vec![];
        for (gid, items) in self.batch.take() {
            let Some(c) = self.convs.get_mut(&gid) else { continue };
            let emissions = c.receipts.sync(now, items.clone());
            // M§12.2 (spec-gap 64): a receipt that changed rendering is archived under the group it arrived in
            for seq in emissions.iter().filter_map(|e| if let Emission::Archive(seq) = e { Some(*seq) } else { None }) {
                let (me, dev) = (self.keys.identity.clone(), self.keys.device.did());
                for it in receipts::archived(&items, seq) {
                    let src = it["src"].as_str().unwrap_or(&gid).to_string();
                    let sender = s_of(&it["object"]["sender"]);
                    let sender_device = it["sender_device"].as_str().unwrap_or("").to_string();
                    let (sender, sender_device) = if sender.is_empty() { (me.clone(), dev.clone()) } else { (sender, sender_device) };
                    if let Some(akid) = self.history.current_akid() {
                        let decisions = [Decision::Archive { group: src.clone(), seq, akid }];
                        out.extend(self.archive_requests(&src, &decisions, &it["object"], &sender, &sender_device, seq, now));
                    }
                }
            }
            out.extend(self.receipt_sends(&gid, emissions, now));
        }
        out
    }

    /// Send what a conversation's receipts machine asked for: a receipt object to the conversation, or — an
    /// undisclosed read watermark — to the personal group (M§10.5, spec-gap 52).
    /// Seal and deposit one activity (M§11.1): signed by the device key, AES-256-GCM under the epoch's exporter key,
    /// AAD `group_id ‖ epoch`, an ephemeral deposit no `accepted` answers.
    fn activity_out(&mut self, gid: &str, activity: &str, state: &str, now: i64) -> Vec<Event> {
        let Some(c) = self.convs.get(gid) else { return vec![] };
        let obj = json!({"object": "activity", "conversation": c.conversation, "sender": self.keys.identity, "activity": activity, "state": state});
        let signed = dsip_core::envelope::sign(&obj, &self.keys.device, &self.keys.device.kid());
        let key = match dsip_mls::activity_key(&c.group, self.mls.provider()) {
            Ok(k) => k,
            Err(e) => return vec![Event::error(format!("activity key: {e}"))],
        };
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&KeyPair::generate().seed()[..12]);
        let use_ = SealUse::Activity { group: c.group.group_id().as_slice(), epoch: c.group.epoch().as_u64() };
        let sealed = seal(&key, &nonce, compact(&signed).as_bytes(), use_);
        let frame = self.hub_deposit(gid, "ephemeral", json!({"sealed": b64(&sealed)}), now);
        vec![Event::send(frame), Ui::ActivitySent { group: gid.to_string(), activity: activity.to_string(), state: state.to_string() }.into()]
    }

    /// A pushed activity (M§11.1): opened with the epoch's exporter key, its device signature verified, and kept only
    /// from a device that is a member's leaf; shown until the deposit's `expires_at` (M§11.2).
    fn activity_in(&mut self, item: &Value, now: i64) -> Vec<Event> {
        let gid = s_of(&item["group"]);
        let ctx = Context::new(now, &self.resolver);
        let Some(c) = self.convs.get(&gid) else { return vec![] };
        let Ok(key) = dsip_mls::activity_key(&c.group, self.mls.provider()) else { return vec![] };
        let use_ = SealUse::Activity { group: c.group.group_id().as_slice(), epoch: c.group.epoch().as_u64() };
        let Ok(plain) = open(&key, &unb64(&item["sealed"]), use_) else {
            return vec![Ui::Dropped { why: "activity: not sealed for this epoch".into() }.into()];
        };
        let mut parts = std::str::from_utf8(&plain).unwrap_or("").split('.');
        let mut next = || parts.next().unwrap_or("").to_string();
        let env = Envelope { protected: next(), payload: next(), signature: next() };
        let Ok(ver) = dsip_core::envelope::verify_raw(&env, &ctx, false) else {
            return vec![Ui::Dropped { why: "activity: bad signature".into() }.into()];
        };
        // M§11.1: the signature attributes it; the signing device must be a leaf of the group
        let leaf = c.group.members().filter_map(|m| member_identity(&c.group, m.index, &ctx).ok()).find(|w| w.device == ver.signer_did).map(|w| w.identity);
        let octx = json!({"conversation": c.conversation, "conversation_kind": c.kind, "leaf_identity": leaf});
        let obj = ver.payload;
        if dsip_messaging::checks::check_object(&obj, &octx)["verdict"] != "accept" {
            return vec![Ui::Dropped { why: format!("activity from {}: not a member's device", ver.signer_did) }.into()];
        }
        let mut out = self.advance_receipts(now);
        let emissions = self.convs.get_mut(&gid).map(|c| c.receipts.activity_in(now, &obj["sender"], &obj["activity"], &obj["state"], &item["expires_at"]))
            .unwrap_or_default();
        out.extend(self.receipt_sends(&gid, emissions, now));
        out.push(Ui::Activity { group: gid, from: obj["sender"].clone(), activity: obj["activity"].clone(), state: obj["state"].clone() }.into());
        out
    }

    /// Advance every conversation's receipts machine to `now` (M§10.3, M§11.2): what it emits, and the activity that
    /// expired (`activity_cleared`).
    fn advance_receipts(&mut self, now: i64) -> Vec<Event> {
        let mut out = vec![];
        for gid in self.convs.keys().cloned().collect::<Vec<_>>() {
            let c = self.convs.get_mut(&gid).expect("group");
            let before = c.receipts.snapshot()["activity"].clone();
            let emissions = c.receipts.at(now);
            let after = c.receipts.snapshot()["activity"].clone();
            for (who, acts) in before.as_object().into_iter().flatten() {
                for a in acts.as_object().into_iter().flatten().map(|(a, _)| a) {
                    if after[who.as_str()].get(a).is_none() {
                        out.push(Ui::ActivityCleared { group: gid.clone(), from: who.clone(), activity: a.clone() }.into());
                    }
                }
            }
            out.extend(self.receipt_sends(&gid, emissions, now));
        }
        out
    }

    /// A contact grant for `peer` (§19.4, scope `dsip.message`), answering introduction `session` if any, valid 30 days;
    /// the compact envelope. The device's delegation rides in its header, so a verifier binds the signer to this
    /// identity (§7.4).
    pub fn grant(&self, peer: &str, session: Option<String>, now: f64) -> String {
        let now = now as i64;
        let p = json!({"dsip": wire::version_block(), "type": "grant", "id": wire::new_id(now), "from": self.keys.identity,
            "to": peer, "session": session.unwrap_or_else(|| wire::new_id(now)), "scope": ["dsip.message"],
            "valid_until": now + 30 * 86400, "issued_at": now, "expires_at": now + 30});
        compact(&self.sign_delegated(&p))
    }

    /// Hold another identity's key agreement delegation, when it verifies (its hint carries it): introductions to it
    /// are sealed to its key from now on. Whether it was taken.
    ///
    /// Spec: core §7.3 (spec-gap 179).
    pub fn hold_key_agreement(&mut self, credential: &Value, now: i64) -> bool {
        let ctx = Context::new(now, &self.resolver);
        if dsip_schema::key_agreement::verify(credential, &ctx, None).is_err() {
            return false;
        }
        self.key_agreements.retain(|c| dsip_schema::key_agreement::verify(c, &ctx, None).is_ok() && c != credential);
        self.key_agreements.push(credential.clone());
        true
    }

    /// An introduction to `target` asking permission to message (M§14.1), its purpose sealed to the key agreement key
    /// in `target`'s document (M§6.9) unless `plain`: the compact envelope the host deposits at `target`'s mailbox ([`Messenger::first_contact_frame`]), and the `mailbox-config` that tells this identity's own
    /// mailbox first, so the grant that answers it is not rate-limited there (spec-gap 81).
    pub fn introduce(&mut self, target: &str, purpose: &str, plain: bool, now: f64) -> Result<Introduction, Error> {
        let now = now as i64;
        let mut p = json!({"dsip": wire::version_block(), "type": "introduction", "id": wire::new_id(now), "from": self.keys.identity,
            "to": target, "identity": {"display_name": self.keys.display_name}, "purpose": purpose, "issued_at": now,
            "expires_at": now + 7 * 86_400});
        if !plain {
            // core §7.3, §10.4 rule 3: the document's key agreement key, else the current held delegation's, else for a
            // did:key the derived key
            let document = dsip_core::did::Resolver::resolve(&self.resolver, target)
                .and_then(|d| d.x25519_key_agreement())
                .map(|k| dsip_core::did::multibase_x25519(&k));
            let ctx = Context::new(now, &self.resolver);
            let pk = dsip_schema::key_agreement::recipient_key(target, document.as_deref(), &self.key_agreements, &ctx).map(|(_, k)| k);
            let pk = pk.ok_or_else(|| Error::from(format!("{target} publishes no key agreement key: introduce it plain")))?;
            let mut sk_e = [0u8; 32];
            sk_e.copy_from_slice(&KeyPair::generate().seed());
            dsip_messaging::first_contact::seal_introduction(&mut p, purpose, &pk, &sk_e);
        }
        let id = s_of(&p["id"]);
        let envelope = compact(&self.sign_delegated(&p));
        let notice = self.config_env(json!({"subject": self.keys.identity, "introductions_sent": [id]}), now);
        Ok(Introduction { id, envelope, send: notice.frame() })
    }

    /// A first-contact deposit (spec-gap 54) of `class` `introduction` or `grant` for `recipient`, to send on a
    /// connection to `recipient`'s mailbox `to_mailbox`; the mailbox answers on that connection.
    pub fn first_contact_frame(&self, to_mailbox: &str, class: &str, recipient: &str, envelope: &str, now: f64) -> String {
        wire::message(&self.keys.device, "deposit", to_mailbox, now as i64, wire::TTL_S,
            json!({"class": class, "recipient": recipient, "envelope": envelope})).frame()
    }

    /// Answer request `id` (M§14.1) with a `dsip.message` grant, to deposit at the requester's mailbox. The request is kept until [`Messenger::forget_request`], once that deposit is accepted.
    pub fn accept_request(&self, id: &str, now: f64) -> Result<Granted, Error> {
        let r = self.requests.get(id).ok_or_else(|| Error::from("no such request"))?;
        let requester = s_of(&r["from"]);
        let envelope = self.grant(&requester, Some(id.to_string()), now);
        Ok(Granted { requester, envelope })
    }

    /// Forget request `id`, answered or declined.
    pub fn forget_request(&mut self, id: &str) -> bool {
        self.requests.remove(id).is_some()
    }

    /// A `mailbox-config` releasing this device's binding (M§4.1): the mailbox stops pushing to it. The frame; not
    /// kept pending, so the next binding does not release it again.
    pub fn release(&self, now: f64) -> String {
        wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now as i64, wire::TTL_S,
            json!({"subject": self.keys.identity, "release": true})).frame()
    }

    fn sign_delegated(&self, p: &Value) -> Envelope {
        dsip_core::envelope::sign_bytes(&dsip_core::envelope::encode_payload(p), &self.keys.device, &self.keys.device.kid(),
                                        vec![self.keys.delegation.clone()])
    }

    /// The user's own activity in `gid` (M§11.1: typing, uploading, recording), `state` `active` or `stopped`: sent
    /// when the policy discloses activity, at the pace the receipts machine keeps. Frames and events.
    pub fn activity(&mut self, gid: &str, activity: &str, state: &str, now: f64) -> Vec<Event> {
        let now = now as i64;
        let gid = self.live(gid);
        let Some(c) = self.convs.get_mut(&gid) else { return vec![] };
        let emissions = c.receipts.activity(now, activity, state);
        let mut out = self.receipt_sends(&gid, emissions, now);
        if out.is_empty() {
            out.push(Ui::ActivityNotSent { group: gid, activity: activity.to_string(), state: state.to_string() }.into());
        }
        out
    }

    fn receipt_sends(&mut self, gid: &str, emissions: Vec<Emission>, now: i64) -> Vec<Event> {
        let mut out = vec![];
        for e in emissions {
            // an archive decision is the batch's (receipts_batch)
            let receipt = match e {
                Emission::Receipt(r) => r,
                Emission::Activity { activity, state } => {
                    out.extend(self.activity_out(gid, &activity, &state, now));
                    continue;
                }
                _ => continue,
            };
            let kind = receipt.kind.as_str();
            let target = if receipt.personal {
                match self.personal.clone() {
                    Some(p) => p,
                    None => { out.push(Ui::ReadPrivateKept { group: gid.to_string() }.into()); continue; }
                }
            } else {
                gid.to_string()
            };
            if target == gid && self.may_send_content(gid, now).is_err() {
                // C§5: no receipts into a recorded conversation until its recorders are accepted (nor ever from a recorder)
                out.push(Ui::ReceiptWithheld { group: gid.to_string(), kind: kind.to_string() }.into());
                continue;
            }
            let conversation = self.convs.get(gid).map(|c| c.conversation.clone()).unwrap_or_default();
            let id = self.fresh_id(now);
            let obj = receipt.object(&conversation, &self.keys.identity, &id, now);
            match self.send_object(&target, &obj, now) {
                Ok(f) => {
                    out.push(Event::send(f));
                    out.push(Ui::ReceiptSent { group: gid.to_string(), kind: kind.to_string(), targets: receipt.targets.clone(), through: receipt.through.clone(),
                        via: if target == gid { "conversation" } else { "personal group" }.to_string() }.into());
                }
                Err(e) => out.push(Event::error(e.0)),
            }
        }
        out
    }

    /// Archive records the history machine asked for (M§12.2): each sealed under its key, AAD `group_id ‖ seq`, and
    /// deposited to this identity's mailbox as `class: archive`.
    #[allow(clippy::too_many_arguments)] // the record's fields, named as M§12.2 names them
    fn archive_requests(&mut self, gid: &str, decisions: &[Decision], obj: &Value, sender: &str, sender_device: &str, seq: i64, now: i64) -> Vec<Event> {
        let mut out = vec![];
        let Some(conversation) = self.convs.get(gid).map(|c| c.conversation.clone()) else { return out };
        let at = archive::Received { conversation: &conversation, group: gid, seq, sender, sender_device, received_at: now };
        for (akid, record) in history::archive_records(decisions, &at, obj) {
            let Some((key, _)) = self.archive_keys.get(&akid).cloned() else { continue };
            let key: [u8; 32] = match key.as_slice().try_into() { Ok(k) => k, Err(_) => continue };
            let nonce: [u8; 12] = KeyPair::generate().seed()[..12].try_into().expect("12 bytes");
            let Some(fields) = archive::seal_record(&key, &nonce, &akid, &record) else { continue };
            let env = wire::deposit_delegated(&self.keys.device, vec![self.keys.delegation.clone()], &self.mailbox.0, now, gid, "archive", fields.clone());
            self.pending.insert(wire::payload_of(&env).map(|p| s_of(&p["id"])).unwrap_or_default(), Pending::Archive { fields });
            out.push(Event::send(env.frame()));
            out.push(Ui::Archive { group: gid.to_string(), seq, akid, object: obj["object"].clone() }.into());
        }
        out
    }

    /// An archive item (M§12.2, M§12.3 step 5): opened and shown as history, or kept sealed until its key arrives.
    fn archive_in(&mut self, item: &Value, now: i64) -> Vec<Event> {
        let akid = s_of(&item["akid"]);
        if !self.archive_keys.contains_key(&akid) {
            let cursor = s_of(&item["cursor"]);
            self.held_archive.insert(cursor.clone(), item.clone());
            self.history.held(item);
            return vec![Ui::ArchiveHeld { cursor, akid }.into()];
        }
        self.open_archive(item, now)
    }

    /// Open one archive record under a held key; content becomes a timeline entry once, a receipt is applied as
    /// history (nothing sent, nothing archived again — spec-gap 64).
    fn open_archive(&mut self, item: &Value, now: i64) -> Vec<Event> {
        let mut out = vec![];
        let akid = s_of(&item["akid"]);
        let Some((key, _)) = self.archive_keys.get(&akid).cloned() else { return out };
        let key: [u8; 32] = match key.as_slice().try_into() { Ok(k) => k, Err(_) => return out };
        let opened = match archive::open_item(&key, item) {
            Ok(o) => o,
            Err(archive::OpenError::DoesNotOpen) => {
                out.push(Ui::Dropped { why: format!("archive {}: does not open for its group and seq", item["cursor"]) }.into());
                return out;
            }
            Err(archive::OpenError::NotJson) => return out,
        };
        let obj = opened.record["payload"].clone();
        let key_id = history::object_key(&obj);
        let decisions = self.history.opened(item, &opened, &key_id);
        let (gid, seq, record) = (opened.group, opened.seq, opened.record);
        let sender = s_of(&record["sender"]);
        if decisions.iter().any(Decision::is_show) && self.shown.insert(key_id.clone()) {
            self.messages.push(json!({"group": gid, "key": key_id, "sender": sender, "sender_device": record["sender_device"], "object": obj,
                "seq": seq, "mine": sender == self.keys.identity, "item": null, "from_archive": true}));
            self.restored.push(seq, &obj);
            out.push(Ui::History { group: gid, seq, from: sender, kind: obj["kind"].clone(), text: obj["text"].clone() }.into());
        } else if decisions.iter().any(Decision::is_apply) {
            if obj["object"] == "call-event" {
                // spec-gap 63: an archived call event goes to the call log, not the timeline's content
                if self.calls.record(&obj) {
                    out.push(Ui::CallEvent { session: obj["session"].clone(), peer: obj["peer"].clone(), outcome: obj["outcome"].clone(),
                        direction: obj["direction"].clone(), from_device: None, collapsed: None, from_archive: Some(true) }.into());
                }
            } else {
                self.restored.push(seq, &obj);
                out.push(Ui::HistoryReceipt { group: gid, seq, from: sender, kind: obj["kind"].clone(), targets: obj["targets"].clone(),
                    through: obj["through"].clone() }.into());
            }
        }
        out.extend(self.apply_restored(now));
        out
    }

    /// Restored content and receipts are applied to their conversation's receipt state as history once this device
    /// is in that conversation (spec-gap 64); the rest wait.
    fn apply_restored(&mut self, now: i64) -> Vec<Event> {
        let groups = self.convs.iter().map(|(g, c)| (g.as_str(), c.conversation.as_str(), c.kind == "personal"));
        let mut out = vec![];
        for (g, items) in self.restored.ready(groups) {
            let Some(c) = self.convs.get_mut(&g) else { continue };
            let n = items.len();
            let emissions = c.receipts.restore(now, items);
            out.extend(self.receipt_sends(&g, emissions, now));
            out.push(Ui::HistoryApplied { group: g, items: n }.into());
        }
        out
    }

    /// A signed introduction or grant delivered through the mailbox (M§14.1, spec-gap 54), verified as a credential.
    fn first_contact_in(&mut self, item: &Value, now: i64) -> Vec<Event> {
        let ctx = self.ctx(now);
        // sealed purposes (M§6.9) open with the identity's key agreement key, derived from the identity key (spec-gap 55)
        let why = match first_contact::received_with(item, &self.keys.identity, &ctx, now, &self.key_agreement_secrets) {
            first_contact::Received::Request(req) => {
                let purpose = req.purpose.unwrap_or_else(|| "(sealed: this device holds no key agreement key)".to_string());
                // with the name and devices it claims (§19.4: claims, for the user to weigh)
                let mut kept = json!({"from": req.from, "purpose": purpose, "sealed": req.sealed, "expires_at": req.payload["expires_at"]});
                if let Some(identity) = req.payload.get("identity") {
                    kept["identity"] = identity.clone();
                }
                self.requests.insert(req.id.clone(), kept);
                // M§6.9: a sealed purpose never travels in the clear
                let on_wire = req.payload.get("purpose").is_some();
                return vec![Ui::Request { id: req.id, from: req.from, purpose, sealed: req.sealed, purpose_on_wire: on_wire }.into()];
            }
            first_contact::Received::Grant(g) => {
                self.grants_held.insert(g.from.clone(), g.envelope);
                return vec![Ui::Granted { by: g.from, scope: g.scope, request: g.request }.into()];
            }
            first_contact::Received::DoesNotVerify => format!("{} {}: does not verify", s_of(&item["class"]), item["cursor"]),
            first_contact::Received::BadIntroduction { id, code, .. } => format!("introduction {id}: {code}"),
            first_contact::Received::NoMessageScope { id, from } => format!("grant {id} from {from}: no dsip.message scope"),
        };
        vec![Ui::Dropped { why }.into()]
    }
}



/// Whether a refusal of a deposit to the hub is an outage (M§9.4): unreachable, or unable to store (spec-gap 99).
fn is_outage(reason: &str) -> bool {
    matches!(reason, "mailbox.hub-unreachable" | "mailbox.quota-exceeded")
}

/// What a call to the device refused, as text for the host to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<&str> for Error {
    fn from(s: &str) -> Error {
        Error(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Error {
        Error(s)
    }
}

fn err(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}

/// A 32-byte seed from 64 hex characters.
pub fn unhex(s: &str) -> Result<[u8; 32], Error> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(Error::from("seed must be 64 hex chars"));
    }
    let mut out = [0u8; 32];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(c).map_err(err)?, 16).map_err(err)?;
    }
    Ok(out)
}
