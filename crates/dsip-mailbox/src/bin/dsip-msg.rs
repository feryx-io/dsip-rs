//! A messaging device: one identity's device, its MLS groups, and a connection to its mailbox.
//!
//! Spec: M§4.2 (find the mailbox in the DID document), M§5.4–M§5.5 (sync, KeyPackages), M§6.2–M§6.8
//! (leaves, groups, welcomes, external joins), M§7.1–M§7.5 (personal group, direct and group conversations, adds and
//! removes rendered with their committer, hub moves, successors), M§8.1 (content objects), M§8.4 (blobs), M§9.1–M§9.4
//! (deposit once, the outbox, hub outages), M§10–M§11 (receipts, activity), M§12 (archive key, archiving, adding and
//! removing a device), M§13.2–M§13.3 (voicemail, call events), M§14.1–M§14.2 (introductions, grants), M§5.7 (release).
//!
//! Impl: a thin host of `dsip_messaging_device::Messenger` (dsip-rs stage 3j), which decides everything the profile
//! asks of a device, as it does in the browser; this binary moves its frames over a `wss` connection, keeps the clock,
//! fetches KeyPackages and blobs, and prints its events as the lines the demos read. Commands on stdin, events on
//! stdout, so a demo script can drive several devices. Whatever set deposits going — a command, a frame, the clock —
//! completes when they are settled (`Messenger::settled`: every deposit answered) before the next command is read, so
//! commands run one at a time as a person's would. MLS state and
//! the device's delivery state live in one SQLite database under `--state`: each inbound item is processed and its
//! delivery state committed in one transaction (spec-gap 44), and the device's state is written after every step, so
//! the process can be killed at any point and restarted. State written by dsip-msg before it hosted the `Messenger`
//! is migrated on first load. A device holds any number of groups: its identity's personal group and its
//! conversations; commands act on the most recent conversation. A second device of an identity is started with
//! `--controller` pointing at the identity key. `revoke-device` (spec-gap 57) signs a `delegation-revocation` with the
//! identity key, publishes it in the identity's DID document and sends it to the mailbox, which ends the device's
//! binding. `offline` only drops the connection; `crash-next` exits after processing the next new item and before
//! committing it. Device events (E§3–E§6: the gateway and the alarm lists) are in the `events` module.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use clap::Parser;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};

use dsip_core::delegation::delegation_payload;
use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;
use dsip_mailbox::wire;
use dsip_messaging_device::events::{NewRecorder, SuccessorDue};
use dsip_messaging_device::{blob, CallLeg, CallLog, Conversation, Event, OpInfo, ReceiptPolicy, Store, Ui};
use dsip_mls::sqlite::SqliteProvider;
use dsip_mls::{conversation_extension, MlsError};
use dsip_messenger::{resolver, mailbox_of, Engine, Host, Output};
use dsip_transport::now_s;

#[path = "dsip-msg/events.rs"]
mod events;

use openmls::prelude::{GroupId, MlsGroup, OpenMlsProvider};

#[derive(Parser)]
#[command(name = "dsip-msg", version, about = "A DSIP messaging device (Messaging Profile 1.0)")]
struct Args {
    /// State directory (keys, and `device.sqlite`: MLS and delivery state).
    #[arg(long)]
    state: PathBuf,
    /// This device's identity, a `did:web` whose document is published.
    #[arg(long)]
    identity: String,
    /// The identity's controller key (hex seed file), for a second device of an existing identity (M§12.3 step 1).
    #[arg(long)]
    controller: Option<PathBuf>,
    /// DID document files to resolve from.
    #[arg(long = "resolver-file")]
    resolver_files: Vec<PathBuf>,
    /// Trust anchor for the mailboxes.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Write this identity's DID document (with its DSIPMailbox entry) and exit.
    #[arg(long)]
    write_doc: Option<PathBuf>,
    /// Mailbox service DID, for `--write-doc`.
    #[arg(long)]
    mailbox_did: Option<String>,
    /// Mailbox `wss://` URI, for `--write-doc`.
    #[arg(long)]
    mailbox_uri: Option<String>,
    /// Seconds a seq gap may stay unfilled before this device re-joins by external commit (M§6.5; spec-gap 69).
    #[arg(long, default_value_t = dsip_messaging::client::GAP_TIMEOUT_S)]
    gap_timeout: i64,
    /// How long a group's hub may be unreachable before this device creates the successor group (M§9.4, M§7.5;
    /// RECOMMENDED 24 h).
    #[arg(long, default_value_t = dsip_messaging::client::HUB_TIMEOUT_S)]
    hub_timeout: i64,
    /// Seconds before a deposit with no answer at all counts as the hub unreachable (M§9.4).
    ///
    /// Impl: spec-gap 72 sets no time; a local mailbox answers in milliseconds, so 20 s finds an outage soon.
    #[arg(long, default_value_t = 20)]
    no_answer_timeout: i64,
    /// Behavior disclosed to other identities (M§10.5): any of `read`, `played`, `activity`. `delivered` is on
    /// unless `--no-delivered`.
    #[arg(long, value_delimiter = ',')]
    disclose: Vec<String>,
    /// Do not send `delivered` receipts.
    #[arg(long)]
    no_delivered: bool,
    /// Act as a Device Events escalation agent (E§6): escalate alarms at or above this severity…
    #[arg(long)]
    escalate_min: Option<String>,
    /// …left unacknowledged for this many seconds…
    #[arg(long, default_value_t = 300)]
    escalate_after: i64,
    /// …by running this shell command (the alarm in `ALARM_RESOURCE`, `ALARM_TYPE`, `ALARM_SEVERITY`), e.g. a
    /// `dsip call` to the on-call person.
    #[arg(long)]
    escalate_cmd: Option<String>,
    /// Act as a Device Events gateway (E§2–E§3): receive SNMPv1/v2c traps and v2c informs on this UDP address and
    /// deposit each as a signed `device-event` into the active conversation. An inform is answered only once the
    /// hub has accepted its event.
    #[arg(long)]
    snmp_listen: Option<String>,
    /// The gateway's E§4 rule table (JSON array): trap rules (`trap_oid`) and syslog rules (`syslog`).
    #[arg(long, alias = "event-rules")]
    snmp_rules: Option<PathBuf>,
    /// SNMPv3 USM users (JSON array of `{engine_id|null, user, auth, auth_password|auth_key, priv: "aes128"|null,
    /// priv_password|priv_key}`, E§3). Without it, SNMPv3 is refused.
    #[arg(long)]
    snmp_users: Option<PathBuf>,
    /// The gateway's SNMP engine ID (hex). Default: generated once and kept in the state directory. Its boots are
    /// kept there too, one more at every start (RFC 3414 §2.2).
    #[arg(long)]
    snmp_engine_id: Option<String>,
    /// Receive syslog over UDP (RFC 5426) on this address: basis `syslog-udp` (E§2–E§3).
    #[arg(long)]
    syslog_listen: Option<String>,
    /// Receive syslog over TLS (RFC 5425, octet-counted frames) on this address. Devices must present a certificate
    /// chaining to --syslog-tls-ca: basis `syslog-tls`, with the certificate's SHA-256 in the claim (E§2).
    #[arg(long, requires_all = ["syslog_tls_cert", "syslog_tls_key", "syslog_tls_ca"])]
    syslog_tls_listen: Option<String>,
    /// The gateway's TLS certificate (PEM) for --syslog-tls-listen.
    #[arg(long)]
    syslog_tls_cert: Option<PathBuf>,
    /// The gateway's TLS private key (PEM).
    #[arg(long)]
    syslog_tls_key: Option<PathBuf>,
    /// The CA (PEM) that devices' syslog client certificates must chain to.
    #[arg(long)]
    syslog_tls_ca: Option<PathBuf>,
    /// This device is a compliance recorder (Recording Profile C§5): its delegation also carries `dsip.record`; it
    /// sends no content or receipts and archives what it receives to `<state>/recorder-archive.jsonl`.
    #[arg(long)]
    recorder: bool,
    /// This device is a Device Events gateway (E§2): its delegation also carries `dsip.events`, without which members
    /// refuse its `device-event`s (spec-gap 165). Implied by any of the gateway's listeners and by --heartbeat.
    #[arg(long)]
    gateway: bool,
    /// TEST ONLY: a recorder that sends anyway, to show members dropping its content (C§5).
    #[arg(long, hide = true)]
    recorder_misbehave: bool,
    /// As a gateway, accept SNMPv3 over TLS (RFC 6353, TSM) here — the notification port is 10162 (E§3, v0.10).
    #[arg(long, requires_all = ["snmp_tls_cert", "snmp_tls_key", "snmp_tls_ca", "snmp_tls_map"])]
    snmp_tls_listen: Option<String>,
    /// The gateway's TLS certificate for SNMP over TLS (PEM).
    #[arg(long)]
    snmp_tls_cert: Option<PathBuf>,
    /// Its private key (PEM).
    #[arg(long)]
    snmp_tls_key: Option<PathBuf>,
    /// The CA certificates that device certificates must chain to (PEM).
    #[arg(long)]
    snmp_tls_ca: Option<PathBuf>,
    /// The certificate-to-security-name table (JSON array of `{id, fingerprint, map, data?}`, RFC 6353; E§3).
    #[arg(long)]
    snmp_tls_map: Option<PathBuf>,
    /// As a gateway, accept SNMPv3 over DTLS (RFC 6353 over UDP, TSM) here (E§3, v0.11), with the same certificate,
    /// key, CA and name table as --snmp-tls-listen.
    #[arg(long, requires_all = ["snmp_tls_cert", "snmp_tls_key", "snmp_tls_ca", "snmp_tls_map"])]
    snmp_dtls_listen: Option<String>,
    /// As a gateway, hold clears this many seconds (E§4 hold-down, v0.10): a re-raise within it cancels the clear, so a
    /// flapping link is one alarm. 0 (the default) turns it off. Events from informs are never held.
    #[arg(long, default_value_t = 0)]
    hold_down: i64,
    /// Names for syslog-TLS device certificates (JSON object `{"<sha256 hex>": "<name>"}`), carried as the gateway's
    /// `source.name` claim (E§2, v0.10).
    #[arg(long)]
    syslog_tls_names: Option<PathBuf>,
    /// Signed syslog (RFC 5848; E§3, v0.10): the signers whose messages are held until a verified Signature Block
    /// lists them. A JSON array of `{"hostname", "certificate": "<PEM path>"}` (key blob type C, a DSA certificate),
    /// `{"hostname", "openpgp": "<path to the base64 P key blob>"}` (type P, v0.11)
    /// or `{"hostname", "key": "<base64 of the four MPIs p, q, g, y>"}` (type K). Add `"gaps": true` when this
    /// gateway receives all of the signer's messages, to raise `dsip-syslog-gap` for lost ones (E§3, v0.11).
    #[arg(long)]
    syslog_signers: Option<PathBuf>,
    /// How long a signer's message waits for its Signature Block before it is deposited unsigned (E§3).
    #[arg(long, default_value_t = 10)]
    syslog_sign_hold: i64,
    /// The gateway's syslog severity table overrides (JSON object, e.g. `{"5": "minor"}`; E§3).
    #[arg(long)]
    syslog_table: Option<PathBuf>,
    /// As a gateway, deposit a heartbeat every this many seconds (E§5).
    #[arg(long)]
    heartbeat: Option<i64>,
}

impl Args {
    /// A Device Events gateway (E§2): asked for, or implied by a listener or a heartbeat.
    fn is_gateway(&self) -> bool {
        self.gateway
            || self.heartbeat.is_some()
            || [&self.snmp_listen, &self.syslog_listen, &self.syslog_tls_listen, &self.snmp_tls_listen, &self.snmp_dtls_listen]
                .iter()
                .any(|l| l.is_some())
    }
}

/// The device's persistent keys: an identity controller key and a device key.
struct Keys {
    controller: KeyPair,
    device: KeyPair,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    anyhow::ensure!(s.len() == 64, "expected 64 hex chars");
    let mut out = [0u8; 32];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(c)?, 16)?;
    }
    Ok(out)
}

impl Keys {
    fn load_or_create(dir: &Path, controller: Option<&Path>) -> Result<Keys> {
        std::fs::create_dir_all(dir)?;
        let read = |p: PathBuf| -> Result<KeyPair> {
            if p.exists() {
                Ok(KeyPair::from_seed(unhex(&std::fs::read_to_string(&p)?)?))
            } else {
                let k = KeyPair::generate();
                std::fs::write(&p, hex(&k.seed()))?;
                Ok(k)
            }
        };
        let controller = match controller {
            Some(p) => KeyPair::from_seed(unhex(&std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?)?),
            None => read(dir.join("controller.key"))?,
        };
        Ok(Keys { controller, device: read(dir.join("device.key"))? })
    }
}

fn compact(e: &Envelope) -> String {
    format!("{}.{}.{}", e.protected, e.payload, e.signature)
}


fn display(o: &Value) -> String {
    match o["kind"].as_str() {
        Some("text") => o["text"].as_str().unwrap_or("").to_string(),
        Some(k) => format!("[{k}]"),
        None => String::new(),
    }
}


fn state_err(e: MlsError) -> anyhow::Error {
    anyhow::anyhow!("{e}")
}

fn messenger_err(e: dsip_messaging_device::messenger::Error) -> anyhow::Error {
    anyhow::anyhow!("{}", e.0)
}


/// `["a", "b"]` as dsip-msg always printed a list of identities.
fn list(v: &Value) -> String {
    let items: Vec<String> = v.as_array().into_iter().flatten().map(|x| x.as_str().map(String::from).unwrap_or_else(|| x.to_string())).collect();
    format!("{items:?}")
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// A value that may be absent, as dsip-msg always printed it: `null` when it is.
fn opt<T: std::fmt::Display>(v: &Option<T>) -> String {
    v.as_ref().map_or_else(|| "null".into(), T::to_string)
}

/// The device's SQLite database as the `Messenger`'s store, with the `crash-next` test hook (spec-gap 44's demo): armed,
/// the next item the `Messenger` processes exits inside its transaction, before the commit.
struct Db {
    inner: SqliteProvider,
    /// `crash-next` was typed.
    crash: Cell<bool>,
    /// The `Messenger` is processing a frame from the mailbox: its transactions are items'.
    processing: Cell<bool>,
    /// The class of each item in the frame being processed, by cursor.
    classes: std::cell::RefCell<HashMap<String, String>>,
}

impl OpenMlsProvider for Db {
    type CryptoProvider = <SqliteProvider as OpenMlsProvider>::CryptoProvider;
    type RandProvider = <SqliteProvider as OpenMlsProvider>::RandProvider;
    type StorageProvider = <SqliteProvider as OpenMlsProvider>::StorageProvider;

    fn storage(&self) -> &Self::StorageProvider {
        self.inner.storage()
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.inner.crypto()
    }

    fn rand(&self) -> &Self::RandProvider {
        self.inner.rand()
    }
}

impl Store for Db {
    fn get(&self, key: &str) -> Result<Option<Value>, MlsError> {
        self.inner.get_state(key)
    }

    fn put(&self, key: &str, value: &Value) -> Result<(), MlsError> {
        self.inner.put_state(key, value)
    }

    fn list(&self, prefix: &str) -> Result<Vec<(String, Value)>, MlsError> {
        self.inner.list_state(prefix)
    }

    fn atomically<T>(&self, f: impl FnOnce() -> Result<T, MlsError>) -> Result<T, MlsError> {
        self.inner.atomically(|| {
            let v = f()?;
            if self.processing.get() && self.crash.replace(false) {
                // processed, its MLS state and delivery state written inside the transaction, never committed
                let cursor = self.inner.get_state("resume").ok().flatten().map(|r| s(&r["cursor"]).to_string()).unwrap_or_default();
                let class = self.classes.borrow().get(&cursor).cloned().unwrap_or_default();
                println!("CRASH {class} {cursor} processed, not committed");
                let _ = std::io::stdout().flush();
                std::process::exit(137);
            }
            Ok(v)
        })
    }
}

/// The state dsip-msg kept before it hosted the `Messenger`, read once and rewritten in the `Messenger`'s shape: the
/// `Messenger`'s state and this host's (`{active, pending_blobs}`), or `None` for a device with nothing saved.
///
/// Impl (decided 2026-10-20): the groups (from their MLS state and `dsip_conversation` extension), the delivery state,
/// the outbox and its outages, archive keys and held archive records, the call log, grants and requests held,
/// successors, GroupInfos and recording acceptances (dsip-msg kept those by group, the `Messenger` by conversation).
/// What dsip-msg kept only in memory (its history timeline, the digests of its own deposits) starts empty.
fn migrate(db: &Db, identity: &str, mailbox: &str, resolver: &StaticResolver) -> Result<Option<(Value, Value)>> {
    let get = |k: &str| db.get(k).map_err(state_err);
    let mut gids: Vec<String> = get("groups")?.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
    if let Some(g) = get("group")?.and_then(|g| g.as_str().map(String::from)) {
        gids.push(g); // state written before devices held several groups
    }
    let resume = get("resume")?;
    if gids.is_empty() && resume.is_none() {
        return Ok(None);
    }
    let ctx = dsip_core::envelope::Context::new(now_s(), resolver);
    let mut convs = serde_json::Map::new();
    for g in &gids {
        let Some(id) = dsip_core::b64::decode(g) else { continue };
        let Some(group) = MlsGroup::load(db.storage(), &GroupId::from_slice(&id)).ok().flatten() else { continue };
        let Some(conv) = conversation_extension(&group).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else { continue };
        if !group.is_active() {
            continue;
        }
        let joined = get(&format!("joined:{g}"))?.and_then(|e| e.as_u64()).unwrap_or(0);
        let peer = if conv["kind"] == "direct" {
            group.members().filter_map(|m| dsip_mls::member_identity(&group, m.index, &ctx).ok()).map(|w| w.identity).find(|i| i != identity)
        } else {
            None
        };
        convs.insert(g.clone(), json!({"conversation": conv["conversation"], "kind": conv["kind"], "hub": conv["hub"], "peer": peer,
                                       "joined_epoch": joined}));
    }
    // the outbox (M§9.2): `{id, mls, obj, extra}` per item, and the outage each waits out (M§9.4)
    let (mut outbox, mut outages) = (serde_json::Map::new(), serde_json::Map::new());
    for (g, v) in get("pending")?.unwrap_or_default().as_object().into_iter().flatten() {
        let items: Vec<Value> = v["items"].as_array().into_iter().flatten().map(|i| {
            let mut item = json!({"id": i["id"], "mls": i["mls"], "obj": i["obj"]});
            if let Some(b) = i["extra"].get("blobs") {
                item["blobs"] = b.clone();
            }
            item
        }).collect();
        if !items.is_empty() {
            outbox.insert(g.clone(), json!(items));
            if let Some(d) = v["down_since"].as_i64() {
                outages.insert(g.clone(), json!(d));
            }
        }
    }
    // requests: dsip-msg kept each introduction's payload; a sealed purpose stays unread
    let requests: serde_json::Map<String, Value> = get("requests")?.unwrap_or_default().as_object().into_iter().flatten().map(|(id, p)| {
        let sealed = p.get("purpose").is_none();
        let purpose = p["purpose"].as_str().unwrap_or("(sealed: received before this device's update)");
        (id.clone(), json!({"from": p["from"], "purpose": purpose, "sealed": sealed, "expires_at": p["expires_at"]}))
    }).collect();
    let mut accepted = serde_json::Map::new();
    for (g, devices) in get("recording-accepted")?.unwrap_or_default().as_object().into_iter().flatten() {
        if let Some(c) = convs.get(g).and_then(|c| c["conversation"].as_str()) {
            accepted.insert(c.to_string(), devices.clone());
        }
    }
    let calls = get("calls")?.and_then(|v| serde_json::from_value(v).ok()).map(CallLog::from_map).unwrap_or_default();
    let group_info: serde_json::Map<String, Value> =
        db.list("group_info:").map_err(state_err)?.into_iter().filter(|(_, v)| v.is_string()).map(|(k, v)| (k.trim_start_matches("group_info:").to_string(), v)).collect();
    let state = json!({
        "convs": convs, "personal": get("personal")?, "resume": resume, "outbox": outbox, "outages": outages,
        "grants_held": get("grants_held")?, "archive_keys": get("archive_keys")?, "held_archive": get("held")?,
        "group_info": group_info, "held_items": get("held_items")?, "requests": requests, "calls": calls,
        "successors": get("successors")?, "recording_accepted": accepted, "mailbox": mailbox,
    });
    let host = json!({"active": get("active")?, "pending_blobs": get("pending_blobs")?});
    Ok(Some((state, host)))
}

/// The keys [`migrate`] read: cleared once the state is rewritten, so nothing reads them again.
fn clear_migrated(db: &Db) -> Result<()> {
    let mut keys: Vec<String> = ["groups", "group", "active", "personal", "archive_keys", "held", "calls", "held_items", "pending_blobs", "pending",
        "successors", "grants_held", "requests", "recording-accepted"].iter().map(|k| k.to_string()).collect();
    for prefix in ["joined:", "group_info:"] {
        keys.extend(db.list(prefix).map_err(state_err)?.into_iter().map(|(k, _)| k));
    }
    db.atomically(|| keys.iter().try_for_each(|k| db.put(k, &Value::Null))).map_err(state_err)
}

/// What an outbox item of this device carries: the line its `sent` prints.
enum Item {
    /// `send`: `OK sent`.
    Text,
    /// A `device-event` (E§5): `OK sent event`.
    Event,
    /// An `alarm-ack` (E§5): `OK sent alarm-ack`.
    AlarmAck,
    /// `voice` or `voicemail` (M§8.2, M§13.2): `OK sent audio`.
    Audio { purpose: String, duration_ms: i64, sha256: String },
    /// A call event to the personal group (M§13.3): `SENT-CALL-EVENT`, and whether a sibling had reported it first.
    CallEvent { outcome: String, session: String, fresh: bool },
    /// A dead group's pending item re-sent in its successor (M§9.4): the id it had there.
    Resent(String),
}

/// What sending content came to (M§9.2, M§9.4).
enum Sent {
    /// Deposited: the outbox item.
    Out(String),
    /// Queued behind a pending item while the hub is unreachable.
    Queued(String),
    /// Kept for the successor of a group past its outage.
    Successor,
}

/// This device: the messenger (the `Messenger` engine, its mailbox connection and the work it does on the network) and
/// what only this console keeps.
struct Client {
    mx: dsip_messenger::Messenger<Db>,
    c: Console,
}

/// What only this console keeps, and how it prints what the messenger tells it ([`Host`]).
struct Console {
    keys: Keys,
    identity: String,
    /// The conversation commands act on.
    active: Option<String>,
    /// Each group's conversation id and kind, as last seen (kept after the group is gone, to name it).
    names: HashMap<String, (String, String)>,
    /// This device's outbox items, by id: what their `sent` prints.
    items: HashMap<String, Item>,
    /// What the commit a command proposed in a group does, as its lines say it.
    labels: HashMap<String, String>,
    /// KeyPackages fetched ahead of an add, by identity: the mailbox's answer (M§5.5: single use, held until used).
    prefetched: HashMap<String, Value>,
    /// A dead group's pending items by content id: the item id each had there (M§9.4).
    resent: HashMap<String, String>,
    /// Device events (E§3–E§6): the alarm lists, and the gateway in gateway mode.
    events: events::Events,
    /// Recording Profile C§5: this device is a recorder.
    recorder_mode: bool,
    /// TEST ONLY: a recorder that sends anyway.
    recorder_misbehave: bool,
    state: PathBuf,
}

/// Now, as the `Messenger` takes it.
fn now_f() -> f64 {
    now_s() as f64
}

/// The conversations, as the `Messenger` lists them.
fn conversations(m: &Engine<Db>) -> Vec<Conversation> {
    m.conversations(now_s() as f64)
}

/// One conversation as the `Messenger` lists it: `gid`, or the successor this device converged on (M§7.5).
fn conv(m: &Engine<Db>, gid: &str) -> Result<Conversation> {
    let live = m.successor(gid).unwrap_or_else(|| gid.to_string());
    conversations(m).into_iter().find(|c| c.group == live).context("not a member of that group")
}

impl Host<Db> for Console {
    /// One output of the messenger, as the lines dsip-msg prints.
    async fn output(&mut self, m: &Engine<Db>, out: Output) {
        self.refresh_names(m);
        match out {
            Output::Event(e) => match e {
                Event::Ui(ui) => self.ui(m, &ui).await,
                Event::Refused { refused, item, pending, .. } => self.refused(&refused, item.as_deref(), pending == Some(true)).await,
                Event::SuccessorDue { successor_due } => self.successor_due(&successor_due),
                // the mailbox's own error, not an answer to a deposit
                Event::Error { reason: Some(reason), detail, .. } => println!("ERR {reason} {}", detail.as_ref().unwrap_or(&Value::Null)),
                Event::Error { error, .. } => println!("ERR {error}"),
                Event::Drop { drop } => println!("DROP {drop}"),
                Event::Rejected { rejected } => println!("ERR frame rejected: {} {}", json!(rejected.code), rejected.reason.as_deref().unwrap_or("")),
                _ => {}
            },
            Output::Connected { identity, mailbox } => println!("OK connected {identity} mailbox={mailbox}"),
            Output::Disconnected => println!("DISCONNECTED by the mailbox"),
            Output::ConnectionError(e) => println!("ERR connection {e}"),
            Output::ReconnectFailed { error, wait_s } => println!("RECONNECT failed ({error}); next attempt in {wait_s} s"),
            Output::Error(e) => println!("ERR {e}"),
            Output::Blob { sender, object, path, sha256, from } => println!(
                "RECV-AUDIO {sender} purpose={} duration_ms={} session={} file={} sha256={sha256} from={from}",
                object["purpose"].as_str().unwrap_or("message"), object["duration_ms"],
                object["session"].as_str().unwrap_or("-"), path.display()
            ),
            Output::BlobPending { id, attempt, retry_in } => println!("AUDIO-PENDING {id} attempt={attempt} retry_in={retry_in}"),
            Output::BlobSourceRejected { uri, why } => println!("BLOB-SOURCE-REJECTED {uri}: {why}"),
            Output::BlobGaveUp { id, why } => println!("ERR blob {id}: given up ({why})"),
            Output::SuccessorExists { group, of } => {
                println!("SUCCESSOR exists group={group} of={of}");
                self.active = Some(group);
            }
            Output::SuccessorCreated { group, of } => {
                println!("SUCCESSOR created group={group} of={of}");
                self.active = Some(group);
            }
            Output::SuccessorRetry { of, error } => println!("SUCCESSOR-RETRY of={of}: {error}"),
            other => println!("?? {other:?}"),
        }
        self.refresh_names(m);
    }

    fn saved(&self) -> Value {
        json!({"active": self.active})
    }

    /// `crash-next` crashes inside the transaction of an item of this frame: the store needs to know which.
    fn frame_in(&mut self, m: &Engine<Db>, p: &Value) {
        let db = m.store();
        *db.classes.borrow_mut() = p["items"].as_array().into_iter().flatten().map(|i| (s(&i["cursor"]).to_string(), s(&i["class"]).to_string())).collect();
        db.processing.set(true);
    }

    fn frame_done(&mut self, m: &Engine<Db>) {
        m.store().processing.set(false);
    }
}

impl Client {
    /// The conversations, as the `Messenger` lists them.
    fn conversations(&self) -> Vec<Conversation> {
        conversations(self.mx.engine())
    }

    /// One conversation as the `Messenger` lists it: `gid`, or the successor this device converged on (M§7.5).
    fn conv(&self, gid: &str) -> Result<Conversation> {
        conv(self.mx.engine(), gid)
    }

    /// Deposit content to `gid` (M§9.2): `kind` says what its `sent` prints.
    async fn send_content(&mut self, gid: &str, obj: Value, kind: Item) -> Result<Sent> {
        let r = self.mx.engine_mut().send(gid, &obj, now_f()).map_err(messenger_err)?;
        let Some(item) = r.item else {
            println!("PENDING kept for the successor of {gid}");
            self.mx.save(&self.c)?;
            return Ok(Sent::Successor);
        };
        self.c.items.insert(item.clone(), kind);
        // M§9.2: pending, durably, before it goes out
        self.mx.save(&self.c)?;
        let frame = r.send;
        if frame.is_empty() {
            // M§9.4: the hub is down; the item waits behind the pending ones and goes out with them
            println!("PENDING {item} queued");
            return Ok(Sent::Queued(item));
        }
        self.mx.send_frame(&mut self.c, &frame).await?;
        Ok(Sent::Out(item))
    }

    /// What may go to `gid` (C§5): nothing from a recorder; content into a recorded conversation once its recorders
    /// are accepted.
    fn may_send(&self, gid: &str) -> Result<()> {
        if self.mx.engine().is_recorder() && !self.c.recorder_misbehave {
            bail!("a recorder device is receive-only (C§5)");
        }
        if !self.conv(gid)?.may_send {
            bail!("recorded conversation: type accept-recording first (C§5)");
        }
        Ok(())
    }

    /// A content object of this identity for `gid`'s conversation (M§8.1), with `fields`.
    fn content(&mut self, gid: &str, fields: Value) -> Result<Value> {
        let now = now_f();
        let mut obj = json!({"object": "content", "id": self.mx.engine_mut().new_id(now), "conversation": self.conv(gid)?.conversation,
            "sender": self.c.identity, "sent_at": now as i64, "purpose": "message"});
        for (k, v) in fields.as_object().into_iter().flatten() {
            obj[k.as_str()] = v.clone();
        }
        Ok(obj)
    }

    async fn send_text(&mut self, text: &str) -> Result<()> {
        let group = self.c.active()?;
        self.may_send(&group)?;
        let obj = self.content(&group, json!({"kind": "text", "content_type": "text/plain", "text": text}))?;
        self.send_content(&group, obj, Item::Text).await.map(|_| ())
    }
}

impl Console {
    fn refresh_names(&mut self, m: &Engine<Db>) {
        for c in conversations(m) {
            self.names.insert(c.group, (c.conversation, c.kind));
        }
    }

    fn name(&self, gid: &str) -> (String, String) {
        self.names.get(gid).cloned().unwrap_or_default()
    }

    fn active(&self) -> Result<String> {
        self.active.clone().context("no conversation")
    }

    /// The conversation commands act on after `gone` went: the first other conversation, never the personal group.
    fn active_after(&mut self, m: &Engine<Db>, gone: &str) {
        if self.active.as_deref() == Some(gone) {
            self.active = conversations(m).into_iter().find(|c| c.kind != "personal" && c.group != gone).map(|c| c.group);
        }
    }

    /// The line a commit in `gid` is reported under: what the command that proposed it said, or what it does.
    fn label(&self, gid: &str, op: Option<&OpInfo>) -> String {
        if let Some(l) = self.labels.get(gid) {
            return l.clone();
        }
        let kind = self.name(gid).1;
        match op {
            Some(OpInfo::Add { device: Some(device), .. }) => format!("added device {device} to {kind}"),
            Some(OpInfo::Add { peer, devices, .. }) => format!("added {peer} ({devices} device(s))"),
            Some(OpInfo::Update) => "rekeyed".into(),
            Some(OpInfo::MoveHub { hub }) => format!("moved to {}", s(&hub["did"])),
            Some(OpInfo::Remove { identity }) => format!("removed {identity}"),
            Some(OpInfo::RemoveDevice { device }) => format!("removed device {device} from {kind}"),
            Some(OpInfo::Leave { identity }) => format!("committed the leave of {identity}"),
            Some(OpInfo::Rejoin) => "rejoin".into(),
            None => String::new(),
        }
    }

    /// One event of the `Messenger`, as the line dsip-msg prints.
    async fn ui(&mut self, m: &Engine<Db>, ui: &Ui) {
        match ui {
            Ui::Joined { group, conversation, kind, epoch, external: Some(true), seq, .. } => {
                println!("OK rejoined {} kind={kind} epoch={epoch} seq={}", s(conversation), opt(&seq.flatten()));
                if kind != "personal" {
                    self.active = Some(group.clone());
                }
            }
            Ui::Joined { group, conversation, kind, members, .. } => {
                println!("JOINED {} kind={kind} members={members:?}", s(conversation));
                if kind != "personal" {
                    self.active = Some(group.clone());
                }
            }
            Ui::Committed { group, epoch, seq, op, .. } => {
                let label = self.label(group, op.as_ref());
                self.labels.remove(group);
                println!("OK {label} epoch={epoch} seq={}", opt(seq));
            }
            Ui::Conflict { group, reason, op, .. } if reason == "mailbox.unknown-group" => {
                // spec-gap 60: the hub may have handed the group on; the sync shows whether it did
                let hub = conv(m, group).map(|c| c.hub.did).unwrap_or_default();
                println!("MOVED? {}: mailbox.unknown-group from {hub}; syncing", self.label(group, op.as_ref()));
            }
            Ui::Conflict { reason, epoch, op: Some(OpInfo::Rejoin), .. } => {
                println!("CONFLICT rejoin: {reason} at epoch {}; syncing for a newer GroupInfo", opt(epoch));
            }
            Ui::Conflict { group, reason, epoch, op } => {
                println!("CONFLICT {}: {reason} at epoch {}; syncing past the winning commit", self.label(group, op.as_ref()), opt(epoch));
            }
            Ui::Repropose { group, op, attempt, epoch } => println!("REPROPOSE {} attempt={attempt} epoch={}", self.label(group, Some(op)), opt(epoch)),
            Ui::NoLongerNeeded { group, op } => {
                println!("OK {} no longer needed after the winning commit", self.label(group, Some(op)));
                self.labels.remove(group);
            }
            Ui::Epoch { group, epoch, by, added, removed } => {
                println!("EPOCH {epoch} kind={} by={by} added={added:?} removed={removed:?}", self.name(group).1);
            }
            Ui::HubMoved { group, seq, hub, .. } => println!("HUB-MOVED {} to {hub} at seq={seq}", self.name(group).0),
            Ui::Removed { group, by, conversation, kind, .. } => {
                println!("REMOVED from {} kind={} by={by}", conversation.as_deref().unwrap_or(""), kind.as_deref().unwrap_or(""));
                self.active_after(m, group);
            }
            Ui::Message { group, from, seq, from_device, object, .. } => self.message_in(group, from, *seq, from_device, object),
            Ui::DuplicateContent { seq } => println!("DUP-HISTORY seq={seq}"),
            Ui::Duplicate { class, cursor } => println!("DUP {class} {}", cursor.as_deref().unwrap_or("")),
            Ui::Own { class, seq } => println!("SELF {class} seq={}", opt(seq)),
            Ui::Prejoin { class, seq } => println!("PREJOIN {class} seq={}", opt(seq)),
            Ui::Hold { class, seq } => println!("HOLD {class} seq={} (waiting for the gap to fill)", opt(seq)),
            Ui::Released { class, seq } => println!("RELEASED {} seq={seq}", s(class)),
            Ui::Unprocessable { class, cursor, why } => println!("?? unprocessable {class} {}: {why}", cursor.as_deref().unwrap_or("")),
            Ui::Dropped { why } => println!("DROP {why}"),
            Ui::Unauthenticated { what } => println!("UNAUTHENTICATED {what}"),
            // C§5: a recorder is receive-only — its content is treated as from an unauthenticated leaf
            Ui::RecorderContent { device, .. } => println!("DROP recorder content from {device} (C§5: a recorder is receive-only)"),
            Ui::SiblingWelcome { cursor } => println!("SIBLING welcome {}", cursor.as_deref().unwrap_or("")),
            Ui::GapTimeout { group, held } => println!("GAP-TIMEOUT group={group} held={held}: re-joining by external commit"),
            Ui::Resync => println!("RESYNC from null"),
            Ui::ArchiveKey { akid, from, fresh: true } => println!("ARCHIVE-KEY {akid} from {from}"),
            Ui::ArchiveKeyCreated { akid, .. } => println!("OK archive-key {akid}"),
            Ui::Archive { seq, akid, .. } => println!("ARCHIVED seq={seq} akid={akid}"),
            Ui::ArchiveHeld { cursor, akid } => println!("HELD archive {cursor} akid={akid}"),
            Ui::History { seq, from, kind, text, .. } => {
                let what = if kind == "text" { s(text).to_string() } else { format!("[{}]", s(kind)) };
                println!("HISTORY seq={seq} {from}: {what}");
            }
            Ui::HistoryReceipt { seq, from, kind, targets, through, .. } => {
                let what = if kind == "read" { through } else { targets };
                println!("HISTORY-RECEIPT seq={seq} {from} {} {what}", s(kind));
            }
            Ui::CallEvent { session, peer, outcome, from_archive: Some(true), .. } => {
                println!("HISTORY-CALL {} {} session={}", s(outcome), s(peer), s(session));
            }
            Ui::CallEvent { session, from_device, collapsed: Some(true), .. } => {
                println!("DUP-CALL session={} from {}", s(session), from_device.as_deref().unwrap_or(""))
            }
            Ui::CallEvent { session, peer, outcome, direction, .. } => println!("CALL {} {} {} session={}", s(outcome), s(direction), s(peer), s(session)),
            Ui::CallRecord { from, session, outcome, .. } => println!("CALL-RECORD from {from} session={} outcome={}", s(session), s(outcome)),
            Ui::Receipt { group, from, kind, targets, through } => {
                let what = if kind == "read" { through } else { targets };
                let personal = m.personal().is_some_and(|p| p == *group);
                println!("RECEIPT {from} {} {what}{}", s(kind), if personal { " (personal group)" } else { "" });
            }
            Ui::ReceiptSent { kind, targets, through, via, .. } => {
                let what = if kind == "read" { through } else { targets };
                let via = if via == "conversation" { "" } else { " (personal group)" };
                println!("SENT-RECEIPT {kind} {}{via}", what.as_ref().unwrap_or(&Value::Null));
            }
            Ui::ReadPrivateKept { .. } => println!("READ-PRIVATE (no personal group: kept on this device)"),
            Ui::ReceiptWithheld { group, kind } => println!("RECEIPT-WITHHELD {kind} group={group} (C§5: a recorder is not accepted yet)"),
            Ui::Activity { from, activity, state, .. } => println!("ACTIVITY {} {} {}", s(from), s(activity), s(state)),
            Ui::ActivityCleared { from, activity, .. } => println!("ACTIVITY-CLEARED {from} {activity}"),
            Ui::ActivitySent { activity, state, .. } => println!("SENT-ACTIVITY {activity} {state}"),
            Ui::Request { id, from, purpose, sealed, purpose_on_wire, .. } => {
                println!("REQUEST {id} from {from}: \"{purpose}\" sealed={sealed} purpose_on_wire={purpose_on_wire}")
            }
            Ui::Granted { by, scope, request, .. } => println!("GRANTED by {by} scope={scope} request={request}"),
            Ui::Recording { group, new, ended, .. } => self.recording(group, new, *ended),
            Ui::RecordingAccepted { conversation, recorders, from_device } => {
                let target = self.names.iter().find(|(_, (c, _))| c == conversation).map(|(g, _)| g.clone()).unwrap_or_default();
                println!("RECORDING-ACCEPTED group={target} recorders={recorders:?} by sibling {from_device}   C§5");
            }
            Ui::Sent { group, item, seq, after_outage, .. } => self.sent(group, item, seq, *after_outage).await,
            Ui::HubDown { group, hub_timeout } => println!("HUB-DOWN group={group} hub_timeout={hub_timeout}"),
            Ui::HubBack { group } => println!("HUB-BACK group={group}"),
            Ui::HubRetry { in_s, item, .. } => println!("PENDING {} retry_in={in_s}", item.as_deref().unwrap_or("")),
            Ui::HubArriving { group, in_s } => println!("ARRIVING {group}: the hub does not host the group yet; again in {in_s}s"),
            Ui::HubArrivalExpired { group } => println!("ARRIVAL-EXPIRED {group}: the new hub never hosted the group"),
            Ui::MovedCheck { group, .. } => {
                let hub = conv(m, group).map(|c| c.hub.did).unwrap_or_default();
                println!("RETRY send: mailbox.unknown-group from {hub}; syncing");
            }
            Ui::HandedOver { sent, .. } => {
                for x in sent {
                    let old = self.resent.remove(s(&x.id));
                    if let (Some(item), Some(old)) = (&x.item, old) {
                        self.items.insert(item.clone(), Item::Resent(old));
                    }
                }
            }
            Ui::Successor { group, of, .. } => {
                println!("SUCCESSOR joined group={group} of={of}");
                self.active = Some(group.clone());
            }
            Ui::SuccessorDeclined { group, of, why } => self.successor_gone(m, group, of, why),
            Ui::SuccessorLeft { group, of } => self.successor_gone(m, group, of, ""),
            Ui::KeyPackagesUploaded { count } => println!("OK uploaded {} key packages", *count as i64 - 1),
            Ui::LeaveProposed { group, seq } => println!("LEAVE proposed group={group} seq={}", opt(seq)),
            Ui::LeaveProposalRefused { group, reason } => println!("LEAVE proposal refused group={group}: {reason}"),
            Ui::LeaveCommitting { group, identity } => println!("LEAVE committing the leave of {identity} group={group}"),
            Ui::Left { group, .. } => println!("LEFT group={group} conversation={} (a sibling device left for this identity)", self.name(group).0),
            Ui::LeaveProposals { group, identity, decision } => println!("LEAVE proposals from {identity} group={group}: {decision}"),
            Ui::ActivityNotSent { activity, state, .. } => println!("OK {activity} {state} (not sent: refresh bound or not disclosed)"),
            // rendered by the lines above, or nothing to say
            Ui::Roster { .. } | Ui::Personal { .. } | Ui::ArchiveKey { .. } | Ui::Archived { .. } | Ui::HistoryApplied { .. } => {}
        }
    }

    /// A successor this device was in is left: not valid (first contact required), or another converged (M§7.5).
    fn successor_gone(&mut self, m: &Engine<Db>, group: &str, of: &str, why: &str) {
        let why = if why.contains("first contact") {
            "not a valid successor: first contact required".to_string()
        } else {
            format!("successor of {of} converged elsewhere")
        };
        println!("LEFT group={group} conversation={} ({why})", self.name(group).0);
        self.active_after(m, group);
        if let Some(w) = m.successor(of) {
            self.active = Some(w);
        }
    }

    /// A content message (M§8.1): a device event to the alarm list, a blob fetched, or text shown.
    fn message_in(&mut self, gid: &str, sender: &str, seq: i64, sender_device: &str, object: &Value) {
        if self.recorder_mode {
            // C§5: the compliance archive
            let line = json!({"group": gid, "seq": seq, "sender": sender, "sender_device": sender_device, "object": object});
            let written = std::fs::OpenOptions::new().create(true).append(true).open(self.state.join("recorder-archive.jsonl"))
                .and_then(|mut f| writeln!(f, "{line}"));
            match written {
                Ok(()) => println!("ARCHIVED {sender}: {}", display(object)),
                Err(err) => println!("ERR recorder archive: {err}"),
            }
        }
        if self.event_in(gid, sender, object) {
            // device events and alarm acknowledgements went to the alarm list (E§5)
        } else if object.get("blob").is_some() {
            // the messenger fetches it, and tries again when a fetch finds nothing (spec-gap 106): `Output::Blob`
        } else {
            println!("RECV {sender}: {}", s(&object["text"]));
        }
    }

    /// Recording Profile C§5: a conversation becoming recorded, or no longer recorded.
    fn recording(&self, g: &str, new: &[NewRecorder], ended: bool) {
        for r in new {
            println!("RECORDED group={g} by recorder device {} of {}{}   C§5", s(&r.device), s(&r.subject),
                     if r.own { " (this identity's own recording)" } else { " — type accept-recording, or decline-recording to leave" });
        }
        if ended {
            println!("RECORDING ENDED group={g}   C§5");
        }
    }

    /// The hub accepted an outbox item of ours (M§9.2).
    async fn sent(&mut self, group: &str, item: &str, seq: &Option<i64>, after_outage: bool) {
        let seq = opt(seq);
        let kind = self.items.remove(item);
        if after_outage && !matches!(kind, Some(Item::Resent(_))) {
            println!("SENT-AFTER-OUTAGE {item} seq={seq}");
        } else {
            match kind {
                Some(Item::Text) => println!("OK sent seq={seq}"),
                Some(Item::Event) => println!("OK sent event seq={seq}"),
                Some(Item::AlarmAck) => println!("OK sent alarm-ack seq={seq}"),
                Some(Item::Audio { purpose, duration_ms, sha256 }) => {
                    println!("OK sent audio purpose={purpose} duration_ms={duration_ms} blob={sha256} seq={seq}")
                }
                Some(Item::CallEvent { outcome, session, fresh }) => {
                    println!("SENT-CALL-EVENT {outcome} session={session}{}", if fresh { "" } else { " (already recorded)" })
                }
                Some(Item::Resent(old)) => println!("RESENT {old} in={group} seq={seq}"),
                None => {}
            }
        }
        self.inform_outcome(item, true).await;
    }

    /// The hub refused something of ours (M§16): `pending` when it stays in the outbox behind an outage (M§9.4).
    async fn refused(&mut self, refused: &str, item: Option<&str>, pending: bool) {
        if pending {
            // M§9.4: kept in the outbox; the outage's retries are announced as PENDING
            if let Some(i) = item {
                self.inform_pending(i);
            }
            return;
        }
        println!("ERR {refused}");
        if let Some(i) = item {
            self.items.remove(i);
            self.inform_outcome(i, false).await;
        }
    }

    /// M§9.4: the hub of `group` has been unreachable past this device's threshold: its pending items wait for the
    /// successor, which the messenger creates (M§7.5).
    fn successor_due(&mut self, d: &SuccessorDue) {
        for p in &d.pending {
            let item = p.item.clone().unwrap_or_default();
            self.items.remove(&item);
            self.resent.insert(s(&p.id).to_string(), item);
        }
        println!("OUTAGE-SUCCESSOR group={} pending={}", d.group, d.pending.len());
    }
}

impl Client {
    /// A group a command proposed a commit in, and what the commit's lines call it.
    fn label_for(&mut self, gid: &str, label: String) {
        self.c.labels.insert(gid.to_string(), label);
    }

    /// Create a conversation of `kind` with `peer` (M§7.2, M§7.3), presenting a held grant when none is given: the
    /// peer's devices and this identity's own others, added in one commit once the group is hubbed here.
    async fn create(&mut self, kind: &str, peer: &str, grant: Option<String>) -> Result<()> {
        if let Some(g) = grant {
            self.mx.engine_mut().set_grants(&BTreeMap::from([(peer.to_string(), g)]));
        }
        let answer = self.mx.fetch_key_packages(&mut self.c, peer, None).await?;
        self.mx.engine_mut().key_package_devices(peer, &answer, now_f()).map_err(messenger_err)?;
        // M§7.2: the creator adds its own other devices with the peer's — recorder devices included (C§5), so a
        // conversation created after a recorder exists is recorded too
        let me = self.c.identity.clone();
        let own = match self.mx.fetch_key_packages(&mut self.c, &me, None).await {
            Ok(a) => match self.mx.engine_mut().key_package_devices(&me, &a, now_f()) {
                Ok(d) => {
                    println!("OWN-DEVICES {} added with the peer's", d.len());
                    Some(a)
                }
                Err(e) => {
                    println!("OWN-DEVICES none ({})", e.0);
                    None
                }
            },
            Err(e) => {
                println!("OWN-DEVICES none ({e})");
                None
            }
        };
        let now = now_f();
        let frames = if kind == "direct" {
            self.mx.engine_mut().create_direct(peer, &answer, own.as_ref(), now)
        } else {
            self.mx.engine_mut().create_group(&BTreeMap::from([(peer.to_string(), answer)]), own.as_ref(), now)
        }
        .map_err(messenger_err)?;
        let gid = frames.first().and_then(|f| Envelope::from_frame(f).ok()).and_then(|e| wire::payload_of(&e))
            .and_then(|p| p["groups"][0]["group"].as_str().map(String::from)).context("no group created")?;
        self.c.active = Some(gid.clone());
        println!("OK conversation {} kind={kind}", self.conv(&gid)?.conversation);
        self.mx.save(&self.c)?;
        Ok(self.mx.send_frames(&mut self.c, &frames).await?)
    }

    /// Add `peer`'s devices to the active conversation (M§7.3, M§14.2), from KeyPackages prefetched or fetched now.
    async fn add(&mut self, peer: &str, grant: Option<String>) -> Result<()> {
        let group = self.c.active()?;
        if let Some(g) = grant {
            self.mx.engine_mut().set_grants(&BTreeMap::from([(peer.to_string(), g)]));
        }
        let answer = match self.c.prefetched.remove(peer) {
            Some(a) => a,
            None => self.mx.fetch_key_packages(&mut self.c, peer, None).await?,
        };
        let frame = self.mx.engine_mut().add_member(&group, peer, &answer, now_f()).map_err(messenger_err)?;
        Ok(self.mx.send_frame(&mut self.c, &frame).await?)
    }

    /// The personal group and the first archive key (M§7.1, M§12.1).
    async fn create_personal(&mut self) -> Result<()> {
        let frames = self.mx.engine_mut().create_personal(now_f()).map_err(messenger_err)?;
        let personal = self.mx.engine_mut().personal().context("no personal group")?;
        println!("OK conversation {} kind=personal", self.conv(&personal)?.conversation);
        self.mx.save(&self.c)?;
        Ok(self.mx.send_frames(&mut self.c, &frames).await?)
    }

    /// M§12.3: add a new device of this identity, first to the personal group (re-sending every archive key in the
    /// epoch after the commit), then to each conversation group; each add from a KeyPackage of its own (M§5.5).
    async fn add_device(&mut self, device: &str) -> Result<()> {
        let personal = self.mx.engine_mut().personal().context("no personal group: create it first (M§7.1)")?;
        let me = self.c.identity.clone();
        let probe = self.mx.fetch_key_packages(&mut self.c, &me, None).await?;
        let devices = self.mx.engine_mut().key_package_devices(&me, &probe, now_f()).map_err(messenger_err)?;
        let found = devices.iter().find(|d| d.device == device).with_context(|| format!("no KeyPackage of {device} at the mailbox"))?;
        // Recording Profile C§5: a recorder device joins conversations only — never the personal group, so it holds no
        // archive key and records only what is sent while it is a visible member
        let recorder = found.recorder;
        if recorder {
            println!("RECORDER {device}: conversations only, never the personal group or the archive key   C§5");
        }
        let order = self.mx.engine_mut().groups_for_new_device(device, now_f());
        let mut first = Some(probe);
        for gid in order {
            if recorder && gid == personal {
                continue;
            }
            let answer = match first.take() {
                Some(a) => a,
                None => self.mx.fetch_key_packages(&mut self.c, &me, None).await?,
            };
            let label = format!("added device {device} to {}", self.conv(&gid)?.kind);
            self.label_for(&gid, label);
            let frame = self.mx.engine_mut().add_device(&gid, device, &answer, now_f()).map_err(messenger_err)?;
            self.mx.send_frame(&mut self.c, &frame).await?;
            self.mx.settle(&mut self.c).await;
            if gid == personal {
                // M§12.3 step 3: a new member cannot read earlier epochs, so every live archive key is re-sent
                let frames = self.mx.engine_mut().resend_archive_keys(now_f());
                let n = self.mx.engine_mut().archive_keys().len();
                self.mx.save(&self.c)?;
                self.mx.send_frames(&mut self.c, &frames).await?;
                println!("OK re-sent {n} archive key(s)");
                self.mx.settle(&mut self.c).await;
            }
        }
        Ok(())
    }

    /// Revoke a device's delegation (spec-gap 57): a `delegation-revocation` signed by the identity key, published in
    /// the identity's DID document (authoritative, §8.1) and sent to its mailbox, which closes the device's binding.
    async fn revoke_device(&mut self, device: &str) -> Result<()> {
        let now = now_s();
        let p = json!({"dsip": wire::version_block(), "type": "delegation-revocation", "id": wire::new_id(now), "from": self.c.identity,
            "subject": self.c.identity, "device": device, "revoked_at": now, "reason": "lost", "issued_at": now, "expires_at": now + 300});
        let rev = sign(&p, &self.c.keys.controller, &format!("{}#key-1", self.c.identity));
        // Publish: the identity's document is one of the files this device resolves from.
        let doc_file = self.mx.config().resolver_files.iter().find(|f| {
            std::fs::read_to_string(f).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).is_some_and(|d| d["id"] == json!(self.c.identity))
        });
        let doc_file = doc_file.cloned().context("this identity's DID document is not among --resolver-file")?;
        let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&doc_file)?)?;
        let list = doc.as_object_mut().context("document")?.entry("dsipDelegationRevocations").or_insert(json!([]));
        list.as_array_mut().context("revocations")?.push(json!(compact(&rev)));
        std::fs::write(&doc_file, serde_json::to_string_pretty(&doc)?)?;
        self.mx.refresh_docs();
        let env = wire::message(&self.c.keys.device, "mailbox-config", &self.mx.config().mailbox.0, now, wire::TTL_S,
            json!({"subject": self.c.identity, "revoked_delegations": [compact(&rev)]}));
        let reply = self.mx.request(&mut self.c, &env.frame()).await?;
        anyhow::ensure!(reply["type"] == "accepted", "mailbox refused the revocation: {}", reply["reason"]);
        println!("OK revoked {device} published={} mailbox=accepted", doc_file.display());
        Ok(())
    }

    /// M§14.1: ask `target` for permission to message, the purpose sealed to its key agreement key unless `plain`.
    async fn introduce(&mut self, target: &str, purpose: &str, plain: bool) -> Result<()> {
        let r = self.mx.engine_mut().introduce(target, purpose, plain, now_f()).map_err(messenger_err)?;
        let id = r.id.clone();
        // M§14.1 (spec-gap 81): tell our own mailbox first, so the grant that answers this is not rate-limited there.
        // Best-effort: it only spares the answer a rate limit. A device that cannot reach its own mailbox still introduces.
        if let Err(e) = self.mx.send_frame(&mut self.c, &r.send).await {
            println!("WARN introduction {id} not announced to our own mailbox: {e}");
        }
        self.mx.save(&self.c)?;
        let mut conn = self.mx.peer_connect(target).await?;
        let did = conn.relay.did.clone();
        let frame = self.mx.engine_mut().first_contact_frame(&did, "introduction", target, &r.envelope, now_f());
        let answer = dsip_messenger::peer_exchange(&mut conn, &frame).await?;
        match answer["type"].as_str() {
            Some("accepted") => println!("OK introduction {id} to {target} accepted sealed={}", !plain),
            _ => println!("ERR introduction {id} refused: {} retry_after={}", answer["reason"], answer["retry_after"]),
        }
        Ok(())
    }

    /// M§14.1: answer a request with a `dsip.message` grant, deposited at the requester's mailbox.
    async fn accept_request(&mut self, id: &str) -> Result<()> {
        let r = self.mx.engine_mut().accept_request(id, now_f()).map_err(messenger_err)?;
        let requester = r.requester.clone();
        let mut conn = self.mx.peer_connect(&requester).await?;
        let did = conn.relay.did.clone();
        let frame = self.mx.engine_mut().first_contact_frame(&did, "grant", &requester, &r.envelope, now_f());
        let answer = dsip_messenger::peer_exchange(&mut conn, &frame).await?;
        anyhow::ensure!(answer["type"] == "accepted", "grant refused: {}", answer["reason"]);
        self.mx.engine_mut().forget_request(id);
        self.mx.save(&self.c)?;
        println!("OK granted {requester} dsip.message for request {id}");
        Ok(())
    }

    /// Send an Ogg Opus recording: seal, upload, reference (M§8.2, M§8.4, M§5.6).
    async fn send_audio(&mut self, path: &str, purpose: &str, session: Option<String>, max_duration_s: Option<i64>) -> Result<()> {
        let group = self.c.active()?;
        self.may_send(&group)?;
        let plain = std::fs::read(path).with_context(|| format!("reading {path}"))?;
        let duration_ms = ogg_opus_duration_ms(&plain).context("not an Ogg Opus file")?;
        if let Some(max) = max_duration_s {
            // M§13.2: recording stops at the callee's max_duration_s.
            anyhow::ensure!(duration_ms <= max * 1000, "recording is {duration_ms} ms, over the callee's {max} s");
        }
        // M§8.4 rule 1: a fresh single-use key, AES-256-GCM, nonce ‖ ciphertext ‖ tag.
        let key: [u8; 32] = rand::random();
        let nonce: [u8; 12] = rand::random();
        let blob::Sealed { bytes: sealed, sha256: sha } = blob::seal_blob(&key, &nonce, &plain);
        let conn = self.mx.connection().context("offline")?;
        let endpoint = conn.relay.capabilities["mailbox"]["blob_endpoint"].as_str().context("mailbox advertises no blob_endpoint")?;
        let uri = format!("{endpoint}/{sha}");
        // M§5.6: one upload, authorized by a signed blob-put carrying the device's delegation.
        let auth = self.mx.engine_mut().blob_put(&sha, sealed.len() as f64, now_f());
        let resp = self.mx.http().put(&uri).header("Authorization", format!("DSIP {auth}")).body(sealed.clone()).send().await?;
        let status = resp.status().as_u16();
        let answer = Envelope::from_frame(&resp.text().await?).ok().and_then(|e| wire::payload_of(&e)).unwrap_or_default();
        anyhow::ensure!(matches!(status, 200 | 201) && answer["type"] == "accepted", "blob upload refused: {status} {}", answer["reason"]);

        let now = now_f();
        let key_b64 = dsip_core::b64::encode(&key);
        let uploaded = blob::Uploaded { uri: &uri, sha256: &sha, size: sealed.len() as u64, key: &key_b64, content_type: "audio/ogg; codecs=opus" };
        let conversation = self.conv(&group)?.conversation;
        let id = self.mx.engine_mut().new_id(now);
        let obj = blob::audio_content(&id, &conversation, &self.c.identity, now as i64, purpose, duration_ms, &uploaded, session.as_deref());
        // M§8.4 rule 4: the deposit's manifest names the blob without its key (the Messenger writes it)
        let item = Item::Audio { purpose: purpose.to_string(), duration_ms, sha256: sha };
        self.send_content(&group, obj, item).await.map(|_| ())
    }

    /// M§13.2: after a call attempt to the conversation's peer ended with `reason`, may we leave a voicemail?
    async fn voicemail(&mut self, session: &str, reason: &str, path: &str) -> Result<()> {
        let group = self.c.active()?;
        let me = self.c.identity.clone();
        let c = self.conv(&group)?;
        let peer = c.peer.or_else(|| c.members.into_iter().find(|m| *m != me))
            .context("no callee in the conversation")?;
        let r = resolver(&self.mx.config().resolver_files);
        let doc = dsip_core::did::Resolver::resolve(&r, &peer).with_context(|| format!("no document for {peer}"))?;
        let entry = doc.service.iter().find(|s| s.service_type == "DSIPMailbox").map(|s| s.service_endpoint.clone()).unwrap_or_default();
        let outcome_type = if reason == "session.timeout" { "cancel" } else { "reject" };
        let offer = dsip_messaging::client::voicemail_offer(&json!({"voicemail": entry["voicemail"], "can_send": true,
            "outcome": {"type": outcome_type, "reason": reason}}));
        if offer["offer"] != json!(true) {
            println!("NO-OFFER {reason}");
            return Ok(());
        }
        println!("OFFER {reason} max_duration_s={}", offer["max_duration_s"]);
        self.send_audio(path, "voicemail", Some(session.to_string()), offer["max_duration_s"].as_i64()).await
    }

    /// The latest content of the active conversation's thread, `pred` choosing among them.
    fn latest(&self, gid: &str, pred: impl Fn(&Value) -> bool) -> Option<String> {
        let thread = self.mx.engine().thread(gid);
        thread.iter().rev().find(|m| pred(m)).and_then(|m| m["object"]["id"].as_str().map(String::from))
    }

    /// How many receipts or activities an answer of the `Messenger`'s decided to send (or to keep, or withhold).
    fn decided(out: &[Event]) -> usize {
        out.iter().filter(|e| matches!(e, Event::Ui(Ui::ReceiptSent { .. } | Ui::ReadPrivateKept { .. } | Ui::ReceiptWithheld { .. } | Ui::ActivitySent { .. }))).count()
    }

    async fn command(&mut self, cmd: &str, rest: &str) -> Result<()> {
        let now = now_f();
        match cmd {
            "" => Ok(()),
            "kp" => {
                let frame = self.mx.engine_mut().key_packages_frame(rest.trim().parse().unwrap_or(2), now).map_err(messenger_err)?;
                Ok(self.mx.send_frame(&mut self.c, &frame).await?)
            }
            "release" => {
                // M§4.1, M§5.7 (spec-gap 130): the mailbox closes the binding once it has released the identity; the
                // device then stays offline instead of redialling, since the sync after a redial would enrol it again
                println!("RELEASE sent to {}", self.mx.config().mailbox.0);
                let frame = self.mx.engine_mut().release(now);
                self.mx.send_frame(&mut self.c, &frame).await?;
                self.mx.hold_offline();
                Ok(())
            }
            "introduce" | "introduce-plain" => {
                // introduce <did> <purpose…>: sealed to the recipient's key agreement key; introduce-plain: not sealed
                let (target, purpose) = rest.trim().split_once(' ').context("usage: introduce <did> <purpose>")?;
                self.introduce(target, purpose.trim(), cmd == "introduce-plain").await
            }
            "requests" => {
                for (id, p) in self.mx.engine_mut().requests() {
                    println!("PENDING {id} from {}", s(&p["from"]));
                }
                Ok(())
            }
            "accept-request" => self.accept_request(rest.trim()).await,
            "grant" => {
                println!("GRANT {}", self.mx.engine_mut().grant(rest.trim(), None, now));
                Ok(())
            }
            "create" | "add" => {
                // create <direct|group> <peer> [grant-file]  /  add <peer> [grant-file]
                let mut words = rest.split_whitespace();
                let kind = if cmd == "create" { words.next().unwrap_or("direct").to_string() } else { String::new() };
                let peer = words.next().unwrap_or("").to_string();
                let grant = match words.next() {
                    Some(f) => Some(std::fs::read_to_string(f)?.trim().to_string()),
                    None => None,
                };
                if cmd == "create" {
                    self.create(&kind, &peer, grant).await
                } else {
                    self.add(&peer, grant).await
                }
            }
            "personal" => self.create_personal().await,
            "add-device" => self.add_device(rest.trim()).await,
            "remove-device" => {
                // M§12.4: by credential from every group (a revoked device's leaf no longer authenticates, spec-gap 57),
                // then a new archive key
                let out = self.mx.engine_mut().remove_device(rest.trim(), now).map_err(messenger_err)?;
                Ok(self.mx.handle(&mut self.c, out).await?)
            }
            "revoke-device" => self.revoke_device(rest.trim()).await,
            "remove-leaf" => {
                let group = self.c.active()?;
                let device = rest.trim();
                let frame = self.mx.engine_mut().remove_lapsed_leaf(&group, device, now).map_err(messenger_err)?;
                self.label_for(&group, format!("removed lapsed leaf {device}"));
                Ok(self.mx.send_frame(&mut self.c, &frame).await?)
            }
            "remove" => {
                let group = self.c.active()?;
                let frame = self.mx.engine_mut().remove_member(&group, rest.trim(), now).map_err(messenger_err)?;
                Ok(self.mx.send_frame(&mut self.c, &frame).await?)
            }
            "successor" => {
                let dead = self.c.active()?;
                Ok(self.mx.successor(&mut self.c, &dead).await?)
            }
            "available" => {
                for a in self.mx.engine_mut().available() {
                    let or_unknown = |v: &str| if v.is_empty() { "?".to_string() } else { v.to_string() };
                    println!("AVAILABLE group={} conversation={} kind={}", a.group, or_unknown(&a.conversation), or_unknown(&a.kind));
                }
                Ok(())
            }
            "prefetch" => {
                // M§5.5: fetch a peer's KeyPackages now and hold them (they are single use) for a later add
                let w: Vec<&str> = rest.split_whitespace().collect();
                let peer = w.first().context("usage: prefetch <peer> [grant file]")?.to_string();
                if let Some(f) = w.get(1) {
                    self.mx.engine_mut().set_grants(&BTreeMap::from([(peer.clone(), std::fs::read_to_string(f)?.trim().to_string())]));
                }
                let answer = self.mx.fetch_key_packages(&mut self.c, &peer, None).await?;
                self.mx.engine_mut().key_package_devices(&peer, &answer, now).map_err(messenger_err)?;
                self.c.prefetched.insert(peer.clone(), answer);
                println!("OK prefetched a key package for {peer}");
                Ok(())
            }
            "call-ended" => {
                // call-ended <session> <peer> <alerted 0|1> <answered here 0|1> <local|remote> <reason>
                let w: Vec<&str> = rest.split_whitespace().collect();
                let [session, peer, alerted, answered, by, reason] = w.as_slice() else {
                    bail!("usage: call-ended <session> <peer> <alerted 0|1> <answered 0|1> <local|remote> <reason>");
                };
                let leg = CallLeg { session: session.to_string(), peer: peer.to_string(), alerted: *alerted == "1", answered_here: *answered == "1",
                                    ended_by: by.to_string(), reason: reason.to_string() };
                let r = self.mx.engine_mut().call_ended_item(&leg, now).map_err(messenger_err)?;
                if r.event.is_none() {
                    println!("NO-CALL-EVENT session={session} reason={reason}");
                    return Ok(());
                }
                // M§13.3 (spec-gap 63): every alerted device may report the call; one entry per session
                if let Some(item) = r.item {
                    let outcome = r.event.as_ref().map(|e| s(&e["outcome"]).to_string()).unwrap_or_default();
                    self.c.items.insert(item, Item::CallEvent { outcome, session: session.to_string(), fresh: r.fresh });
                }
                self.mx.save(&self.c)?;
                match r.send.as_str() {
                    "" => Ok(()),
                    f => Ok(self.mx.send_frame(&mut self.c, f).await?),
                }
            }
            "timeline" => {
                // M§13.3 (spec-gap 63): one peer's direct conversation with this identity's call events for that peer
                let peer = rest.trim();
                let gid = self.conversations().into_iter().find(|c| c.kind == "direct" && c.peer.as_deref() == Some(peer))
                    .map(|c| c.group).with_context(|| format!("no direct conversation with {peer}"))?;
                let entries = self.mx.engine_mut().timeline(&gid);
                println!("PEER-TIMELINE {peer} {}", entries.len());
                for e in entries {
                    match e.get("call") {
                        Some(c) => println!("  CALL {} session={}", s(&c["outcome"]), s(&c["session"])),
                        None => println!("  MSG {}: {}", s(&e["sender"]), display(&e["object"])),
                    }
                }
                Ok(())
            }
            "rejoin" => {
                // M§6.8: join by external commit from the latest GroupInfo this identity's mailbox delivered
                let frames = self.mx.engine_mut().external_join(rest.trim(), now).map_err(messenger_err)?;
                self.mx.save(&self.c)?;
                Ok(self.mx.send_frames(&mut self.c, &frames).await?)
            }
            "move-hub" => {
                // M§7.4: move the active group to another hub, by default this identity's own mailbox
                let group = self.c.active()?;
                let w: Vec<&str> = rest.split_whitespace().collect();
                let frame = match w.as_slice() {
                    [did, uri] => self.mx.engine_mut().move_hub_to(&group, did, uri, now),
                    [] => self.mx.engine_mut().move_hub(&group, now),
                    _ => bail!("usage: move-hub [<hub did> <wss uri>]"),
                }
                .map_err(messenger_err)?;
                Ok(self.mx.send_frame(&mut self.c, &frame).await?)
            }
            "rekey" => {
                // M§6.5: a self-update commit, applied only once the hub accepts it
                let group = self.c.active()?;
                let frame = self.mx.engine_mut().rekey(&group, now).map_err(messenger_err)?;
                Ok(self.mx.send_frame(&mut self.c, &frame).await?)
            }
            "send" => self.send_text(rest).await,
            "accept-recording" => {
                // C§5: per conversation, every recorder device present now
                let gid = self.c.active()?;
                let c = self.conv(&gid)?;
                if c.recorders.is_empty() {
                    println!("OK not recorded");
                    return Ok(());
                }
                let r = self.mx.engine_mut().accept_recording(&gid, now).map_err(messenger_err)?;
                println!("OK recording accepted group={gid} recorders={}", list(&json!(r.accepted)));
                self.mx.save(&self.c)?;
                self.mx.send_frames(&mut self.c, &r.frames).await?;
                // C§5 (v0.10): the acceptance is the person's — this identity's other devices are told
                if !r.frames.is_empty() {
                    println!("OK recording acceptance shared with this identity's devices");
                }
                Ok(())
            }
            "leave" => {
                // M§7.3 "Leaving": this identity's Remove proposals; another member's device commits them
                let gid = self.c.active()?;
                let out = self.mx.engine_mut().leave(&gid, now).map_err(messenger_err)?;
                println!("OK leaving group={gid}");
                Ok(self.mx.handle(&mut self.c, out).await?)
            }
            "decline-recording" => {
                // C§5: declining is leaving the conversation (M§7.3)
                let gid = self.c.active()?;
                let out = self.mx.engine_mut().leave(&gid, now).map_err(messenger_err)?;
                println!("OK leaving group={gid} (declined being recorded, C§5)");
                Ok(self.mx.handle(&mut self.c, out).await?)
            }
            "device-event" => self.send_device_event(rest).await,
            "alarm-ack" => {
                // alarm-ack <resource> <type> ack|closed
                let w: Vec<&str> = rest.split_whitespace().collect();
                match w.as_slice() {
                    [resource, kind, state] => self.send_alarm_ack(resource, kind, state).await,
                    _ => Err(anyhow::anyhow!("usage: alarm-ack <resource> <type> ack|closed")),
                }
            }
            "voice" => self.send_audio(rest.trim(), "voice-message", None, None).await,
            "voicemail" => {
                // voicemail <session> <call outcome reason> <file.ogg>
                let w: Vec<&str> = rest.split_whitespace().collect();
                match w.as_slice() {
                    [session, reason, file] => self.voicemail(session, reason, file).await,
                    _ => Err(anyhow::anyhow!("usage: voicemail <session> <reason> <file.ogg>")),
                }
            }
            "sync" => Ok(self.mx.sync(&mut self.c, false).await?),
            "live" => Ok(self.mx.sync(&mut self.c, true).await?),
            "offline" => {
                self.mx.go_offline();
                println!("OK offline");
                Ok(())
            }
            "online" => Ok(self.mx.connect(&mut self.c).await?),
            "read" => {
                // M§10.3: the local user has read everything up to the latest content of the active conversation
                let group = self.c.active()?;
                let through = self.latest(&group, |_| true).context("nothing to read")?;
                let out = self.mx.engine_mut().read_through(&group, &through, now);
                println!("OK read through={} ({} to send)", json!(through), Self::decided(&out));
                Ok(self.mx.handle(&mut self.c, out).await?)
            }
            "play" => {
                // M§10.4: the local user played a media item (default: the latest received)
                let group = self.c.active()?;
                let id = match rest.trim() {
                    "" => self.latest(&group, |m| m["mine"] != json!(true) && m["object"].get("blob").is_some()),
                    id => Some(id.to_string()),
                }
                .context("nothing to play")?;
                let out = self.mx.engine_mut().played(&group, &id, now);
                println!("OK played {id} ({} to send)", Self::decided(&out));
                Ok(self.mx.handle(&mut self.c, out).await?)
            }
            "typing" | "uploading" | "recording-audio" | "recording-video" => {
                let group = self.c.active()?;
                let state = if rest.trim() == "stop" { "stopped" } else { "active" };
                let out = self.mx.engine_mut().activity(&group, cmd, state, now);
                Ok(self.mx.handle(&mut self.c, out).await?)
            }
            "status" => {
                let group = self.c.active()?;
                let live = self.mx.engine_mut().successor(&group).unwrap_or(group);
                println!("STATUS {}", self.mx.engine_mut().receipt_state(&live));
                Ok(())
            }
            "history" => {
                // M§8.5: the conversation's timeline in hub seq order, from MLS and archive alike
                let group = self.c.active()?;
                let thread = self.mx.engine_mut().thread(&group);
                for (i, m) in thread.iter().enumerate() {
                    println!("TIMELINE {i} {}: {}", s(&m["sender"]), display(&m["object"]));
                }
                let keys = self.mx.engine_mut().archive_keys();
                let current = keys.iter().max_by_key(|k| k.created_at).map(|k| json!(k.akid)).unwrap_or(Value::Null);
                println!("OK history {} item(s), current key {current}", thread.len());
                Ok(())
            }
            "crash-next" => {
                self.mx.engine_mut().store().crash.set(true);
                println!("OK crash-next");
                Ok(())
            }
            other => {
                println!("?? unknown command {other}");
                Ok(())
            }
        }
    }
}

/// Duration of an Ogg Opus file from its last granule position less the pre-skip (RFC 7845 §4).
fn ogg_opus_duration_ms(bytes: &[u8]) -> Option<i64> {
    let mut pos = 0;
    let (mut last_granule, mut pre_skip) = (None, None);
    while pos + 27 <= bytes.len() && &bytes[pos..pos + 4] == b"OggS" {
        let granule = i64::from_le_bytes(bytes[pos + 6..pos + 14].try_into().ok()?);
        let segments = bytes[pos + 26] as usize;
        let table = bytes.get(pos + 27..pos + 27 + segments)?;
        let data = pos + 27 + segments;
        let len: usize = table.iter().map(|&b| b as usize).sum();
        if pre_skip.is_none() {
            let head = bytes.get(data..data + 19)?;
            if &head[..8] != b"OpusHead" {
                return None;
            }
            pre_skip = Some(u16::from_le_bytes([head[10], head[11]]) as i64);
        }
        if granule >= 0 {
            last_granule = Some(granule);
        }
        pos = data + len;
    }
    Some((last_granule? - pre_skip?).max(0) * 1000 / 48_000)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let keys = Keys::load_or_create(&args.state, args.controller.as_deref())?;
    if let Some(path) = &args.write_doc {
        let doc = dsip_messenger::did_document(&args.identity, &keys.controller, args.mailbox_did.as_deref().context("--mailbox-did")?,
            args.mailbox_uri.as_deref().context("--mailbox-uri")?);
        std::fs::write(path, serde_json::to_string_pretty(&doc)?)?;
        println!("OK wrote {}", path.display());
        return Ok(());
    }

    let now = now_s();
    // C§5: a recorder device's delegation also carries dsip.record, which every member reads from its leaf; E§2
    // (spec-gap 165): a gateway's carries dsip.events
    let mut caps = vec!["dsip.signaling", "dsip.messaging"];
    if args.recorder {
        caps.push("dsip.record");
    }
    if args.is_gateway() {
        caps.push("dsip.events");
    }
    let deleg = delegation_payload(&args.identity, &keys.device.did(), now - 60, now + 365 * 86_400, &caps);
    let delegation = sign(&deleg, &keys.controller, &format!("{}#key-1", args.identity));
    let r = resolver(&args.resolver_files);
    let mailbox = mailbox_of(&args.identity, &r)?;
    println!("DEVICE {}", keys.device.did());

    let db = Db { inner: SqliteProvider::open(&args.state.join("device.sqlite")).map_err(state_err)?, crash: Cell::new(false),
                  processing: Cell::new(false), classes: Default::default() };
    // the Messenger's state; dsip-msg's own from before it hosted the Messenger is migrated once (decided 2026-10-20)
    let (mut state, host, migrated) = match db.get("messenger").map_err(state_err)? {
        Some(st) => (st, db.get("dsip-msg").map_err(state_err)?.unwrap_or_default(), false),
        None => match migrate(&db, &args.identity, &mailbox.0, &r)? {
            Some((st, host)) => (st, host, true),
            None => (Value::Null, Value::Null, false),
        },
    };
    // spec-gap 44: the item transactions keep the delivery state under its own key, written with the item's MLS state
    if let (Some(resume), true) = (db.get("resume").map_err(state_err)?, state.is_object()) {
        state["resume"] = resume;
    }
    let identity_json = dsip_messenger::engine_identity(&args.identity, &keys.device, &keys.controller, &delegation, &args.identity);
    let mut m = Engine::open(&identity_json, &mailbox.0, &mailbox.1, db, &state, now as f64).map_err(messenger_err)?;
    // C§5: a recorder discloses nothing (it sends no receipts)
    let policy = ReceiptPolicy { delivered: !args.no_delivered && !args.recorder, read: !args.recorder && args.disclose.iter().any(|d| d == "read"),
        played: args.disclose.iter().any(|d| d == "played"), activity: args.disclose.iter().any(|d| d == "activity") };
    m.set_receipt_policy(policy, now as f64);
    m.set_gap_timeout(args.gap_timeout);
    m.set_hub_timeout(args.hub_timeout as f64);
    m.set_no_answer_timeout(args.no_answer_timeout);
    m.set_recorder_sends(args.recorder_misbehave);
    let cfg = dsip_messenger::Config {
        identity: args.identity.clone(),
        device: keys.device.clone(),
        delegation,
        mailbox,
        resolver_files: args.resolver_files.clone(),
        ca: args.ca.clone(),
        media_dir: args.state.join("media"),
        host_key: "dsip-msg".into(),
    };
    let mx = dsip_messenger::Messenger::new(m, cfg, host["pending_blobs"].as_array().cloned().unwrap_or_default())?;
    let c = Console {
        keys,
        identity: args.identity.clone(),
        active: host["active"].as_str().map(String::from),
        names: HashMap::new(),
        items: HashMap::new(),
        labels: HashMap::new(),
        prefetched: HashMap::new(),
        resent: HashMap::new(),
        events: events::Events::new(&args).await?,
        recorder_mode: args.recorder,
        recorder_misbehave: args.recorder_misbehave,
        state: args.state.clone(),
    };
    let mut client = Client { mx, c };
    client.mx.save(&client.c)?;
    if migrated {
        clear_migrated(client.mx.engine().store())?;
        println!("MIGRATED dsip-msg state into the Messenger's: {} group(s)", client.conversations().len());
    }

    // Restart: everything below comes from the database, exactly as last committed.
    let since = client.mx.engine().state()["resume"]["cursor"].clone();
    for c in client.conversations() {
        println!("RESTORED {} kind={} since={since}", c.conversation, c.kind);
        if c.pending > 0 {
            // M§9.4 (spec-gap 72): pending items and the outage they wait out survive a restart
            println!("PENDING restored {} item(s) for {}", c.pending, c.group);
        }
    }
    if client.c.active.as_ref().is_none_or(|a| client.conv(a).is_err()) {
        client.c.active = client.conversations().into_iter().rev().find(|c| c.kind != "personal").map(|c| c.group);
    }
    client.c.refresh_names(client.mx.engine());
    client.mx.connect(&mut client.c).await?;

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut gw_rx = client.c.events.listen(&args).await?;
    loop {
        let gw = async {
            match gw_rx.recv().await {
                Some(x) => x,
                None => std::future::pending().await,
            }
        };
        let recv = client.mx.recv();
        tokio::select! {
            input = gw => {
                if let Err(e) = client.gateway_input(input).await {
                    println!("ERR {e}");
                }
                client.mx.settle(&mut client.c).await;
            }
            line = stdin.next_line() => {
                let Some(line) = line? else { break };
                let line = line.trim().to_string();
                let (cmd, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
                if cmd == "quit" {
                    break;
                }
                if let Err(e) = client.command(cmd, rest).await {
                    println!("ERR {e}");
                }
                if let Err(e) = client.mx.save(&client.c) {
                    println!("ERR {e}");
                }
                client.mx.settle(&mut client.c).await;
            }
            _ = ticker.tick() => {
                client.mx.tick(&mut client.c).await;
                if let Err(e) = client.mx.check_reconnect(&mut client.c).await {
                    println!("ERR {e}");
                }
                // M§8.4 (spec-gap 106): blob fetches that found nothing are tried again
                if let Err(e) = client.mx.retry_blobs(&client.c) {
                    println!("ERR {e}");
                }
                // E§5–E§6: alarm timers (escalation, gateway silence)
                client.c.tick_alarms();
                if client.c.events.gateway_due() {
                    if let Err(e) = client.gateway_tick().await {
                        println!("ERR {e}");
                    }
                }
                client.mx.settle(&mut client.c).await;
            }
            Some(frame) = recv => {
                // what the frame set going (receipts, archive records) is answered before the next command
                client.mx.received(&mut client.c, frame).await;
                client.mx.settle(&mut client.c).await;
            }
        }
        std::io::stdout().flush()?;
    }
    Ok(())
}
