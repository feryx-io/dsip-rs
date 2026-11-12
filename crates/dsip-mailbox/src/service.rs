//! The mailbox/hub service as a library: [`MailboxServer`]. The `dsip-mailbox` binary parses flags and hosts one; an
//! application embeds one the same way, over TLS ([`MailboxServer::serve_tls`]) or over any byte stream
//! ([`MailboxServer::accept`]).
//!
//! Spec: M§4.3 (bind with `hello`, advertise mailbox capabilities), M§5 (the profile message set),
//! M§6.5–M§6.6 (hub ordering, fan-out, group registration), M§9.1 (deposit once, push to bound
//! devices), M§14.2 (first-contact authorization).
//!
//! Impl: every decision comes from `dsip_messaging::{mailbox::Mailbox, hub::Hub}` and, for commits,
//! `dsip_mls::HubView`; this module only moves bytes and keeps the payloads the cursors name.
//! One instance serves the owner identities it is configured with ([`MailboxConfig::owners`]) and, with
//! [`MailboxConfig::serve_any`] N, up to N more that enrol by binding with a verified `hello` — how a `did:key` identity with no
//! document comes to have a mailbox (spec-gap 115); it hubs the groups whose deposits name it. A member whose
//! identity has no document is reached through its DHT reachability hint's `DSIPMailbox` endpoint (M§4.2), looked
//! up on the hints nodes in [`MailboxConfig::hints_nodes`]. An owner
//! device's deposit for a group hubbed elsewhere is forwarded unchanged to the hub registered for that
//! group, and the hub's answer comes back on the same path (M§5.2, spec-gap 45); the hub takes the
//! acting identity of a forwarded deposit from the delegation in its header, since the connection it
//! arrived on belongs to a mailbox. Welcomes a hub fans out carry the adder's deposit as `origin`,
//! which the receiving mailbox verifies (M§14.2, spec-gap 46).
//!
//! Impl (spec-gap 59): everything but live connections is saved to `<state>/mailbox.sqlite` after each change
//! (`crate::db`: each stored item a row, the rest in parts, only what changed written) and reloaded at startup — the
//! machines' full state, the hub's public MLS views, stored payloads and KeyPackages,
//! fan-out payloads still queued, hub references, revocations and the seen-id window. A restarted hub re-sends the
//! head of every unacknowledged fan-out queue at once, and after that any head left unacknowledged is re-sent with
//! backoff; a member mailbox acknowledges a redelivery as a duplicate.
//!
//! Spec: W§4.2, W§4.4, W§5.1 (Wake Profile, draft: with [`MailboxConfig::wake`], `wake-register` is answered, `wake`
//! is advertised, and an item stored for an identity wakes its registered devices that are not bound, `message`
//! coalesced). Impl (spec-gap 176): `wake-register` is an owner operation (M§4.1): an identity this service does not
//! serve enrols by it as by any other, or is refused `mailbox.not-served`.

mod admin;
mod status;

/// The admin commands the status port answers (`dsip-mailbox admin …`: `enrolments`, `release <did>`).
pub use admin::COMMANDS as ADMIN_COMMANDS;

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use dsip_core::envelope::{self, Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::did::{DidDocument, Resolver, StaticResolver};
use dsip_core::version::Supported;
use crate::db::Db;
use crate::store::{Item, Store};
use crate::verify::{delegated_identity, verify_frame};
use crate::{http, wire, HELLO_TIMEOUT_S};
use dsip_messaging::client::select_mailbox;
use dsip_messaging::enrolment::Enrolment;
use dsip_messaging::hub::Hub;
use dsip_messaging::mailbox::Mailbox;
use dsip_mls::{digest, message_header, HubView};
use dsip_transport::conn::{ConnectParams, Connection};
use dsip_transport::resolver::{Over, WebDocuments};
use dsip_transport::verify::SeenIds;
use dsip_transport::waker::{Outgoing, WakeConfig, Wakes};
use dsip_transport::{now_s, tls};

/// The advertised `blob_endpoint` (M§4.3): the listen port on `host` (the first extra certificate host), else on the
/// listen address.
pub fn blob_endpoint(listen: &SocketAddr, host: Option<&str>) -> String {
    let port = listen.port();
    match host {
        Some(h) if h.contains(':') => format!("https://[{h}]:{port}/blobs"),
        Some(h) => format!("https://{h}:{port}/blobs"),
        None => format!("https://{listen}/blobs"),
    }
}

fn s_of(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// The saved service state, in the state directory.
/// The state file a mailbox kept before its database (imported once, then renamed `….imported`).
const STATE_FILE: &str = "mailbox-state.json";
/// The service's database (`crate::db`).
const DB_FILE: &str = "mailbox.sqlite";
/// `retry_after` on a deposit refused because the state could not be saved (spec-gap 99).
const SAVE_RETRY_AFTER_S: i64 = 60;
/// How long a mailbox found through a hint is used before the hint is looked up again, seconds: a member that moves
/// publishes a newer hint (§8.3), and its deliveries must follow it soon after.
const HINT_REUSE_S: i64 = 60;
/// Seconds between checks for unacknowledged fan-out.
const RETRY_TICK_S: u64 = 2;
/// First and largest delay before re-sending a fan-out head that stays unacknowledged, seconds.
const RETRY_FIRST_S: i64 = 4;
const RETRY_MAX_S: i64 = 60;

/// What a handled message produces.
enum Out {
    /// To a bound device of the owner, if connected.
    Device(String, Envelope),
    /// To another identity's mailbox (federation, M§6.5 rule 5).
    Identity(String, Envelope),
}

/// What this service keeps for one served owner: its mailbox machine and the payloads behind its cursors.
struct Owned {
    mailbox: Mailbox,
    store: Store,
}

struct Service {
    key: KeyPair,
    /// Owners from `--owner`, in order; the first is the one a format-1 saved state belongs to.
    configured: Vec<String>,
    /// `--serve-any`: how many identities may enrol beyond the configured owners (spec-gap 115).
    serve_any: Option<usize>,
    /// Whom this service serves beyond `configured`, and when each enrolment ends (M§4.1; spec-gaps 115, 130): the
    /// vector-pinned machine decides, this host acts on what it emits. Its entries are saved with the state.
    enrolment: Enrolment,
    /// The identities each stored blob was uploaded or replicated for (spec-gap 130): a blob is deleted when the last
    /// of them is released. A blob stored before this index existed belongs to no one and is kept.
    blob_owners: BTreeMap<String, std::collections::BTreeSet<String>>,
    /// The served owners' state, by identity.
    owned: BTreeMap<String, Owned>,
    /// The mailbox machine that answers for recipients this service does not serve: first contact for them is
    /// accepted and dropped exactly as a held one (§19.4 anti-enumeration), rate-limited the same way.
    drop_box: Mailbox,
    /// The `Mailbox::new` context every owner starts from (the operator's limits).
    mailbox_ctx: Value,
    /// Hints nodes asked for a `DSIPMailbox` hint when an identity has no document (M§4.2).
    hints_nodes: Vec<String>,
    /// Mailboxes found through hints, by identity: `(mailbox DID, uri, expires_at)` — a hint, re-looked-up when
    /// it expires (§8.1 rule 6: never authority).
    hinted: HashMap<String, (String, String, i64)>,
    resolver_files: Vec<PathBuf>,
    /// `did:web` documents fetched over HTTPS, after the files (§7.2, §8.1).
    web: Option<Arc<WebDocuments>>,
    ca: Option<PathBuf>,
    seen: SeenIds,
    supported: Supported,
    hubs: HashMap<String, Hub>,
    views: HashMap<String, HubView>,
    /// Items the hub has sequenced but whose fan-out is still in flight, by (group, seq).
    fanout: HashMap<(String, i64), Item>,
    /// `dsip_conversation` of each hubbed group: its kind and the hub reference welcomes carry.
    conversations: HashMap<String, Value>,
    /// Hub `{did, uri}` of each group registered for the owner, from its welcome (M§6.6): where to forward.
    hub_refs: HashMap<String, Value>,
    bound: HashMap<String, mpsc::UnboundedSender<String>>,
    /// A device's second connection while its binding is still open (a KeyPackage fetch at its own mailbox, or a
    /// reconnection whose predecessor has not closed yet): answered on itself, and promoted to the binding when the
    /// first one closes.
    standby: HashMap<String, mpsc::UnboundedSender<String>>,
    /// Connections to other identities' mailboxes, by the member identity they were resolved for.
    peers: HashMap<String, mpsc::UnboundedSender<PeerMsg>>,
    /// `delegation-revocation` records from the owner identities (spec-gap 57).
    revocations: Vec<Envelope>,
    /// Ciphertext blobs, one file per SHA-256 (M§8.4).
    blob_dir: PathBuf,
    /// `https://…/blobs` as advertised (M§4.3).
    blob_endpoint: String,
    max_blob_bytes: i64,
    /// Each owner's quota, bytes (spec-gap 99).
    quota_bytes: i64,
    /// Where [`STATE_FILE`] lives.
    state_dir: PathBuf,
    db: Db,
    /// Unacknowledged fan-out heads by (group, member identity, class): (seq, next retry at, current delay). A welcome
    /// has its own queue (spec-gap 66), so it is tracked apart from the identity's sequenced items.
    retry: HashMap<(String, String, String), (i64, i64, i64)>,
    /// Manifest blobs of newly stored items, waiting to be replicated, with the owner they were stored for (M§8.4
    /// rule 6, spec-gap 65).
    replicate: Vec<(String, Value)>,
    /// Blobs whose replication is still to be tried again: `(owner, entry, attempts so far, next attempt at)`
    /// (spec-gap 67).
    replicate_later: Vec<(String, Value, i64, i64)>,
    /// Welcome deposits in flight, by deposit id: `(group, added identity, the commit's seq)` (spec-gap 66). A welcome
    /// carries no `seq` on the wire (M§5.2), so its acknowledgement is matched here to release the hub's queue.
    welcomes_sent: HashMap<String, (String, String, i64)>,
    /// Fault injection: peer mailbox DID whose fan-out is dropped (`--drop-fanout-to`).
    drop_fanout_to: Option<String>,
    /// `--release-idle` and `--mls-retention`, as the status page reports them.
    release_idle: bool,
    mls_retention: i64,
    /// Counters for the status page (`--status-listen`).
    stats: status::Stats,
    /// Wake Profile (draft): registrations and the `message` wakes; `None` without [`MailboxConfig::wake`].
    wakes: Option<Wakes>,
}

/// What goes out on a connection to a peer service.
enum PeerMsg {
    /// Hub fan-out we originate; its `accepted` releases the next queued item (M§6.5 rule 5).
    Fanout(Envelope),
    /// An owner device's deposit, forwarded unchanged; the answer goes back to that device (M§5.2).
    Forward(Envelope, String),
}

fn ctx_of<'a>(resolver: &'a Documents, seen: &SeenIds, supported: &Supported, revocations: &[Envelope]) -> Context<'a> {
    let mut ctx = Context::new(now_s(), resolver);
    ctx.seen_ids = seen.set();
    ctx.supported = supported.clone();
    // spec-gap 57: revocations the owner sent are applied to every binding, beside those in DID documents
    ctx.revocations = revocations.to_vec();
    ctx
}

/// Sent down a bound device's channel to end its connection (spec-gap 57).
const CLOSE_SENTINEL: &str = "\u{0}close";

impl Service {
    /// Save everything that must survive a restart (spec-gap 59). A failed write is logged, not fatal: the
    /// in-memory state is still correct and the next change writes again.
    fn persist(&mut self) -> bool {
        let now = now_s();
        self.seen.sweep(now);
        let queued: HashMap<&String, std::collections::BTreeSet<i64>> = self.hubs.iter().map(|(g, h)| (g, h.queued_seqs())).collect();
        // A fan-out payload is kept while its seq is queued for some mailbox; group-info and ephemeral (-1) are the latest.
        self.fanout.retain(|(g, seq), _| *seq < 0 || queued.get(g).is_some_and(|q| q.contains(seq)));
        let compact = |e: &Envelope| format!("{}.{}.{}", e.protected, e.payload, e.signature);
        let mut parts: Vec<(String, Value)> = vec![
            ("service".into(), json!(self.key.did())),
            ("enrolment".into(), json!(self.enrolment.entries())),
            ("blob_owners".into(), json!(self.blob_owners)),
            ("drop_box".into(), self.drop_box.full_state()),
            ("fanout".into(), json!(self.fanout.iter().map(|((g, seq), it)| json!([g, seq, it])).collect::<Vec<_>>())),
            ("conversations".into(), json!(self.conversations)),
            ("hub_refs".into(), json!(self.hub_refs)),
            ("revocations".into(), json!(self.revocations.iter().map(compact).collect::<Vec<_>>())),
            ("welcomes_sent".into(), json!(self.welcomes_sent.iter().map(|(id, (g, i, s))| json!([id, g, i, s])).collect::<Vec<_>>())),
            ("replicate_later".into(), json!(self.replicate_later.iter().map(|(o, e, n, at)| json!([o, e, n, at])).collect::<Vec<_>>())),
            ("seen".into(), json!(self.seen.entries())),
        ];
        // each item is a row, written when stored and deleted when its machine drops it (queue-mode deletion,
        // retention, expiry), its payload with it; the owner's part keeps the rest of the machine
        let mut rows = vec![];
        for (id, o) in self.owned.iter_mut() {
            let (stored, dropped) = o.mailbox.changes();
            let (stored, dropped) = (stored.to_vec(), dropped.to_vec());
            for c in dropped {
                o.store.remove(&c);
                rows.push(crate::db::Row::Delete { owner: id.clone(), cursor: c });
            }
            for c in stored {
                let Some(record) = o.mailbox.record(&c) else { continue }; // stored and dropped since the last save
                let item = o.store.get(&c).map(|it| serde_json::to_string(it).unwrap_or_default());
                let n = record["n"].as_i64().unwrap_or(0);
                rows.push(crate::db::Row::Put { owner: id.clone(), cursor: c, n, record: record.to_string(), item });
            }
            let mut v = o.store.key_package_value();
            v["mailbox"] = o.mailbox.full_state_without_items();
            parts.push((format!("owner/{id}"), v));
        }
        parts.extend(self.hubs.iter().map(|(g, h)| (format!("hub/{g}"), h.full_state())));
        parts.extend(self.views.iter().map(|(g, v)| (format!("view/{g}"), serde_json::from_slice(&v.save()).unwrap_or(Value::Null))));
        if let Err(e) = self.db.write(parts, &rows) {
            tracing::warn!("saving state failed: {e}");
            return false;
        }
        for o in self.owned.values_mut() {
            o.mailbox.saved();
        }
        true
    }

    /// Absorb a storing step's emissions, then make the new item durable before acknowledging it.
    ///
    /// Spec: M§9 — `accepted` is where the sender stops retrying. Impl (spec-gap 99): a deposit that stored a new
    /// item is acknowledged only once the state is written. If the write fails (a full disk), the step is rolled
    /// back — machine and payload — and the deposit is refused `mailbox.quota-exceeded` with `retry_after`, so the
    /// sender keeps it pending and retries instead of losing it at the next restart.
    /// `before` is the machine as it was before the step — a clone, not a saved state: restoring a saved state is a
    /// restart and would also drop the live device bindings, so a rolled-back mailbox would stop pushing to them.
    fn commit(&mut self, owner: &str, before: Mailbox, emissions: Vec<Value>, item: Item) -> Vec<Value> {
        let stored = emissions
            .iter()
            .find_map(|e| e.get("accepted"))
            .filter(|a| a["cursor"].is_string() && a["duplicate"] != json!(true))
            .cloned();
        self.absorb(owner, &emissions, item);
        let Some(acc) = stored else { return emissions };
        if self.persist() {
            return emissions;
        }
        if let Some(o) = self.owned.get_mut(owner) {
            o.mailbox = before;
            if let Some(c) = acc["cursor"].as_str() {
                o.store.remove(c);
            }
        }
        tracing::warn!("refusing deposit {}: its state could not be saved", acc["in_reply_to"]);
        vec![json!({"error": {"to": acc["to"], "in_reply_to": acc["in_reply_to"], "reason": "mailbox.quota-exceeded",
            "retry_after": SAVE_RETRY_AFTER_S}})]
    }

    /// Reload what [`Service::persist`] saved: the database, or on the first start after an upgrade the state file
    /// a mailbox kept before it, imported once (written whole to the database, then renamed `….imported`). Returns
    /// false when there is nothing to reload.
    fn restore(&mut self) -> Result<bool> {
        let path = self.state_dir.join(STATE_FILE);
        if !self.db.is_empty().map_err(|e| bad(DB_FILE, e))? {
            if path.exists() {
                tracing::warn!("{} is ignored: the state is in {DB_FILE}", path.display());
            }
            let v = self.db.load().map_err(|e| bad(DB_FILE, e))?;
            return self.restore_from(&v).map(|()| true);
        }
        if !path.exists() {
            return Ok(false);
        }
        let v: Value = serde_json::from_slice(&std::fs::read(&path)?).map_err(|e| bad("saved state", e))?;
        self.restore_from(&v)?;
        for o in self.owned.values_mut() {
            // written whole, once; payloads of items the machine had already dropped are not kept
            let m = &o.mailbox;
            o.store.retain(|c| m.record(c).is_some());
            o.mailbox.all_stored();
        }
        if !self.persist() {
            return Err(bad(DB_FILE, "importing the state file failed"));
        }
        let done = path.with_extension("json.imported");
        std::fs::rename(&path, &done)?;
        tracing::info!("imported {} into {DB_FILE} (kept as {})", path.display(), done.display());
        Ok(true)
    }

    /// Load a saved state, as [`Db::load`] assembles it or as `mailbox-state.json` held it.
    fn restore_from(&mut self, v: &Value) -> Result<()> {
        if v["format"] != 1 && v["format"] != 2 {
            return Err(bad("saved state", format!("unknown format {}", v["format"])));
        }
        if v["format"] == 1 {
            // one owner, one store: the state a single-owner mailbox saved
            let owner = s_of(&v["owner"]);
            if self.configured.first() != Some(&owner) {
                return Err(bad("saved state", format!("it is for {owner}, not {:?}", self.configured.first())));
            }
            let mailbox = Mailbox::from_full_state(&v["mailbox"]).ok_or_else(|| bad("saved mailbox", "does not load"))?;
            let store: Store = serde_json::from_value(v["store"].clone()).map_err(|e| bad("saved store", e))?;
            self.owned.insert(owner, Owned { mailbox, store });
        } else {
            for (id, o) in v["owners"].as_object().into_iter().flatten() {
                let mailbox = Mailbox::from_full_state(&o["mailbox"]).ok_or_else(|| bad(&format!("saved mailbox of {id}"), "does not load"))?;
                let store: Store = serde_json::from_value(o["store"].clone()).map_err(|e| bad(&format!("saved store of {id}"), e))?;
                self.owned.insert(id.clone(), Owned { mailbox, store });
            }
            let entries: Vec<(String, i64)> = match v["enrolment"].as_array() {
                Some(a) => a.iter().map(|e| (s_of(&e[0]), e[1].as_i64().unwrap_or(0))).collect(),
                // a state saved before spec-gap 130 lists the enrolled identities only: each counts as seen now
                None => v["enrolled"].as_array().into_iter().flatten().map(|e| (s_of(e), now_s())).collect(),
            };
            self.enrolment.restore_entries(entries);
            self.blob_owners = serde_json::from_value(v["blob_owners"].clone()).unwrap_or_default();
            if let Some(d) = Mailbox::from_full_state(&v["drop_box"]) {
                self.drop_box = d;
            }
        }
        // the configured quota wins over a saved one (or a state saved before quotas existed; spec-gap 99)
        for o in self.owned.values_mut() {
            o.mailbox.set_quota(Some(self.quota_bytes));
        }
        // a configured owner with no saved state starts fresh
        for id in self.configured.clone() {
            self.ensure_owner(&id);
        }
        for (g, h) in v["hubs"].as_object().into_iter().flatten() {
            self.hubs.insert(g.clone(), Hub::from_full_state(h).ok_or_else(|| bad(&format!("saved hub of {g}"), "does not load"))?);
        }
        for (g, view) in v["views"].as_object().into_iter().flatten() {
            let view = HubView::load(&serde_json::to_vec(view)?).map_err(|e| bad(&format!("saved view of {g}"), e))?;
            self.views.insert(g.clone(), view);
        }
        for f in v["fanout"].as_array().into_iter().flatten() {
            let item: Item = serde_json::from_value(f[2].clone()).map_err(|e| bad("saved fan-out", e))?;
            self.fanout.insert((f[0].as_str().unwrap_or("").to_string(), f[1].as_i64().unwrap_or(-1)), item);
        }
        let map = |x: &Value| x.as_object().map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
        self.conversations = map(&v["conversations"]);
        self.hub_refs = map(&v["hub_refs"]);
        self.revocations = v["revocations"].as_array().into_iter().flatten().filter_map(Value::as_str)
            .filter_map(|c| {
                let mut parts = c.split('.');
                Some(Envelope { protected: parts.next()?.into(), payload: parts.next()?.into(), signature: parts.next()?.into() })
            })
            .collect();
        for r in v["replicate_later"].as_array().into_iter().flatten() {
            if r[0].is_string() {
                self.replicate_later.push((s_of(&r[0]), r[1].clone(), r[2].as_i64().unwrap_or(1), r[3].as_i64().unwrap_or(0)));
            } else if let Some(owner) = self.configured.first().cloned() {
                self.replicate_later.push((owner, r[0].clone(), r[1].as_i64().unwrap_or(1), r[2].as_i64().unwrap_or(0)));
            }
        }
        for w in v["welcomes_sent"].as_array().into_iter().flatten() {
            self.welcomes_sent.insert(s_of(&w[0]), (s_of(&w[1]), s_of(&w[2]), w[3].as_i64().unwrap_or(0)));
        }
        self.seen = SeenIds::from_entries(serde_json::from_value(v["seen"].clone()).unwrap_or_default());
        Ok(())
    }

    /// Re-send fan-out heads nobody has acknowledged (M§6.5 rule 5, spec-gap 59): all of them at once after a restart,
    /// then each head that stays unacknowledged, with doubling delay. Our own owner's queue is filled in-process and
    /// never waits.
    fn retry_fanout(&mut self, service: &Arc<Mutex<Service>>, restarted: bool) {
        let now = now_s();
        // spec-gap 119: each hub's clock follows ours; a member that acknowledged nothing for mls_retention_s loses its
        // queues here (the payloads go with the next persist), and nothing more is retried for it until new items come
        let mut dropped = false;
        for (group, h) in self.hubs.iter_mut() {
            let behind = now - h.now();
            if behind <= 0 {
                continue;
            }
            for e in h.step(&json!({"advance": behind})) {
                if let Some(d) = e.get("dropped") {
                    dropped = true;
                    tracing::info!("hub of {group}: {} acknowledged nothing for mls_retention_s: dropped its queue (seqs {}, welcomes {}); \
                        a returning device re-joins by external commit (spec-gap 119)", s_of(&d["identity"]), d["pending"], d["welcomes"]);
                }
            }
        }
        if dropped {
            self.persist();
        }
        let heads: Vec<(String, Value)> =
            self.hubs.iter().flat_map(|(g, h)| h.resend_heads().into_iter().map(move |e| (g.clone(), e))).collect();
        let mut live = std::collections::HashSet::new();
        for (group, e) in heads {
            let (to, seq) = (e["fanout"]["to"].as_str().unwrap_or("").to_string(), e["fanout"]["seq"].as_i64().unwrap_or(-1));
            let class = e["fanout"]["class"].as_str().unwrap_or("").to_string();
            let key = (group.clone(), to.clone(), class.clone());
            live.insert(key.clone());
            let due = match self.retry.get(&key) {
                _ if restarted => Some(RETRY_FIRST_S),
                Some((s, at, delay)) if *s == seq => (now >= *at).then_some((delay * 2).min(RETRY_MAX_S)),
                _ => {
                    self.retry.insert(key.clone(), (seq, now + RETRY_FIRST_S, RETRY_FIRST_S)); // just sent: wait before retrying
                    None
                }
            };
            let Some(delay) = due else { continue };
            self.retry.insert(key, (seq, now + delay, delay));
            tracing::info!("re-sending {} seq {seq} in {group} to {to}", if class == "welcome" { "welcome" } else { "fan-out" });
            for out in self.hub_out(&group, vec![e], now) {
                match out {
                    Out::Identity(id, env) => federate(service, self, &id, env),
                    Out::Device(..) => {}
                }
            }
        }
        self.retry.retain(|k, _| live.contains(k));
    }

    /// Advance the mailbox machine's clock to `now`. It keeps its own (timers: §19.4 holds, M§6.6 pending groups, the
    /// M§7.4 handover wait), advanced before every message and on the retry tick, and catching up from the saved clock
    /// after a restart.
    fn catch_up(&mut self, now: i64) {
        for owner in self.owned.keys().cloned().collect::<Vec<_>>() {
            let behind = now - self.owned[&owner].mailbox.now();
            if behind > 0 {
                let emissions = self.owned.get_mut(&owner).expect("owner").mailbox.step(&json!({"advance": behind}));
                let outs = self.mailbox_out(&owner, emissions, now);
                self.send_local(outs);
            }
        }
        let behind = now - self.drop_box.now();
        if behind > 0 {
            self.drop_box.step(&json!({"advance": behind}));
        }
        // M§4.1 (spec-gap 130): with --release-idle, an enrolled identity with no registered device is released
        let behind = now - self.enrolment.now();
        if behind > 0 {
            for e in self.enrolment.advance(behind) {
                if let Some(id) = e["released"]["identity"].as_str() {
                    self.end_enrolment(id, "idle");
                }
            }
        }
        let Service { wakes, key, .. } = self;
        if let Some(w) = wakes.as_mut() {
            w.settle(now, key); // W§4.3: registrations at their expires_at
        }
    }

    /// Whether this service serves `identity`: configured, or enrolled (spec-gap 115).
    fn serves(&self, identity: &str) -> bool {
        self.owned.contains_key(identity)
    }

    /// The owner's mailbox machine, created from the operator's context if it is served for the first time.
    fn ensure_owner(&mut self, identity: &str) -> &mut Owned {
        if !self.owned.contains_key(identity) {
            let mut ctx = self.mailbox_ctx.clone();
            ctx["now"] = json!(now_s());
            ctx["owner"] = json!(identity);
            ctx["serves"] = json!([identity]);
            self.owned.insert(identity.to_string(), Owned { mailbox: Mailbox::new(&ctx), store: Store::default() });
        }
        self.owned.get_mut(identity).expect("owner")
    }

    /// An owner operation (`sync`, `key-packages`, `mailbox-config`) on a verified binding: an identity this service
    /// does not serve enrols while the operator's bound has room, as the vector-pinned [`Enrolment`] decides (M§4.1,
    /// spec-gaps 115, 130), and its device is registered. Returns the refusal to send instead of handling the operation
    /// (`mailbox.not-served`), or `None`. A service identity (bound as itself) is not an owner and never enrols; its
    /// operations go to the drop box as before.
    fn owner_op(&mut self, identity: &str, device: &str, id: &str, now: i64) -> Option<Vec<Out>> {
        if identity == device {
            return None;
        }
        if self.serves(identity) {
            // M§4.4: the device is on a verified binding of a served identity. One that bound before another device of
            // the identity enrolled it was not registered at its hello, so it is registered here.
            self.register(identity, device);
            return None;
        }
        let emissions = self.enrolment.owner_op(identity, device, id);
        if emissions.iter().any(|e| e.get("enrolled").is_some()) {
            self.ensure_owner(identity);
            self.register(identity, device);
            tracing::info!("enrolled {identity} (serve-any {}/{})", self.enrolment.entries().len(), self.serve_any.unwrap_or(0));
            return None;
        }
        tracing::info!("not serving {identity}: serve-any {}/{} (M§4.1)", self.enrolment.entries().len(), self.serve_any.unwrap_or(0));
        Some(self.mailbox_out(identity, emissions, now))
    }

    /// Register `device` as one of the served `identity`'s devices (M§4.4), if it is not already.
    fn register(&mut self, identity: &str, device: &str) {
        let Some(o) = self.owned.get_mut(identity) else { return };
        if !o.mailbox.devices().iter().any(|d| d == device) {
            let mut devices: Vec<String> = o.mailbox.devices().to_vec();
            devices.push(device.to_string());
            o.mailbox.register_devices(&devices);
        }
    }

    /// End an identity's enrolment (M§4.1, spec-gap 130): delete everything held for it — its mailbox machine and
    /// store, the blobs only it had, its pending replications — and close its devices' bindings. Its place in the
    /// bound is already free in [`Enrolment`].
    fn end_enrolment(&mut self, identity: &str, cause: &str) {
        let devices = self.owned.remove(identity).map(|o| o.mailbox.devices().to_vec()).unwrap_or_default();
        for d in &devices {
            if let Some(tx) = self.bound.remove(d) {
                let _ = tx.send(CLOSE_SENTINEL.to_string());
            }
            if let Some(tx) = self.standby.remove(d) {
                let _ = tx.send(CLOSE_SENTINEL.to_string());
            }
        }
        let mut deleted = 0;
        self.blob_owners.retain(|sha, owners| {
            owners.remove(identity);
            if owners.is_empty() {
                let _ = std::fs::remove_file(self.blob_dir.join(sha));
                deleted += 1;
            }
            !owners.is_empty()
        });
        self.replicate_later.retain(|(owner, ..)| owner != identity);
        let Service { wakes, key, .. } = self;
        if let Some(w) = wakes.as_mut() {
            w.forget_identity(identity, key, now_s()); // W§4.3: its devices are no longer registered devices (M§4.4)
        }
        tracing::info!("released {identity} ({cause}): deleted its mailbox, {deleted} blob(s), closed {} binding(s)", devices.len());
        self.persist();
    }

    /// The mailbox machine that answers for `recipient`: its own if served, else the drop box (§19.4 anti-enumeration:
    /// an introduction for an identity not served here is accepted like a held one, then dropped).
    fn mailbox_for(&mut self, recipient: &str) -> &mut Mailbox {
        match self.owned.get_mut(recipient) {
            Some(o) => &mut o.mailbox,
            None => &mut self.drop_box,
        }
    }

    /// Send what is addressed to bound devices of our owner; nothing else arises outside a connection handler.
    fn send_local(&self, outs: Vec<Out>) {
        for out in outs {
            if let Out::Device(to, env) = out {
                if let Some(tx) = self.bound.get(&to) {
                    let _ = tx.send(env.frame());
                }
            }
        }
    }

    fn resolver(&self) -> Documents {
        let mut r = StaticResolver::default();
        for f in &self.resolver_files {
            let Ok(text) = std::fs::read_to_string(f) else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
            if v.get("id").is_some() {
                if let Ok(doc) = serde_json::from_value(v) {
                    r.insert(doc);
                }
            }
        }
        Documents { files: r, web: self.web.clone() }
    }

    /// An item as `items` carries it, with blobs this mailbox holds named at its own blob endpoint (M§8.4 rule 6).
    fn item_value(&self, it: &Item, cursor: &str) -> Value {
        let mut v = it.to_value(cursor);
        if let Some(manifest) = v.get("blobs").cloned() {
            let stored: Vec<Value> = manifest.as_array().into_iter().flatten()
                .filter_map(|e| e["sha256"].as_str())
                .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) && self.blob_dir.join(h).exists())
                .map(|h| json!(h)).collect();
            v["blobs"] = dsip_messaging::mailbox::items_blobs(&json!({"blob_endpoint": self.blob_endpoint, "stored": stored,
                "manifest": manifest}))["blobs"].clone();
        }
        v
    }

    /// Mailbox emissions of `owner`'s machine → envelopes (M§5.3, M§5.4, M§5.5).
    fn mailbox_out(&mut self, owner: &str, emissions: Vec<Value>, now: i64) -> Vec<Out> {
        let mut out = vec![];
        for e in emissions {
            let (kind, body) = e.as_object().and_then(|m| m.iter().next()).map(|(k, v)| (k.clone(), v.clone())).unwrap_or_default();
            let to = body["to"].as_str().unwrap_or("").to_string();
            match kind.as_str() {
                "accepted" => {
                    let mut extra = json!({});
                    for k in ["cursor", "duplicate", "seq"] {
                        if let Some(v) = body.get(k) {
                            extra[k] = v.clone();
                        }
                    }
                    let env = wire::accepted(&self.key, &to, now, body["in_reply_to"].as_str().unwrap_or(""), extra);
                    out.push(Out::Device(to, env));
                }
                "handover_expired" => {
                    // spec-gap 71: the old hub never delivered its last items; the new hub is admitted regardless and
                    // the owner's devices treat the missing seqs as a gap (M§6.5)
                    tracing::info!("handover wait expired for group {}: admitting the new hub without the old hub {}'s seqs {}",
                        body["group"], body["hub"], body["missing"]);
                }
                "error" => {
                    let mut fields = json!({"reason": body["reason"]});
                    for k in ["in_reply_to", "retry_after"] {
                        if let Some(v) = body.get(k) {
                            fields[k] = v.clone(); // §19.4: policy.rate-limited carries retry_after
                        }
                    }
                    out.push(Out::Device(to.clone(), wire::message(&self.key, "error", &to, now, wire::TTL_S, fields)));
                }
                "items" => {
                    let list: Vec<Value> = body["cursors"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|c| c.as_str())
                        .filter_map(|c| self.owned.get(owner).and_then(|o| o.store.get(c)).map(|it| self.item_value(it, c)))
                        .collect();
                    let env = wire::fit_items(list, body["next"].clone(), |items, next| {
                        wire::items(&self.key, &to, now, body["in_reply_to"].as_str(), items, next)
                    });
                    out.push(Out::Device(to, env));
                }
                "push" => {
                    if let Some(c) = body["cursor"].as_str() {
                        if let Some(it) = self.owned.get(owner).and_then(|o| o.store.get(c)) {
                            let env = wire::items(&self.key, &to, now, None, vec![self.item_value(it, c)], Value::Null);
                            out.push(Out::Device(to, env));
                        }
                    }
                }
                "key_packages" => {
                    let mut packages = vec![];
                    let mut last_resort = None;
                    for (device, kind) in body["devices"].as_object().into_iter().flatten() {
                        let Some(o) = self.owned.get_mut(owner) else { continue };
                        if let Some(bytes) = o.store.take_key_package(device, kind.as_str().unwrap_or("")) {
                            if kind == "last-resort" {
                                last_resort = Some(bytes);
                            } else {
                                packages.push(json!(bytes));
                            }
                        }
                    }
                    let mut fields = json!({"in_reply_to": body["in_reply_to"], "subject": owner, "key_packages": packages});
                    if let Some(lr) = last_resort {
                        fields["last_resort"] = json!(lr);
                    }
                    out.push(Out::Device(to.clone(), wire::message(&self.key, "key-packages", &to, now, wire::TTL_S, fields)));
                }
                _ => {}
            }
        }
        out
    }

    /// Hub emissions → envelopes, with fan-out routed locally or federated (M§6.5 rule 5).
    fn hub_out(&mut self, group: &str, emissions: Vec<Value>, now: i64) -> Vec<Out> {
        let mut out = vec![];
        let batch_seq = emissions.iter().find_map(|e| e.get("accepted").and_then(|a| a.get("seq")).and_then(Value::as_i64));
        for e in emissions {
            let (kind, body) = e.as_object().and_then(|m| m.iter().next()).map(|(k, v)| (k.clone(), v.clone())).unwrap_or_default();
            let to = body["to"].as_str().unwrap_or("").to_string();
            match kind.as_str() {
                "accepted" => {
                    let mut extra = json!({"group": group});
                    for k in ["seq", "duplicate"] {
                        if let Some(v) = body.get(k) {
                            extra[k] = v.clone();
                        }
                    }
                    out.push(Out::Device(to.clone(), wire::accepted(&self.key, &to, now, body["in_reply_to"].as_str().unwrap_or(""), extra)));
                }
                "error" => {
                    let env = wire::error(&self.key, &to, now, body["in_reply_to"].as_str(), body["reason"].as_str().unwrap_or(""), None);
                    out.push(Out::Device(to, env));
                }
                "fanout" if body["class"] == "welcome" => {
                    // M§6.5 rule 5, M§14.2: the welcome the commit carried, with the grants and the
                    // committer's own deposit as `origin`, so the new member's mailbox can verify the adder.
                    let seq = body["seq"].as_i64().or(batch_seq);
                    let Some(item) = seq.and_then(|s| self.fanout.get(&(group.to_string(), s)).cloned()) else { continue };
                    let Some(welcome) = item.welcome else { continue };
                    let mut fields = json!({"recipient": to, "mls": welcome,
                        "hub": self.conversations.get(group).map(|c| c["hub"].clone()).unwrap_or(Value::Null)});
                    if let Some(pred) = self.conversations.get(group).and_then(|c| c["successor_of"].as_str()) {
                        fields["successor_of"] = json!(pred); // M§7.5: admitted by the member mailbox without a grant
                    }
                    if let Some(g) = item.grants {
                        fields["grants"] = g;
                    }
                    if let Some(o) = item.origin {
                        fields["origin"] = json!(o);
                    }
                    if let Some(s) = seq {
                        // spec-gap 83: the adding commit's seq — where the new member starts counting the group
                        fields["seq"] = json!(s);
                    }
                    let env = wire::deposit(&self.key, "", now, group, "welcome", fields);
                    if let (Some(id), Some(seq)) = (wire::payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)), seq) {
                        self.welcomes_sent.insert(id, (group.to_string(), to.clone(), seq));
                    }
                    out.push(Out::Identity(to, env));
                }
                "forward" if body["class"] == "ephemeral" => {
                    // M§11.2: never stored, no seq, no accepted; the envelope never outlives the originating
                    // deposit (spec-gap 49), so an expired activity is dropped here.
                    let Some(item) = self.fanout.get(&(group.to_string(), -1)).cloned() else { continue };
                    let (Some(sealed), Some(exp)) = (item.sealed, item.expires_at) else { continue };
                    if exp <= now {
                        continue;
                    }
                    let fields = json!({"recipient": to, "group": group, "class": "ephemeral", "sealed": sealed});
                    out.push(Out::Identity(to, wire::message(&self.key, "deposit", "", now, exp - now, fields)));
                }
                "fanout" | "forward" => {
                    let class = body["class"].as_str().unwrap_or("application").to_string();
                    let seq = body["seq"].as_i64();
                    let item = match seq.and_then(|s| self.fanout.get(&(group.to_string(), s)).cloned()) {
                        Some(i) => i,
                        None => match self.fanout.get(&(group.to_string(), -1)).cloned() {
                            Some(i) => i, // group-info and ephemeral: the latest deposit of that class
                            None => continue,
                        },
                    };
                    let mut fields = json!({"recipient": to, "class": class});
                    if let Some(s) = seq {
                        fields["seq"] = json!(s);
                    }
                    for (k, v) in [("mls", &item.mls), ("archive", &item.archive)] {
                        if let Some(s) = v {
                            fields[k] = json!(s);
                        }
                    }
                    if let Some(h) = &item.hub {
                        fields["hub"] = h.clone();
                    }
                    if let Some(b) = &item.blobs {
                        fields["blobs"] = b.clone();
                    }
                    out.push(Out::Identity(to, wire::deposit(&self.key, "", now, group, &class, fields)));
                }
                _ => {}
            }
        }
        out
    }

    /// Ephemeral pushes (no cursor) become `items` carrying the sealed activity and its originating expiry.
    ///
    /// Spec: M§11.2. Impl (spec-gap 49): the pushed item is `{class, group, source, sealed, expires_at}`.
    fn ephemeral_pushes(&self, emissions: &[Value], dep: &Value, source: &str, now: i64) -> Vec<Out> {
        let exp = dep["expires_at"].as_i64().unwrap_or(0);
        let Some(sealed) = dep["sealed"].as_str() else { return vec![] };
        emissions
            .iter()
            .filter_map(|e| e.get("push"))
            .filter(|p| p["class"] == "ephemeral" && exp > now)
            .map(|p| {
                let to = p["to"].as_str().unwrap_or("").to_string();
                let item = json!({"class": "ephemeral", "group": dep["group"], "source": source, "sealed": sealed, "expires_at": exp});
                let env = wire::message(&self.key, "items", &to, now, exp - now, json!({"items": [item], "next": null}));
                Out::Device(to, env)
            })
            .collect()
    }

    /// Record the payload behind whatever cursor `owner`'s machine just assigned.
    fn absorb(&mut self, owner: &str, emissions: &[Value], item: Item) {
        for e in emissions {
            if let Some(c) = e.get("accepted").and_then(|a| a.get("cursor")).and_then(Value::as_str) {
                if e["accepted"]["duplicate"] != json!(true) {
                    if item.class == "application" {
                        // M§8.4 rule 6: the blobs this item references are replicated after it is stored
                        let blobs = item.blobs.as_ref().and_then(Value::as_array).into_iter().flatten().cloned();
                        self.replicate.extend(blobs.map(|b| (owner.to_string(), b)));
                    }
                    let class = item.class.clone();
                    if let Some(o) = self.owned.get_mut(owner) {
                        o.store.put(c, item.clone());
                    }
                    let Service { wakes, key, .. } = self;
                    if let Some(w) = wakes.as_mut() {
                        w.store(now_s(), owner, &class, key); // W§5.1: `message`, coalesced, never for `ephemeral`
                    }
                }
                return;
            }
        }
    }
}

/// The kinds a mailbox sends. Spec: W§4.4, W§5.1
const WAKE_KINDS: [&str; 1] = ["message"];

/// The `type` a frame's payload claims, before it is verified (to choose the verification path).
fn claimed_type(frame: &str) -> Option<String> {
    Envelope::from_frame(frame).ok().and_then(|e| wire::payload_of(&e)).and_then(|p| p["type"].as_str().map(String::from))
}

impl Service {
    /// A `wake-register` from bound `device` of `identity` (W§4.2): verified by stages 1–11 (the Messaging Profile's
    /// message rules do not apply to it), then as an owner operation (M§4.1; spec-gap 176), then the profile's checks
    /// by [`Wakes::register`]; answered `wake-accepted` or a signed `error`. Returns the frames for this connection.
    fn wake_register(&mut self, frame: &str, device: &str, identity: &str, resolver: &Documents, now: i64) -> Vec<String> {
        let verdict = {
            let ctx = ctx_of(resolver, &self.seen, &self.supported, &self.revocations);
            Envelope::from_frame(frame).and_then(|env| envelope::verify(&env, &ctx, Some(frame)))
        };
        let verified = match verdict {
            Ok(v) => v,
            Err(v) => {
                let code = v.code.and_then(|c| serde_json::to_value(c).ok()).and_then(|c| c.as_str().map(String::from)).unwrap_or_default();
                tracing::info!("refused wake-register from {device}: {code}");
                let env = wire::error(&self.key, device, now, None, v.reason.unwrap_or("transport.routing-refused"), Some(&code));
                return vec![env.frame()];
            }
        };
        let p = &verified.payload;
        let id = p["id"].as_str().unwrap_or("").to_string();
        self.seen.insert(&id, now, now);
        self.stats.frame_in("wake-register");
        if verified.signer_did != device || p["to"] != self.key.did().as_str() {
            let env = wire::error(&self.key, device, now, Some(&id), "transport.routing-refused", Some("wake-register is from the bound device to this mailbox"));
            return vec![env.frame()];
        }
        if let Some(refused) = self.owner_op(identity, device, &id, now) {
            return refused.into_iter().map(|o| match o { Out::Device(_, e) | Out::Identity(_, e) => e.frame() }).collect();
        }
        let did = self.key.did();
        let Some(w) = self.wakes.as_mut() else { return vec![] };
        let env = match w.register(p, device, identity, &did, now) {
            Ok(()) => envelope::sign(&dsip_wake::accepted_message(&did, device, &id, None, now), &self.key, &self.key.kid()),
            Err(reason) => wire::error(&self.key, device, now, Some(&id), reason, None),
        };
        vec![env.frame()]
    }
}

/// Verify a hub-forwarded welcome's `origin`: the adder device's signed `handshake` deposit, with its
/// delegation (M§14.2). Returns what the mailbox machine checks: identity, group, `issued_at`.
fn origin_of(compact: &str, ctx: &Context) -> Option<Value> {
    let mut parts = compact.split('.');
    let env = Envelope {
        protected: parts.next()?.to_string(),
        payload: parts.next()?.to_string(),
        signature: parts.next()?.to_string(),
    };
    // Verified as a credential: it is presented after its own delivery, so the replay window does not apply;
    // the machine bounds its age against the hub deposit instead.
    let ver = envelope::verify_raw(&env, ctx, false).ok()?;
    let p = &ver.payload;
    if p["type"] != "deposit" || p["class"] != "handshake" {
        return None;
    }
    let identity = delegated_identity(&ver, ctx)?;
    Some(json!({"identity": identity, "group": p["group"], "issued_at": p["issued_at"]}))
}

fn grant_payload(compact: &str, ctx: &Context) -> Option<Value> {
    crate::verify::grant_credential(compact, ctx)
}

/// Verify the signed envelope a first-contact deposit carries, fresh at deposit time (§19.4 pipeline: signature,
/// delegation binding, introduction validity, expiry, ULID), and the profile's introduction rules (M§14.1).
/// Returns `(sender identity, recipient, expires_at)`.
fn first_contact_envelope(kind: &str, compact: &str, ctx: &Context) -> std::result::Result<(String, String, i64, Option<String>), String> {
    let mut parts = compact.split('.');
    let mut next = || parts.next().unwrap_or("").to_string();
    let env = Envelope { protected: next(), payload: next(), signature: next() };
    let ver = envelope::verify(&env, ctx, None).map_err(|v| format!("{:?}", v.code))?;
    let p = &ver.payload;
    if p["type"] != kind {
        return Err(format!("carried {} is not a {kind}", p["type"]));
    }
    if kind == "introduction" {
        let v = dsip_messaging::first_contact::check_introduction(p);
        if v["verdict"] != "accept" {
            return Err(v["code"].as_str().unwrap_or("introduction").to_string());
        }
    }
    // a grant names the introduction it answers in `session` (§19.4): what makes it solicited (spec-gap 81)
    let answers = (kind == "grant").then(|| p["session"].as_str().map(String::from)).flatten();
    Ok((ver.identity.clone(), p["to"].as_str().unwrap_or("").to_string(), p["expires_at"].as_i64().unwrap_or(0), answers))
}

/// How a mailbox service behaves. The defaults are the binary's.
#[derive(Debug, Clone)]
pub struct MailboxConfig {
    /// State directory: the service key, the saved state, blobs.
    pub state: PathBuf,
    /// Identities this mailbox serves (their DID documents, or their reachability hints, name this service).
    pub owners: Vec<String>,
    /// Serve up to this many further identities that enrol by binding with a verified `hello` (spec-gap 115).
    pub serve_any: Option<usize>,
    /// Hints nodes (`https://host:port`) asked for the `DSIPMailbox` hint of a member identity with no DID document
    /// (M§4.2).
    pub hints_nodes: Vec<String>,
    /// DID document files, re-read when resolving.
    pub resolver_files: Vec<PathBuf>,
    /// Fetch `did:web` documents over HTTPS (§7.2, §8.1), after [`MailboxConfig::resolver_files`]. `None`: only the
    /// files (and `did:key`) verify.
    pub did_web: Option<Arc<WebDocuments>>,
    /// Trust anchor for dialling peer mailboxes.
    pub ca: Option<PathBuf>,
    /// Admit policy (M§5.7): `grant` or `open`.
    pub admit: String,
    /// Introductions (and grants) allowed per sender identity and per recipient inbox within `intro_window` (§19.4).
    pub intro_limit: usize,
    /// Rate-limit window for introductions, seconds (§19.4).
    pub intro_window: i64,
    /// Introductions held per recipient inbox (§19.4).
    pub inbox_cap: usize,
    /// Largest blob accepted, bytes (M§4.3 `max_blob_bytes`).
    pub max_blob_bytes: i64,
    /// Each owner's storage quota, bytes (M§4.3 `quota_bytes`; spec-gap 99).
    pub quota_bytes: i64,
    /// How long a moved group's new hub is held off while the old hub's last items are missing, seconds (M§7.4;
    /// spec-gap 71).
    pub handover_wait: i64,
    /// How long a hub keeps fanning out to a member identity that acknowledges nothing, seconds (M§4.4
    /// `mls_retention_s`; spec-gap 119).
    pub mls_retention: i64,
    /// End an enrolled identity's enrolment once none of its devices has bound within `mls_retention` (M§4.1;
    /// spec-gap 130).
    pub release_idle: bool,
    /// Fault injection for demos: never deliver hub fan-out to this peer mailbox.
    pub drop_fanout_to: Option<String>,
    /// The advertised `https://…/blobs` (M§4.3; [`blob_endpoint`]).
    pub blob_endpoint: String,
    /// Wake sleeping devices through their push gateways (Wake Profile, draft): `wake-register` is answered, the
    /// service advertises `wake` in its `hello`, and an item stored for an identity wakes its devices. `None`: neither.
    pub wake: Option<WakeConfig>,
}

impl MailboxConfig {
    /// The binary's defaults, keeping state in `state` and advertising `blob_endpoint`.
    pub fn new(state: PathBuf, blob_endpoint: String) -> MailboxConfig {
        MailboxConfig {
            state,
            owners: vec![],
            serve_any: None,
            hints_nodes: vec![],
            resolver_files: vec![],
            did_web: None,
            ca: None,
            admit: "grant".into(),
            intro_limit: 5,
            intro_window: 3600,
            inbox_cap: 16,
            max_blob_bytes: 16_777_216,
            quota_bytes: 10_737_418_240,
            handover_wait: dsip_messaging::mailbox::HANDOVER_WAIT_S,
            mls_retention: dsip_messaging::hub::MLS_RETENTION_S,
            release_idle: false,
            drop_fanout_to: None,
            blob_endpoint,
            wake: None,
        }
    }
}

/// Why a mailbox could not start, or a connection ended.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Reading or writing the state directory, or a socket, failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON that does not parse.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The WebSocket failed.
    #[error("websocket: {0}")]
    Ws(Box<tokio_tungstenite::tungstenite::Error>),
    /// Dialling a peer mailbox failed.
    #[error(transparent)]
    Transport(#[from] dsip_transport::Error),
    /// A blob fetch or its client failed.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    /// The configuration cannot serve anyone.
    #[error("{0}")]
    Config(&'static str),
    /// Saved state that does not load.
    #[error("{what}: {why}")]
    State {
        /// What was being loaded.
        what: String,
        /// Why it failed.
        why: String,
    },
    /// A connection closed before its `hello`, or sent something else first.
    #[error("no hello")]
    NoHello,
    /// The first envelope verified but was not a `hello`.
    #[error("first envelope was {0}")]
    NotHello(String),
    /// The `hello` did not verify.
    #[error("hello rejected: {0}")]
    HelloRejected(String),
    /// No mailbox could be found for a member identity (M§4.2).
    #[error("no mailbox found for {0}")]
    NoMailbox(String),
    /// Fan-out to a peer was dropped by fault injection.
    #[error("fan-out dropped")]
    FanoutDropped,
    /// A peer mailbox answered as another service.
    #[error("peer mailbox is {got} not {expected}")]
    WrongPeer {
        /// The DID it was dialled as.
        expected: String,
        /// The DID that answered.
        got: String,
    },
}

impl From<tokio_tungstenite::tungstenite::Error> for Error {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Error {
        Error::Ws(Box::new(e))
    }
}

/// A mailbox result.
pub type Result<T> = std::result::Result<T, Error>;

fn bad(what: &str, why: impl std::fmt::Display) -> Error {
    Error::State { what: what.into(), why: why.to_string() }
}

/// A mailbox and hub service: the state every connection shares. Cheap to clone; clones share it.
#[derive(Clone)]
pub struct MailboxServer {
    service: Arc<Mutex<Service>>,
    did: String,
    /// The wakes to send, taken by the sender task [`MailboxServer::spawn_tasks`] starts.
    wake_rx: Arc<std::sync::Mutex<Option<mpsc::UnboundedReceiver<Outgoing>>>>,
}

impl MailboxServer {
    /// Open the service in `cfg.state`: its key (made on first use, and its DID written to `service.did`), then the
    /// saved state (spec-gap 59), or a fresh one for the configured owners. Its timers do not run until
    /// [`MailboxServer::spawn_tasks`].
    pub fn open(cfg: MailboxConfig) -> Result<MailboxServer> {
        if cfg.owners.is_empty() && cfg.serve_any.is_none() {
            return Err(Error::Config("a mailbox needs owners and/or serve_any"));
        }
        std::fs::create_dir_all(&cfg.state)?;
        let key_path = cfg.state.join("service.key");
        let key = if key_path.exists() {
            let hex = std::fs::read_to_string(&key_path)?;
            let mut seed = [0u8; 32];
            for (i, c) in hex.trim().as_bytes().chunks(2).enumerate().take(32) {
                seed[i] = std::str::from_utf8(c).ok().and_then(|c| u8::from_str_radix(c, 16).ok())
                    .ok_or_else(|| bad("service.key", "not hex"))?;
            }
            KeyPair::from_seed(seed)
        } else {
            let k = KeyPair::generate();
            std::fs::write(&key_path, k.seed().iter().map(|b| format!("{b:02x}")).collect::<String>())?;
            k
        };
        std::fs::write(cfg.state.join("service.did"), key.did())?;
        let did = key.did();
        let mailbox_ctx = json!({"now": now_s(), "owner": "", "serves": [], "devices": [],
            "admit": cfg.admit, "intro_limit": cfg.intro_limit, "intro_window": cfg.intro_window, "inbox_cap": cfg.inbox_cap,
            "handover_wait": cfg.handover_wait, "quota_bytes": cfg.quota_bytes, "mls_retention_s": cfg.mls_retention});
        let mut st = Service {
            key,
            configured: cfg.owners.clone(),
            serve_any: cfg.serve_any,
            enrolment: Enrolment::new(&json!({"now": now_s(), "configured": cfg.owners, "serve_any": cfg.serve_any.unwrap_or(0),
                "expire_idle": cfg.release_idle, "mls_retention_s": cfg.mls_retention})),
            blob_owners: BTreeMap::new(),
            owned: BTreeMap::new(),
            drop_box: Mailbox::new(&mailbox_ctx),
            mailbox_ctx,
            hints_nodes: cfg.hints_nodes,
            hinted: HashMap::new(),
            resolver_files: cfg.resolver_files,
            web: cfg.did_web,
            ca: cfg.ca,
            seen: SeenIds::default(),
            supported: Supported::all_known(),
            hubs: HashMap::new(),
            views: HashMap::new(),
            fanout: HashMap::new(),
            conversations: HashMap::new(),
            hub_refs: HashMap::new(),
            bound: HashMap::new(),
            standby: HashMap::new(),
            peers: HashMap::new(),
            revocations: vec![],
            blob_dir: cfg.state.join("blobs"),
            blob_endpoint: cfg.blob_endpoint,
            max_blob_bytes: cfg.max_blob_bytes,
            quota_bytes: cfg.quota_bytes,
            state_dir: cfg.state.clone(),
            db: Db::open(&cfg.state.join(DB_FILE)).map_err(|e| bad(DB_FILE, e))?,
            retry: HashMap::new(),
            replicate: vec![],
            replicate_later: vec![],
            welcomes_sent: HashMap::new(),
            drop_fanout_to: cfg.drop_fanout_to,
            release_idle: cfg.release_idle,
            mls_retention: cfg.mls_retention,
            stats: status::Stats::new(now_s()),
            wakes: None,
        };
        let wake_rx = cfg.wake.map(|w| {
            let (w, rx) = Wakes::new(w, now_s());
            st.wakes = Some(w);
            rx
        });
        std::fs::create_dir_all(cfg.state.join("blobs"))?;
        if st.restore()? {
            let items: usize = st.owned.values().map(|o| o.mailbox.snapshot()["items"].as_array().map_or(0, Vec::len)).sum();
            let devices: usize = st.owned.values().map(|o| o.mailbox.devices().len()).sum();
            tracing::info!("restored state: {} owner(s), {items} items, {} hubbed groups, {devices} registered devices",
                st.owned.len(), st.hubs.len());
        } else {
            for id in st.configured.clone() {
                st.ensure_owner(&id);
            }
        }
        Ok(MailboxServer { service: Arc::new(Mutex::new(st)), did, wake_rx: Arc::new(std::sync::Mutex::new(wake_rx)) })
    }

    /// The service's DID: the `from` of its `hello`.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Run the service's clock: re-send unacknowledged fan-out (at once for what was queued before a restart),
    /// release idle enrolments, and retry blob replication. With [`MailboxConfig::wake`] it also starts sending wakes
    /// to gateways, each on its own task (W§5.2).
    pub fn spawn_tasks(&self) -> tokio::task::JoinHandle<()> {
        if let Some(mut rx) = self.wake_rx.lock().ok().and_then(|mut r| r.take()) {
            let service = self.service.clone();
            tokio::spawn(async move {
                while let Some(out) = rx.recv().await {
                    let Some(client) = service.lock().await.wakes.as_ref().map(|w| w.client.clone()) else { return };
                    let service = service.clone();
                    tokio::spawn(async move {
                        if let Some(reason) = dsip_transport::waker::send(&client, &out).await {
                            let mut st = service.lock().await;
                            let Service { wakes, key, .. } = &mut *st;
                            if let Some(w) = wakes.as_mut() {
                                w.answered(&out.device, &reason, key, now_s()); // W§4.3
                            }
                        }
                    });
                }
            });
        }
        let service = self.service.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(RETRY_TICK_S));
            let mut restarted = true; // the first tick runs at once: re-send whatever was queued before we stopped
            loop {
                tick.tick().await;
                let mut st = service.lock().await;
                let now = now_s();
                st.catch_up(now);
                st.retry_fanout(&service, restarted);
                let (due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut st.replicate_later).into_iter().partition(|(_, _, _, at)| *at <= now);
                st.replicate_later = waiting;
                drop(st);
                for (owner, entry, attempt, _) in due {
                    let service = service.clone();
                    tokio::spawn(async move { replicate_blob(service, owner, entry, attempt).await });
                }
                restarted = false;
            }
        })
    }

    /// Serve `GET /status` and `GET /metrics` on `addr`, plain HTTP (keep it on loopback).
    pub fn spawn_status(&self, addr: SocketAddr) -> tokio::task::JoinHandle<()> {
        let service = self.service.clone();
        tokio::spawn(async move {
            if let Err(e) = dsip_transport::status::serve(addr, move |p| status::render(service.clone(), p)).await {
                tracing::warn!("status port {addr}: {e}");
            }
        })
    }

    /// Accept connections on `listener` for ever: TLS, then a WebSocket served as a connection or a blob request.
    pub async fn serve_tls(&self, listener: tokio::net::TcpListener, acceptor: tokio_rustls::TlsAcceptor) -> Result<()> {
        loop {
            let (tcp, peer) = listener.accept().await?;
            let (acceptor, server) = (acceptor.clone(), self.clone());
            tokio::spawn(async move {
                match acceptor.accept(tcp).await {
                    Ok(tls) => {
                        if let Err(e) = server.accept(tls).await {
                            tracing::info!("{peer}: {e}");
                        }
                    }
                    Err(e) => {
                        server.service.lock().await.stats.tls_failed();
                        tracing::info!("{peer}: TLS handshake failed: {e}");
                    }
                }
            });
        }
    }

    /// Serve one connection over `stream` (already through TLS, or an in-process pipe): a WebSocket until it closes,
    /// or one blob request.
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(&self, stream: S) -> Result<()> {
        match http::classify(stream).await? {
            http::First::WebSocket(stream) => serve(stream, self.service.clone()).await,
            http::First::Http(req) => blob_request(req, self.service.clone()).await,
        }
    }
}

/// One blob request: `PUT` authorized by a `blob-put` envelope, or `GET` by hash (M§5.6, M§8.4).
async fn blob_request<S: AsyncRead + AsyncWrite + Unpin>(mut req: http::Request<S>, service: Arc<Mutex<Service>>) -> Result<()> {
    if req.method == "OPTIONS" {
        return Ok(http::preflight(&mut req.stream).await?); // a browser's CORS preflight before a PUT with Authorization
    }
    let Some(sha) = req.path.strip_prefix(http::BLOB_PATH).map(String::from) else {
        return Ok(http::respond(&mut req.stream, 404, "text/plain", b"not found").await?);
    };
    let valid_name = sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    match req.method.as_str() {
        "GET" => {
            let (path, stored) = {
                let st = service.lock().await;
                let path = st.blob_dir.join(&sha);
                (path.clone(), valid_name && path.exists())
            };
            let verdict = dsip_messaging::mailbox::blob_get(&json!({"path_sha256": sha, "stored": if stored { vec![sha.clone()] } else { vec![] }}));
            service.lock().await.stats.blob("GET", if verdict["status"] == 200 { 200 } else { 404 });
            if verdict["status"] == 200 {
                let body = std::fs::read(&path)?;
                http::respond(&mut req.stream, 200, "application/octet-stream", &body).await?;
            } else {
                http::respond(&mut req.stream, 404, "text/plain", b"not found").await?;
            }
            Ok(())
        }
        "PUT" => {
            let now = now_s();
            let credential = req.header("authorization").and_then(|h| h.strip_prefix("DSIP ")).and_then(|compact| {
                let mut parts = compact.trim().split('.');
                Some(Envelope { protected: parts.next()?.to_string(), payload: parts.next()?.to_string(), signature: parts.next()?.to_string() })
            });
            if let Some(env) = &credential {
                fetch_documents(&service, &env.frame()).await;
            }
            // The credential: the full envelope pipeline, the device's delegation, the message rules (M§5.1).
            let (authorization, mbx, stored) = {
                let mut st = service.lock().await;
                let resolver = st.resolver();
                let ctx = ctx_of(&resolver, &st.seen, &st.supported, &st.revocations);
                let auth = credential.as_ref().and_then(|env| {
                    let ver = envelope::verify(env, &ctx, None).ok()?;
                    if ver.msg_type() != "blob-put" || dsip_messaging::checks::check_message(&ver.payload)["verdict"] != "accept" {
                        return None;
                    }
                    let identity = delegated_identity(&ver, &ctx)?;
                    Some(json!({"identity": identity, "payload": ver.payload}))
                });
                if let Some(a) = &auth {
                    let id = a["payload"]["id"].as_str().unwrap_or("").to_string();
                    st.seen.insert(&id, now, now);
                }
                // spec-gap 99: the quota covers stored items and the blobs on disk
                let blob_bytes: i64 = std::fs::read_dir(&st.blob_dir).into_iter().flatten().flatten()
                    .filter_map(|e| e.metadata().ok()).filter(|m| m.is_file()).map(|m| m.len() as i64).sum();
                let identity = auth.as_ref().and_then(|a| a["identity"].as_str()).unwrap_or("");
                let used = st.owned.get(identity).map_or(0, |o| o.mailbox.used_bytes());
                let mbx = json!({"did": st.key.did(), "serves": st.owned.keys().collect::<Vec<_>>(), "max_blob_bytes": st.max_blob_bytes,
                    "quota_bytes": st.quota_bytes, "used_bytes": used + blob_bytes});
                let stored = valid_name && st.blob_dir.join(&sha).exists();
                (auth.unwrap_or(Value::Null), mbx, stored)
            };
            let stored_list = if stored { vec![sha.clone()] } else { vec![] };
            // Decide everything that does not need the body first (413 before reading it).
            let declared = authorization["payload"]["size"].as_i64().unwrap_or(-1);
            let pre = dsip_messaging::mailbox::blob_put(&json!({"mailbox": mbx, "authorization": authorization, "stored": stored_list,
                "request": {"path_sha256": sha, "body_size": authorization["payload"]["size"], "body_sha256": authorization["payload"]["sha256"]}}));
            let verdict = if pre["status"].as_i64().is_some_and(|s| s >= 400) {
                pre
            } else {
                let content_length: i64 = req.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(-1);
                let body = if content_length == declared { http::read_body(&mut req, declared as usize).await? } else { vec![] };
                let body_sha = hex_sha256(&body);
                let v = dsip_messaging::mailbox::blob_put(&json!({"mailbox": mbx, "authorization": authorization, "stored": stored_list,
                    "request": {"path_sha256": sha, "body_size": body.len(), "body_sha256": body_sha}}));
                if v["status"] == 201 {
                    let st = service.lock().await;
                    let tmp = st.blob_dir.join(format!(".{sha}.part"));
                    std::fs::write(&tmp, &body)?;
                    std::fs::rename(&tmp, st.blob_dir.join(&sha))?;
                    tracing::info!("stored blob {sha} ({} bytes) for {}", body.len(), authorization["identity"]);
                }
                v
            };
            let mut st = service.lock().await;
            let to = authorization["payload"]["from"].as_str().unwrap_or("").to_string();
            let status = verdict["status"].as_u64().unwrap_or(500) as u16;
            if verdict.get("accepted").is_some() {
                // spec-gap 130: whose blob it is, so a release deletes it
                if let Some(owner) = authorization["identity"].as_str() {
                    st.blob_owners.entry(sha.clone()).or_default().insert(owner.to_string());
                    st.persist();
                }
            }
            let env = match verdict.get("accepted") {
                Some(a) => {
                    let mut extra = json!({});
                    if a.get("duplicate").is_some() {
                        extra["duplicate"] = json!(true);
                    }
                    wire::accepted(&st.key, &to, now, a["in_reply_to"].as_str().unwrap_or(""), extra)
                }
                None => {
                    tracing::info!("blob PUT {sha} refused: {status} {}", verdict["reason"]);
                    let in_reply_to = authorization["payload"]["id"].as_str();
                    wire::error(&st.key, &to, now, in_reply_to, verdict["reason"].as_str().unwrap_or("policy.blocked"), None)
                }
            };
            st.stats.blob("PUT", status);
            drop(st);
            http::respond(&mut req.stream, status, "application/json", env.frame().as_bytes()).await?;
            Ok(())
        }
        _ => Ok(http::respond(&mut req.stream, 405, "text/plain", b"method not allowed").await?),
    }
}

/// HTTPS trusting the service's `--ca`, read when used (it may be written after startup, as for peer connections).
fn https_client(ca: Option<&std::path::Path>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder().use_rustls_tls().https_only(true);
    if let Some(ca) = ca {
        for cert in reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)? {
            b = b.add_root_certificate(cert);
        }
    }
    Ok(b.build()?)
}

/// Replicate one manifest blob into this mailbox, as the pinned decision says (M§8.4 rule 6, spec-gap 65).
async fn replicate_blob(service: Arc<Mutex<Service>>, owner: String, entry: Value, attempt: i64) {
    let (decision, http, path) = {
        let st = service.lock().await;
        let sha = entry["sha256"].as_str().unwrap_or("").to_string();
        let valid = sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let path = st.blob_dir.join(&sha);
        let stored = if valid && path.exists() { vec![sha] } else { vec![] };
        let mode = st.owned.get(&owner).map_or("sync", |o| o.mailbox.mode()).to_string();
        let d = dsip_messaging::mailbox::blob_replicate(&json!({"mode": mode, "max_blob_bytes": st.max_blob_bytes,
            "stored": stored, "entry": entry, "attempt": attempt}));
        if !valid {
            return;
        }
        (d, https_client(st.ca.as_deref()), path)
    };
    let Ok(http) = http else { return };
    let uri = entry["uri"].as_str().unwrap_or("").to_string();
    if decision["action"] != "fetch" {
        if decision["reason"] != "stored" {
            tracing::info!("not replicating {uri}: {}", decision["reason"]);
        }
        return;
    }
    let fetched = match http.get(&uri).send().await {
        Ok(resp) if resp.status().as_u16() == 200 => match resp.bytes().await {
            Ok(body) => Some(body.to_vec()),
            Err(_) => None,
        },
        Ok(resp) => {
            tracing::info!("replicating {uri}: {}", resp.status());
            None
        }
        Err(e) => {
            tracing::info!("replicating {uri}: {e}");
            None
        }
    };
    let f = match &fetched {
        Some(body) => json!({"status": 200, "sha256": hex_sha256(body), "size": body.len()}),
        None => json!({"status": 0}),
    };
    let d = dsip_messaging::mailbox::blob_replicate(&json!({"entry": entry, "fetched": f, "attempt": attempt}));
    match (d["action"].as_str(), fetched) {
        (Some("store"), Some(body)) => {
            let tmp = path.with_extension("part");
            if std::fs::write(&tmp, &body).and_then(|_| std::fs::rename(&tmp, &path)).is_ok() {
                tracing::info!("replicated blob {} ({} bytes) from {uri}", entry["sha256"].as_str().unwrap_or(""), body.len());
                // spec-gap 130: replicated for this owner, deleted with it
                let mut st = service.lock().await;
                st.blob_owners.entry(entry["sha256"].as_str().unwrap_or("").to_string()).or_default().insert(owner.clone());
                st.persist();
            }
        }
        _ if d["retry"] == json!(true) => {
            // spec-gap 67: the origin had nothing to serve just now; try again, with the fan-out backoff
            let delay = (RETRY_FIRST_S * (1 << (attempt - 1).min(4))).min(RETRY_MAX_S);
            let mut st = service.lock().await;
            st.replicate_later.push((owner.clone(), entry.clone(), attempt + 1, now_s() + delay));
            st.persist();
            tracing::info!("not replicating {uri}: {} (attempt {attempt}, again in {delay}s)", d["reason"]);
        }
        _ => tracing::info!("not replicating {uri}: {}", d["reason"]),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// One client connection: `hello`, then profile messages until it closes (M§4.3).
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(tls: http::Prefixed<S>, service: Arc<Mutex<Service>>) -> Result<()> {
    let mut ws = tokio_tungstenite::accept_async_with_config(tls, Some(dsip_transport::conn::ws_config())).await?;
    let first = match tokio::time::timeout(std::time::Duration::from_secs(HELLO_TIMEOUT_S), ws.next()).await {
        Ok(Some(Ok(WsMessage::Text(t)))) => t.to_string(),
        _ => return Err(Error::NoHello),
    };
    fetch_documents(&service, &first).await;
    let (device, identity, hello_env) = {
        let mut st = service.lock().await;
        let resolver = st.resolver();
        let ctx = ctx_of(&resolver, &st.seen, &st.supported, &st.revocations);
        let inb = match verify_frame(&first, &ctx) {
            Ok(i) => i,
            Err(r) => {
                tracing::info!("hello rejected: {r}");
                // Answered like the service's own hello (core version block), so the client can read why (§13.2).
                let now = now_s();
                // Addressed from the rejected hello's own (unverified) fields: it is only ever sent back on this socket.
                let claimed = Envelope::from_frame(&first).ok().and_then(|e| wire::payload_of(&e)).unwrap_or_default();
                let mut body = json!({"dsip": {"core": "1.0", "min_core": "1.0", "profiles": [], "extensions": [], "critical": []},
                    "type": "error", "id": wire::new_id(now), "from": st.key.did(), "to": claimed["from"],
                    "reason": "transport.hello-rejected", "detail": r.code, "issued_at": now, "expires_at": now + wire::TTL_S});
                if let Some(h) = claimed["id"].as_str() {
                    body["in_reply_to"] = json!(h);
                }
                let env = envelope::sign(&body, &st.key, &st.key.kid());
                drop(st);
                let _ = ws.send(WsMessage::Text(env.frame().into())).await;
                return Err(Error::HelloRejected(r.to_string()));
            }
        };
        if inb.msg_type() != "hello" {
            return Err(Error::NotHello(inb.msg_type().to_string()));
        }
        let (device, identity) = (inb.device().to_string(), inb.identity().to_string());
        let id = inb.payload()["id"].as_str().unwrap_or("").to_string();
        let hub = true;
        let mut caps = wire::mailbox_capabilities(hub, &st.blob_endpoint, st.max_blob_bytes);
        if st.wakes.is_some() {
            // W§4.4: the profile and the kinds this mailbox sends
            caps["wake"] = json!({"profiles": [dsip_wake::PROFILE], "kinds": WAKE_KINDS});
        }
        let env = wire::service_hello(&st.key, &id, now_s(), caps);
        st.seen.insert(&id, now_s(), now_s());
        (device, identity, env)
    };
    ws.send(WsMessage::Text(hello_env.frame().into())).await?;
    tracing::info!("bound {device} (for {identity})");

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    {
        let mut st = service.lock().await;
        st.stats.bound();
        // The clocks move on ticks and frames: bring them to now before the hello, or it is stamped up to a tick early
        // and an enrolment can be released as idle before its retention has run (M§4.1). Before the binding is
        // recorded, so an enrolment that did run out closes only the bindings it had.
        st.catch_up(now_s());
        // A device may hold a second, short-lived connection beside its binding (a KeyPackage fetch at its own mailbox):
        // that connection gets its replies on itself and changes nothing about the binding, its live push included.
        let second = st.bound.get(&device).is_some_and(|t| !t.is_closed());
        if second {
            st.standby.insert(device.clone(), tx.clone());
        } else {
            // Every binding can be pushed to (its replies, and an enrolment later on this connection); only a served
            // identity's device is registered (M§4.4).
            st.bound.insert(device.clone(), tx.clone());
            if let Some(w) = st.wakes.as_mut() {
                w.bound(&device, true); // W§5.1: no wake while bound; the binding restarts the coalescing
            }
            if st.serves(&identity) {
                // M§4.4: a verified hello keeps the identity's device registered, and its enrolment alive (M§4.1)
                st.enrolment.hello(&identity);
                // M§5.4: live push belongs to a connection. A new binding starts not live, whatever an earlier
                // connection of this device asked for, until it syncs live; otherwise a push could jump its cursor past
                // items stored while it was away, which it would then never sync.
                st.ensure_owner(&identity).mailbox.step(&json!({"unbind": {"device": device}}));
                // The owner's registered devices are the ones that have bound (M§4.4), including before a restart.
                st.register(&identity, &device);
            }
        }
        st.persist();
    }

    // The binding ends however the connection does (a clean close, a send error, a dropped socket), so the cleanup
    // below always runs.
    let result: Result<()> = async {
        loop {
            tokio::select! {
                outbound = rx.recv() => match outbound {
                    Some(frame) if frame == CLOSE_SENTINEL => {
                        // The device's delegation was revoked: end the binding now (M§12.4, spec-gap 57).
                        let _ = ws.close(None).await;
                        return Ok(());
                    }
                    Some(frame) => ws.send(WsMessage::Text(frame.into())).await?,
                    None => return Ok(()),
                },
                inbound = ws.next() => match inbound {
                    Some(Ok(WsMessage::Text(t))) => {
                        if is_live_sync(&t) {
                            take_binding(&service, &device, &tx).await;
                        }
                        let replies = handle(&service, t.to_string(), &device, &identity).await;
                        for frame in replies {
                            ws.send(WsMessage::Text(frame.into())).await?;
                        }
                    }
                    Some(Ok(WsMessage::Close(_))) | None => return Ok(()),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e.into()),
                },
            }
        }
    }
    .await;
    let mut st = service.lock().await;
    if st.standby.get(&device).is_some_and(|t| t.same_channel(&tx)) {
        st.standby.remove(&device); // a second connection ending changes nothing about the binding
    } else if st.bound.get(&device).is_some_and(|t| t.same_channel(&tx)) {
        st.bound.remove(&device);
        if let Some(o) = st.owned.get_mut(&identity) {
            o.mailbox.step(&json!({"unbind": {"device": device}}));
        }
        tracing::info!("unbound {device}");
        // a connection that arrived while this one was still open becomes the binding: not live until it syncs (M§5.4)
        if let Some(next) = st.standby.remove(&device).filter(|t| !t.is_closed()) {
            st.bound.insert(device.clone(), next);
            tracing::info!("bound {device} again on its later connection");
        } else if let Some(w) = st.wakes.as_mut() {
            w.bound(&device, false);
        }
    }
    result
}

/// Whether a frame is a `sync` asking for live push (M§5.4). Only the shape is read here; `handle` verifies it.
fn is_live_sync(frame: &str) -> bool {
    Envelope::from_frame(frame).ok().and_then(|e| wire::payload_of(&e)).is_some_and(|p| p["type"] == "sync" && p["live"] == json!(true))
}

/// The connection that syncs live is the device's binding (M§5.4: live push belongs to a connection). A second
/// connection that does so (the device reloaded while its old connection was still closing) takes the binding at
/// once, and the old one becomes the standby, whose end changes nothing. A short-lived second connection that never
/// syncs (a KeyPackage fetch at its own mailbox) stays a standby. Without this, the old connection's end would mark
/// the device not live and hand the binding to a connection that had already synced, which would never be pushed to.
async fn take_binding(service: &Arc<Mutex<Service>>, device: &str, tx: &mpsc::UnboundedSender<String>) {
    let mut st = service.lock().await;
    if !st.standby.get(device).is_some_and(|t| t.same_channel(tx)) {
        return;
    }
    st.standby.remove(device);
    if let Some(old) = st.bound.insert(device.to_string(), tx.clone()).filter(|t| !t.is_closed()) {
        st.standby.insert(device.to_string(), old);
    }
    tracing::info!("bound {device} on its later connection, which synced live");
}

/// Verify one frame and run it through the state machines; returns frames for this connection.
async fn handle(service: &Arc<Mutex<Service>>, frame: String, sender: &str, bound_identity: &str) -> Vec<String> {
    fetch_documents(service, &frame).await;
    let now = now_s();
    let mut st = service.lock().await;
    st.catch_up(now);
    let resolver = st.resolver();
    if st.wakes.is_some() && claimed_type(&frame).as_deref() == Some("wake-register") {
        let replies = st.wake_register(&frame, sender, bound_identity, &resolver, now);
        st.persist();
        return replies;
    }
    let inb = {
        let ctx = ctx_of(&resolver, &st.seen, &st.supported, &st.revocations);
        match verify_frame(&frame, &ctx) {
            Ok(i) => i,
            Err(r) => {
                tracing::info!("refused frame from {sender}: {r}");
                st.stats.refused(r.token(), &r.code);
                let env = wire::error(&st.key, sender, now, None, r.token(), Some(&r.code));
                return vec![env.frame()];
            }
        }
    };
    st.seen.insert(inb.payload()["id"].as_str().unwrap_or(""), now, now);
    let signer = inb.device().to_string();
    st.stats.frame_in(inb.payload()["type"].as_str().unwrap_or(""));
    let outs = dispatch(service, &mut st, &inb, &frame, sender, bound_identity, &resolver, now);
    let envs: Vec<&Envelope> = outs.iter().map(|o| match o { Out::Device(_, e) | Out::Identity(_, e) => e }).collect();
    st.stats.refusals_in(&envs);
    let mut replies = vec![];
    for out in outs {
        match out {
            Out::Device(to, env) => {
                // A forwarded deposit's signer is not bound here: its answer returns on this connection (M§5.2).
                if to == sender || to == signer {
                    replies.push(env.frame());
                } else if let Some(tx) = st.bound.get(&to) {
                    let _ = tx.send(env.frame());
                }
            }
            Out::Identity(identity, env) => federate(service, &mut st, &identity, env),
        }
    }
    for (owner, entry) in std::mem::take(&mut st.replicate) {
        let service = service.clone();
        tokio::spawn(async move { replicate_blob(service, owner, entry, 1).await });
    }
    st.persist();
    replies
}

/// Route one verified message to the right state machine (M§5, M§6.5, M§6.6).
#[allow(clippy::too_many_arguments)]
fn dispatch(
    service: &Arc<Mutex<Service>>,
    st: &mut Service,
    inb: &crate::verify::Inbound,
    frame: &str,
    hello_device: &str,
    bound_identity: &str,
    resolver: &Documents,
    now: i64,
) -> Vec<Out> {
    let p = inb.payload().clone();
    let device = inb.device().to_string();
    // §13.2: a device acts for the identity it bound as, not for the DID that signs each envelope
    // (a profile message's `from` is the device, M§5.1). A deposit forwarded by a mailbox is signed by a
    // device that did not bind here: it acts for the identity its header delegation proves (M§5.1, M§5.2).
    let identity = if device == hello_device {
        bound_identity.to_string()
    } else {
        let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
        delegated_identity(&inb.verified, &ctx).unwrap_or_else(|| device.clone())
    };
    let id = p["id"].as_str().unwrap_or("").to_string();
    match inb.msg_type() {
        "deposit" => {
            let class = p["class"].as_str().unwrap_or("");
            let group = p["group"].as_str().unwrap_or("").to_string();
            let mut item = Item::from_deposit(&p, &device, now);
            if matches!(class, "introduction" | "grant") {
                // First contact (M§14.1, spec-gap 54): a signed introduction or grant for an identity, under §19.4's rules.
                let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
                let (sender, to, expires_at, answers) = match first_contact_envelope(class, p["envelope"].as_str().unwrap_or(""), &ctx) {
                    Ok(v) => v,
                    Err(why) => {
                        tracing::info!("{class} refused: {why}");
                        return vec![Out::Device(device.clone(), wire::error(&st.key, &device, now, Some(&id), "policy.blocked", Some(&why)))];
                    }
                };
                if to != p["recipient"].as_str().unwrap_or("") {
                    return vec![Out::Device(device.clone(), wire::error(&st.key, &device, now, Some(&id), "policy.blocked", Some("recipient is not the envelope's to")))];
                }
                item.expires_at = Some(expires_at);
                let mut event = json!({"first_contact": {"id": id, "from": device, "sender_identity": sender, "recipient": to,
                    "kind": class, "expires_at": expires_at}});
                if let Some(session) = answers {
                    event["first_contact"]["session"] = json!(session);
                }
                // §19.4: the sender's budget is the service's, whoever the recipient is (an introduction for an identity
                // not served here costs the same as one held): the drop box counts every first-contact deposit and
                // refuses `policy.rate-limited` first; the recipient's own machine then holds what it accepts.
                let gate = st.drop_box.step(&event);
                let emissions = if gate.iter().any(|e| e.get("error").is_some()) || !st.serves(&to) {
                    gate
                } else {
                    st.mailbox_for(&to).step(&event)
                };
                for e in &emissions {
                    match (e.get("accepted"), e.get("error")) {
                        (Some(a), _) if a.get("cursor").is_some() => tracing::info!("held {class} from {sender} for {to}"),
                        (Some(_), _) => tracing::info!("{class} from {sender} for {to} accepted, not held"),
                        (_, Some(err)) => tracing::info!("{class} from {sender} refused: {}", err["reason"]),
                        _ => {}
                    }
                }
                st.absorb(&to, &emissions, item);
                return st.mailbox_out(&to, emissions, now);
            }
            let recipient = s_of(&p["recipient"]);
            if class == "welcome" && st.serves(&recipient) {
                let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
                // M§14.2: the deposit carries a grant from each identity it adds; the one for this mailbox is its owner's
                let grant = p["grants"].as_array().into_iter().flatten().filter_map(Value::as_str)
                    .filter_map(|g| grant_payload(g, &ctx)).find(|g| g["from"] == recipient.as_str()).unwrap_or(Value::Null);
                // spec-gap 66: the welcome's own bytes tell a retried delivery from a new invitation
                let w_digest = p["mls"].as_str().and_then(dsip_core::b64::decode).map(|b| digest(&b));
                let mut w = json!({"id": id, "from": device, "adder_identity": identity,
                    "recipient": recipient, "group": group, "hub": p["hub"]["did"], "grant": grant,
                    "successor_of": p["successor_of"], "digest": w_digest, "size": item.stored_bytes()});
                // A service-signed welcome (no delegation) came from a hub: only `origin` names the adder (M§14.2).
                if device == hello_device && bound_identity == device {
                    w["via_hub"] = json!(true);
                    w["issued_at"] = p["issued_at"].clone();
                    w.as_object_mut().expect("object").remove("adder_identity");
                    if let Some(o) = p["origin"].as_str().and_then(|o| origin_of(o, &ctx)) {
                        w["origin"] = o;
                    }
                }
                let before = st.mailbox_for(&recipient).clone();
                let emissions = st.mailbox_for(&recipient).step(&json!({"welcome": w}));
                if let Some(e) = emissions.iter().find_map(|e| e.get("error")) {
                    tracing::info!("welcome for {group} refused: {} (origin {})", e["reason"], w.get("origin").is_some());
                }
                let emissions = st.commit(&recipient, before, emissions, item);
                if emissions.iter().any(|e| e.get("accepted").is_some()) {
                    st.hub_refs.insert(group.clone(), p["hub"].clone());
                }
                return st.mailbox_out(&recipient, emissions, now);
            }
            if class == "archive" {
                // The owner is the depositing device's identity; one not served here is refused by its machine.
                let owner = identity.clone();
                let event = json!({"archive": {"id": id, "device": device, "ref_group": p["ref_group"], "ref_seq": p["ref_seq"],
                    "size": item.stored_bytes()}});
                let before = st.mailbox_for(&owner).clone();
                let emissions = st.mailbox_for(&owner).step(&event);
                let emissions = st.commit(&owner, before, emissions, item);
                return st.mailbox_out(&owner, emissions, now);
            }
            if st.serves(&recipient) {
                // Fan-out from another hub for one of our owners.
                let event = json!({"hub_deposit": {"id": id, "from": identity, "recipient": recipient,
                    "group": group, "seq": p["seq"], "class": class, "expires_at": p["expires_at"], "size": item.stored_bytes()}});
                let before = st.mailbox_for(&recipient).clone();
                let emissions = st.mailbox_for(&recipient).step(&event);
                let mut out = st.ephemeral_pushes(&emissions, &p, &identity, now);
                let emissions = st.commit(&recipient, before, emissions, item);
                if let Some(a) = emissions.iter().find_map(|e| e.get("accepted")) {
                    tracing::info!("stored fan-out {class} seq {} in {group} as {}{}", p["seq"], a["cursor"],
                        if a["duplicate"] == json!(true) { " (duplicate)" } else { "" });
                }
                out.extend(st.mailbox_out(&recipient, emissions, now));
                return out;
            }
            if p["to"].as_str() != Some(st.key.did().as_str()) {
                // Addressed to another service: forward to the group's hub, or refuse (M§5.2, spec-gap 45).
                let owner = identity.clone();
                let event = json!({"forward": {"id": id, "device": device, "identity": identity, "group": group, "to": p["to"]}});
                let emissions = st.mailbox_for(&owner).step(&event);
                if emissions.iter().any(|e| e.get("forward").is_some()) {
                    let uri = st.hub_refs.get(&group).and_then(|h| h["uri"].as_str()).map(String::from);
                    let target = p["to"].as_str().unwrap_or("").to_string();
                    match (uri, Envelope::from_frame(frame)) {
                        (Some(uri), Ok(env)) => {
                            peer_send(service, st, PeerTarget::Service { did: target, uri }, PeerMsg::Forward(env, device.clone()));
                            return vec![];
                        }
                        _ => {
                            // M§9.4 (spec-gap 72): no endpoint for the hub is the same outage as a failed dial
                            let env = wire::error(&st.key, &device, now, Some(&id), "mailbox.hub-unreachable", Some("no endpoint known for the hub"));
                            return vec![Out::Device(device, env)];
                        }
                    }
                }
                return st.mailbox_out(&owner, emissions, now);
            }
            let mut item = item;
            if class == "handshake" {
                item.origin = Envelope::from_frame(frame).ok().map(|e| format!("{}.{}.{}", e.protected, e.payload, e.signature));
            }
            hub_deposit(st, &p, &device, &identity, item, resolver, now)
        }
        "sync" => {
            if let Some(refused) = st.owner_op(&identity, &device, &id, now) {
                return refused;
            }
            let mut e = json!({"id": id, "device": device, "since": p["since"], "live": p["live"] == json!(true)});
            if let Some(a) = p.get("ack_through") {
                e["ack_through"] = a.clone();
            }
            if let Some(l) = p.get("limit") {
                e["limit"] = l.clone();
            }
            let emissions = st.mailbox_for(&identity).step(&json!({"sync": e}));
            let n = emissions.iter().find_map(|e| e["items"]["cursors"].as_array().map(Vec::len)).unwrap_or(0);
            tracing::info!("sync from {device} since {} live={}: {n} items", p["since"], p["live"] == json!(true));
            st.mailbox_out(&identity, emissions, now)
        }
        "key-packages" => {
            if let Some(refused) = st.owner_op(&identity, &device, &id, now) {
                return refused;
            }
            let packages: Vec<String> = p["key_packages"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect();
            let count = packages.len() as i64;
            let last = p["last_resort"].as_str().map(String::from);
            if let Some(o) = st.owned.get_mut(&identity) {
                o.store.add_key_packages(&device, packages, last.clone());
            }
            let event = json!({"kp_upload": {"id": id, "device": device, "count": count, "last_resort": last.is_some()}});
            let emissions = st.mailbox_for(&identity).step(&event);
            st.mailbox_out(&identity, emissions, now)
        }
        "key-package-fetch" => {
            let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
            let grant = p["grant"].as_str().and_then(|g| grant_payload(g, &ctx)).unwrap_or(Value::Null);
            tracing::info!("key-package-fetch from {identity} for {}: grant {}", p["target"],
                if p["grant"].is_null() { "none" } else if grant.is_null() { "presented, does not verify as the target's consent (M§14.2)" } else { "verified" });
            let mut event = json!({"kp_fetch": {"id": id, "from": device, "from_identity": identity,
                "target": p["target"], "grant": grant}});
            if let Some(g) = p.get("successor_of") {
                event["kp_fetch"]["successor_of"] = g.clone(); // M§7.5, spec-gap 61
            }
            let target = s_of(&p["target"]);
            let emissions = st.mailbox_for(&target).step(&event);
            st.mailbox_out(&target, emissions, now)
        }
        "mailbox-config" => {
            if p["release"] == json!(true) && identity != device {
                // M§4.1, M§5.7 (spec-gap 130): accepted, then everything held for the identity is deleted; the other
                // fields are not applied
                let emissions = st.enrolment.release(&identity, &device, &id);
                let out = st.mailbox_out(&identity, emissions.clone(), now);
                if emissions.iter().any(|e| e.get("released").is_some()) {
                    st.end_enrolment(&identity, "owner");
                }
                return out;
            }
            if let Some(refused) = st.owner_op(&identity, &device, &id, now) {
                return refused;
            }
            let mut e = json!({"id": id, "device": device});
            for k in ["mode", "admit", "groups", "revoked_grants", "introductions_sent"] {
                if let Some(v) = p.get(k) {
                    e[k] = v.clone();
                }
            }
            // spec-gap 57: revocations from the owner identity, each signed directly by one of its keys
            let mut revoked_devices = vec![];
            for c in p["revoked_delegations"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                let mut parts = c.split('.');
                let mut next = || parts.next().unwrap_or("").to_string();
                let rev = Envelope { protected: next(), payload: next(), signature: next() };
                let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
                let device_of = envelope::verify_raw(&rev, &ctx, false).ok().and_then(|ver| {
                    let q = &ver.payload;
                    (q["type"] == "delegation-revocation" && q["subject"] == json!(identity) && q["from"] == json!(identity)
                        && ver.signer_did == identity && st.serves(&identity))
                        .then(|| q["device"].as_str().map(String::from))
                        .flatten()
                });
                match device_of {
                    Some(d) => {
                        tracing::info!("delegation of {d} revoked by {identity}");
                        st.revocations.push(rev);
                        revoked_devices.push(d);
                    }
                    None => tracing::info!("revocation refused: not signed by {identity}"),
                }
            }
            if !revoked_devices.is_empty() {
                let Service { wakes, key, .. } = &mut *st;
                if let Some(w) = wakes.as_mut() {
                    for d in &revoked_devices {
                        w.revoked(d, key, now); // W§4.3
                    }
                }
                e["revoked_devices"] = json!(revoked_devices);
            }
            let emissions = st.mailbox_for(&identity).step(&json!({"config": e}));
            if emissions.iter().any(|x| x.get("accepted").is_some()) {
                // M§7.4 (spec-gap 60): a group moved to another hub is forwarded to that hub's endpoint from now on
                for g in p["groups"].as_array().into_iter().flatten() {
                    if let (Some(group), Some(did)) = (g["group"].as_str(), g["hub"].as_str()) {
                        if let Some(uri) = g["hub_uri"].as_str() {
                            st.hub_refs.insert(group.to_string(), json!({"did": did, "uri": uri}));
                        }
                        if g.get("handover_seq").is_some() {
                            tracing::info!("group {group} moved to hub {did} after seq {}", g["handover_seq"]);
                        }
                    }
                }
            }
            for c in emissions.iter().filter_map(|x| x.get("close")) {
                let d = c["device"].as_str().unwrap_or("");
                if let Some(tx) = st.bound.remove(d) {
                    let _ = tx.send(CLOSE_SENTINEL.to_string());
                    tracing::info!("closed the binding of revoked device {d}");
                }
            }
            st.mailbox_out(&identity, emissions, now)
        }
        other => {
            tracing::info!("no handler for {other}");
            vec![]
        }
    }
}

/// One group's hub state as it was before a deposit (M§9.3, spec-gap 99).
struct HubSnapshot {
    hub: Option<Value>,
    view: Option<Vec<u8>>,
    conversation: Option<Value>,
    /// The latest group-info / ephemeral payload (fan-out key `-1`).
    latest: Option<Item>,
}

impl HubSnapshot {
    /// Undo a deposit whose state could not be saved: the hub machine, its public view (a commit is merged into it
    /// on validation), the conversation, and the payload kept for fan-out.
    fn restore(self, st: &mut Service, group: &str, seq: Option<i64>) {
        let g = group.to_string();
        match self.hub.as_ref().and_then(Hub::from_full_state) {
            Some(h) => st.hubs.insert(g.clone(), h),
            None => st.hubs.remove(&g),
        };
        match self.view.as_deref().map(HubView::load) {
            Some(Ok(v)) => st.views.insert(g.clone(), v),
            _ => st.views.remove(&g),
        };
        match self.conversation {
            Some(c) => st.conversations.insert(g.clone(), c),
            None => st.conversations.remove(&g),
        };
        match (seq, self.latest) {
            (Some(s), _) => st.fanout.remove(&(g, s)),
            (None, Some(l)) => st.fanout.insert((g, -1), l),
            (None, None) => st.fanout.remove(&(g, -1)),
        };
    }
}

/// Hub path: bootstrap the public view from a GroupInfo, validate commits, sequence, fan out.
fn hub_deposit(
    st: &mut Service,
    p: &Value,
    device: &str,
    identity: &str,
    item: Item,
    resolver: &Documents,
    now: i64,
) -> Vec<Out> {
    let group = p["group"].as_str().unwrap_or("").to_string();
    let class = p["class"].as_str().unwrap_or("").to_string();
    let id = p["id"].as_str().unwrap_or("").to_string();
    let mls = p["mls"].as_str().unwrap_or("");
    let bytes = dsip_core::b64::decode(mls).unwrap_or_default();
    let ctx = ctx_of(resolver, &st.seen, &st.supported, &st.revocations);
    // Spec: M§9.3 (spec-gap 99) — what a deposit may change here, restored if it cannot be made durable
    let before = HubSnapshot {
        hub: st.hubs.get(&group).map(Hub::full_state),
        view: st.views.get(&group).map(HubView::save),
        conversation: st.conversations.get(&group).cloned(),
        latest: st.fanout.get(&(group.clone(), -1)).cloned(),
    };

    let mut refreshed = None;
    let mut returning = None;
    if class == "group-info" {
        // Bootstrap or refresh the public view (M§6.5 rule 6).
        match HubView::from_group_info(&bytes) {
            Ok(view) if st.hubs.contains_key(&group) => {
                // spec-gap 128: a handover group-info whose GroupInfo names this hub again brings back a group that left;
                // the hub machine gets its epoch and roster (and refuses it unless the group had moved away)
                if let Some(h) = p["handover_seq"].as_i64() {
                    if view.conversation().is_some_and(|c| c["hub"]["did"] == json!(st.key.did())) {
                        returning = Some((h, json!({"epoch": view.epoch(), "roster": view.roster(&ctx).unwrap_or(json!({}))})));
                    }
                }
                refreshed = Some(view); // applied once the hub accepts it
            }
            Ok(view) => {
                let conv = view.conversation().unwrap_or(Value::Null);
                if conv["hub"]["did"] != json!(st.key.did()) {
                    // Impl (spec-gap 60): a hub hosts only a group whose dsip_conversation names it
                    tracing::info!("group-info for {group} names hub {} — not hosting it", conv["hub"]["did"]);
                    let env = wire::error(&st.key, device, now, Some(&id), "mailbox.unknown-group", Some("the group names another hub"));
                    return vec![Out::Device(device.to_string(), env)];
                }
                let roster = view.roster(&ctx).unwrap_or(json!({}));
                let kind = conv["kind"].as_str().unwrap_or("direct");
                // M§7.4 (spec-gap 60): a group moved here continues the numbering its previous hub reached
                let next_seq = p["handover_seq"].as_i64().map_or(1, |h| h + 1);
                let mut ctx_hub = json!({"now": now, "kind": kind, "epoch": view.epoch(), "roster": roster, "next_seq": next_seq,
                    "mls_retention_s": st.mailbox_ctx["mls_retention_s"]});
                if kind == "personal" {
                    // Impl (spec-gap 62): a personal group is hubbed at its owner's mailbox (M§7.1), so the owner — who may
                    // re-join it by external commit with no leaf left (M§6.8) — is the served identity that brought it here
                    ctx_hub["owner"] = json!(identity);
                }
                let hub = Hub::new(&ctx_hub);
                st.hubs.insert(group.clone(), hub);
                tracing::info!("hubbing {kind} group {group} from epoch {} at seq {next_seq}", view.epoch());
                st.conversations.insert(group.clone(), conv);
                st.views.insert(group.clone(), view);
            }
            Err(e) => tracing::info!("group-info refused: {e}"),
        }
    }
    let Some(_) = st.hubs.get_mut(&group) else {
        let env = wire::error(&st.key, device, now, Some(&id), "mailbox.unknown-group", None);
        return vec![Out::Device(device.to_string(), env)];
    };
    let mut deposit = json!({"id": id, "device": device, "identity": identity, "class": class, "digest": digest(&bytes)});
    if let Some((h, view)) = returning {
        deposit["handover_seq"] = json!(h);
        deposit["view"] = view;
    }
    if let Ok((_, epoch, _)) = message_header(&bytes) {
        deposit["epoch"] = json!(epoch);
    }
    if class == "ephemeral" {
        deposit["expires_at"] = p["expires_at"].clone();
        deposit["digest"] = json!(id);
    }
    if class == "handshake" {
        let view = st.views.get_mut(&group);
        let commit = view.map(|v| v.observe_commit(&bytes, &ctx).unwrap_or(json!({"adds": [], "removes": [], "valid": false})));
        if let Some(c) = commit {
            if c.get("adds").is_some() {
                deposit["commit"] = c;
            }
        }
    }
    let hub = st.hubs.get_mut(&group).expect("hub");
    let emissions = hub.step(&json!({"deposit": deposit}));
    if deposit.get("view").is_some() && emissions.iter().any(|e| e.get("accepted").is_some()) {
        tracing::info!("group {group} came back to this hub at seq {} (spec-gap 128)", deposit["handover_seq"].as_i64().unwrap_or(0) + 1);
    }
    if let Some(view) = refreshed.filter(|_| emissions.iter().any(|e| e.get("accepted").is_some())) {
        st.conversations.insert(group.clone(), view.conversation().unwrap_or(Value::Null));
        st.views.insert(group.clone(), view);
    }
    if let Some(c) = deposit.get("commit").filter(|c| c["moves_to"].is_string()) {
        if emissions.iter().any(|e| e.get("accepted").is_some()) {
            tracing::info!("group {group} moves to hub {}: ordered here, refused from now on", c["moves_to"]);
        }
    }
    for e in &emissions {
        if let Some(err) = e.get("error") {
            tracing::info!("hub refused {class} from {identity}: {}", err["reason"]);
        }
    }
    if let Some(seq) = emissions.iter().find_map(|e| e.get("accepted").and_then(|a| a.get("seq"))) {
        tracing::info!("hub sequenced {class} seq {seq} from {identity} in {group}");
    }
    // Remember the payload so the fan-out can carry it: by seq, or as the latest of its class.
    let seq = emissions.iter().find_map(|e| e.get("accepted").and_then(|a| a.get("seq")).and_then(Value::as_i64));
    st.fanout.insert((group.clone(), seq.unwrap_or(-1)), item);
    // M§9.3 (spec-gap 99): a newly accepted item is durable before anyone hears of it — the depositor's `accepted`
    // and the fan-out both wait for the write. If it fails, the deposit is undone and refused, and the sender
    // retries it (M§9.3) as if the hub had been unreachable.
    let stored = emissions.iter().filter_map(|e| e.get("accepted")).any(|a| a["duplicate"] != json!(true));
    if stored && !st.persist() {
        before.restore(st, &group, seq);
        tracing::warn!("refusing {class} {id} from {identity} in {group}: its state could not be saved");
        let fields = json!({"reason": "mailbox.quota-exceeded", "in_reply_to": id, "retry_after": SAVE_RETRY_AFTER_S});
        return vec![Out::Device(device.to_string(), wire::message(&st.key, "error", device, now, wire::TTL_S, fields))];
    }
    // Fan-out to member identities is routed once each one's mailbox is resolved (M§4.2): in-process when that
    // mailbox is this service, federated otherwise ([`peer_task`]).
    st.hub_out(&group, emissions, now)
}

/// Deposit into a member identity's mailbox (M§6.5 rule 5), on the connection kept for that identity; the mailbox is
/// resolved when the connection is dialled: its DID document (M§4.2, authoritative), or for an identity with no
/// document its reachability hint's `DSIPMailbox` endpoint (M§4.2 `did:key`; §8.1 rule 6: a hint, never authority),
/// looked up on the hints nodes (DHT Hints Profile §10). The deposit is addressed to the resolved mailbox there —
/// or, when that mailbox is this service, taken in-process. An identity enrolled here (spec-gap 115) whose hint
/// names another mailbox is reached there: what it advertises decides, not where it once bound.
fn federate(service: &Arc<Mutex<Service>>, st: &mut Service, identity: &str, env: Envelope) {
    peer_send(service, st, PeerTarget::Identity(identity.to_string()), PeerMsg::Fanout(env));
}

/// Where a peer connection goes: a member identity whose mailbox is resolved when dialling, or a service already
/// known by DID and endpoint (the hub a group is registered with, M§6.6).
enum PeerTarget {
    Identity(String),
    Service { did: String, uri: String },
}

impl PeerTarget {
    /// The key the connection is kept under.
    fn key(&self) -> &str {
        match self {
            PeerTarget::Identity(id) => id,
            PeerTarget::Service { did, .. } => did,
        }
    }
}

/// What the mailbox verifies with: its document files, re-read each time (a host may rewrite them), then the
/// `did:web` documents it fetched.
///
/// Spec: §8.1 — the files answer first, as overrides; a fetched document within its TTL next; hints never.
struct Documents {
    files: StaticResolver,
    web: Option<Arc<WebDocuments>>,
}

impl Resolver for Documents {
    fn resolve(&self, did: &str) -> Option<DidDocument> {
        Over(&self.files, self.web.as_deref()).resolve(did)
    }
}

/// Fetch the `did:web` documents `frame` names that the mailbox does not hold, before it is verified under the lock
/// (a fetch must not hold it). Without [`MailboxConfig::did_web`], nothing.
async fn fetch_documents(service: &Arc<Mutex<Service>>, frame: &str) {
    let (web, dids) = {
        let st = service.lock().await;
        let Some(web) = st.web.clone() else { return };
        let dids = web.missing(frame, &st.resolver());
        (web, dids)
    };
    if !dids.is_empty() {
        web.fetch(&dids).await;
    }
}

/// The `DSIPMailbox` entries an identity's DID document lists, if it has one held here.
fn document_mailboxes(identity: &str, resolver: &Documents) -> Option<Vec<Value>> {
    let doc = resolver.resolve(identity)?;
    Some(doc.service.iter().filter(|s| s.service_type == "DSIPMailbox").map(|s| s.service_endpoint.clone()).collect())
}

/// Resolve `identity`'s mailbox to `(mailbox DID, uri)`: the document's entries through the vector-pinned
/// `select_mailbox` (M§4.2); with no document, the hints nodes' records folded by §8.3 (`dsip_dht::record::select`)
/// and their `DSIPMailbox` endpoints offered as `hint_entries`. `None` when nothing usable is found.
async fn resolve_mailbox(service: &Arc<Mutex<Service>>, identity: &str) -> Option<(String, String)> {
    // M§4.2: the identity's own document first, fetched when it is a did:web the files do not hold.
    let web = {
        let st = service.lock().await;
        st.web.clone().filter(|w| w.needs(identity, &st.resolver()))
    };
    if let Some(web) = web {
        web.fetch(&[identity.to_string()]).await;
    }
    let (entries, nodes, ca) = {
        let st = service.lock().await;
        let resolver = st.resolver();
        if let Some(cached) = st.hinted.get(identity).filter(|(_, _, exp)| *exp > now_s()) {
            return Some((cached.0.clone(), cached.1.clone()));
        }
        (document_mailboxes(identity, &resolver), st.hints_nodes.clone(), st.ca.clone())
    };
    let (source, entries) = match entries {
        Some(e) => ("document_entries", e),
        None => {
            // M§4.2: hints only for an identity with no document entry; every node's records through §8.3. A node
            // may be plain http (a local node, or one proxied elsewhere): the records are signed, the transport is not
            // what is trusted (§8.1 rule 6).
            let http = {
                let mut b = reqwest::Client::builder().use_rustls_tls();
                if let Some(ca) = ca.as_deref() {
                    for cert in std::fs::read(ca).ok().and_then(|pem| reqwest::Certificate::from_pem_bundle(&pem).ok()).into_iter().flatten() {
                        b = b.add_root_certificate(cert);
                    }
                }
                b.build().ok()?
            };
            let mut frames: Vec<String> = vec![];
            for n in &nodes {
                let url = format!("{}/dsip/v1/hints/{}", n.trim_end_matches('/'), identity);
                match http.get(&url).send().await {
                    Ok(r) if r.status().as_u16() == 200 => {
                        let v: Value = r.json().await.unwrap_or(Value::Null);
                        for f in v["hints"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                            if !frames.iter().any(|x| x == f) {
                                frames.push(f.to_string());
                            }
                        }
                    }
                    Ok(r) => tracing::info!("hints for {identity} at {n}: {}", r.status()),
                    Err(e) => tracing::info!("hints for {identity} at {n}: {e}"),
                }
            }
            let resolver = StaticResolver::default();
            let ctx = Context::new(now_s(), &resolver);
            let (winner, _) = dsip_dht::record::select(&frames, &ctx);
            let Some(hint) = winner.filter(|h| h.subject == identity) else {
                tracing::info!("no mailbox for {identity}: no document held and no verified hint on {} node(s)", nodes.len());
                return None;
            };
            let entries: Vec<Value> = hint.endpoints.iter().filter(|e| e.service() == "DSIPMailbox")
                .map(|e| { let mut v = json!(e); v.as_object_mut().map(|m| m.remove("service")); v }).collect();
            tracing::info!("hint for {identity}: {} DSIPMailbox endpoint(s), seq {}, signed by {} — a hint, not authority (§8.1)",
                entries.len(), hint.seq, hint.signer);
            let mut st = service.lock().await;
            if let Some(e) = entries.first() {
                st.hinted.insert(identity.to_string(), (s_of(&e["mailbox"]), s_of(&e["uri"]), hint.expires_at.min(now_s() + HINT_REUSE_S)));
            }
            ("hint_entries", entries)
        }
    };
    let choice = select_mailbox(&json!({source: entries}));
    let mailbox_did = choice["selected"].as_str().map(String::from)?;
    let uri = entries.iter().find(|e| e["mailbox"] == json!(mailbox_did)).and_then(|e| e["uri"].as_str()).unwrap_or_default().to_string();
    Some((mailbox_did, uri))
}

/// Send on the connection kept for `target`, dialling it first if needed.
fn peer_send(service: &Arc<Mutex<Service>>, st: &mut Service, target: PeerTarget, msg: PeerMsg) {
    let k = target.key().to_string();
    if st.peers.get(&k).is_none_or(|tx| tx.is_closed()) {
        let (tx, rx) = mpsc::unbounded_channel();
        st.peers.insert(k.clone(), tx);
        let (key, ca, service2, name) = (st.key.clone(), st.ca.clone(), service.clone(), k.clone());
        tokio::spawn(async move {
            if let Err(e) = peer_task(key, ca, target, rx, service2).await {
                tracing::info!("connection for {name} ended: {e}");
            }
        });
    }
    if let Some(tx) = st.peers.get(&k) {
        let _ = tx.send(msg);
    }
}

/// One outbound connection to the mailbox of `identity`: send deposits, feed acceptances back to the hub. When it
/// ends — no mailbox found, a dial that failed, or a connection lost — every deposit a device forwarded through it
/// and the hub never answered is answered `mailbox.hub-unreachable`, so the device keeps it pending (M§9.4,
/// spec-gap 72).
async fn peer_task(
    key: KeyPair,
    ca: Option<PathBuf>,
    target: PeerTarget,
    mut rx: mpsc::UnboundedReceiver<PeerMsg>,
    service: Arc<Mutex<Service>>,
) -> Result<()> {
    // forwarded deposit id → the owner device waiting for the hub's answer (M§5.2)
    let mut forwarded: HashMap<String, String> = HashMap::new();
    let identity = target.key().to_string();
    let resolved = match target {
        PeerTarget::Identity(id) => resolve_mailbox(&service, &id).await,
        PeerTarget::Service { did, uri } => Some((did, uri)),
    };
    let outcome = match resolved {
        Some((mailbox_did, _)) if mailbox_did == key.did() => {
            // The member's mailbox is this service: in-process (M§6.5 rule 5). The resolution is re-done when this
            // task ends: once its reuse bound has passed (spec-gap 116: HINT_REUSE_S from the resolution, however busy
            // the task — a member that moved away keeps sending through its old groups), or at once when this mailbox
            // refuses a delivery for the member (it registered the group elsewhere, or has moved on), so the hub
            // follows the hint.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(HINT_REUSE_S as u64);
            loop {
                let Ok(Some(msg)) = tokio::time::timeout_at(deadline, rx.recv()).await else { break };
                let mut st = service.lock().await;
                match msg {
                    PeerMsg::Fanout(env) => {
                        // Exactly what a remote mailbox would do with this deposit: addressed to this service, verified
                        // as a frame and dispatched — a welcome through M§14.2's authorization, a fan-out into the
                        // member's registration — and the answers read as the peer loop reads them (M§6.5 rule 5).
                        let now = now_s();
                        let mut dep = wire::payload_of(&env).unwrap_or_default();
                        let (group, class, id) = (s_of(&dep["group"]), s_of(&dep["class"]), s_of(&dep["id"]));
                        let seq = dep["seq"].as_i64().unwrap_or(-1);
                        dep["to"] = json!(st.key.did());
                        let env = envelope::sign(&dep, &st.key, &st.key.kid());
                        let frame = env.frame();
                        let resolver = st.resolver();
                        let me = st.key.did();
                        let inb = {
                            let ctx = ctx_of(&resolver, &st.seen, &st.supported, &st.revocations);
                            match verify_frame(&frame, &ctx) {
                                Ok(i) => i,
                                Err(r) => {
                                    tracing::info!("our own fan-out {class} in {group} does not verify: {r}");
                                    continue;
                                }
                            }
                        };
                        st.seen.insert(&id, now, now);
                        let outs = dispatch(&service, &mut st, &inb, &frame, &me, &me, &resolver, now);
                        let mut refused: Option<String> = None;
                        let mut more = vec![];
                        let (replies, rest): (Vec<Out>, Vec<Out>) = outs.into_iter().partition(|o| matches!(o, Out::Device(to, _) if *to == me));
                        for reply in replies {
                            let Out::Device(_, renv) = reply else { continue };
                            let Some(p) = wire::payload_of(&renv) else { continue };
                            if p["type"] == "error" {
                                refused = Some(s_of(&p["reason"]));
                                let queued = if seq >= 0 || class == "welcome" { " (queued, retried)" } else { "" };
                                tracing::info!("our own mailbox refused hub fan-out {class} seq {} in {group}: {}{queued}", dep["seq"], p["reason"]);
                            } else if p["type"] == "accepted" {
                                if p["duplicate"] == json!(true) {
                                    tracing::info!("our own mailbox already had {class} seq {} in {group}", dep["seq"]);
                                }
                                // spec-gap 66: a welcome carries no seq; its acknowledgement is matched by deposit id
                                let welcome_seq = if class == "welcome" { st.welcomes_sent.remove(&id).map(|(_, _, s)| s) } else { None };
                                if let Some(h) = st.hubs.get_mut(&group) {
                                    if let Some(s) = welcome_seq {
                                        more.extend(h.step(&json!({"ack": {"identity": identity, "seq": s, "class": "welcome"}})));
                                    }
                                    if seq >= 0 && class != "welcome" {
                                        more.extend(h.step(&json!({"ack": {"identity": identity, "seq": seq}})));
                                    }
                                }
                            }
                        }
                        let mut outs = rest;
                        outs.extend(st.hub_out(&group, more, now));
                        let (local, rest): (Vec<Out>, Vec<Out>) = outs.into_iter().partition(|o| matches!(o, Out::Device(..)));
                        st.send_local(local);
                        route_identities(&service, &mut st, rest);
                        st.persist();
                        if let Some(r) = refused {
                            // queued at the hub and retried: looked up again first, since the member may be served elsewhere
                            tracing::info!("{identity}'s delivery of {group} refused here ({r}): its mailbox is looked up again at the next delivery");
                            st.hinted.remove(&identity);
                            break;
                        }
                    }
                    PeerMsg::Forward(env, device) => {
                        if let Some(id) = wire::payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)) {
                            forwarded.insert(id, device); // a forward to ourselves cannot arise; answered unreachable below
                        }
                    }
                }
            }
            Ok(())
        }
        Some((mailbox_did, uri)) => {
            let dropped = service.lock().await.drop_fanout_to.as_deref() == Some(mailbox_did.as_str());
            if dropped {
                tracing::info!("dropping fan-out to {mailbox_did} (fault injection: --drop-fanout-to)");
                Err(Error::FanoutDropped)
            } else {
                peer_run(&key, ca, uri, &mailbox_did, &mut rx, &mut forwarded, &service).await
            }
        }
        None => Err(Error::NoMailbox(identity.clone())),
    };
    let mut lost: Vec<(String, String)> = forwarded.drain().collect();
    while let Ok(msg) = rx.try_recv() {
        if let PeerMsg::Forward(env, device) = msg {
            if let Some(id) = wire::payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)) {
                lost.push((id, device));
            }
        }
    }
    if !lost.is_empty() {
        let st = service.lock().await;
        let now = now_s();
        for (id, device) in lost {
            tracing::info!("hub of {identity} unreachable: answering {device}'s deposit {id} mailbox.hub-unreachable");
            if let Some(tx) = st.bound.get(&device) {
                let env = wire::error(&st.key, &device, now, Some(&id), "mailbox.hub-unreachable", Some("the group's hub could not be reached"));
                let _ = tx.send(env.frame());
            }
        }
    }
    outcome
}

/// Deliver hub outs addressed to identities (M§6.5 rule 5): each through its resolved mailbox.
fn route_identities(service: &Arc<Mutex<Service>>, st: &mut Service, outs: Vec<Out>) {
    for out in outs {
        if let Out::Identity(to, env) = out {
            federate(service, st, &to, env);
        }
    }
}

async fn peer_run(
    key: &KeyPair,
    ca: Option<PathBuf>,
    uri: String,
    mailbox_did: &str,
    rx: &mut mpsc::UnboundedReceiver<PeerMsg>,
    forwarded: &mut HashMap<String, String>,
    service: &Arc<Mutex<Service>>,
) -> Result<()> {
    let tls = tls::client_config(ca.as_deref())?;
    let mut seen = SeenIds::default();
    let params = ConnectParams {
        url: uri,
        tls,
        device: key,
        on_behalf_of: None,
        delegations: vec![],
        supported: Supported::all_known(),
    };
    // The resolver is built and dropped inside the call: `&dyn Resolver` is not Send across awaits.
    let mut conn = {
        let resolver = StaticResolver::default();
        Connection::connect(&params, &resolver, &mut seen).await?
    };
    // deposit id → (group, recipient identity, seq): an `accepted` names only what it answers, but the
    // hub's fan-out queue is per identity (M§6.5 rule 5), so the recipient has to be remembered here.
    let mut inflight: HashMap<String, (String, String, i64)> = HashMap::new();
    if conn.relay.did != mailbox_did {
        return Err(Error::WrongPeer { expected: mailbox_did.to_string(), got: conn.relay.did.clone() });
    }
    tracing::info!("federating to {mailbox_did}");
    loop {
        tokio::select! {
            next = rx.recv() => match next {
                Some(PeerMsg::Fanout(env)) => {
                    // The deposit is addressed to the peer mailbox: re-signed with the resolved `to` (M§5.2).
                    let mut env = env;
                    if let Some(mut p) = wire::payload_of(&env) {
                        if let (Some(id), Some(group), Some(to)) =
                            (p["id"].as_str(), p["group"].as_str(), p["recipient"].as_str())
                        {
                            inflight.insert(id.into(), (group.into(), to.into(), p["seq"].as_i64().unwrap_or(-1)));
                        }
                        p["to"] = json!(mailbox_did);
                        env = envelope::sign(&p, key, &key.kid());
                    }
                    conn.send(&env).await?
                }
                Some(PeerMsg::Forward(env, device)) => {
                    if let Some(id) = wire::payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)) {
                        forwarded.insert(id, device);
                    }
                    tracing::info!("forwarding a deposit to hub {mailbox_did}");
                    conn.send(&env).await?
                }
                None => break,
            },
            frame = conn.recv() => match frame? {
                Some(text) => {
                    let Ok(env) = Envelope::from_frame(&text) else { continue };
                    let Some(p) = wire::payload_of(&env) else { continue };
                    if let Some(device) = p["in_reply_to"].as_str().and_then(|id| forwarded.remove(id)) {
                        // The hub's answer to a forwarded deposit, passed through to the device (M§5.2).
                        let st = service.lock().await;
                        if let Some(tx) = st.bound.get(&device) {
                            let _ = tx.send(text.clone());
                        }
                        continue;
                    }
                    if p["type"] == "error" {
                        tracing::info!("{mailbox_did} refused our deposit: {} {}", p["reason"], p["detail"]);
                    }
                    if p["type"] == "accepted" {
                        // spec-gap 66: a welcome carries no seq, so its acknowledgement is matched by deposit id
                        if let Some(id) = p["in_reply_to"].as_str() {
                            let mut st = service.lock().await;
                            if let Some((group, identity, seq)) = st.welcomes_sent.remove(id) {
                                if let Some(hub) = st.hubs.get_mut(&group) {
                                    let more = hub.step(&json!({"ack": {"identity": identity, "seq": seq, "class": "welcome"}}));
                                    let outs = st.hub_out(&group, more, now_s());
                                    route_identities(service, &mut st, outs);
                                }
                                st.persist();
                                continue;
                            }
                        }
                        let Some((group, identity, seq)) = p["in_reply_to"].as_str().and_then(|id| inflight.remove(id)) else {
                            continue;
                        };
                        if seq < 0 {
                            continue; // group-info and ephemeral are not sequenced
                        }
                        let mut st = service.lock().await;
                        if p["duplicate"] == json!(true) {
                            tracing::info!("{mailbox_did} already had seq {seq} in {group}");
                        }
                        if let Some(hub) = st.hubs.get_mut(&group) {
                            let more = hub.step(&json!({"ack": {"identity": identity, "seq": seq}}));
                            // The ack may release the next queued item for that mailbox.
                            let outs = st.hub_out(&group, more, now_s());
                            route_identities(service, &mut st, outs);
                        }
                        st.persist();
                    }
                }
                None => break,
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `n` items of `bytes` each, as `items` carries them (an MLS item's sealed bytes are base64url text).
    fn items_of(n: usize, bytes: usize) -> Vec<Value> {
        (1..=n).map(|i| json!({"cursor": format!("c:{i:016}"), "stored_at": 1_790_000_000, "class": "application",
                               "source": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                               "group": "MDFLNzQyU0cwMEhBWlpDS0MxMzFFQzBQR1M", "seq": i, "mls": "A".repeat(bytes)}))
            .collect()
    }

    fn build(key: &KeyPair) -> impl Fn(Vec<Value>, Value) -> Envelope + '_ {
        move |items, next| wire::items(key, "did:key:z6MktKcVRmk9oMmrUdeCnPAXYKCyhqUMetp3H8WK7CitqnMQ", 1_790_000_000,
                                       Some("01K742SG00NPM1814RWZ3GWQZW"), items, next)
    }

    fn page(env: &Envelope) -> Value {
        wire::payload_of(env).expect("payload")
    }

    /// The phone's case: 54 items, about 830 bytes each, too many for one frame. Spec: M§5.4, §13.2.
    #[test]
    fn a_page_too_big_for_one_frame_is_cut_at_the_cap_and_says_where_to_go_on() {
        let key = KeyPair::generate();
        let items = items_of(54, 830);
        assert!(build(&key)(items.clone(), Value::Null).frame().len() > dsip_core::WS_MAX_ENVELOPE_BYTES, "the whole page must not fit");
        let env = wire::fit_items(items.clone(), Value::Null, build(&key));
        let p = page(&env);
        let k = p["items"].as_array().unwrap().len();
        assert!(env.frame().len() <= dsip_core::WS_MAX_ENVELOPE_BYTES);
        assert!((1..54).contains(&k));
        assert_eq!(p["items"].as_array().unwrap()[..], items[..k], "a prefix, in cursor order");
        assert_eq!(p["next"], items[k - 1]["cursor"], "next is the last cursor sent");
        assert!(build(&key)(items[..=k].to_vec(), Value::Null).frame().len() > dsip_core::WS_MAX_ENVELOPE_BYTES, "the longest prefix");
        assert_eq!(p["in_reply_to"], "01K742SG00NPM1814RWZ3GWQZW");
    }

    /// A page that fits goes as the machine made it, `next` included (a page `limit` cut short).
    #[test]
    fn a_page_that_fits_goes_unchanged() {
        let key = KeyPair::generate();
        let items = items_of(3, 500);
        let p = page(&wire::fit_items(items.clone(), json!("c:0000000000000003"), build(&key)));
        assert_eq!(p["items"].as_array().unwrap()[..], items[..]);
        assert_eq!(p["next"], "c:0000000000000003");
        let p = page(&wire::fit_items(items.clone(), Value::Null, build(&key)));
        assert_eq!(p["next"], Value::Null);
    }
}
