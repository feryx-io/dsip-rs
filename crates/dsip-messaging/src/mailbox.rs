//! The mailbox: durable store, sync and live push, KeyPackage directory, group registration.
//!
//! Spec: M§4.4 (`sync` retains; `queue` deletes once every registered device has acknowledged),
//! M§5.4 (cursors, pagination, live push), M§5.5 (single-use KeyPackages, last resort, per-device
//! bound), M§5.7 (configuration and grant revocation), M§6.6 (pending registration, bound, TTL,
//! hub match), M§11.2 (ephemeral never stored), M§12.2 (archive first-wins, refused in `queue`),
//! M§14.2 (first-contact authorization, `origin` on hub-forwarded welcomes), M§15.5 (unknown recipients),
//! M§5.2 (forwarding an owner device's deposit to its group's hub), M§5.6 and M§8.4 (the blob endpoint —
//! [`blob_put`], [`blob_get`]).
//!
//! Impl: cursors are `c:` plus 16 lowercase hex digits of a per-mailbox counter; a grant is
//! presented already verified (signature checks are the envelope pipeline's job), and so is an `origin`
//! (its identity, group and `issued_at`); forwarding targets and `origin` refusals are spec-gaps 45 and 46.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::checks::MAILBOX_MODES;

/// Maximum one-time KeyPackages kept per device.
///
/// Spec: M§5.5 (RECOMMENDED bound).
pub const KEY_PACKAGES_PER_DEVICE: i64 = 100;

/// Grant scopes that authorize messaging first contact.
///
/// Spec: M§14.2 condition 2.
pub const MESSAGE_GRANT_SCOPES: &[&str] = &["dsip.message", "dsip.invite"];

/// Maximum distance between a hub-forwarded welcome's `origin` and the hub deposit, seconds.
///
/// Spec: M§14.2.
pub const ORIGIN_SKEW_S: i64 = 300;

/// How long a mailbox holds a moved group's new hub off while the old hub's items through `handover_seq` are
/// still missing, seconds, from the `mailbox-config` that named the new hub.
///
/// Spec: M§7.4 (RECOMMENDED 300 s). Impl (spec-gap 71): a mailbox's own choice, `handover_wait` in a vector context.
pub const HANDOVER_WAIT_S: i64 = 300;

/// The hub a group moved from (M§7.4, spec-gap 60) and how far its delivery got (spec-gap 71).
#[derive(Serialize, Deserialize, Clone)]
struct Previous {
    hub: String,
    /// `handover_seq`: the seq the old hub gave the moving commit.
    through: i64,
    /// When the owner's device named the new hub; the wait for the old hub's last items starts here.
    #[serde(default)]
    since: i64,
    /// The group's highest stored seq when the wait expired and the new hub was admitted regardless.
    #[serde(default)]
    released: Option<i64>,
    /// Seqs the old hub delivered after the wait expired, stored out of order.
    #[serde(default)]
    late: Vec<i64>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Group {
    hub: String,
    state: String,
    since: i64,
    items: i64,
    #[serde(default)]
    high_seq: i64,
    /// The hub the group moved from and the seq of the commit that moved it (M§7.4, spec-gap 60).
    #[serde(default)]
    previous: Option<Previous>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Item {
    cursor: String,
    n: i64,
    class: String,
    group: String,
    expires_at: Option<i64>,
    seq: Option<i64>,
    /// Digest of a welcome's MLS bytes, which tells a redelivery from a new invitation (spec-gap 66).
    #[serde(default)]
    digest: Option<String>,
    /// Bytes the deposit declared, counted against the owner's quota (spec-gap 99).
    #[serde(default)]
    size: i64,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct KeyPackages {
    one_time: i64,
    last_resort: bool,
}

/// Mailbox state for one served owner.
#[derive(Clone, Serialize, Deserialize)]
pub struct Mailbox {
    now: i64,
    owner: String,
    serves: BTreeSet<String>,
    devices: Vec<String>,
    mode: String,
    admit: String,
    pending_ttl: i64,
    pending_max: i64,
    /// The owner's quota in bytes (M§4.3 `quota_bytes`); `None` = unlimited (spec-gap 99).
    #[serde(default)]
    quota: Option<i64>,
    #[serde(default = "default_handover_wait")]
    handover_wait: i64,
    groups: BTreeMap<String, Group>,
    kp: BTreeMap<String, KeyPackages>,
    revoked: BTreeSet<String>,
    items: Vec<Item>,
    counter: i64,
    acks: HashMap<String, i64>,
    #[serde(skip)]
    bound: BTreeSet<String>,
    #[serde(with = "archived_index")]
    archived: HashMap<(String, i64), String>,
    intro_limit: usize,
    intro_window: i64,
    inbox_cap: usize,
    intro_log: HashMap<String, Vec<i64>>,
    /// Introductions the owner sent and has no answer for yet (`mailbox-config` `introductions_sent`, spec-gap 81).
    #[serde(default)]
    introductions_sent: Vec<String>,
    /// Cursors stored and dropped since the host last saved them ([`Mailbox::changes`]): not state.
    #[serde(skip)]
    changes: Changes,
}

/// What a host saving item by item needs: the cursors stored and those dropped, in order.
#[derive(Clone, Default)]
struct Changes {
    stored: Vec<String>,
    dropped: Vec<String>,
}

fn default_handover_wait() -> i64 {
    HANDOVER_WAIT_S
}

/// The archive index as a list of `[group, seq, cursor]`: JSON object keys cannot be tuples.
mod archived_index {
    use std::collections::HashMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(m: &HashMap<(String, i64), String>, ser: S) -> Result<S::Ok, S::Error> {
        let mut v: Vec<(&String, i64, &String)> = m.iter().map(|((g, s), c)| (g, *s, c)).collect();
        v.sort();
        v.serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<HashMap<(String, i64), String>, D::Error> {
        Ok(Vec::<(String, i64, String)>::deserialize(de)?.into_iter().map(|(g, s, c)| ((g, s), c)).collect())
    }
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// Cursor text for counter value `n`.
pub fn cursor(n: i64) -> String {
    format!("c:{n:016x}")
}

/// Counter value of a cursor this mailbox format could have issued.
pub fn cursor_num(c: &Value) -> Option<i64> {
    let c = c.as_str()?;
    let hex = c.strip_prefix("c:")?;
    if hex.len() != 16 {
        return None;
    }
    i64::from_str_radix(hex, 16).ok()
}

impl Mailbox {
    /// A mailbox from a vector `context`.
    pub fn new(ctx: &Value) -> Mailbox {
        let now = ctx["now"].as_i64().unwrap_or(0);
        let owner = s(&ctx["owner"]);
        let serves = match ctx["serves"].as_array() {
            Some(a) => a.iter().map(s).collect(),
            None => BTreeSet::from([owner.clone()]),
        };
        let mut devices: Vec<String> = ctx["devices"].as_array().into_iter().flatten().map(s).collect();
        devices.sort();
        let groups = ctx["groups"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(g, r)| (g.clone(), Group { hub: s(&r["hub"]), state: s(&r["state"]), since: now, items: 0, high_seq: 0, previous: None }))
                    .collect()
            })
            .unwrap_or_default();
        let kp = ctx["key_packages"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(d, k)| {
                        let k = KeyPackages {
                            one_time: k["one_time"].as_i64().unwrap_or(0),
                            last_resort: k["last_resort"].as_bool().unwrap_or(false),
                        };
                        (d.clone(), k)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Mailbox {
            now,
            owner,
            serves,
            devices,
            mode: ctx["mode"].as_str().unwrap_or("sync").to_string(),
            admit: ctx["admit"].as_str().unwrap_or("grant").to_string(),
            pending_ttl: ctx["pending_group_ttl"].as_i64().unwrap_or(604_800),
            pending_max: ctx["pending_group_max_items"].as_i64().unwrap_or(500),
            quota: ctx["quota_bytes"].as_i64(),
            handover_wait: ctx["handover_wait"].as_i64().unwrap_or(HANDOVER_WAIT_S),
            groups,
            kp,
            revoked: BTreeSet::new(),
            items: vec![],
            counter: 0,
            acks: HashMap::new(),
            bound: BTreeSet::new(),
            archived: HashMap::new(),
            intro_limit: ctx["intro_limit"].as_u64().unwrap_or(5) as usize,
            intro_window: ctx["intro_window"].as_i64().unwrap_or(3600),
            inbox_cap: ctx["inbox_cap"].as_u64().unwrap_or(16) as usize,
            intro_log: HashMap::new(),
            introductions_sent: Vec::new(),
            changes: Changes::default(),
        }
    }

    /// Everything a mailbox keeps across a restart: items, cursor counter, acknowledgements, registrations (with their
    /// pending age and bound), KeyPackages, revoked grants, the archive index and the first-contact rate window.
    ///
    /// Spec: M§4.4, M§5.4, M§5.5, M§5.7, M§6.6, M§12.2, §19.4. Impl (spec-gap 59): live bindings are not state; a
    /// restarted mailbox pushes nothing until a device syncs live again.
    pub fn full_state(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }

    /// A mailbox restored from [`Mailbox::full_state`], with no live bindings; `None` if the value is not one.
    pub fn from_full_state(v: &Value) -> Option<Mailbox> {
        serde_json::from_value(v.clone()).ok()
    }

    /// The owner's mailbox mode (M§4.4): `sync` or `queue`.
    pub fn mode(&self) -> &str {
        &self.mode
    }

    /// The mailbox's clock, seconds; a host advances it with `advance` events.
    pub fn now(&self) -> i64 {
        self.now
    }

    /// The owner's registered devices.
    pub fn devices(&self) -> &[String] {
        &self.devices
    }

    /// Set the owner's registered devices (M§4.4: those that have completed a verified `hello`
    /// within the retention window). A host calls this as devices bind; vectors set it in `context`.
    pub fn register_devices(&mut self, devices: &[String]) {
        let mut d: Vec<String> = devices.to_vec();
        d.sort();
        d.dedup();
        self.devices = d;
    }

    /// Apply one event and return what the mailbox emits.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        let Some((name, e)) = ev.as_object().and_then(|m| m.iter().next()) else { return vec![] };
        match name.as_str() {
            "advance" => self.advance(e.as_i64().unwrap_or(0)),
            "welcome" => self.welcome(e),
            "forward" => self.forward(e),
            "forward_failed" => {
                // M§9.4 (spec-gap 72): a forwarded deposit the mailbox could not hand to the hub (connection refused
                // or lost) is answered mailbox.hub-unreachable, so the device keeps it pending and retries
                Self::error(&e["device"], &e["id"], "mailbox.hub-unreachable")
            }
            "first_contact" => self.first_contact(e),
            "hub_deposit" => self.hub_deposit(e),
            "sync" => self.sync(e),
            "unbind" => {
                self.bound.remove(&s(&e["device"]));
                vec![]
            }
            "config" => self.config(e),
            "archive" => self.archive(e),
            "kp_upload" => self.kp_upload(e),
            "kp_fetch" => self.kp_fetch(e),
            "restart" => {
                // spec-gap 59: everything durable survives; live bindings are connections and do not
                if let Some(m) = Mailbox::from_full_state(&self.full_state()) {
                    *self = m;
                }
                vec![]
            }
            _ => vec![],
        }
    }

    fn error(to: &Value, id: &Value, reason: &str) -> Vec<Value> {
        vec![json!({"error": {"to": to, "in_reply_to": id, "reason": reason}})]
    }

    fn grant_ok(&self, grant: &Value, grantee: &str, target: &str) -> bool {
        grant.is_object()
            && grant["from"].as_str() == Some(target)
            && grant["to"].as_str() == Some(grantee)
            && grant["scope"].as_array().into_iter().flatten().any(|sc| MESSAGE_GRANT_SCOPES.contains(&sc.as_str().unwrap_or("")))
            && grant["valid_until"].as_i64().unwrap_or(0) > self.now
            && !self.revoked.contains(&s(&grant["id"]))
    }

    /// Keep the items `keep` accepts, noting each dropped cursor for the host ([`Mailbox::changes`]).
    fn drop_items(&mut self, keep: impl Fn(&Item) -> bool) {
        let dropped = &mut self.changes.dropped;
        self.items.retain(|it| {
            let k = keep(it);
            if !k {
                dropped.push(it.cursor.clone());
            }
            k
        });
    }

    /// The cursors stored and those dropped since [`Mailbox::saved`], for a host that saves item by item: its
    /// payload for each cursor lives while the machine holds it (M§5.4). A cursor can be in both.
    ///
    /// Spec: none (infrastructure).
    pub fn changes(&self) -> (&[String], &[String]) {
        (&self.changes.stored, &self.changes.dropped)
    }

    /// The host has saved [`Mailbox::changes`].
    ///
    /// Spec: none (infrastructure).
    pub fn saved(&mut self) {
        self.changes = Changes::default();
    }

    /// Count every item held as stored since the last save: a host writing this machine whole, once.
    ///
    /// Spec: none (infrastructure).
    pub fn all_stored(&mut self) {
        self.changes.stored = self.items.iter().map(|it| it.cursor.clone()).collect();
    }

    /// The machine's record of the item at `cursor`, as [`Mailbox::full_state`] lists it under `items`.
    ///
    /// Spec: none (infrastructure).
    pub fn record(&self, cursor: &str) -> Option<Value> {
        let n = cursor_num(&json!(cursor))?;
        // items are held in the order they were stored, which is cursor order
        let i = self.items.binary_search_by_key(&n, |it| it.n).ok()?;
        serde_json::to_value(&self.items[i]).ok()
    }

    /// [`Mailbox::full_state`] with `items` empty: what a host saving the items one by one ([`Mailbox::record`])
    /// saves for the rest. [`Mailbox::from_full_state`] takes it back with the records put under `items`.
    ///
    /// Spec: none (infrastructure).
    pub fn full_state_without_items(&mut self) -> Value {
        let items = std::mem::take(&mut self.items);
        let v = self.full_state();
        self.items = items;
        v
    }

    /// Bytes held for the owner: the declared sizes of the retained items (spec-gap 99).
    pub fn used_bytes(&self) -> i64 {
        self.items.iter().map(|it| it.size).sum()
    }

    /// Spec: M§4.3 `quota_bytes`, M§4.4, M§14.3. Impl (spec-gap 99): would storing this deposit's declared `size`
    /// take the owner past the quota? Checked after the duplicate checks (a redelivery stores nothing) and before
    /// anything is stored or registered.
    fn over_quota(&self, e: &Value) -> bool {
        self.quota.is_some_and(|q| self.used_bytes() + e["size"].as_i64().unwrap_or(0) > q)
    }

    /// Set the owner's quota (M§4.3 `quota_bytes`; `None` = unlimited). A host applies its configuration after
    /// reloading saved state, which may predate the quota (spec-gap 99).
    pub fn set_quota(&mut self, quota: Option<i64>) {
        self.quota = quota;
    }

    /// Record the declared size on the item just stored.
    fn size_last(&mut self, e: &Value) {
        if let Some(it) = self.items.last_mut() {
            it.size = e["size"].as_i64().unwrap_or(0);
        }
    }

    fn store(&mut self, class: &str, group: &str, depositor: Option<&str>) -> (String, Vec<Value>) {
        if class == "group-info" {
            // M§5.2: latest per group only
            self.drop_items(|it| !(it.group == group && it.class == "group-info"));
        }
        self.counter += 1;
        let c = cursor(self.counter);
        self.items.push(Item { cursor: c.clone(), n: self.counter, class: class.into(), group: group.into(), expires_at: None, seq: None,
            digest: None, size: 0 });
        self.changes.stored.push(c.clone());
        let pushes =
            self.bound.iter().filter(|d| Some(d.as_str()) != depositor).map(|d| json!({"push": {"to": d, "cursor": c}})).collect();
        (c, pushes)
    }

    /// Spec: core §19.4 carried to mailboxes. Impl (spec-gap 54): rate-limited per sender identity and per recipient
    /// inbox; an unknown recipient or a full inbox is accepted without holding (indistinguishable from delivery); held
    /// until the envelope expires.
    fn first_contact(&mut self, e: &Value) -> Vec<Value> {
        let mut keys = vec![format!("sender:{}", s(&e["sender_identity"])), format!("inbox:{}", s(&e["recipient"]))];
        // M§14.1 (spec-gap 81): a grant answering an introduction the owner sent is the reply it asked for — not
        // metered, and the entry is consumed: one introduction, one answer. Any other grant is an unsolicited write
        // into the mailbox and takes the introduction budget below.
        if s(&e["kind"]) == "grant" {
            if let Some(i) = e["session"].as_str().and_then(|id| self.introductions_sent.iter().position(|x| x == id)) {
                self.introductions_sent.remove(i);
                keys.clear();
            }
        }
        let (now, window) = (self.now, self.intro_window);
        for k in &keys {
            let log = self.intro_log.entry(k.clone()).or_default();
            log.retain(|t| *t > now - window);
            if log.len() >= self.intro_limit {
                let retry = log[0] + window - now;
                return vec![json!({"error": {"to": e["from"], "in_reply_to": e["id"], "reason": "policy.rate-limited", "retry_after": retry}})];
            }
        }
        for k in &keys {
            self.intro_log.entry(k.clone()).or_default().push(now);
        }
        let accepted = vec![json!({"accepted": {"to": e["from"], "in_reply_to": e["id"]}})];
        if !self.serves.contains(&s(&e["recipient"])) {
            return accepted;
        }
        let kind = s(&e["kind"]);
        if kind == "introduction" && self.items.iter().filter(|it| it.class == kind).count() >= self.inbox_cap {
            return accepted;
        }
        let (c, pushes) = self.store(&kind, "", None);
        if let Some(it) = self.items.last_mut() {
            it.expires_at = e["expires_at"].as_i64();
        }
        let mut out = vec![json!({"accepted": {"to": e["from"], "in_reply_to": e["id"], "cursor": c}})];
        out.extend(pushes);
        out
    }

    fn advance(&mut self, n: i64) -> Vec<Value> {
        self.now += n;
        let now = self.now;
        self.drop_items(|it| it.expires_at.is_none_or(|t| t > now)); // §19.4: held until the envelope expires (at expires_at, spec-gap 141)
        let expired: Vec<String> = self
            .groups
            .iter()
            .filter(|(_, r)| r.state == "pending" && r.since + self.pending_ttl < self.now)
            .map(|(g, _)| g.clone())
            .collect();
        for g in expired {
            // M§6.6: an unconfirmed pending group is dropped with its items
            self.groups.remove(&g);
            self.drop_items(|it| !(it.group == g && it.class != "archive"));
        }
        vec![]
    }

    fn welcome(&mut self, e: &Value) -> Vec<Value> {
        let recipient = s(&e["recipient"]);
        if !self.serves.contains(&recipient) {
            return Self::error(&e["from"], &e["id"], "transport.unknown-recipient");
        }
        let mut adder = s(&e["adder_identity"]);
        if e["via_hub"].as_bool().unwrap_or(false) {
            // M§14.2 (spec-gap 46): only `origin` proves who added the owner; the hub connection does not. Its age
            // (spec-gap 118): not from the future beyond 300 s of skew, and not older than the pending-group retention —
            // the hub re-signs every retry, so a welcome delivered after an outage carries an origin as old as the outage.
            let o = &e["origin"];
            let age = e["issued_at"].as_i64().unwrap_or(0).saturating_sub(o["issued_at"].as_i64().unwrap_or(i64::MAX / 2));
            if !o.is_object() || o["group"] != e["group"] || age < -ORIGIN_SKEW_S || age > self.pending_ttl {
                return Self::error(&e["from"], &e["id"], "policy.blocked");
            }
            adder = s(&o["identity"]);
        }
        let successor = e.get("successor_of").and_then(Value::as_str).is_some_and(|g| self.groups.contains_key(g));
        let ok = self.admit == "open" || adder == self.owner || self.grant_ok(&e["grant"], &adder, &recipient) || successor;
        if !ok {
            return Self::error(&e["from"], &e["id"], "policy.first-contact-required"); // M§14.2
        }
        let group = s(&e["group"]);
        let now = self.now;
        if let Some(digest) = e["digest"].as_str() {
            // spec-gap 66: the hub retries a welcome it saw no acknowledgement for. A redelivery is the same MLS bytes
            // (M§9.3), not merely another welcome for the group: adding a sibling device sends a new one (M§6.7).
            // Among the welcomes still held for that group: one dropped with an expired pending registration is held no
            // more, and the same bytes for another group are not this group's welcome (spec-gap 94).
            if let Some(it) = self.items.iter().find(|it| it.class == "welcome" && it.group == group && it.digest.as_deref() == Some(digest)) {
                return vec![json!({"accepted": {"to": e["from"], "in_reply_to": e["id"], "cursor": it.cursor, "duplicate": true}})];
            }
        }
        if self.over_quota(e) {
            return Self::error(&e["from"], &e["id"], "mailbox.quota-exceeded");
        }
        self.groups.entry(group.clone()).or_insert_with(|| Group { hub: s(&e["hub"]), state: "pending".into(), since: now, items: 0, high_seq: 0, previous: None });
        let (c, pushes) = self.store("welcome", &group, None);
        if let Some(it) = self.items.last_mut() {
            it.digest = e["digest"].as_str().map(String::from);
        }
        self.size_last(e);
        let mut out = vec![json!({"accepted": {"to": e["from"], "in_reply_to": e["id"], "cursor": c}})];
        out.extend(pushes);
        out
    }

    /// Spec: M§5.2, M§6.6. Impl (spec-gap 45): forward only an owner device's deposit, and only to the
    /// hub registered for its group; nothing is stored.
    fn forward(&mut self, e: &Value) -> Vec<Value> {
        if s(&e["identity"]) != self.owner {
            return Self::error(&e["device"], &e["id"], "policy.blocked");
        }
        match self.groups.get(&s(&e["group"])) {
            Some(r) if e["to"].as_str() == Some(r.hub.as_str()) => vec![json!({"forward": {"to": e["to"], "id": e["id"]}})],
            _ => Self::error(&e["device"], &e["id"], "mailbox.unknown-group"),
        }
    }

    fn hub_deposit(&mut self, e: &Value) -> Vec<Value> {
        if !self.serves.contains(&s(&e["recipient"])) {
            return Self::error(&e["from"], &e["id"], "transport.unknown-recipient");
        }
        let group = s(&e["group"]);
        let from = s(&e["from"]);
        let now = self.now;
        let wait = self.handover_wait;
        let Some(reg) = self.groups.get_mut(&group) else {
            return Self::error(&e["from"], &e["id"], "mailbox.unknown-group"); // M§6.6
        };
        let seq_in = e["seq"].as_i64();
        // An item of the previous hub arriving after the wait for it expired (spec-gap 71): stored out of order.
        let mut late = false;
        let mut out = vec![];
        match &mut reg.previous {
            Some(prev) if prev.hub == from && reg.hub != from => {
                // spec-gap 60: the previous hub still delivers what it ordered, through the commit that moved the group
                let Some(n) = seq_in.filter(|n| *n <= prev.through) else {
                    return Self::error(&e["from"], &e["id"], "mailbox.unknown-group");
                };
                // spec-gap 71: after the wait, what it still delivers at or below handover_seq is stored (the owner's
                // devices fill their gap with it); what was stored before is a redelivery as usual
                late = prev.released.is_some_and(|r| n > r) && !prev.late.contains(&n);
            }
            _ if reg.hub != from => return Self::error(&e["from"], &e["id"], "mailbox.unknown-group"), // M§6.6
            Some(prev) => {
                if reg.high_seq < prev.through && prev.released.is_none() {
                    if now - prev.since < wait {
                        // spec-gap 60: not before the previous hub's items through the move are stored (the new hub retries)
                        return Self::error(&e["from"], &e["id"], "mailbox.unknown-group");
                    }
                    // spec-gap 71: the previous hub did not finish within handover_wait of the owner naming the new one;
                    // the new hub is admitted and the missing seqs are left to the owner's devices (M§6.5 gap handling)
                    prev.released = Some(reg.high_seq);
                    prev.late = vec![];
                    let missing: Vec<i64> = (reg.high_seq + 1..=prev.through).collect();
                    out.push(json!({"handover_expired": {"group": group, "hub": prev.hub, "missing": missing}}));
                }
                if seq_in.is_some_and(|n| n <= prev.through) {
                    // spec-gap 60: numbering continues — and the expiry just noticed is still announced (spec-gap 88)
                    out.extend(Self::error(&e["from"], &e["id"], "policy.blocked"));
                    return out;
                }
            }
            None => {}
        }
        let reg = &self.groups[&group];
        let class = s(&e["class"]);
        if class == "ephemeral" {
            // M§11.2: pushed to bound devices, never stored, never acknowledged; dropped at the
            // originating deposit's expires_at (spec-gap 49)
            if e["expires_at"].as_i64().is_some_and(|t| t <= self.now) {
                return out;
            }
            out.extend(self.bound.iter().map(|d| json!({"push": {"to": d, "class": "ephemeral"}})));
            return out;
        }
        let seq = e["seq"].as_i64();
        if let Some(seq) = seq.filter(|n| *n <= reg.high_seq && !late) {
            // spec-gap 59: a hub retries an unacknowledged fan-out (M§6.5 rule 5) and delivers in seq order, so a seq at
            // or below the group's highest stored is a redelivery: acknowledged as a duplicate, not stored or pushed again
            let mut acc = json!({"to": e["from"], "in_reply_to": e["id"], "duplicate": true});
            // by group and seq, across a registration the owner left and made again; an archive record shares the seq
            // space (its ref_seq) and is never the item (spec-gap 92)
            if let Some(it) = self.items.iter().find(|it| it.group == group && it.seq == Some(seq) && it.class != "archive") {
                acc["cursor"] = json!(it.cursor);
            }
            return vec![json!({"accepted": acc})];
        }
        if reg.state == "pending" && reg.items >= self.pending_max {
            return Self::error(&e["from"], &e["id"], "mailbox.quota-exceeded");
        }
        if self.over_quota(e) {
            out.extend(Self::error(&e["from"], &e["id"], "mailbox.quota-exceeded"));
            return out;
        }
        if let Some(r) = self.groups.get_mut(&group) {
            r.items += 1;
            match (seq, late, &mut r.previous) {
                (Some(n), true, Some(prev)) => prev.late.push(n),
                (Some(n), _, _) => r.high_seq = n,
                _ => {}
            }
        }
        let (c, pushes) = self.store(&class, &group, None);
        if let Some(it) = self.items.last_mut() {
            it.seq = seq;
        }
        self.size_last(e);
        out.push(json!({"accepted": {"to": e["from"], "in_reply_to": e["id"], "cursor": c}}));
        out.extend(pushes);
        out
    }

    fn sync(&mut self, e: &Value) -> Vec<Value> {
        let dev = s(&e["device"]);
        let mut n_since = 0;
        if let Some(since) = e.get("since").filter(|v| !v.is_null()) {
            match cursor_num(since) {
                Some(n) if n <= self.counter => n_since = n,
                _ => return Self::error(&e["device"], &e["id"], "mailbox.cursor-invalid"),
            }
        }
        if let Some(ack) = e.get("ack_through") {
            let Some(n) = cursor_num(ack).filter(|n| *n <= self.counter) else {
                return Self::error(&e["device"], &e["id"], "mailbox.cursor-invalid");
            };
            let a = self.acks.entry(dev.clone()).or_insert(0);
            *a = (*a).max(n);
            if self.mode == "queue" {
                // M§4.4: deleted once every registered device has acknowledged
                let floor = self.devices.iter().map(|d| self.acks.get(d).copied().unwrap_or(0)).min().unwrap_or(0);
                self.drop_items(|it| it.n > floor);
            }
        }
        if e["live"].as_bool().unwrap_or(false) {
            self.bound.insert(dev);
        }
        let limit = e["limit"].as_u64().unwrap_or(200) as usize;
        let avail: Vec<&Item> = self.items.iter().filter(|it| it.n > n_since).collect();
        let page = &avail[..avail.len().min(limit)];
        let next = if avail.len() > limit { json!(page.last().map(|it| it.cursor.clone())) } else { Value::Null };
        let cursors: Vec<&str> = page.iter().map(|it| it.cursor.as_str()).collect();
        vec![json!({"items": {"to": e["device"], "in_reply_to": e["id"], "cursors": cursors, "next": next}})]
    }

    fn config(&mut self, e: &Value) -> Vec<Value> {
        if let Some(mode) = e.get("mode") {
            let m = mode.as_str().unwrap_or("");
            if !MAILBOX_MODES.contains(&m) {
                return Self::error(&e["device"], &e["id"], "mailbox.unsupported-mode");
            }
            self.mode = m.to_string();
        }
        if let Some(a) = e["admit"].as_str() {
            self.admit = a.to_string();
        }
        for g in e["groups"].as_array().into_iter().flatten() {
            let group = s(&g["group"]);
            if g["state"] == "left" {
                self.groups.remove(&group);
            } else if let Some(r) = self.groups.get_mut(&group) {
                r.state = "joined".into();
                if let Some(hub) = g["hub"].as_str().filter(|h| *h != r.hub) {
                    // M§7.4 (spec-gap 60): an owner device that processed the commit moving the group names the new hub
                    // and that commit's seq; the old hub's items through it are still admitted
                    let through = g["handover_seq"].as_i64().unwrap_or(r.high_seq);
                    let hub = std::mem::replace(&mut r.hub, hub.to_string());
                    // spec-gap 71: the wait for the old hub's last items starts here
                    r.previous = Some(Previous { hub, through, since: self.now, released: None, late: vec![] });
                }
            } else if let Some(hub) = g["hub"].as_str() {
                self.groups.insert(group, Group { hub: hub.into(), state: "joined".into(), since: self.now, items: 0, high_seq: 0, previous: None });
            }
        }
        self.revoked.extend(e["revoked_grants"].as_array().into_iter().flatten().map(s));
        for id in e["introductions_sent"].as_array().into_iter().flatten().map(s) {
            if !self.introductions_sent.contains(&id) {
                self.introductions_sent.push(id);
            }
        }
        let mut out = vec![json!({"accepted": {"to": e["device"], "in_reply_to": e["id"]}})];
        for d in e["revoked_devices"].as_array().into_iter().flatten().map(s) {
            // spec-gap 57: a revoked device loses its binding now, its registration and its KeyPackages
            if self.bound.remove(&d) {
                out.push(json!({"close": {"device": d, "reason": "delegation-revoked"}}));
            }
            self.devices.retain(|x| *x != d);
            self.kp.remove(&d);
        }
        out
    }

    fn archive(&mut self, e: &Value) -> Vec<Value> {
        if self.mode == "queue" {
            return Self::error(&e["device"], &e["id"], "mailbox.unsupported-class"); // M§12.2
        }
        let key = (s(&e["ref_group"]), e["ref_seq"].as_i64().unwrap_or(0));
        if let Some(c) = self.archived.get(&key) {
            return vec![json!({"accepted": {"to": e["device"], "in_reply_to": e["id"], "cursor": c, "duplicate": true}})];
        }
        let dev = s(&e["device"]);
        if self.over_quota(e) {
            return Self::error(&e["device"], &e["id"], "mailbox.quota-exceeded");
        }
        let (c, pushes) = self.store("archive", &key.0, Some(&dev));
        self.size_last(e);
        self.archived.insert(key, c.clone());
        let mut out = vec![json!({"accepted": {"to": e["device"], "in_reply_to": e["id"], "cursor": c}})];
        out.extend(pushes);
        out
    }

    fn kp_upload(&mut self, e: &Value) -> Vec<Value> {
        let dev = s(&e["device"]);
        if !self.devices.contains(&dev) {
            return Self::error(&e["device"], &e["id"], "policy.blocked");
        }
        let k = self.kp.entry(dev).or_insert(KeyPackages { one_time: 0, last_resort: false });
        k.one_time = (k.one_time + e["count"].as_i64().unwrap_or(0)).min(KEY_PACKAGES_PER_DEVICE);
        if e["last_resort"].as_bool().unwrap_or(false) {
            k.last_resort = true;
        }
        vec![json!({"accepted": {"to": e["device"], "in_reply_to": e["id"]}})]
    }

    fn kp_fetch(&mut self, e: &Value) -> Vec<Value> {
        let target = s(&e["target"]);
        if !self.serves.contains(&target) {
            return Self::error(&e["from"], &e["id"], "transport.unknown-recipient");
        }
        let who = s(&e["from_identity"]);
        // M§7.5 (spec-gap 61): a registered predecessor authorizes a successor creator's fetch, as it does the welcome
        let successor = e["successor_of"].as_str().is_some_and(|g| self.groups.contains_key(g));
        if !(self.admit == "open" || who == target || successor || self.grant_ok(&e["grant"], &who, &target)) {
            return Self::error(&e["from"], &e["id"], "policy.first-contact-required");
        }
        let mut served = serde_json::Map::new();
        for d in &self.devices {
            // M§5.5: one per device, single use, then the last resort
            match self.kp.get_mut(d) {
                Some(k) if k.one_time > 0 => {
                    k.one_time -= 1;
                    served.insert(d.clone(), json!("one-time"));
                }
                Some(k) if k.last_resort => {
                    served.insert(d.clone(), json!("last-resort"));
                }
                _ => {}
            }
        }
        if served.is_empty() {
            return Self::error(&e["from"], &e["id"], "mailbox.no-key-packages");
        }
        vec![json!({"key_packages": {"to": e["from"], "in_reply_to": e["id"], "devices": served}})]
    }

    /// Snapshot compared by the vectors: stored cursors, group registration states, KeyPackage counts.
    pub fn snapshot(&self) -> Value {
        let groups: serde_json::Map<String, Value> = self.groups.iter().map(|(g, r)| (g.clone(), json!(r.state))).collect();
        let kps: serde_json::Map<String, Value> = self
            .kp
            .iter()
            .map(|(d, k)| (d.clone(), json!({"one_time": k.one_time, "last_resort": k.last_resort})))
            .collect();
        let mut snap = json!({"items": self.items.iter().map(|it| it.cursor.as_str()).collect::<Vec<_>>(), "groups": groups, "key_packages": kps});
        if self.quota.is_some() {
            snap["used_bytes"] = json!(self.used_bytes()); // spec-gap 99
        }
        snap
    }
}

/// Attempts a member mailbox makes at replicating one blob before leaving it at its origin.
///
/// Spec: M§8.4 rule 6 (SHOULD replicate). Impl (spec-gap 67).
pub const BLOB_REPLICATION_ATTEMPTS: i64 = 5;

/// Whether a member mailbox replicates a manifest blob (no `fetched`), and whether it keeps what it fetched.
///
/// Spec: M§8.4 rule 6 — a member mailbox of a `sync`-mode owner SHOULD replicate every manifest blob on receipt,
/// verifying `sha256`. Impl (spec-gap 65): skipped when not `sync`, already stored, over `max_blob_bytes`, or not
/// https; a fetched body is stored only for a 200 matching the manifest's `sha256` and `size`.
pub fn blob_replicate(inp: &Value) -> Value {
    let e = &inp["entry"];
    let Some(f) = inp.get("fetched") else {
        let skip = |reason: &str| json!({"action": "skip", "reason": reason});
        if inp["mode"] != "sync" {
            return skip("mode");
        }
        if inp["stored"].as_array().into_iter().flatten().any(|h| *h == e["sha256"]) {
            return skip("stored");
        }
        if e["size"].as_i64().unwrap_or(i64::MAX) > inp["max_blob_bytes"].as_i64().unwrap_or(0) {
            return skip("too-large");
        }
        if !e["uri"].as_str().unwrap_or("").starts_with("https://") {
            return skip("not-https");
        }
        return json!({"action": "fetch"});
    };
    if f["status"] != 200 {
        // spec-gap 67: the origin was unreachable or had nothing to serve — worth trying again, boundedly
        let attempts = inp["max_attempts"].as_i64().unwrap_or(BLOB_REPLICATION_ATTEMPTS);
        return json!({"action": "discard", "reason": "unavailable", "retry": inp["attempt"].as_i64().unwrap_or(1) < attempts});
    }
    if f["sha256"] != e["sha256"] || f["size"] != e["size"] {
        // the origin served something else: retrying fetches the same wrong bytes
        return json!({"action": "discard", "reason": "mismatch", "retry": false});
    }
    json!({"action": "store"})
}

/// The `items-pages` check: a mailbox holding `input.items` answers a `sync` from `null`, and the device follows each
/// `next` until it is `null`. Each page is what the mailbox service sends: the machine's page by count (`limit`), then
/// [`crate::wire::fit_items`] by bytes, signed with the fixture key `context.mailbox_key`. Reports what every
/// conforming mailbox shares, not where it splits: `{cursors, fit, within_limit, next_chain}`.
///
/// Spec: M§5.4 (every `items` envelope fits the transport cap; spec-gap 180), §13.2 (65,536 bytes).
pub fn items_pages(v: &Value) -> Value {
    let (ctx, inp) = (&v["context"], &v["input"]);
    let key = dsip_core::keys::KeyPair::from_fixture_name(ctx["mailbox_key"].as_str().unwrap_or(""));
    let (device, now) = (ctx["device"].as_str().unwrap_or(""), ctx["now"].as_i64().unwrap_or(0));
    let limit = inp["limit"].as_u64().unwrap_or(200) as usize;
    let sync_id = crate::wire::new_id(now);
    let mut rest: Vec<Value> = inp["items"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|it| {
            let mut o = it.clone();
            let n = o.as_object_mut().and_then(|m| m.remove("mls_bytes")).and_then(|n| n.as_u64()).unwrap_or(0);
            o["mls"] = json!(dsip_core::b64::encode(&vec![0u8; n as usize]));
            o
        })
        .collect();
    let (mut cursors, mut fit, mut within, mut chain) = (vec![], true, true, true);
    loop {
        let k = limit.min(rest.len());
        let next = if rest.len() > k { rest[k - 1]["cursor"].clone() } else { Value::Null };
        let env = crate::wire::fit_items(rest[..k].to_vec(), next, |items, next| {
            crate::wire::items(&key, device, now, Some(&sync_id), items, next)
        });
        fit &= env.frame().len() <= dsip_core::WS_MAX_ENVELOPE_BYTES;
        let p = crate::wire::payload_of(&env).unwrap_or_default();
        let page = p["items"].as_array().cloned().unwrap_or_default();
        within &= page.len() <= limit;
        cursors.extend(page.iter().map(|it| it["cursor"].clone()));
        rest.drain(..page.len().min(rest.len()));
        if p["next"].is_null() {
            chain &= rest.is_empty();
            break;
        }
        chain &= page.last().is_some_and(|l| l["cursor"] == p["next"]);
        if page.is_empty() {
            break;
        }
    }
    json!({"cursors": cursors, "fit": fit, "within_limit": within, "next_chain": chain})
}

/// The `blobs` manifest a mailbox puts in `items`: `uri` at its own blob endpoint for every blob it holds.
///
/// Spec: M§8.4 rule 6 ("rewrite `uri` in `items`"). Impl (spec-gap 65): only held blobs are rewritten.
pub fn items_blobs(inp: &Value) -> Value {
    let endpoint = inp["blob_endpoint"].as_str().unwrap_or("").trim_end_matches('/');
    let stored: Vec<&Value> = inp["stored"].as_array().into_iter().flatten().collect();
    let blobs: Vec<Value> = inp["manifest"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|e| {
            let mut e = e.clone();
            if stored.contains(&&e["sha256"]) {
                e["uri"] = json!(format!("{endpoint}/{}", e["sha256"].as_str().unwrap_or("")));
            }
            e
        })
        .collect();
    json!({"blobs": blobs})
}

/// What a mailbox answers to `PUT {blob_endpoint}/{sha256}`: `{status, reason}` or `{status, accepted}`.
///
/// Spec: M§5.6 (verify the envelope, the device delegated by a served identity, SHA-256 and length of the
/// body; `201` with a signed `accepted`), M§8.4, M§16 (`mailbox.object-too-large` over `max_blob_bytes`).
///
/// Impl (spec-gap 48): the profile names no statuses for refusals and no token for a body that does not
/// match. `authorization` is the verified envelope (`{identity, payload}`) or null; checks run in the order
/// a server can make them — credential (401), addressee and served identity (403), URL bound to the
/// authorized hash (400), declared size before the body is read (413), body (400
/// `mailbox.blob-mismatch`) — and a hash already stored is an idempotent `200` with `duplicate`.
pub fn blob_put(inp: &Value) -> Value {
    let (mbx, req, auth) = (&inp["mailbox"], &inp["request"], &inp["authorization"]);
    if !auth.is_object() {
        return json!({"status": 401, "reason": "policy.blocked"});
    }
    let p = &auth["payload"];
    if p["to"] != mbx["did"] {
        return json!({"status": 403, "reason": "policy.blocked"});
    }
    if !mbx["serves"].as_array().is_some_and(|a| a.contains(&auth["identity"])) {
        return json!({"status": 403, "reason": "transport.unknown-recipient"});
    }
    if req["path_sha256"] != p["sha256"] {
        return json!({"status": 400, "reason": "policy.blocked"});
    }
    if p["size"].as_i64().unwrap_or(i64::MAX) > mbx["max_blob_bytes"].as_i64().unwrap_or(0) {
        return json!({"status": 413, "reason": "mailbox.object-too-large"});
    }
    // Impl (spec-gap 99): the owner's quota, decided from the authorized size before the body is read; a hash already
    // stored stores nothing more and is never refused for quota.
    let stored = inp["stored"].as_array().is_some_and(|a| a.contains(&p["sha256"]));
    if let Some(quota) = mbx["quota_bytes"].as_i64() {
        if !stored && mbx["used_bytes"].as_i64().unwrap_or(0) + p["size"].as_i64().unwrap_or(0) > quota {
            return json!({"status": 507, "reason": "mailbox.quota-exceeded"});
        }
    }
    if req["body_size"] != p["size"] || req["body_sha256"] != p["sha256"] {
        return json!({"status": 400, "reason": "mailbox.blob-mismatch"});
    }
    if inp["stored"].as_array().is_some_and(|a| a.contains(&p["sha256"])) {
        return json!({"status": 200, "accepted": {"in_reply_to": p["id"], "duplicate": true}});
    }
    json!({"status": 201, "accepted": {"in_reply_to": p["id"]}})
}

/// What a mailbox answers to `GET {blob_endpoint}/{sha256}`.
///
/// Spec: M§8.4 rule 5 — the hash is a capability; the mailbox serves what it stored under it.
pub fn blob_get(inp: &Value) -> Value {
    let stored = inp["stored"].as_array().is_some_and(|a| a.contains(&inp["path_sha256"]));
    json!({"status": if stored { 200 } else { 404 }})
}
