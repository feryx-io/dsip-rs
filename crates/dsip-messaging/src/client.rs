//! Client-side rules: voicemail offer, conversation convergence, receipts and activity, seq gaps.
//!
//! Spec: M§13.2 (when a caller may offer voicemail — [`voicemail_offer`]), M§7.2 and M§7.5
//! (duplicate direct conversations and successor groups converge on the lowest ULID —
//! [`select_direct`], [`check_successor`], [`select_successor`]), M§10.2–M§10.5 (identity-level
//! receipts, first-by-seq collapse, monotone read watermarks, privacy routing — [`Client`]),
//! M§11.2 (activity opt-in and refresh bound — [`Client`]), M§6.5 (holding handshake items across
//! a seq gap and re-joining on timeout — [`GapTracker`]), M§5.4 and M§8.5 (what a device keeps
//! durably across a restart — [`Resume`]).
//!
//! Impl: an unregistered `endpoint.*` rejection offers voicemail by category fallback, an
//! unregistered condition in any other category does not; delivered receipts are decided after a
//! whole sync batch; the gap timer starts when the first item is held; delivery state commits atomically with each
//! item and redelivery is recognised by seq (spec-gaps 41, 42, 44).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use dsip_core::registry::REASONS;
use dsip_core::ulid::Ulid;

use crate::checks::{accept, reject, ULID_TOLERANCE_S};

/// The profile a usable mailbox entry must advertise.
///
/// Spec: M§4.2.
pub const MESSAGING_PROFILE: &str = "messaging/1.0";

/// Choose a mailbox from what an identity advertises.
///
/// Spec: M§4.2, §8.1 — DID document entries are authoritative and hints serve only identities with
/// no document entry; an entry is usable when it satisfies the service schema and advertises
/// `messaging/1.0`; order is by `priority` (absent = 0), stable within a priority; the selection is
/// the first usable entry that accepts a connection, and devices sync every usable one.
pub fn select_mailbox(inp: &Value) -> Value {
    let list = |k: &str| -> Vec<Value> { inp[k].as_array().cloned().unwrap_or_default() };
    let (doc, hints) = (list("document_entries"), list("hint_entries"));
    let source = if !doc.is_empty() {
        json!("did-document")
    } else if !hints.is_empty() {
        json!("hint")
    } else {
        Value::Null
    };
    let entries = if doc.is_empty() { hints } else { doc }; // §8.1 rule 6: no falling back past a document
    let (mut usable, mut discarded): (Vec<Value>, Vec<Value>) = (vec![], vec![]);
    for e in entries {
        let advertises = e["profiles"].as_array().is_some_and(|p| p.iter().any(|x| x == MESSAGING_PROFILE));
        if crate::schemas::schema_ok("mailbox-service", &e) && advertises {
            usable.push(e);
        } else {
            discarded.push(e["uri"].clone());
        }
    }
    usable.sort_by_key(|e| e["priority"].as_i64().unwrap_or(0)); // stable
    let order: Vec<Value> = usable.iter().map(|e| e["mailbox"].clone()).collect();
    let reachable = inp["reachable"].as_array();
    let selected = order
        .iter()
        .find(|m| reachable.is_none_or(|r| r.contains(m)))
        .cloned()
        .unwrap_or(Value::Null);
    json!({"source": source, "selected": selected, "order": order, "sync_targets": order, "discarded": discarded})
}

/// Whether an established conversation's mailbox may move to `candidate`.
///
/// Spec: M§4.2, M§15.4 — never on a hint alone.
pub fn mailbox_switch(inp: &Value) -> Value {
    let (established, candidate) = (&inp["established"], &inp["candidate"]);
    if candidate["mailbox"] == established["mailbox"] {
        json!({"switch": false, "reason": "unchanged"})
    } else if candidate["source"] != "did-document" {
        json!({"switch": false, "reason": "hint-sourced"})
    } else {
        json!({"switch": true, "reason": "did-document"})
    }
}

/// Rejection reasons after which a caller may offer voicemail.
///
/// Spec: M§13.2.
pub const VOICEMAIL_REJECT_REASONS: &[&str] = &["user.no-answer", "user.declined", "endpoint.busy", "endpoint.unavailable"];
/// Member-identity count above which delivered receipts are not sent.
///
/// Spec: M§10.2.
pub const DELIVERED_MAX_GROUP: i64 = 32;
/// Maximum targets in one receipt.
///
/// Spec: M§10.2.
pub const RECEIPT_MAX_TARGETS: usize = 256;
/// Minimum interval between read watermarks for one conversation, seconds.
///
/// Spec: M§10.3.
pub const READ_MIN_INTERVAL_S: i64 = 5;
/// Minimum interval between `active` refreshes of one activity, seconds.
///
/// Spec: M§11.2.
pub const ACTIVITY_REFRESH_S: i64 = 5;
/// How long a held item may wait for a seq gap to fill before the device re-joins, seconds.
///
/// Spec: M§6.5 (`gap_timeout`, RECOMMENDED 300 s).
pub const GAP_TIMEOUT_S: i64 = 300;

/// How long a group's hub may be unreachable before the device creates the successor group (M§7.5), seconds.
///
/// Spec: M§9.4 (RECOMMENDED 24 h). Impl (spec-gap 72): the device's own choice, `hub_timeout` in a vector context.
pub const HUB_TIMEOUT_S: i64 = 86400;
/// First and largest delay before a pending deposit is re-deposited to an unreachable hub, seconds.
///
/// Spec: §13.2 (initial 1 s, factor 2, max 60 s; the ceiling — a host adds full jitter). Impl (spec-gap 72).
pub const HUB_RETRY_INITIAL_S: i64 = 1;
/// See [`HUB_RETRY_INITIAL_S`].
pub const HUB_RETRY_MAX_S: i64 = 60;

/// A device's outbox for one group while its hub cannot be reached.
///
/// Spec: M§9.4 — the client keeps content pending, retries with the §13.2 backoff, never deposits into members'
/// mailboxes directly, and a hub unreachable past a threshold is the successor-group trigger (M§7.5); M§9.3 — a
/// retry re-deposits the same bytes. Impl (spec-gap 72): the hub is down from the first `mailbox.hub-unreachable`
/// (or no answer at all) until an `accepted`; the head is retried first and an `accepted` flushes the rest in order;
/// after `hub_timeout` the pending items are handed to the successor to re-encrypt and the dead group's outbox is
/// abandoned. Any other refusal is not an outage: the item leaves the outbox for its own handling. The hand-over to
/// the successor can fail: once abandoned, `handover_failed` is answered with the §13.2 backoff started afresh and the
/// `advance` that reaches it emits one `{"handover": "retry"}`; in any other state it is nothing.
#[derive(Debug, Clone)]
pub struct HubOutage {
    now: i64,
    hub_timeout: i64,
    pending: Vec<String>,
    down_since: Option<i64>,
    attempt: i64,
    retry_at: Option<i64>,
    state: &'static str,
    handover_attempt: i64,
    handover_at: Option<i64>,
}

impl HubOutage {
    /// An outbox from a vector `context`: `now`, `hub_timeout` (default [`HUB_TIMEOUT_S`]). A host restoring its
    /// outbox passes `pending` (item ids, in order) and `down_since`; the first retry is then due at once.
    pub fn new(ctx: &Value) -> HubOutage {
        let now = ctx["now"].as_i64().unwrap_or(0);
        let pending: Vec<String> = ctx["pending"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect();
        let down_since = ctx["down_since"].as_i64();
        HubOutage {
            now,
            hub_timeout: ctx["hub_timeout"].as_i64().unwrap_or(HUB_TIMEOUT_S),
            pending,
            down_since,
            attempt: 0,
            retry_at: down_since.map(|_| now),
            state: if down_since.is_some() { "down" } else { "up" },
            handover_attempt: 0,
            handover_at: None,
        }
    }

    /// Whether the hub is currently unreachable.
    pub fn is_down(&self) -> bool {
        self.state == "down"
    }

    /// Whether the outbox is abandoned: its items went to the successor, whose hand-over it may still be retrying.
    pub fn is_abandoned(&self) -> bool {
        self.state == "abandoned"
    }

    /// The outbox's clock, seconds.
    pub fn now(&self) -> i64 {
        self.now
    }

    /// When the current outage began, if the hub is down.
    pub fn down_since(&self) -> Option<i64> {
        self.down_since
    }

    /// Pending item ids, oldest first.
    pub fn pending(&self) -> &[String] {
        &self.pending
    }

    /// A new deposit for the group: forwarded now, or queued while the hub is down.
    pub fn deposit(&mut self, id: &str) -> Vec<Value> {
        if self.state == "abandoned" {
            return vec![json!({"refuse": "group-abandoned"})];
        }
        self.pending.push(id.to_string());
        if self.state == "up" { vec![json!({"forward": id})] } else { vec![json!({"queued": id})] }
    }

    fn unreachable(&mut self, id: &str) -> Vec<Value> {
        if !self.pending.iter().any(|p| p == id) {
            return vec![];
        }
        if self.down_since.is_none() {
            self.down_since = Some(self.now);
            self.state = "down";
        }
        self.attempt += 1;
        let delay = (HUB_RETRY_INITIAL_S << (self.attempt - 1).min(30)).min(HUB_RETRY_MAX_S);
        self.retry_at = Some(self.now + delay);
        vec![json!({"retry_in": delay})]
    }

    /// The deposit got no answer at all: an outage like a refusal.
    pub fn no_answer(&mut self, id: &str) -> Vec<Value> {
        self.unreachable(id)
    }

    /// The hub's (or the mailbox's) answer to a pending deposit; `reason` is `None` for `accepted`.
    pub fn answer(&mut self, id: &str, reason: Option<&str>) -> Vec<Value> {
        // M§9.4: a hub that cannot be reached, or cannot store the deposit (M§9.3, spec-gap 99), is unavailable
        if matches!(reason, Some("mailbox.hub-unreachable" | "mailbox.quota-exceeded")) {
            return self.unreachable(id);
        }
        let Some(pos) = self.pending.iter().position(|p| p == id) else { return vec![] };
        self.pending.remove(pos);
        if let Some(r) = reason {
            return vec![json!({"refused": {"id": id, "reason": r}})];
        }
        let mut out = vec![json!({"sent": id})];
        if self.state == "down" {
            self.state = "up";
            self.down_since = None;
            self.attempt = 0;
            self.retry_at = None;
            out.extend(self.pending.iter().map(|p| json!({"forward": p}))); // the hub is back: flush in order
        }
        out
    }

    /// The host could not complete the hand-over to the successor (none could be created or found, or an item could
    /// not be moved into it): retried with the §13.2 backoff, started afresh. Nothing unless abandoned.
    ///
    /// Spec: M§9.4, §13.2. Impl (spec-gap 72): every failure counts; a later schedule replaces an earlier one.
    pub fn handover_failed(&mut self) -> Vec<Value> {
        if self.state != "abandoned" {
            return vec![];
        }
        self.handover_attempt += 1;
        let delay = (HUB_RETRY_INITIAL_S << (self.handover_attempt - 1).min(30)).min(HUB_RETRY_MAX_S);
        self.handover_at = Some(self.now + delay);
        vec![json!({"handover_retry_in": delay})]
    }

    /// Time passes: a retry when due, the successor trigger at the threshold, a hand-over retry once abandoned.
    pub fn advance(&mut self, n: i64) -> Vec<Value> {
        self.now += n;
        if self.state == "abandoned" && self.handover_at.is_some_and(|at| self.now >= at) {
            self.handover_at = None; // the next failure schedules the next attempt
            return vec![json!({"handover": "retry"})];
        }
        if self.state != "down" {
            return vec![];
        }
        if self.now - self.down_since.unwrap_or(self.now) >= self.hub_timeout {
            // M§9.4: the successor-group trigger of M§7.5; the pending items are re-encrypted for the successor
            let pending = std::mem::take(&mut self.pending);
            self.state = "abandoned";
            self.retry_at = None;
            return vec![json!({"successor": {"pending": pending}})];
        }
        if let (Some(head), Some(at)) = (self.pending.first(), self.retry_at) {
            if self.now >= at {
                self.retry_at = None; // the answer schedules the next attempt
                return vec![json!({"forward": head})];
            }
        }
        vec![]
    }

    /// Apply one trace event (`deposit`, `answer`, `no_answer`, `handover_failed`, `advance`).
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        if let Some(d) = ev.get("deposit") {
            return self.deposit(d["id"].as_str().unwrap_or(""));
        }
        if let Some(a) = ev.get("answer") {
            return self.answer(a["id"].as_str().unwrap_or(""), a["reason"].as_str());
        }
        if let Some(a) = ev.get("no_answer") {
            return self.no_answer(a["id"].as_str().unwrap_or(""));
        }
        if ev.get("handover_failed").is_some() {
            return self.handover_failed();
        }
        self.advance(ev["advance"].as_i64().unwrap_or(0))
    }

    /// Snapshot compared by the vectors.
    pub fn snapshot(&self) -> Value {
        json!({"state": self.state, "pending": self.pending, "attempt": self.attempt,
               "down_for": self.down_since.map(|d| self.now - d), "handover_attempt": self.handover_attempt})
    }
}

/// How long a member waits for the hub a group moved to, from the move, seconds.
///
/// Spec: M§7.4. Impl (spec-gap 129): the same bound as the mailbox's `handover_wait` (300 s RECOMMENDED).
pub const ARRIVAL_WAIT_S: i64 = 300;

/// A member reaching the hub a group moved to before the committer's `group-info` has set it up.
///
/// Spec: M§7.4 — the new hub initializes from the latest `group-info`, and a member that processed the move deposits
/// there; §13.2 — the backoff. Impl (spec-gap 129): `moved` names the new hub (the device processed the moving commit,
/// or its own move was accepted). Until that hub accepts a deposit, its `mailbox.unknown-group` is not final: the same
/// deposit is retried with the §13.2 backoff, for at most `arrival_wait` from the move; the first such refusal at or
/// past the bound emits `expired`, once. Every other answer, and any answer from another hub, emits nothing: the caller
/// handles it as usual (M§7.4 sync, M§9.4 outage, M§6.5). A later `moved` starts afresh.
#[derive(Debug, Clone)]
pub struct MoveArrival {
    now: i64,
    wait: i64,
    state: &'static str,
    hub: Option<String>,
    since: Option<i64>,
    attempt: i64,
}

impl MoveArrival {
    /// A machine from a vector `context`: `now`, `arrival_wait` (default [`ARRIVAL_WAIT_S`]).
    pub fn new(ctx: &Value) -> MoveArrival {
        MoveArrival {
            now: ctx["now"].as_i64().unwrap_or(0),
            wait: ctx["arrival_wait"].as_i64().unwrap_or(ARRIVAL_WAIT_S),
            state: "none",
            hub: None,
            since: None,
            attempt: 0,
        }
    }

    /// The group moved to `hub`: wait for it to host the group.
    pub fn moved(&mut self, hub: &str) -> Vec<Value> {
        (self.state, self.hub, self.since, self.attempt) = ("arriving", Some(hub.to_string()), Some(self.now), 0);
        vec![]
    }

    /// `hub` answered a deposit for the group; `reason` is `None` for `accepted`.
    pub fn answer(&mut self, hub: &str, reason: Option<&str>) -> Vec<Value> {
        if self.state != "arriving" || self.hub.as_deref() != Some(hub) {
            return vec![];
        }
        match reason {
            None => {
                self.state = "hosted";
                vec![]
            }
            Some("mailbox.unknown-group") if self.now - self.since.unwrap_or(self.now) >= self.wait => {
                self.state = "expired";
                vec![json!({"expired": {}})]
            }
            Some("mailbox.unknown-group") => {
                self.attempt += 1;
                vec![json!({"retry_in": (HUB_RETRY_INITIAL_S << (self.attempt - 1).min(30)).min(HUB_RETRY_MAX_S)})]
            }
            Some(_) => vec![],
        }
    }

    /// Time passes.
    pub fn advance(&mut self, n: i64) -> Vec<Value> {
        self.now += n;
        vec![]
    }

    /// The machine's clock, seconds.
    pub fn now(&self) -> i64 {
        self.now
    }

    /// Set the clock (a host driving the machine from its own clock).
    pub fn set_now(&mut self, now: i64) {
        self.now = now;
    }

    /// Apply one trace event (`moved`, `answer`, `advance`).
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        if let Some(m) = ev.get("moved") {
            return self.moved(m["hub"].as_str().unwrap_or(""));
        }
        if let Some(a) = ev.get("answer") {
            return self.answer(a["hub"].as_str().unwrap_or(""), a["reason"].as_str());
        }
        self.advance(ev["advance"].as_i64().unwrap_or(0))
    }

    /// Snapshot compared by the vectors.
    pub fn snapshot(&self) -> Value {
        json!({"state": self.state, "hub": self.hub, "attempt": self.attempt, "waited": self.since.map(|s| self.now - s)})
    }
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// Whether the caller's client may offer to record a voicemail after an attempt outcome, and its `kind`: `video` only
/// when the attempt offered video (`call_video`) and the callee's entry `accepts` `video`, else `audio`.
///
/// Spec: M§13.2 (spec-gap 184).
pub fn voicemail_offer(inp: &Value) -> Value {
    let vm = &inp["voicemail"];
    if !vm.is_object() || !inp["can_send"].as_bool().unwrap_or(false) {
        return json!({"offer": false});
    }
    let reason = inp["outcome"]["reason"].as_str().unwrap_or("");
    let ok = match inp["outcome"]["type"].as_str() {
        Some("reject") => {
            let registered = REASONS.iter().any(|(t, _)| *t == reason);
            VOICEMAIL_REJECT_REASONS.contains(&reason)
                || (!registered && reason.split('.').next() == Some("endpoint"))
        }
        Some("cancel") => reason == "session.timeout",
        _ => false,
    };
    if !ok {
        return json!({"offer": false});
    }
    // M§13.2 (spec-gap 184): video after a video attempt, to a callee whose clients render it (M§4.2 `accepts`)
    let video = inp["call_video"].as_bool() == Some(true)
        && inp["accepts"].as_array().is_some_and(|a| a.iter().any(|k| k == "video"));
    let mut out = json!({"offer": true, "kind": if video { "video" } else { "audio" }});
    if let Some(d) = vm.get("max_duration_s") {
        out["max_duration_s"] = d.clone();
    }
    out
}

/// Converge duplicate direct conversations on the lowest conversation ULID.
///
/// Spec: M§7.2 — candidates failing the §20.6 ULID/`issued_at` consistency check cannot win.
pub fn select_direct(candidates: &[Value]) -> Value {
    let mut kept: Vec<String> = vec![];
    let mut discarded: Vec<String> = vec![];
    for c in candidates {
        let conv = s(&c["conversation"]);
        let consistent = Ulid::parse(&conv)
            .is_some_and(|u| (u.timestamp_s() - c["issued_at"].as_i64().unwrap_or(0)).abs() <= ULID_TOLERANCE_S);
        if consistent { kept.push(conv) } else { discarded.push(conv) }
    }
    json!({"winner": kept.into_iter().min(), "discarded": discarded})
}
/// What a device does after trying a content's blob sources in order (`tried`: each source's
/// `{uri, status, sha256?, size?}`): `play` the first matching 200, otherwise `retry` (or `give-up` on the last
/// attempt) when some source had nothing to serve, or `give-up` at once when every source served other bytes.
///
/// Spec: M§8.4 "Fetching". Impl (spec-gap 106): the device retries like a mailbox's replication (spec-gap 67),
/// bounded by `max_attempts` (default 5); a mismatch everywhere is never retried.
pub fn blob_fetch(inp: &Value) -> Value {
    let b = &inp["blob"];
    let tried = inp["tried"].as_array().cloned().unwrap_or_default();
    if let Some(t) = tried.iter().find(|t| t["status"] == json!(200) && t["sha256"] == b["sha256"] && t["size"] == b["size"]) {
        return json!({"action": "play", "source": t["uri"]});
    }
    if tried.is_empty() || tried.iter().any(|t| t["status"] != json!(200)) {
        let attempts = inp["max_attempts"].as_i64().unwrap_or(crate::mailbox::BLOB_REPLICATION_ATTEMPTS);
        let more = inp["attempt"].as_i64().unwrap_or(1) < attempts;
        return json!({"action": if more { "retry" } else { "give-up" }, "reason": "unavailable"});
    }
    json!({"action": "give-up", "reason": "mismatch"})
}


/// Where a device fetches a content blob from, in order: its own mailbox's copy (a manifest entry for the same
/// `sha256` and `size` at another `uri`), then the content object's `uri`.
///
/// Spec: M§8.4 rules 6–7 — devices fetch from their own mailbox, falling back to the original `uri`, and verify
/// `sha256` and `size` either way. Impl (spec-gap 65): the unencrypted manifest only reorders sources for the blob the
/// encrypted content names.
pub fn blob_sources(inp: &Value) -> Value {
    let b = &inp["blob"];
    let mut sources: Vec<Value> = inp["manifest"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["sha256"] == b["sha256"] && e["size"] == b["size"] && e["uri"] != b["uri"])
        .map(|e| e["uri"].clone())
        .take(1)
        .collect();
    sources.push(b["uri"].clone());
    json!({"sources": sources})
}

/// Whether a callee device sends a `call-event` for a leg that ended, and with which outcome.
///
/// Spec: M§13.3 — a callee device that alerted and was not answered sends one; never for `session.answered-elsewhere`.
/// Impl (spec-gap 63): a leg this device rejected with `user.declined` is `declined`; any other alerted, unanswered leg
/// is `missed`; a leg that never alerted sends nothing.
pub fn call_event_decision(inp: &Value) -> Value {
    if !inp["alerted"].as_bool().unwrap_or(false) || inp["answered_here"].as_bool().unwrap_or(false) {
        return json!({"send": false});
    }
    let reason = inp["reason"].as_str().unwrap_or("");
    if reason == "session.answered-elsewhere" {
        return json!({"send": false});
    }
    if inp["ended_by"] == "local" && reason == "user.declined" {
        return json!({"send": true, "outcome": "declined"});
    }
    json!({"send": true, "outcome": "missed"})
}

/// One timeline per peer identity: its conversation's content (seq order) and the personal group's call events for it.
///
/// Spec: M§13.3 (interleave by peer identity), M§8.5 (time never reorders history). Impl (spec-gap 63): call events
/// collapse by `session`, first by seq kept; a call goes before the first content item whose `at` is later than its own.
pub fn peer_timeline(inp: &Value) -> Value {
    let mut seen = BTreeSet::new();
    let (mut calls, mut collapsed) = (vec![], vec![]);
    for c in inp["calls"].as_array().into_iter().flatten() {
        let session = s(&c["session"]);
        if !seen.insert(session.clone()) {
            collapsed.push(session);
            continue;
        }
        calls.push((c["at"].as_i64().unwrap_or(0), session));
    }
    calls.sort_by_key(|(at, _)| *at); // stable: equal times keep seq order
    let (mut out, mut k) = (vec![], 0);
    for item in inp["content"].as_array().into_iter().flatten() {
        let at = item["at"].as_i64().unwrap_or(0);
        while k < calls.len() && calls[k].0 < at {
            out.push(format!("call:{}", calls[k].1));
            k += 1;
        }
        out.push(format!("content:{}", s(&item["id"])));
    }
    out.extend(calls[k..].iter().map(|(_, sess)| format!("call:{sess}")));
    json!({"timeline": out, "collapsed": collapsed})
}

/// Accept a successor group only from a predecessor member re-adding predecessor members.
///
/// Spec: M§7.5 — otherwise the group is a new conversation subject to first contact.
pub fn check_successor(inp: &Value) -> Value {
    let set = |k: &str| -> BTreeSet<String> { inp[k].as_array().into_iter().flatten().map(s).collect() };
    let pred = set("predecessor_roster");
    if pred.contains(&s(&inp["creator"])) && set("roster").is_subset(&pred) {
        accept()
    } else {
        reject("successor-invalid", None)
    }
}

/// Converge concurrent successor groups on the lowest `group_id`, compared as the decoded ULID.
///
/// Spec: M§7.5, M§6.3 (`group_id` is the UTF-8 bytes of a ULID; the wire form is base64url).
pub fn select_successor(candidates: &[Value]) -> Value {
    let mut kept: Vec<(String, String)> = vec![];
    let mut discarded: Vec<String> = vec![];
    for c in candidates {
        let g = s(c);
        let ulid = dsip_core::b64::decode(&g)
            .and_then(|b| String::from_utf8(b).ok())
            .filter(|u| Ulid::parse(u).is_some());
        match ulid {
            Some(u) => kept.push((u, g)),
            None => discarded.push(g),
        }
    }
    json!({"winner": kept.into_iter().min().map(|(_, g)| g), "discarded": discarded})
}

/// A device converging on one successor per dead group.
///
/// Spec: M§7.5 — a successor is accepted only from a predecessor member re-adding predecessor members, otherwise it is a
/// new conversation under first contact; concurrent successors converge on the lowest `group_id`.
///
/// Impl (spec-gap 61): per predecessor the device keeps its valid successors as candidates and stays in only the
/// lowest — declining a higher one, leaving one it had kept (or created) when a lower one appears; a successor for a
/// group the device never knew is first contact; asked to create a successor when one exists, it uses that one.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SuccessorTracker {
    groups: BTreeMap<String, BTreeSet<String>>,
    candidates: BTreeMap<String, BTreeSet<String>>,
    winner: BTreeMap<String, String>,
}

impl SuccessorTracker {
    /// A tracker from a vector `context`: `groups` (group → roster by identity).
    pub fn new(ctx: &Value) -> SuccessorTracker {
        let groups = ctx["groups"]
            .as_object()
            .map(|m| m.iter().map(|(g, r)| (g.clone(), r.as_array().into_iter().flatten().map(s).collect())).collect())
            .unwrap_or_default();
        SuccessorTracker { groups, ..Default::default() }
    }

    /// Record (or refresh) a group this device is a member of, with its roster by identity.
    pub fn member_of(&mut self, group: &str, roster: &[String]) {
        self.groups.insert(group.to_string(), roster.iter().cloned().collect());
    }

    /// The successor this device converged on for `predecessor`, if any.
    pub fn successor(&self, predecessor: &str) -> Option<&str> {
        self.winner.get(predecessor).map(String::as_str)
    }

    /// Apply one event (`create`, `created`, `welcome`) and return what the device does.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        let Some((name, e)) = ev.as_object().and_then(|m| m.iter().next()) else { return vec![] };
        match name.as_str() {
            "create" => {
                let pred = s(&e["predecessor"]);
                if let Some(w) = self.winner.get(&pred) {
                    return vec![json!({"use": w})];
                }
                match self.groups.get(&pred) {
                    Some(r) => vec![json!({"create": {"successor_of": pred, "roster": r}})],
                    None => vec![json!({"refuse": "not-a-member"})],
                }
            }
            "created" => {
                let pred = s(&e["successor_of"]);
                let roster = self.groups.get(&pred).cloned().unwrap_or_default();
                self.candidate(&s(&e["group"]), &pred, roster, true)
            }
            "welcome" => {
                let pred = s(&e["successor_of"]);
                let group = s(&e["group"]);
                let Some(pred_roster) = self.groups.get(&pred) else { return vec![json!({"first_contact": group})] };
                let check = check_successor(&json!({"predecessor_roster": pred_roster, "creator": e["creator"], "roster": e["roster"]}));
                if check["verdict"] != "accept" {
                    return vec![json!({"first_contact": group})];
                }
                let roster = e["roster"].as_array().into_iter().flatten().map(s).collect();
                self.candidate(&group, &pred, roster, false)
            }
            _ => vec![],
        }
    }

    fn candidate(&mut self, group: &str, pred: &str, roster: BTreeSet<String>, mine: bool) -> Vec<Value> {
        let cands = self.candidates.entry(pred.to_string()).or_default();
        cands.insert(group.to_string());
        let list: Vec<Value> = cands.iter().map(|c| json!(c)).collect();
        let best = select_successor(&list)["winner"].as_str().map(String::from);
        if best.as_deref() != Some(group) {
            return vec![json!({if mine { "leave" } else { "decline" }: group})];
        }
        let prev = self.winner.insert(pred.to_string(), group.to_string());
        self.groups.insert(group.to_string(), roster); // a successor can itself be succeeded
        let mut out = if mine { vec![] } else { vec![json!({"join": group})] };
        if let Some(p) = prev.filter(|p| p != group) {
            out.push(json!({"leave": p}));
        }
        out
    }

    /// Snapshot compared by the vectors: per predecessor with candidates, the successor and the candidates.
    pub fn snapshot(&self) -> Value {
        let m: serde_json::Map<String, Value> = self
            .candidates
            .iter()
            .map(|(p, c)| (p.clone(), json!({"successor": self.winner.get(p), "candidates": c})))
            .collect();
        Value::Object(m)
    }
}

struct Content {
    sender: String,
    seq: i64,
    kind: String,
}

/// One device's view of one conversation, and what it sends.
///
/// Spec: M§10.2–M§10.5, M§11.2, M§8.5.
pub struct Client {
    now: i64,
    me: String,
    policy: Value,
    members: i64,
    content: BTreeMap<String, Content>,
    timeline: Vec<String>,
    delivered: BTreeMap<String, BTreeMap<String, Value>>,
    played: BTreeMap<String, BTreeMap<String, Value>>,
    read_seq: BTreeMap<String, i64>,
    read_through: BTreeMap<String, String>,
    sent_delivered: BTreeSet<String>,
    sent_played: BTreeSet<String>,
    last_read_sent: Option<i64>,
    pending_read: bool,
    last_activity: BTreeMap<String, i64>,
    shown: BTreeMap<String, BTreeMap<String, i64>>,
}

impl Client {
    /// A client from a vector `context`: `now`, `me`, `policy`, `member_identities`.
    pub fn new(ctx: &Value) -> Client {
        Client {
            now: ctx["now"].as_i64().unwrap_or(0),
            me: s(&ctx["me"]),
            policy: ctx["policy"].clone(),
            members: ctx["member_identities"].as_i64().unwrap_or(2),
            content: BTreeMap::new(),
            timeline: vec![],
            delivered: BTreeMap::new(),
            played: BTreeMap::new(),
            read_seq: BTreeMap::new(),
            read_through: BTreeMap::new(),
            sent_delivered: BTreeSet::new(),
            sent_played: BTreeSet::new(),
            last_read_sent: None,
            pending_read: false,
            last_activity: BTreeMap::new(),
            shown: BTreeMap::new(),
        }
    }

    fn policy(&self, k: &str) -> bool {
        self.policy[k].as_bool().unwrap_or(false)
    }

    /// Apply one event (`sync`, `read`, `play`, `activity`, `activity_in`, `advance`) and return what the device sends.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        let Some((name, e)) = ev.as_object().and_then(|m| m.iter().next()) else { return vec![] };
        match name.as_str() {
            "sync" => self.sync(e),
            "restore" => self.restore(e),
            "read" => self.read(e),
            "play" => self.play(e),
            "activity" => self.activity(e),
            "activity_in" => self.activity_in(e),
            "advance" => self.advance(e.as_i64().unwrap_or(0)),
            _ => vec![],
        }
    }

    fn sync(&mut self, e: &Value) -> Vec<Value> {
        let mut fresh = vec![];
        let mut out = vec![];
        for it in e["items"].as_array().into_iter().flatten() {
            let o = &it["object"];
            match o["object"].as_str() {
                Some("content") => {
                    let id = s(&o["id"]);
                    if self.content.contains_key(&id) {
                        continue; // M§8.5: duplicates collapse silently
                    }
                    let seq = it["seq"].as_i64().unwrap_or(0);
                    self.content.insert(id.clone(), Content { sender: s(&o["sender"]), seq, kind: s(&o["kind"]) });
                    self.timeline.push(id.clone());
                    fresh.push(id);
                }
                #[allow(clippy::collapsible_match)] // `receipt` records the receipt: not a thing to do in a match guard
                Some("receipt") => {
                    if self.receipt(o) {
                        // M§12.2 (spec-gap 64): a receipt that changes rendering is archived like content
                        out.push(json!({"archive": {"seq": it["seq"]}}));
                    }
                }
                _ => {}
            }
        }
        if self.policy("delivered") && self.members <= DELIVERED_MAX_GROUP {
            // M§10.2: decided after the whole batch, so a sibling's receipt in it suppresses ours
            let targets: Vec<String> = fresh
                .into_iter()
                .filter(|i| {
                    self.content[i].sender != self.me
                        && !self.delivered.get(i).is_some_and(|m| m.contains_key(&self.me))
                        && !self.sent_delivered.contains(i)
                })
                .collect();
            for chunk in targets.chunks(RECEIPT_MAX_TARGETS) {
                out.push(json!({"send": {"to": "conversation", "receipt": "delivered", "targets": chunk}}));
            }
            self.sent_delivered.extend(targets);
        }
        out
    }

    /// Content and receipts opened from archive: rendering state only, nothing sent or archived (spec-gap 64).
    fn restore(&mut self, e: &Value) -> Vec<Value> {
        for it in e["items"].as_array().into_iter().flatten() {
            let o = &it["object"];
            match o["object"].as_str() {
                Some("content") => {
                    let id = s(&o["id"]);
                    if !self.content.contains_key(&id) {
                        let seq = it["seq"].as_i64().unwrap_or(0);
                        self.content.insert(id.clone(), Content { sender: s(&o["sender"]), seq, kind: s(&o["kind"]) });
                        self.timeline.push(id);
                    }
                }
                Some("receipt") => {
                    self.receipt(o);
                }
                _ => {}
            }
        }
        vec![]
    }

    /// Apply a receipt; `true` when it changed what is rendered.
    fn receipt(&mut self, o: &Value) -> bool {
        let who = s(&o["sender"]);
        let mut changed = false;
        match o["kind"].as_str() {
            Some(kind @ ("delivered" | "played")) => {
                for t in o["targets"].as_array().into_iter().flatten().map(s) {
                    let Some(c) = self.content.get(&t) else { continue };
                    if c.sender == who || (kind == "played" && !matches!(c.kind.as_str(), "audio" | "video")) {
                        continue;
                    }
                    let book = if kind == "delivered" { &mut self.delivered } else { &mut self.played };
                    let entry = book.entry(t).or_default();
                    if !entry.contains_key(&who) {
                        entry.insert(who.clone(), o["sent_at"].clone()); // first by seq wins
                        changed = true;
                    }
                }
            }
            Some("read") => {
                let through = s(&o["through"]);
                if let Some(c) = self.content.get(&through) {
                    if c.seq > self.read_seq.get(&who).copied().unwrap_or(0) {
                        // M§10.3: monotone
                        self.read_seq.insert(who.clone(), c.seq);
                        self.read_through.insert(who, through);
                        changed = true;
                    }
                }
            }
            _ => {}
        }
        changed
    }

    fn read_send(&mut self) -> Vec<Value> {
        self.last_read_sent = Some(self.now);
        self.pending_read = false;
        let to = if self.policy("read") { "conversation" } else { "personal" }; // M§10.5
        vec![json!({"send": {"to": to, "receipt": "read", "through": self.read_through[&self.me]}})]
    }

    fn read(&mut self, e: &Value) -> Vec<Value> {
        let through = s(&e["through"]);
        let Some(seq) = self.content.get(&through).map(|c| c.seq) else { return vec![] };
        if seq <= self.read_seq.get(&self.me).copied().unwrap_or(0) {
            return vec![];
        }
        self.read_seq.insert(self.me.clone(), seq);
        self.read_through.insert(self.me.clone(), through);
        if self.last_read_sent.is_some_and(|t| self.now - t < READ_MIN_INTERVAL_S) {
            self.pending_read = true;
            return vec![];
        }
        self.read_send()
    }

    /// Spec: M§11.2 — a received activity is shown until its last refresh's `expires_at`; `stopped` clears it.
    /// Impl (spec-gap 49): that `expires_at` is the originating deposit's, carried unchanged to the device.
    fn activity_in(&mut self, e: &Value) -> Vec<Value> {
        let sender = s(&e["sender"]);
        let acts = self.shown.entry(sender.clone()).or_default();
        let exp = e["expires_at"].as_i64().unwrap_or(i64::MIN);
        if e["state"] == "stopped" {
            acts.remove(&s(&e["activity"]));
        } else if exp > self.now {
            // gone at its expires_at (§12.9, spec-gap 141)
            acts.insert(s(&e["activity"]), exp);
        }
        if acts.is_empty() {
            self.shown.remove(&sender);
        }
        vec![]
    }

    fn advance(&mut self, n: i64) -> Vec<Value> {
        self.now += n;
        let now = self.now;
        for acts in self.shown.values_mut() {
            acts.retain(|_, t| *t > now);
        }
        self.shown.retain(|_, a| !a.is_empty());
        if self.pending_read && self.last_read_sent.is_some_and(|t| self.now - t >= READ_MIN_INTERVAL_S) {
            return self.read_send();
        }
        vec![]
    }

    fn play(&mut self, e: &Value) -> Vec<Value> {
        let id = s(&e["id"]);
        let media = self.content.get(&id).is_some_and(|c| matches!(c.kind.as_str(), "audio" | "video"));
        let already = self.played.get(&id).is_some_and(|m| m.contains_key(&self.me)) || self.sent_played.contains(&id);
        if !media || !self.policy("played") || already {
            return vec![];
        }
        self.sent_played.insert(id.clone());
        vec![json!({"send": {"to": "conversation", "receipt": "played", "targets": [id]}})]
    }

    fn activity(&mut self, e: &Value) -> Vec<Value> {
        if !self.policy("activity") {
            return vec![]; // M§11.2: same opt-in as read receipts
        }
        let a = s(&e["activity"]);
        let state = s(&e["state"]);
        if state == "active" {
            if self.last_activity.get(&a).is_some_and(|t| self.now - t < ACTIVITY_REFRESH_S) {
                return vec![];
            }
            self.last_activity.insert(a.clone(), self.now);
        } else {
            self.last_activity.remove(&a);
        }
        vec![json!({"send": {"to": "conversation", "activity": a, "state": state}})]
    }

    /// Snapshot compared by the vectors: timeline, collapsed receipts, read watermarks.
    pub fn snapshot(&self) -> Value {
        let book = |b: &BTreeMap<String, BTreeMap<String, Value>>| -> Value {
            let m: serde_json::Map<String, Value> =
                b.iter().filter(|(_, m)| !m.is_empty()).map(|(i, m)| (i.clone(), json!(m))).collect();
            Value::Object(m)
        };
        json!({"timeline": self.timeline, "delivered": book(&self.delivered), "played": book(&self.played),
               "read_through": self.read_through, "activity": self.shown})
    }

    /// The machine's clock, seconds; a host advances it to wall time with `advance` events.
    pub fn now(&self) -> i64 {
        self.now
    }
}

/// Seq-gap handling for one group on one device.
///
/// Spec: M§6.5 — handshake items beyond a gap, and anything after a held item, wait for the gap;
/// a gap not filled within [`GAP_TIMEOUT_S`] of the first held item triggers a re-join (M§6.8).
pub struct GapTracker {
    now: i64,
    timeout: i64,
    contiguous: i64,
    seen: BTreeSet<i64>,
    held: Vec<i64>,
    gap_since: Option<i64>,
}

impl GapTracker {
    /// A tracker from a vector `context`: `now`, `contiguous`, `gap_timeout` (default [`GAP_TIMEOUT_S`]).
    pub fn new(ctx: &Value) -> GapTracker {
        GapTracker {
            now: ctx["now"].as_i64().unwrap_or(0),
            // M§6.5 RECOMMENDED 300 s; a device may hold for less (spec-gap 69)
            timeout: ctx["gap_timeout"].as_i64().unwrap_or(GAP_TIMEOUT_S),
            contiguous: ctx["contiguous"].as_i64().unwrap_or(0),
            seen: BTreeSet::new(),
            held: vec![],
            gap_since: None,
        }
    }

    /// Apply one event (`item`, `advance`).
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        if let Some(n) = ev.get("advance").and_then(Value::as_i64) {
            self.now += n;
            if !self.held.is_empty() && self.gap_since.is_some_and(|t| self.now - t >= self.timeout) {
                let out = vec![json!({"rejoin": {"held": self.held}})];
                self.contiguous = self.held.iter().chain(self.seen.iter()).copied().max().unwrap_or(self.contiguous);
                self.seen.clear();
                self.held.clear();
                self.gap_since = None;
                return out;
            }
            return vec![];
        }
        let it = &ev["item"];
        let seq = it["seq"].as_i64().unwrap_or(0);
        if seq <= self.contiguous || self.seen.contains(&seq) {
            return vec![json!({"duplicate": seq})];
        }
        self.seen.insert(seq);
        let mut out = vec![];
        let blocked = it["class"] == "handshake" && seq > self.contiguous + 1;
        if blocked || self.held.first().is_some_and(|h| seq > *h) {
            self.held.push(seq);
            self.held.sort_unstable();
            self.gap_since.get_or_insert(self.now);
            out.push(json!({"hold": seq}));
        } else {
            out.push(json!({"process": seq}));
        }
        while self.seen.remove(&(self.contiguous + 1)) {
            self.contiguous += 1;
        }
        while self.held.first().is_some_and(|h| *h <= self.contiguous) {
            out.push(json!({"process": self.held.remove(0)}));
        }
        if self.held.is_empty() {
            self.gap_since = None;
        }
        out
    }

    /// The time this tracker has been advanced to.
    pub fn now(&self) -> i64 {
        self.now
    }

    /// Snapshot compared by the vectors.
    pub fn snapshot(&self) -> Value {
        json!({"contiguous": self.contiguous, "held": self.held})
    }
}

/// Whether a device removed from a group ends its identity's mailbox registration (`left`).
///
/// Spec: M§5.7, M§6.6 — registrations are per identity. Impl (spec-gap 53): only when no leaf of the identity
/// remains in the group.
pub fn registration_on_removal(inp: &Value) -> Value {
    let remains = inp["remaining_identities"].as_array().is_some_and(|a| a.contains(&inp["me"]));
    json!({"left": !remains})
}

/// The deposit classes the hub sequences.
///
/// Spec: M§6.5 rule 4.
pub const SEQUENCED_CLASSES: [&str; 2] = ["handshake", "application"];

/// A device's durable delivery state: the ack cursor, per-group seq positions and joined groups.
///
/// Spec: M§5.4 — `ack_through` covers only items the device has durably processed; M§8.5 — duplicates
/// collapse silently; M§5.4 — on `mailbox.cursor-invalid` the device re-syncs from `null`.
///
/// Impl (spec-gap 44): each item is processed and committed together with this state, or not at all,
/// so a crash rolls an item back with its MLS state and it is redelivered. A redelivered sequenced
/// item is recognised by its hub `seq` ([`GapTracker`]'s contiguous position plus the seqs seen past
/// a gap), never by decrypting it, since MLS consumed its secret the first time; a welcome is a
/// duplicate for a group already joined; unsequenced `group-info` is state and is processed again.
/// Holding across a gap is [`GapTracker`]'s job and is not modelled here.
#[derive(Debug, Clone, Default)]
pub struct Resume {
    cursor: Option<String>,
    groups: BTreeMap<String, (i64, BTreeSet<i64>)>,
    joined: BTreeSet<String>,
    /// The device's own `limit` (vector `context.limit`; `None`: it sends none). Not durable: a restart returns to it.
    base_limit: Option<i64>,
    /// The `limit` its syncs carry now, halved for each envelope over the cap (spec-gap 180).
    limit: Option<i64>,
}

/// The `limit` a device that sent none sends after an envelope over the cap (M§5.4: "a `limit` of its choosing").
///
/// Impl (spec-gap 180): 100, half of the 200 the profile's example sends; it halves from there.
pub const LIMIT_AFTER_TOO_LARGE: i64 = 100;

impl Resume {
    /// Durable state from a vector `context` or a previous [`Resume::snapshot`]: `cursor`, `groups`, `joined`; and the
    /// device's `limit`, when the context states one.
    pub fn new(ctx: &Value) -> Resume {
        let groups = ctx["groups"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(g, p)| {
                let seen = p["seen"].as_array().into_iter().flatten().filter_map(Value::as_i64).collect();
                (g.clone(), (p["contiguous"].as_i64().unwrap_or(0), seen))
            })
            .collect();
        Resume {
            cursor: ctx["cursor"].as_str().map(String::from),
            groups,
            joined: ctx["joined"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect(),
            base_limit: ctx["limit"].as_i64(),
            limit: ctx["limit"].as_i64(),
        }
    }

    /// Whether an `items[]` element was already durably processed.
    pub fn is_duplicate(&self, item: &Value) -> bool {
        let class = item["class"].as_str().unwrap_or("");
        let group = item["group"].as_str().unwrap_or("");
        if SEQUENCED_CLASSES.contains(&class) {
            let seq = item["seq"].as_i64().unwrap_or(0);
            return self.groups.get(group).is_some_and(|(contiguous, seen)| seq <= *contiguous || seen.contains(&seq));
        }
        class == "welcome" && self.joined.contains(group)
    }

    /// Record an item as committed; `duplicate` items only advance the cursor, so they are acknowledged.
    pub fn commit(&mut self, item: &Value, duplicate: bool) {
        self.cursor = item["cursor"].as_str().map(String::from);
        if duplicate {
            return;
        }
        let class = item["class"].as_str().unwrap_or("");
        let group = item["group"].as_str().unwrap_or("").to_string();
        if SEQUENCED_CLASSES.contains(&class) {
            self.sent(&group, item["seq"].as_i64().unwrap_or(0));
        } else if class == "welcome" {
            // spec-gap 83: the welcome carries the seq of the commit that added this device — its exact position. What
            // is at or below it is pre-join history; what follows is counted from there.
            if let Some(seq) = item["seq"].as_i64() {
                self.groups.insert(group.clone(), (seq, Default::default()));
            }
            self.joined.insert(group);
        }
    }

    /// Record a seq as processed without an item: the device's own deposit, from the seq in its `accepted`.
    ///
    /// Impl (spec-gap 47): the hub fans a device's own item back to its identity (M§6.5 rule 5) and MLS
    /// cannot decrypt a device's own message, so the copy must be recognised as already processed.
    pub fn sent(&mut self, group: &str, seq: i64) {
        if !self.groups.contains_key(group) {
            // spec-gap 69, the fallback of spec-gap 83: with no position from a welcome, a device counts from where it
            // starts — the first sequenced item it processes — not from seq 1
            self.groups.insert(group.to_string(), (seq, Default::default()));
            return;
        }
        let (contiguous, seen) = self.groups.entry(group.to_string()).or_default();
        if seq > *contiguous {
            seen.insert(seq);
        }
        while seen.remove(&(*contiguous + 1)) {
            *contiguous += 1;
        }
    }

    /// Re-joined by external commit: every seq up to the highest seen is passed.
    ///
    /// Spec: M§6.5, M§6.8 — the items behind the gap are gone, or for epochs this device can no longer reach, so a
    /// later redelivery is a duplicate (spec-gap 69).
    pub fn rejoined(&mut self, group: &str, seq: i64) {
        let (contiguous, seen) = self.groups.entry(group.to_string()).or_default();
        *contiguous = seen.iter().copied().chain([seq, *contiguous]).max().unwrap_or(seq);
        seen.clear();
        self.joined.insert(group.to_string());
    }

    /// A commit removed this device's identity from `group`: no longer joined, so a welcome adding it back is a join.
    ///
    /// Spec: M§7.3, M§8.5. Impl (spec-gap 127): the seq positions stay, so items already processed remain duplicates.
    pub fn removed(&mut self, group: &str) {
        self.joined.remove(group);
    }

    /// Forget the cursor after `mailbox.cursor-invalid`; seq positions and joined groups are kept.
    pub fn cursor_invalid(&mut self) {
        self.cursor = None;
    }

    /// The mailbox answered the last `sync` with an envelope over the cap (§13.2). The same `sync` would get the same
    /// envelope, so the next one carries half the `limit`, at least 1. Returns `true` when the `limit` is already 1: the
    /// mailbox is at fault, and the same `sync` waits out the §13.2 reconnection backoff.
    ///
    /// Spec: M§5.4 (spec-gap 180), M§5.1 (`MAX_MLS_BYTES` makes any one item fit).
    pub fn too_large(&mut self) -> bool {
        match self.limit {
            Some(1) => true,
            Some(n) => {
                self.limit = Some((n / 2).max(1));
                false
            }
            None => {
                self.limit = Some(LIMIT_AFTER_TOO_LARGE);
                false
            }
        }
    }

    /// The `sync` fields this state allows: `since`, `ack_through` never ahead of the last commit, and the `limit` when
    /// there is one (M§5.4, spec-gap 180).
    pub fn sync_fields(&self) -> Value {
        let mut f = match &self.cursor {
            Some(c) => json!({"since": c, "ack_through": c}),
            None => json!({"since": null}),
        };
        if let Some(l) = self.limit {
            f["limit"] = json!(l);
        }
        f
    }

    /// Apply one trace event (`items` with optional `crash_at`, `sent`, `rejoined`, `sync`, `restart`, `cursor_invalid`,
    /// `too_large`).
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        if let Some(e) = ev.get("items") {
            let mut out = vec![];
            for item in e["items"].as_array().into_iter().flatten() {
                let cursor = item["cursor"].clone();
                if e.get("crash_at") == Some(&cursor) {
                    out.push(json!({"crash": cursor})); // processed in memory, never committed
                    break;
                }
                let dup = self.is_duplicate(item);
                if !dup && item["sibling"] == json!(true) {
                    // spec-gap 51: a sibling device's welcome is acknowledged but is not a join
                    out.push(json!({"sibling": cursor}));
                    self.commit(item, true);
                    continue;
                }
                out.push(json!({ if dup { "duplicate" } else { "process" }: cursor }));
                self.commit(item, dup);
            }
            return out;
        }
        if let Some(e) = ev.get("sent") {
            self.sent(e["group"].as_str().unwrap_or(""), e["seq"].as_i64().unwrap_or(0));
            return vec![];
        }
        if let Some(e) = ev.get("rejoined") {
            self.rejoined(e["group"].as_str().unwrap_or(""), e["seq"].as_i64().unwrap_or(0));
            return vec![];
        }
        if let Some(e) = ev.get("removed") {
            self.removed(e["group"].as_str().unwrap_or(""));
            return vec![];
        }
        let mut out = vec![];
        if ev.get("restart").is_some() {
            let base = self.base_limit;
            *self = Resume::new(&self.snapshot()); // only durable state survives
            (self.base_limit, self.limit) = (base, base);
        } else if ev.get("cursor_invalid").is_some() {
            self.cursor_invalid();
        } else if ev.get("too_large").is_some() && self.too_large() {
            out.push(json!({"backoff": {}}));
        }
        out.push(json!({"sync": self.sync_fields()}));
        out
    }

    /// The durable state, as the vectors compare it and as a device stores it.
    pub fn snapshot(&self) -> Value {
        let groups: serde_json::Map<String, Value> = self
            .groups
            .iter()
            .map(|(g, (contiguous, seen))| (g.clone(), json!({"contiguous": contiguous, "seen": seen})))
            .collect();
        json!({"cursor": self.cursor, "groups": groups, "joined": self.joined})
    }
}

/// One device's conversation history assembled from MLS items and archive records.
///
/// Spec: M§12.2 (archive records, the current archive key), M§12.3 (a new device reads history from archive and MLS
/// items from its join epoch onward), M§8.5 (archive and MLS copies are duplicates; display in hub `seq` order).
///
/// Impl (spec-gap 51): archive records under a key the device does not hold yet are held and released when that key
/// arrives; MLS items from epochs before the device joined are skipped; a device archives what it shows from MLS,
/// including its own sent content, under the current key — the greatest `created_at`, ties by `akid`.
#[derive(Debug, Clone, Default)]
pub struct History {
    keys: BTreeMap<String, i64>,
    joined: BTreeMap<String, i64>,
    held: Vec<Value>,
    shown: BTreeMap<String, (String, i64)>,
    applied: std::collections::BTreeSet<String>,
}

impl History {
    /// A history from a vector `context`: `keys` (`[{akid, created_at}]`), `joined` (`{group: epoch}`).
    pub fn new(ctx: &Value) -> History {
        History {
            keys: ctx["keys"].as_array().into_iter().flatten().map(|k| (s(&k["akid"]), k["created_at"].as_i64().unwrap_or(0))).collect(),
            joined: ctx["joined"].as_object().into_iter().flatten().map(|(g, e)| (g.clone(), e.as_i64().unwrap_or(0))).collect(),
            held: vec![],
            shown: BTreeMap::new(),
            applied: Default::default(),
        }
    }

    /// The current archive key id, if any.
    pub fn current_akid(&self) -> Option<String> {
        self.keys.iter().max_by(|a, b| (a.1, a.0).cmp(&(b.1, b.0))).map(|(k, _)| k.clone())
    }

    /// Whether an MLS item of `group` at `epoch` predates this device's membership (the `mls` event's `prejoin` rule).
    pub fn is_prejoin(&self, group: &str, epoch: i64) -> bool {
        self.joined.get(group).is_some_and(|j| epoch < *j)
    }

    /// Whether the device holds this archive key.
    pub fn has_key(&self, akid: &str) -> bool {
        self.keys.contains_key(akid)
    }

    fn show(&mut self, e: &Value) -> Value {
        let id = s(&e["id"]);
        if self.shown.contains_key(&id) {
            return json!({"duplicate": id});
        }
        self.shown.insert(id.clone(), (s(&e["group"]), e["seq"].as_i64().unwrap_or(0)));
        json!({"show": id})
    }

    /// An archive record under a held key: content is shown; a receipt (spec-gap 64) or call event (spec-gap 63) is
    /// applied to the receipt state or call log and is not a timeline entry.
    fn open(&mut self, e: &Value) -> Value {
        if e["object"] == "receipt" || e["object"] == "call-event" {
            let id = s(&e["id"]);
            if !self.applied.insert(id.clone()) {
                return json!({"duplicate": id});
            }
            return json!({"apply": e["cursor"]});
        }
        self.show(e)
    }

    fn show_from_mls(&mut self, e: &Value) -> Vec<Value> {
        let shown = self.show(e);
        let fresh = shown.get("show").is_some();
        let mut out = vec![shown];
        if let (true, Some(akid)) = (fresh, self.current_akid()) {
            out.push(json!({"archive": {"group": e["group"], "seq": e["seq"], "akid": akid}}));
        }
        out
    }

    /// Apply one event (`joined`, `archive_key`, `archive`, `mls`, `sent`) and return the decisions.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        let Some((name, e)) = ev.as_object().and_then(|m| m.iter().next()) else { return vec![] };
        match name.as_str() {
            "joined" => {
                self.joined.insert(s(&e["group"]), e["epoch"].as_i64().unwrap_or(0));
                vec![]
            }
            "archive_key" => {
                let akid = s(&e["akid"]);
                self.keys.insert(akid.clone(), e["created_at"].as_i64().unwrap_or(0));
                let (release, keep): (Vec<Value>, Vec<Value>) = std::mem::take(&mut self.held).into_iter().partition(|h| h["akid"] == json!(akid));
                self.held = keep;
                release.iter().map(|h| self.open(h)).collect()
            }
            "archive" => {
                if !self.keys.contains_key(e["akid"].as_str().unwrap_or("")) {
                    self.held.push(e.clone());
                    return vec![json!({"hold": e["cursor"]})];
                }
                vec![self.open(e)]
            }
            "mls" => {
                let group = s(&e["group"]);
                if self.is_prejoin(&group, e["epoch"].as_i64().unwrap_or(0)) {
                    return vec![json!({"prejoin": e["seq"]})];
                }
                self.step(&json!({"sent": e}))
            }
            "sent" => {
                if e["object"] == "receipt" || e["object"] == "call-event" {
                    // spec-gap 68: the read watermark a device sends is archived, so a device added later knows where
                    // its user had read (M§10.3, M§10.5); like any archived receipt it is state, not a timeline entry;
                    // a call event too, sent or received (spec-gap 63)
                    let id = s(&e["id"]);
                    if !self.applied.insert(id.clone()) {
                        return vec![json!({"duplicate": id})];
                    }
                    return match self.current_akid() {
                        Some(akid) => vec![json!({"archive": {"group": e["group"], "seq": e["seq"], "akid": akid}})],
                        None => vec![],
                    };
                }
                self.show_from_mls(e)
            }
            _ => vec![],
        }
    }

    /// Snapshot compared by the vectors, and what a device persists: timeline in (group, seq) order, held cursors,
    /// current key id.
    pub fn snapshot(&self) -> Value {
        let mut order: Vec<(&String, &(String, i64))> = self.shown.iter().collect();
        order.sort_by(|a, b| a.1.cmp(b.1));
        json!({"timeline": order.iter().map(|(k, _)| k).collect::<Vec<_>>(),
               "held": self.held.iter().map(|h| h["cursor"].clone()).collect::<Vec<_>>(), "current_akid": self.current_akid()})
    }
}

/// What a committing device does with the hub's answer to its commit.
///
/// Spec: M§6.5 — a member applies its commit only with the hub's `accepted`; on `mailbox.commit-conflict` it syncs,
/// processes the winning commit and re-proposes if still needed; §15.3 — an unknown `mailbox` condition is re-synced,
/// retried once, then surfaced.
///
/// Impl (spec-gap 58): `mailbox.stale-epoch` is handled like a conflict; re-proposal is bounded at `max_attempts`
/// proposals in all (3); any other refusal is discarded and surfaced without retry. Spec: M§7.4 — Impl (spec-gap 60):
/// `mailbox.unknown-group` is retried like a conflict when the sync shows the group moved to another hub, and surfaced
/// otherwise.
#[derive(Debug, Clone)]
pub struct CommitRetry {
    max_attempts: i64,
    attempt: i64,
    state: &'static str,
    unknown_retry_used: bool,
    last_reason: Option<String>,
}

impl CommitRetry {
    /// A retry machine from a vector `context` (`max_attempts`, default 3).
    pub fn new(ctx: &Value) -> CommitRetry {
        CommitRetry { max_attempts: ctx["max_attempts"].as_i64().unwrap_or(3), attempt: 1, state: "pending", unknown_retry_used: false, last_reason: None }
    }

    fn surface(&mut self, reason: &str) -> Vec<Value> {
        self.state = "surfaced";
        vec![json!({"discard": {}}), json!({"surface": reason})]
    }

    /// The hub answered: `reason` is `None` for `accepted`.
    pub fn answer(&mut self, reason: Option<&str>) -> Vec<Value> {
        self.last_reason = reason.map(String::from);
        let Some(reason) = reason else {
            self.state = "merged";
            return vec![json!({"merge": {}})];
        };
        if matches!(reason, "mailbox.commit-conflict" | "mailbox.stale-epoch" | "mailbox.unknown-group") {
            if self.attempt >= self.max_attempts {
                return self.surface(reason);
            }
        } else if reason.split('.').next() == Some("mailbox")
            && !REASONS.iter().any(|(t, _)| *t == reason)
            && !self.unknown_retry_used
            && self.attempt < self.max_attempts
        {
            // §15.3 mailbox fallback: re-sync, retry once, then surface — inside M§6.5's bound of three proposals
            self.unknown_retry_used = true;
        } else {
            return self.surface(reason);
        }
        self.state = "syncing";
        vec![json!({"discard": {}}), json!({"sync": {}})]
    }

    /// The device has synced past the winning commit; `still_needed` says whether the operation remains to be done, and
    /// `hub_moved` whether the sync showed the group moved to another hub (M§7.4).
    pub fn synced(&mut self, still_needed: bool, hub_moved: bool) -> Vec<Value> {
        if self.last_reason.as_deref() == Some("mailbox.unknown-group") && !hub_moved {
            self.state = "surfaced"; // spec-gap 60: no move, so unknown-group is final
            return vec![json!({"surface": "mailbox.unknown-group"})];
        }
        if !still_needed {
            self.state = "done";
            return vec![json!({"done": "no-longer-needed"})];
        }
        self.attempt += 1;
        self.state = "pending";
        vec![json!({"repropose": {"attempt": self.attempt}})]
    }

    /// Apply one trace event (`answer`, `synced`).
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        if let Some(a) = ev.get("answer") {
            return self.answer(a["reason"].as_str());
        }
        self.synced(ev["synced"]["still_needed"].as_bool().unwrap_or(true), ev["synced"]["hub_moved"].as_bool().unwrap_or(false))
    }

    /// Snapshot compared by the vectors.
    pub fn snapshot(&self) -> Value {
        json!({"attempt": self.attempt, "state": self.state})
    }
}
