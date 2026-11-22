//! A phone's presence: this device's record, published to its relay, and the identities it watches, each through the
//! relay that answers for it.
//!
//! Spec: P§3 (records to the authority; the subscriber verifies each itself), P§4 (several devices combined), P§5
//! (states), P§6 (the grants held from a target admit its watcher), P§8 (refresh and the publish interval), P§9 (a
//! refusal), §9.3 (subscribe, notify, a `reject` that looks the same for unknown and not allowed, renewal before
//! `expires_in`), §8.1 (a target's relay from its hint), P§12.2 (a sealed scope's records sealed at its epoch), P§12.4
//! (watches list `presence/0.2`; sealed records open with the keys our grants carried), P§12.5 (a sealing device
//! watches its own identity for its siblings' epochs, and sends its record again under a new key).
//!
//! Impl: a watch whose subscription is refused, or whose relay drops us, is tried again after [`RETRY_S`]. The own
//! watch is not shown unless the host watches its own identity too. An authority that keeps one subscription per
//! subscriber identity (spec-gap 177) lets only the last of an identity's devices to subscribe hold it, so a sibling's
//! epoch reaches that device alone.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};

use dsip_broadcast::presence::{Publisher, Watch};
use dsip_transport::agent::Agent;
use dsip_transport::now_s;

/// §9.3: the presence event class's cap on `expires_in`; a watch is renewed [`RENEW_EARLY_S`] before it lapses.
pub(crate) const SUBSCRIBE_S: i64 = 3600;
const RENEW_EARLY_S: i64 = 300;
/// How long a refused or unanswered watch waits before it is asked again.
pub(crate) const RETRY_S: i64 = 60;
/// How long this device's records live; [`Publisher`] refreshes them before they lapse (P§8).
const LIFETIME_S: i64 = 300;
/// The ids of the records sent, kept to tell the authority's refusal of one (P§9) from other errors.
const SENT_KEPT: usize = 32;

/// One identity watched.
struct Watched {
    /// The relay its hint names, when not ours.
    via: Option<String>,
    /// The subscription's id, once asked.
    sub: Option<String>,
    watch: Watch,
    /// When to subscribe (again): `0` at once.
    due: i64,
    /// Shown in [`crate::Phone::presence`]: the host watches it (not only the own watch, P§12.5).
    shown: bool,
    /// The last `valid_until` among the grants the subscription presented (P§6); `None`: it presented none.
    presented_until: Option<i64>,
}

/// The last `valid_until` among `claims` (the `dsip-grant` claims of a subscribe, P§6).
fn last_valid_until(claims: &[Value]) -> Option<i64> {
    claims
        .iter()
        .filter_map(|c| dsip_core::b64::decode(c["grant"]["payload"].as_str()?))
        .filter_map(|p| serde_json::from_slice::<Value>(&p).ok()?["valid_until"].as_i64())
        .max()
}

pub(crate) struct Presence {
    publisher: Option<Publisher>,
    /// The state the user picked (`None`: automatic, no record).
    state: Option<String>,
    watched: HashMap<String, Watched>,
    sent: VecDeque<String>,
    /// Our siblings' records from the own watch, verified, for the engine to read their epochs (P§12.5).
    siblings: Vec<Value>,
    shown: watch::Sender<BTreeMap<String, crate::Presence>>,
    /// The shares that ended early, for the host ([`crate::Phone::share_ended`]).
    ended: mpsc::UnboundedSender<crate::ShareEnded>,
}

impl Presence {
    pub(crate) fn new(shown: watch::Sender<BTreeMap<String, crate::Presence>>, ended: mpsc::UnboundedSender<crate::ShareEnded>) -> Presence {
        Presence { publisher: None, state: None, watched: HashMap::new(), sent: VecDeque::new(), siblings: vec![], shown, ended }
    }

    /// Whether anything needs the clock: a record to refresh, or a watch.
    pub(crate) fn active(&self) -> bool {
        self.state.is_some() || !self.watched.is_empty()
    }

    /// Bound (again) to our relay, the authority (P§3): our record goes to it, and the watches there are asked again
    /// (a relay that dropped us forgot them).
    pub(crate) async fn bound(&mut self, agent: &mut Agent) {
        let now = now_s();
        let authority = agent.relay().did.clone();
        let out = match self.publisher.as_mut() {
            Some(p) => p.rebind(&authority, now),
            None if self.state.is_some() => {
                let mut p = Publisher::new(agent.identity_did(), agent.device_did(), &authority, LIFETIME_S);
                p.set(self.state.as_deref(), now);
                let out = p.rebind(&authority, now);
                self.publisher = Some(p);
                out
            }
            None => None,
        };
        self.send(agent, out).await;
        if agent.presence_sealed(None) {
            // P§12.5: our own identity, admitted by P§6 rule 1, shows the epochs our siblings seal at
            let me = agent.identity_did().to_string();
            self.watched.entry(me.clone()).or_insert_with(|| Watched { via: None, sub: None, watch: Watch::new(&me), due: 0, shown: false, presented_until: None });
        }
        for w in self.watched.values_mut().filter(|w| w.via.is_none()) {
            w.due = 0;
        }
    }

    /// The user picked `state` (`None`: automatic; the last record lapses at its `expires_at`). P§3, P§5.
    pub(crate) async fn set(&mut self, agent: &mut Agent, state: Option<String>) {
        self.state = state;
        if self.publisher.is_none() {
            return self.bound(agent).await;
        }
        let out = self.publisher.as_mut().and_then(|p| p.set(self.state.as_deref(), now_s()));
        self.send(agent, out).await;
    }

    /// Watch `target`, through the relay at `via` when its hint names one other than ours.
    pub(crate) fn watch(&mut self, agent: &mut Agent, target: String, via: Option<String>) {
        if let Some(url) = &via {
            agent.keep_peer(url, true);
        }
        let old = self.watched.insert(target.clone(), Watched { via, sub: None, watch: Watch::new(&target), due: 0, shown: true, presented_until: None });
        if let Some(url) = old.and_then(|o| o.via) {
            self.release(agent, &url);
        }
    }

    /// Stop watching `target`: nothing more is shown for it (its subscription lapses at the authority).
    pub(crate) fn unwatch(&mut self, agent: &mut Agent, target: &str) {
        if target == agent.identity_did() && agent.presence_sealed(None) {
            // the own watch stays (P§12.5), unshown
            if let Some(w) = self.watched.get_mut(target) {
                w.shown = false;
            }
        } else if let Some(url) = self.watched.remove(target).and_then(|w| w.via) {
            self.release(agent, &url);
        }
        self.shown.send_if_modified(|m| m.remove(target).is_some());
    }

    /// A connection kept for watches closes once none goes through it.
    fn release(&self, agent: &mut Agent, url: &str) {
        if !self.watched.values().any(|w| w.via.as_deref() == Some(url)) {
            agent.keep_peer(url, false);
        }
    }

    /// Once a second: records due (P§8), watches to ask or renew, and records that expired since (P§4).
    pub(crate) async fn tick(&mut self, agent: &mut Agent) {
        for record in std::mem::take(&mut self.siblings) {
            if let Err(e) = agent.own_record(&record).await {
                tracing::warn!("a sibling's presence record: {e}");
            }
        }
        let now = now_s();
        for _ in 0..4 {
            let out = self.publisher.as_mut().and_then(|p| p.tick(now));
            if out.is_none() {
                break;
            }
            self.send(agent, out).await;
        }
        let peers = agent.peer_relays();
        let due: Vec<String> = self
            .watched
            .iter_mut()
            .filter_map(|(t, w)| {
                // the relay its hint names dropped us, and the subscription with it: asked again there
                if w.sub.is_some() && w.via.as_ref().is_some_and(|u| !peers.contains(u)) {
                    w.sub = None;
                    w.due = now;
                }
                (now >= w.due).then(|| t.clone())
            })
            .collect();
        for target in due {
            self.subscribe(agent, &target).await;
        }
        self.refresh(agent, now);
    }

    /// Subscribe to `target`'s presence at the relay that answers for it, presenting the grants we hold from it.
    /// Spec: §9.3, P§6.
    async fn subscribe(&mut self, agent: &mut Agent, target: &str) {
        let Some(w) = self.watched.get_mut(target) else { return };
        w.due = now_s() + RETRY_S; // until it is answered, not asked again for a while
        let via = w.via.clone();
        let authority = match &via {
            Some(url) => match agent.relay_at(url).await {
                Ok(did) => did,
                Err(e) => return tracing::info!("presence of {target}: their relay {url} did not bind us ({e}); trying again later"),
            },
            None => agent.relay().did.clone(),
        };
        let supported = dsip_core::version::Supported::all_known();
        // P§12.4: sealed records come too, opened with the keys our grants carried
        let profiles = [dsip_broadcast::PROFILE, dsip_core::presence_seal::PROFILE];
        let mut p = json!({"dsip": dsip_core::version::version_block(&supported, &profiles), "type": "subscribe",
                           "to": authority, "target": target, "events": ["presence"], "expires_in": SUBSCRIBE_S});
        // P§6: presence is private by default; the grants the target gave us admit us
        let claims = agent.presence_claims(target);
        let grants = claims.len();
        let presented_until = last_valid_until(&claims);
        if grants > 0 {
            p["claims"] = Value::Array(claims);
        }
        let frame = match agent.sign(p, 30) {
            Ok(f) => f,
            Err(e) => return tracing::warn!("presence subscribe for {target}: {e}"),
        };
        if let Err(e) = agent.send_frame(&frame, via.as_deref()).await {
            return tracing::info!("presence subscribe for {target}: {e}; trying again later");
        }
        let sub = payload_of(&frame)["id"].as_str().unwrap_or_default().to_string();
        tracing::info!("watching {target} at {} ({grants} grant(s) of theirs presented)", via.as_deref().unwrap_or("our relay"));
        if let Some(w) = self.watched.get_mut(target) {
            // §9.3: a renewal replaces the subscription; the watch follows the new one
            w.sub = Some(sub);
            w.watch = Watch::new(target);
            w.presented_until = presented_until;
            w.due = now_s() + SUBSCRIBE_S - RENEW_EARLY_S;
        }
    }

    /// A verified message: a `notify` for one of our watches, the `reject` of one, or the authority's refusal of one
    /// of our records. Returns whether it was presence's.
    pub(crate) fn received(&mut self, agent: &Agent, payload: &Value) -> bool {
        let now = now_s();
        let t = payload["type"].as_str().unwrap_or("");
        match t {
            "notify" => {
                let Some(sub) = payload["subscription"].as_str() else { return false };
                let Some((target, w)) = self.watched.iter_mut().find(|(_, w)| w.sub.as_deref() == Some(sub)) else { return false };
                if !w.watch.notify(payload, |f| agent.verify_record(f)) {
                    return true; // stale (§9.3)
                }
                if target == agent.identity_did() {
                    // P§12.5: our siblings' records, verified, each signed by the device it is about
                    let frames = payload["body"]["records"].as_array().into_iter().flatten().filter_map(|r| r["frame"].as_str());
                    let me = (agent.identity_did(), agent.device_did());
                    self.siblings.extend(frames.filter_map(|f| agent.verify_record(f)).filter_map(|(rec, identity)| {
                        (identity == me.0 && rec["device"] == rec["from"] && rec["device"] != me.1).then_some(rec)
                    }));
                }
                if w.watch.terminated() {
                    // P§7: the share that admitted us ended, or the subscription did; asked again, and shown again
                    // only if admitted
                    w.sub = None;
                    w.due = now + RETRY_S;
                    let target = target.clone();
                    // §19.4 "Keeping it" (spec-gap 190): ended by policy while a grant it presented still ran, which
                    // is all a grantee sees of that grant's revocation (P§7)
                    if payload["reason"] == "policy.terminated" && w.presented_until.take().is_some_and(|until| until > now) {
                        let _ = self.ended.send(crate::ShareEnded { identity: target.clone() });
                    }
                    self.shown.send_if_modified(|m| m.remove(&target).is_some());
                    return true;
                }
                self.refresh(agent, now);
                true
            }
            "reject" | "error" => {
                if let Some(sub) = payload["session"].as_str().or(payload["in_reply_to"].as_str()) {
                    if let Some((target, w)) = self.watched.iter_mut().find(|(_, w)| w.sub.as_deref() == Some(sub)) {
                        // §9.3: unknown and not allowed look the same; P§6: private unless they granted us
                        tracing::info!("presence of {target}: not available from that relay ({}); trying again later", payload["reason"]);
                        w.sub = None;
                        w.due = now + RETRY_S;
                        let target = target.clone();
                        self.shown.send_if_modified(|m| m.remove(&target).is_some());
                        return true;
                    }
                }
                let refused = payload["in_reply_to"].as_str().is_some_and(|r| self.sent.iter().any(|s| s == r));
                if t == "error" && refused {
                    let reason = payload["reason"].as_str().unwrap_or("");
                    tracing::info!("our presence record was refused: {reason}");
                    if let Some(p) = self.publisher.as_mut() {
                        p.refused(reason, payload["retry_after"].as_i64(), now);
                    }
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    /// Show each watched identity's presence as it is at `now` (P§4: records expire).
    fn refresh(&mut self, agent: &Agent, now: i64) {
        let views: Vec<(String, crate::Presence)> = self
            .watched
            .iter()
            .filter(|(_, w)| w.shown && w.sub.is_some() && w.watch.notified())
            .map(|(t, w)| {
                let (c, unreadable) = w.watch.view(now, |kid| agent.presence_key(t, kid));
                (t.clone(), crate::Presence { state: c.state, token: c.token, source: c.source.to_string(), unreadable: unreadable.len() })
            })
            .collect();
        self.shown.send_if_modified(|m| {
            let mut changed = false;
            for (t, v) in views {
                if m.get(&t) != Some(&v) {
                    m.insert(t, v);
                    changed = true;
                }
            }
            changed
        });
    }

    /// The epoch of `scope` (`main`, or an audience tag) rose: our record for it goes again, sealed under the new key,
    /// so the grantees given that key read us without waiting for the next refresh. Spec: P§12.5, P§8 (the interval may
    /// hold it back; [`Publisher::tick`] sends it then).
    pub(crate) async fn rekeyed(&mut self, agent: &mut Agent, scope: &str) {
        let audience = (scope != dsip_core::presence_seal::MAIN).then_some(scope);
        let now = now_s();
        let out = self.publisher.as_mut().and_then(|p| {
            let state = p.state_for(audience)?.to_string();
            p.set_for(audience, Some(&state), now)
        });
        self.send(agent, out).await;
    }

    async fn send(&mut self, agent: &mut Agent, out: Option<Value>) {
        let Some(p) = out else { return };
        match agent.send_presence(p, LIFETIME_S).await {
            Ok(frame) => {
                self.sent.push_back(payload_of(&frame)["id"].as_str().unwrap_or_default().to_string());
                if self.sent.len() > SENT_KEPT {
                    self.sent.pop_front();
                }
            }
            Err(e) => tracing::warn!("sending our presence record: {e}"),
        }
    }
}

fn payload_of(frame: &str) -> Value {
    dsip_core::envelope::Envelope::from_frame(frame)
        .ok()
        .and_then(|e| dsip_core::b64::decode(&e.payload))
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null)
}
