//! Whom a mailbox service serves, and when an enrolment ends.
//!
//! Spec: M§4.1 ("Whom a mailbox serves", "When an enrolment ends"), M§4.4 (a registered device completed a verified
//! `hello` within `mls_retention_s`), M§5.7 (`release`, `admission`), M§16 (`mailbox.not-served`, `mailbox.not-enrolled`,
//! `mailbox.admission-required`, `mailbox.admission-refused`).
//!
//! Impl: pinned by the `enrolment-trace` vectors (spec-gaps 115, 130, 164; admission codes, 185). The machine decides; the host acts on what it
//! emits: `enrolled` creates the identity's mailbox, `released` deletes everything held for it and closes its bindings.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hub::MLS_RETENTION_S;

/// The service's view of the identities it serves: configured ones, and those enrolled within the operator's bound.
///
/// Spec: M§4.1. Configured identities are always served and never count against the bound. Any other identity enrols
/// with its first owner operation while fewer than `serve_any` are enrolled; past the bound its owner operations are
/// refused `mailbox.not-served`. An enrolment ends by `mailbox-config` `release: true` (a configured identity is refused
/// `mailbox.not-enrolled`), by its operator (spec-gap 164) or, when the operator chose idle expiry (a MAY), once no
/// device of the identity has completed a verified `hello` within `mls_retention_s` (M§4.4).
#[derive(Debug, Clone)]
pub struct Enrolment {
    now: i64,
    configured: Vec<String>,
    serve_any: usize,
    expire_idle: bool,
    retention: i64,
    /// Enrolled identities in enrolment order, each with the time of its last verified `hello`.
    enrolled: Vec<(String, i64)>,
    /// The admission codes issued, in issue order, where the mailbox enrols only by code (spec-gap 185); else `None`.
    codes: Option<Vec<(String, AdmissionCode)>>,
}

/// An admission code the operator issued: what is left of it.
///
/// Spec: M§4.1 "Admission codes" (spec-gap 185) — single-use unless issued for more, expiring when the operator says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionCode {
    /// Enrolments it still admits.
    pub uses: u32,
    /// Valid while the clock is before it, seconds; `None`, it does not expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl Enrolment {
    /// A machine from a vector `context`: `now`, `configured`, `serve_any` (default 0: enrolment closed),
    /// `expire_idle` (default false), `mls_retention_s` (default [`MLS_RETENTION_S`]), and `admission`, the codes issued
    /// (`[{code, uses?, expires_at?}]`; present, even empty, the mailbox enrols only by code).
    pub fn new(ctx: &Value) -> Enrolment {
        let codes = ctx.get("admission").map(|a| {
            a.as_array()
                .into_iter()
                .flatten()
                .map(|c| {
                    let code = AdmissionCode { uses: c["uses"].as_u64().unwrap_or(1) as u32, expires_at: c["expires_at"].as_i64() };
                    (c["code"].as_str().unwrap_or_default().to_string(), code)
                })
                .collect()
        });
        Enrolment {
            now: ctx["now"].as_i64().unwrap_or(0),
            configured: ctx["configured"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect(),
            serve_any: ctx["serve_any"].as_u64().unwrap_or(0) as usize,
            expire_idle: ctx["expire_idle"].as_bool().unwrap_or(false),
            retention: ctx["mls_retention_s"].as_i64().unwrap_or(MLS_RETENTION_S),
            enrolled: vec![],
            codes,
        }
    }

    /// Whether the mailbox enrols only by admission code (its `hello` says `enrolment: "admission"`, M§4.3).
    pub fn admits_by_code(&self) -> bool {
        self.codes.is_some()
    }

    /// Enrol only by admission code from now on (spec-gap 185); the codes issued so far stay.
    pub fn require_admission(&mut self) {
        self.codes.get_or_insert_with(Vec::new);
    }

    /// Issue `code` for `uses` enrolments, until `expires_at` if given; an earlier code with the same string is replaced.
    /// The mailbox enrols only by code from then on.
    pub fn issue_code(&mut self, code: &str, uses: u32, expires_at: Option<i64>) {
        let codes = self.codes.get_or_insert_with(Vec::new);
        codes.retain(|(c, _)| c != code);
        codes.push((code.to_string(), AdmissionCode { uses, expires_at }));
    }

    /// Withdraw `code`; true if it was issued.
    pub fn revoke_code(&mut self, code: &str) -> bool {
        let Some(codes) = self.codes.as_mut() else { return false };
        let before = codes.len();
        codes.retain(|(c, _)| c != code);
        codes.len() != before
    }

    /// The codes issued, in issue order, with what is left of each: what a host saves across a restart.
    pub fn codes(&self) -> &[(String, AdmissionCode)] {
        self.codes.as_deref().unwrap_or_default()
    }

    /// Take back what [`Enrolment::codes`] gave, after a restart. Whether the mailbox enrols by code stays the host's
    /// current configuration: codes restored where it no longer does are kept for when it does again.
    pub fn restore_codes(&mut self, codes: Vec<(String, AdmissionCode)>) {
        if let Some(c) = self.codes.as_mut() {
            *c = codes;
        }
    }

    /// Whether `identity` is served now: configured or enrolled.
    pub fn serves(&self, identity: &str) -> bool {
        self.configured.iter().any(|c| c == identity) || self.enrolled.iter().any(|(e, _)| e == identity)
    }

    /// The enrolled identities, in enrolment order.
    pub fn enrolled(&self) -> Vec<String> {
        self.enrolled.iter().map(|(e, _)| e.clone()).collect()
    }

    /// An owner operation (`sync`, `key-packages`, `mailbox-config` without `release`) on a verified binding, carrying
    /// no admission code.
    ///
    /// Spec: M§4.1 — enrols within the bound, else `mailbox.not-served`.
    pub fn owner_op(&mut self, identity: &str, device: &str, id: &str) -> Vec<Value> {
        self.owner_op_admitted(identity, device, id, None)
    }

    /// An owner operation carrying `admission`, the code of a `mailbox-config` (M§5.7), if any.
    ///
    /// Spec: M§4.1 "Admission codes" (spec-gap 185) — a served identity: nothing, its code ignored. Otherwise the bound
    /// first (`mailbox.not-served`, no code looked at); where the mailbox enrols by code, none is
    /// `mailbox.admission-required`, one not issued, used up or expired (the clock at or past `expires_at`)
    /// `mailbox.admission-refused`; else the identity enrols and the code has one use fewer.
    pub fn owner_op_admitted(&mut self, identity: &str, device: &str, id: &str, admission: Option<&str>) -> Vec<Value> {
        if self.serves(identity) {
            return vec![];
        }
        if self.enrolled.len() >= self.serve_any {
            return error(device, id, "mailbox.not-served");
        }
        let now = self.now;
        if let Some(codes) = self.codes.as_mut() {
            let Some(code) = admission else { return error(device, id, "mailbox.admission-required") };
            let valid = |c: &AdmissionCode| c.uses > 0 && c.expires_at.is_none_or(|t| now < t);
            let Some((_, c)) = codes.iter_mut().find(|(k, c)| k == code && valid(c)) else {
                return error(device, id, "mailbox.admission-refused");
            };
            c.uses -= 1;
        }
        // enrolment happens on a verified binding: it counts as a hello
        self.enrolled.push((identity.to_string(), self.now));
        vec![json!({"enrolled": {"identity": identity}})]
    }

    /// `mailbox-config` with `release: true`.
    ///
    /// Spec: M§4.1, M§5.7 — `accepted`, then `released`; a configured identity is refused `mailbox.not-enrolled`, and
    /// one not served `mailbox.not-served` (a release never enrols).
    pub fn release(&mut self, identity: &str, device: &str, id: &str) -> Vec<Value> {
        if self.configured.iter().any(|c| c == identity) {
            return error(device, id, "mailbox.not-enrolled");
        }
        let Some(i) = self.enrolled.iter().position(|(e, _)| e == identity) else {
            return error(device, id, "mailbox.not-served");
        };
        self.enrolled.remove(i);
        vec![
            json!({"accepted": {"to": device, "in_reply_to": id}}),
            json!({"released": {"identity": identity, "cause": "owner"}}),
        ]
    }

    /// The operator ends `identity`'s enrolment (`dsip-mailbox admin release`): its place is free at once.
    ///
    /// Spec: M§4.1 "By its operator" (spec-gap 164) — the same effects as a release, with nothing sent: `released`
    /// with cause `operator`. A configured identity is not ended this way (it leaves by the configuration), and one not
    /// enrolled emits nothing.
    pub fn operator_release(&mut self, identity: &str) -> Vec<Value> {
        let Some(i) = self.enrolled.iter().position(|(e, _)| e == identity) else { return vec![] };
        self.enrolled.remove(i);
        vec![json!({"released": {"identity": identity, "cause": "operator"}})]
    }

    /// Whether `identity` is one of the operator's configured identities.
    pub fn is_configured(&self, identity: &str) -> bool {
        self.configured.iter().any(|c| c == identity)
    }

    /// A verified `hello` of a device of `identity`.
    ///
    /// Spec: M§4.4 — the device is registered again for `mls_retention_s`. A binding alone enrols nothing (M§4.1).
    pub fn hello(&mut self, identity: &str) -> Vec<Value> {
        let now = self.now;
        if let Some((_, seen)) = self.enrolled.iter_mut().find(|(e, _)| e == identity) {
            *seen = now;
        }
        vec![]
    }

    /// Time passes; with idle expiry, enrolled identities without a registered device are released.
    ///
    /// Spec: M§4.1, M§4.4 — registered while the last `hello` is within `mls_retention_s`, so at exactly the bound the
    /// enrolment stays. Released in enrolment order.
    pub fn advance(&mut self, n: i64) -> Vec<Value> {
        self.now += n;
        if !self.expire_idle {
            return vec![];
        }
        let now = self.now;
        let retention = self.retention;
        let (idle, kept): (Vec<_>, Vec<_>) = self.enrolled.drain(..).partition(|(_, seen)| now - seen > retention);
        self.enrolled = kept;
        idle.into_iter().map(|(e, _)| json!({"released": {"identity": e, "cause": "idle"}})).collect()
    }

    /// The enrolled identities with the time of each one's last verified `hello`, in enrolment order: what a host
    /// saves to keep enrolments across a restart.
    pub fn entries(&self) -> &[(String, i64)] {
        &self.enrolled
    }

    /// Take back what [`Enrolment::entries`] gave, after a restart; the configuration stays the host's current one.
    pub fn restore_entries(&mut self, entries: Vec<(String, i64)>) {
        self.enrolled = entries;
    }

    /// The machine's clock, seconds.
    pub fn now(&self) -> i64 {
        self.now
    }

    /// Apply one trace event (`owner_op`, `release`, `operator_release`, `hello`, `advance`).
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        let Some((name, e)) = ev.as_object().and_then(|o| o.iter().next()) else { return vec![] };
        let s = |k: &str| e[k].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "owner_op" => self.owner_op_admitted(&s("identity"), &s("device"), &s("id"), e["admission"].as_str()),
            "release" => self.release(&s("identity"), &s("device"), &s("id")),
            "operator_release" => self.operator_release(&s("identity")),
            "hello" => self.hello(&s("identity")),
            "advance" => self.advance(e.as_i64().unwrap_or(0)),
            _ => vec![],
        }
    }

    /// `{enrolled, free}`: the enrolled identities in enrolment order, and the places left in the bound; where the
    /// mailbox enrols by code, `codes` too: each code's uses left.
    pub fn snapshot(&self) -> Value {
        let mut snap = json!({"enrolled": self.enrolled(), "free": self.serve_any.saturating_sub(self.enrolled.len())});
        if let Some(codes) = &self.codes {
            snap["codes"] = codes.iter().map(|(k, c)| (k.clone(), json!(c.uses))).collect::<serde_json::Map<_, _>>().into();
        }
        snap
    }
}

fn error(to: &str, id: &str, reason: &str) -> Vec<Value> {
    vec![json!({"error": {"to": to, "in_reply_to": id, "reason": reason}})]
}
