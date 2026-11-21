//! Stateless semantic checks (stages 12–14).
//!
//! Spec: §11 (version), §13.2/§20.5 (relay `hello` anti-splicing), §14.2
//! (selection ⊆ offer), §9.3 (subscription lifetime caps), §19.4
//! (introduction size, grant references an introduction), §15.1/§14.3/§12.10/§22.2
//! (registry membership with fallback), §7.5 (`key-rotation`: `from` = `subject`,
//! `next` ≠ `previous`, signer = `previous` unless `recovery`), P§3 (a `presence` record's `device` is its signer),
//! P§5 (an unknown presence state is shown as `available`), P§12.2 (a sealed record names `presence/0.2` and a `kid` for
//! its audience). Schema README checks 5, 7, 9, 11, 12.

use serde_json::{Map, Value};

use dsip_core::registry::{
    effective_answered_by, effective_integrity, effective_presence_state, effective_progress_status, resolve_reason,
    INTEGRITY_MODES, PRESENCE_STATES, REASON_BEARING_TYPES, SUBSCRIPTION_EVENTS,
};
use dsip_core::version::{check_version, Supported};
use dsip_core::{RejectCode, Verdict};

use crate::validate::validate;

/// Receiver context for the stateless checks.
#[derive(Debug, Default, Clone)]
pub struct SemanticContext {
    /// Supported versions.
    pub supported: Supported,
    /// The id of the client `hello` this connection sent (relay `hello` anti-splicing).
    pub sent_hello_id: Option<String>,
    /// The offer (`media`, `transports`) an `answer` must select from.
    pub offer: Option<Value>,
    /// Pending introduction ids a `grant` may reference; `None` skips the check.
    pub known_introductions: Option<Vec<String>>,
    /// Live grants held from the signer's identity, which a `grant` may follow instead of an introduction (§19.4,
    /// spec-gap 150); consulted only with `known_introductions`.
    pub held_grants: Vec<String>,
    /// Encoded envelope size in bytes, when known (introduction cap).
    pub encoded_size: Option<usize>,
    /// The `kid` that signed the envelope, when known (`key-rotation` signer rule, §7.5).
    pub signer_kid: Option<String>,
    /// The addressee's X25519 key agreement secret: with it the receiver opens sealed bodies (stage 12b, §10.4).
    pub unseal_key: Option<[u8; 32]>,
    /// This receiver only routes: it never opens a seal, and `sealed-body/1.0` is no critical-extension failure
    /// for it — that rule binds the addressee (§10.4).
    pub router: bool,
}

impl SemanticContext {
    /// From a vector's `context` object.
    pub fn from_vector(ctx: &Value) -> SemanticContext {
        SemanticContext {
            supported: Supported::from_json(ctx.get("supported")),
            sent_hello_id: ctx.get("sent_hello_id").and_then(Value::as_str).map(String::from),
            offer: ctx.get("offer").filter(|o| o.is_object()).cloned(),
            known_introductions: ctx.get("known_introductions").and_then(Value::as_array).map(|a| {
                a.iter().filter_map(Value::as_str).map(String::from).collect()
            }),
            held_grants: ctx
                .get("held_grants")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                .unwrap_or_default(),
            encoded_size: ctx.get("encoded_size").and_then(Value::as_u64).map(|n| n as usize),
            signer_kid: ctx.get("signer_kid").and_then(Value::as_str).map(String::from),
            unseal_key: ctx.get("unseal_key_hex").and_then(Value::as_str).and_then(|h| {
                let b: Vec<u8> = (0..h.len()).step_by(2).map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok()).collect::<Option<_>>()?;
                b.try_into().ok()
            }),
            router: ctx.get("router").and_then(Value::as_bool).unwrap_or(false),
        }
    }
}

/// Impl (spec-gap 9): SDP-style offer→answer direction compatibility.
fn direction_answers(offered: &str, selected: &str) -> bool {
    matches!(
        (offered, selected),
        ("sendrecv", _) | ("sendonly", "recvonly" | "inactive") | ("recvonly", "sendonly" | "inactive") | ("inactive", "inactive")
    ) && ["sendrecv", "sendonly", "recvonly", "inactive"].contains(&selected)
}

/// Check 9: is `selection` (an `answer`) a subset of `offer`?
///
/// Spec: §14.2 — an answer is a selection, not a second offer. Impl (spec-gap 9)
/// for the per-field rule: match descriptors on `type`+`purpose`; codec ids ⊆
/// offered; direction answers the offered direction; transport id ∈ offered.
pub fn selection_is_subset(selection: &Value, offer: &Value) -> bool {
    let arr = |v: &Value, k: &str| v.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(String::from);
    let offered_media = arr(offer, "media");
    for sel in arr(selection, "media") {
        let Some(m) = offered_media.iter().find(|o| s(o, "type") == s(&sel, "type") && s(o, "purpose") == s(&sel, "purpose"))
        else {
            return false;
        };
        let offered_codecs: Vec<_> = arr(m, "codecs").iter().filter_map(|c| s(c, "id")).collect();
        if arr(&sel, "codecs").iter().any(|c| !s(c, "id").is_some_and(|id| offered_codecs.contains(&id))) {
            return false;
        }
        if !direction_answers(&s(m, "direction").unwrap_or_default(), &s(&sel, "direction").unwrap_or_default()) {
            return false;
        }
    }
    let offered_transports: Vec<_> = arr(offer, "transports").iter().filter_map(|t| s(t, "id")).collect();
    arr(selection, "transports").iter().all(|t| s(t, "id").is_some_and(|id| offered_transports.contains(&id)))
}

/// Stage 14: the stateless semantic checks, then registry effects on accept.
pub fn check_semantic(payload: &Value, ctx: &SemanticContext) -> Verdict {
    let t = payload.get("type").and_then(Value::as_str).unwrap_or("");
    let s = |k: &str| payload.get(k).and_then(Value::as_str);
    if t == "hello" {
        if let (Some(irt), Some(sent)) = (s("in_reply_to"), ctx.sent_hello_id.as_deref()) {
            if irt != sent {
                // §13.2 / §20.5: the relay hello is bound to the client hello it answers
                return Verdict::reject(RejectCode::HelloInReplyToMismatch);
            }
        }
    }
    if t == "answer" {
        if let Some(offer) = &ctx.offer {
            if !selection_is_subset(payload, offer) {
                return Verdict::reject(RejectCode::SelectionNotSubset);
            }
        }
    }
    if t == "subscribe" {
        let expires_in = payload.get("expires_in").and_then(Value::as_i64).unwrap_or(0);
        for ev in payload.get("events").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            if let Some((_, cap)) = SUBSCRIPTION_EVENTS.iter().find(|(e, _)| *e == ev) {
                if expires_in > *cap {
                    // §9.3 hard caps → `error policy.subscription-lifetime` (v0.7, spec-gap 19)
                    return Verdict::reject_with(RejectCode::SubscriptionLifetimeExceeded, "policy.subscription-lifetime");
                }
            }
        }
    }
    if t == "introduction" {
        if let Some(size) = ctx.encoded_size {
            // §19.4: 4,096, or 16,384 with `sealed` and profile-card/1.0 listed (spec-gap 186)
            if size > dsip_core::profile_card::introduction_cap(payload) {
                return Verdict::reject(RejectCode::IntroductionTooLarge);
            }
        }
        if payload.get("purpose").is_some() && payload.get("sealed").is_some() {
            return Verdict::reject(RejectCode::IntroductionPurposeAndSealed); // §19.4 (v0.8, spec-gap 36): sealed replaces purpose
        }
    }
    if t == "delegation-revocation" {
        // §7.4 (v0.8, spec-gap 57): only the identity revokes its own devices' delegations, with its own key
        if s("subject") != s("from") {
            return Verdict::reject(RejectCode::RevocationSubjectMismatch);
        }
        if let Some(signer) = ctx.signer_kid.as_deref() {
            if Some(signer.split('#').next().unwrap_or("")) != s("subject") {
                return Verdict::reject(RejectCode::RevocationSignerNotSubject);
            }
        }
    }
    if t == "grant" {
        if let Some(known) = &ctx.known_introductions {
            // §19.4: an introduction we sent, or (spec-gap 150) a live grant held from the signer that this one follows
            if !s("session").is_some_and(|sid| known.iter().chain(&ctx.held_grants).any(|k| k == sid)) {
                return Verdict::reject(RejectCode::GrantUnknownIntroduction);
            }
        }
    }
    if t == "presence" && payload.get("device").is_some() && s("device") != s("from") {
        // P§3 (v0.17, spec-gap 135): a record describes the device that signs it
        return Verdict::reject_with(RejectCode::PresenceSignerMismatch, "presence.signer-mismatch");
    }
    if t == "presence" && payload.get("sealed_state").is_some() {
        // P§12.2 (v0.17, spec-gaps 152, 157): a sealed record names presence/0.2, and its kid is for its audience
        use dsip_core::presence_seal::{kid_scope, MAIN, PROFILE};
        let names_profile = payload["dsip"]["profiles"].as_array().is_some_and(|p| p.iter().any(|p| p == PROFILE));
        let audience = s("audience");
        if !names_profile || audience == Some(MAIN) || s("kid").map(kid_scope) != Some(audience.unwrap_or(MAIN)) {
            return Verdict::reject_with(RejectCode::PresenceSealedInvalid, "presence.sealed-invalid");
        }
    }
    if t == "key-rotation" {
        // §7.5 (v0.7, spec-gap 22): only the identity rotates its own keys, by its retiring key
        // unless a recovery key signs with `recovery: true`.
        if s("subject") != s("from") {
            return Verdict::reject(RejectCode::RotationSubjectMismatch);
        }
        if s("next") == s("previous") {
            return Verdict::reject(RejectCode::RotationNextSameAsPrevious);
        }
        let recovery = payload.get("recovery").and_then(Value::as_bool).unwrap_or(false);
        if let Some(signer) = ctx.signer_kid.as_deref() {
            if !recovery && Some(signer) != s("previous") {
                return Verdict::reject(RejectCode::RotationSignerNotPrevious);
            }
        }
    }
    let mut v = Verdict::accept();
    for (k, val) in registry_effects(payload) {
        v = v.with(&k, val);
    }
    v
}

/// Check 5 — registry membership with fallback. Never rejects; yields `effective` and `warnings`.
///
/// Spec: §15.1, §14.3, §12.10.
pub fn registry_effects(payload: &Value) -> Map<String, Value> {
    let t = payload.get("type").and_then(Value::as_str).unwrap_or("");
    let mut eff = Map::new();
    let mut warnings: Vec<Value> = vec![];
    if let Some(reason) = payload.get("reason").and_then(Value::as_str) {
        if REASON_BEARING_TYPES.contains(&t) || t == "notify" {
            let r = resolve_reason(reason, t);
            eff.insert("reason".into(), r.effective.into());
            eff.insert("fallback".into(), r.fallback.into());
            if !r.valid_on_type {
                warnings.push("reason-not-valid-on-type".into()); // Impl (spec-gap 10)
            }
        }
    }
    if (t == "answer" || t == "update") && payload.get("answered_by").is_some() {
        if let Some(a) = payload.get("answered_by").and_then(Value::as_str) {
            eff.insert("answered_by".into(), effective_answered_by(a).into());
        }
    }
    if t == "progress" {
        if let Some(st) = payload.get("status").and_then(Value::as_str) {
            eff.insert("status".into(), effective_progress_status(st).into());
        }
    }
    if t == "presence" {
        if let Some(st) = payload.get("state").and_then(Value::as_str) {
            // P§5 (spec-gap 136): an unknown state is accepted and shown as available
            eff.insert("state".into(), effective_presence_state(st).into());
            if !PRESENCE_STATES.contains(&st) {
                warnings.push("presence-state-unknown".into());
            }
        }
    }
    if t == "publish" {
        if let Some(m) = payload.get("integrity").and_then(Value::as_str) {
            eff.insert("integrity".into(), effective_integrity(Some(m)).into());
            if !INTEGRITY_MODES.contains(&m) {
                warnings.push("integrity-mode-unknown".into()); // §22.2 registry fallback
            }
        }
    }
    let mut out = Map::new();
    if !eff.is_empty() {
        out.insert("effective".into(), Value::Object(eff));
    }
    if !warnings.is_empty() {
        out.insert("warnings".into(), Value::Array(warnings));
    }
    out
}

/// Stages 12–14 in order: version, sealed body (12b, §10.4), schema, semantic.
///
/// An addressee holding `unseal_key` opens `sealed` and runs 13–14 on the merged payload, reporting the opened
/// keys as `effective.sealed`; a router validates the clear part as it stands.
pub fn check_payload(payload: &Value, ctx: &SemanticContext) -> Verdict {
    let sealed = payload.get("sealed").is_some();
    let mut supported = ctx.supported.clone();
    if ctx.router && sealed && !supported.extensions.iter().any(|e| e == crate::sealed::EXT) {
        // §10.4: a router routes a sealed payload whether or not it implements the extension
        supported.extensions.push(crate::sealed::EXT.to_string());
    }
    let v = check_version(payload, &supported);
    if !v.ok() {
        return v;
    }
    let (payload, opened) = match ctx.unseal_key.filter(|_| sealed && !ctx.router) {
        Some(sk) => match crate::sealed::open(payload, &sk) {
            Ok(x) => x,
            Err(v) => return v,
        },
        None => (payload.clone(), vec![]),
    };
    let v = validate(&payload);
    if !v.ok() {
        return v;
    }
    let mut v = check_semantic(&payload, ctx);
    if v.ok() && !opened.is_empty() {
        let eff = v.extra.entry("effective").or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(m) = eff {
            m.insert("sealed".into(), opened.into());
        }
    }
    v
}
