//! DSIP Core v1.0 registries: reason tokens, `answered_by`, progress status, subscription events, grant scopes.
//!
//! Spec: §15.4 (`dsip-reason`), §15.6 (registry policy: extension-namespaced
//! tokens fall back by category), §14.3 (`dsip-answered-by`), §12.10
//! (`dsip-progress-status`), §9.3 (`dsip-subscription-event`), §19.4
//! (`dsip-grant-scope`).
//!
//! Registries govern *membership*; schemas govern *shape*. Nothing here is a
//! closed enum: unknown-but-well-formed values resolve to the category or
//! receiver fallback, never to a rejection (§15.1, §14.3, §12.10).

/// Message types on which a reason token may be carried, per the §15.4 "valid on" column.
pub const REASON_BEARING_TYPES: &[&str] = &["reject", "cancel", "bye", "error"];

/// The reason categories.
///
/// Spec: §15.1 token grammar; §15.3 fallback behavior. v0.8 adds `mailbox` (spec-gap 38), v0.17 `presence` (P§9,
/// spec-gap 134).
pub const CATEGORIES: &[&str] =
    &["user", "endpoint", "identity", "session", "media", "policy", "transport", "gateway", "mailbox", "presence"];

/// `dsip-reason` registry: (token, valid-on message types).
///
/// Spec: §15.4.
pub const REASONS: &[(&str, &[&str])] = &[
    ("user.declined", &["reject", "bye"]),
    ("user.no-answer", &["reject"]),
    ("user.hangup", &["bye"]),
    ("user.cancelled", &["cancel"]),
    ("user.blocked", &["reject"]),
    ("endpoint.busy", &["reject"]),
    ("endpoint.unavailable", &["reject"]),
    ("endpoint.capability", &["reject"]),
    ("identity.not-in-service", &["reject", "error"]),
    ("identity.moved", &["reject"]),
    ("identity.suspended", &["reject"]),
    ("identity.unknown", &["reject", "error"]),
    ("session.expired", &["reject"]),
    ("session.timeout", &["cancel", "bye"]),
    ("session.glare", &["reject", "cancel"]),
    ("session.answered-elsewhere", &["cancel"]),
    ("session.already-answered", &["bye"]),
    ("session.cancelled", &["bye"]),
    ("session.invalid-state", &["error"]),
    ("session.unknown-session", &["error"]),
    ("session.update-pending", &["error"]),
    ("session.unsupported-core-version", &["reject", "error"]),
    ("session.unsupported-profile-version", &["reject", "error"]),
    ("session.unsupported-critical-extension", &["reject", "error"]),
    ("session.version-downgrade-detected", &["error"]),
    ("session.unsupported-wire-format", &["error"]),
    ("session.failed", &["reject", "bye", "error"]),
    ("media.unsupported", &["reject", "bye"]),
    ("media.offer-required", &["reject"]),
    ("media.encryption-required", &["reject"]),
    ("media.failed", &["bye"]),
    ("policy.trust-insufficient", &["reject"]),
    ("policy.first-contact-required", &["reject"]),
    ("policy.blocked", &["reject", "cancel"]),
    ("policy.terminated", &["bye"]),
    ("policy.recording-declined", &["reject", "bye"]), // Recording Profile C§4 (draft)
    ("policy.rate-limited", &["reject", "error"]),
    ("policy.subscription-lifetime", &["error"]), // v0.7 (spec-gap 19): expires_in above the §9.3 cap
    ("transport.envelope-too-large", &["error"]),
    ("transport.hello-required", &["error"]),
    ("transport.hello-rejected", &["error"]),
    ("transport.routing-refused", &["error"]),
    ("transport.unknown-recipient", &["error"]),
    ("transport.rate-limited", &["error"]),
    ("transport.no-response", &["error"]), // §12.7 rule 6 (spec-gap 76)
    ("transport.replaced", &["error"]), // §13.2: the connection a newer hello replaced (spec-gap 158)
    ("gateway.unreachable", &["reject", "bye", "error"]),
    ("gateway.downgraded", &["error"]),
    ("gateway.mapped", &["reject", "bye", "error"]),
    // v0.8 (spec-gaps 38, 48): the Messaging Profile's mailbox conditions (M§16)
    ("mailbox.commit-conflict", &["error"]),
    ("mailbox.stale-epoch", &["error"]),
    ("mailbox.unknown-group", &["error"]),
    ("mailbox.cursor-invalid", &["error"]),
    ("mailbox.object-too-large", &["error"]),
    ("mailbox.quota-exceeded", &["error"]),
    ("mailbox.no-key-packages", &["error"]),
    ("mailbox.unsupported-class", &["error"]),
    ("mailbox.unsupported-mode", &["error"]),
    ("mailbox.blob-mismatch", &["error"]),
    ("mailbox.hub-unreachable", &["error"]), // v0.8 (spec-gap 72): the mailbox could not reach the group's hub (M§9.4)
    ("mailbox.not-served", &["error"]), // v0.16 (spec-gap 130): an owner operation the mailbox will not serve (M§4.1)
    ("mailbox.not-enrolled", &["error"]), // v0.16 (spec-gap 130): a release for a configured identity (M§4.1)
    ("mailbox.admission-required", &["error"]), // 1.0 (spec-gap 185): no admission code where one is required (M§4.1)
    ("mailbox.admission-refused", &["error"]), // 1.0 (spec-gap 185): a code not issued, used up or expired (M§4.1)
    ("presence.signer-mismatch", &["error"]), // v0.17 (spec-gap 134): the record's device/subject is not its signer's (P§3)
    ("presence.sealed-invalid", &["error"]), // v0.17 (spec-gaps 152, 157): a sealed record without presence/0.2 or a kid for its audience (P§12.2)
    ("presence.lifetime", &["error"]), // v0.17 (spec-gap 134): a record's lifetime outside 60–3,600 s (P§8)
    ("presence.stale", &["error"]), // v0.17 (spec-gap 134): a record not newer than the one held for its device (P§3)
];

/// `dsip-answered-by` registered values. Unknown values render as `service`.
///
/// Spec: §14.3.
pub const ANSWERED_BY: &[&str] = &["user", "service", "screening", "gateway"];

/// `dsip-progress-status` registered values. Unknown values are treated as `trying`.
///
/// Spec: §12.10.
pub const PROGRESS_STATUS: &[&str] = &["trying", "ringing", "queued", "forwarded"];

/// `dsip-subscription-event` registered values with their hard lifetime caps (seconds).
///
/// Spec: §9.3.
pub const SUBSCRIPTION_EVENTS: &[(&str, i64)] = &[("presence", 3_600), ("publication", 86_400)];

/// `dsip-grant-scope` registered values.
///
/// Spec: §19.4; `dsip.message` v0.8 (spec-gap 36).
pub const GRANT_SCOPES: &[&str] = &["dsip.invite", "dsip.subscribe", "dsip.message"];

/// `dsip-delegation-capability` registered values.
///
/// Spec: §7.4 (v0.8, spec-gap 39). Binding any envelope requires `dsip.signaling`; the Messaging Profile's
/// devices carry `dsip.messaging` as well (spec-gap 56).
pub const DELEGATION_CAPABILITIES: &[&str] = &["dsip.signaling", "dsip.media.interactive", "dsip.messaging"];

/// `dsip-revocation-reason` registered values (§7.4, v0.8, spec-gap 57).
pub const REVOCATION_REASONS: &[&str] = &["lost", "compromised", "retired", "policy"];

/// The core message set plus `hello`.
///
/// Spec: §12.1, §13.2.
pub const MESSAGE_TYPES: &[&str] = &[
    "invite", "progress", "answer", "reject", "cancel", "update", "info", "bye", "introduction", "grant",
    "publish", "subscribe", "notify", "unpublish", "error", "hello",
    "provenance", "key-rotation", "reachability-hint", // v0.7: §22.3, §7.5, DHT Hints Profile
    "delegation-revocation",                           // v0.8: §7.4 (spec-gap 57)
    "alias-monitor",                                   // v0.14: Alias Transparency T§8 (spec-gap 124)
    "presence",                                        // v0.17: §9.4 / Presence Profile P§3 (spec-gap 134)
    "grant-revocation",                                // v0.17: §19.4 / P§7 (spec-gap 147)
];

/// `dsip-presence-state` registered values (P§5, v0.17, spec-gap 136). The registry is open: any other well-formed
/// token is accepted and resolves to [`PRESENCE_STATE_FALLBACK`].
pub const PRESENCE_STATES: &[&str] = &["available", "busy", "away", "dnd", "offline"];

/// What an unknown presence state is shown and ranked as (P§5): never one that makes a reachable person look
/// unreachable.
pub const PRESENCE_STATE_FALLBACK: &str = "available";

/// The effective presence state of `token` (P§5).
pub fn effective_presence_state(token: &str) -> &str {
    if PRESENCE_STATES.contains(&token) {
        token
    } else {
        PRESENCE_STATE_FALLBACK
    }
}

/// `dsip-integrity-mode` registered values (§22.2). Unknown values resolve to `metadata-only`.
pub const INTEGRITY_MODES: &[&str] = &["metadata-only", "derivative-bound"];

/// `dsip-rotation-reason` registered values (§7.5, v0.7).
pub const ROTATION_REASONS: &[&str] = &["scheduled", "compromised", "lost", "policy"];

/// `dsip-provenance-operation` registered values (§22.3, v0.7).
pub const PROVENANCE_OPERATIONS: &[&str] = &["transcode", "relay", "repackage"];

/// Registry membership with fallback for `integrity`: an unknown or absent mode is the weaker
/// claim, `metadata-only` (§22.2; never a rejection).
pub fn effective_integrity(v: Option<&str>) -> &'static str {
    match v {
        Some(m) if INTEGRITY_MODES.contains(&m) => INTEGRITY_MODES.iter().copied().find(|x| *x == m).unwrap_or("metadata-only"),
        _ => "metadata-only",
    }
}

/// Registered `about` namespaces for `info`.
///
/// Spec: §12.12 (`dsip-info-about`); `media:dtmf` carries DTMF digits (spec-gap 70).
pub const INFO_ABOUT: &[&str] = &["transport:webrtc", "media:dtmf"];

/// How a reason token resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonResolution {
    /// The token the implementation acts on (the input, or `session.failed`).
    pub effective: String,
    /// `none` | `category` | `unknown-category`.
    pub fallback: &'static str,
    /// False when the registry lists the token but not for this message type.
    pub valid_on_type: bool,
}

/// Apply the §15.1 fallback rule to a well-formed token carried on `msg_type`.
///
/// Spec: §15.1 (category fallback), §15.6 (an extension token such as `x-contactcenter.queue-full`
/// is an unrecognized category to a receiver without the extension → `session.failed`).
pub fn resolve_reason(token: &str, msg_type: &str) -> ReasonResolution {
    let category = token.split('.').next().unwrap_or("");
    if let Some((_, valid_on)) = REASONS.iter().find(|(t, _)| *t == token) {
        let valid = !REASON_BEARING_TYPES.contains(&msg_type) || valid_on.contains(&msg_type);
        return ReasonResolution { effective: token.to_string(), fallback: "none", valid_on_type: valid };
    }
    if CATEGORIES.contains(&category) {
        // §15.1: unregistered token → behavior of its category
        return ReasonResolution { effective: token.to_string(), fallback: "category", valid_on_type: true };
    }
    // §15.1: unrecognized category → session.failed
    ReasonResolution { effective: "session.failed".to_string(), fallback: "unknown-category", valid_on_type: true }
}

/// Shape check for a reason token (`category.condition`), mirroring the schema pattern.
pub fn is_reason_shape(s: &str) -> bool {
    let Some((c, d)) = s.split_once('.') else { return false };
    let part = |p: &str| {
        p.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    part(c) && part(d)
}

/// Effective `answered_by` (unknown → `service`).
pub fn effective_answered_by(v: &str) -> &str {
    if ANSWERED_BY.contains(&v) { v } else { "service" }
}

/// Effective progress status (unknown → `trying`).
pub fn effective_progress_status(v: &str) -> &str {
    if PROGRESS_STATUS.contains(&v) { v } else { "trying" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallbacks() {
        assert_eq!(resolve_reason("user.declined", "reject").fallback, "none");
        assert!(!resolve_reason("user.hangup", "reject").valid_on_type);
        assert_eq!(resolve_reason("endpoint.on-fire", "reject").fallback, "category");
        assert_eq!(resolve_reason("x-cc.queue-full", "reject").effective, "session.failed");
        assert_eq!(effective_answered_by("butler"), "service");
        assert_eq!(effective_progress_status("pondering"), "trying");
        assert!(is_reason_shape("session.glare") && !is_reason_shape("timeout"));
    }
}
