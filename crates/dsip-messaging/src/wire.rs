//! Building the profile's envelopes.
//!
//! Spec: M§5 (every profile message is a DSIP-JOSE envelope whose `dsip` block names
//! `messaging/1.0`, with the device or service key as signer and a lifetime inside M§5.1's bound),
//! §10.2 (signature over the payload bytes), §13.2 (`hello`).

use serde_json::{json, Value};

use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::ulid::Ulid;

/// Profile identifier (M§1).
pub const PROFILE: &str = "messaging/1.0";
/// Lifetime of a profile envelope, seconds (M§5.1: ≤ 60).
pub const TTL_S: i64 = 30;
/// Lifetime of an `ephemeral` deposit, seconds (M§11.2: ≤ 10).
pub const EPHEMERAL_TTL_S: i64 = 10;

/// The `dsip` version block of a profile message.
pub fn version_block() -> Value {
    json!({"core": "1.0", "min_core": "1.0", "profiles": [PROFILE], "extensions": [], "critical": []})
}

/// A fresh ULID for `now` (seconds).
pub fn new_id(now: i64) -> String {
    Ulid::generate_at(now.max(0) as u64 * 1000).as_str().to_string()
}

/// Build and sign a profile payload: `{dsip, type, id, from, to, …fields, issued_at, expires_at}`.
pub fn message(key: &KeyPair, msg_type: &str, to: &str, now: i64, ttl: i64, fields: Value) -> Envelope {
    message_delegated(key, vec![], msg_type, to, now, ttl, fields)
}

/// [`message`] with delegations in the protected header, for a receiver that does not hold them —
/// a hub reached through the device's own mailbox (M§5.1).
pub fn message_delegated(
    key: &KeyPair,
    delegations: Vec<Envelope>,
    msg_type: &str,
    to: &str,
    now: i64,
    ttl: i64,
    fields: Value,
) -> Envelope {
    let mut p = json!({"dsip": version_block(), "type": msg_type, "id": new_id(now), "from": key.did(), "to": to});
    for (k, v) in fields.as_object().into_iter().flatten() {
        p[k.as_str()] = v.clone();
    }
    p["issued_at"] = json!(now);
    p["expires_at"] = json!(now + ttl);
    dsip_core::envelope::sign_bytes(&dsip_core::envelope::encode_payload(&p), key, &key.kid(), delegations)
}

/// The decoded payload of an envelope.
pub fn payload_of(env: &Envelope) -> Option<Value> {
    serde_json::from_slice(&dsip_core::b64::decode(&env.payload)?).ok()
}

/// A signed `accepted` (M§5.3): the service's claim that it took responsibility.
pub fn accepted(key: &KeyPair, to: &str, now: i64, in_reply_to: &str, extra: Value) -> Envelope {
    let mut fields = json!({"in_reply_to": in_reply_to});
    for (k, v) in extra.as_object().into_iter().flatten() {
        fields[k.as_str()] = v.clone();
    }
    message(key, "accepted", to, now, TTL_S, fields)
}

/// A signed `error` carrying a reason token (M§16).
pub fn error(key: &KeyPair, to: &str, now: i64, in_reply_to: Option<&str>, reason: &str, detail: Option<&str>) -> Envelope {
    let mut fields = json!({"reason": reason});
    if let Some(id) = in_reply_to {
        fields["in_reply_to"] = json!(id);
    }
    if let Some(d) = detail {
        fields["detail"] = json!(d);
    }
    message(key, "error", to, now, TTL_S, fields)
}

/// The service's `hello` answering a client's (§13.2, M§4.3).
pub fn service_hello(key: &KeyPair, to_hello_id: &str, now: i64, capabilities: Value) -> Envelope {
    let p = json!({
        "dsip": {"core": "1.0", "min_core": "1.0", "profiles": [], "extensions": [], "critical": []},
        "type": "hello", "id": new_id(now), "from": key.did(), "in_reply_to": to_hello_id,
        "capabilities": capabilities, "issued_at": now, "expires_at": now + TTL_S});
    sign(&p, key, &key.kid())
}

/// The `capabilities.mailbox` object a mailbox advertises (M§4.3).
pub fn mailbox_capabilities(hub: bool, blob_endpoint: &str, max_blob_bytes: i64) -> Value {
    json!({
        "max_envelope_bytes": dsip_core::WS_MAX_ENVELOPE_BYTES,
        "store_and_forward": true,
        "mailbox": {
            "profiles": [PROFILE],
            "modes": ["sync", "queue"],
            "hub": hub,
            "ciphersuites": [1],
            "max_mls_bytes": crate::checks::MAX_MLS_BYTES,
            "mls_retention_s": 2_592_000,
            "blob_endpoint": blob_endpoint,
            "max_blob_bytes": max_blob_bytes,
        }
    })
}

/// A `deposit` (M§5.2).
pub fn deposit(key: &KeyPair, to: &str, now: i64, group: &str, class: &str, fields: Value) -> Envelope {
    deposit_delegated(key, vec![], to, now, group, class, fields)
}

/// A `deposit` carrying the device's delegation in its header, as a hub reached by forwarding needs it
/// (M§5.1, M§5.2).
pub fn deposit_delegated(
    key: &KeyPair,
    delegations: Vec<Envelope>,
    to: &str,
    now: i64,
    group: &str,
    class: &str,
    fields: Value,
) -> Envelope {
    let mut f = json!({"group": group, "class": class});
    for (k, v) in fields.as_object().into_iter().flatten() {
        f[k.as_str()] = v.clone();
    }
    let ttl = if class == "ephemeral" { EPHEMERAL_TTL_S } else { TTL_S };
    message_delegated(key, delegations, "deposit", to, now, ttl, f)
}

/// An `items` response or live push (M§5.4).
pub fn items(key: &KeyPair, to: &str, now: i64, in_reply_to: Option<&str>, items: Vec<Value>, next: Value) -> Envelope {
    let mut fields = json!({"items": items, "next": next});
    if let Some(id) = in_reply_to {
        fields["in_reply_to"] = json!(id);
    }
    message(key, "items", to, now, TTL_S, fields)
}

/// The `items` envelope `build` makes of the longest prefix of `items` whose frame fits the `ws/1.0` cap, `next` the
/// last cursor it carries when any are left out (`next` as the page had it otherwise). The page the mailbox machine
/// chose bounds the count (`limit`); this bounds the bytes, which the machine does not see. A device follows `next`
/// with another sync, as it does for a page `limit` cut short. One item always goes: `MAX_MLS_BYTES` makes any item
/// fit. Found on a phone whose 54 items (44,756 bytes, about 80 KB as one frame) were sent as one page: it refused the
/// frame, reconnected and synced from the start again, every second.
///
/// Spec: M§5.4 ("A mailbox MUST paginate so every `items` envelope fits the transport cap"), §13.2 (65,536 bytes).
/// Impl: the prefix is found by measuring the signed frame (a binary search over the prefix's length), not estimated
/// from the items' sizes. The mailbox machine pages by count; this is the paging by bytes the `items-pages` vectors test
/// (spec-gap 180).
pub fn fit_items(items: Vec<Value>, next: Value, build: impl Fn(Vec<Value>, Value) -> Envelope) -> Envelope {
    let fits = |env: &Envelope| env.frame().len() <= dsip_core::WS_MAX_ENVELOPE_BYTES;
    let whole = build(items.clone(), next.clone());
    if items.len() <= 1 || fits(&whole) {
        return whole;
    }
    let page = |k: usize| build(items[..k].to_vec(), items[k - 1]["cursor"].clone());
    // the longest k in 1..items.len() that fits; 1 is taken even if it does not (it cannot, by MAX_MLS_BYTES)
    let (mut lo, mut hi) = (1, items.len() - 1);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if fits(&page(mid)) { lo = mid } else { hi = mid - 1 }
    }
    page(lo)
}
