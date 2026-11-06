//! First contact for messaging: sealed introductions (HPKE) and how introductions and grants reach a mailbox.
//!
//! Spec: M§6.9 (HPKE base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM; the recipient key is the
//! identity's X25519 key agreement key, derived from Ed25519 as `did:key` defines — [`x25519_from_ed25519_seed`]),
//! M§14.1 (`sealed` replaces `purpose`, `info` = `"dsip sealed introduction v1"`, AAD `id ‖ 0 ‖ from ‖ 0 ‖ to`,
//! never both — [`check_introduction`], [`seal_introduction`], [`open_sealed_introduction`]), core §19.4.
//!
//! Impl: RFC 9180 is implemented here from its definition (single-shot base mode, sequence 0), so that vectors can
//! pin it byte for byte; it is anchored by the RFC's own Appendix A.1.1 test vector (`messaging/hpke-open-rfc9180-*`)
//! and cross-checked against `hpke-rs` in `dsip-mls`. Introductions and grants for messaging identities travel as
//! mailbox deposits (spec-gap 54, [`crate::mailbox`]); a `did:web` identity's devices hold its key agreement key
//! (spec-gap 55).

use serde_json::{json, Value};

pub use dsip_core::hpke::{hpke_derive_sk, hpke_open, hpke_seal, x25519_from_ed25519_seed, x25519_public};

use crate::checks::{accept_effective, reject};

/// The only sealing algorithm of 1.0.
///
/// Spec: M§6.9, M§14.1.
pub const SEALED_ALG: &str = "hpke-base-x25519-sha256-aes128gcm";
/// HPKE `info` for sealed introductions.
///
/// Spec: M§14.1.
pub const SEALED_INFO: &[u8] = b"dsip sealed introduction v1";
/// `purpose` length bound, in characters.
///
/// Spec: §19.4.
pub const PURPOSE_MAX_CHARS: usize = 280;


/// The AAD binding a sealed body to its introduction: `id ‖ 0x00 ‖ from ‖ 0x00 ‖ to`.
///
/// Spec: M§14.1.
pub fn sealed_aad(p: &Value) -> Vec<u8> {
    let s = |k: &str| p[k].as_str().unwrap_or("").as_bytes().to_vec();
    [s("id"), vec![0], s("from"), vec![0], s("to")].concat()
}

/// An introduction under the profile: the core §19.4 shape plus `sealed`, never both `purpose` and `sealed`.
///
/// Spec: M§14.1.
pub fn check_introduction(p: &Value) -> Value {
    // The core v0.8 introduction schema carries `sealed` (§19.4).
    if dsip_schema::validate::validate_against("introduction", p).is_err() {
        return reject("schema-invalid", None);
    }
    if p.get("purpose").is_some() && p.get("sealed").is_some() {
        return reject("introduction-purpose-and-sealed", None);
    }
    if p.get("sealed").is_some_and(|s| s["alg"] != SEALED_ALG) {
        return reject("sealed-alg-unsupported", None);
    }
    accept_effective(json!({"sealed": p.get("sealed").is_some()}))
}

/// Seal `purpose` into an introduction payload for the recipient's X25519 key (M§14.1).
pub fn seal_introduction(p: &mut Value, purpose: &str, pk_r: &[u8; 32], sk_e: &[u8; 32]) {
    let (enc, ct) = hpke_seal(pk_r, SEALED_INFO, &sealed_aad(p), &serde_json::to_vec(&json!({"purpose": purpose})).expect("json"), sk_e);
    if let Some(m) = p.as_object_mut() {
        m.remove("purpose");
    }
    p["sealed"] = json!({"alg": SEALED_ALG, "enc": dsip_core::b64::encode(&enc), "ct": dsip_core::b64::encode(&ct)});
}

/// Check an introduction and, if sealed, open it with the recipient's Ed25519 identity seed: `accept` with `purpose`.
///
/// Spec: M§14.1, M§6.9.
pub fn open_sealed_introduction(p: &Value, recipient_seed: &[u8; 32]) -> Value {
    open_sealed_introduction_with(p, &x25519_from_ed25519_seed(recipient_seed))
}

/// As [`open_sealed_introduction`], with the recipient's X25519 key agreement secret itself: a key agreement
/// delegation's (core §7.3, spec-gap 179), or one derived from an identity key.
///
/// Spec: M§14.1, M§6.9, §7.3.
pub fn open_sealed_introduction_with(p: &Value, sk: &[u8; 32]) -> Value {
    let v = check_introduction(p);
    if v["verdict"] != "accept" {
        return v;
    }
    let Some(sealed) = p.get("sealed") else {
        return json!({"verdict": "accept", "purpose": p.get("purpose").cloned().unwrap_or(Value::Null)});
    };
    let d = |k: &str| sealed[k].as_str().and_then(dsip_core::b64::decode).unwrap_or_default();
    let Some(pt) = hpke_open(&d("enc"), sk, SEALED_INFO, &sealed_aad(p), &d("ct")) else {
        return reject("sealed-open-failed", None);
    };
    let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(&pt) else {
        return reject("sealed-plaintext-invalid", None);
    };
    let purpose = match (body.len(), body.get("purpose").and_then(Value::as_str)) {
        (1, Some(p)) => p.to_string(),
        _ => return reject("sealed-plaintext-invalid", None),
    };
    if purpose.chars().count() > PURPOSE_MAX_CHARS {
        return reject("purpose-too-long", None);
    }
    json!({"verdict": "accept", "purpose": purpose})
}

fn hex_in(v: &Value) -> Vec<u8> {
    v.as_str().and_then(|s| hex::decode(s).ok()).unwrap_or_default()
}

fn arr32(v: &Value) -> [u8; 32] {
    hex_in(v).try_into().unwrap_or([0; 32])
}

/// Run one first-contact vector check; `None` when `check` is not one of them.
///
/// Spec: none (infrastructure).
pub fn run_check(check: &str, inp: &Value) -> Option<Value> {
    Some(match check {
        "hpke-open" => match hpke_open(&hex_in(&inp["enc_hex"]), &arr32(&inp["sk_r_hex"]), &hex_in(&inp["info_hex"]), &hex_in(&inp["aad_hex"]), &hex_in(&inp["ct_hex"])) {
            Some(pt) => json!({"verdict": "accept", "plaintext_hex": hex::encode(pt)}),
            None => reject("hpke-open-failed", None),
        },
        "hpke-derive-key-pair" => {
            let sk = hpke_derive_sk(&hex_in(&inp["ikm_hex"]));
            json!({"sk_hex": hex::encode(sk), "pk_hex": hex::encode(x25519_public(&sk))})
        }
        "x25519-key-agreement" => json!({"x25519_pk_hex": hex::encode(x25519_public(&x25519_from_ed25519_seed(&arr32(&inp["ed25519_seed_hex"]))))}),
        "introduction" => check_introduction(&inp["payload"]),
        "sealed-introduction-open" => open_sealed_introduction(&inp["payload"], &arr32(&inp["recipient_ed25519_seed_hex"])),
        _ => return None,
    })
}
