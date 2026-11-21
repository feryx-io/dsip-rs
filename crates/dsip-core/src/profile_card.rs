//! Profile cards: the extension `profile-card/1.0`. A card is the name and small picture an identity asks to be shown
//! as, sealed to the other party on an `introduction` (in the sealed plaintext, beside `purpose`) or on a `grant`
//! (member `profile`). Here: the card's own rules, the introduction cap the extension raises, and a grant's card
//! sealed and opened. An introduction's card is sealed with its purpose, in `dsip-messaging` (`first_contact`).
//!
//! Spec: §19.4 (Profile cards), §18.2.

use serde_json::{json, Map, Value};

use crate::hpke::{hpke_open, hpke_seal};
use crate::INTRODUCTION_MAX_BYTES;

/// The extension's id, as listed in `dsip.extensions`.
///
/// Spec: §19.4.
pub const PROFILE_CARD_EXT: &str = "profile-card/1.0";

/// Maximum encoded size of an `introduction` that carries `sealed` and lists `profile-card/1.0`.
///
/// Spec: §19.4.
pub const INTRODUCTION_CARD_MAX_BYTES: usize = 16_384;

/// `display_name` bound of a card, in Unicode code points.
///
/// Spec: §19.4.
pub const CARD_NAME_MAX_CHARS: usize = 256;

/// The largest picture a card carries, in bytes before encoding.
///
/// Spec: §19.4 — what the introduction cap leaves after three encodings.
pub const CARD_PICTURE_MAX_BYTES: usize = 4_096;

/// The picture types a card may name.
///
/// Spec: §19.4.
pub const CARD_PICTURE_TYPES: [&str; 2] = ["image/jpeg", "image/png"];

/// Whether a payload lists the extension in `dsip.extensions`.
///
/// Spec: §19.4.
pub fn lists_profile_card(payload: &Value) -> bool {
    payload["dsip"]["extensions"].as_array().is_some_and(|e| e.iter().any(|x| x == PROFILE_CARD_EXT))
}

/// The cap of an introduction: 16,384 bytes when it carries `sealed` and lists the extension, 4,096 otherwise. A
/// holder cannot see whether the sealed plaintext holds a card, so the cap is the extension's, not the card's.
///
/// Spec: §19.4.
pub fn introduction_cap(payload: &Value) -> usize {
    if payload.get("sealed").is_some() && lists_profile_card(payload) {
        INTRODUCTION_CARD_MAX_BYTES
    } else {
        INTRODUCTION_MAX_BYTES
    }
}

/// The cap of an introduction carried as a compact envelope (a mailbox deposit): the holder reads its payload for
/// `sealed` and the extension. An envelope that cannot be read as three parts with a JSON object payload stays at
/// 4,096.
///
/// Spec: §19.4, M§14.1.
pub fn introduction_cap_compact(envelope: &str) -> usize {
    let parts: Vec<&str> = envelope.split('.').collect();
    if parts.len() != 3 {
        return INTRODUCTION_MAX_BYTES;
    }
    match crate::b64::decode(parts[1]).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
        Some(p) if p.is_object() => introduction_cap(&p),
        _ => INTRODUCTION_MAX_BYTES,
    }
}

/// A card as taken: its known members, any other dropped. `None` when the card is ignored, which is whole or not at
/// all: not an object, a `display_name` that is not 1 to 256 characters, or a `picture` that is not exactly a listed
/// `content_type` and unpadded base64url `data` of 1 to 4,096 bytes.
///
/// Spec: §19.4.
/// Impl: the picture's bytes are counted from the length of `data`, ⌊3n/4⌋; the string is not decoded, so its unused
/// trailing bits are not looked at, and the image is not parsed (spec-gap 186).
pub fn take_card(card: &Value) -> Option<Value> {
    let card = card.as_object()?;
    let mut out = Map::new();
    if let Some(name) = card.get("display_name") {
        let name = name.as_str()?;
        if !(1..=CARD_NAME_MAX_CHARS).contains(&name.chars().count()) {
            return None;
        }
        out.insert("display_name".into(), json!(name));
    }
    if let Some(picture) = card.get("picture") {
        let picture = picture.as_object()?;
        if picture.len() != 2 {
            return None;
        }
        let (content_type, data) = (picture.get("content_type")?.as_str()?, picture.get("data")?.as_str()?);
        let alphabet = data.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !CARD_PICTURE_TYPES.contains(&content_type) || !alphabet || data.len() % 4 == 1 {
            return None;
        }
        if !(1..=CARD_PICTURE_MAX_BYTES).contains(&(data.len() * 3 / 4)) {
            return None;
        }
        out.insert("picture".into(), json!({"content_type": content_type, "data": data}));
    }
    Some(Value::Object(out))
}

/// The sealing algorithm of a card, the sealed purpose's.
///
/// Spec: §19.4, M§6.9.
pub const CARD_SEALED_ALG: &str = "hpke-base-x25519-sha256-aes128gcm";

/// HPKE `info` for a grant's profile card.
///
/// Spec: §19.4.
pub const PROFILE_INFO: &[u8] = b"dsip profile card v1";

/// Why a grant's card is ignored; the grant stands either way. The text of each is the vectors' code.
///
/// Spec: §19.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardIgnored {
    /// The grant carries `profile` and does not list `profile-card/1.0`.
    ExtensionUnlisted,
    /// `profile.alg` is not the one algorithm of 1.0.
    AlgUnsupported,
    /// `enc` or `ct` is not base64url, or HPKE does not open.
    OpenFailed,
    /// The plaintext is not a §10.3 JSON object of exactly `profile`.
    PlaintextInvalid,
    /// The card fails its own rules ([`take_card`]).
    CardInvalid,
}

impl CardIgnored {
    /// The code the conformance vectors name it by.
    pub fn code(self) -> &'static str {
        match self {
            CardIgnored::ExtensionUnlisted => "profile-extension-unlisted",
            CardIgnored::AlgUnsupported => "sealed-alg-unsupported",
            CardIgnored::OpenFailed => "sealed-open-failed",
            CardIgnored::PlaintextInvalid => "sealed-plaintext-invalid",
            CardIgnored::CardInvalid => "profile-card-invalid",
        }
    }
}

/// The AAD that binds a card to its grant: `id ‖ 0x00 ‖ from ‖ 0x00 ‖ to`.
///
/// Spec: §19.4.
fn grant_aad(g: &Value) -> Vec<u8> {
    let s = |k: &str| g[k].as_str().unwrap_or("").as_bytes().to_vec();
    [s("id"), vec![0], s("from"), vec![0], s("to")].concat()
}

/// Add `profile-card/1.0` to a payload's `dsip.extensions`, once.
///
/// Spec: §19.4.
pub fn list_profile_card(p: &mut Value) {
    if lists_profile_card(p) {
        return;
    }
    match p["dsip"]["extensions"].as_array_mut() {
        Some(exts) => exts.push(json!(PROFILE_CARD_EXT)),
        None => p["dsip"]["extensions"] = json!([PROFILE_CARD_EXT]),
    }
}

/// Seal the grantor's `card` into a grant payload as `profile`, for the grantee identity's X25519 key, and list
/// `profile-card/1.0`. Only for a grantee known to support the extension. The grant's `id`, `from` and `to` must be
/// final: they bind the card.
///
/// Spec: §19.4.
pub fn seal_grant_profile(g: &mut Value, card: &Value, pk_r: &[u8; 32], sk_e: &[u8; 32]) {
    list_profile_card(g);
    let pt = serde_json::to_vec(&json!({"profile": card})).expect("json");
    let (enc, ct) = hpke_seal(pk_r, PROFILE_INFO, &grant_aad(g), &pt, sk_e);
    g["profile"] = json!({"alg": CARD_SEALED_ALG, "enc": crate::b64::encode(&enc), "ct": crate::b64::encode(&ct)});
}

/// The card a grant's `profile` carries, opened with the grantee's X25519 key agreement secret: the card as taken,
/// `None` for a grant without `profile`, or why it is ignored.
///
/// Spec: §19.4.
pub fn open_grant_profile(g: &Value, sk: &[u8; 32]) -> Result<Option<Value>, CardIgnored> {
    let Some(sealed) = g.get("profile") else { return Ok(None) };
    if !lists_profile_card(g) {
        return Err(CardIgnored::ExtensionUnlisted);
    }
    if sealed["alg"] != CARD_SEALED_ALG {
        return Err(CardIgnored::AlgUnsupported);
    }
    let d = |k: &str| sealed[k].as_str().and_then(crate::b64::decode).unwrap_or_default();
    let pt = hpke_open(&d("enc"), sk, PROFILE_INFO, &grant_aad(g), &d("ct")).ok_or(CardIgnored::OpenFailed)?;
    // §10.3: UTF-8, a JSON object, no floats
    let Ok(Value::Object(body)) = crate::wire::parse_payload(&pt, false) else {
        return Err(CardIgnored::PlaintextInvalid);
    };
    let (1, Some(card)) = (body.len(), body.get("profile")) else {
        return Err(CardIgnored::PlaintextInvalid);
    };
    take_card(card).map(Some).ok_or(CardIgnored::CardInvalid)
}
