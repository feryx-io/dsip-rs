//! Profile cards: the extension `profile-card/1.0`. A card is the name and small picture an identity asks to be shown
//! as, sealed to the other party on an `introduction` (in the sealed plaintext, beside `purpose`) or on a `grant`
//! (member `profile`). Here: the card's own rules and the introduction cap the extension raises. Sealing and
//! opening are `dsip-messaging`'s (`first_contact`).
//!
//! Spec: §19.4 (Profile cards), §18.2.

use serde_json::{json, Map, Value};

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
