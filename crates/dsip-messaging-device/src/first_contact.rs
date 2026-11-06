//! Introductions and grants delivered through the mailbox: verified as credentials, an introduction checked and its
//! sealed purpose opened, a grant kept for the `dsip.message` scope.
//!
//! Spec: M§14.1 (an introduction under the profile, `sealed` or `purpose` and never both; the purpose sealed to the
//! identity's key agreement key, M§6.9), core §19.4 (an introduction lives until its `expires_at`; a grant until its
//! `valid_until`), §7.4 (the signer bound to `from`), spec-gap 54 (they travel as mailbox deposits, held since they
//! were checked fresh), spec-gap 55 (the key agreement key derived from the identity key).
//!
//! Impl: a device that does not hold the identity key (a browser device linked without it) still keeps a checked
//! sealed introduction as a request, its purpose unread ([`Request::purpose`] is `None`); M§6.9 leaves which devices
//! hold the key to the identity.

use dsip_core::envelope::{verify_raw, Context, Envelope};
use dsip_messaging::first_contact::open_sealed_introduction_with;
use serde_json::{json, Value};

/// An introduction this device holds as a request (M§14.1: requests, never messages).
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// The introduction's `id`.
    pub id: String,
    /// Who asks.
    pub from: String,
    /// What they ask for: `None` when it is sealed and this device holds no key agreement key.
    pub purpose: Option<String>,
    /// Whether the purpose was sealed.
    pub sealed: bool,
    /// The verified payload.
    pub payload: Value,
}

/// A grant this device holds, letting it message `from` (§19.4).
#[derive(Debug, Clone, PartialEq)]
pub struct Grant {
    /// Who granted.
    pub from: String,
    /// The grant envelope, compact, as delivered: what a KeyPackage fetch presents (M§14.2).
    pub envelope: String,
    /// The granted scope.
    pub scope: Value,
    /// The introduction it answers (`session`).
    pub request: String,
}

/// What a delivered introduction or grant is to this device.
#[derive(Debug, Clone, PartialEq)]
pub enum Received {
    /// An introduction, checked and its purpose opened.
    Request(Request),
    /// A grant with the `dsip.message` scope.
    Grant(Grant),
    /// Its signature, type, recipient, lifetime or signer binding does not verify.
    DoesNotVerify,
    /// An introduction that verifies but is not one under the profile (M§14.1), or whose seal does not open: the
    /// introduction's `id`, `from` and the refusal code.
    BadIntroduction {
        /// The introduction's `id`.
        id: String,
        /// Who sent it.
        from: String,
        /// The refusal code of `check_introduction` or the opening.
        code: String,
    },
    /// A grant without the `dsip.message` scope: its `id` and `from`.
    NoMessageScope {
        /// The grant's `id`.
        id: String,
        /// Who granted.
        from: String,
    },
}

/// A mailbox item of class `introduction` or `grant` for identity `to`, at `now`: verified as a credential (its
/// signature, and its signer bound to `from`, §7.4), then read. `seed` is the identity key's seed, when this device
/// holds it, which the sealed purpose opens with (M§6.9, spec-gap 55).
pub fn received(item: &Value, to: &str, ctx: &Context, now: i64, seed: Option<&[u8; 32]>) -> Received {
    let secrets: Vec<[u8; 32]> = seed.map(dsip_messaging::first_contact::x25519_from_ed25519_seed).into_iter().collect();
    received_with(item, to, ctx, now, &secrets)
}

/// As [`received`], with the identity's X25519 key agreement secrets (none: this device opens no sealed purpose): a
/// sealed introduction opens with the first that opens it, the delegated key before the derived one (core §7.3,
/// spec-gap 179).
pub fn received_with(item: &Value, to: &str, ctx: &Context, now: i64, secrets: &[[u8; 32]]) -> Received {
    let class = item["class"].as_str().unwrap_or("");
    let compact = item["envelope"].as_str().unwrap_or("");
    let mut parts = compact.split('.');
    let mut next = || parts.next().unwrap_or("").to_string();
    let env = Envelope { protected: next(), payload: next(), signature: next() };
    let checked = verify_raw(&env, ctx, false).ok().filter(|ver| {
        let from = ver.payload["from"].as_str().unwrap_or("");
        ver.payload["type"] == class
            && ver.payload["to"] == json!(to)
            // an introduction lives until its expires_at; a grant's delivery expiry has passed, its valid_until has not (§19.4)
            && ver.payload[if class == "grant" { "valid_until" } else { "expires_at" }].as_i64().unwrap_or(0) > now
            && dsip_core::delegation::check_binding(from, &ver.signer_did, &ver.header.delegations, ctx).ok()
    });
    let Some(ver) = checked else { return Received::DoesNotVerify };
    let mut p = ver.payload;
    if class == "grant" && p["from"] == json!(ver.signer_did) {
        // §7.4: a grant a calling engine signs names its device in `from`; the granter is the identity the device's
        // delegation binds it to, as wherever the grant is checked as a credential (dsip_core::grant)
        if let Some(g) = dsip_core::grant::credential(&env, ctx) {
            p["from"] = g["from"].clone();
        }
    }
    let s = |k: &str| p[k].as_str().unwrap_or("").to_string();
    let (id, from) = (s("id"), s("from"));
    if class == "introduction" {
        let sealed = p.get("sealed").is_some();
        // M§14.1: checked whether or not this device can open it
        let checked = dsip_messaging::first_contact::check_introduction(&p);
        let opened = match secrets.split_first() {
            Some((first, rest)) if checked["verdict"] == "accept" => {
                let try_one = |sk: &[u8; 32]| open_sealed_introduction_with(&p, sk);
                let attempt = try_one(first);
                if attempt["verdict"] == "accept" || !sealed {
                    attempt
                } else {
                    rest.iter().map(try_one).find(|o| o["verdict"] == "accept").unwrap_or(attempt)
                }
            }
            _ => checked,
        };
        if opened["verdict"] != "accept" {
            return Received::BadIntroduction { id, from, code: opened["code"].as_str().unwrap_or("").to_string() };
        }
        let purpose = match (sealed, secrets.is_empty()) {
            (true, true) => None,
            _ => Some(opened["purpose"].as_str().or(p["purpose"].as_str()).unwrap_or("").to_string()),
        };
        Received::Request(Request { id, from, purpose, sealed, payload: p })
    } else {
        let scope = p["scope"].clone();
        if !scope.as_array().is_some_and(|s| s.iter().any(|x| x == "dsip.message")) {
            return Received::NoMessageScope { id, from };
        }
        let envelope = format!("{}.{}.{}", env.protected, env.payload, env.signature);
        Received::Grant(Grant { from, envelope, scope, request: s("session") })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsip_core::envelope::{encode_payload, sign_bytes};
    use dsip_core::keys::KeyPair;

    const NOW: i64 = 1_790_000_000;

    #[test]
    fn a_grant_a_device_signs_in_its_own_name_is_the_identitys() {
        // §7.4: a calling engine names its device in `from`; its delegation binds it to the identity that grants
        let (identity, device) = (KeyPair::from_seed([1; 32]), KeyPair::from_seed([2; 32]));
        let deleg = dsip_core::delegation::delegation_payload(&identity.did(), &device.did(), NOW - 60, NOW + 86_400, &["dsip.signaling"]);
        let deleg = sign_bytes(&encode_payload(&deleg), &identity, &identity.kid(), vec![]);
        let grantee = KeyPair::from_seed([3; 32]).did();
        let p = json!({"type": "grant", "id": "01M6CNVZ51GZPHFE0WD2FGDNNC", "from": device.did(), "to": grantee, "session": "01M6CNVZ52H17DM49J4SAQPFW0",
                       "scope": ["dsip.invite", "dsip.message", "dsip.subscribe"], "valid_until": NOW + 3600, "issued_at": NOW - 600, "expires_at": NOW - 570});
        let env = sign_bytes(&encode_payload(&p), &device, &device.kid(), vec![deleg]);
        let item = json!({"class": "grant", "envelope": format!("{}.{}.{}", env.protected, env.payload, env.signature)});
        let resolver = dsip_core::did::StaticResolver::default();
        match received(&item, &grantee, &Context::new(NOW, &resolver), NOW, None) {
            Received::Grant(g) => assert_eq!((g.from, g.request), (identity.did(), "01M6CNVZ52H17DM49J4SAQPFW0".to_string())),
            _ => panic!("not read as a grant"),
        }
    }
}
