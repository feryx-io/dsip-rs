//! Key agreement delegation (1.x, spec-gap 179): an identity-signed credential naming an independent X25519 key
//! agreement key, so that an identity's devices open what is sealed to it (sealed introductions, sealed bodies, sealed
//! presence) without holding its signing key, which a `did:key`'s derived secret is in effect.
//!
//! Spec: §7.3 (the credential, its verification, which one is current, the key agreement key of a DID); §10.4 rule 3
//! and M§6.9 (the recipient key); DHT Hints Profile §2 and §4 (carried in a hint, which is refused when it does not
//! verify).

use dsip_core::did::{multibase_x25519, public_from_did_key, x25519_from_multibase};
use dsip_core::envelope::{self, Context, Envelope};
use serde_json::{json, Value};

use crate::validate::validate_against;

/// The longest lifetime: one year (§7.3).
pub const LIFETIME_CAP_S: i64 = 31_536_000;
/// How far ahead `issued_at` may be: the replay window (§7.3, §12.9).
pub const FUTURE_S: i64 = 300;

/// A verified key agreement delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAgreementDelegation {
    /// The identity it is of.
    pub subject: String,
    /// The X25519 key, multibase (`z6LS…`).
    pub key: String,
    /// The key's 32 bytes.
    pub public: [u8; 32],
    /// When issued.
    pub issued_at: i64,
    /// When it ends.
    pub expires_at: i64,
}

/// Why a credential does not verify, in the order checked; the vectors' codes.
///
/// Spec: §7.3.
pub fn verify(credential: &Value, ctx: &Context, subject: Option<&str>) -> Result<KeyAgreementDelegation, &'static str> {
    // as a delegation is: shape, header, kid resolution, signature, payload parse; no core fields, no replay window
    let env = Envelope::from_value(credential).map_err(|_| "credential-invalid")?;
    let ver = envelope::verify_raw(&env, ctx, false).map_err(|_| "credential-invalid")?;
    let p = &ver.payload;
    validate_against("key-agreement-delegation", p).map_err(|_| "schema-invalid")?;
    // the pattern admits strings that are not 0xec 0x01 and 32 bytes
    let key = p["key"].as_str().unwrap_or_default().to_string();
    let public = x25519_from_multibase(&key).ok_or("schema-invalid")?;
    let text = |k: &str| p[k].as_str().unwrap_or_default().to_string();
    let int = |k: &str| p[k].as_i64().unwrap_or_default();
    let (who, issued_at, expires_at) = (text("subject"), int("issued_at"), int("expires_at"));
    // signed directly by the subject: a device's key never counts, even under a live delegation
    if ver.signer_did != who {
        return Err("not-subject-signed");
    }
    if subject.is_some_and(|s| s != who) {
        return Err("subject-mismatch");
    }
    if !(issued_at < expires_at && expires_at <= issued_at + LIFETIME_CAP_S) {
        return Err("validity-invalid");
    }
    if issued_at > ctx.now + FUTURE_S {
        return Err("not-yet-valid");
    }
    if ctx.now >= expires_at {
        return Err("expired");
    }
    Ok(KeyAgreementDelegation { subject: who, key, public, issued_at, expires_at })
}

/// Of the delegations that verify for `subject`, the current one: the greatest `issued_at`, ties to the smaller `key`.
///
/// Spec: §7.3.
pub fn current(delegations: &[Value], subject: &str, ctx: &Context) -> Option<KeyAgreementDelegation> {
    delegations
        .iter()
        .filter_map(|d| verify(d, ctx, Some(subject)).ok())
        .min_by(|a, b| b.issued_at.cmp(&a.issued_at).then_with(|| a.key.cmp(&b.key)))
}

/// Where a DID's key agreement key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Its DID document's `keyAgreement` method.
    Document,
    /// Its current key agreement delegation.
    Delegation,
    /// The key the `did:key` method derives from the Ed25519 key.
    Derived,
}

impl Source {
    fn name(self) -> &'static str {
        match self {
            Source::Document => "document",
            Source::Delegation => "delegation",
            Source::Derived => "derived",
        }
    }
}

/// The X25519 key the `did:key` method derives from an Ed25519 public key (the Montgomery `u = (1 + y) / (1 − y)`).
pub fn x25519_from_ed25519_public(public: &[u8; 32]) -> Option<[u8; 32]> {
    let point = curve25519_dalek::edwards::CompressedEdwardsY(*public).decompress()?;
    Some(point.to_montgomery().to_bytes())
}

/// The key agreement key of `did`: its document's (`document`, multibase), else its current delegation's, else for
/// `did:key` the derived key; none for a DID with neither.
///
/// Spec: §7.3, §10.4 rule 3.
pub fn recipient_key(did: &str, document: Option<&str>, delegations: &[Value], ctx: &Context) -> Option<(Source, [u8; 32])> {
    if let Some(doc) = document {
        return x25519_from_multibase(doc).map(|k| (Source::Document, k));
    }
    if let Some(cur) = current(delegations, did, ctx) {
        return Some((Source::Delegation, cur.public));
    }
    public_from_did_key(did).and_then(|p| x25519_from_ed25519_public(&p)).map(|k| (Source::Derived, k))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Run a `key-agreement/` vector: its actual expectation object.
pub fn run_vector(v: &Value) -> Value {
    let resolver = Context::resolver_from_vector(&v["context"]);
    let ctx = Context::from_vector(&v["context"], &resolver);
    let i = &v["input"];
    match i["check"].as_str() {
        Some("delegation") => match verify(&i["delegation"], &ctx, i["subject"].as_str()) {
            Ok(d) => json!({"verdict": "accept", "subject": d.subject, "key": d.key, "x25519_pk_hex": hex(&d.public),
                            "expires_at": d.expires_at}),
            Err(code) => json!({"verdict": "reject", "code": code}),
        },
        Some("recipient-key") => {
            let dels: Vec<Value> = i["delegations"].as_array().cloned().unwrap_or_default();
            match recipient_key(i["did"].as_str().unwrap_or_default(), i["document_key_agreement"].as_str(), &dels, &ctx) {
                Some((src, k)) => {
                    json!({"verdict": "accept", "source": src.name(), "key": multibase_x25519(&k), "x25519_pk_hex": hex(&k)})
                }
                None => json!({"verdict": "accept", "source": "none"}),
            }
        }
        other => json!({"verdict": "error", "detail": format!("unknown key-agreement check {other:?}")}),
    }
}
