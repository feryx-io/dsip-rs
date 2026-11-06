//! Hint records: key derivation, construction, verification, and §8.3 conflict resolution.
//!
//! Spec: §8.3 (conflict rules), §8.5 (hints, not authority), §7.4 (delegated
//! signers), §12.9 (the envelope replay window applies to hints too).
//!
//! A hint is a DSIP-JOSE envelope whose payload is
//! `{"type":"reachability-hint","subject":DID,"endpoints":[{uri,bindings}],"seq":N,…}`
//! (schema: `reachability-hint.schema.json` in the v0.7 spec set). The DHT key is the
//! SHA-256 multihash of the normalized subject DID.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use dsip_core::b64;
use dsip_core::envelope::{self, Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::ulid::Ulid;
use dsip_core::version::check_version;
use dsip_core::{RejectCode, Verdict};
use dsip_schema::validate_against;

/// Payload `type` of a hint.
pub const HINT_TYPE: &str = "reachability-hint";

/// Normalize a DID for keying: the `did:` prefix and method are case-folded;
/// the method-specific id is left as-is (`did:key` identifiers are case-sensitive base58).
pub fn normalize_did(did: &str) -> String {
    match did.splitn(3, ':').collect::<Vec<_>>().as_slice() {
        [scheme, method, rest] => format!("{}:{}:{}", scheme.to_ascii_lowercase(), method.to_ascii_lowercase(), rest),
        _ => did.to_string(),
    }
}

/// DHT key for a subject DID: multihash `sha2-256` (`0x12 0x20` ‖ digest) of the normalized DID.
pub fn key_for(did: &str) -> Vec<u8> {
    let digest = Sha256::digest(normalize_did(did).as_bytes());
    let mut out = Vec::with_capacity(34);
    out.extend_from_slice(&[0x12, 0x20]);
    out.extend_from_slice(&digest);
    out
}

/// An advertised endpoint: a signaling relay (`service` absent, `DSIPSignaling`), or another DID service type the
/// hint stands in for — `DSIPMailbox` carries that service entry's fields (`mailbox`, `profiles`, `priority`, …;
/// Messaging Profile M§4.2), kept in `extra` exactly as published (profile §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// `wss://…` URI.
    pub uri: String,
    /// Bindings, e.g. `["ws/1.0"]`.
    pub bindings: Vec<String>,
    /// Every other field of the endpoint object (`service`, and the service entry's fields).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Endpoint {
    /// A signaling endpoint (`service` absent).
    pub fn signaling(uri: &str) -> Endpoint {
        Endpoint { uri: uri.to_string(), bindings: vec!["ws/1.0".into()], extra: Default::default() }
    }

    /// The DID service type this endpoint stands in for: `DSIPSignaling` when `service` is absent (profile §2).
    pub fn service(&self) -> &str {
        self.extra.get("service").and_then(|s| s.as_str()).unwrap_or("DSIPSignaling")
    }
}

/// Build a hint payload with a fresh id.
pub fn hint_payload(subject: &str, from: &str, endpoints: &[Endpoint], seq: i64, issued_at: i64, ttl_s: i64) -> Value {
    hint_payload_with_id(subject, from, endpoints, seq, issued_at, ttl_s, Ulid::generate().as_str())
}

/// Build a hint payload under a caller-supplied id (a host whose clock and randomness are its own, such as wasm).
pub fn hint_payload_with_id(subject: &str, from: &str, endpoints: &[Endpoint], seq: i64, issued_at: i64, ttl_s: i64, id: &str) -> Value {
    json!({
        "dsip": {"core": "1.0", "min_core": "1.0", "profiles": [], "extensions": [], "critical": []},
        "type": HINT_TYPE,
        "id": id,
        "from": from,
        "subject": subject,
        "endpoints": endpoints,
        "seq": seq,
        "issued_at": issued_at,
        "expires_at": issued_at + ttl_s,
    })
}

/// Sign a hint with a device key, presenting its delegation inline so any node can verify.
pub fn sign_hint(payload: &Value, device: &KeyPair, delegations: Vec<Envelope>) -> Envelope {
    envelope::sign_bytes(&serde_json::to_vec(payload).expect("json"), device, &device.kid(), delegations)
}

/// A verified hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hint {
    /// Subject DID.
    pub subject: String,
    /// Endpoints.
    pub endpoints: Vec<Endpoint>,
    /// Sequence number.
    pub seq: i64,
    /// Issued at.
    pub issued_at: i64,
    /// Expires at.
    pub expires_at: i64,
    /// Signing DID (device or subject).
    pub signer: String,
    /// The exact frame (for forwarding and storage).
    pub frame: String,
    /// The subject's key agreement delegation the hint carried, verified (DHT Hints Profile §2; core §7.3).
    pub key_agreement: Option<Value>,
}

/// Outcome of comparing a verified input against an existing record (§8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Conflict {
    /// No existing live record, or identical record.
    None,
    /// Input has the higher `seq`; it wins.
    NewerSeq,
    /// Input has the lower `seq`; existing wins.
    OlderSeq,
    /// Same key, same `seq`, different content, both live: warn; existing kept.
    SameSeqLive,
}

/// Result of [`evaluate`].
#[derive(Debug)]
pub struct Evaluation {
    /// Verification verdict (accept ⇒ `hint` is `Some`).
    pub verdict: Verdict,
    /// The verified hint.
    pub hint: Option<Hint>,
    /// `input` or `existing`.
    pub winner: &'static str,
    /// Conflict classification.
    pub conflict: Conflict,
}

impl Evaluation {
    /// The vector `expect` projection.
    pub fn to_expect(&self) -> Value {
        if !self.verdict.ok() {
            return self.verdict.to_expect();
        }
        let mut v = self.verdict.to_expect();
        v["winner"] = self.winner.into();
        v["conflict"] = serde_json::to_value(self.conflict).expect("enum");
        v
    }
}

fn payload_of(frame_or_env: &Envelope) -> Option<Value> {
    serde_json::from_slice(&b64::decode(&frame_or_env.payload)?).ok()
}

/// Verify a hint frame and resolve it against an optional existing record.
///
/// Pipeline: envelope stages 1–11 → `identity == subject` → §11 version → hint
/// schema → §8.3 conflict. `existing` is assumed to have been accepted earlier;
/// only its liveness and `seq` are consulted.
pub fn evaluate(frame: &str, ctx: &Context, existing: Option<&Envelope>) -> Evaluation {
    let reject = |v: Verdict| Evaluation { verdict: v, hint: None, winner: "existing", conflict: Conflict::None };
    let env = match Envelope::from_frame(frame) {
        Ok(e) => e,
        Err(v) => return reject(v),
    };
    let ver = match envelope::verify(&env, ctx, Some(frame)) {
        Ok(v) => v,
        Err(v) => return reject(v),
    };
    let p = &ver.payload;
    if p.get("subject").and_then(Value::as_str) != Some(ver.identity.as_str()) {
        // A hint binds to its subject: the signer must be (or be delegated by) the subject.
        return reject(Verdict::reject(RejectCode::HintSubjectMismatch));
    }
    let vv = check_version(p, &ctx.supported);
    if !vv.ok() {
        return reject(vv);
    }
    if let Err(e) = validate_against(HINT_TYPE, p) {
        return reject(Verdict::reject(RejectCode::SchemaInvalid).detail(e));
    }
    // 1.x, spec-gap 179: a key agreement delegation the hint carries verifies for its subject, or the hint is refused
    // (DHT Hints Profile §4 step 2)
    if let Some(ka) = p.get("key_agreement") {
        if let Err(why) = dsip_schema::key_agreement::verify(ka, ctx, Some(ver.identity.as_str())) {
            return reject(Verdict::reject(RejectCode::KeyAgreementInvalid).detail(why));
        }
    }
    let hint = Hint {
        subject: ver.identity.clone(),
        endpoints: serde_json::from_value(p["endpoints"].clone()).unwrap_or_default(),
        seq: p["seq"].as_i64().unwrap_or(0),
        issued_at: p["issued_at"].as_i64().unwrap_or(0),
        expires_at: p["expires_at"].as_i64().unwrap_or(0),
        signer: ver.signer_did.clone(),
        frame: frame.to_string(),
        key_agreement: p.get("key_agreement").cloned(),
    };
    let (mut winner, mut conflict) = ("input", Conflict::None);
    if let Some(ex_env) = existing {
        if let Some(ex) = payload_of(ex_env) {
            let ex_seq = ex["seq"].as_i64().unwrap_or(0);
            if ex["expires_at"].as_i64().unwrap_or(0) <= ctx.now {
                // §8.3: records past expiration (from expires_at, spec-gap 141) are invalid — the existing one carries no weight
            } else if hint.seq > ex_seq {
                (winner, conflict) = ("input", Conflict::NewerSeq);
            } else if hint.seq < ex_seq {
                (winner, conflict) = ("existing", Conflict::OlderSeq);
            } else if ex_env.payload == env.payload {
                (winner, conflict) = ("existing", Conflict::None);
            } else {
                (winner, conflict) = ("existing", Conflict::SameSeqLive);
            }
        }
    }
    Evaluation { verdict: envelope::accept_verdict(&ver), hint: Some(hint), winner, conflict }
}

/// Fold a set of candidate frames (e.g. every record a GET returned) down to the winning hint.
///
/// Returns the winner and, per candidate, its verdict and conflict classification.
pub fn select(frames: &[String], ctx: &Context) -> (Option<Hint>, Vec<(String, Value)>) {
    let mut best: Option<(Hint, Envelope)> = None;
    let mut report = vec![];
    for f in frames {
        let ev = evaluate(f, ctx, best.as_ref().map(|(_, e)| e));
        report.push((f.clone(), ev.to_expect()));
        if let Some(h) = ev.hint {
            if ev.winner == "input" {
                let env = Envelope::from_frame(f).expect("verified");
                best = Some((h, env));
            }
        }
    }
    (best.map(|(h, _)| h), report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_multihash_of_normalized_did() {
        let k = key_for("DID:KEY:z6MkABC");
        assert_eq!(&k[..2], &[0x12, 0x20]);
        assert_eq!(k, key_for("did:key:z6MkABC"));
        assert_ne!(k, key_for("did:key:z6mkabc"), "method-specific id stays case-sensitive");
    }
}
