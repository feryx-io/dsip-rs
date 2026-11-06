//! Verdicts and implementation-neutral rejection codes.
//!
//! Spec: none (infrastructure) — the codes are defined by `impl/vectors/README.md`
//! so that Python and Rust classify every rejection identically. Where the spec
//! assigns a reason token to a condition (§15), [`Verdict::reason`] carries it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Why an envelope or payload was rejected. Serialized in kebab-case to match the vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub enum RejectCode {
    FrameTooLarge,
    EnvelopeShape,
    HeaderInvalid,
    AlgUnsupported,
    KidInvalid,
    KidUnresolvable,
    SignatureInvalid,
    PayloadNotUtf8,
    PayloadNotJson,
    PayloadFloat,
    PayloadShape,
    SignerMismatch,
    DelegationInvalid,
    DelegationExpired,
    DelegationCapability,
    /// A revocation covers the delegation (§7.4, v0.8, spec-gap 57).
    DelegationRevoked,
    /// An introduction carries both `purpose` and `sealed` (§19.4, v0.8).
    IntroductionPurposeAndSealed,
    /// A revocation's `from` is not its `subject` (§7.4, v0.8).
    RevocationSubjectMismatch,
    /// A revocation is not signed by a key of its subject (§7.4, v0.8).
    RevocationSignerNotSubject,
    ExpiryOrder,
    ReplayWindow,
    IntroductionValidity,
    /// A `reachability-hint` whose `expires_at − issued_at` exceeds 3,600 s (§12.9, v0.8; spec-gap 96).
    HintValidity,
    /// A `presence` record whose `expires_at − issued_at` exceeds 3,600 s (§12.9, P§3, v0.17; spec-gap 134).
    PresenceValidity,
    Expired,
    DuplicateId,
    UlidIssuedAtMismatch,
    HelloRequired,
    VersionUnsupported,
    /// A payload carries `sealed` without `sealed-body/1.0` in `dsip.critical` (§10.4; spec-gap 97).
    SealedNotCritical,
    /// `sealed.alg` is not the 1.0 HPKE suite (§10.4, §19.4).
    SealedAlgUnsupported,
    /// A sealed body does not open: bad base64url, wrong key, tampering, or another message's AAD (§10.4).
    BodyUnsealFailed,
    /// An opened body is not a non-empty §10.3 JSON object padded to a multiple of 256 bytes (§10.4).
    SealedPlaintextInvalid,
    /// An opened body holds a field outside the type's sealable fields (§10.4).
    SealedFieldNotSealable,
    /// A field is present both sealed and in clear (§10.4).
    SealedFieldInClear,
    UnknownType,
    SchemaInvalid,
    SelectionNotSubset,
    SubscriptionLifetimeExceeded,
    IntroductionTooLarge,
    GrantUnknownIntroduction,
    HelloInReplyToMismatch,
    HintSubjectMismatch,
    /// A hint whose `key_agreement` member is not a key agreement delegation of its subject (DHT Hints Profile §4; §7.3,
    /// spec-gap 179).
    KeyAgreementInvalid,
    PublisherMismatch,
    StreamIdNamespace,
    RotationSubjectMismatch,
    RotationNextSameAsPrevious,
    RotationSignerNotPrevious,
    /// A `presence` record whose `device` is not its signer, `from` (P§3, v0.17; spec-gap 135).
    PresenceSignerMismatch,
    /// A sealed `presence` record without `presence/0.2`, or whose `kid` is not for its audience (P§12.2, v0.17;
    /// spec-gaps 152, 157).
    PresenceSealedInvalid,
    BindingIceMode,
    BindingSdpMissing,
    BindingSdpInvalid,
    BindingSectionCount,
    BindingExtraSection,
    BindingKindMismatch,
    BindingDirectionMismatch,
    BindingCodecMissing,
    BindingEncryption,
    BindingRtcpMuxMissing,
    BindingFingerprintMissing,
    BindingIceCredentialsMissing,
    BindingSetupInvalid,
    BindingIceRestart,
}

/// The outcome of a pipeline stage.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// `None` = accept.
    pub code: Option<RejectCode>,
    /// Reason token the implementation signals for this rejection, when the spec defines one.
    pub reason: Option<&'static str>,
    /// Human detail; never compared.
    pub detail: Option<String>,
    /// Accept-side extras (`type`, `signer`, `identity`, `effective`, `warnings`, …).
    pub extra: serde_json::Map<String, Value>,
}

impl Verdict {
    /// An accept with no extras.
    pub fn accept() -> Verdict {
        Verdict { code: None, reason: None, detail: None, extra: Default::default() }
    }

    /// A rejection.
    pub fn reject(code: RejectCode) -> Verdict {
        Verdict { code: Some(code), reason: None, detail: None, extra: Default::default() }
    }

    /// A rejection carrying a reason token.
    pub fn reject_with(code: RejectCode, reason: &'static str) -> Verdict {
        Verdict { code: Some(code), reason: Some(reason), detail: None, extra: Default::default() }
    }

    /// Attach human detail.
    pub fn detail(mut self, d: impl Into<String>) -> Verdict {
        self.detail = Some(d.into());
        self
    }

    /// Add an accept-side extra.
    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Verdict {
        self.extra.insert(key.to_string(), value.into());
        self
    }

    /// Is this an accept?
    pub fn ok(&self) -> bool {
        self.code.is_none()
    }

    /// The comparable projection used by the vector runner (`expect` shape).
    pub fn to_expect(&self) -> Value {
        let mut m = serde_json::Map::new();
        match self.code {
            None => {
                m.insert("verdict".into(), "accept".into());
                for (k, v) in &self.extra {
                    m.insert(k.clone(), v.clone());
                }
            }
            Some(c) => {
                m.insert("verdict".into(), "reject".into());
                m.insert("code".into(), serde_json::to_value(c).expect("enum"));
                if let Some(r) = self.reason {
                    m.insert("reason".into(), r.into());
                }
            }
        }
        Value::Object(m)
    }
}

/// Early-return helper: `try_stage!(verdict)` returns the verdict from the enclosing fn if it rejects.
#[macro_export]
macro_rules! try_stage {
    ($v:expr) => {{
        let v = $v;
        if !v.ok() {
            return v;
        }
        v
    }};
}
