//! On-disk identity: controller key, device key, the device delegation, and an optional key agreement key the
//! identity delegated (`key-agreement.json`).
//!
//! Spec: §7.3 (identity vs device keys; key agreement delegation, spec-gap 179), §7.4 (device delegation). The
//! controller key signs exactly one thing in Phase 1 — the delegation — and
//! never a session message; the device key signs everything on the wire.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use dsip_core::delegation::delegation_payload;
use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;

use crate::error::{file, Error, Result};

/// Metadata written next to the keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMeta {
    /// Controller DID.
    pub identity: String,
    /// Device DID.
    pub device: String,
    /// Display name (a claim; §18.2).
    pub display_name: String,
}

/// A loaded identity directory.
pub struct Identity {
    /// Directory.
    pub dir: PathBuf,
    /// Controller key (`did:key`).
    pub controller: KeyPair,
    /// Device key (`did:key`).
    pub device: KeyPair,
    /// Delegation controller→device (signed by the controller).
    pub delegation: Envelope,
    /// Metadata.
    pub meta: IdentityMeta,
    /// The key agreement key the identity delegated, if it has one (§7.3, spec-gap 179): what is sealed to the
    /// identity opens with it, and a device holding it needs no identity key to open anything.
    pub key_agreement: Option<KeyAgreement>,
}

/// An independent X25519 key agreement key and the identity's credential naming it (§7.3, spec-gap 179).
#[derive(Clone)]
pub struct KeyAgreement {
    /// The X25519 secret.
    pub secret: [u8; 32],
    /// The `KeyAgreementDelegation`, signed by the identity.
    pub delegation: Envelope,
}

impl KeyAgreement {
    /// The X25519 public key.
    pub fn public(&self) -> [u8; 32] {
        dsip_core::hpke::x25519_public(&self.secret)
    }
}

/// What `key-agreement.json` holds.
#[derive(Serialize, Deserialize)]
struct KeyAgreementFile {
    secret: String,
    delegation: String,
}

/// The longest key agreement delegation (§7.3).
const KEY_AGREEMENT_LIFETIME_S: i64 = 31_536_000;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok()?;
    }
    Some(out)
}

fn write(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    file(path, std::fs::write(path, contents))
}

/// A key file: readable by its owner alone (Unix; elsewhere the folder's own protection).
fn write_key(path: &Path, key: &KeyPair) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = file(path, std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path))?;
        // an existing file keeps its mode through `open`: set it
        file(path, f.set_permissions(std::fs::Permissions::from_mode(0o600)))?;
        file(path, f.write_all(hex(&key.seed()).as_bytes()))
    }
    #[cfg(not(unix))]
    write(path, hex(&key.seed()))
}

impl Identity {
    /// Create a new identity directory with fresh keys and a one-year delegation.
    pub fn init(dir: &Path, display_name: &str, fixture: Option<&str>, controller_from: Option<&Path>) -> Result<Identity> {
        Identity::init_with(dir, display_name, fixture, controller_from, &[])
    }

    /// As [`Identity::init`], delegating `extra` capabilities as well (e.g. `dsip.record`, Recording Profile C§1).
    pub fn init_with(dir: &Path, display_name: &str, fixture: Option<&str>, controller_from: Option<&Path>, extra: &[String]) -> Result<Identity> {
        file(dir, std::fs::create_dir_all(dir))?;
        let (controller, device) = match (fixture, controller_from) {
            // A second device of an existing identity: reuse its controller, mint a new device key.
            (_, Some(src)) => (Identity::load(src)?.controller, KeyPair::generate()),
            (Some(f), None) => (KeyPair::from_fixture_name(f), KeyPair::from_fixture_name(&format!("{f}-phone"))),
            (None, None) => (KeyPair::generate(), KeyPair::generate()),
        };
        let now = crate::now_s();
        let payload = delegation_payload(
            &controller.did(),
            &device.did(),
            now - 60,
            now + 365 * 86_400,
            &["dsip.signaling", "dsip.media.interactive", "dsip.messaging"]
                .iter()
                .copied()
                .chain(extra.iter().map(String::as_str))
                .collect::<Vec<_>>(),
        );
        let delegation = sign(&payload, &controller, &controller.kid());
        let meta = IdentityMeta { identity: controller.did(), device: device.did(), display_name: display_name.into() };
        write_key(&dir.join("controller.key"), &controller)?;
        write_key(&dir.join("device.key"), &device)?;
        write(&dir.join("delegation.json"), delegation.frame())?;
        write(&dir.join("identity.json"), serde_json::to_string_pretty(&meta)?)?;
        Ok(Identity { dir: dir.to_path_buf(), controller, device, delegation, meta, key_agreement: None })
    }

    /// Re-home this identity on `did:web` `did`: its controller key becomes the document's `#key-1`, the delegation is
    /// re-signed with that subject and kid, and `did.json` is written for the domain to serve. `also_known_as` lists
    /// aliases the document claims, e.g. `tel:+15551234567` for a bound number (Number Attestation N§3.3).
    ///
    /// Spec: §7.2 (did:web), §7.4 (the delegation names the identity), §8.1 (the document is authoritative).
    pub fn rehome_did_web(&mut self, did: &str, also_known_as: &[String]) -> Result<()> {
        if !did.starts_with("did:web:") {
            return Err(Error::NotDidWeb(did.to_string()));
        }
        let kid = format!("{did}#key-1");
        // Keep the capabilities the current delegation grants (its payload is our own, already trusted).
        use base64::Engine as _;
        let payload: serde_json::Value = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.delegation.payload)
            .ok()
            .and_then(|b: Vec<u8>| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let caps: Vec<String> = payload["capabilities"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect();
        let now = crate::now_s();
        let caps_ref: Vec<&str> = caps.iter().map(String::as_str).collect();
        let payload = delegation_payload(did, &self.device.did(), now - 60, now + 365 * 86_400, &caps_ref);
        self.delegation = sign(&payload, &self.controller, &kid);
        self.meta.identity = did.to_string();
        write(&self.dir.join("delegation.json"), self.delegation.frame())?;
        write(&self.dir.join("identity.json"), serde_json::to_string_pretty(&self.meta)?)?;
        // a key agreement delegation names its subject: the new identity's is issued under it, for the same key
        if let Some(secret) = self.key_agreement.as_ref().map(|k| k.secret) {
            self.issue_key_agreement(secret, now)?;
        }
        let doc = self.did_web_document(None, None, also_known_as);
        write(&self.dir.join("did.json"), serde_json::to_string_pretty(&doc)?)?;
        Ok(())
    }

    /// The DID document a `did:web` identity serves (§7.2): its identity key as `#key-1`; its key agreement key under
    /// `keyAgreement` (the delegated one when it holds one, §7.3, else the one derived from the identity key, M§6.9),
    /// since a document's is authoritative and senders never take a `did:web`'s from a hint (§8.1); a `DSIPSignaling`
    /// service for `relay` (§13.2) and a `DSIPMailbox` service for `mailbox` (`(DID, URI)`, M§4.2) when given; and
    /// `also_known_as`.
    ///
    /// Spec: §7.2, §7.3, §8.1, §13.2, M§4.2, M§6.9.
    pub fn did_web_document(&self, relay: Option<&str>, mailbox: Option<(&str, &str)>, also_known_as: &[String]) -> serde_json::Value {
        let did = self.meta.identity.as_str();
        let kid = format!("{did}#key-1");
        let x25519 = dsip_core::hpke::x25519_public(&self.key_agreement_secret());
        let mut doc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": did,
            "verificationMethod": [{"id": kid, "type": "Multikey", "controller": did,
                                    "publicKeyMultibase": dsip_core::did::multibase_ed25519(&self.controller.public())}],
            "authentication": [kid],
            "assertionMethod": [kid],
            "keyAgreement": [{"id": format!("{did}#key-agreement-1"), "type": "Multikey", "controller": did,
                              "publicKeyMultibase": dsip_core::did::multibase_x25519(&x25519)}],
        });
        let mut services = vec![];
        if let Some(uri) = relay {
            services.push(serde_json::json!({"id": format!("{did}#dsip"), "type": "DSIPSignaling",
                                             "serviceEndpoint": {"uri": uri, "bindings": ["ws/1.0"]}}));
        }
        if let Some((mailbox_did, uri)) = mailbox {
            services.push(serde_json::json!({"id": format!("{did}#dsip-mailbox"), "type": "DSIPMailbox",
                "serviceEndpoint": {"uri": uri, "bindings": ["ws/1.0"], "mailbox": mailbox_did, "priority": 0,
                                    "profiles": ["messaging/1.0"], "accepts": ["text", "audio"]}}));
        }
        if !services.is_empty() {
            doc["service"] = serde_json::json!(services);
        }
        if !also_known_as.is_empty() {
            doc["alsoKnownAs"] = serde_json::json!(also_known_as);
        }
        doc
    }

    /// Load an identity directory.
    pub fn load(dir: &Path) -> Result<Identity> {
        let read = |n: &str| file(dir.join(n), std::fs::read_to_string(dir.join(n)));
        let key = |n: &str| unhex(&read(n)?).ok_or_else(|| Error::BadKey(dir.join(n)));
        let controller = KeyPair::from_seed(key("controller.key")?);
        let device = KeyPair::from_seed(key("device.key")?);
        let delegation = Envelope::from_frame(&read("delegation.json")?)?;
        let meta: IdentityMeta = serde_json::from_str(&read("identity.json")?)?;
        let key_agreement = match std::fs::read_to_string(dir.join("key-agreement.json")) {
            Ok(text) => {
                let f: KeyAgreementFile = serde_json::from_str(&text)?;
                let secret = unhex(&f.secret).ok_or_else(|| Error::BadKey(dir.join("key-agreement.json")))?;
                Some(KeyAgreement { secret, delegation: Envelope::from_frame(&f.delegation)? })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::File { path: dir.join("key-agreement.json"), source: e }),
        };
        Ok(Identity { dir: dir.to_path_buf(), controller, device, delegation, meta, key_agreement })
    }

    /// The `kid` the identity signs its own credentials with: its did:key's, or `#key-1` of a did:web it moved to.
    fn identity_kid(&self) -> String {
        if self.meta.identity == self.controller.did() {
            self.controller.kid()
        } else {
            format!("{}#key-1", self.meta.identity)
        }
    }

    /// The `n`th key agreement secret of this identity, derived from its identity key: HMAC-SHA256 keyed by the
    /// Ed25519 seed over `dsip key agreement secret v1` and `n` (4 bytes, big-endian). Unlike the did:key derivation
    /// it says nothing of the signing key, and every device holding the identity key derives the same one, so a second
    /// device restored from a backup opens what the first does; `n` moves on when a key is replaced.
    ///
    /// Spec: §7.3. Impl: how an identity's devices come to hold the key agreement secret is the identity's own matter
    /// (§7.3, M§6.9); deriving it keeps a backup of the identity key enough.
    pub fn derived_key_agreement_secret(&self, n: u32) -> [u8; 32] {
        use hmac::Mac;
        let mut m = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(&self.controller.seed()).expect("an HMAC key");
        m.update(b"dsip key agreement secret v1");
        m.update(&n.to_be_bytes());
        m.finalize().into_bytes().into()
    }

    /// Sign the identity's delegation naming the X25519 key of `secret` (a year, the longest, §7.3), and keep both in
    /// `key-agreement.json` (its owner's alone): what is sealed to the identity from then on opens with it. A key held
    /// already is replaced (a newer delegation is current).
    ///
    /// Spec: §7.3 (spec-gap 179).
    pub fn issue_key_agreement(&mut self, secret: [u8; 32], now: i64) -> Result<()> {
        let public = dsip_core::hpke::x25519_public(&secret);
        let issued_at = now - 60;
        let payload = serde_json::json!({
            "type": "KeyAgreementDelegation", "subject": self.meta.identity, "key": dsip_core::did::multibase_x25519(&public),
            "issued_at": issued_at, "expires_at": issued_at + KEY_AGREEMENT_LIFETIME_S,
        });
        let delegation = sign(&payload, &self.controller, &self.identity_kid());
        let f = KeyAgreementFile { secret: hex(&secret), delegation: delegation.frame() };
        let path = self.dir.join("key-agreement.json");
        write(&path, serde_json::to_string_pretty(&f)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file(&path, std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)))?;
        }
        self.key_agreement = Some(KeyAgreement { secret, delegation });
        Ok(())
    }

    /// The identity's X25519 key agreement secret (§7.3): its delegated key's, else the one derived from the
    /// identity key (M§6.9).
    pub fn key_agreement_secret(&self) -> [u8; 32] {
        match &self.key_agreement {
            Some(k) => k.secret,
            None => dsip_core::hpke::x25519_from_ed25519_seed(&self.controller.seed()),
        }
    }

    /// Every X25519 secret what is sealed to the identity may open with: the delegated key's first, then the derived
    /// one a sender that has not seen the delegation still seals to.
    pub fn key_agreement_secrets(&self) -> Vec<[u8; 32]> {
        let derived = dsip_core::hpke::x25519_from_ed25519_seed(&self.controller.seed());
        match &self.key_agreement {
            Some(k) => vec![k.secret, derived],
            None => vec![derived],
        }
    }
}

#[cfg(test)]
mod key_agreement_tests {
    use super::*;

    #[test]
    fn an_identity_issues_a_key_agreement_key_and_its_hint_carries_the_credential() {
        let dir = std::env::temp_dir().join(format!("dsip-identity-ka-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut id = Identity::init(&dir, "Ann", None, None).unwrap();
        let derived = dsip_core::hpke::x25519_from_ed25519_seed(&id.controller.seed());
        assert_eq!(id.key_agreement_secrets(), vec![derived], "none issued: the derived key alone");

        let now = crate::now_s();
        let secret = id.derived_key_agreement_secret(0);
        assert_ne!(secret, derived, "not the did:key derivation");
        assert_ne!(secret, id.derived_key_agreement_secret(1), "the next one differs");
        id.issue_key_agreement(secret, now).unwrap();
        let ka = id.key_agreement.clone().unwrap();
        assert_eq!(id.key_agreement_secret(), ka.secret);
        assert_eq!(id.key_agreement_secrets(), vec![ka.secret, derived], "the delegated key first");

        // kept: loaded back as issued; the file its owner's alone
        let back = Identity::load(&dir).unwrap();
        assert_eq!(back.key_agreement.as_ref().map(|k| (k.secret, k.delegation.frame())), Some((ka.secret, ka.delegation.frame())));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join("key-agreement.json")).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // the credential verifies as the identity's (§7.3), naming the key
        let resolver = dsip_core::did::StaticResolver::default();
        let ctx = dsip_core::envelope::Context::new(now, &resolver);
        let cred = serde_json::from_str(&ka.delegation.frame()).unwrap();
        let v = dsip_schema::key_agreement::verify(&cred, &ctx, Some(&id.meta.identity)).unwrap();
        assert_eq!(v.public, ka.public());

        // a device's hint carrying it passes a node's check (DHT Hints Profile §4)
        let endpoints = [dsip_dht::record::Endpoint::signaling("wss://relay.example.com/dsip")];
        let hint = crate::hints::reachability_with(&id.meta.identity, &id.device, &id.delegation, &endpoints, now, now, 3600, Some(&ka.delegation));
        let e = dsip_dht::record::evaluate(&hint.frame(), &ctx, None);
        assert!(e.verdict.ok(), "{:?}", e.verdict);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_key_files_are_their_owners_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("dsip-identity-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let made = Identity::init(&dir, "Ann", None, None).unwrap();
        for f in ["controller.key", "device.key"] {
            assert_eq!(std::fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
        }
        assert_eq!(Identity::load(&dir).unwrap().device.did(), made.device.did(), "and still read back");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_did_web_document_names_the_relay_the_mailbox_and_the_delegated_key_agreement_key() {
        let dir = std::env::temp_dir().join(format!("dsip-identity-web-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut id = Identity::init(&dir, "Ann", None, None).unwrap();
        let secret = id.derived_key_agreement_secret(0);
        id.issue_key_agreement(secret, crate::now_s()).unwrap();
        id.rehome_did_web("did:web:ann.example.com", &[]).unwrap();
        let ka = id.key_agreement.clone().unwrap();
        assert_eq!(ka.secret, secret, "the same key, re-issued for the new subject");
        let doc = id.did_web_document(Some("wss://relay.example.com/dsip"), Some(("did:web:mbx.example.com", "wss://mbx.example.com/dsip")), &[]);
        let parsed: dsip_core::did::DidDocument = serde_json::from_value(doc).unwrap();
        assert_eq!(parsed.id, "did:web:ann.example.com");
        assert_eq!(parsed.signaling_uri().as_deref(), Some("wss://relay.example.com/dsip"));
        assert_eq!(parsed.x25519_key_agreement(), Some(ka.public()), "the delegated key, not the derived one");
        assert_eq!(parsed.ed25519_key("did:web:ann.example.com#key-1", "key-1"), Some(id.controller.public()));
        assert!(parsed.service.iter().any(|s| s.service_type == "DSIPMailbox"));
        // rehome wrote one too, with the key agreement key and no services
        let written: dsip_core::did::DidDocument = serde_json::from_str(&std::fs::read_to_string(dir.join("did.json")).unwrap()).unwrap();
        assert_eq!(written.x25519_key_agreement(), Some(ka.public()));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
