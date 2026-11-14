//! `dsip-wasm` — the same verifier and engine, compiled for the browser.
//!
//! Spec: none (infrastructure) — every normative behavior comes from
//! `dsip-core`, `dsip-schema`, `dsip-session`, and `dsip-endpoint`; this crate
//! only marshals values across the wasm-bindgen boundary, as JavaScript objects
//! typed by the declarations in [`types`]. Saved records (the identity, the
//! contact file) cross as the JSON text that is stored. The browser supplies
//! the clock (`Date.now()/1000`), the WebSocket, WebRTC, and storage.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

pub mod messaging;
pub mod types;

/// What this client's device delegation carries (§7.4): signaling and interactive media for calls, and
/// `dsip.messaging` for the mailbox (M§4.3).
const DEVICE_CAPABILITIES: &[&str] = &["dsip.signaling", "dsip.media.interactive", "dsip.messaging"];

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_endpoint::hello::{client_hello, verify_relay_hello};
use dsip_endpoint::verify::SeenIds;
use dsip_endpoint::calls::AcceptPolicy;
use dsip_endpoint::{AnswerPolicy, CallCommand, Calls, CallsConfig, ContactFile, Core, CoreConfig, CoreEvent, IdentityKeys, Invite,
                    MediaResult, PresenceSealing};
use tsify::{Ts, Tsify as _};
use types::{CallOuts, Consent, Contacts, EndpointConfig, HintEndpoints, HintSelection, Json, LocalCommand, Mailbox, Notified, NumberContacts,
            OwnPresence, Placed, SealingStatus, Presence, PresenceStates, PresenceSubscription, Presences, RelayHello, Requests,
            SelectedHint, Sessions, Verdict, Voicemail, Whoami};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Result<[u8; 32], JsValue> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(JsValue::from_str("seed must be 64 hex chars"));
    }
    let mut out = [0u8; 32];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(c).map_err(js)?, 16).map_err(js)?;
    }
    Ok(out)
}

pub(crate) fn js<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Install the panic hook (better errors in the browser console).
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Create an identity: `{"controller_seed_hex","device_seed_hex"}` are generated when absent.
/// Returns JSON with seeds (keep private), DIDs, kid, and the signed delegation frame (§7.4).
#[wasm_bindgen]
pub fn create_identity(controller_seed_hex: Option<String>, device_seed_hex: Option<String>, display_name: &str, now: f64) -> Result<String, JsValue> {
    let controller = match controller_seed_hex {
        Some(h) => KeyPair::from_seed(unhex(&h)?),
        None => KeyPair::generate(),
    };
    let device = match device_seed_hex {
        Some(h) => KeyPair::from_seed(unhex(&h)?),
        None => KeyPair::generate(),
    };
    let now = now as i64;
    let payload = dsip_core::delegation::delegation_payload(
        &controller.did(),
        &device.did(),
        now - 60,
        now + 365 * 86_400,
        DEVICE_CAPABILITIES,
    );
    let delegation = sign(&payload, &controller, &controller.kid());
    Ok(json!({
        "controller_seed_hex": hex(&controller.seed()), "device_seed_hex": hex(&device.seed()),
        "identity": controller.did(), "device": device.did(), "kid": device.kid(),
        "display_name": display_name, "delegation": delegation.frame(),
    })
    .to_string())
}

/// Sign a `delegation-revocation` for `device` with the identity key in `identity_json` (§7.4, v0.8; spec-gap 57):
/// `id` a fresh ULID, `reason` a `dsip-revocation-reason` token. Returns the frame: hand it to the relay (which ends
/// the device's binding and refuses its next `hello`) and hold it ([`Endpoint::hold_revocation`]).
#[wasm_bindgen]
pub fn revocation_frame(identity_json: &str, id: &str, device: &str, reason: &str, now: f64) -> Result<String, JsValue> {
    let idj: Value = serde_json::from_str(identity_json).map_err(js)?;
    let controller = KeyPair::from_seed(unhex(idj["controller_seed_hex"].as_str().unwrap_or(""))?);
    let now = now as i64;
    let dsip = dsip_core::version::version_block(&dsip_core::version::Supported::all_known(), &[]);
    let p = dsip_core::delegation::revocation_payload(dsip, id, &controller.did(), device, now, reason, now);
    Ok(sign(&p, &controller, &controller.kid()).frame())
}

/// Rehome an identity to `did:web` (§7.2, §8.4): the same keys, the identity named by the DID, the device delegation
/// re-signed under `<did>#key-1`. Returns the identity JSON; [`did_document`] gives the document to host at the
/// DID's URL (`https://<host>/.well-known/did.json`, or `/<path>/did.json`).
#[wasm_bindgen]
pub fn rehome(identity_json: &str, did_web: &str, now: f64) -> Result<String, JsValue> {
    if !did_web.starts_with("did:web:") {
        return Err(JsValue::from_str("not a did:web DID"));
    }
    let mut id: Value = serde_json::from_str(identity_json).map_err(js)?;
    let controller = KeyPair::from_seed(unhex(id["controller_seed_hex"].as_str().unwrap_or(""))?);
    let device = KeyPair::from_seed(unhex(id["device_seed_hex"].as_str().unwrap_or(""))?);
    let now = now as i64;
    let payload = dsip_core::delegation::delegation_payload(
        did_web,
        &device.did(),
        now - 60,
        now + 365 * 86_400,
        DEVICE_CAPABILITIES,
    );
    id["identity"] = json!(did_web);
    id["delegation"] = json!(sign(&payload, &controller, &format!("{did_web}#key-1")).frame());
    Ok(id.to_string())
}

/// The DID document of a `did:web` identity (§7.2; the shape `dsip identity init --did-web` writes): one Multikey
/// verification method for the identity key, and `alsoKnownAs` (`tel:+…` claims the number of a binding, N§3.3).
/// Returns the document's text, to host as it is.
#[wasm_bindgen]
pub fn did_document(identity_json: &str, also_known_as: Vec<String>) -> Result<String, JsValue> {
    let id: Value = serde_json::from_str(identity_json).map_err(js)?;
    let did = id["identity"].as_str().unwrap_or("").to_string();
    if !did.starts_with("did:web:") {
        return Err(JsValue::from_str("not a did:web identity"));
    }
    let controller = KeyPair::from_seed(unhex(id["controller_seed_hex"].as_str().unwrap_or(""))?);
    let kid = format!("{did}#key-1");
    let multibase = controller.did().trim_start_matches("did:key:").to_string();
    let aka = also_known_as;
    let mut doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": did,
        "verificationMethod": [{"id": kid, "type": "Multikey", "controller": did, "publicKeyMultibase": multibase}],
        "authentication": [kid],
        "assertionMethod": [kid],
    });
    if !aka.is_empty() {
        doc["alsoKnownAs"] = json!(aka);
    }
    serde_json::to_string_pretty(&doc).map_err(js)
}

/// The X25519 secrets sealed bodies addressed to this identity and this device open with (§10.4): the identity's
/// when its key is on this device, and the device's.
fn unseal_keys(id: &Value, keys: &IdentityKeys) -> Result<Vec<(String, [u8; 32])>, JsValue> {
    let mut out = vec![];
    if let Some(seed) = id["controller_seed_hex"].as_str().filter(|s| !s.is_empty()) {
        out.push((keys.identity.clone(), dsip_core::hpke::x25519_from_ed25519_seed(&unhex(seed)?)));
    }
    out.push((keys.device.did(), dsip_core::hpke::x25519_from_ed25519_seed(&keys.device.seed())));
    Ok(out)
}

fn policy_of(policy: Json) -> dsip_number::Policy {
    dsip_number::Policy::from_json(&if policy.0.is_null() { json!({}) } else { policy.0 })
}

/// N§4: check a `tel` claim from an invite's `identity.claims` against the envelope's verified signing identity and
/// that identity's DID document (`null` when none is held), under a `tn-binding` policy (the vectors' context shape:
/// `trust_anchors`, `certificates`, …; `{}` for none). Returns the outcome: the lines the `tn-binding/claim-*`
/// vectors pin.
#[wasm_bindgen]
pub fn check_claim(claim: Ts<Json>, identity: &str, did_document: Ts<Json>, now: f64, policy: Ts<Json>) -> Result<Ts<dsip_number::ClaimOutcome>, JsError> {
    let out = dsip_number::check_claim(&claim.to_rust()?.0, identity, &did_document.to_rust()?.0, now as i64, &policy_of(policy.to_rust()?));
    Ok(out.into_ts()?)
}

/// N§5: the warning when a verified number now belongs to another identity than a stored contact listing it.
/// Returns the warning, or nothing when none is due.
#[wasm_bindgen]
pub fn identity_change(contacts: Ts<NumberContacts>, tn: &str, did: &str, attested_by: Option<String>, issued: f64) -> Result<Option<String>, JsError> {
    Ok(dsip_number::identity_change(&contacts.to_rust()?.0, tn, did, attested_by.as_deref(), issued as i64))
}

/// N§6, N§7: the DID a number resolves to, from the bindings a lookup returned (compact JWS strings; anything else
/// is passed over), each verified in full against its own DID's document (`documents`: `{did: document}`), the newest
/// winning. Returns nothing when no binding verifies.
#[wasm_bindgen]
pub fn tn_select(tn: &str, bindings: Ts<Json>, documents: Ts<Json>, now: f64, policy: Ts<Json>) -> Result<Option<Ts<dsip_number::Selected>>, JsError> {
    let bindings: Vec<Value> = serde_json::from_value(bindings.to_rust()?.0).unwrap_or_default();
    let docs: serde_json::Map<String, Value> = serde_json::from_value(documents.to_rust()?.0).unwrap_or_default();
    Ok(dsip_number::select(tn, &bindings, &docs, now as i64, &policy_of(policy.to_rust()?)).map(|s| s.into_ts()).transpose()?)
}

/// A signed reachability hint for this identity (DHT Hints Profile §2; §8.3: `seq` is the publisher's, newer wins):
/// the frame to `POST /dsip/v1/hints` on a node (§10). `endpoints` are `{uri, bindings?, service?, …}`: the
/// signaling relay (`service` absent) and, with `"service": "DSIPMailbox"`, the mailbox entry a `did:key` identity
/// advertises this way (Messaging Profile M§4.2). Signed by the device under its delegation, as the CLI's
/// `--publish-hint` signs; `ttl_s` is clamped to the profile's maximum (§12.9, spec-gap 96).
#[wasm_bindgen]
pub fn hint_frame(identity_json: &str, id: &str, endpoints: Ts<HintEndpoints>, ttl_s: f64, seq: f64, now: f64) -> Result<String, JsValue> {
    let id_v: Value = serde_json::from_str(identity_json).map_err(js)?;
    let device = KeyPair::from_seed(unhex(id_v["device_seed_hex"].as_str().unwrap_or(""))?);
    let delegation = Envelope::from_frame(id_v["delegation"].as_str().unwrap_or("")).map_err(|v| JsValue::from_str(&format!("{:?}", v.code)))?;
    let subject = id_v["identity"].as_str().unwrap_or("");
    let ttl = (ttl_s as i64).clamp(3, dsip_core::HINT_MAX_VALIDITY_S);
    let endpoints: Vec<dsip_dht::record::Endpoint> = serde_json::from_value::<Vec<Value>>(endpoints.to_rust().map_err(js)?.0)
        .map_err(js)?
        .into_iter()
        .map(|mut e| {
            if e.get("bindings").is_none() {
                e["bindings"] = json!(["ws/1.0"]);
            }
            serde_json::from_value(e).map_err(js)
        })
        .collect::<Result<_, _>>()?;
    let payload = dsip_dht::record::hint_payload_with_id(subject, subject, &endpoints, seq as i64, now as i64, ttl, id);
    Ok(dsip_dht::record::sign_hint(&payload, &device, vec![delegation]).frame())
}

/// Fold the hint frames a node (or several) returned for `did` down to the winner (§8.3: verified against the
/// subject DID or its delegation, unexpired, highest `seq`), with every candidate's verdict. `documents` is
/// `{did: document}` for `did:web` subjects. What it returns is a hint: never authority (§8.1 rule 6).
#[wasm_bindgen]
pub fn hint_select(did: &str, frames: Vec<String>, documents: Ts<Json>, now: f64) -> Result<Ts<HintSelection>, JsError> {
    let mut resolver = StaticResolver::default();
    for d in documents.to_rust()?.0.as_object().map(|o| o.values().cloned().collect::<Vec<_>>()).unwrap_or_default() {
        if let Ok(doc) = serde_json::from_value::<dsip_core::did::DidDocument>(d) {
            resolver.insert(doc);
        }
    }
    let ctx = Context::new(now as i64, &resolver);
    let (winner, report) = dsip_dht::record::select(&frames, &ctx);
    let hint = winner.filter(|h| h.subject == did).map(|h| {
        // `uri` is the signaling endpoint's (profile §2: `service` absent); every endpoint is in `endpoints`
        let signaling = h.endpoints.iter().find(|e| e.service() == "DSIPSignaling").or(h.endpoints.first());
        SelectedHint { uri: signaling.map(|e| e.uri.clone()), bindings: signaling.map(|e| e.bindings.clone()), endpoints: h.endpoints.clone(),
                       seq: h.seq, issued_at: h.issued_at, expires_at: h.expires_at, signer: h.signer }
    });
    Ok(HintSelection { hint, report: report.into_iter().map(|(_, v)| v).collect() }.into_ts()?)
}

/// Verify a frame standalone (stages 1–14) with a vector-style context. Returns the `expect` projection.
#[wasm_bindgen]
pub fn verify_frame(frame: &str, context: Ts<Json>) -> Result<Ts<Verdict>, JsError> {
    Ok(Verdict(verify_expect(frame, context.to_rust()?.0)).into_ts()?)
}

fn verify_expect(frame: &str, ctx: Value) -> Value {
    let ctx = if ctx.is_null() { json!({}) } else { ctx };
    let resolver = Context::resolver_from_vector(&ctx);
    let c = Context::from_vector(&ctx, &resolver);
    let env = match Envelope::from_frame(frame) {
        Ok(e) => e,
        Err(v) => return v.to_expect(),
    };
    match dsip_core::envelope::verify(&env, &c, Some(frame)) {
        Ok(ver) => {
            let sem = dsip_schema::check_payload(&ver.payload, &dsip_schema::SemanticContext::from_vector(&ctx));
            if !sem.ok() {
                return sem.to_expect();
            }
            let mut out = dsip_core::envelope::accept_verdict(&ver).to_expect();
            for (k, v) in sem.extra {
                out[k] = v;
            }
            out["payload"] = ver.payload;
            out
        }
        Err(v) => v.to_expect(),
    }
}

/// §18.1 verification basis for an identity + its `identity.claims` (anything but an array counts as none). The
/// browser renders exactly what the CLI does, through the one canonical `dsip_core::trust` function.
#[wasm_bindgen]
pub fn verification_basis(identity_did: &str, claims: Ts<Json>) -> Result<String, JsError> {
    let claims: Vec<Value> = serde_json::from_value(claims.to_rust()?.0).unwrap_or_default();
    Ok(dsip_core::trust::verification_basis(identity_did, &claims))
}

/// The `tel` caller headline for a call surface, or `""` if the claim is not a `tel` claim.
#[wasm_bindgen]
pub fn tel_caller_line(claim: Ts<Json>) -> Result<String, JsError> {
    Ok(dsip_core::trust::tel_caller_line(&claim.to_rust()?.0).unwrap_or_default())
}

/// A human summary of a `gateway.downgraded` error's losses.
#[wasm_bindgen]
pub fn downgrade_summary(losses: Vec<String>) -> String {
    dsip_core::trust::downgrade_summary(&losses.iter().map(String::as_str).collect::<Vec<_>>())
}

/// A watched identity's presence, as the page shows it: sealed records opened with the keys `core` holds, and the
/// devices whose records it cannot read listed as `unreadable`. Spec: P§4, P§12.4.
fn presence_of(core: &Core, w: &dsip_broadcast::presence::Watch, now: i64) -> Presence {
    let (c, unreadable) = w.view(now, |kid| core.presence_key(w.target(), kid));
    Presence { target: w.target().to_string(), state: c.state, token: c.token, source: c.source.to_string(), records: w.records().len(),
               unreadable, terminated: w.terminated() }
}

/// A browser endpoint: the engine + verifier + builder behind a JSON API, with the call glue
/// ([`dsip_endpoint::calls`]): the page is the media host, doing the media work the glue asks for.
#[wasm_bindgen]
pub struct Endpoint {
    core: Core,
    calls: Calls,
    supported: dsip_core::version::Supported,
    resolver: StaticResolver,
    seen: SeenIds,
    hello_id: Option<String>,
    presence: Option<dsip_broadcast::presence::Publisher>,
    /// The states picked, by audience (`None`: no audience), kept for the publisher created at the first binding.
    presence_states: std::collections::BTreeMap<Option<String>, String>,
    watches: std::collections::BTreeMap<String, dsip_broadcast::presence::Watch>,
    /// The labels of the audiences sealed, to their wire tags (P§12.1: a label never leaves this device).
    audience_tags: std::collections::BTreeMap<String, String>,
}

#[wasm_bindgen]
impl Endpoint {
    /// `identity_json` as returned by [`create_identity`], with its configuration. Sealed bodies addressed to this
    /// identity or device open with their keys (§10.4); `did:web` signers whose documents are not held are asked for
    /// (`resolve` events, answered with [`Endpoint::resolved`]). `seal_presence` seals this device's presence records
    /// (P§12), those with no audience and those of each label in `presence_audiences` (a label goes on the wire as its
    /// tag): it needs the identity's key agreement secret, so a device without the identity's key publishes in clear
    /// ([`Endpoint::presence_sealing`] says which).
    #[wasm_bindgen(constructor)]
    pub fn new(identity_json: &str, config: Ts<EndpointConfig>, now: f64) -> Result<Endpoint, JsValue> {
        let id: Value = serde_json::from_str(identity_json).map_err(js)?;
        let cfgv = config.to_rust().map_err(js)?;
        let device = KeyPair::from_seed(unhex(id["device_seed_hex"].as_str().unwrap_or(""))?);
        let delegation = Envelope::from_frame(id["delegation"].as_str().unwrap_or("")).map_err(|v| JsValue::from_str(&format!("{:?}", v.code)))?;
        let keys = IdentityKeys {
            identity: id["identity"].as_str().unwrap_or("").to_string(),
            device,
            delegation,
            display_name: id["display_name"].as_str().unwrap_or("").to_string(),
        };
        let unseal = unseal_keys(&id, &keys)?;
        // P§12.1, P§12.6: sealing is per audience; here `main` and every audience the user named, or none
        let secret = unseal.iter().find(|(did, _)| *did == keys.identity).map(|(_, sk)| *sk);
        let mut audience_tags = std::collections::BTreeMap::new();
        let presence = match (cfgv.seal_presence.unwrap_or(false), secret) {
            (true, Some(sk)) => {
                for l in &cfgv.presence_audiences {
                    audience_tags.insert(l.to_string(), dsip_core::presence_seal::audience_tag(&sk, &keys.identity, l));
                }
                Some(PresenceSealing {
                    sealed: std::iter::once(dsip_core::presence_seal::MAIN.to_string()).chain(audience_tags.values().cloned()).collect(),
                    t_rotate: cfgv.t_presence_rotate,
                })
            }
            _ => None,
        };
        let cfg = CoreConfig {
            video: cfgv.video.unwrap_or(false),
            t_establish: cfgv.t_establish,
            t_ring: cfgv.t_ring,
            t_ring_local: cfgv.t_ring_local,
            first_contact_required: cfgv.first_contact_required.unwrap_or(false),
            seal: cfgv.seal.unwrap_or(false),
            resolve_on_demand: true,
            unseal_keys: unseal,
            presence,
        };
        let calls = CallsConfig {
            media: true,
            answer: match cfgv.answer.as_deref().unwrap_or("ring") {
                "accept" => AnswerPolicy::Accept,
                "screen" => AnswerPolicy::Screen,
                "decline" => AnswerPolicy::Decline,
                "silent" => AnswerPolicy::Silent,
                _ => AnswerPolicy::Ring,
            },
            recording: match cfgv.recording.as_deref().unwrap_or("ask") {
                "always" => AcceptPolicy::Always,
                "never" => AcceptPolicy::Never,
                _ => AcceptPolicy::Ask,
            },
            one_call: cfgv.one_call.unwrap_or(false),
        };
        let resolver = StaticResolver::default();
        Ok(Endpoint {
            core: Core::new(keys, cfg, resolver.clone(), now as i64),
            calls: Calls::new(calls),
            supported: dsip_core::version::Supported::all_known(),
            resolver,
            seen: SeenIds::default(),
            hello_id: None,
            presence: None,
            presence_states: Default::default(),
            watches: Default::default(),
            audience_tags,
        })
    }

    /// Bound to the relay `authority` (its DID, from its `hello`): our presence records go there, and ending or changing
    /// a share sends its `grant-revocation`s there (they come back as `send` events of the `local` that ends it).
    /// Returns the first signed record to send now, or `null`; [`Endpoint::presence_tick`] returns the rest.
    /// Spec: P§3, P§6, P§7, P§12.5.
    pub fn presence_bound(&mut self, authority: &str, now: f64) -> Result<Option<String>, JsValue> {
        let now = now as i64;
        self.core.set_authority(Some(authority.to_string()));
        let out = match self.presence.as_mut() {
            Some(p) => p.rebind(authority, now),
            None => {
                let k = self.core.keys();
                let mut p = dsip_broadcast::presence::Publisher::new(&k.identity, &k.device.did(), authority, 300);
                for (audience, state) in &self.presence_states {
                    p.set_for(self.wire_audience(audience.as_deref()).as_deref(), Some(state), now);
                }
                let out = p.rebind(authority, now);
                self.presence = Some(p);
                out
            }
        };
        self.sign_presence(out, now)
    }

    /// The connection to our relay closed: a share ended now is ended here only (§19.4), as nothing reaches the
    /// authority. Spec: P§7.
    pub fn presence_unbound(&mut self) {
        self.core.set_authority(None);
    }

    /// Whether this device seals its presence records, the sealed audiences' tags, and when sealing was asked for but
    /// cannot be done, why. Spec: P§12.1, P§12.6.
    pub fn presence_sealing(&self) -> Result<Ts<SealingStatus>, JsError> {
        let sealed = self.core.presence_sealed(None);
        let reason = (!sealed && self.core.audience_tag("").is_none())
            .then(|| "this device does not hold the identity's key agreement secret (P§12.1)".to_string());
        Ok(SealingStatus { sealed, audiences: self.audience_tags.clone(), reason }.into_ts()?)
    }

    /// The `audience` (or `presence_audience` of a grant) that goes on the wire for the audience labelled `label`: its
    /// tag when the audience is sealed, else the label. Spec: P§12.1.
    pub fn presence_wire_audience(&self, label: &str) -> String {
        self.audience_tags.get(label).cloned().unwrap_or_else(|| label.to_string())
    }

    /// The label of a wire `audience`: the one whose tag it is, else the audience itself. Spec: P§12.1.
    pub fn presence_audience_label(&self, audience: &str) -> String {
        self.audience_tags.iter().find(|(_, t)| *t == audience).map_or_else(|| audience.to_string(), |(l, _)| l.clone())
    }

    fn wire_audience(&self, label: Option<&str>) -> Option<String> {
        label.map(|l| self.presence_wire_audience(l))
    }

    /// The user picked a presence state with no audience (`null` stops publishing). See [`Endpoint::presence_set_for`].
    /// Spec: P§3, P§5, P§8.
    pub fn presence_set(&mut self, state: Option<String>, now: f64) -> Result<Option<String>, JsValue> {
        self.presence_set_for(None, state, now)
    }

    /// The user picked a presence state for `audience` (`null`: the record with no audience; a state of `null` stops
    /// publishing that record). Returns the signed record to send now, or `null` (not bound yet, or P§8's publish
    /// interval holds it back: [`Endpoint::presence_tick`] returns it then). An audience that is not a P§6 token
    /// (`[a-z][a-z0-9-]*`, at most 64 characters) is an error.
    /// Spec: P§3, P§5, P§6, P§8.
    pub fn presence_set_for(&mut self, audience: Option<String>, state: Option<String>, now: f64) -> Result<Option<String>, JsValue> {
        if let Some(a) = &audience {
            if !dsip_broadcast::presence::is_audience(a) {
                return Err(JsValue::from_str(&format!("not an audience token (P§6): {a}")));
            }
            // P§12.6: a sealed subject never sends an audience it did not seal in clear (the label would leak)
            if self.core.presence_sealed(None) && !self.audience_tags.contains_key(a) {
                return Err(JsValue::from_str(&format!("audience {a} is not sealed yet: restart the engine with it in presence_audiences")));
            }
        }
        match &state {
            Some(st) => self.presence_states.insert(audience.clone(), st.clone()),
            None => self.presence_states.remove(&audience),
        };
        let wire = self.wire_audience(audience.as_deref());
        let out = self.presence.as_mut().and_then(|p| p.set_for(wire.as_deref(), state.as_deref(), now as i64));
        self.sign_presence(out, now as i64)
    }

    /// The states being published, by audience (`""`: no audience). Spec: P§6.
    pub fn presence_states(&self) -> Result<Ts<PresenceStates>, JsError> {
        Ok(PresenceStates(self.presence_states.iter().map(|(a, s)| (a.clone().unwrap_or_default(), s.clone())).collect()).into_ts()?)
    }

    /// One presence record due at `now` (a refresh, or one held back), signed, or `null`: call until `null`. Spec: P§8.
    pub fn presence_tick(&mut self, now: f64) -> Result<Option<String>, JsValue> {
        let out = self.presence.as_mut().and_then(|p| p.tick(now as i64));
        self.sign_presence(out, now as i64)
    }

    /// The epoch of `scope` (`main`, or an audience tag) rose: a `keys` emission. Returns its record, sealed at the new
    /// epoch, to send now, or `null` (none published for it, or P§8's interval holds it back: [`Endpoint::presence_tick`]
    /// returns it then). Spec: P§12.5, P§8. Impl: sent at once, not at the next refresh, so the grantees re-granted the
    /// new key read this device without waiting for it.
    pub fn presence_rekeyed(&mut self, scope: &str, now: f64) -> Result<Option<String>, JsValue> {
        let audience = (scope != dsip_core::presence_seal::MAIN).then(|| scope.to_string());
        let out = self.presence.as_mut().and_then(|p| {
            let state = p.state_for(audience.as_deref())?.to_string();
            p.set_for(audience.as_deref(), Some(&state), now as i64)
        });
        self.sign_presence(out, now as i64)
    }

    /// The authority refused our record for `audience` (`null`: no audience; the refused record's wire `audience`) with
    /// `reason` (an `error` whose `in_reply_to` is the record). Spec: P§9.
    pub fn presence_refused(&mut self, reason: &str, retry_after: Option<f64>, now: f64, audience: Option<String>) {
        if let Some(p) = self.presence.as_mut() {
            p.refused_for(audience.as_deref(), reason, retry_after.map(|r| r as i64), now as i64);
        }
    }

    fn sign_presence(&mut self, out: Option<Value>, now: i64) -> Result<Option<String>, JsValue> {
        let Some(p) = out else { return Ok(None) };
        let lifetime = self.presence.as_ref().map_or(300, |p| p.lifetime());
        // P§12.2: a sealed scope's record is sealed at its current epoch
        self.core.sign_presence(p, now, lifetime).map(Some).map_err(js)
    }

    /// A signed `subscribe` to `target`'s presence at its authority `authority` (the relay that answers for it,
    /// §9.3), for `expires_in` seconds (at most 3,600 for presence; a renewal replaces). Returns the frame, the
    /// subscription's id and how many grants it presents; the host sends the frame on its connection to that relay. It lists `presence/0.2`,
    /// so sealed records come too and are opened with the keys our grants carried. With `target` our own identity it
    /// is our own watch (P§6 rule 1), from which a sibling's higher epoch is adopted ([`Endpoint::presence_notify`]).
    /// Spec: §9.3, P§3, P§12.4, P§12.5.
    pub fn presence_subscribe(&mut self, target: &str, authority: &str, expires_in: f64, now: f64) -> Result<Ts<PresenceSubscription>, JsError> {
        let profiles = [dsip_broadcast::PROFILE, dsip_core::presence_seal::PROFILE];
        let mut p = json!({"dsip": dsip_core::version::version_block(&self.supported, &profiles),
                           "type": "subscribe", "to": authority, "target": target, "events": ["presence"], "expires_in": expires_in as i64});
        // P§6: presence is private by default; the grants we hold from the target admit us
        let claims = self.core.presence_claims(target, now as i64);
        let presented = claims.len();
        if presented > 0 {
            p["claims"] = Value::Array(claims);
        }
        let frame = self.core.sign_payload(p, now as i64, 30)?;
        let sub = Envelope::from_frame(&frame)
            .ok()
            .and_then(|e| dsip_core::b64::decode(&e.payload))
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v["id"].as_str().map(String::from))
            .unwrap_or_default();
        // §9.3: a renewal replaces the subscription; the watch follows the new one
        self.watches.retain(|_, w| w.target() != target);
        self.watches.insert(sub.clone(), dsip_broadcast::presence::Watch::new(target));
        Ok(PresenceSubscription { frame, subscription: sub, grants: presented }.into_ts()?)
    }

    /// A verified presence `notify` payload (from a `received` event). Each carried record is verified here, independently
    /// of the authority, and a sealed one opened with the keys our grants from the target carried. Returns the
    /// target's presence (P§4: `source` is `record`, `assertion` — the authority's claim — or `none`; P§12.4:
    /// `unreadable` lists the devices whose records we hold no key for), or nothing when it is for no presence watch
    /// of ours or out of order.
    ///
    /// On our own watch it returns `{own: true, events}` instead: each record of a sibling device may carry a higher
    /// epoch, which this device adopts, re-granting the grants that carry it; the events are driven like
    /// [`Endpoint::local`]'s. Spec: §9.3, P§3, P§4, P§12.4, P§12.5.
    pub fn presence_notify(&mut self, payload: Ts<Json>, now: f64) -> Result<Option<Ts<Notified>>, JsError> {
        let payload = payload.to_rust()?.0;
        let Some(sub) = payload["subscription"].as_str().map(String::from) else { return Ok(None) };
        let core = &self.core;
        let Some(w) = self.watches.get_mut(&sub) else { return Ok(None) };
        if !w.notify(&payload, |f| core.verify_record(f, now as i64)) {
            return Ok(None);
        }
        let terminated = w.terminated();
        let out = if w.target() == core.keys().identity {
            let me = core.keys().identity.clone();
            let mut events = vec![];
            for f in payload["body"]["records"].as_array().into_iter().flatten().filter_map(|r| r["frame"].as_str()) {
                if let Some((rec, identity)) = self.core.verify_record(f, now as i64) {
                    if identity == me && rec["device"] == rec["from"] {
                        events.extend(self.core.own_record(&rec, now as i64)?);
                    }
                }
            }
            let events = self.calls.observe(&mut self.core, events, now as i64)?;
            Notified::Own(OwnPresence { own: true, target: me, events, terminated })
        } else {
            Notified::Presence(presence_of(&self.core, w, now as i64))
        };
        if terminated {
            self.watches.remove(&sub);
        }
        Ok(Some(out.into_ts()?))
    }

    /// The authority refused the subscription `subscription` (a `reject`, §9.3): its watch is dropped, so nothing is
    /// shown for a target we may not watch.
    pub fn presence_rejected(&mut self, subscription: &str) {
        self.watches.remove(subscription);
    }

    /// Every watched identity's presence at `now`, as [`Endpoint::presence_notify`] gives it (records expire, P§4); our
    /// own watch, and a watch the authority has not answered yet, are not listed.
    pub fn presence_all(&self, now: f64) -> Result<Ts<Presences>, JsError> {
        let me = &self.core.keys().identity;
        let all = self.watches.values().filter(|w| w.target() != me && w.notified()).map(|w| presence_of(&self.core, w, now as i64));
        Ok(Presences(all.collect()).into_ts()?)
    }

    /// The client `hello` frame to send first on a connection (§13.2).
    pub fn hello_frame(&mut self, now: f64) -> String {
        let id = self.core.new_id(now as i64);
        self.hello_id = Some(id.clone());
        client_hello(self.core.keys(), &self.supported, &id, now as i64).frame()
    }

    /// Verify the relay's `hello` (must echo our id, §20.5): its DID and capabilities, or the verdict's code.
    pub fn relay_hello(&mut self, frame: &str, now: f64) -> Result<Ts<RelayHello>, JsError> {
        let sent = self.hello_id.clone().unwrap_or_default();
        let out = match verify_relay_hello(frame, &sent, now as i64, &self.resolver, &mut self.seen, &self.supported) {
            Ok(r) => RelayHello::Ok { ok: true, did: r.did, capabilities: r.capabilities },
            Err(v) => RelayHello::Refused { ok: false, code: v.to_expect()["code"].clone(), detail: v.detail },
        };
        Ok(out.into_ts()?)
    }

    /// Our DIDs and display name.
    pub fn whoami(&self) -> Result<Ts<Whoami>, JsError> {
        let k = self.core.keys();
        Ok(Whoami { identity: k.identity.clone(), device: k.device.did(), display_name: k.display_name.clone() }.into_ts()?)
    }

    /// A fresh ULID.
    pub fn new_id(&mut self, now: f64) -> String {
        self.core.new_id(now as i64)
    }

    /// Whether the next `invite`/`update` offers video (its descriptors must match the SDP that rides with it, B§2.1).
    pub fn set_video(&mut self, video: bool) {
        self.core.set_video(video);
    }

    /// Video codec registry ids the next offer lists; they must appear as `rtpmap`s in the SDP (B§3.4).
    pub fn set_video_codecs(&mut self, ids: Vec<String>) {
        self.core.set_video_codecs(ids);
    }

    /// A local event (README vocabulary), with what the host supplies for its message beside it: `sdp` on
    /// `place_call`, `accept`, `update` and `answer_update`; `claims` (§18.1) and `patch` (`{direction?,
    /// recording_session?, destination?}`, C§6, N§4.1) on `place_call`; `data` on `info` (B§4).
    pub fn local(&mut self, event: Ts<LocalCommand>, now: f64) -> Result<Ts<CallOuts>, JsError> {
        let out = self.core.command(event.to_rust()?.into_command(), now as i64)?;
        self.observe_ts(out, now)
    }

    /// An inbound frame.
    pub fn inbound(&mut self, frame: &str, now: f64) -> Result<Ts<CallOuts>, JsError> {
        let out = self.core.inbound(frame, now as i64)?;
        self.observe_ts(out, now)
    }

    /// Advance the clock; due timers fire.
    pub fn tick(&mut self, now: f64) -> Result<Ts<CallOuts>, JsError> {
        let out = self.core.tick(now as i64)?;
        self.observe_ts(out, now)
    }

    fn observe_ts(&mut self, events: Vec<CoreEvent>, now: f64) -> Result<Ts<CallOuts>, JsError> {
        let out = self.calls.observe(&mut self.core, events, now as i64)?;
        Ok(CallOuts(out).into_ts()?)
    }

    /// Place a call to `to` with what the invite carries beside its SDP (`{claims?, patch?}`, as `place_call` takes
    /// them). The events ask for the SDP offer (`media_request` `offer`), and the invite goes out once
    /// [`Endpoint::media`] hands it back (§16.3).
    pub fn place(&mut self, to: &str, invite: Ts<Invite>, now: f64) -> Result<Ts<Placed>, JsError> {
        let invite = Invite { sdp: None, ..invite.to_rust()? };
        let (session, events) = self.calls.place(&mut self.core, to, invite, now as i64)?;
        Ok(Placed { session, events }.into_ts()?)
    }

    /// What the user asks of a call.
    pub fn call(&mut self, command: Ts<CallCommand>, now: f64) -> Result<Ts<CallOuts>, JsError> {
        let out = self.calls.command(&mut self.core, command.to_rust()?, now as i64)?;
        Ok(CallOuts(out).into_ts()?)
    }

    /// The page's answer to a `media_request` (`offer`, `answer`), or a local ICE candidate (`candidate`: `null` at
    /// the end).
    pub fn media(&mut self, result: Ts<MediaResult>, now: f64) -> Result<Ts<CallOuts>, JsError> {
        let out = self.calls.media(&mut self.core, result.to_rust()?, now as i64)?;
        Ok(CallOuts(out).into_ts()?)
    }

    /// The outcome of a `resolve` event: the DID document fetched for `did` (JSON), or `""` when the fetch failed
    /// (`error` says why). A document is held from now on, for calls and for relay `hello`s alike (§8.1, §8.4); the
    /// frames that waited for it are verified.
    pub fn resolved(&mut self, did: &str, doc_json: &str, error: &str, now: f64) -> Result<Ts<CallOuts>, JsError> {
        let result = match serde_json::from_str::<dsip_core::did::DidDocument>(doc_json) {
            Ok(d) if d.id == did => {
                self.resolver.insert(d.clone());
                Ok(d)
            }
            Ok(d) => Err(dsip_core::did::ResolveError::Fetch { did: did.into(), detail: format!("the document is for {}", d.id) }),
            Err(e) => Err(dsip_core::did::ResolveError::Fetch { did: did.into(), detail: if error.is_empty() { e.to_string() } else { error.into() } }),
        };
        let out = self.core.resolved(did, result, now as i64)?;
        self.observe_ts(out, now)
    }

    /// Whether outbound session bodies are sealed (§10.4); a sealed call refused as an unknown critical extension is
    /// placed once more in clear, and sealing stays off afterwards.
    pub fn seal(&self) -> bool {
        self.core.seal()
    }

    /// Seal outbound session bodies to the addressee's key agreement key when it resolves (§10.4).
    pub fn set_seal(&mut self, on: bool) {
        self.core.set_seal(on);
    }

    /// The other side's recording in `session` (C§4), or nothing for a session that is not a call.
    pub fn recording(&self, session: &str) -> Result<Option<Ts<Consent>>, JsError> {
        Ok(self.calls.consent(session).map(|c| Consent(c).into_ts()).transpose()?)
    }

    /// Whether the other side's recording holds our media in `session` (C§4).
    pub fn holds_media(&self, session: &str) -> bool {
        self.calls.holds_media(session)
    }

    /// Seconds until the next timer, or -1.
    pub fn next_deadline(&self) -> f64 {
        self.core.endpoint().next_deadline().map(|d| d as f64).unwrap_or(-1.0)
    }

    /// Session snapshot (README shape) for one session id.
    pub fn session(&self, id: &str) -> Result<Ts<Sessions>, JsError> {
        Ok(Sessions(self.core.endpoint().snapshot([id.to_string()])).into_ts()?)
    }

    /// Contacts snapshot (README shape).
    pub fn contacts_snapshot(&self) -> Result<Ts<Contacts>, JsError> {
        Ok(Contacts(self.core.endpoint().contacts.snapshot()).into_ts()?)
    }

    /// Pending introductions, `[id, identity]` each.
    pub fn requests(&self) -> Result<Ts<Requests>, JsError> {
        Ok(Requests(self.core.requests()).into_ts()?)
    }

    /// Export persisted first-contact state (store it; reload with [`Endpoint::load_contacts`]).
    pub fn contacts_json(&self) -> String {
        serde_json::to_string(&self.core.contacts()).unwrap_or_else(|_| "{}".into())
    }

    /// Import persisted first-contact state.
    pub fn load_contacts(&mut self, json_text: &str) {
        if let Ok(f) = serde_json::from_str::<ContactFile>(json_text) {
            self.core.load_contacts(&f);
        }
    }

    /// Hold a DID document for resolution (§8.1: the document is the authority for its DID; the host obtained it, as
    /// the CLI's `--did-document`): `did:web` signers verify against it. Returns false for a value that is not a
    /// document.
    pub fn add_document(&mut self, doc: Ts<Json>) -> Result<bool, JsError> {
        Ok(match serde_json::from_value::<dsip_core::did::DidDocument>(doc.to_rust()?.0) {
            Ok(d) => {
                self.resolver.insert(d.clone());
                self.core.add_document(d);
                true
            }
            Err(_) => false,
        })
    }

    /// Hold a `delegation-revocation` frame (one we signed, or one handed to us): every later verification applies
    /// it (§7.4, v0.8: "any store they hold"). Returns false for text that is not a frame.
    pub fn hold_revocation(&mut self, frame: &str) -> bool {
        match Envelope::from_frame(frame) {
            Ok(e) => {
                self.core.hold_revocation(e);
                true
            }
            Err(_) => false,
        }
    }
}

/// Choose a peer's mailbox (M§4.2, §8.1): its DID document's `DSIPMailbox` entries when it has a document held here,
/// else the `DSIPMailbox` endpoints of its reachability hint (`hint_select`'s `endpoints`), through the vector-pinned
/// `select_mailbox`, with the selected entry and its URI.
#[wasm_bindgen]
pub fn mailbox_select(document: Ts<Json>, hint_endpoints: Ts<Json>) -> Result<Ts<Mailbox>, JsError> {
    let doc = document.to_rust()?.0;
    let document_entries: Vec<Value> = doc["service"].as_array().into_iter().flatten()
        .filter(|s| s["type"] == "DSIPMailbox").map(|s| s["serviceEndpoint"].clone()).collect();
    let hint_entries: Vec<Value> = serde_json::from_value::<Vec<Value>>(hint_endpoints.to_rust()?.0).unwrap_or_default().into_iter()
        .filter(|e| e["service"] == "DSIPMailbox")
        .map(|mut e| { if let Some(m) = e.as_object_mut() { m.remove("service"); } e }).collect();
    let all: Vec<Value> = document_entries.iter().chain(hint_entries.iter()).cloned().collect();
    let mut out = dsip_messaging::client::select_mailbox(&json!({"document_entries": document_entries, "hint_entries": hint_entries}));
    let entry = all.iter().find(|e| e["mailbox"] == out["selected"]).cloned().unwrap_or(Value::Null);
    out["uri"] = entry["uri"].clone();
    out["entry"] = entry; // M§4.2: `accepts` and `voicemail` are read from the selected entry
    Ok(Mailbox(out).into_ts()?)
}

/// Whether the caller may offer to record a voicemail after an attempt ended (M§13.2, the pinned rule), and its kind:
/// `entry_json` the callee's selected `DSIPMailbox` entry, `can_send` from [`messaging::Messenger::can_send`],
/// `outcome_type` `reject` or `cancel` (our own), `reason` its token, `call_video` whether the attempt offered video
/// (spec-gap 184; absent is false).
#[wasm_bindgen]
pub fn voicemail_offer(entry: Ts<Json>, can_send: bool, outcome_type: &str, reason: &str, call_video: Option<bool>)
                       -> Result<Ts<Voicemail>, JsError> {
    let entry = entry.to_rust()?.0;
    let out = dsip_messaging::client::voicemail_offer(&json!({"voicemail": entry["voicemail"], "can_send": can_send,
        "outcome": {"type": outcome_type, "reason": reason}, "call_video": call_video.unwrap_or(false),
        "accepts": entry["accepts"]}));
    Ok(Voicemail(out).into_ts()?)
}

/// Re-issue this identity's delegation with `dsip.messaging` (M§4.3), and `extra` when given (`dsip.record` for a
/// record-keeper, C§9), when the identity key is on this device: the identity JSON with the new delegation (see
/// [`messaging::redelegate`]).
#[wasm_bindgen]
pub fn redelegate(identity_json: &str, now: f64, extra: Option<String>) -> Result<String, JsValue> {
    messaging::redelegate(identity_json, now as i64, extra.as_deref())
}
