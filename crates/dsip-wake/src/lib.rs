//! `dsip-wake` — the rules of the DSIP Wake Profile (draft `wake/0.1`, `v1.0/dsip-wake-profile-v1.0-draft.md`, cited
//! `W§n`). Pure: no network, no push provider. A relay and a mailbox use [`Waker`] and [`check_register`]; a push
//! gateway uses [`check_enrol`] and [`check_wake`]; a woken app uses [`open_hint`].
//!
//! Spec: sections owned by this crate — W§3 (enrolment at the gateway — [`check_enrol`]), W§4 (the registration
//! credential, `wake-register`, when a registration ends — [`verify_registration`], [`check_register`], [`Waker`]),
//! W§5 (when a waker wakes, the gateway's checks and what it forwards — [`Waker`], [`check_wake`]), W§6 (the sealed
//! hint — [`seal_hint`], [`open_hint`]), W§7 (timers), W§8 (reason tokens).
//!
//! Every rule is pinned by `impl/vectors/wake/`; the Python reference is `impl/tools/dsipvec/wake.py`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod schemas;

use std::collections::{BTreeMap, BTreeSet};

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{self, Context, Envelope};
use dsip_core::{b64, hpke, wire};
use serde_json::{json, Map, Value};

pub use schemas::schema_ok;

/// The profile token every message of this profile names in `dsip.profiles`. Spec: W§2
pub const PROFILE: &str = "wake/0.1";
/// The longest registration, `expires_at` − `issued_at`. Spec: W§7 (W-Registration)
pub const W_REGISTRATION_S: i64 = 2_592_000;
/// A mailbox's minimum gap between `message` wakes to one device. Spec: W§7 (W-Coalesce)
pub const W_COALESCE_S: i64 = 60;
/// How long a `call-ended` wake is worth delivering. Spec: W§7 (W-Call-Ended)
pub const W_CALL_ENDED_S: i64 = 60;
/// How far ahead a registration's `issued_at` may be: the replay window (§12.9). Spec: W§4.2 step 3
pub const FUTURE_S: i64 = 300;
/// The sealed hint's HPKE suite, M§6.9's. Spec: W§6
pub const HINT_ALG: &str = hpke::ALG;
/// The sealed hint's HPKE `info`. Spec: W§6
pub const HINT_INFO: &[u8] = b"dsip wake hint v1";
/// The sealed hint's plaintext length, padded with spaces. Spec: W§6
pub const HINT_BYTES: usize = 256;

/// A refusal: the code the vectors compare, and the W§8.1 reason token when the refusal carries one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// The condition (`registration-invalid`, `schema-invalid`, …).
    pub code: &'static str,
    /// The reason token sent in a core `error` (`wake.registration-invalid`), when there is one.
    pub reason: Option<&'static str>,
}

impl Refusal {
    const fn token(reason: &'static str, code: &'static str) -> Refusal {
        Refusal {
            code,
            reason: Some(reason),
        }
    }
    const fn plain(code: &'static str) -> Refusal {
        Refusal { code, reason: None }
    }

    /// The vector form: `{"verdict": "reject", "code", "reason"?}`.
    pub fn to_json(self) -> Value {
        let mut out = json!({"verdict": "reject", "code": self.code});
        if let Some(r) = self.reason {
            out["reason"] = json!(r);
        }
        out
    }
}

/// The payload is not valid against its schema.
pub const SCHEMA_INVALID: Refusal = Refusal::plain("schema-invalid");
/// Spec: W§8.1 `wake.registration-invalid`.
pub const REGISTRATION_INVALID: Refusal =
    Refusal::token("wake.registration-invalid", "registration-invalid");
/// Spec: W§8.1 `wake.waker-mismatch`.
pub const WAKER_MISMATCH: Refusal = Refusal::token("wake.waker-mismatch", "waker-mismatch");
/// Spec: W§8.1 `wake.gateway-unknown`.
pub const GATEWAY_UNKNOWN: Refusal = Refusal::token("wake.gateway-unknown", "gateway-unknown");
/// Spec: W§8.1 `wake.unsupported-app`.
pub const UNSUPPORTED_APP: Refusal = Refusal::token("wake.unsupported-app", "unsupported-app");
/// Spec: W§8.1 `wake.not-authorized`.
pub const NOT_AUTHORIZED: Refusal = Refusal::token("wake.not-authorized", "not-authorized");
/// Spec: W§8.1 `wake.expired`.
pub const EXPIRED: Refusal = Refusal::token("wake.expired", "expired");

fn i64_of(v: &Value, k: &str) -> i64 {
    v[k].as_i64().unwrap_or(0)
}

fn str_of<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}

/// Verify a registration credential: stages 2–6 of the pipeline with no core-field check, no replay window and no
/// dedup; its payload valid against `wake-registration`; signed by a key of its `key`. Returns the payload.
///
/// Spec: W§4.1, W§4.2 step 1, §7.4 (the delegation's form; a credential is verified by its signature, not by a
/// delivery window).
pub fn verify_registration(registration: &Value, now: i64) -> Option<Value> {
    let env = Envelope::from_value(registration).ok()?;
    let resolver = StaticResolver::from_json_map(&Value::Null);
    let ver = envelope::verify_raw(&env, &Context::new(now, &resolver), false).ok()?;
    let p = ver.payload;
    (schema_ok("wake-registration", &p) && ver.signer_did == str_of(&p, "key")).then_some(p)
}

/// The gateway's reading of a verified `wake-enrol`: `{key, provider, app, token, environment?}`. `apps` are the
/// `(provider, app)` pairs it pushes for.
///
/// Spec: W§3.
pub fn check_enrol(enrol: &Value, apps: &[(String, String)]) -> Result<Value, Refusal> {
    if !schema_ok("wake-enrol", enrol) {
        return Err(SCHEMA_INVALID);
    }
    let (provider, app) = (str_of(enrol, "provider"), str_of(enrol, "app"));
    if !apps.iter().any(|(p, a)| p == provider && a == app) {
        return Err(UNSUPPORTED_APP);
    }
    let mut out =
        json!({"key": enrol["from"], "provider": provider, "app": app, "token": enrol["token"]});
    if provider == "apns" {
        // Spec: W§3 — `environment` is APNs only, `production` by default.
        out["environment"] = json!(enrol["environment"].as_str().unwrap_or("production"));
    }
    Ok(out)
}

/// What a waker accepted from a `wake-register`. Spec: W§4.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registered {
    /// The device's registration, to keep: `{device, key, gateway, handle, expires_at, kinds?, seal_key?}`.
    Registration(Value),
    /// `remove: true`: the device's registration ends.
    Removed,
}

/// A waker's checks on a verified `wake-register` from `device`, in the order W§4.2 gives. `gateways`, when given,
/// are the gateways it will use; `None` admits any.
///
/// Spec: W§4.2.
pub fn check_register(
    register: &Value,
    device: &str,
    waker: &str,
    now: i64,
    gateways: Option<&[String]>,
) -> Result<Registered, Refusal> {
    if !schema_ok("wake-register", register) {
        return Err(SCHEMA_INVALID);
    }
    if register["remove"] == json!(true) {
        return Ok(Registered::Removed);
    }
    let r = verify_registration(&register["registration"], now).ok_or(REGISTRATION_INVALID)?;
    if str_of(&r, "waker") != waker {
        return Err(WAKER_MISMATCH);
    }
    let (issued, expires) = (i64_of(&r, "issued_at"), i64_of(&r, "expires_at"));
    if !(issued < expires && expires <= issued + W_REGISTRATION_S)
        || expires <= now
        || issued > now + FUTURE_S
    {
        return Err(REGISTRATION_INVALID);
    }
    if gateways.is_some_and(|g| !g.iter().any(|x| x == str_of(&r, "gateway"))) {
        return Err(GATEWAY_UNKNOWN);
    }
    let mut out = json!({"device": device, "key": r["key"], "gateway": r["gateway"], "handle": r["handle"], "expires_at": expires});
    if let Some(kinds) = register["kinds"].as_array() {
        let set: BTreeSet<&str> = kinds.iter().filter_map(Value::as_str).collect();
        out["kinds"] = json!(set);
    }
    if let Some(k) = register.get("seal_key") {
        out["seal_key"] = k.clone();
    }
    Ok(Registered::Registration(out))
}

/// What a gateway knows of a handle it issued. Spec: W§3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    /// The wake key's `did:key`.
    pub key: String,
    /// `apns` or `fcm`.
    pub provider: String,
    /// The APNs topic or the FCM project.
    pub app: String,
    /// The platform token.
    pub token: String,
    /// APNs only: `production` or `sandbox`.
    pub environment: Option<String>,
}

/// The gateway's checks on a verified `wake` from `signer`, and the push it forwards: `{provider, app, token, class,
/// deliver_by, data, environment?}`. `handles` reads a handle the gateway issued.
///
/// Spec: W§5.3.
pub fn check_wake(
    wake: &Value,
    signer: &str,
    gateway: &str,
    now: i64,
    handles: impl Fn(&str) -> Option<Handle>,
) -> Result<Value, Refusal> {
    if !schema_ok("wake", wake) {
        return Err(SCHEMA_INVALID);
    }
    let r = verify_registration(&wake["registration"], now).ok_or(NOT_AUTHORIZED)?;
    let h = handles(str_of(&r, "handle")).ok_or(NOT_AUTHORIZED)?;
    if str_of(&r, "key") != h.key
        || str_of(&r, "waker") != signer
        || str_of(&r, "gateway") != gateway
        || i64_of(&r, "expires_at") <= now
    {
        return Err(NOT_AUTHORIZED);
    }
    if i64_of(wake, "deliver_by") <= now {
        return Err(EXPIRED);
    }
    let kind = str_of(wake, "kind");
    let mut data = json!({"kind": kind, "waker": signer});
    for k in ["session", "sealed"] {
        if let Some(x) = wake.get(k) {
            data[k] = x.clone();
        }
    }
    // Spec: W§5.3, W§8.2 — `call` and `call-ended` are the call class; any other kind, unknown ones included, is
    // `message`.
    let class = if matches!(kind, "call" | "call-ended") {
        "call"
    } else {
        "message"
    };
    let mut out = json!({"provider": h.provider, "app": h.app, "token": h.token, "class": class,
                         "deliver_by": wake["deliver_by"], "data": {"dsip-wake": data}});
    if h.provider == "apns" {
        out["environment"] = json!(h.environment.as_deref().unwrap_or("production"));
    }
    Ok(out)
}

/// Seal a `call` wake's hint to a registration's `seal_key`: `{alg, enc, ct}`, or `None` when the hint would exceed
/// 256 bytes (it is then not sent). `ephemeral` is the HPKE ephemeral secret, fresh for every hint.
///
/// Spec: W§6.
pub fn seal_hint(
    seal_key: &[u8; 32],
    session: &str,
    from: &str,
    on_behalf_of: Option<&str>,
    ephemeral: &[u8; 32],
) -> Option<Value> {
    let mut hint = Map::new();
    hint.insert("from".into(), json!(from));
    if let Some(o) = on_behalf_of {
        hint.insert("on_behalf_of".into(), json!(o));
    }
    let mut pt = serde_json::to_vec(&Value::Object(hint)).ok()?;
    if pt.len() > HINT_BYTES {
        return None;
    }
    pt.resize(HINT_BYTES, b' ');
    let (enc, ct) = hpke::hpke_seal(seal_key, HINT_INFO, session.as_bytes(), &pt, ephemeral);
    Some(json!({"alg": HINT_ALG, "enc": b64::encode(&enc), "ct": b64::encode(&ct)}))
}

/// A woken device opens a `call` wake's sealed hint with its seal secret: the hint `{from, on_behalf_of?}`, or why it
/// cannot be read (`sealed-alg-unsupported`, `sealed-open-failed`, `sealed-plaintext-invalid`).
///
/// Spec: W§6. The hint is the relay's claim: never the caller's identity until the invite verifies.
pub fn open_hint(sealed: &Value, session: &str, secret: &[u8; 32]) -> Result<Value, &'static str> {
    if sealed["alg"] != HINT_ALG {
        return Err("sealed-alg-unsupported");
    }
    let enc = b64::decode(str_of(sealed, "enc")).ok_or("sealed-open-failed")?;
    let ct = b64::decode(str_of(sealed, "ct")).ok_or("sealed-open-failed")?;
    let pt = hpke::hpke_open(&enc, secret, HINT_INFO, session.as_bytes(), &ct)
        .ok_or("sealed-open-failed")?;
    if pt.len() != HINT_BYTES {
        return Err("sealed-plaintext-invalid");
    }
    let end = pt.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    let hint = wire::parse_payload(&pt[..end], false).map_err(|_| "sealed-plaintext-invalid")?;
    if !schema_ok("wake-hint", &hint) {
        return Err("sealed-plaintext-invalid");
    }
    Ok(hint)
}

/// The `dsip` version block every message of this profile carries. Spec: W§2
pub fn version() -> Value {
    json!({"core": "1.0", "min_core": "1.0", "profiles": [PROFILE], "extensions": [], "critical": []})
}

fn message(msg_type: &str, from: &str, to: &str, now: i64, fields: Value) -> Value {
    let mut p = json!({"dsip": version(), "type": msg_type, "id": dsip_core::ulid::Ulid::generate().as_str(), "from": from, "to": to});
    if let Value::Object(f) = fields {
        for (k, v) in f {
            p[k] = v;
        }
    }
    p["issued_at"] = json!(now);
    p["expires_at"] = json!(now + 30);
    p
}

/// A `wake-enrol` payload from the wake key `from` (its `did:key`) to `gateway`. Spec: W§3
pub fn enrol_message(from: &str, gateway: &str, provider: &str, app: &str, token: &str, environment: Option<&str>, now: i64) -> Value {
    let mut f = json!({"provider": provider, "app": app, "token": token});
    if let Some(e) = environment {
        f["environment"] = json!(e);
    }
    message("wake-enrol", from, gateway, now, f)
}

/// A `wake-accepted` payload answering `in_reply_to`, with the `handle` when it answers an enrolment. Spec: W§3,
/// W§4.2, W§5.3
pub fn accepted_message(from: &str, to: &str, in_reply_to: &str, handle: Option<&str>, now: i64) -> Value {
    let mut f = json!({"in_reply_to": in_reply_to});
    if let Some(h) = handle {
        f["handle"] = json!(h);
    }
    message("wake-accepted", from, to, now, f)
}

/// A `WakeRegistration` credential payload: `waker` may ask `gateway` to wake `handle` until `expires_at`. Signed by
/// the wake key `key`. Spec: W§4.1
pub fn registration_payload(key: &str, waker: &str, gateway: &str, handle: &str, issued_at: i64, expires_at: i64) -> Value {
    json!({"type": "WakeRegistration", "key": key, "waker": waker, "gateway": gateway, "handle": handle,
           "issued_at": issued_at, "expires_at": expires_at})
}

/// A device's `WakeRegistration` for `waker` (W§4.1), signed by `wake_key` (the key it enrolled `handle` with at
/// `gateway`) and good for W-Registration from `now`: what `wake-register` carries, as JSON.
/// Spec: W§4.1, W§7.
pub fn registration(wake_key: &dsip_core::keys::KeyPair, waker: &str, gateway: &str, handle: &str, now: i64) -> Value {
    let p = registration_payload(&wake_key.did(), waker, gateway, handle, now, now + W_REGISTRATION_S);
    serde_json::to_value(envelope::sign(&p, wake_key, &wake_key.kid())).expect("an envelope is JSON")
}

/// A fresh seal secret for a device (W§6) and its X25519 public key, the `seal_key` it registers with a relay; the
/// secret opens the hints sealed to it ([`open_hint`]). Spec: W§4.2, W§6. Impl: the secret's 32 bytes are a fresh
/// Ed25519 seed (the system's random number generator, as every key here).
pub fn seal_keys() -> ([u8; 32], [u8; 32]) {
    let secret = dsip_core::keys::KeyPair::generate().seed();
    (secret, hpke::x25519_public(&secret))
}

/// A `wake-register` payload from `device` to `waker`, carrying a signed registration. Spec: W§4.2
pub fn register_message(device: &str, waker: &str, registration: &Value, seal_key: Option<&[u8; 32]>, kinds: Option<&[&str]>, now: i64) -> Value {
    let mut f = json!({"registration": registration});
    if let Some(k) = seal_key {
        f["seal_key"] = json!(b64::encode(k));
    }
    if let Some(k) = kinds {
        f["kinds"] = json!(k);
    }
    message("wake-register", device, waker, now, f)
}

/// A `wake-register` payload ending `device`'s registration at `waker`. Spec: W§4.2
pub fn remove_message(device: &str, waker: &str, now: i64) -> Value {
    message("wake-register", device, waker, now, json!({"remove": true}))
}

/// The `wake` payload from `waker` to `gateway` for a [`Waker`]'s [`Emit::Wake`] (`None` for any other emission),
/// with the sealed hint when there is one. Spec: W§5.2
pub fn wake_message(waker: &str, gateway: &str, registration: &Value, emit: &Emit, sealed: Option<Value>, now: i64) -> Option<Value> {
    let Emit::Wake { kind, session, deliver_by, .. } = emit else { return None };
    let mut f = json!({"registration": registration, "kind": kind});
    if let Some(s) = session {
        f["session"] = json!(s);
    }
    if let Some(s) = sealed {
        f["sealed"] = s;
    }
    f["deliver_by"] = json!(deliver_by);
    Some(message("wake", waker, gateway, now, f))
}

/// The `DSIPWake` endpoint a gateway's DID document names: the first such service whose `serviceEndpoint` is an
/// `https` URI.
///
/// Spec: W§2.
pub fn wake_endpoint(doc: &dsip_core::did::DidDocument) -> Option<String> {
    doc.service
        .iter()
        .filter(|s| s.service_type == "DSIPWake")
        .find_map(|s| s.service_endpoint.as_str().filter(|u| u.starts_with("https://")).map(String::from))
}

/// What a [`Waker`] emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emit {
    /// Send the gateway a `wake` for `device` (W§5.2).
    Wake {
        /// The device's DID.
        device: String,
        /// `call`, `call-ended` or `message`.
        kind: &'static str,
        /// The invite's session, for `call` and `call-ended`.
        session: Option<String>,
        /// After it the wake is useless.
        deliver_by: i64,
    },
    /// A device's registration ended (W§4.3).
    Ended {
        /// The device's DID.
        device: String,
        /// `expired`, `removed`, `revoked`, `forgotten` or `gateway`.
        cause: &'static str,
    },
}

impl Emit {
    /// The vector form.
    pub fn to_json(&self) -> Value {
        match self {
            Emit::Wake {
                device,
                kind,
                session,
                deliver_by,
            } => {
                let mut w = json!({"device": device, "kind": kind, "deliver_by": deliver_by});
                if let Some(s) = session {
                    w["session"] = json!(s);
                }
                json!({"wake": w})
            }
            Emit::Ended { device, cause } => json!({"ended": {"device": device, "cause": cause}}),
        }
    }
}

#[derive(Debug, Clone)]
struct Reg {
    identity: String,
    expires_at: i64,
    kinds: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
struct Held {
    expires_at: i64,
    devices: BTreeSet<String>,
    woken: BTreeSet<String>,
}

/// A relay's or a mailbox's wake state: registrations, bound devices, held invites, and the wakes it sends. Every
/// operation takes the time `at`; [`Waker::settle`] first settles what has expired by then, held invites before
/// registrations.
///
/// Spec: W§4.3 (when a registration ends), W§5.1 (when a waker wakes), §13.3 (a binding flushes what is held).
#[derive(Debug, Clone, Default)]
pub struct Waker {
    regs: BTreeMap<String, Reg>,
    bound: BTreeSet<String>,
    held: BTreeMap<String, Held>,
    last_message: BTreeMap<String, i64>,
}

impl Waker {
    /// An empty waker.
    pub fn new() -> Waker {
        Waker::default()
    }

    fn live(&self, d: &str, t: i64) -> bool {
        self.regs.get(d).is_some_and(|r| r.expires_at > t)
    }

    fn wants(&self, d: &str, kind: &str) -> bool {
        self.regs
            .get(d)
            .and_then(|r| r.kinds.as_ref())
            .is_none_or(|k| k.iter().any(|x| x == kind))
    }

    fn end(&mut self, d: &str, cause: &'static str) -> Vec<Emit> {
        match self.regs.remove(d) {
            Some(_) => vec![Emit::Ended {
                device: d.to_string(),
                cause,
            }],
            None => vec![],
        }
    }

    /// The invite `session` stops being held at `when`: each woken device still held for it gets `call-ended`.
    fn stop_holding(&mut self, session: &str, when: i64) -> Vec<Emit> {
        let Some(h) = self.held.remove(session) else {
            return vec![];
        };
        h.woken
            .intersection(&h.devices)
            .filter(|d| self.live(d, when) && self.wants(d, "call-ended"))
            .map(|d| Emit::Wake {
                device: d.clone(),
                kind: "call-ended",
                session: Some(session.to_string()),
                deliver_by: when + W_CALL_ENDED_S,
            })
            .collect()
    }

    /// Settle what has expired by `at`: held invites (in session order) at their `expires_at`, then registrations
    /// (§12.9: `expires_at` is the first instant they are no longer valid).
    pub fn settle(&mut self, at: i64) -> Vec<Emit> {
        let mut out = vec![];
        let due: Vec<(String, i64)> = self
            .held
            .iter()
            .filter(|(_, h)| h.expires_at <= at)
            .map(|(s, h)| (s.clone(), h.expires_at))
            .collect();
        for (s, when) in due {
            out.extend(self.stop_holding(&s, when));
        }
        let ended: Vec<String> = self
            .regs
            .iter()
            .filter(|(_, r)| r.expires_at <= at)
            .map(|(d, _)| d.clone())
            .collect();
        for d in ended {
            out.extend(self.end(&d, "expired"));
        }
        out
    }

    /// The devices with a registration, in code-point order.
    pub fn registrations(&self) -> Vec<String> {
        self.regs.keys().cloned().collect()
    }

    /// Keep `device`'s registration, replacing any (W§4.2).
    pub fn register(
        &mut self,
        device: &str,
        identity: &str,
        expires_at: i64,
        kinds: Option<Vec<String>>,
    ) {
        self.regs.insert(
            device.to_string(),
            Reg {
                identity: identity.to_string(),
                expires_at,
                kinds,
            },
        );
    }

    /// End `device`'s registration with `cause` (`removed`, `revoked`, `forgotten`; W§4.3).
    pub fn end_registration(&mut self, device: &str, cause: &'static str) -> Vec<Emit> {
        self.end(device, cause)
    }

    /// The gateway answered a wake for `device` with `reason`: any `wake.*` token, known or not, ends the
    /// registration (W§4.3, W§8.1); anything else changes nothing.
    pub fn answered(&mut self, device: &str, reason: &str) -> Vec<Emit> {
        if reason.starts_with("wake.") {
            self.end(device, "gateway")
        } else {
            vec![]
        }
    }

    /// `device` bound: what is held for it is flushed (§13.3), and its message count starts afresh (W§5.1).
    pub fn bind(&mut self, device: &str) {
        self.bound.insert(device.to_string());
        for h in self.held.values_mut() {
            h.devices.remove(device);
            h.woken.remove(device);
        }
        self.last_message.remove(device);
    }

    /// `device`'s binding ended.
    pub fn unbind(&mut self, device: &str) {
        self.bound.remove(device);
    }

    /// A relay holds the invite `session` for `devices` (§13.3): each unbound, registered device that wants calls is
    /// woken once (W§5.1).
    pub fn hold(
        &mut self,
        at: i64,
        session: &str,
        devices: &[String],
        expires_at: i64,
    ) -> Vec<Emit> {
        if expires_at <= at {
            return vec![];
        }
        let candidates: BTreeSet<&String> = devices
            .iter()
            .filter(|d| !self.bound.contains(*d))
            .collect();
        let wake: Vec<String> = {
            let h = self.held.get(session);
            candidates
                .iter()
                .filter(|d| {
                    !h.is_some_and(|h| h.woken.contains(**d))
                        && self.live(d, at)
                        && self.wants(d, "call")
                })
                .map(|d| (*d).clone())
                .collect()
        };
        let h = self
            .held
            .entry(session.to_string())
            .or_insert_with(|| Held {
                expires_at,
                devices: BTreeSet::new(),
                woken: BTreeSet::new(),
            });
        h.devices.extend(candidates.into_iter().cloned());
        h.woken.extend(wake.iter().cloned());
        wake.into_iter()
            .map(|d| Emit::Wake {
                device: d,
                kind: "call",
                session: Some(session.to_string()),
                deliver_by: expires_at,
            })
            .collect()
    }

    /// The held invite `session` was dropped at `at` (the initiator's `cancel`): `call-ended` to the woken (W§5.1).
    pub fn drop_invite(&mut self, at: i64, session: &str) -> Vec<Emit> {
        self.stop_holding(session, at)
    }

    /// A mailbox stored an item of `class` for `identity` (M§5.2): a `message` wake to each unbound, registered device
    /// of it that wants messages, at most once per W-Coalesce; never for `ephemeral` (W§5.1).
    pub fn store(&mut self, at: i64, identity: &str, class: &str) -> Vec<Emit> {
        if class == "ephemeral" {
            return vec![];
        }
        let due: Vec<String> = self
            .regs
            .iter()
            .filter(|(d, r)| {
                r.identity == identity
                    && !self.bound.contains(*d)
                    && self.live(d, at)
                    && self.wants(d, "message")
                    && self
                        .last_message
                        .get(*d)
                        .is_none_or(|last| at - last >= W_COALESCE_S)
            })
            .map(|(d, _)| d.clone())
            .collect();
        due.into_iter()
            .map(|d| {
                self.last_message.insert(d.clone(), at);
                Emit::Wake {
                    device: d,
                    kind: "message",
                    session: None,
                    deliver_by: at + W_COALESCE_S,
                }
            })
            .collect()
    }

    /// One trace event of the `wake` vectors (README, kind `wake`).
    fn step(&mut self, component: &str, ev: &Value) -> Vec<Emit> {
        let at = i64_of(ev, "at");
        let mut out = self.settle(at);
        let s = |k: &str| str_of(ev, k).to_string();
        if let Some(r) = ev.get("register") {
            let kinds = r["kinds"].as_array().map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            });
            self.register(
                str_of(r, "device"),
                str_of(r, "identity"),
                i64_of(r, "expires_at"),
                kinds,
            );
        } else if ev.get("remove").is_some() {
            out.extend(self.end(&s("remove"), "removed"));
        } else if ev.get("revoke").is_some() {
            out.extend(self.end(&s("revoke"), "revoked"));
        } else if ev.get("forget").is_some() {
            out.extend(self.end(&s("forget"), "forgotten"));
        } else if ev.get("bind").is_some() {
            self.bind(&s("bind"));
        } else if ev.get("unbind").is_some() {
            self.unbind(&s("unbind"));
        } else if let (Some(x), "relay") = (ev.get("hold"), component) {
            let devices: Vec<String> = x["devices"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect();
            out.extend(self.hold(at, str_of(x, "session"), &devices, i64_of(x, "expires_at")));
        } else if let (Some(_), "relay") = (ev.get("drop"), component) {
            out.extend(self.drop_invite(at, &s("drop")));
        } else if let (Some(x), "mailbox") = (ev.get("store"), component) {
            out.extend(self.store(at, str_of(x, "identity"), str_of(x, "class")));
        } else if let Some(a) = ev.get("answer") {
            out.extend(self.answered(str_of(a, "device"), str_of(a, "reason")));
        }
        out
    }
}

/// Run one `wake/` vector; the result is compared with its `expect`.
///
/// Spec: none (infrastructure).
pub fn run_vector(v: &Value) -> Value {
    let (i, c) = (&v["input"], &v["context"]);
    let now = i64_of(c, "now");
    let verdict = |r: Result<Value, Refusal>, key: &str| match r {
        Ok(x) => json!({"verdict": "accept", key: x}),
        Err(e) => e.to_json(),
    };
    match i["check"].as_str() {
        Some("schema") => {
            if schema_ok(str_of(i, "schema"), &i["value"]) {
                json!({"verdict": "accept"})
            } else {
                SCHEMA_INVALID.to_json()
            }
        }
        Some("enrol") => {
            let apps: Vec<(String, String)> = c["apps"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|a| {
                    (
                        str_of(a, "provider").to_string(),
                        str_of(a, "app").to_string(),
                    )
                })
                .collect();
            verdict(check_enrol(&i["enrol"], &apps), "enrolment")
        }
        Some("register") => {
            let gateways: Option<Vec<String>> = c["gateways"].as_array().map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            });
            match check_register(
                &i["register"],
                str_of(i, "device"),
                str_of(c, "waker"),
                now,
                gateways.as_deref(),
            ) {
                Ok(Registered::Removed) => json!({"verdict": "accept", "removed": true}),
                Ok(Registered::Registration(r)) => json!({"verdict": "accept", "registration": r}),
                Err(e) => e.to_json(),
            }
        }
        Some("gateway") => {
            let handles = &c["handles"];
            let read = |h: &str| {
                let e = handles.get(h)?;
                Some(Handle {
                    key: str_of(e, "key").to_string(),
                    provider: str_of(e, "provider").to_string(),
                    app: str_of(e, "app").to_string(),
                    token: str_of(e, "token").to_string(),
                    environment: e["environment"].as_str().map(String::from),
                })
            };
            verdict(
                check_wake(
                    &i["wake"],
                    str_of(i, "signer"),
                    str_of(c, "gateway"),
                    now,
                    read,
                ),
                "forward",
            )
        }
        Some("open-hint") => {
            let secret: Option<[u8; 32]> =
                hex(str_of(i, "secret_hex")).and_then(|b| b.try_into().ok());
            match secret.map(|s| open_hint(&i["sealed"], str_of(i, "session"), &s)) {
                Some(Ok(h)) => json!({"verdict": "accept", "hint": h}),
                Some(Err(code)) => json!({"verdict": "reject", "code": code}),
                None => json!({"error": "bad secret_hex"}),
            }
        }
        Some(_) => json!({"error": "unknown check"}),
        None => {
            let component = str_of(c, "component");
            let mut w = Waker::new();
            Value::Array(
                i["steps"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|st| {
                        let emit: Vec<Value> = w
                            .step(component, &st["event"])
                            .iter()
                            .map(Emit::to_json)
                            .collect();
                        json!({"emit": emit, "registrations": w.registrations()})
                    })
                    .collect(),
            )
        }
    }
}

fn hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_hint_opens() {
        let secret = [7u8; 32];
        let pk = hpke::x25519_public(&secret);
        let s = seal_hint(
            &pk,
            "01K8S0E8M3000000000000000A",
            "did:key:z6MkCaller",
            Some("did:web:alice.example"),
            &[9u8; 32],
        )
        .unwrap();
        let h = open_hint(&s, "01K8S0E8M3000000000000000A", &secret).unwrap();
        assert_eq!(
            h,
            json!({"from": "did:key:z6MkCaller", "on_behalf_of": "did:web:alice.example"})
        );
        assert_eq!(
            open_hint(&s, "01K8S0E8M3000000000000000B", &secret),
            Err("sealed-open-failed")
        );
    }

    #[test]
    fn a_hint_too_long_is_not_sealed() {
        let long = format!("did:web:{}", "a".repeat(250));
        assert!(seal_hint(&[1u8; 32], "s", &long, None, &[2u8; 32]).is_none());
    }
}
