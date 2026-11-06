//! Push providers: what a gateway hands a checked wake to. APNs (token-based provider authentication over HTTP/2),
//! FCM (the HTTP v1 API with a service account), and [`Recorder`], which delivers nothing and keeps what it was given
//! (tests, demos, a gateway being set up).
//!
//! Spec: W§5.3 — the class decides the push (`call`: APNs `voip` push type, topic the handle's app; FCM high priority;
//! `message`: APNs `alert` with `mutable-content`, topic the handle's app; FCM high priority), the expiry is
//! `deliver_by`, the app's data is the compact JSON `{"dsip-wake": …}` (APNs: a top-level key beside `aps`; FCM: the
//! data field `dsip-wake` holding it as a string), and a token the provider reports unknown (APNs 410, FCM
//! `UNREGISTERED`) ends the handle.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use base64::Engine;
use serde_json::{json, Value};

use dsip_wake::Handle;

/// What a provider did with a push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Handed to the provider (never "delivered": neither APNs nor FCM reports delivery, W§5.3).
    Sent,
    /// The provider no longer knows the platform token.
    Unregistered,
    /// The provider could not be reached, or refused for another reason.
    Failed(String),
}

/// What [`Provider::push`] returns.
pub type PushFuture<'a> = Pin<Box<dyn Future<Output = Outcome> + Send + 'a>>;

/// A push provider.
pub trait Provider: Send + Sync {
    /// Push the gateway's `forward` (the output of [`dsip_wake::check_wake`]) to the handle's token.
    fn push<'a>(&'a self, handle: &'a Handle, forward: &'a Value) -> PushFuture<'a>;
}

/// The compact JSON of the app's data. Spec: W§5.3
fn data_json(forward: &Value) -> String {
    forward["data"].to_string()
}

/// A provider that delivers nothing and keeps every push it is given, as `{provider, app, token, class, deliver_by,
/// data}`, in memory and, when set, as JSON lines in a file. A token beginning `unregistered-` answers as a dead
/// token would (APNs 410), so the gateway's ending of a handle can be exercised.
///
/// Spec: none (infrastructure).
#[derive(Default, Clone)]
pub struct Recorder {
    pushes: Arc<Mutex<Vec<Value>>>,
    file: Option<std::path::PathBuf>,
}

impl Recorder {
    /// A recorder that also appends each push to `file`.
    pub fn to_file(file: std::path::PathBuf) -> Recorder {
        Recorder { pushes: Arc::default(), file: Some(file) }
    }

    /// Every push so far.
    pub fn pushes(&self) -> Vec<Value> {
        self.pushes.lock().map(|p| p.clone()).unwrap_or_default()
    }
}

impl Provider for Recorder {
    fn push<'a>(&'a self, handle: &'a Handle, forward: &'a Value) -> PushFuture<'a> {
        Box::pin(async move {
            if handle.token.starts_with("unregistered-") {
                return Outcome::Unregistered;
            }
            let line = json!({"provider": handle.provider, "app": handle.app, "token": handle.token, "class": forward["class"],
                              "deliver_by": forward["deliver_by"], "data": forward["data"]});
            if let Some(f) = &self.file {
                use std::io::Write;
                let w = std::fs::OpenOptions::new().create(true).append(true).open(f).and_then(|mut o| writeln!(o, "{line}"));
                if let Err(e) = w {
                    return Outcome::Failed(format!("{}: {e}", f.display()));
                }
            }
            if let Ok(mut p) = self.pushes.lock() {
                p.push(line);
            }
            Outcome::Sent
        })
    }
}

/// The DER inside a PEM block.
fn pem_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

fn b64(data: &[u8]) -> String {
    dsip_core::b64::encode(data)
}

/// A JWT `header.claims.signature` signed by `sign`.
fn jwt(header: &Value, claims: &Value, sign: impl FnOnce(&[u8]) -> Option<Vec<u8>>) -> Option<String> {
    let input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
    let sig = sign(input.as_bytes())?;
    Some(format!("{input}.{}", b64(&sig)))
}

/// A cached bearer token and when it is to be replaced.
type Cached = Mutex<Option<(String, i64)>>;

/// APNs over HTTP/2 with a provider authentication token (an ES256 JWT from the team's `.p8` signing key).
///
/// Spec: W§5.3. Apple: "Sending notification requests to APNs", "Establishing a token-based connection to APNs".
pub struct Apns {
    team_id: String,
    key_id: String,
    key: ring::signature::EcdsaKeyPair,
    http: reqwest::Client,
    production: String,
    sandbox: String,
    token: Cached,
}

impl Apns {
    /// APNs with the team's key `p8` (PEM PKCS#8 P-256), its key id and the team id.
    pub fn new(team_id: &str, key_id: &str, p8: &str) -> anyhow::Result<Apns> {
        let der = pem_der(p8).ok_or_else(|| anyhow::anyhow!("the APNs key is not PEM"))?;
        let rng = ring::rand::SystemRandom::new();
        let key = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng)
            .map_err(|e| anyhow::anyhow!("the APNs key is not a PKCS#8 P-256 key: {e}"))?;
        let http = reqwest::Client::builder().https_only(true).timeout(std::time::Duration::from_secs(10)).build()?;
        Ok(Apns {
            team_id: team_id.into(),
            key_id: key_id.into(),
            key,
            http,
            production: "https://api.push.apple.com".into(),
            sandbox: "https://api.sandbox.push.apple.com".into(),
            token: Mutex::new(None),
        })
    }

    /// The provider token, signed afresh every 50 minutes (APNs refuses one older than an hour, and one renewed more
    /// often than every 20 minutes).
    fn bearer(&self, now: i64) -> Option<String> {
        let mut t = self.token.lock().ok()?;
        if let Some((tok, until)) = t.as_ref() {
            if *until > now {
                return Some(tok.clone());
            }
        }
        let rng = ring::rand::SystemRandom::new();
        let tok = jwt(&json!({"alg": "ES256", "kid": self.key_id}), &json!({"iss": self.team_id, "iat": now}), |m| {
            self.key.sign(&rng, m).ok().map(|s| s.as_ref().to_vec())
        })?;
        *t = Some((tok.clone(), now + 3000));
        Some(tok)
    }

    /// The request for a push: its URL, headers and body. Spec: W§5.3
    pub fn request(&self, h: &Handle, forward: &Value) -> (String, Vec<(&'static str, String)>, Value) {
        let host = if h.environment.as_deref() == Some("sandbox") { &self.sandbox } else { &self.production };
        let data = &forward["data"]["dsip-wake"];
        let call = forward["class"] == "call";
        // The topic is the handle's app either way: an iOS device enrols its VoIP token on `<bundle>.voip` and its alert
        // token on `<bundle>` apart, as APNs takes each token for its own topic only (spec-gap 178).
        let (push_type, mut body) = if call {
            ("voip", json!({}))
        } else {
            ("alert", json!({"aps": {"alert": {"title-loc-key": "DSIP_NEW_MESSAGE"}, "mutable-content": 1}}))
        };
        let topic = h.app.clone();
        body["dsip-wake"] = data.clone();
        let headers = vec![
            ("apns-push-type", push_type.to_string()),
            ("apns-topic", topic),
            ("apns-priority", "10".to_string()),
            ("apns-expiration", forward["deliver_by"].as_i64().unwrap_or(0).max(0).to_string()),
        ];
        (format!("{host}/3/device/{}", h.token), headers, body)
    }
}

impl Provider for Apns {
    fn push<'a>(&'a self, h: &'a Handle, forward: &'a Value) -> PushFuture<'a> {
        Box::pin(async move {
            let Some(bearer) = self.bearer(dsip_transport::now_s()) else { return Outcome::Failed("signing the APNs token".into()) };
            let (url, headers, body) = self.request(h, forward);
            let mut req = self.http.post(&url).bearer_auth(bearer).json(&body);
            for (k, v) in headers {
                req = req.header(k, v);
            }
            match req.send().await {
                Ok(r) if r.status().is_success() => Outcome::Sent,
                Ok(r) if r.status() == reqwest::StatusCode::GONE => Outcome::Unregistered,
                Ok(r) => {
                    let status = r.status();
                    let reason = r.json::<Value>().await.ok().and_then(|v| v["reason"].as_str().map(String::from)).unwrap_or_default();
                    if status == reqwest::StatusCode::BAD_REQUEST && reason == "BadDeviceToken" {
                        Outcome::Unregistered
                    } else {
                        Outcome::Failed(format!("APNs {status} {reason}"))
                    }
                }
                Err(e) => Outcome::Failed(format!("APNs: {e}")),
            }
        })
    }
}

/// FCM's HTTP v1 API with a service account: an OAuth 2.0 access token from an RS256-signed assertion, then
/// `messages:send` in the handle's project.
///
/// Spec: W§5.3. Google: "Send messages using the FCM HTTP v1 API", "Using OAuth 2.0 for Server to Server Applications".
pub struct Fcm {
    client_email: String,
    token_uri: String,
    key: ring::signature::RsaKeyPair,
    http: reqwest::Client,
    send_base: String,
    token: Cached,
}

impl Fcm {
    /// The OAuth scope FCM needs.
    pub const SCOPE: &'static str = "https://www.googleapis.com/auth/firebase.messaging";

    /// FCM with a service account's JSON key file (`client_email`, `private_key`, `token_uri`).
    pub fn new(service_account: &Value) -> anyhow::Result<Fcm> {
        let field = |k: &str| service_account[k].as_str().map(String::from).ok_or_else(|| anyhow::anyhow!("the service account has no {k}"));
        let der = pem_der(&field("private_key")?).ok_or_else(|| anyhow::anyhow!("the service account key is not PEM"))?;
        let key = ring::signature::RsaKeyPair::from_pkcs8(&der).map_err(|e| anyhow::anyhow!("the service account key is not PKCS#8 RSA: {e}"))?;
        let http = reqwest::Client::builder().https_only(true).timeout(std::time::Duration::from_secs(10)).build()?;
        Ok(Fcm {
            client_email: field("client_email")?,
            token_uri: field("token_uri").unwrap_or_else(|_| "https://oauth2.googleapis.com/token".into()),
            key,
            http,
            send_base: "https://fcm.googleapis.com".into(),
            token: Mutex::new(None),
        })
    }

    /// The signed assertion exchanged for an access token.
    pub fn assertion(&self, now: i64) -> Option<String> {
        let rng = ring::rand::SystemRandom::new();
        let claims = json!({"iss": self.client_email, "scope": Self::SCOPE, "aud": self.token_uri, "iat": now, "exp": now + 3600});
        jwt(&json!({"alg": "RS256", "typ": "JWT"}), &claims, |m| {
            let mut sig = vec![0; self.key.public().modulus_len()];
            self.key.sign(&ring::signature::RSA_PKCS1_SHA256, &rng, m, &mut sig).ok()?;
            Some(sig)
        })
    }

    async fn access_token(&self, now: i64) -> Result<String, String> {
        if let Some((tok, until)) = self.token.lock().ok().and_then(|t| t.clone()) {
            if until > now {
                return Ok(tok);
            }
        }
        let assertion = self.assertion(now).ok_or("signing the assertion")?;
        let r = self
            .http
            .post(&self.token_uri)
            .form(&[("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"), ("assertion", assertion.as_str())])
            .send()
            .await
            .map_err(|e| format!("token: {e}"))?;
        if !r.status().is_success() {
            return Err(format!("token: {}", r.status()));
        }
        let v: Value = r.json().await.map_err(|e| format!("token: {e}"))?;
        let tok = v["access_token"].as_str().ok_or("token: no access_token")?.to_string();
        let ttl = v["expires_in"].as_i64().unwrap_or(3600);
        if let Ok(mut t) = self.token.lock() {
            *t = Some((tok.clone(), now + ttl - 60));
        }
        Ok(tok)
    }

    /// The request for a push: its URL and body. Spec: W§5.3
    pub fn request(&self, h: &Handle, forward: &Value, now: i64) -> (String, Value) {
        let ttl = (forward["deliver_by"].as_i64().unwrap_or(now) - now).max(0);
        let body = json!({"message": {"token": h.token, "data": {"dsip-wake": data_json(forward)},
                                      "android": {"priority": "HIGH", "ttl": format!("{ttl}s")}}});
        (format!("{}/v1/projects/{}/messages:send", self.send_base, h.app), body)
    }
}

impl Provider for Fcm {
    fn push<'a>(&'a self, h: &'a Handle, forward: &'a Value) -> PushFuture<'a> {
        Box::pin(async move {
            let now = dsip_transport::now_s();
            let tok = match self.access_token(now).await {
                Ok(t) => t,
                Err(e) => return Outcome::Failed(format!("FCM {e}")),
            };
            let (url, body) = self.request(h, forward, now);
            match self.http.post(&url).bearer_auth(tok).json(&body).send().await {
                Ok(r) if r.status().is_success() => Outcome::Sent,
                Ok(r) => {
                    let status = r.status();
                    let v: Value = r.json().await.unwrap_or_default();
                    let unregistered = v["error"]["details"].as_array().into_iter().flatten().any(|d| d["errorCode"] == "UNREGISTERED");
                    if unregistered || status == reqwest::StatusCode::NOT_FOUND {
                        Outcome::Unregistered
                    } else {
                        Outcome::Failed(format!("FCM {status} {}", v["error"]["status"].as_str().unwrap_or("")))
                    }
                }
                Err(e) => Outcome::Failed(format!("FCM: {e}")),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forward(class: &str, kind: &str) -> Value {
        json!({"class": class, "deliver_by": 1_790_000_060, "data": {"dsip-wake": {"kind": kind, "waker": "did:key:z6MkRelay", "session": "01K8S0E8M3000000000000000A"}}})
    }

    fn apns() -> (Apns, ring::signature::UnparsedPublicKey<Vec<u8>>) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref()));
        let a = Apns::new("TEAM123456", "KEY1234567", &pem).unwrap();
        let public = ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, ring::signature::KeyPair::public_key(&a.key).as_ref().to_vec());
        (a, public)
    }

    #[test]
    fn the_apns_token_is_an_es256_jwt_with_the_team_and_key() {
        let (a, public) = apns();
        let t = a.bearer(1_790_000_000).unwrap();
        let parts: Vec<&str> = t.split('.').collect();
        let header: Value = serde_json::from_slice(&dsip_core::b64::decode(parts[0]).unwrap()).unwrap();
        let claims: Value = serde_json::from_slice(&dsip_core::b64::decode(parts[1]).unwrap()).unwrap();
        assert_eq!(header, json!({"alg": "ES256", "kid": "KEY1234567"}));
        assert_eq!(claims, json!({"iss": "TEAM123456", "iat": 1_790_000_000}));
        public.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &dsip_core::b64::decode(parts[2]).unwrap()).unwrap();
        assert_eq!(a.bearer(1_790_000_100).unwrap(), t, "reused within 50 minutes");
    }

    #[test]
    fn a_call_is_a_voip_push_on_the_voip_topic() {
        let (a, _) = apns();
        let h = Handle { key: "k".into(), provider: "apns".into(), app: "org.dsip.app.voip".into(), token: "ab12".into(), environment: Some("sandbox".into()) };
        let (url, headers, body) = a.request(&h, &forward("call", "call"));
        assert_eq!(url, "https://api.sandbox.push.apple.com/3/device/ab12");
        assert!(headers.contains(&("apns-push-type", "voip".into())));
        assert!(headers.contains(&("apns-topic", "org.dsip.app.voip".into())));
        assert!(headers.contains(&("apns-expiration", "1790000060".into())));
        assert_eq!(body, json!({"dsip-wake": {"kind": "call", "waker": "did:key:z6MkRelay", "session": "01K8S0E8M3000000000000000A"}}));
    }

    #[test]
    fn a_message_is_a_mutable_alert_on_the_alert_tokens_topic() {
        let (a, _) = apns();
        let h = Handle { key: "k".into(), provider: "apns".into(), app: "org.dsip.app".into(), token: "ab12".into(), environment: None };
        let (url, headers, body) = a.request(&h, &forward("message", "message"));
        assert!(url.starts_with("https://api.push.apple.com/"));
        assert!(headers.contains(&("apns-push-type", "alert".into())));
        assert!(headers.contains(&("apns-topic", "org.dsip.app".into())));
        assert_eq!(body["aps"]["mutable-content"], 1);
        assert_eq!(body["dsip-wake"]["kind"], "message");
    }

    #[test]
    fn an_fcm_push_carries_the_data_as_a_string_and_the_assertion_verifies() {
        let pem = include_str!("../tests/fcm-test-key.pem");
        let f = Fcm::new(&json!({"client_email": "push@proj.iam.gserviceaccount.com", "private_key": pem, "token_uri": "https://oauth2.googleapis.com/token"})).unwrap();
        let h = Handle { key: "k".into(), provider: "fcm".into(), app: "proj".into(), token: "tok".into(), environment: None };
        let (url, body) = f.request(&h, &forward("call", "call"), 1_790_000_000);
        assert_eq!(url, "https://fcm.googleapis.com/v1/projects/proj/messages:send");
        assert_eq!(body["message"]["android"], json!({"priority": "HIGH", "ttl": "60s"}));
        let data: Value = serde_json::from_str(body["message"]["data"]["dsip-wake"].as_str().unwrap()).unwrap();
        assert_eq!(data["dsip-wake"]["kind"], "call");
        let a = f.assertion(1_790_000_000).unwrap();
        let parts: Vec<&str> = a.split('.').collect();
        let claims: Value = serde_json::from_slice(&dsip_core::b64::decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["scope"], Fcm::SCOPE);
        assert_eq!(claims["exp"], 1_790_003_600);
        let public = ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, ring::signature::KeyPair::public_key(&f.key).as_ref().to_vec());
        public.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &dsip_core::b64::decode(parts[2]).unwrap()).unwrap();
    }
}
