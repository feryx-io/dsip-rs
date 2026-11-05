//! Talking to a push gateway: one signed envelope POSTed to its `DSIPWake` endpoint, one signed envelope back.
//! A waker (relay, mailbox) sends `wake` with it; a device sends `wake-enrol` ([`enrol`]). A waker's own answer to a
//! device's `wake-register` is read the same way ([`read_reply`]).
//!
//! Spec: W§2.1 (the endpoint in the gateway's DID document, `POST` with `application/dsip+json`, a `200` answered with
//! `wake-accepted` or a core `error` naming the request in `in_reply_to`; any other status is a transport failure),
//! W§3, W§5.2, §8.1 (the gateway's document is authoritative for its endpoint and its keys).

use std::sync::Arc;
use std::time::Duration;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{self, Context, Envelope};

use crate::resolver::DidResolver;

/// What a gateway answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// `wake-accepted`; `handle` only in answer to `wake-enrol` (W§3).
    Accepted {
        /// The handle the gateway issued.
        handle: Option<String>,
    },
    /// A core `error`: its `reason` (a W§8.1 token, `transport.rate-limited`, …) and `retry_after` when given.
    Refused {
        /// The reason token.
        reason: String,
        /// Seconds to wait, with `transport.rate-limited`.
        retry_after: Option<i64>,
    },
}

/// Why a request got no answer to act on: a transport failure (W§2.1), which a waker MAY retry once (W§5.2).
#[derive(Debug, thiserror::Error)]
pub enum WakeError {
    /// The gateway's DID document could not be resolved.
    #[error("resolving {did}: {detail}")]
    Resolve {
        /// The gateway DID.
        did: String,
        /// Why.
        detail: String,
    },
    /// The document names no `DSIPWake` https endpoint.
    #[error("{0} names no DSIPWake https endpoint (W§2)")]
    NoEndpoint(String),
    /// The HTTP exchange failed, or the status was not 200.
    #[error("POST {url}: {detail}")]
    Http {
        /// The endpoint.
        url: String,
        /// Why.
        detail: String,
    },
    /// The gateway refused the enrolment ([`enrol`]): its reason.
    #[error("refused: {0}")]
    Refused(String),
    /// The answer was not a signed envelope from the gateway answering this request.
    #[error("answer from {did}: {detail}")]
    BadAnswer {
        /// The gateway DID.
        did: String,
        /// Why.
        detail: String,
    },
}

/// A client for push gateways, resolving each gateway's document with `resolver`.
#[derive(Clone)]
pub struct WakeClient {
    http: reqwest::Client,
    resolver: Arc<dyn DidResolver>,
}

impl WakeClient {
    /// Seconds a request may take.
    pub const TIMEOUT_S: u64 = 10;

    /// A client resolving gateway documents with `resolver`.
    pub fn new(resolver: Arc<dyn DidResolver>) -> WakeClient {
        let http = reqwest::Client::builder().https_only(true).timeout(Duration::from_secs(Self::TIMEOUT_S)).build().unwrap_or_default();
        WakeClient { http, resolver }
    }

    /// This client, also trusting the certificates in `pem` for gateway hosts (a private CA, a test's self-signed one).
    pub fn with_ca(mut self, pem: &[u8]) -> Result<WakeClient, WakeError> {
        let bad = |e: reqwest::Error| WakeError::Http { url: String::new(), detail: e.to_string() };
        let mut builder = reqwest::Client::builder().https_only(true).timeout(Duration::from_secs(Self::TIMEOUT_S));
        for cert in reqwest::Certificate::from_pem_bundle(pem).map_err(bad)? {
            builder = builder.add_root_certificate(cert);
        }
        self.http = builder.build().map_err(bad)?;
        Ok(self)
    }

    /// Send the signed `request` (its `to` is `gateway`) and read the gateway's signed answer.
    ///
    /// Spec: W§2.1. The answer is verified against the gateway's document (§8.1): signed by a key of `gateway`,
    /// addressed in reply to `request`'s id.
    pub async fn send(&self, gateway: &str, request: &Envelope) -> Result<Answer, WakeError> {
        let doc = self.resolver.resolve(gateway).await.map_err(|e| WakeError::Resolve { did: gateway.to_string(), detail: e.to_string() })?;
        let url = dsip_wake::wake_endpoint(&doc).ok_or_else(|| WakeError::NoEndpoint(gateway.to_string()))?;
        let http = |detail: String| WakeError::Http { url: url.clone(), detail };
        let resp = self
            .http
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/dsip+json")
            .body(request.frame())
            .send()
            .await
            .map_err(|e| http(e.to_string()))?;
        if resp.status() != reqwest::StatusCode::OK {
            return Err(http(format!("status {}", resp.status())));
        }
        let body = resp.text().await.map_err(|e| http(e.to_string()))?;
        let request_id = dsip_core::b64::decode(&request.payload)
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|p| p["id"].as_str().map(String::from))
            .unwrap_or_default();
        read_answer(gateway, &doc, &body, &request_id, crate::now_s())
    }
}

/// Verify and read a gateway's answer `body` to the request `request_id`, against the gateway's document.
///
/// Spec: W§2.1, §10.2 (stages 1–11; the answer is a fresh message, so the replay window applies).
pub fn read_answer(gateway: &str, doc: &dsip_core::did::DidDocument, body: &str, request_id: &str, now: i64) -> Result<Answer, WakeError> {
    let mut resolver = StaticResolver::default();
    resolver.insert(doc.clone());
    read_reply(gateway, &resolver, body, request_id, now)
}

/// Verify and read `frame`, an answer from `from` (a gateway, or the waker a device sent `wake-register`, W§4.2) to the
/// request `request_id`, against the documents in `resolver`: `wake-accepted` or a core `error`.
///
/// Spec: W§2.1, W§4.2, §10.2 (stages 1–11; the answer is a fresh message, so the replay window applies). Impl: read
/// apart from the endpoint's pipeline, whose schemas are the core's and drop the profile's `wake-accepted`.
pub fn read_reply(from: &str, resolver: &StaticResolver, frame: &str, request_id: &str, now: i64) -> Result<Answer, WakeError> {
    let bad = |detail: &str| WakeError::BadAnswer { did: from.to_string(), detail: detail.to_string() };
    let env = Envelope::from_frame(frame.trim()).map_err(|_| bad("not an envelope"))?;
    let ver = envelope::verify(&env, &Context::new(now, resolver), None).map_err(|v| bad(&format!("{:?}", v.code)))?;
    let p = &ver.payload;
    if ver.signer_did != from || p["from"] != from {
        return Err(bad("not signed by the one asked"));
    }
    if p["in_reply_to"] != request_id {
        return Err(bad("in_reply_to does not name the request"));
    }
    match ver.msg_type() {
        "wake-accepted" => Ok(Answer::Accepted { handle: p["handle"].as_str().map(String::from) }),
        "error" => Ok(Answer::Refused {
            reason: p["reason"].as_str().unwrap_or("transport.routing-refused").to_string(),
            retry_after: p["retry_after"].as_i64(),
        }),
        other => Err(bad(&format!("unexpected {other}"))),
    }
}

/// Enrol at `gateway` (W§3): `wake_key`, a key made for this enrolment and nothing else, sends `wake-enrol` with the
/// platform `token` of `provider` (`apns`, `fcm`) for `app`; returns the handle the gateway issued, or the refusal's
/// reason (`wake.unsupported-app`, …) as [`WakeError::Refused`]. The gateway never learns the device's DID.
///
/// Spec: W§3 (spec-gap 175).
pub async fn enrol(client: &WakeClient, gateway: &str, wake_key: &dsip_core::keys::KeyPair, provider: &str, app: &str, token: &str,
                   environment: Option<&str>) -> Result<String, WakeError> {
    let msg = dsip_wake::enrol_message(&wake_key.did(), gateway, provider, app, token, environment, crate::now_s());
    match client.send(gateway, &envelope::sign(&msg, wake_key, &wake_key.kid())).await? {
        Answer::Accepted { handle: Some(h) } => Ok(h),
        Answer::Accepted { handle: None } => Err(WakeError::BadAnswer { did: gateway.into(), detail: "wake-accepted with no handle".into() }),
        Answer::Refused { reason, .. } => Err(WakeError::Refused(reason)),
    }
}
