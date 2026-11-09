//! TURN credentials from a relay's `/turn` (the TURN REST API's short-lived credentials, the ones the browser client
//! asks for): a native device's calls get relay candidates, the path left when neither side's NAT lets a direct one
//! through (a phone on a mobile network). A device asks its own relay, which mints credentials for the TURN server its
//! operator runs beside it (`dsip-relay --turn-uri --turn-secret-file`); a relay with none answers `404`, and calls go
//! without TURN.
//!
//! Spec: none (infrastructure).

use std::time::Duration;

use serde_json::Value;

use crate::error::{Error, Result};

/// One TURN server and its credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnServer {
    /// `turn:host:port` (or `turns:`), as the relay names it.
    pub uri: String,
    /// The long-term-credential username (`<expiry>:<name>` under the TURN REST API).
    pub username: String,
    /// The password.
    pub credential: String,
}

/// What a relay's `/turn` gave: its servers, and when their credentials stop working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnCredentials {
    /// The servers, one for each URI the relay names.
    pub servers: Vec<TurnServer>,
    /// Unix seconds after which the credentials are refused.
    pub expires_at: i64,
}

impl TurnCredentials {
    /// Whether they still work for at least `margin` seconds after `now`.
    pub fn fresh(&self, now: i64, margin: i64) -> bool {
        self.expires_at - margin > now
    }
}

/// A client of one relay's `/turn`.
#[derive(Debug, Clone)]
pub struct TurnClient {
    url: String,
    http: reqwest::Client,
}

impl TurnClient {
    /// Seconds the relay may take to answer: a call waits for it.
    pub const TIMEOUT_S: u64 = 3;

    /// The `/turn` of the relay at `relay` (its `wss://host:port/…` URL, asked as `https://host:port/turn`), trusting
    /// `ca_pem` besides the platform's roots. `None` when `relay` is not a `wss://` URL.
    pub fn for_relay(relay: &str, ca_pem: Option<&[u8]>) -> Result<Option<TurnClient>> {
        let Some(rest) = relay.strip_prefix("wss://") else { return Ok(None) };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        if authority.is_empty() {
            return Ok(None);
        }
        TurnClient::new(&format!("https://{authority}/turn"), ca_pem).map(Some)
    }

    /// The credentials endpoint at `url` itself, trusting `ca_pem` besides the platform's roots.
    pub fn new(url: &str, ca_pem: Option<&[u8]>) -> Result<TurnClient> {
        let bad = |what: &str, e: reqwest::Error| Error::Io(std::io::Error::other(format!("turn {what}: {e}")));
        let mut b = reqwest::Client::builder().use_rustls_tls().timeout(Duration::from_secs(Self::TIMEOUT_S));
        if let Some(pem) = ca_pem {
            for cert in reqwest::Certificate::from_pem_bundle(pem).map_err(|e| bad("CA", e))? {
                b = b.add_root_certificate(cert);
            }
        }
        Ok(TurnClient { url: url.to_string(), http: b.build().map_err(|e| bad("client", e))? })
    }

    /// The URL asked.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Ask for credentials at `now` (unix seconds). An error when the relay has none (`404`), does not answer, or
    /// answers what is not `{"iceServers": [{urls, username, credential}], "ttl": s}`.
    pub async fn fetch(&self, now: i64) -> Result<TurnCredentials> {
        let fail = |what: String| Error::Io(std::io::Error::other(format!("{}: {what}", self.url)));
        let r = self.http.get(&self.url).send().await.map_err(|e| fail(e.to_string()))?;
        if !r.status().is_success() {
            return Err(fail(format!("HTTP {}", r.status().as_u16())));
        }
        let v: Value = r.json().await.map_err(|e| fail(e.to_string()))?;
        parse(&v, now).ok_or_else(|| fail("not TURN credentials".into()))
    }
}

/// `{"iceServers": [{urls, username, credential}], "ttl": s}` at `now`; only `turn:`/`turns:` URIs are kept.
fn parse(v: &Value, now: i64) -> Option<TurnCredentials> {
    let ttl = v["ttl"].as_i64().filter(|t| *t > 0)?;
    let mut servers = vec![];
    for s in v["iceServers"].as_array()? {
        let (Some(username), Some(credential)) = (s["username"].as_str(), s["credential"].as_str()) else { continue };
        let urls = match &s["urls"] {
            Value::String(u) => vec![u.as_str()],
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            _ => vec![],
        };
        for uri in urls.into_iter().filter(|u| u.starts_with("turn:") || u.starts_with("turns:")) {
            servers.push(TurnServer { uri: uri.into(), username: username.into(), credential: credential.into() });
        }
    }
    (!servers.is_empty()).then_some(TurnCredentials { servers, expires_at: now + ttl })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_relays_answer_gives_each_turn_uri_and_the_expiry() {
        let v = json!({"iceServers": [{"urls": ["turn:198.51.100.7:3478", "stun:198.51.100.7:3478", "turns:t.example:5349"],
                                       "username": "1794245505:dsip", "credential": "c"}], "ttl": 3600});
        let c = parse(&v, 1000).unwrap();
        assert_eq!(c.servers.iter().map(|s| s.uri.as_str()).collect::<Vec<_>>(), ["turn:198.51.100.7:3478", "turns:t.example:5349"]);
        assert_eq!((c.servers[0].username.as_str(), c.servers[0].credential.as_str()), ("1794245505:dsip", "c"));
        assert_eq!(c.expires_at, 4600);
        assert!(c.fresh(4000, 300) && !c.fresh(4300, 300));
        // one URL as a string, as RTCIceServer allows
        assert_eq!(parse(&json!({"iceServers": [{"urls": "turn:h:3478", "username": "u", "credential": "p"}], "ttl": 60}), 0).unwrap().servers.len(), 1);
    }

    #[test]
    fn nothing_usable_is_no_credentials() {
        assert!(parse(&json!({"iceServers": [{"urls": ["stun:h:3478"], "username": "u", "credential": "p"}], "ttl": 60}), 0).is_none());
        assert!(parse(&json!({"iceServers": [{"urls": ["turn:h:3478"]}], "ttl": 60}), 0).is_none());
        assert!(parse(&json!({"iceServers": [{"urls": ["turn:h:3478"], "username": "u", "credential": "p"}]}), 0).is_none());
    }

    #[test]
    fn the_relays_turn_is_beside_its_websocket() {
        let at = |r: &str| TurnClient::for_relay(r, None).unwrap().map(|c| c.url().to_string());
        assert_eq!(at("wss://relay.example:8443/dsip").as_deref(), Some("https://relay.example:8443/turn"));
        assert_eq!(at("wss://relay.example").as_deref(), Some("https://relay.example/turn"));
        assert_eq!(at("ws://relay.example/dsip"), None);
        assert_eq!(at("wss:///dsip"), None);
    }
}
