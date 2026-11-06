//! The hints tier, through the hints nodes' HTTP API (DHT Hints Profile §10): a device publishes its signed
//! reachability hint (its relay, and for a `did:key` identity its mailbox, M§4.2), and looks up another identity's,
//! the winner of every node's records chosen as §8.3 says. What it finds is a hint, never authority (§8.1 rule 6): an
//! identity's DID document, when it has one, decides, and a hint is used only for one that has none.
//!
//! Spec: §8.1 (the authority order; hints last), §8.3 (signed, expiring records; the winner), §8.5, DHT Hints Profile
//! §2 (endpoints, `DSIPMailbox` carrying the service entry's fields), §10 (`GET /dsip/v1/hints/{did}`, `POST
//! /dsip/v1/hints`), M§4.2 (a mailbox found through a hint).
//! Impl: a node may be plain `http` (one on the same host, or behind the relay's proxy): the records are signed, and the
//! transport is not what is trusted. Nodes are asked in turn; one that does not answer is skipped.

use std::time::Duration;

use serde_json::{json, Value};

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_dht::record::{Endpoint, Hint};

use crate::error::{Error, Result};

/// What a node said to a published hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Published {
    /// Stored (`202`), and acknowledged by this many peers of the node's overlay.
    Accepted {
        /// Peers that acknowledged it, when the node says.
        acknowledged: Option<i64>,
    },
    /// The node holds a record that wins over it (`409`, §8.3: a higher `seq`, or the same `seq` live).
    Superseded,
    /// Refused, or not answered: why.
    Failed(String),
}

/// A client of the hints nodes.
#[derive(Debug, Clone)]
pub struct HintsClient {
    nodes: Vec<String>,
    http: reqwest::Client,
}

impl HintsClient {
    /// Seconds a node may take to answer.
    pub const TIMEOUT_S: u64 = 5;

    /// The nodes at `nodes` (`https://host:port`, or `http://` for one on this host), trusting `ca_pem` besides the
    /// platform's roots.
    pub fn new(nodes: Vec<String>, ca_pem: Option<&[u8]>) -> Result<HintsClient> {
        let mut b = reqwest::Client::builder().use_rustls_tls().timeout(Duration::from_secs(Self::TIMEOUT_S));
        if let Some(pem) = ca_pem {
            for cert in reqwest::Certificate::from_pem_bundle(pem).map_err(|e| Error::Io(std::io::Error::other(format!("hints CA: {e}"))))? {
                b = b.add_root_certificate(cert);
            }
        }
        let http = b.build().map_err(|e| Error::Io(std::io::Error::other(format!("hints client: {e}"))))?;
        Ok(HintsClient { nodes: nodes.into_iter().map(|n| n.trim_end_matches('/').to_string()).collect(), http })
    }

    /// The nodes asked.
    pub fn nodes(&self) -> &[String] {
        &self.nodes
    }

    /// Every record the nodes hold for `did`, each frame once.
    pub async fn frames(&self, did: &str) -> Vec<String> {
        let mut frames: Vec<String> = vec![];
        for n in &self.nodes {
            match self.http.get(format!("{n}/dsip/v1/hints/{did}")).send().await {
                Ok(r) if r.status().as_u16() == 200 => {
                    let v: Value = r.json().await.unwrap_or(Value::Null);
                    for f in v["hints"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                        if !frames.iter().any(|x| x == f) {
                            frames.push(f.to_string());
                        }
                    }
                }
                Ok(r) => tracing::debug!("hints for {did} at {n}: {}", r.status()),
                Err(e) => tracing::debug!("hints for {did} at {n}: {e}"),
            }
        }
        frames
    }

    /// The winning hint for `did` at `now` (§8.3: verified against the subject or its delegation, unexpired, the
    /// highest `seq`), or `None`. `documents` resolves a `did:web` subject; a `did:key` needs none.
    pub async fn lookup(&self, did: &str, documents: &StaticResolver, now: i64) -> Option<Hint> {
        let frames = self.frames(did).await;
        let ctx = Context::new(now, documents);
        let (winner, _) = dsip_dht::record::select(&frames, &ctx);
        winner.filter(|h| h.subject == did)
    }

    /// Publish `hint` on every node.
    pub async fn publish(&self, hint: &Envelope) -> Vec<(String, Published)> {
        let frame = hint.frame();
        let mut out = vec![];
        for n in &self.nodes {
            let r = self.http.post(format!("{n}/dsip/v1/hints")).header("content-type", "text/plain").body(frame.clone()).send().await;
            let p = match r {
                Ok(r) if r.status().as_u16() == 202 => {
                    let v: Value = r.json().await.unwrap_or(Value::Null);
                    Published::Accepted { acknowledged: v["acknowledged"].as_i64() }
                }
                Ok(r) if r.status().as_u16() == 409 => Published::Superseded,
                Ok(r) => {
                    let status = r.status();
                    Published::Failed(format!("{status} {}", r.text().await.unwrap_or_default().chars().take(80).collect::<String>()))
                }
                Err(e) => Published::Failed(e.to_string()),
            };
            out.push((n.clone(), p));
        }
        out
    }
}

/// The mailbox endpoint a `did:key` identity's hint carries for it (M§4.2, DHT Hints Profile §2): the fields of the
/// `DSIPMailbox` service entry it would have in a document.
pub fn mailbox_endpoint(mailbox_did: &str, uri: &str) -> Endpoint {
    let mut e = Endpoint::signaling(uri);
    for (k, v) in [
        ("service", json!("DSIPMailbox")),
        ("mailbox", json!(mailbox_did)),
        ("priority", json!(0)),
        ("profiles", json!(["messaging/1.0"])),
        ("accepts", json!(["text", "audio"])),
    ] {
        e.extra.insert(k.into(), v);
    }
    e
}

/// The endpoints a device advertises: `relay` (its signaling endpoint) and `mailbox` (`(DID, URI)`).
pub fn endpoints(relay: Option<&str>, mailbox: Option<(&str, &str)>) -> Vec<Endpoint> {
    let mut out = vec![];
    if let Some(r) = relay {
        out.push(Endpoint::signaling(r));
    }
    if let Some((did, uri)) = mailbox {
        out.push(mailbox_endpoint(did, uri));
    }
    out
}

/// This device's reachability hint for `identity`, advertising `endpoints` ([`endpoints`]), signed by `device` under
/// `delegation`, `seq` (newer than any it published before), valid `ttl_s` from `now` (at most
/// [`dsip_core::HINT_MAX_VALIDITY_S`]).
pub fn reachability(identity: &str, device: &KeyPair, delegation: &Envelope, endpoints: &[Endpoint], seq: i64, now: i64, ttl_s: i64) -> Envelope {
    reachability_with(identity, device, delegation, endpoints, seq, now, ttl_s, None)
}

/// As [`reachability`], carrying the identity's key agreement delegation (`key_agreement`, DHT Hints Profile §2; core
/// §7.3, spec-gap 179), so that senders find the key they seal to where they find the identity's devices.
#[allow(clippy::too_many_arguments)] // a hint's fields, as `reachability`'s
pub fn reachability_with(
    identity: &str,
    device: &KeyPair,
    delegation: &Envelope,
    endpoints: &[Endpoint],
    seq: i64,
    now: i64,
    ttl_s: i64,
    key_agreement: Option<&Envelope>,
) -> Envelope {
    let ttl = ttl_s.clamp(3, dsip_core::HINT_MAX_VALIDITY_S);
    // its id's time is its issue time (§12.9: a ULID consistent with `issued_at`)
    let id = dsip_core::ulid::Ulid::generate_at((now.max(0) as u64) * 1000);
    let mut payload = dsip_dht::record::hint_payload_with_id(identity, identity, endpoints, seq, now, ttl, id.as_str());
    if let Some(ka) = key_agreement {
        payload["key_agreement"] = json!({"protected": ka.protected, "payload": ka.payload, "signature": ka.signature});
    }
    dsip_dht::record::sign_hint(&payload, device, vec![delegation.clone()])
}

/// The `DSIPMailbox` entries a hint carries, as service entries (`service` dropped), for M§4.2's selection.
pub fn mailbox_entries(hint: &Hint) -> Vec<Value> {
    hint.endpoints
        .iter()
        .filter(|e| e.service() == "DSIPMailbox")
        .map(|e| {
            let mut v = json!(e);
            if let Some(m) = v.as_object_mut() {
                m.remove("service");
            }
            v
        })
        .collect()
}

/// The relay a hint names (its first signaling endpoint).
pub fn relay_of(hint: &Hint) -> Option<String> {
    hint.endpoints.iter().find(|e| e.service() == "DSIPSignaling").map(|e| e.uri.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reachability_hint_verifies_and_carries_the_mailbox() {
        let (controller, device) = (KeyPair::generate(), KeyPair::generate());
        let now = 1_790_000_000;
        let p = dsip_core::delegation::delegation_payload(&controller.did(), &device.did(), now - 60, now + 86_400, &["dsip.signaling", "dsip.messaging"]);
        let delegation = dsip_core::envelope::sign(&p, &controller, &controller.kid());
        let mailbox = KeyPair::generate().did();
        let advertised = endpoints(Some("wss://relay.test/dsip"), Some((&mailbox, "wss://mbx.test/dsip")));
        let hint = reachability(&controller.did(), &device, &delegation, &advertised, 7, now, 99_999);
        let resolver = StaticResolver::default();
        let (winner, verdicts) = dsip_dht::record::select(&[hint.frame()], &Context::new(now, &resolver));
        let h = winner.unwrap_or_else(|| panic!("it verifies: {verdicts:?}"));
        assert_eq!((h.subject.as_str(), h.seq, h.expires_at - h.issued_at), (controller.did().as_str(), 7, dsip_core::HINT_MAX_VALIDITY_S));
        assert_eq!(relay_of(&h).as_deref(), Some("wss://relay.test/dsip"));
        let entries = mailbox_entries(&h);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].get("service").is_none());
        let choice = dsip_messaging_select(&entries);
        assert_eq!(choice, Some(mailbox));
    }

    /// M§4.2's selection, as dsip-messaging makes it, reduced to what this test needs (the crate is not a dependency).
    fn dsip_messaging_select(entries: &[Value]) -> Option<String> {
        entries.iter().find(|e| e["profiles"].as_array().is_some_and(|p| p.iter().any(|x| x == "messaging/1.0"))).and_then(|e| e["mailbox"].as_str().map(String::from))
    }
}
