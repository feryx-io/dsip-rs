//! Reachability hints on Pkarr: publish this identity's `_dsip` records, and discover a callee's relay, through
//! Pkarr relays, the Mainline DHT directly, or both.
//!
//! Spec: §8.1 (a hint is never authority), §8.3 (the higher seq wins), §8.5; DHT Hints Profile §9 (v0.9,
//! spec-gap 105). The relay HTTP API is Pkarr's: `PUT /<z32>` and `GET /<z32>`, the body a relay payload
//! (`signature ‖ ts ‖ dns`). On the DHT the same bytes are a BEP 44 mutable item: key, signature, `seq` = ts,
//! `v` = dns, no salt.
//!
//! Impl: relays and the DHT are sources of the same candidates. Every candidate, whatever its source, is read offline
//! by `dsip_core::pkarr::read`, and the highest valid seq wins — the mainline crate's own signature check and
//! "most recent" choice are not relied on. The publisher starts from the highest candidate that verifies under its
//! own key, keeps that packet's foreign TXT/A/AAAA records, and signs a timestamp strictly above it. The DHT put
//! carries no compare-and-swap: the seq order already settles concurrent publishers of one key.

use anyhow::{Context as _, Result};
use dsip_core::pkarr::{self, Hint, PublishEndpoint};
use dsip_transport::identity::Identity;
use futures_util::StreamExt as _;
use mainline::{async_dht::AsyncDht, Dht, MutableItem};
use std::time::Duration;

fn now_s() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn now_us() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

/// How long a DHT lookup may take before the answers in hand are used.
const DHT_QUERY: Duration = Duration::from_secs(20);

/// Where Pkarr packets are published and looked up: Pkarr relays, a Mainline DHT node, or both.
///
/// Spec: none (infrastructure).
pub struct Pkarr {
    relays: Vec<String>,
    dht: Option<AsyncDht>,
    http: reqwest::Client,
}

/// A Pkarr packet as found, with where it was found.
struct Candidate {
    source: String,
    payload: Vec<u8>,
}

impl Pkarr {
    /// `None` when neither relays nor the DHT were asked for. `bootstrap` empty means Mainline's public bootstrap
    /// nodes.
    pub async fn new(relays: &[String], mainline: bool, bootstrap: &[String]) -> Result<Option<Pkarr>> {
        if relays.is_empty() && !mainline {
            return Ok(None);
        }
        let dht = if mainline {
            let mut b = Dht::builder();
            if !bootstrap.is_empty() {
                b.bootstrap(bootstrap);
            }
            let dht = b.build().context("starting a Mainline DHT node")?.as_async();
            let joined = dht.bootstrapped().await;
            let addr = dht.info().await.local_addr();
            println!("dht        mainline node {addr} {}   (BEP 44; a hints tier, never authority §8.1)",
                     if joined { "joined" } else { "did NOT join — no bootstrap node answered" });
            Some(dht)
        } else {
            None
        };
        let http = reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?;
        Ok(Some(Pkarr { relays: relays.to_vec(), dht, http }))
    }

    /// Every packet the sources hold for `key`: one per relay, and every distinct item the DHT returns.
    async fn candidates(&self, key: &[u8; 32]) -> Vec<Candidate> {
        let z32 = pkarr::z32_encode(key);
        let mut out = vec![];
        for r in &self.relays {
            let url = format!("{}/{z32}", r.trim_end_matches('/'));
            let Ok(resp) = self.http.get(url).send().await else { continue };
            if resp.status().is_success() {
                if let Ok(b) = resp.bytes().await {
                    out.push(Candidate { source: format!("pkarr relay {r}"), payload: b.to_vec() });
                }
            }
        }
        if let Some(dht) = &self.dht {
            let mut items = dht.get_mutable(key, None, None);
            let deadline = tokio::time::Instant::now() + DHT_QUERY;
            while let Ok(Some(item)) = tokio::time::timeout_at(deadline, items.next()).await {
                let mut payload = item.signature().to_vec();
                payload.extend_from_slice(&(item.seq() as u64).to_be_bytes());
                payload.extend_from_slice(item.value());
                if !out.iter().any(|c| c.payload == payload) {
                    out.push(Candidate { source: "mainline DHT".into(), payload });
                }
            }
        }
        out
    }

    /// Publish a zone signed by `key`: start from the newest packet of its own (one slot per key), keep the foreign
    /// records, stay above its timestamp, then `build(ts, foreign)` and store it on every source. Returns the `ts`.
    ///
    /// Spec: DHT Hints Profile §9 (publishing).
    async fn publish_zone(
        &self,
        key: &dsip_core::keys::KeyPair,
        build: impl Fn(u64, &[pkarr::ForeignRecord]) -> Result<Vec<u8>, &'static str>,
    ) -> Result<(u64, Vec<String>)> {
        let public = key.public();
        let z32 = pkarr::z32_encode(&public);
        let mut prev_ts = 0u64;
        let mut foreign = vec![];
        for c in self.candidates(&public).await {
            let p = &c.payload;
            if p.len() < 72 || !pkarr::verify_payload(&public, p) {
                continue; // not ours: a relay's or a node's claim cannot move our seq
            }
            let ts = u64::from_be_bytes(p[64..72].try_into().unwrap_or_default());
            if ts > prev_ts {
                prev_ts = ts;
                foreign = pkarr::foreign_records(&public, p);
            }
        }
        let ts = pkarr::next_ts(now_us(), (prev_ts > 0).then_some(prev_ts))
            .context("this key's timestamps are exhausted (above 2^53−1 µs): nothing can be signed")?;
        let payload = build(ts, &foreign).map_err(|e| anyhow::anyhow!(e))?;
        let mut stored = vec![];
        for r in &self.relays {
            let resp = self.http.put(format!("{}/{z32}", r.trim_end_matches('/'))).body(payload.clone()).send().await;
            match resp {
                Ok(resp) if resp.status().is_success() => stored.push(format!("relay {r}")),
                Ok(resp) => println!("hint       pkarr relay {r} refused the publish: {}", resp.status()),
                Err(e) => println!("hint       pkarr relay {r} unreachable: {e}"),
            }
        }
        if let Some(dht) = &self.dht {
            let sig: [u8; 64] = payload[..64].try_into().expect("64-byte signature");
            let item = MutableItem::new_signed_unchecked(public, sig, &payload[72..], ts as i64, None);
            match dht.put_mutable(item, None).await {
                Ok(_) => stored.push("the mainline DHT".into()),
                Err(e) => println!("hint       mainline DHT put failed: {e}"),
            }
        }
        anyhow::ensure!(!stored.is_empty(), "no Pkarr relay or DHT stored the packet");
        Ok((ts, stored))
    }

    /// Publish this identity's `_dsip` endpoint at `relay_uri` to every source, signed by the identity key.
    ///
    /// Spec: DHT Hints Profile §9 (publishing).
    pub async fn publish(&self, id: &Identity, relay_uri: &str, ttl: u32) -> Result<()> {
        let ep = PublishEndpoint { uri: relay_uri.to_string(), bindings: vec!["ws/1.0".into()], service: None };
        let key = id.identity_key()?;
        let (ts, stored) = self.publish_zone(key, |ts, foreign| pkarr::build_payload(key, std::slice::from_ref(&ep), ttl, ts, foreign)).await?;
        println!("hint       pkarr published {relay_uri}  seq {ts}  ttl {ttl} s  to {}   §8.5 signed by the identity key",
                 stored.join(", "));
        Ok(())
    }

    /// Publish this **device's** zone: its endpoint at `relay_uri` and its delegation, signed by the device key, so
    /// the identity key can stay offline.
    ///
    /// Spec: DHT Hints Profile §9.1 (device hint).
    pub async fn publish_device(&self, id: &Identity, relay_uri: &str, ttl: u32) -> Result<()> {
        let ep = PublishEndpoint { uri: relay_uri.to_string(), bindings: vec!["ws/1.0".into()], service: None };
        let d = &id.delegation;
        let compact = format!("{}.{}.{}", d.protected, d.payload, d.signature);
        let key = &id.device;
        let (ts, stored) = self
            .publish_zone(key, |ts, foreign| pkarr::build_device_payload(key, std::slice::from_ref(&ep), &compact, ttl, ts, foreign))
            .await?;
        println!("hint       pkarr published device zone {relay_uri}  seq {ts}  ttl {ttl} s  to {}   §9.1 signed by the device key, with its delegation",
                 stored.join(", "));
        Ok(())
    }

    /// Publish this identity's pointer to its devices, signed by the identity key (§9.1). Done rarely: it lives up
    /// to 7 days.
    ///
    /// Spec: DHT Hints Profile §9.1 (pointer).
    pub async fn publish_pointer(&self, id: &Identity, devices: &[String], ttl: u32) -> Result<()> {
        let key = id.identity_key()?;
        let (ts, stored) = self.publish_zone(key, |ts, foreign| pkarr::build_pointer_payload(key, devices, ttl, ts, foreign)).await?;
        println!("pointer    pkarr published {} device(s)  seq {ts}  ttl {ttl} s  to {}   §9.1 signed by the identity key",
                 devices.len(), stored.join(", "));
        Ok(())
    }

    /// Discover `did`'s relay: every candidate from every source is read and checked offline, and the highest seq
    /// wins (§8.3). `None` when no source holds a valid, unexpired hint.
    ///
    /// Spec: §8.3, §8.5; DHT Hints Profile §9 (reading).
    pub async fn discover(&self, did: &str) -> Result<Option<Hint>> {
        let key = dsip_core::did::public_from_did_key(did).context("Pkarr discovery is for did:key subjects")?;
        let mut best: Option<(Hint, String)> = None;
        for c in self.candidates(&key).await {
            match pkarr::read(did, &c.payload, now_s()) {
                Ok(h) => {
                    if best.as_ref().is_none_or(|(b, _)| h.seq > b.seq) {
                        best = Some((h, c.source));
                    }
                }
                // a zone holding only a pointer (§9.1) has no `_dsip` endpoints: not a rejection, the next step reads it
                Err(e) if e.0 == "no-endpoints" => {}
                Err(e) => println!("hint       {}: rejected ({})", c.source, e.0),
            }
        }
        if let Some((h, source)) = &best {
            let uri = h.endpoints.first().and_then(|e| e["uri"].as_str()).unwrap_or("-");
            println!("hint       pkarr {uri}  seq {}  expires in {} s  from {source}, signed by the identity key   §8.1 hint, not authority",
                     h.seq, h.expires_at - now_s());
            return Ok(best.map(|(h, _)| h));
        }
        self.discover_devices(did, &key).await
    }

    /// §9.1: the identity's pointer (newest valid one), then each listed device's own zone, in order; the first
    /// device whose hint and delegation verify gives the hint.
    ///
    /// Spec: DHT Hints Profile §9.1 (reading).
    async fn discover_devices(&self, did: &str, key: &[u8; 32]) -> Result<Option<Hint>> {
        let now = now_s();
        let mut pointer: Option<pkarr::Pointer> = None;
        for c in self.candidates(key).await {
            if let Ok(p) = pkarr::read_pointer(did, &c.payload, now) {
                if pointer.as_ref().is_none_or(|b| p.seq > b.seq) {
                    pointer = Some(p);
                }
            }
        }
        let Some(ptr) = pointer else { return Ok(None) };
        println!("pointer    pkarr lists {} device(s), expires in {} s   §9.1 signed by the identity key", ptr.devices.len(), ptr.expires_at - now);
        for dev in &ptr.devices {
            let Some(dkey) = dsip_core::did::public_from_did_key(dev) else { continue };
            let mut best: Option<(u64, Vec<serde_json::Value>, i64)> = None;
            let mut last_err = String::from("unavailable");
            for c in self.candidates(&dkey).await {
                match pkarr::read_device(did, dev, &c.payload, now, &[]) {
                    Ok((eps, exp)) => {
                        let seq = u64::from_be_bytes(c.payload[64..72].try_into().unwrap_or_default());
                        if best.as_ref().is_none_or(|(s, _, _)| seq > *s) {
                            best = Some((seq, eps, exp));
                        }
                    }
                    Err(e) => last_err = e,
                }
            }
            match best {
                Some((seq, eps, exp)) => {
                    let uri = eps.first().and_then(|e| e["uri"].as_str()).unwrap_or("-").to_string();
                    println!("hint       pkarr device {}…  {uri}  expires in {} s   §9.1 signed by the device, delegation verified", &dev[..20], exp - now);
                    return Ok(Some(Hint { subject: did.to_string(), seq, issued_at: (seq / 1_000_000) as i64, expires_at: exp, endpoints: eps }));
                }
                None => println!("hint       pkarr device {}…: not usable ({last_err})", &dev[..20]),
            }
        }
        Ok(None)
    }
}

/// `dsip mainline-testnet`: a local Mainline DHT of `nodes` nodes on 127.0.0.1, for demos and tests — nothing reaches
/// the public DHT. Prints `bootstrap <addr>,<addr>,…` and runs until killed.
///
/// Spec: none (infrastructure).
pub async fn testnet(nodes: usize) -> Result<()> {
    let net = mainline::Testnet::builder(nodes).build().context("building the local Mainline testnet")?;
    println!("bootstrap {}", net.bootstrap.join(","));
    tokio::signal::ctrl_c().await?;
    drop(net);
    Ok(())
}
