//! Verified Broadcast roles on the command line: publisher, receiver, processor.
//!
//! Spec: §22.1 (publish a signed record to the publisher's authority), §9.3
//! (subscribe; first notify carries current state; renewal), §22.2–§22.3
//! (receiver verifies the publisher and every provenance statement, selects a
//! compatible variant, and displays the delivery path honestly), §27 (flow); and presence: a device's own record
//! (P§3, P§8) and a watched identity's combined state (P§4).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result};
use serde_json::{json, Value};

use dsip_broadcast::{evaluate_publication, PROFILE};
use dsip_core::did::StaticResolver;
use dsip_core::envelope::{Context, Envelope};
use dsip_schema::SemanticContext;
use dsip_transport::agent::{Agent, AgentConfig, AgentEvent};
use dsip_transport::identity::Identity;
use dsip_transport::{now_s, tls};

/// Connection options shared by the broadcast roles.
pub struct Conn {
    /// Identity directory.
    pub identity: PathBuf,
    /// Relay (authority) URL.
    pub relay: String,
    /// CA/self-signed cert.
    pub ca: Option<PathBuf>,
}

fn short(did: &str) -> String {
    if did.len() > 28 { format!("{}…{}", &did[..18], &did[did.len() - 6..]) } else { did.to_string() }
}

fn bcast_version() -> Value {
    json!({"core": "1.0", "min_core": "1.0", "profiles": [PROFILE], "extensions": [], "critical": []})
}

async fn connect(c: &Conn) -> Result<Agent> {
    connect_with(c, None).await
}

/// [`connect`], sealing presence for the scopes in `presence` (P§12).
async fn connect_with(c: &Conn, presence: Option<dsip_transport::PresenceSealing>) -> Result<Agent> {
    let id = Identity::load(&c.identity)?;
    let cfg = AgentConfig {
        relay_url: c.relay.clone(),
        tls: tls::client_config(c.ca.as_deref())?,
        video: false,
        t_establish: None,
        t_ring: None,
        t_ring_local: None,
        first_contact_required: false,
        seal: false,
        did_resolver: None,
        calls: None,
        presence,
        dialer: None,
        peer_dialer: None,
    };
    let agent = Agent::connect(id, cfg, StaticResolver::default()).await?;
    println!("identity  {}", agent.identity_did());
    println!("authority {} (this relay)   §9.3", short(&agent.relay().did));
    Ok(agent)
}

/// Listen briefly for signed relay errors (no silent drops, §13.2) and print them.
async fn drain(agent: &mut Agent, ms: u64) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        let events = tokio::select! {
            ev = agent.next() => ev?,
            _ = tokio::time::sleep_until(deadline) => return Ok(()),
        };
        for ev in events {
            match ev {
                AgentEvent::Received { message, payload, .. } if message.msg_type == "error" => {
                    println!("← error    {} {}", payload["reason"], payload.get("detail").and_then(Value::as_str).unwrap_or(""));
                }
                AgentEvent::Rejected(code, detail) => println!("✗ inbound rejected: {code} {detail}"),
                _ => {}
            }
        }
    }
}

/// A variant spec `id,codec,transport,uri[,integrity]`.
pub fn parse_variant(s: &str) -> Result<Value> {
    let parts: Vec<&str> = s.split(',').map(str::trim).collect();
    anyhow::ensure!(parts.len() >= 4, "variant must be id,codec,transport,uri[,integrity]");
    let media = if parts[1].starts_with("codec:video/") { json!(["audio", "video"]) } else { json!(["audio"]) };
    Ok(json!({"id": parts[0], "media": media, "codec": parts[1], "transport": parts[2], "uri": parts[3],
              "integrity": parts.get(4).copied().unwrap_or("metadata-only")}))
}

/// `dsip publish`: sign and send a publication record to the authority; returns the publication id.
pub async fn publish(c: &Conn, stream_suffix: &str, title: &str, state: &str, variants: Vec<Value>, ttl: i64, policy: Value) -> Result<()> {
    let mut agent = connect(c).await?;
    let stream = format!("{}:{}", agent.identity_did(), stream_suffix);
    let p = json!({
        "dsip": bcast_version(), "type": "publish", "from": agent.identity_did(), "publisher": agent.identity_did(), "stream_id": stream,
        "title": title, "state": state, "integrity": "metadata-only", "variants": variants, "policy": policy,
    });
    let frame = agent.send_payload(p, ttl).await?;
    let env = Envelope::from_frame(&frame).map_err(|v| anyhow::anyhow!("{:?}", v.code))?;
    let payload: Value = serde_json::from_slice(&dsip_core::b64::decode(&env.payload).context("payload")?)?;
    println!("→ publish  stream {stream}  state {state}  publication {}  ttl {ttl} s   §22.1", payload["id"]);
    println!("           variants: {}", payload["variants"].as_array().map(|a| a.iter().map(|v| format!("{} ({} over {})", v["id"].as_str().unwrap_or(""), v["codec"].as_str().unwrap_or(""), v["transport"].as_str().unwrap_or(""))).collect::<Vec<_>>().join(", ")).unwrap_or_default());
    std::fs::write(c.identity.join("last-publication.json"), json!({"stream": stream, "publication": payload["id"]}).to_string())?;
    drain(&mut agent, 400).await?;
    agent.close().await;
    Ok(())
}

/// `dsip unpublish`: withdraw the last (or given) publication.
pub async fn unpublish(c: &Conn, stream_suffix: &str, publication: Option<String>) -> Result<()> {
    let mut agent = connect(c).await?;
    let stream = format!("{}:{}", agent.identity_did(), stream_suffix);
    let pid = match publication {
        Some(p) => p,
        None => {
            let last: Value = serde_json::from_slice(&std::fs::read(c.identity.join("last-publication.json")).context("no last publication; pass --publication")?)?;
            last["publication"].as_str().unwrap_or("").to_string()
        }
    };
    let p = json!({"dsip": bcast_version(), "type": "unpublish", "from": agent.identity_did(), "publisher": agent.identity_did(), "stream_id": stream, "publication": pid});
    agent.send_payload(p, 30).await?;
    println!("→ unpublish stream {stream} publication {pid}   §22.1");
    drain(&mut agent, 400).await?;
    agent.close().await;
    Ok(())
}

/// `dsip provenance`: a processor (relay/transcoder) attaches its signed statement to a publication.
pub async fn provenance(c: &Conn, stream: &str, publication: &str, operation: &str, input: &str, output: &str, uri: Option<String>) -> Result<()> {
    let mut agent = connect(c).await?;
    let mut p = json!({
        "dsip": bcast_version(), "type": "provenance", "from": agent.identity_did(), "original_stream": stream, "original_publication": publication,
        "processor": agent.identity_did(), "operation": operation, "input_variant": input, "output_variant": output,
    });
    if let Some(u) = uri {
        p["output_uri"] = u.into();
    }
    agent.send_payload(p, 3600).await?;
    println!("→ provenance  {operation} {input} → {output} on {}/{}  signed by processor {}   §22.3", short(stream), &publication[publication.len().saturating_sub(8)..], short(agent.identity_did()));
    drain(&mut agent, 400).await?;
    agent.close().await;
    Ok(())
}

/// `dsip subscribe`: subscribe to publication or presence events and verify what arrives.
pub async fn subscribe(c: &Conn, target: &str, events: Vec<String>, expires_in: i64, wait: u64, codecs: Vec<String>, transports: Vec<String>) -> Result<()> {
    let mut agent = connect(c).await?;
    let authority = agent.relay().did.clone();
    let mut p = json!({"dsip": bcast_version(), "type": "subscribe", "to": authority, "target": target, "events": events, "expires_in": expires_in});
    let presence = p["events"].as_array().is_some_and(|e| e.iter().any(|x| x == "presence"));
    if presence {
        // P§12.4: we open sealed records, so we ask for them
        p["dsip"]["profiles"] = json!([PROFILE, dsip_core::presence_seal::PROFILE]);
    }
    // P§6: presence is private by default; the grants we hold from the target admit us
    let claims = if presence { agent.presence_claims(target) } else { vec![] };
    if !claims.is_empty() {
        println!("· presenting {} grant(s) from {} with dsip.subscribe   P§6", claims.len(), short(target));
        p["claims"] = Value::Array(claims);
    }
    let frame = agent.send_payload(p, 30).await?;
    let sub_id = Envelope::from_frame(&frame)
        .ok()
        .and_then(|e| dsip_core::b64::decode(&e.payload))
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v["id"].as_str().map(String::from))
        .unwrap_or_default();
    println!("→ subscribe  target {}  events {:?}  expires_in {expires_in}  (subscription …{})   §9.3", short(target), events, &sub_id[sub_id.len().saturating_sub(8)..]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
    let resolver = StaticResolver::default();
    let mut seq_seen = 0u64;
    let mut watch = dsip_broadcast::presence::Watch::new(target);
    loop {
        let events = tokio::select! {
            ev = agent.next() => ev?,
            _ = tokio::time::sleep_until(deadline) => break,
        };
        for ev in events {
            match ev {
                // §9.3: a notify is of the subscription it names, and `seq` orders that subscription's alone. One of an
                // earlier subscription of ours, kept for us while we were away (§13.2 store-and-forward), is not this
                // one's: counted as this one's, its larger `seq` made every notify after it look stale.
                AgentEvent::Received { message, payload, .. } if message.msg_type == "notify" && payload["subscription"].as_str() != Some(sub_id.as_str()) => {
                    let of = payload["subscription"].as_str().unwrap_or("");
                    println!("· dropped notify seq {} of another subscription (…{})   §9.3", payload["seq"], &of[of.len().saturating_sub(8)..]);
                }
                AgentEvent::Received { message, identity, payload, .. } if message.msg_type == "notify" => {
                    let seq = payload["seq"].as_u64().unwrap_or(0);
                    if seq <= seq_seen {
                        println!("· dropped notify seq {seq} (stale)   §9.3");
                        continue;
                    }
                    seq_seen = seq;
                    let state = payload["state"].as_str().unwrap_or("");
                    println!("← notify   seq {seq} {state} from authority {}{}", short(&identity),
                             payload.get("reason").and_then(Value::as_str).map(|r| format!("  reason {r}")).unwrap_or_default());
                    let body = &payload["body"];
                    if body["event"] == "presence" {
                        watch.notify(&payload, |f| agent.verify_record(f));
                        let (c, unreadable) = watch.view(now_s(), |kid| agent.presence_key(target, kid));
                        let from = match c.source {
                            "record" => "from a device's signed record",
                            "assertion" => "the authority's claim, no device record",
                            _ => "no record, nothing bound",
                        };
                        println!("           presence: {}{}  ({from})   P§4", c.state, if c.token != c.state { format!(" (shown raw: {})", c.token) } else { String::new() });
                        let held = body["records"].as_array().map_or(0, Vec::len);
                        for r in watch.records() {
                            let device = r["device"].as_str().unwrap_or("");
                            match r["kid"].as_str() {
                                None => println!("             device {} {} seq {}  ✓ verified   P§3", short(device), r["state"].as_str().unwrap_or(""), r["seq"]),
                                Some(kid) if unreadable.iter().any(|d| d == device) => {
                                    println!("             device {} sealed {kid} seq {}  ✓ verified, unreadable: no key for {kid}   P§12.4", short(device), r["seq"])
                                }
                                Some(kid) => println!("             device {} sealed {kid} seq {}  ✓ verified, opened   P§12.4", short(device), r["seq"]),
                            }
                        }
                        if held > watch.records().len() {
                            println!("             {} record(s) did not verify: ignored   P§3", held - watch.records().len());
                        }
                        println!("           assertion: {}   (authority-asserted, §9.3)", body["state"]);
                    } else {
                        println!("           publication state: {}", body["state"]);
                        if let Some(record) = body["record"].as_str() {
                            show_record(record, body["statements"].as_array().cloned().unwrap_or_default(), &resolver, &codecs, &transports);
                        }
                    }
                    if state == "terminated" {
                        println!("           subscription terminated — final (§9.3)");
                        agent.close().await;
                        return Ok(());
                    }
                }
                AgentEvent::Received { message, payload, .. } if message.msg_type == "error" => {
                    println!("← error    {} {}   (signed by the relay; e.g. a subscribe above the per-event cap is refused, §9.3)", payload["reason"], payload.get("detail").and_then(Value::as_str).unwrap_or(""));
                    agent.close().await;
                    return Ok(());
                }
                AgentEvent::Received { message, identity, payload, .. } if message.msg_type == "reject" => {
                    println!("← reject   {} from {}   (uniform for unauthorized and nonexistent targets, §9.3)", payload["reason"], short(&identity));
                    agent.close().await;
                    return Ok(());
                }
                AgentEvent::Rejected(code, detail) => println!("✗ inbound rejected: {code} {detail}"),
                _ => {}
            }
        }
    }
    println!("· wait over");
    agent.close().await;
    Ok(())
}

/// `AUDIENCE=STATE` (or `STATE`, for the record with no audience): the audience, checked as a P§6 token, and the state
/// (`none`: stop publishing that record). With `tag`, the audience is a label sent as its tag (P§12.1).
fn audience_state(arg: &str, tag: Option<&dyn Fn(&str) -> String>) -> Result<(Option<String>, Option<String>)> {
    let (audience, state) = match arg.split_once('=') {
        Some((a, st)) => {
            anyhow::ensure!(dsip_broadcast::presence::is_audience(a), "not an audience token (P§6: [a-z][a-z0-9-]*): {a}");
            (Some(tag.map_or_else(|| a.to_string(), |t| t(a))), st)
        }
        None => (None, arg),
    };
    Ok((audience, (state != "none").then(|| state.to_string())))
}

/// `dsip presence publish`: send this device's presence records to its relay (the authority) and keep them fresh: one
/// with no audience and one per `--audience`, following `then` (`SECONDS:STATE` or `SECONDS:AUDIENCE=STATE`, `none`
/// to stop) and printing what the authority refuses.
///
/// With `sealed` the records are sealed (P§12.2): `main` and every audience named, each a label sent as its tag; the
/// device also watches its own identity and moves to the epoch a sibling's record shows (P§12.5).
///
/// Spec: P§3, P§6, P§8, P§9, P§12.
pub async fn presence_publish(c: &Conn, state: &str, audiences: &[String], then: &[String], lifetime: i64, wait: u64, sealed: bool) -> Result<()> {
    let id = Identity::load(&c.identity)?;
    let label_tag = |l: &str| dsip_transport::agent::audience_tag(&id, l);
    let tag: Option<&dyn Fn(&str) -> String> = if sealed { Some(&label_tag) } else { None };
    let start = now_s();
    let mut plan: Vec<(i64, Option<String>, Option<String>)> = then
        .iter()
        .map(|t| {
            let (secs, rest) = t.split_once(':').context("--then wants SECONDS:STATE or SECONDS:AUDIENCE=STATE")?;
            let (audience, st) = audience_state(rest, tag)?;
            Ok((start + secs.parse::<i64>()?, audience, st))
        })
        .collect::<Result<_>>()?;
    let named: Vec<Option<String>> = audiences.iter().map(|a| audience_state(a, tag).map(|(au, _)| au)).collect::<Result<_>>()?;
    let presence = sealed.then(|| dsip_transport::PresenceSealing {
        // P§12.6: sealing is per audience; here every scope this device publishes
        sealed: std::iter::once("main".to_string()).chain(named.into_iter().flatten()).chain(plan.iter().filter_map(|(_, a, _)| a.clone())).collect(),
        t_rotate: None,
    });
    let mut agent = connect_with(c, presence).await?;
    let me = agent.identity_did().to_string();
    if sealed {
        // P§12.5: the device watches its own identity (admitted by P§6 rule 1) to learn its siblings' epochs
        let p = json!({"dsip": {"core": "1.0", "min_core": "1.0", "profiles": [PROFILE, dsip_core::presence_seal::PROFILE], "extensions": [], "critical": []},
                       "type": "subscribe", "to": agent.relay().did.clone(), "target": me, "events": ["presence"], "expires_in": 3600});
        agent.send_payload(p, 30).await?;
        println!("→ subscribe  target our own identity, sealed records too   P§12.5");
    }
    plan.sort_by_key(|(at, ..)| *at);
    plan.reverse();
    let mut publisher = dsip_broadcast::presence::Publisher::new(agent.identity_did(), agent.device_did(), &agent.relay().did.clone(), lifetime);
    let mut out = publisher.set(Some(state), now_s());
    let mut pending: Vec<Value> = vec![];
    for a in audiences {
        let (audience, st) = audience_state(a, tag)?;
        anyhow::ensure!(audience.is_some(), "--audience wants AUDIENCE=STATE");
        pending.extend(publisher.set_for(audience.as_deref(), st.as_deref(), now_s()));
    }
    // P§9: a refusal names the record in `in_reply_to`; it is held back for its own audience only
    let mut sent: std::collections::HashMap<String, Option<String>> = Default::default();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
    loop {
        if let Some(p) = out.take().or_else(|| pending.pop()) {
            let (st, seq, audience) = (p["state"].clone(), p["seq"].clone(), p["audience"].as_str().map(String::from));
            let frame = agent.send_presence(p, publisher.lifetime()).await?;
            let kid = Envelope::from_frame(&frame).ok().and_then(|e| dsip_core::b64::decode(&e.payload)).and_then(|b| {
                serde_json::from_slice::<Value>(&b).ok()?["kid"].as_str().map(String::from)
            });
            if let Some(id) = Envelope::from_frame(&frame).ok().and_then(|e| dsip_core::b64::decode(&e.payload)).and_then(|b| {
                serde_json::from_slice::<Value>(&b).ok()?["id"].as_str().map(String::from)
            }) {
                sent.insert(id, audience.clone());
            }
            let to = audience.map(|a| format!(" (audience {a})")).unwrap_or_default();
            let how = kid.map(|k| format!(" sealed under {k}   P§12.2")).unwrap_or_else(|| "   P§3".into());
            println!("→ presence {}{to} seq {seq} for {} s to the authority{how}", st.as_str().unwrap_or(""), publisher.lifetime());
            continue;
        }
        let now = now_s();
        if let Some((at, audience, st)) = plan.last().cloned() {
            if now >= at {
                let what = audience.as_ref().map(|a| format!("{a}: ")).unwrap_or_default();
                println!("· state → {what}{}", st.as_deref().unwrap_or("none (stop publishing; the record lapses at its expires_at)"));
                out = publisher.set_for(audience.as_deref(), st.as_deref(), now);
                plan.pop();
                continue;
            }
        }
        out = publisher.tick(now);
        if out.is_some() {
            continue;
        }
        let events = tokio::select! {
            ev = agent.next() => ev?,
            _ = tokio::time::sleep(Duration::from_millis(500)) => vec![],
            _ = tokio::time::sleep_until(deadline) => break,
        };
        for ev in events {
            match ev {
                AgentEvent::Received { message, payload, .. } if message.msg_type == "error" => {
                    let reason = payload["reason"].as_str().unwrap_or("");
                    let retry = payload["retry_after"].as_i64();
                    let audience = message.in_reply_to.as_ref().and_then(|id| sent.get(id)).cloned().flatten();
                    let of = audience.as_ref().map(|a| format!(" (audience {a})")).unwrap_or_default();
                    println!("← error    {reason}{}   (the authority refused the record{of}, P§3)", retry.map(|r| format!(" retry_after {r}")).unwrap_or_default());
                    publisher.refused_for(audience.as_deref(), reason, retry, now_s());
                }
                AgentEvent::Received { message, payload, .. } if message.msg_type == "notify" && sealed => {
                    // our own watch: each sibling record, verified, may carry a higher epoch (P§12.5)
                    let frames: Vec<String> =
                        payload["body"]["records"].as_array().into_iter().flatten().filter_map(|r| r["frame"].as_str().map(String::from)).collect();
                    for f in frames {
                        if let Some((rec, identity)) = agent.verify_record(&f) {
                            if identity == me && rec["device"] == rec["from"] {
                                agent.own_record(&rec).await?;
                            }
                        }
                    }
                }
                AgentEvent::Emission(dsip_session::Emission::Keys { action, scope, epoch }) => {
                    println!("· presence key {scope} {} to epoch {epoch}   P§12.5", action.as_str());
                    agent.save_contacts()?;
                }
                AgentEvent::Sent { msg_type, session, .. } if msg_type == "grant" => {
                    println!("→ grant following …{} with the new keys   P§12.5", &session[session.len().saturating_sub(8)..]);
                    agent.save_contacts()?;
                }
                AgentEvent::Rejected(code, detail) => println!("✗ inbound rejected: {code} {detail}"),
                _ => {}
            }
        }
    }
    println!("· wait over");
    agent.close().await;
    Ok(())
}

/// Verify an embedded record (and statements) independently of the relay and print the §22.3 display.
fn show_record(record: &str, statements: Vec<Value>, resolver: &StaticResolver, codecs: &[String], transports: &[String]) {
    let Ok(env) = Envelope::from_frame(record) else { return println!("           record: malformed") };
    let prov: Vec<Envelope> = statements.iter().filter_map(Value::as_str).filter_map(|f| Envelope::from_frame(f).ok()).collect();
    let ctx = Context::new(now_s(), resolver);
    let sem = SemanticContext { supported: dsip_core::version::Supported::from_json(Some(&json!({"core": "1.0", "profiles": [PROFILE, "interactive-media/1.0"], "extensions": []}))), ..Default::default() };
    match evaluate_publication(&env, &prov, codecs, transports, &ctx, &sem) {
        Ok((signer, r)) => {
            let p = &r.publication;
            println!("           ✓ record verified: publisher {}  (signed by {})   §22.1", short(&r.publisher), short(&signer));
            println!("             title \"{}\"  state {}  policy {}", p["title"].as_str().unwrap_or(""), p["state"], p["policy"]);
            for v in p["variants"].as_array().into_iter().flatten() {
                let pick = if r.selected_variant.as_deref() == v["id"].as_str() { "  ← selected" } else { "" };
                println!("             variant {}: {} over {} @ {}{pick}", v["id"].as_str().unwrap_or(""), v["codec"].as_str().unwrap_or(""), v["transport"].as_str().unwrap_or(""), v["uri"].as_str().unwrap_or(""));
            }
            if r.selected_variant.is_none() {
                println!("             (no variant matches this receiver's codecs/transports)");
            }
            for s in &r.provenance {
                if s["verdict"] == "accept" {
                    println!("             provenance ✓ {} by {}{}", s["operation"].as_str().unwrap_or(""), short(s["processor"].as_str().unwrap_or("")),
                             s.get("policy_violation").and_then(Value::as_str).map(|v| format!("  ⚠ violates publisher policy: {v}")).unwrap_or_default());
                } else {
                    println!("             provenance ✗ {}", s["code"]);
                }
            }
            println!("             Original publisher: {}", short(&r.publisher));
            println!("             Delivered by:       {}", if r.delivered_by.is_empty() { "(direct)".to_string() } else { r.delivered_by.iter().map(|d| short(d)).collect::<Vec<_>>().join(", ") });
            println!("             Transcoded by:      {}", if r.transcoded_by.is_empty() { "—".to_string() } else { r.transcoded_by.iter().map(|d| short(d)).collect::<Vec<_>>().join(", ") });
            println!("             Integrity mode:     {}   §22.2", r.integrity_mode());
        }
        Err(v) => println!("           ✗ record rejected: {:?} {}", v.code, v.detail.unwrap_or_default()),
    }
}
