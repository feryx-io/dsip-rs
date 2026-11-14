//! `dsip recorder` — a recorder service (Recording Profile C§6): it answers only recording sessions, records each
//! stream to Ogg/Opus, and keeps their RFC 7865-shaped metadata.
//!
//! Spec: C§6 (a recording session carries `recording_session` metadata and `sendonly` streams; the recorder
//! answers `recvonly`), C§1 (its delegation carries `dsip.record`, which the recording party checks).
//!
//! Impl: one leg per recording session; an invite without `recording_session` is refused `policy.blocked`.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use dsip_media::{Candidate, MediaConfig, MediaEvent, MediaLeg, Source};
use dsip_session::LocalEvent;
use dsip_transport::agent::{Agent, AgentConfig, AgentEvent};
use dsip_transport::identity::Identity;
use dsip_transport::Command;
use futures_util::FutureExt as _;
use serde_json::{json, Value};

struct Stream {
    leg: MediaLeg,
    file: PathBuf,
    pending: Vec<Option<Candidate>>,
    active: bool,
}

fn short(d: &str) -> String {
    if d.len() > 24 { format!("{}…{}", &d[..16], &d[d.len() - 6..]) } else { d.to_string() }
}

/// Run the recorder for `seconds`.
pub async fn run(identity: PathBuf, relay: String, ca: Option<PathBuf>, dir: PathBuf, backend: String, seconds: u64) -> Result<()> {
    let id = Identity::load(&identity)?;
    std::fs::create_dir_all(&dir)?;
    println!("recorder  {}  device {}", id.meta.identity, id.meta.device);
    let resolver = dsip_transport::resolver::build_resolver(&[], &[]).await?;
    let cfg = AgentConfig {
        relay_url: relay,
        tls: dsip_transport::tls::client_config(ca.as_deref())?,
        video: false,
        t_establish: None,
        t_ring: None,
        t_ring_local: None,
        first_contact_required: false,
        seal: false,
        did_resolver: None,
        calls: None,
        presence: None,
        peer_dialer: None,
        dialer: None,
    };
    let mut agent = Agent::connect(id, cfg, resolver).await?;
    println!("recorder  bound; answering recording sessions only   C§6");
    let backend = dsip_media::Backend::parse(&backend)?;
    let mut streams: HashMap<String, Stream> = HashMap::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(50));
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = tick.tick() => {
                for (sid, s) in streams.iter_mut() {
                    while let Some(Some(ev)) = s.leg.next_event().now_or_never() {
                        match ev {
                            MediaEvent::Candidate(c) => s.pending.push(c),
                            MediaEvent::FirstPacket => println!("RECORDING …{} ♫ first packet", &sid[sid.len() - 8..]),
                            MediaEvent::State(_) => {}
                        }
                    }
                    if s.active && !s.pending.is_empty() {
                        let batch = std::mem::take(&mut s.pending);
                        let end = batch.iter().any(Option::is_none);
                        let cands: Vec<Candidate> = batch.into_iter().flatten().collect();
                        agent.command(Command::Info { session: sid.clone(), data: json!({"candidates": cands, "end_of_candidates": end}) }).await?;
                    }
                }
            }
            events = agent.next() => {
                for ev in events? {
                    let AgentEvent::Received { message, identity, payload, .. } = ev else { continue };
                    let sid = message.session_id().to_string();
                    match message.msg_type.as_str() {
                        "invite" => {
                            let Some(rs) = payload.get("recording_session").cloned() else {
                                println!("REFUSED …{} from {}: not a recording session   C§6", &sid[sid.len() - 8..], short(&identity));
                                agent.local(LocalEvent::Alert { session: sid.clone(), ring_timeout: Some(30) }).await?;
                                agent.local(LocalEvent::Decline { session: sid.clone(), reason: Some("policy.blocked".into()) }).await?;
                                continue;
                            };
                            let of = rs["of"].as_str().unwrap_or("unknown").to_string();
                            let participant = rs["streams"][0]["participant"].as_str().unwrap_or("").to_string();
                            // one file per recording session (C§6: one or more sessions per recorded call)
                            let file = dir.join(format!("{of}-{}.ogg", &sid[sid.len() - 8..]));
                            let leg = MediaLeg::new(MediaConfig { source: Source::None, record: Some(file.clone()), stun: vec![], turn: vec![], backend,
                                                                  send_only: false, tap_in: None, tap_out: None, video: None }).await?;
                            let offer = payload.pointer("/transports/0/sdp").and_then(Value::as_str).context("recording session without SDP")?;
                            let ans = leg.accept_offer(offer).await?;
                            agent.local(LocalEvent::Alert { session: sid.clone(), ring_timeout: Some(30) }).await?;
                            agent.command(Command::Accept { session: sid.clone(), answered_by: Some("service".into()), sdp: Some(ans) }).await?;
                            // the metadata, kept beside the media (RFC 7865 shape)
                            let meta_path = dir.join(format!("{of}.json"));
                            let mut meta: Value = std::fs::read_to_string(&meta_path).ok().and_then(|s| serde_json::from_str(&s).ok())
                                .unwrap_or_else(|| json!({"of": of, "recording_party": identity, "participants": rs["participants"], "streams": []}));
                            meta["streams"].as_array_mut().context("metadata")?.push(json!({"participant": participant, "file": file.file_name().map(|f| f.to_string_lossy().to_string())}));
                            std::fs::write(&meta_path, serde_json::to_string_pretty(&meta)?)?;
                            println!("RECORDING session …{} of …{} from {}: stream of {} → {}", &sid[sid.len() - 8..], &of[of.len() - 8..], short(&identity), short(&participant), file.display());
                            streams.insert(sid, Stream { leg, file, pending: vec![], active: true });
                        }
                        "info" if payload["about"] == "transport:webrtc" => {
                            if let Some(s) = streams.get(&sid) {
                                let cands: Vec<Candidate> = serde_json::from_value(payload["data"]["candidates"].clone()).unwrap_or_default();
                                for c in &cands {
                                    s.leg.add_remote_candidate(c).await.ok();
                                }
                            }
                        }
                        "bye" => {
                            if let Some(s) = streams.remove(&sid) {
                                let st = s.leg.stats();
                                s.leg.close().await;
                                println!("RECORDED session …{}: {} packets → {}", &sid[sid.len() - 8..], st.packets_in, s.file.display());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    for (_, s) in streams.drain() {
        s.leg.close().await;
    }
    agent.close().await;
    Ok(())
}
