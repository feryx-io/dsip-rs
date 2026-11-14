//! The recording party's recorder leg (Recording Profile C§6): from a second device of its own identity, one
//! recording session per stream to the declared recorder, each `sendonly`, forwarding the call's Opus unchanged.
//!
//! Spec: C§6 — the recorder's identity must be the declared one and its delegation must carry `dsip.record`
//! (checked with `dsip_recording::recording_session` before any media is sent; a failure ends the session with
//! `bye policy.blocked`). The counterparty's media reaches the recorder only once it is flowing, which C§4 holds
//! until that counterparty accepted.
//!
//! Impl: one recording session per stream (C§6 allows one or more), so each leg carries one track; `paused` holds
//! the legs' sending rather than renegotiating them to `inactive` (C§6 allows either).

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use dsip_media::{Candidate, Feed, MediaConfig, MediaEvent, MediaLeg, Source};
use dsip_session::LocalEvent;
use dsip_transport::agent::{Agent, AgentConfig, AgentEvent};
use dsip_transport::identity::Identity;
use dsip_transport::{Command, Invite, InvitePatch};
use futures_util::FutureExt as _;
use serde_json::{json, Value};
use tokio::sync::{oneshot, watch};

/// What the console hands the fork.
pub struct Fork {
    /// A second device of the recording party's identity.
    pub device: PathBuf,
    /// Relay and CA.
    pub relay: String,
    /// CA for the relay's certificate.
    pub ca: Option<PathBuf>,
    /// The declared recorder identity.
    pub recorder: String,
    /// The recorded session.
    pub of: String,
    /// This side's identity, and the counterparty's.
    pub me: String,
    /// The counterparty's identity.
    pub peer: String,
    /// Media stack.
    pub backend: String,
    /// `(participant, feed)` per stream.
    pub feeds: Vec<(String, Feed)>,
}

struct Leg {
    leg: MediaLeg,
    participant: String,
    pending: Vec<Option<Candidate>>,
    active: bool,
}

/// Run the fork until `stop`; `paused` holds the legs' media while true.
pub async fn run(f: Fork, mut stop: oneshot::Receiver<()>, mut paused: watch::Receiver<bool>) -> Result<()> {
    let id = Identity::load(&f.device)?;
    let resolver = dsip_transport::resolver::build_resolver(&[], &[]).await?;
    let cfg = AgentConfig {
        relay_url: f.relay.clone(),
        tls: dsip_transport::tls::client_config(f.ca.as_deref())?,
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
    let backend = dsip_media::Backend::parse(&f.backend)?;
    let participants = json!([{"identity": f.me, "role": "self"}, {"identity": f.peer, "role": "peer"}]);
    let mut legs: HashMap<String, Leg> = HashMap::new();
    for (participant, feed) in f.feeds {
        let leg = MediaLeg::new(MediaConfig { source: Source::Feed(feed), record: None, stun: vec![], turn: vec![], backend,
                                              send_only: true, tap_in: None, tap_out: None, video: None }).await?;
        let rs = json!({"of": f.of, "participants": participants, "streams": [{"media": 0, "participant": participant}]});
        let invite = Invite {
            sdp: Some(leg.create_offer().await?),
            patch: InvitePatch { direction: Some("sendonly".into()), recording_session: Some(rs), ..Default::default() },
            ..Default::default()
        };
        let sid = agent.place_call_with(&f.recorder, invite).await?;
        println!("  ⏺  recorder leg …{} → {} (stream of {})   C§6", &sid[sid.len() - 8..], f.recorder, participant);
        legs.insert(sid, Leg { leg, participant, pending: vec![], active: false });
    }
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(50));
    loop {
        tokio::select! {
            _ = &mut stop => break,
            changed = paused.changed() => {
                if changed.is_err() { break }
                let p = *paused.borrow();
                for l in legs.values().filter(|l| l.active) {
                    if p { l.leg.hold_sending() } else { l.leg.start_sending() }
                }
                println!("  ⏺  recorder legs {}", if p { "paused" } else { "resumed" });
            }
            _ = tick.tick() => {
                for (sid, l) in legs.iter_mut() {
                    while let Some(Some(MediaEvent::Candidate(c))) = l.leg.next_event().now_or_never() {
                        l.pending.push(c);
                    }
                    if l.active && !l.pending.is_empty() {
                        let batch = std::mem::take(&mut l.pending);
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
                    let Some(l) = legs.get_mut(&sid) else { continue };
                    match message.msg_type.as_str() {
                        "answer" => {
                            // C§6: the declared recorder, carrying dsip.record — before any media is sent
                            let caps: Vec<&str> = if agent.peer_has_capability(&message.from, dsip_recording::RECORD) { vec![dsip_recording::RECORD] } else { vec![] };
                            let check = dsip_recording::recording_session(&json!({
                                "declared": {"session": f.of, "state": "on", "recorder": f.recorder},
                                "recorder": {"identity": identity, "capabilities": caps},
                                "offer": {"media": [{"type": "audio", "direction": "sendonly"}],
                                          "recording_session": {"of": f.of, "participants": participants,
                                                                "streams": [{"media": 0, "participant": l.participant}]}}}));
                            if let Some(why) = check.get("refused") {
                                println!("  ⏺  recorder leg …{} REFUSED: {} — nothing sent, bye policy.blocked   C§6", &sid[sid.len() - 8..], why);
                                agent.local(LocalEvent::Hangup { session: sid.clone(), reason: Some("policy.blocked".into()) }).await?;
                                continue;
                            }
                            if let Some(sdp) = payload.pointer("/transports/0/sdp").and_then(Value::as_str) {
                                l.leg.set_answer(sdp).await?;
                            }
                            l.active = true;
                            if !*paused.borrow() {
                                l.leg.start_sending();
                            }
                            println!("  ⏺  recorder leg …{} verified (dsip.record) — forwarding {}'s audio   C§6", &sid[sid.len() - 8..], l.participant);
                        }
                        "info" if payload["about"] == "transport:webrtc" => {
                            let cands: Vec<Candidate> = serde_json::from_value(payload["data"]["candidates"].clone()).unwrap_or_default();
                            for c in &cands {
                                l.leg.add_remote_candidate(c).await.ok();
                            }
                        }
                        "reject" | "bye" => {
                            println!("  ⏺  recorder leg …{} ended by the recorder: {}", &sid[sid.len() - 8..], message.reason.clone().unwrap_or_default());
                            l.active = false;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    for (sid, l) in legs.drain() {
        if l.active {
            agent.local(LocalEvent::Hangup { session: sid.clone(), reason: None }).await.ok();
        }
        let st = l.leg.stats();
        println!("  ⏺  recorder leg …{} closed — forwarded {} frames of {}", &sid[sid.len() - 8..], st.frames_out, l.participant);
        l.leg.close().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await; // let the byes go out
    agent.close().await;
    Ok(())
}
