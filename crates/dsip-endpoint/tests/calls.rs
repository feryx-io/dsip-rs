//! The call glue over two cores wired back to back, with a media host that answers every request at once: offers and
//! answers carry SDP, candidates wait for ACTIVE and ride in signed `info`, media starts on the signed answer,
//! screening answers with a leg that sends nothing and escalates by re-offering, a refused sealed call is placed again
//! in clear, and a declared recording holds or declines the call.
//!
//! Spec: §12.12, §14.1, §14.4, §16.3, §10.4, C§4.

use dsip_core::did::StaticResolver;
use dsip_core::envelope::sign;
use dsip_core::keys::KeyPair;
use dsip_endpoint::{AnswerPolicy, CallCommand, CallEvent, CallOut, Calls, CallsConfig, Core, CoreConfig, CoreEvent, IdentityKeys, Invite,
                    MediaRequest, MediaResult};
use dsip_endpoint::calls::AcceptPolicy;
use dsip_session::SessionState;
use serde_json::{json, Value};

const NOW: i64 = 1_790_000_000;

const SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
c=IN IP4 0.0.0.0\r\na=ice-ufrag:0123456789abcdef0123456789abcdef\r\n\
a=ice-pwd:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n\
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
a=setup:SETUP\r\na=mid:0\r\na=DIRECTION\r\na=rtcp-mux\r\na=rtpmap:111 opus/48000/2\r\n";

fn sdp(setup: &str, direction: &str) -> String {
    SDP.replace("SETUP", setup).replace("DIRECTION", direction)
}

fn keys(seed: u8, name: &str) -> IdentityKeys {
    let controller = KeyPair::from_seed([seed; 32]);
    let device = KeyPair::from_seed([seed.wrapping_add(100); 32]);
    let payload = dsip_core::delegation::delegation_payload(&controller.did(), &device.did(), NOW - 60, NOW + 86_400,
                                                            &["dsip.signaling", "dsip.media.interactive"]);
    IdentityKeys { identity: controller.did(), delegation: sign(&payload, &controller, &controller.kid()), device, display_name: name.into() }
}

/// One side: a core, its call glue, and everything the glue asked of the host or told it.
struct Side {
    core: Core,
    calls: Calls,
    media: Vec<MediaRequest>,
    events: Vec<CallEvent>,
    sent: Vec<(String, Value)>,
    /// Frames for the other side.
    outbox: Vec<String>,
    /// The fake media host answers SDP requests by itself.
    auto_media: bool,
}

impl Side {
    fn new(seed: u8, name: &str, cfg: CallsConfig, core_cfg: CoreConfig) -> Side {
        let mut s = Side {
            core: Core::new(keys(seed, name), core_cfg, StaticResolver::default(), NOW),
            calls: Calls::new(cfg),
            media: vec![],
            events: vec![],
            sent: vec![],
            outbox: vec![],
            auto_media: true,
        };
        s.core.set_video(false);
        s
    }

    fn did(&self) -> String {
        self.core.keys().identity.clone()
    }

    fn take(&mut self, out: Vec<CallOut>) {
        for o in out {
            match o {
                CallOut::Core(CoreEvent::Send { frame, msg_type, .. }) => {
                    let env = dsip_core::envelope::Envelope::from_frame(&frame).unwrap();
                    let body: Value = serde_json::from_slice(&dsip_core::b64::decode(&env.payload).unwrap()).unwrap_or(Value::Null);
                    self.sent.push((msg_type, body));
                    self.outbox.push(frame);
                }
                CallOut::Core(_) => {}
                CallOut::Media(m) => {
                    self.media.push(m.clone());
                    if self.auto_media {
                        let answer = match m {
                            MediaRequest::Offer { session, .. } => Some(MediaResult::Offer { session, sdp: sdp("actpass", "sendrecv") }),
                            MediaRequest::Answer { session, screening, .. } => {
                                Some(MediaResult::Answer { session, sdp: sdp("active", if screening { "recvonly" } else { "sendrecv" }) })
                            }
                            _ => None,
                        };
                        if let Some(r) = answer {
                            let more = self.calls.media(&mut self.core, r, NOW).unwrap();
                            self.take(more);
                        }
                    }
                }
                CallOut::Call(e) => self.events.push(e),
            }
        }
    }

    fn command(&mut self, cmd: CallCommand) {
        let out = self.calls.command(&mut self.core, cmd, NOW).unwrap();
        self.take(out);
    }

    fn result(&mut self, r: MediaResult) {
        let out = self.calls.media(&mut self.core, r, NOW).unwrap();
        self.take(out);
    }

    fn state(&self, sid: &str) -> Option<SessionState> {
        self.core.endpoint().session(sid).map(|s| s.state)
    }

    fn sent_types(&self) -> Vec<&str> {
        self.sent.iter().map(|(t, _)| t.as_str()).collect()
    }

    fn sent_of(&self, t: &str) -> Vec<&Value> {
        self.sent.iter().filter(|(x, _)| x == t).map(|(_, b)| b).collect()
    }
}

/// Whether a relay would deliver `frame` to the one other device here: not a caller's `cancel` of the legs that did
/// not answer (§12.7), which goes to the other devices of the callee, and there are none.
fn relayed(frame: &str) -> bool {
    let env = dsip_core::envelope::Envelope::from_frame(frame).unwrap();
    let body: Value = serde_json::from_slice(&dsip_core::b64::decode(&env.payload).unwrap()).unwrap_or(Value::Null);
    !(body["type"] == "cancel" && body["reason"] == "session.answered-elsewhere")
}

/// Deliver frames both ways until neither side has any.
fn pump(a: &mut Side, b: &mut Side) {
    for _ in 0..50 {
        let (mut fa, mut fb) = (std::mem::take(&mut a.outbox), std::mem::take(&mut b.outbox));
        fa.retain(|f| relayed(f));
        fb.retain(|f| relayed(f));
        if fa.is_empty() && fb.is_empty() {
            return;
        }
        for f in fa {
            let ev = b.core.inbound(&f, NOW).unwrap();
            let out = b.calls.observe(&mut b.core, ev, NOW).unwrap();
            b.take(out);
        }
        for f in fb {
            let ev = a.core.inbound(&f, NOW).unwrap();
            let out = a.calls.observe(&mut a.core, ev, NOW).unwrap();
            a.take(out);
        }
    }
    panic!("the sides never went quiet");
}

fn pair(answer: AnswerPolicy) -> (Side, Side) {
    let alice = Side::new(1, "Alice", CallsConfig::default(), CoreConfig::default());
    let bob = Side::new(2, "Bob", CallsConfig { answer, ..Default::default() }, CoreConfig::default());
    (alice, bob)
}

/// An `error` as a relay without `sealed-body/1.0` answers a sealed invite (§10.4, §11.3), signed by `by`.
fn refusal(by: &mut Side, to: &str, session: &str) -> String {
    let dsip = json!({"core": "1.0", "min_core": "1.0", "profiles": [], "extensions": [], "critical": []});
    by.core.sign_payload(json!({"dsip": dsip, "type": "error", "to": to, "session": session, "in_reply_to": session,
                                "reason": "session.unsupported-critical-extension"}), NOW, 30).unwrap()
}

fn place(a: &mut Side, b: &Side) -> String {
    let (sid, out) = a.calls.place(&mut a.core, &b.did(), Invite::default(), NOW).unwrap();
    a.take(out);
    sid
}

fn starts(s: &Side, sid: &str) -> bool {
    s.media.contains(&MediaRequest::StartSending { session: sid.into() })
}

#[test]
fn an_automatic_answer_carries_sdp_both_ways_and_starts_media_on_the_signed_answer() {
    let (mut a, mut b) = pair(AnswerPolicy::Accept);
    let sid = place(&mut a, &b);
    assert_eq!(a.media, vec![MediaRequest::Offer { session: sid.clone(), add_source: false, video: false }]);
    assert_eq!(a.sent_of("invite")[0].pointer("/transports/0/sdp").and_then(Value::as_str), Some(sdp("actpass", "sendrecv").as_str()));
    pump(&mut a, &mut b);
    assert!(matches!(&b.media[0], MediaRequest::Answer { session, screening: false, .. } if *session == sid), "{:?}", b.media);
    assert_eq!(b.sent_types(), vec!["progress", "answer"]);
    assert_eq!(b.sent_of("answer")[0]["answered_by"], "user");
    assert!(a.media.contains(&MediaRequest::ApplyAnswer { session: sid.clone(), sdp: sdp("active", "sendrecv") }), "{:?}", a.media);
    assert_eq!((a.state(&sid), b.state(&sid)), (Some(SessionState::Active), Some(SessionState::Active)));
    assert!(starts(&a, &sid) && starts(&b, &sid), "§14.1: both send once ACTIVE: {:?} {:?}", a.media, b.media);
}

#[test]
fn a_ringing_call_waits_for_the_user() {
    let (mut a, mut b) = pair(AnswerPolicy::Ring);
    let sid = place(&mut a, &b);
    pump(&mut a, &mut b);
    assert_eq!(b.events, vec![CallEvent::Ringing { session: sid.clone() }]);
    assert_eq!(b.sent_types(), vec!["progress"]);
    assert!(b.media.is_empty(), "no media work before the user answers");
    b.command(CallCommand::Accept { session: sid.clone() });
    pump(&mut a, &mut b);
    assert_eq!(b.state(&sid), Some(SessionState::Active));
    assert!(starts(&a, &sid) && starts(&b, &sid));
}

#[test]
fn candidates_wait_for_active_then_ride_in_one_signed_info() {
    let (mut a, mut b) = pair(AnswerPolicy::Ring);
    let sid = place(&mut a, &b);
    let c1 = json!({"candidate": "candidate:1 1 udp 2122260223 192.0.2.1 50000 typ host", "sdp_mid": "0", "sdp_m_line_index": 0});
    a.result(MediaResult::Candidate { session: sid.clone(), candidate: Some(c1.clone()) });
    a.result(MediaResult::Candidate { session: sid.clone(), candidate: None });
    pump(&mut a, &mut b);
    assert!(a.sent_of("info").is_empty(), "§12.12: info is ACTIVE-only");
    b.command(CallCommand::Accept { session: sid.clone() });
    pump(&mut a, &mut b);
    let info = a.sent_of("info");
    assert_eq!(info.len(), 1, "{:?}", a.sent_types());
    assert_eq!(info[0]["data"], json!({"candidates": [c1.clone()], "end_of_candidates": true}));
    assert!(b.media.contains(&MediaRequest::RemoteCandidates { session: sid.clone(), candidates: vec![c1] }), "{:?}", b.media);
}

#[test]
fn screening_answers_without_sending_then_escalates_with_a_re_offer() {
    let (mut a, mut b) = pair(AnswerPolicy::Screen);
    let sid = place(&mut a, &b);
    pump(&mut a, &mut b);
    assert!(matches!(&b.media[0], MediaRequest::Answer { screening: true, .. }), "{:?}", b.media);
    assert_eq!(b.sent_of("answer")[0]["answered_by"], "screening");
    b.command(CallCommand::Escalate { session: sid.clone() });
    assert!(b.media.contains(&MediaRequest::Offer { session: sid.clone(), add_source: true, video: false }), "{:?}", b.media);
    assert_eq!(b.sent_of("update")[0]["answered_by"], "user", "§14.4 step 3");
    pump(&mut a, &mut b);
    let update = b.sent_of("update")[0]["id"].as_str().unwrap().to_string();
    assert!(a.events.contains(&CallEvent::UpdateOffered { session: sid.clone(), id: update.clone() }), "{:?}", a.events);
    a.command(CallCommand::AnswerUpdate { session: sid.clone() });
    assert!(a.media.iter().any(|m| matches!(m, MediaRequest::Answer { screening: false, .. })), "{:?}", a.media);
    assert_eq!(a.sent_of("answer").last().unwrap()["in_reply_to"], update.as_str());
    pump(&mut a, &mut b);
    assert_eq!(b.state(&sid), Some(SessionState::Active));
}

#[test]
fn an_update_can_be_rejected() {
    let (mut a, mut b) = pair(AnswerPolicy::Accept);
    let sid = place(&mut a, &b);
    pump(&mut a, &mut b);
    a.command(CallCommand::Update { session: sid.clone() });
    pump(&mut a, &mut b);
    b.command(CallCommand::RejectUpdate { session: sid.clone() });
    assert_eq!(b.sent_of("reject").last().map(|r| r["reason"].clone()), Some(json!("media.unsupported")), "{:?}", b.sent_types());
}

#[test]
fn without_media_the_call_carries_no_sdp_and_asks_nothing() {
    let mut a = Side::new(1, "Alice", CallsConfig { media: false, ..Default::default() }, CoreConfig::default());
    let mut b = Side::new(2, "Bob", CallsConfig { media: false, answer: AnswerPolicy::Accept, ..Default::default() }, CoreConfig::default());
    let sid = place(&mut a, &b);
    pump(&mut a, &mut b);
    assert!(a.media.is_empty() && b.media.is_empty());
    assert!(a.sent_of("invite")[0].pointer("/transports/0/sdp").is_none());
    assert_eq!(b.state(&sid), Some(SessionState::Active));
}

#[test]
fn a_silent_callee_neither_rings_nor_answers() {
    let (mut a, mut b) = pair(AnswerPolicy::Silent);
    let sid = place(&mut a, &b);
    pump(&mut a, &mut b);
    assert_eq!(b.events, vec![CallEvent::Silent { session: sid }]);
    assert!(b.sent.is_empty() && b.media.is_empty());
}

#[test]
fn a_declined_call_rings_then_rejects() {
    let (mut a, mut b) = pair(AnswerPolicy::Decline);
    place(&mut a, &b);
    pump(&mut a, &mut b);
    assert_eq!(b.sent_types(), vec!["progress", "reject"]);
}

#[test]
fn a_recorded_call_is_answered_only_once_the_recording_is_accepted() {
    let (mut a, mut b) = pair(AnswerPolicy::Accept);
    a.core.set_recording(Some(json!({"state": "on", "recorder": a.did(), "purpose": "quality"})));
    let sid = place(&mut a, &b);
    pump(&mut a, &mut b);
    assert!(b.events.iter().any(|e| matches!(e, CallEvent::Recording { emission, .. } if emission.get("render").is_some())), "{:?}", b.events);
    assert!(b.events.contains(&CallEvent::Ringing { session: sid.clone() }), "C§4: never answer before acceptance: {:?}", b.events);
    assert!(b.sent_of("answer").is_empty());
    b.command(CallCommand::AcceptRecording { session: sid.clone() });
    pump(&mut a, &mut b);
    assert_eq!(b.sent_of("answer").len(), 1, "{:?}", b.sent_types());
    assert_eq!(b.state(&sid), Some(SessionState::Active));
}

#[test]
fn a_recording_declined_by_policy_rejects_the_call() {
    let mut a = Side::new(1, "Alice", CallsConfig::default(), CoreConfig::default());
    let mut b = Side::new(2, "Bob", CallsConfig { recording: AcceptPolicy::Never, answer: AnswerPolicy::Accept, ..Default::default() },
                          CoreConfig::default());
    a.core.set_recording(Some(json!({"state": "on", "recorder": a.did()})));
    place(&mut a, &b);
    pump(&mut a, &mut b);
    assert_eq!(b.sent_of("reject").first().map(|r| r["reason"].clone()), Some(json!(dsip_recording::DECLINED)), "{:?}", b.sent_types());
}

#[test]
fn a_sealed_call_refused_as_an_unknown_critical_extension_is_placed_once_more_in_clear() {
    let mut a = Side::new(1, "Alice", CallsConfig::default(), CoreConfig { seal: true, ..Default::default() });
    let mut b = Side::new(2, "Bob", CallsConfig::default(), CoreConfig::default());
    let sid = place(&mut a, &b);
    assert!(a.sent_of("invite")[0].get("media").is_none(), "the invite went out sealed: {:?}", a.sent_of("invite")[0]);
    // what a relay without sealed-body/1.0 answers (§10.4, §11.3)
    let frame = refusal(&mut b, &a.did(), &sid);
    let ev = a.core.inbound(&frame, NOW).unwrap();
    let out = a.calls.observe(&mut a.core, ev, NOW).unwrap();
    a.take(out);
    let new = a.events.iter().find_map(|e| match e { CallEvent::ResentInClear { old, new, .. } if *old == sid => Some(new.clone()), _ => None });
    let new = new.unwrap_or_else(|| panic!("{:?}", a.events));
    assert!(a.media.contains(&MediaRequest::Close { session: sid.clone() }));
    assert!(!a.core.seal());
    let invites = a.sent_of("invite");
    assert_eq!(invites.len(), 2);
    assert_eq!(invites[1]["id"], new.as_str());
    assert!(invites[1].get("media").is_some(), "the second invite is in clear");
    // once: a second refusal changes nothing
    let again = refusal(&mut b, &a.did(), &new);
    let ev = a.core.inbound(&again, NOW).unwrap();
    let out = a.calls.observe(&mut a.core, ev, NOW).unwrap();
    a.take(out);
    assert_eq!(a.sent_of("invite").len(), 2);
}


#[test]
fn a_sealed_invite_goes_to_the_key_the_callees_key_agreement_delegation_names() {
    // core §7.3, §10.4 rule 3 (spec-gap 179): Bob's identity delegated an X25519 key; his device holds that alone
    let bob_identity = KeyPair::from_seed([2; 32]);
    let secret = [42u8; 32];
    let public = dsip_core::hpke::x25519_public(&secret);
    let payload = json!({"type": "KeyAgreementDelegation", "subject": bob_identity.did(),
                         "key": dsip_core::did::multibase_x25519(&public), "issued_at": NOW - 60, "expires_at": NOW + 86_400});
    let credential: Value = serde_json::from_str(&sign(&payload, &bob_identity, &bob_identity.kid()).frame()).unwrap();

    let mut a = Side::new(1, "Alice", CallsConfig::default(), CoreConfig { seal: true, ..Default::default() });
    let device_signed: Value = serde_json::from_str(&sign(&payload, &KeyPair::from_seed([102; 32]), &KeyPair::from_seed([102; 32]).kid()).frame()).unwrap();
    assert!(!a.core.hold_key_agreement(&device_signed, NOW), "not the identity's own: refused");
    assert!(a.core.hold_key_agreement(&credential, NOW));
    let mut b = Side::new(2, "Bob", CallsConfig::default(), CoreConfig { unseal_keys: vec![(bob_identity.did(), secret)], ..Default::default() });
    let sid = place(&mut a, &b);
    assert!(a.sent_of("invite")[0].get("sealed").is_some(), "sealed: {:?}", a.sent_of("invite")[0]);
    pump(&mut a, &mut b);
    assert_eq!(b.state(&sid), Some(SessionState::Alerting), "Bob's device opened it with the delegated key alone, and rings");
}

#[test]
fn with_one_call_a_second_invite_is_declined_busy_without_asking_the_user() {
    let mut a = Side::new(1, "Alice", CallsConfig::default(), CoreConfig::default());
    let mut c = Side::new(3, "Carol", CallsConfig::default(), CoreConfig::default());
    let mut b = Side::new(2, "Bob", CallsConfig { one_call: true, ..Default::default() }, CoreConfig::default());
    let first = place(&mut a, &b);
    pump(&mut a, &mut b);
    assert_eq!(b.events, vec![CallEvent::Ringing { session: first.clone() }]);
    let second = place(&mut c, &b);
    pump(&mut c, &mut b);
    assert_eq!(b.events.len(), 1, "the second call is not put to the user: {:?}", b.events);
    assert_eq!(b.sent_types(), vec!["progress", "progress", "reject"], "§12.4: rejected from ALERTING");
    assert_eq!(b.sent_of("reject")[0]["reason"], "user.busy");
    assert_eq!(b.sent_of("reject")[0]["session"], second.as_str());
    assert_eq!(b.state(&first), Some(SessionState::Alerting), "the first call still rings");
}

#[test]
fn a_call_cancelled_before_its_offer_is_dropped_and_does_not_make_us_busy() {
    let mut a = Side::new(1, "Alice", CallsConfig { one_call: true, ..Default::default() }, CoreConfig::default());
    let mut b = Side::new(2, "Bob", CallsConfig::default(), CoreConfig::default());
    a.auto_media = false;
    let (sid, out) = a.calls.place(&mut a.core, &b.did(), Invite::default(), NOW).unwrap();
    a.take(out);
    a.command(CallCommand::Cancel { session: sid.clone() });
    assert_eq!(a.media.last(), Some(&MediaRequest::Close { session: sid.clone() }));
    assert!(a.sent.is_empty(), "nothing went out");
    a.result(MediaResult::Offer { session: sid, sdp: sdp("actpass", "sendrecv") });
    assert!(a.sent.is_empty(), "a late offer for the dropped call places nothing");
    a.auto_media = true;
    let back = place(&mut b, &a);
    pump(&mut b, &mut a);
    assert_eq!(a.events, vec![CallEvent::Ringing { session: back }], "not busy");
}

#[test]
fn consent_says_a_declared_recording_is_pending() {
    let (mut a, mut b) = pair(AnswerPolicy::Ring);
    a.core.set_recording(Some(json!({"state": "on", "recorder": a.did()})));
    let sid = place(&mut a, &b);
    pump(&mut a, &mut b);
    assert_eq!(b.calls.consent(&sid).map(|c| c["pending"].clone()), Some(json!(true)));
    b.command(CallCommand::AcceptRecording { session: sid.clone() });
    assert_eq!(b.calls.consent(&sid).map(|c| c["pending"].clone()), Some(json!(false)));
    assert_eq!(b.calls.consent("nope"), None);
}

#[test]
fn a_host_decided_call_waits_offered_then_rings_and_answers_as_the_host_says() {
    let (mut a, mut b) = pair(AnswerPolicy::Host);
    let sid = place(&mut a, &b);
    pump(&mut a, &mut b);
    assert!(b.events.is_empty() && b.sent.is_empty() && b.media.is_empty(), "nothing until the host decides: {:?} {:?}", b.events, b.sent_types());
    assert_eq!(b.state(&sid), Some(SessionState::Offered));
    b.command(CallCommand::Alert { session: sid.clone(), ring_timeout: Some(60) });
    assert_eq!(b.sent_types(), vec!["progress"]);
    b.command(CallCommand::AcceptAs { session: sid.clone(), answered_by: "gateway".into() });
    assert!(matches!(&b.media[0], MediaRequest::Answer { session, screening: false, .. } if *session == sid));
    assert_eq!(b.sent_of("answer")[0]["answered_by"], "gateway");
    pump(&mut a, &mut b);
    assert_eq!((a.state(&sid), b.state(&sid)), (Some(SessionState::Active), Some(SessionState::Active)));
}

#[test]
fn accepting_a_call_still_offered_alerts_it_first() {
    let (mut a, mut b) = pair(AnswerPolicy::Host);
    let sid = place(&mut a, &b);
    pump(&mut a, &mut b);
    b.command(CallCommand::AcceptAs { session: sid.clone(), answered_by: "gateway".into() });
    assert_eq!(b.sent_types(), vec!["progress", "answer"], "§12.4: a callee answers from ALERTING");
    pump(&mut a, &mut b);
    assert_eq!(a.state(&sid), Some(SessionState::Active));
}

#[test]
fn candidates_gathered_together_ride_in_one_info() {
    let (mut a, mut b) = pair(AnswerPolicy::Accept);
    let sid = place(&mut a, &b);
    pump(&mut a, &mut b);
    let c = |n: u8| json!({"candidate": format!("candidate:{n} 1 udp 1 127.0.0.1 500{n} typ host"), "sdp_mid": "0", "sdp_m_line_index": 0});
    a.result(MediaResult::Candidates { session: sid.clone(), candidates: vec![c(1), c(2), c(3)] });
    let infos = a.sent_of("info");
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0]["data"]["candidates"].as_array().map(Vec::len), Some(3));
}
