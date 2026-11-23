//! Property tests over random event orderings (plan §6 WS-3 exit criterion).
//!
//! Spec: §12.5 — "cancel is authoritative for the initiator's intent. A session
//! only becomes ACTIVE at the initiator when the initiator has not cancelled."
//! Also: the engine never panics, and at most one update is outstanding (§12.8 rule 2).

use proptest::prelude::*;
use serde_json::json;

use dsip_session::{Emission, Endpoint, EndpointConfig, Event, LocalEvent, Message, SessionState};

const SID: &str = "01J5Y0Q6K8ZJ4M2N7P9R3S5T7V";
const ALICE_PHONE: &str = "did:key:z6MkAlicePhone";
const BOB: &str = "did:key:z6MkBob";
const BOB_PHONE: &str = "did:key:z6MkBobPhone";
const BOB_LAPTOP: &str = "did:key:z6MkBobLaptop";

fn msg(t: &str, id: &str, from: &str) -> Message {
    Message { msg_type: t.into(), id: id.into(), from: from.into(), session: Some(SID.into()), ..Default::default() }
}

fn arb_event() -> impl Strategy<Value = Event> {
    let ids = prop::sample::select(vec!["01J5Y0Q7A1BCD2EF3GH4JK5MN6", "01J5Y0Q8P0QRS1TV2WX3YZ4A5B", "01J5Y0Q9C6DE7FG8HJ9KM0NP1Q"]);
    let devs = prop::sample::select(vec![BOB_PHONE, BOB_LAPTOP]);
    prop_oneof![
        Just(Event::Local(LocalEvent::PlaceCall { session: SID.into(), to: BOB.into() })),
        Just(Event::Local(LocalEvent::Cancel { session: SID.into() })),
        Just(Event::Local(LocalEvent::Hangup { session: SID.into(), reason: None })),
        ids.clone().prop_map(|id| Event::Local(LocalEvent::Update { session: SID.into(), id: id.into(), answered_by: None, validity: None })),
        ids.clone().prop_map(|id| Event::Local(LocalEvent::AnswerUpdate { session: SID.into(), in_reply_to: id.into(), answered_by: None })),
        Just(Event::Local(LocalEvent::Info { session: SID.into() })),
        (ids.clone(), devs.clone()).prop_map(|(id, d)| Event::Recv { recv: Message { status: Some("ringing".into()), ..msg("progress", id, d) } }),
        (ids.clone(), devs.clone()).prop_map(|(id, d)| Event::Recv { recv: Message { status: Some("queued".into()), queue_timeout: Some(60), ..msg("progress", id, d) } }),
        (ids.clone(), devs.clone()).prop_map(|(id, d)| Event::Recv { recv: Message { answered_by: Some("user".into()), ..msg("answer", id, d) } }),
        (ids.clone(), devs.clone()).prop_map(|(id, d)| Event::Recv { recv: Message { reason: Some("user.declined".into()), ..msg("reject", id, d) } }),
        (ids.clone(), devs.clone()).prop_map(|(id, d)| Event::Recv { recv: msg("update", id, d) }),
        (ids.clone(), devs.clone()).prop_map(|(id, d)| Event::Recv { recv: Message { reason: Some("user.hangup".into()), ..msg("bye", id, d) } }),
        (ids, devs).prop_map(|(id, d)| Event::Recv { recv: Message { about: Some("transport:webrtc".into()), ..msg("info", id, d) } }),
        (1i64..200).prop_map(|s| Event::Advance { advance: s }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn initiator_invariants(events in prop::collection::vec(arb_event(), 1..40)) {
        let cfg = EndpointConfig::from_vector(&json!({
            "self": {"device": ALICE_PHONE, "identity": "did:key:z6MkAlice"},
            "identities": {BOB_PHONE: BOB, BOB_LAPTOP: BOB}, "start": 1_760_000_000,
        }));
        let mut ep = Endpoint::new(cfg);
        let mut cancelled = false;
        for ev in &events {
            if matches!(ev, Event::Local(LocalEvent::PlaceCall { .. })) {
                cancelled = false; // a fresh attempt (the generator reuses one session id)
            }
            let out = ep.step(ev);
            for e in &out {
                if let Emission::Send(m) = e {
                    // A withdrawal of intent (§12.5) — not the post-accept per-leg cancel of §12.7 rule 3.
                    if m.msg_type == "cancel" && m.reason.as_deref() != Some("session.answered-elsewhere") { cancelled = true; }
                    // §12.5 rule 3: after our cancel, any answer gets bye session.cancelled, never media.
                    if cancelled && m.msg_type == "bye" && m.reason.as_deref() == Some("session.already-answered") {
                        prop_assert!(false, "already-answered after cancel: {:?}", events);
                    }
                }
                if cancelled {
                    prop_assert!(!matches!(e, Emission::Media(dsip_session::MediaCommand::Start)), "media started after cancel: {:?}", events);
                }
            }
            if let Some(s) = ep.session(SID) {
                if cancelled {
                    prop_assert_ne!(s.state, SessionState::Active, "ACTIVE after cancel: {:?}", events);
                }
                // §12.8 rule 2 is structural (Option<Outstanding>), but renegotiating implies outbound.
                if s.renegotiating() {
                    prop_assert!(s.outstanding.is_some());
                }
            }
        }
    }
}
