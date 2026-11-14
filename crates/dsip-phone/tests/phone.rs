//! Phones on the testkit's in-process network: a call answered and hung up from either side, a call declined, a call
//! cancelled while it rings, a phone that answers by policy, a call to nobody, and two phones calling with native
//! audio, whose media starts on the signed answer.
//!
//! Spec: §12.4, §12.11 (cancel before the answer, bye after), §14.1, §14.3 (`answered_by`), §14.4 (screening).

use std::time::Duration;

use dsip_phone::{AnswerPolicy, CallState, Outcome, Phone};
use dsip_testkit::Network;

async fn phone(net: &Network, name: &str, answer: AnswerPolicy) -> Phone {
    Phone::builder().identity(net.identity(name)).dialer(net.dialer()).answer(answer).build().await.expect("phone")
}

async fn within<T>(what: &str, f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(dsip_testkit::TIMEOUT, f).await.unwrap_or_else(|_| panic!("no {what} within {:?}", dsip_testkit::TIMEOUT))
}

#[tokio::test]
async fn a_call_is_answered_then_hung_up_by_the_caller() {
    let net = Network::new();
    let alice = phone(&net, "Alice", AnswerPolicy::Ring).await;
    let bob = phone(&net, "Bob", AnswerPolicy::Ring).await;

    let mut call = alice.call(bob.identity()).await.unwrap();
    let incoming = within("incoming call", bob.incoming()).await.unwrap();
    assert_eq!(incoming.from, alice.identity());
    assert_eq!(incoming.display_name.as_deref(), Some("Alice"));
    let mut theirs = incoming.accept();

    assert_eq!(within("answer", call.outcome()).await, Outcome::Answered { answered_by: "user".into() });
    call.hang_up();
    assert_eq!(within("bye", theirs.ended()).await, "user.hangup");
    assert!(matches!(call.state(), CallState::Ended { .. }) || within("our end", call.ended()).await == "user.hangup");
}

#[tokio::test]
async fn the_callee_hangs_up() {
    let net = Network::new();
    let alice = phone(&net, "Alice", AnswerPolicy::Ring).await;
    let bob = phone(&net, "Bob", AnswerPolicy::Accept).await;

    let mut call = alice.call(bob.identity()).await.unwrap();
    let mut theirs = within("incoming call", bob.incoming()).await.unwrap().call;
    assert!(matches!(within("answer", call.outcome()).await, Outcome::Answered { .. }));
    within("answered on Bob's side", async {
        while !matches!(theirs.state(), CallState::Answered { .. }) {
            theirs.changed().await;
        }
    })
    .await;
    theirs.hang_up();
    assert_eq!(within("bye", call.ended()).await, "user.hangup");
}

#[tokio::test]
async fn a_declined_call_ends_with_the_callees_reason() {
    let net = Network::new();
    let alice = phone(&net, "Alice", AnswerPolicy::Ring).await;
    let bob = phone(&net, "Bob", AnswerPolicy::Ring).await;

    let mut call = alice.call(bob.identity()).await.unwrap();
    within("incoming call", bob.incoming()).await.unwrap().decline();
    match within("rejection", call.outcome()).await {
        Outcome::Ended { reason } => assert!(reason.starts_with("user."), "{reason}"),
        o => panic!("{o:?}"),
    }
}

#[tokio::test]
async fn a_ringing_call_is_cancelled() {
    let net = Network::new();
    let alice = phone(&net, "Alice", AnswerPolicy::Ring).await;
    let bob = phone(&net, "Bob", AnswerPolicy::Ring).await;

    let mut call = alice.call(bob.identity()).await.unwrap();
    let mut theirs = within("incoming call", bob.incoming()).await.unwrap().call;
    within("ringing", async {
        while call.state() != CallState::Ringing {
            call.changed().await;
        }
    })
    .await;
    call.hang_up();
    within("cancel on Bob's side", theirs.ended()).await;
    within("our end", call.ended()).await;
}

#[tokio::test]
async fn a_screening_phone_answers_as_screening() {
    let net = Network::new();
    let alice = phone(&net, "Alice", AnswerPolicy::Ring).await;
    let bob = phone(&net, "Bob", AnswerPolicy::Screen).await;

    let mut call = alice.call(bob.identity()).await.unwrap();
    assert_eq!(within("answer", call.outcome()).await, Outcome::Answered { answered_by: "screening".into() });
}

#[tokio::test]
async fn a_call_to_nobody_says_why_and_ends_by_its_timer() {
    let net = Network::new();
    // T-Establish at its 5 s floor (§12.9): the relay's refusal changes no state (§12.7 rule 6), the timer ends it
    let alice = Phone::builder().identity(net.identity("Alice")).dialer(net.dialer()).configure(|c| c.t_establish = Some(5))
        .build().await.unwrap();
    let nobody = net.identity("Nobody");

    let mut call = alice.call(&nobody.meta.identity).await.unwrap();
    assert!(matches!(within("the call's end", call.outcome()).await, Outcome::Ended { .. }));
    assert_eq!(call.error().as_deref(), Some("transport.unknown-recipient"));
}

#[tokio::test]
async fn closing_a_phone_ends_its_calls() {
    let net = Network::new();
    let alice = phone(&net, "Alice", AnswerPolicy::Ring).await;
    let bob = phone(&net, "Bob", AnswerPolicy::Accept).await;

    let mut call = alice.call(bob.identity()).await.unwrap();
    assert!(matches!(within("answer", call.outcome()).await, Outcome::Answered { .. }));
    alice.close().await.unwrap();
    assert_eq!(within("end", call.ended()).await, "transport.closed");
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn two_phones_with_native_audio_hear_each_other() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let net = Network::new();
    let media = || {
        dsip_phone::Media::Native(dsip_media::MediaConfig { source: dsip_media::Source::Tone { hz: 440.0 }, ..Default::default() })
    };
    let alice = Phone::builder().identity(net.identity("Alice")).dialer(net.dialer()).media(media()).build().await.unwrap();
    let bob = Phone::builder().identity(net.identity("Bob")).dialer(net.dialer()).media(media()).answer(AnswerPolicy::Accept)
        .build().await.unwrap();

    let mut call = alice.call(bob.identity()).await.unwrap();
    let theirs = within("incoming call", bob.incoming()).await.unwrap().call;
    assert!(matches!(within("answer", call.outcome()).await, Outcome::Answered { .. }));
    // §14.1: both sides send once the answer is signed; each hears the other
    within("media both ways", async {
        while !(call.media_received() && theirs.media_received()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    call.hang_up();
}

/// A relay's `/turn` on a local port: what it answers, and how many times it was asked.
async fn turn_endpoint(body: Option<&'static str>) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/turn", listener.local_addr().unwrap());
    let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf).await;
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (status, body) = match body {
                Some(b) => ("200 OK", b),
                None => ("404 Not Found", "no turn"),
            };
            let reply = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = s.write_all(reply.as_bytes()).await;
        }
    });
    (url, asked)
}

#[tokio::test]
async fn calls_go_on_without_turn_when_the_relay_has_none_or_its_server_is_down() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let net = Network::new();
    let media = || {
        dsip_phone::Media::Native(dsip_media::MediaConfig { source: dsip_media::Source::Tone { hz: 440.0 }, ..Default::default() })
    };
    // Alice's relay gives credentials for a TURN server that is not there; Bob's has none (404)
    let (alice_url, alice_asked) =
        turn_endpoint(Some(r#"{"iceServers":[{"urls":["turn:127.0.0.1:9"],"username":"9999999999:dsip","credential":"x"}],"ttl":3600}"#)).await;
    let (bob_url, bob_asked) = turn_endpoint(None).await;
    let turn = |url: &str| dsip_transport::turn::TurnClient::new(url, None).unwrap();
    let alice = Phone::builder().identity(net.identity("Alice")).dialer(net.dialer()).media(media()).turn(turn(&alice_url))
        .build().await.unwrap();
    let bob = Phone::builder().identity(net.identity("Bob")).dialer(net.dialer()).media(media()).answer(AnswerPolicy::Accept)
        .turn(turn(&bob_url)).build().await.unwrap();

    for n in 0..2 {
        let started = std::time::Instant::now();
        let mut call = alice.call(bob.identity()).await.unwrap();
        let theirs = within("incoming call", bob.incoming()).await.unwrap().call;
        assert!(matches!(within("answer", call.outcome()).await, Outcome::Answered { .. }));
        // the direct path still carries the call: an unreachable TURN server, or none, takes nothing away
        within("media both ways", async {
            while !(call.media_received() && theirs.media_received()) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        call.hang_up();
        within("the end", call.ended()).await;
        // the first waits for the TURN server a few seconds and goes on without it; the second does not wait
        if n == 1 {
            assert!(started.elapsed() < Duration::from_secs(3), "the second call waited {:?}", started.elapsed());
        }
    }
    use std::sync::atomic::Ordering::SeqCst;
    assert_eq!(alice_asked.load(SeqCst), 1, "asked once: the second call skips a TURN server that did not answer");
    assert_eq!(bob_asked.load(SeqCst), 2, "a relay with no TURN is asked again for each call");
}

#[tokio::test]
async fn a_did_key_bound_elsewhere_is_called_through_the_relay_its_hint_names() {
    // §8.1: Bob has no document; his hint on the hints node names his relay, which is not Alice's
    let (mine, theirs) = (Network::new(), Network::new());
    let node = dsip_testkit::hints_node().await;
    let hints = dsip_transport::hints::HintsClient::new(vec![node.clone()], None).unwrap();
    let bob_id = theirs.identity("Bob");
    let now = dsip_transport::now_s();
    let endpoints = dsip_transport::hints::endpoints(Some(theirs.url()), None);
    let hint = dsip_transport::hints::reachability(&bob_id.meta.identity, &bob_id.device, &bob_id.delegation, &endpoints, now, now, 3600);
    hints.publish(&hint).await;
    let bob = Phone::builder().identity(bob_id).relay(theirs.url()).dialer(theirs.dialer()).answer(AnswerPolicy::Ring).build().await.unwrap();

    let peers = Network::peers(&[&mine, &theirs]);
    let alice = Phone::builder()
        .identity(mine.identity("Alice"))
        .relay(mine.url())
        .dialer(mine.dialer())
        .hints(hints)
        .configure(move |c| c.peer_dialer = Some(peers))
        .build()
        .await
        .unwrap();
    let mut call = alice.call(bob.identity()).await.unwrap();
    assert_eq!(call.via(), Some(theirs.url()), "through Bob's relay, as his hint says");
    let incoming = within("incoming call at Bob", bob.incoming()).await.unwrap();
    assert_eq!(incoming.from, alice.identity());
    let mut theirs_call = incoming.accept();
    assert_eq!(within("answer", call.outcome()).await, Outcome::Answered { answered_by: "user".into() });
    call.hang_up();
    assert_eq!(within("bye at Bob", theirs_call.ended()).await, "user.hangup");
}

/// A phone whose media has video: the sender its encoder writes to, and what its decoder is given.
struct VideoPhone {
    phone: Phone,
    frames: tokio::sync::mpsc::UnboundedSender<dsip_media::VideoFrame>,
    received: tokio::sync::mpsc::UnboundedReceiver<dsip_media::VideoFrame>,
}

async fn video_phone(net: &Network, name: &str, answer: AnswerPolicy) -> VideoPhone {
    let (frames, feed) = dsip_media::VideoFeed::channel();
    let (sink, received) = tokio::sync::mpsc::unbounded_channel();
    let media = dsip_phone::Media::Native(dsip_media::MediaConfig {
        source: dsip_media::Source::Tone { hz: 440.0 },
        video: Some(dsip_media::VideoConfig { source: Some(feed), sink: Some(sink), ..Default::default() }),
        ..Default::default()
    });
    let phone = Phone::builder().identity(net.identity(name)).dialer(net.dialer()).media(media).answer(answer).build().await.unwrap();
    VideoPhone { phone, frames, received }
}

/// An H.264 keyframe (SPS, PPS, IDR), `n` in its bytes.
fn keyframe(n: u32) -> dsip_media::VideoFrame {
    let mut f = vec![0, 0, 0, 1, 0x67, 0x42, 0xe0, 0x1f, 0xda, 0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80, 0, 0, 0, 1, 0x65];
    f.extend((0..3_000u32).map(|i| ((n + i) % 250 + 1) as u8));
    dsip_media::VideoFrame { data: f.into(), keyframe: true, timestamp: n * 3_000 }
}

/// Feed `frames` a keyframe every 33 ms until the returned task is aborted.
fn camera(frames: tokio::sync::mpsc::UnboundedSender<dsip_media::VideoFrame>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for n in 0.. {
            if frames.send(keyframe(n)).is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(33)).await;
        }
    })
}

#[tokio::test]
async fn a_video_call_carries_video_both_ways() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if !dsip_media::Backend::available().contains(&dsip_media::Backend::Forge) {
        return; // video is the forge backend's for now
    }
    let net = Network::new();
    let mut alice = video_phone(&net, "Alice", AnswerPolicy::Ring).await;
    let mut bob = video_phone(&net, "Bob", AnswerPolicy::Accept).await;
    let (ca, cb) = (camera(alice.frames.clone()), camera(bob.frames.clone()));

    let mut call = alice.phone.video_call(bob.phone.identity()).await.unwrap();
    let theirs = within("incoming call", bob.phone.incoming()).await.unwrap().call;
    assert!(matches!(within("answer", call.outcome()).await, Outcome::Answered { .. }));
    within("both sides know it is a video call", async {
        while !(call.video() && theirs.video()) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    // B§3.4: each side's frames reach the other's decoder, whole
    let a = within("video at Alice", alice.received.recv()).await.unwrap();
    let b = within("video at Bob", bob.received.recv()).await.unwrap();
    assert!(a.keyframe && b.keyframe && a.data.len() > 3_000 && b.data.len() > 3_000);
    call.hang_up();
    ca.abort();
    cb.abort();
}

#[tokio::test]
async fn a_plain_call_between_video_phones_offers_no_video() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if !dsip_media::Backend::available().contains(&dsip_media::Backend::Forge) {
        return;
    }
    let net = Network::new();
    let alice = video_phone(&net, "Alice", AnswerPolicy::Ring).await;
    let mut bob = video_phone(&net, "Bob", AnswerPolicy::Accept).await;
    let ca = camera(alice.frames.clone());

    // video is per call (Phone::video_call): a plain call is audio only, so a callee whose answer to video its
    // caller would refuse (dsip-rs before 2026-11-14) is never offered it
    let mut call = alice.phone.call(bob.phone.identity()).await.unwrap();
    let theirs = within("incoming call", bob.phone.incoming()).await.unwrap().call;
    assert!(matches!(within("answer", call.outcome()).await, Outcome::Answered { .. }));
    within("audio both ways", async {
        while !(call.media_received() && theirs.media_received()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(bob.received.try_recv().is_err(), "a plain call carried video");
    assert!(!call.video() && !theirs.video());
    call.hang_up();
    ca.abort();
}
