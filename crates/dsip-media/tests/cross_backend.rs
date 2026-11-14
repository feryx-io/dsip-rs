//! Backend interop through the `MediaLeg` surface: forge ↔ webrtc-rs in both
//! directions and forge ↔ forge, with candidates trickled exactly as the DSIP
//! agent would do it (`info.data.candidates`, end_of_candidates = `None`).
//!
//! Spec: §14.1 (sending starts on `start_sending`), §12.12 (candidate shape),
//! §14.2 (the answer is an answer to the offer). Both backends must satisfy
//! the WebRTC Media Binding; this is the executable form of "demos run against
//! both backends" from the binding's Appendix C.

use std::time::Duration;

use dsip_media::{Backend, MediaConfig, MediaEvent, MediaLeg, Source};

async fn run(a: Backend, b: Backend) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let avail = Backend::available();
    if !avail.contains(&a) || !avail.contains(&b) {
        eprintln!("skipping {}↔{}: not compiled", a.name(), b.name());
        return;
    }
    let dir = std::env::temp_dir().join(format!("dsip-cross-{}-{}-{}", a.name(), b.name(), std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut caller = MediaLeg::new(MediaConfig {
        source: Source::Tone { hz: 440.0 },
        record: Some(dir.join("caller-heard.ogg")),
        stun: vec![],
        turn: vec![],
        backend: a,
        send_only: false,
        tap_in: None,
        tap_out: None,
        video: None,
    })
    .await
    .unwrap();
    let mut callee = MediaLeg::new(MediaConfig {
        source: Source::Tone { hz: 660.0 },
        record: Some(dir.join("callee-heard.ogg")),
        stun: vec![],
        turn: vec![],
        backend: b,
        send_only: false,
        tap_in: None,
        tap_out: None,
        video: None,
    })
    .await
    .unwrap();

    let offer = caller.create_offer().await.unwrap();
    let answer = callee.accept_offer(&offer).await.unwrap();
    caller.set_answer(&answer).await.unwrap();
    // §14.1: the host starts media only once ACTIVE; here ACTIVE is "answer applied".
    caller.start_sending();
    callee.start_sending();

    let (mut first_a, mut first_b, mut end_a, mut end_b) = (false, false, false, false);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !(first_a && first_b) {
        tokio::select! {
            Some(ev) = caller.next_event() => match ev {
                MediaEvent::Candidate(Some(c)) => callee.add_remote_candidate(&c).await.unwrap(),
                MediaEvent::Candidate(None) => end_a = true,
                MediaEvent::FirstPacket => first_a = true,
                MediaEvent::State(s) => { eprintln!("caller[{}]: {s}", a.name()); assert!(!s.starts_with("failed")); }
            },
            Some(ev) = callee.next_event() => match ev {
                MediaEvent::Candidate(Some(c)) => caller.add_remote_candidate(&c).await.unwrap(),
                MediaEvent::Candidate(None) => end_b = true,
                MediaEvent::FirstPacket => first_b = true,
                MediaEvent::State(s) => { eprintln!("callee[{}]: {s}", b.name()); assert!(!s.starts_with("failed")); }
            },
            _ = tokio::time::sleep_until(deadline) => panic!("{}↔{}: no media within 20 s (first_a={first_a} first_b={first_b})", a.name(), b.name()),
        }
    }
    assert!(end_a && end_b, "both sides must signal end of candidates");
    // Let a few frames flow, then check counters and recordings.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (sa, sb) = (caller.stats(), callee.stats());
    assert!(sa.packets_in >= 5 && sb.packets_in >= 5, "caller {sa:?} callee {sb:?}");
    assert!(sa.frames_out >= 5 && sb.frames_out >= 5, "caller {sa:?} callee {sb:?}");
    caller.close().await;
    callee.close().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    for f in ["caller-heard.ogg", "callee-heard.ogg"] {
        let bytes = std::fs::read(dir.join(f)).unwrap();
        assert!(bytes.windows(8).any(|w| w == b"OpusHead"), "{f} lacks OpusHead");
        assert!(bytes.windows(4).filter(|w| *w == b"OggS").count() >= 2, "{f} has no audio pages");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn forge_calls_webrtc_rs() {
    run(Backend::Forge, Backend::WebRtcRs).await;
}

#[tokio::test]
async fn webrtc_rs_calls_forge() {
    run(Backend::WebRtcRs, Backend::Forge).await;
}

#[tokio::test]
async fn forge_calls_forge() {
    run(Backend::Forge, Backend::Forge).await;
}

#[tokio::test]
async fn webrtc_rs_calls_webrtc_rs() {
    run(Backend::WebRtcRs, Backend::WebRtcRs).await;
}
