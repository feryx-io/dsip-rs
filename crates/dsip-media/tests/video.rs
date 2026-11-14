//! A leg's video end to end on the forge backend: coded frames in on one side come out whole on the other, over
//! DTLS-SRTP on loopback, with candidates trickled as the DSIP agent does.
//!
//! Spec: B§3.4 (H.264 constrained baseline, the codec every endpoint doing video supports; spec-gap 181), B§2.1 (the
//! video section follows the audio one; an audio-only answerer refuses video with port 0), §14.1 (nothing is sent
//! before `start_sending`).

use std::time::Duration;

use dsip_media::{Backend, Bytes, MediaConfig, MediaEvent, MediaLeg, Source, VideoConfig, VideoFeed, VideoFrame};
use tokio::sync::mpsc;

/// Set up logging; whether the forge backend is in this build (CI also builds dsip-media with webrtc-rs alone).
fn init() -> bool {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    Backend::available().contains(&Backend::Forge)
}

/// An Annex B H.264 frame of `size` bytes: SPS, PPS and an IDR slice for a keyframe, else a non-IDR slice. Its
/// bytes after the NAL header count up from `n`, so a frame that arrives altered or out of order does not compare
/// equal. Large frames go out as several FU-A packets.
fn h264(n: u32, keyframe: bool, size: usize) -> Bytes {
    let mut f = vec![];
    if keyframe {
        f.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x42, 0xe0, 0x1f, 0xda]); // SPS, constrained baseline 3.1
        f.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80]); // PPS
    }
    f.extend_from_slice(&[0, 0, 0, 1, if keyframe { 0x65 } else { 0x41 }]);
    // no 0x00 0x00 runs: they would read as a start code
    f.extend((0..size).map(|i| ((n as usize + i) % 250 + 1) as u8));
    Bytes::from(f)
}

struct Side {
    leg: MediaLeg,
    frames: mpsc::UnboundedSender<VideoFrame>,
    received: mpsc::UnboundedReceiver<VideoFrame>,
}

async fn side(video: bool) -> Side {
    let (frames, feed) = VideoFeed::channel();
    let (sink, received) = mpsc::unbounded_channel();
    let leg = MediaLeg::new(MediaConfig {
        source: Source::Tone { hz: 440.0 },
        backend: Backend::Forge,
        video: video.then(|| VideoConfig { source: Some(feed), sink: Some(sink), ..VideoConfig::default() }),
        ..MediaConfig::default()
    })
    .await
    .unwrap();
    Side { leg, frames, received }
}

/// Offer, answer, start, and trickle candidates until both sides hear audio.
async fn connect(a: &mut Side, b: &mut Side) {
    let offer = a.leg.create_offer().await.unwrap();
    let answer = b.leg.accept_offer(&offer).await.unwrap();
    a.leg.set_answer(&answer).await.unwrap();
    a.leg.start_sending();
    b.leg.start_sending();
    connect_events(a, b).await;
}

#[tokio::test]
async fn frames_cross_whole_both_ways() {
    if !init() {
        return;
    }
    let (mut a, mut b) = (side(true).await, side(true).await);
    connect(&mut a, &mut b).await;
    // 3 s of 30 fps from each side: a keyframe a second, 6 KB keyframes over several packets, 1.5 KB deltas
    let sent: Vec<VideoFrame> = (0..90u32)
        .map(|n| {
            let key = n % 30 == 0;
            VideoFrame { data: h264(n, key, if key { 6_000 } else { 1_500 }), keyframe: key, timestamp: n * 3_000 }
        })
        .collect();
    for f in &sent {
        a.frames.send(f.clone()).unwrap();
        b.frames.send(f.clone()).unwrap();
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    for (who, side) in [("a", &mut a), ("b", &mut b)] {
        let mut got = vec![];
        while let Ok(f) = side.received.try_recv() {
            got.push(f);
        }
        // loopback loses nothing: every frame, whole, in order, flagged as sent
        assert_eq!(got.len(), sent.len(), "{who} received {} of {} frames", got.len(), sent.len());
        for (g, s) in got.iter().zip(&sent) {
            assert_eq!((g.timestamp, g.keyframe), (s.timestamp, s.keyframe), "{who}");
            assert_eq!(g.data, s.data, "{who}: frame at {} altered", s.timestamp);
        }
        let stats = side.leg.stats();
        assert_eq!((stats.video_frames_in, stats.video_frames_out), (90, 90), "{who} {stats:?}");
        assert!(stats.packets_in > 0, "{who}: audio flows alongside {stats:?}");
    }
    a.leg.close().await;
    b.leg.close().await;
}

#[tokio::test]
async fn an_audio_only_answerer_refuses_video_and_the_call_goes_on() {
    if !init() {
        return;
    }
    let (mut a, mut b) = (side(true).await, side(false).await);
    let offer = a.leg.create_offer().await.unwrap();
    assert!(offer.contains("m=video"), "the offer carries video");
    let answer = b.leg.accept_offer(&offer).await.unwrap();
    // B§2.1: a refused section is answered with port 0
    assert!(answer.contains("m=video 0 "), "video refused with port 0:\n{answer}");
    a.leg.set_answer(&answer).await.unwrap();
    // audio still flows; frames offered for video go nowhere
    a.leg.start_sending();
    b.leg.start_sending();
    connect_events(&mut a, &mut b).await;
    a.frames.send(VideoFrame { data: h264(0, true, 2_000), keyframe: true, timestamp: 0 }).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(a.leg.stats().video_frames_out, 0, "no video section to send on");
    a.leg.close().await;
    b.leg.close().await;
}

/// Trickle candidates until both sides hear audio, for a pair already offered and answered.
async fn connect_events(a: &mut Side, b: &mut Side) {
    let (mut first_a, mut first_b) = (false, false);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !(first_a && first_b) {
        tokio::select! {
            Some(ev) = a.leg.next_event() => match ev {
                MediaEvent::Candidate(Some(c)) => b.leg.add_remote_candidate(&c).await.unwrap(),
                MediaEvent::FirstPacket => first_a = true,
                _ => {}
            },
            Some(ev) = b.leg.next_event() => match ev {
                MediaEvent::Candidate(Some(c)) => a.leg.add_remote_candidate(&c).await.unwrap(),
                MediaEvent::FirstPacket => first_b = true,
                _ => {}
            },
            _ = tokio::time::sleep_until(deadline) => panic!("no audio within 20 s (a={first_a} b={first_b})"),
        }
    }
}

#[tokio::test]
async fn the_webrtc_rs_backend_says_it_has_no_video_yet() {
    init();
    if !Backend::available().contains(&Backend::WebRtcRs) {
        return;
    }
    let r = MediaLeg::new(MediaConfig { backend: Backend::WebRtcRs, video: Some(VideoConfig::default()), ..MediaConfig::default() }).await;
    assert!(matches!(r, Err(dsip_media::Error::VideoUnsupported { backend: "webrtc-rs" })));
}
