//! The webrtc-rs backend (plan §7's named fallback).
//!
//! Spec: see `leg` — this module satisfies that surface with the `webrtc`
//! crate. Impl: candidates come from `on_ice_candidate` (`None` = end of
//! candidates), re-offers are `create_offer` on the same `RTCPeerConnection`,
//! a screening leg is a `recvonly` transceiver with no local track.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::{MediaEngine, MIME_TYPE_OPUS};
use webrtc::api::APIBuilder;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::media::Sample;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTPCodecType};
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use webrtc::rtp_transceiver::RTCRtpTransceiverInit;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;

use crate::error::{At as _, Result};
use crate::leg::{Candidate, MediaConfig, MediaEvent, Stats};
use crate::ogg::Recorder;
use crate::source::{self, Source, FRAME_DURATION};

/// A webrtc-rs peer connection with one audio track.
pub struct WebRtcRsLeg {
    pc: Arc<RTCPeerConnection>,
    track: Option<Arc<TrackLocalStaticSample>>,
    source: Source,
    pub(crate) events: mpsc::UnboundedReceiver<MediaEvent>,
    packets_in: Arc<AtomicU64>,
    bytes_in: Arc<AtomicU64>,
    frames_out: Arc<AtomicU64>,
    sending: Arc<AtomicBool>,
    tap_out: Option<mpsc::UnboundedSender<bytes::Bytes>>,
}

impl WebRtcRsLeg {
    /// Build the peer connection and local track; nothing is sent until [`WebRtcRsLeg::start_sending`].
    pub async fn new(cfg: MediaConfig) -> Result<WebRtcRsLeg> {
        // Impl: video is carried by the forge backend only, for now; the cross-backend video test waits for this one.
        if cfg.video.is_some() {
            return Err(crate::Error::VideoUnsupported { backend: "webrtc-rs" });
        }
        let mut me = MediaEngine::default();
        me.register_default_codecs().at("codecs")?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut me).at("interceptors")?;
        let api = APIBuilder::new().with_media_engine(me).with_interceptor_registry(registry).build();
        let mut ice_servers = Vec::new();
        if !cfg.stun.is_empty() {
            ice_servers.push(RTCIceServer { urls: cfg.stun.clone(), ..Default::default() });
        }
        for t in &cfg.turn {
            ice_servers.push(RTCIceServer {
                urls: vec![t.uri.clone()],
                username: t.username.clone(),
                credential: t.password.clone(),
            });
        }
        let config = RTCConfiguration { ice_servers, ..Default::default() };
        let pc = Arc::new(api.new_peer_connection(config).await.at("peer connection")?);
        let (tx, events) = mpsc::unbounded_channel();

        // Local track (or a recvonly transceiver for screening / receive-only legs)
        let track = if cfg.source == Source::None {
            pc.add_transceiver_from_kind(
                RTPCodecType::Audio,
                Some(RTCRtpTransceiverInit { direction: RTCRtpTransceiverDirection::Recvonly, send_encodings: vec![] }),
            )
            .await
            .at("recvonly transceiver")?;
            None
        } else {
            let t = Arc::new(TrackLocalStaticSample::new(
                RTCRtpCodecCapability { mime_type: MIME_TYPE_OPUS.to_owned(), clock_rate: 48_000, channels: 1, ..Default::default() },
                "audio".to_owned(),
                "dsip".to_owned(),
            ));
            let sender = if cfg.send_only {
                // C§6: a recorder leg sends and receives nothing
                let tr = pc
                    .add_transceiver_from_track(
                        Arc::clone(&t) as Arc<dyn TrackLocal + Send + Sync>,
                        Some(RTCRtpTransceiverInit { direction: RTCRtpTransceiverDirection::Sendonly, send_encodings: vec![] }),
                    )
                    .await
                    .at("sendonly transceiver")?;
                tr.sender().await
            } else {
                pc.add_track(Arc::clone(&t) as Arc<dyn TrackLocal + Send + Sync>).await.at("add track")?
            };
            // Drain RTCP for the sender so the interceptors keep working.
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1500];
                while sender.read(&mut buf).await.is_ok() {}
            });
            Some(t)
        };

        // Trickle-out: hand each candidate to the host (it sends them in signed `info` once ACTIVE).
        let ctx = tx.clone();
        pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
            let ctx = ctx.clone();
            Box::pin(async move {
                let ev = match c {
                    Some(c) => match c.to_json() {
                        Ok(j) => MediaEvent::Candidate(Some(Candidate { candidate: j.candidate, sdp_mid: j.sdp_mid, sdp_m_line_index: j.sdp_mline_index })),
                        Err(_) => return,
                    },
                    None => MediaEvent::Candidate(None),
                };
                let _ = ctx.send(ev);
            })
        }));
        let stx = tx.clone();
        pc.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
            let _ = stx.send(MediaEvent::State(s.to_string()));
            Box::pin(async {})
        }));

        // Inbound: count packets and optionally record to Ogg.
        let packets_in = Arc::new(AtomicU64::new(0));
        let bytes_in = Arc::new(AtomicU64::new(0));
        let (pi, bi, record, ftx, tin) = (packets_in.clone(), bytes_in.clone(), cfg.record.clone(), tx.clone(), cfg.tap_in.clone());
        pc.on_track(Box::new(move |track, _receiver, _transceiver| {
            let (pi, bi, record, ftx, tin) = (pi.clone(), bi.clone(), record.clone(), ftx.clone(), tin.clone());
            Box::pin(async move {
                let mime = track.codec().capability.mime_type.to_lowercase();
                tracing::info!("inbound track {mime}");
                let mut rec = match &record {
                    Some(p) if mime.contains("opus") => Recorder::open(p),
                    _ => None,
                };
                let mut first = true;
                while let Ok((pkt, _)) = track.read_rtp().await {
                    if first {
                        first = false;
                        let _ = ftx.send(MediaEvent::FirstPacket);
                    }
                    pi.fetch_add(1, Ordering::Relaxed);
                    bi.fetch_add(pkt.payload.len() as u64, Ordering::Relaxed);
                    if let Some(t) = &tin {
                        let _ = t.send(pkt.payload.clone());
                    }
                    if let Some(r) = rec.as_mut() {
                        r.write(&pkt);
                    }
                }
                if let Some(mut r) = rec.take() {
                    r.close();
                }
            })
        }));

        Ok(WebRtcRsLeg {
            pc,
            track,
            source: cfg.source,
            events,
            packets_in,
            bytes_in,
            frames_out: Arc::new(AtomicU64::new(0)),
            sending: Arc::new(AtomicBool::new(false)),
            tap_out: cfg.tap_out,
        })
    }

    /// Add a local audio track to a leg that was created receive-only (screening → user escalation,
    /// §14.4 step 3); the next [`WebRtcRsLeg::create_offer`] re-offers `sendrecv`. No-op if a track exists.
    pub async fn add_source(&mut self, source: Source) -> Result<()> {
        if self.track.is_some() || source == Source::None {
            return Ok(());
        }
        let t = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability { mime_type: MIME_TYPE_OPUS.to_owned(), clock_rate: 48_000, channels: 1, ..Default::default() },
            "audio".to_owned(),
            "dsip".to_owned(),
        ));
        let sender = self.pc.add_track(Arc::clone(&t) as Arc<dyn TrackLocal + Send + Sync>).await.at("add track")?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            while sender.read(&mut buf).await.is_ok() {}
        });
        self.track = Some(t);
        self.source = source;
        self.sending.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Create an SDP offer (also used for re-offers, §12.8).
    pub async fn create_offer(&self) -> Result<String> {
        let offer = self.pc.create_offer(None).await.at("create offer")?;
        let sdp = offer.sdp.clone();
        self.pc.set_local_description(offer).await.at("set local")?;
        Ok(sdp)
    }

    /// Apply a remote offer and produce the SDP answer.
    pub async fn accept_offer(&self, sdp: &str) -> Result<String> {
        self.pc.set_remote_description(RTCSessionDescription::offer(sdp.to_string()).at("parse offer")?).await.at("set remote offer")?;
        let answer = self.pc.create_answer(None).await.at("create answer")?;
        let out = answer.sdp.clone();
        self.pc.set_local_description(answer).await.at("set local answer")?;
        Ok(out)
    }

    /// Apply the remote answer.
    pub async fn set_answer(&self, sdp: &str) -> Result<()> {
        self.pc.set_remote_description(RTCSessionDescription::answer(sdp.to_string()).at("parse answer")?).await.at("set remote answer")
    }

    /// Add a remote candidate (from a verified `info`).
    pub async fn add_remote_candidate(&self, c: &Candidate) -> Result<()> {
        self.pc
            .add_ice_candidate(RTCIceCandidateInit {
                candidate: c.candidate.clone(),
                sdp_mid: c.sdp_mid.clone(),
                sdp_mline_index: c.sdp_m_line_index,
                username_fragment: None,
            })
            .await
            .at("add candidate")
    }

    /// Next leg event.
    pub async fn next_event(&mut self) -> Option<MediaEvent> {
        self.events.recv().await
    }

    /// Stop transmitting until the next `start_sending` (Recording Profile C§4: media held until acceptance).
    pub fn hold_sending(&self) {
        self.sending.store(false, Ordering::SeqCst);
    }

    /// Begin transmitting the configured source. Spec §14.1: the host calls this only once ACTIVE.
    pub fn start_sending(&self) {
        if self.sending.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(track) = self.track.clone() else { return };
        let (frames, sending, src) = (self.frames_out.clone(), self.sending.clone(), self.source.clone());
        tokio::spawn(source::pump(src, sending, frames, self.tap_out.clone(), move |data| {
            let track = track.clone();
            Box::pin(async move { track.write_sample(&Sample { data, duration: FRAME_DURATION, ..Default::default() }).await.is_ok() })
        }));
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        Stats {
            packets_in: self.packets_in.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            frames_out: self.frames_out.load(Ordering::Relaxed),
            ..Stats::default()
        }
    }

    /// Stop sending and close the peer connection.
    pub async fn close(&self) {
        self.sending.store(false, Ordering::SeqCst);
        let _ = self.pc.close().await;
    }
}
