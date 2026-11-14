//! The forge-media backend: `forge-webrtc` 0.3's endpoint-shaped
//! `PeerConnection` (the project's own stack; `impl/docs/forge-media-plan.md`).
//!
//! Spec: see `leg` — this module satisfies that surface with forge. The
//! mapping is one-to-one with the WebRTC Media Binding draft, Appendix C:
//! answerer role (`set_remote_offer` + `create_answer`, DTLS role from
//! `a=setup`), trickle-out (`PeerEvent::LocalCandidate` → [`MediaEvent::Candidate`],
//! `GatheringComplete` → `Candidate(None)`), single-leg media
//! (`AudioSender::send_audio` / `PeerEvent::Rtp`), re-offer on the same
//! transport (`create_offer` after `Connected`; a screening leg starts
//! `RecvOnly` and [`ForgeLeg::add_source`] switches it to `SendRecv`).
//!
//! Video (B§3.4, [`crate::video`]): forge's video section (`PeerConfig.video`)
//! carries pre-built RTP; this module packetizes the host's coded frames
//! (`forge_rtp::video::packetize`), keeps them for retransmission
//! (`RtxCache`, answering NACK), assembles what arrives (`FrameAssembler`),
//! NACKs what is missing and asks for a keyframe (PLI, gated by
//! [`crate::video::KEYFRAME_INTERVAL`]) when a frame cannot be repaired. The
//! far end's PLI, FIR and REMB go to the host's encoder as
//! [`VideoRequest`]s.
//!
//! Impl: `PeerConnection` methods take `&mut self`, so it sits behind a tokio
//! mutex; the event pump is spawned on the first offer/answer (that is when
//! forge creates its transport and event channel).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use forge_rtp::rtcp::{PayloadFeedback, PsFeedback, RtpFeedback, TransportFeedback};
use forge_rtp::rtp::{RtpHeader, RtpPacket};
use forge_rtp::video::{packetize, AssemblerEvent, CodedFrame, FrameAssembler, KeyframeRequestGate, RtxCache};
use forge_webrtc::{AudioCodec, Direction, PeerConfig, PeerConnection, PeerEvent, RtcpPacket, TransportConfig, TurnServer,
                   VideoCodec, VideoSender};
use tokio::sync::{mpsc, Mutex};

use crate::error::{At as _, Result};
use crate::leg::{Candidate, MediaConfig, MediaEvent, Stats};
use crate::ogg::{rtp_packet, Recorder};
use crate::source::{self, Source, FRAME_SAMPLES};
use crate::video::{VideoConfig, VideoFrame, VideoRequest, KEYFRAME_INTERVAL};

/// The largest RTP payload a video packet carries: under a 1,500-byte MTU with IP, UDP, SRTP and RTP headers.
const VIDEO_MAX_PAYLOAD: usize = 1_200;

/// Video packets kept for retransmission: about a second of 1 Mbit/s video.
const RTX_PACKETS: usize = 512;

/// The forge codec for a DSIP video codec id (B§3.4).
fn forge_codec(id: &str) -> Option<VideoCodec> {
    match id {
        crate::video::H264 => Some(VideoCodec::H264),
        crate::video::VP8 => Some(VideoCodec::VP8),
        _ => None,
    }
}

/// This leg's video: the host's channels, and the packets kept for retransmission.
struct Video {
    cfg: VideoConfig,
    rtx: std::sync::Mutex<RtxCache>,
    frames_in: AtomicU64,
    frames_out: AtomicU64,
    keyframes_asked: AtomicU64,
}

/// A forge peer connection with one audio track.
pub struct ForgeLeg {
    pc: Arc<Mutex<PeerConnection>>,
    source: Source,
    record: Option<PathBuf>,
    events_tx: mpsc::UnboundedSender<MediaEvent>,
    pub(crate) events: mpsc::UnboundedReceiver<MediaEvent>,
    pump_started: AtomicBool,
    packets_in: Arc<AtomicU64>,
    bytes_in: Arc<AtomicU64>,
    frames_out: Arc<AtomicU64>,
    sending: Arc<AtomicBool>,
    tap_in: Option<mpsc::UnboundedSender<Bytes>>,
    tap_out: Option<mpsc::UnboundedSender<Bytes>>,
    video: Option<Arc<Video>>,
}

impl ForgeLeg {
    /// Build the peer connection; nothing is sent until [`ForgeLeg::start_sending`].
    pub async fn new(cfg: MediaConfig) -> Result<ForgeLeg> {
        let direction = match (&cfg.source, cfg.send_only) {
            (Source::None, _) => Direction::RecvOnly,
            (_, true) => Direction::SendOnly,
            _ => Direction::SendRecv,
        };
        let pc = PeerConnection::with_config(PeerConfig {
            stun_servers: cfg.stun.clone(),
            direction,
            // Opus only, as before forge offered a codec list: the recorder and the speech checks expect it
            codecs: vec![(AudioCodec::Opus, 111)],
            dtmf: false,
            video: cfg.video.as_ref().map(|v| forge_webrtc::VideoConfig {
                codecs: v.codecs.iter().filter_map(|id| forge_codec(id)).map(|c| (c, c.default_payload_type())).collect(),
                direction: match (v.source.is_some(), v.sink.is_some()) {
                    (true, true) => Direction::SendRecv,
                    (true, false) => Direction::SendOnly,
                    (false, true) => Direction::RecvOnly,
                    (false, false) => Direction::Inactive,
                },
                // B§3.4 (spec-gap 181): constrained baseline, which every endpoint doing video decodes
                h264_profile_level_id: "42e01f".into(),
                max_kbps: v.max_kbps,
                content: false,
            }),
            transport: TransportConfig {
                turn_servers: cfg
                    .turn
                    .iter()
                    .map(|t| TurnServer::new(t.uri.clone(), t.username.clone(), t.password.clone()))
                    .collect(),
                ..TransportConfig::default()
            },
        })
        .await
        .at("peer connection")?;
        let (events_tx, events) = mpsc::unbounded_channel();
        Ok(ForgeLeg {
            pc: Arc::new(Mutex::new(pc)),
            source: cfg.source,
            record: cfg.record,
            events_tx,
            events,
            pump_started: AtomicBool::new(false),
            packets_in: Arc::new(AtomicU64::new(0)),
            bytes_in: Arc::new(AtomicU64::new(0)),
            frames_out: Arc::new(AtomicU64::new(0)),
            sending: Arc::new(AtomicBool::new(false)),
            tap_in: cfg.tap_in,
            tap_out: cfg.tap_out,
            video: cfg.video.map(|cfg| {
                Arc::new(Video {
                    cfg,
                    rtx: std::sync::Mutex::new(RtxCache::new(RTX_PACKETS)),
                    frames_in: AtomicU64::new(0),
                    frames_out: AtomicU64::new(0),
                    keyframes_asked: AtomicU64::new(0),
                })
            }),
        })
    }

    /// Forward forge events to the host once the transport exists.
    async fn ensure_pump(&self) {
        if self.pump_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(mut rx) = self.pc.lock().await.take_events() else {
            self.pump_started.store(false, Ordering::SeqCst);
            return;
        };
        let (tx, pi, bi, record) = (self.events_tx.clone(), self.packets_in.clone(), self.bytes_in.clone(), self.record.clone());
        let tap_in = self.tap_in.clone();
        let (pc, video) = (self.pc.clone(), self.video.clone());
        tokio::spawn(async move {
            let mut rec: Option<Recorder> = None;
            let mut first = true;
            let mut inbound = video.map(|v| Inbound::new(v, pc));
            while let Some(ev) = rx.recv().await {
                match ev {
                    PeerEvent::LocalCandidate(c) => {
                        // forge emits the `candidate:` attribute form; BUNDLE means one section, mid 0.
                        let _ = tx.send(MediaEvent::Candidate(Some(Candidate {
                            candidate: c.to_sdp_attribute(),
                            sdp_mid: Some("0".into()),
                            sdp_m_line_index: Some(0),
                        })));
                    }
                    PeerEvent::GatheringComplete => {
                        let _ = tx.send(MediaEvent::Candidate(None));
                    }
                    PeerEvent::IceConnected { local, remote } => {
                        let _ = tx.send(MediaEvent::State(format!("ice connected {local} ↔ {remote}")));
                    }
                    PeerEvent::Connected => {
                        let _ = tx.send(MediaEvent::State("connected".into()));
                    }
                    PeerEvent::Failed(why) => {
                        let _ = tx.send(MediaEvent::State(format!("failed: {why}")));
                    }
                    PeerEvent::VideoRtp(pkt) => {
                        if let Some(v) = inbound.as_mut() {
                            v.packet(pkt).await;
                        }
                    }
                    // no shared-screen section is offered or accepted
                    PeerEvent::ContentRtp(_) => {}
                    PeerEvent::Closed => {
                        let _ = tx.send(MediaEvent::State("closed".into()));
                        break;
                    }
                    PeerEvent::Rtp(pkt) => {
                        if first {
                            first = false;
                            rec = record.as_deref().and_then(Recorder::open);
                            let _ = tx.send(MediaEvent::FirstPacket);
                        }
                        pi.fetch_add(1, Ordering::Relaxed);
                        bi.fetch_add(pkt.payload.len() as u64, Ordering::Relaxed);
                        if let Some(t) = &tap_in {
                            let _ = t.send(pkt.payload.clone());
                        }
                        if let Some(r) = rec.as_mut() {
                            let h = &pkt.header;
                            let (seq, ts, ssrc) = (h.sequence_number, h.timestamp, h.ssrc);
                            r.write(&rtp_packet(h.payload_type(), h.marker(), seq, ts, ssrc, pkt.payload.clone()));
                        }
                    }
                    PeerEvent::Rtcp(packets) => {
                        if let Some(v) = inbound.as_mut() {
                            v.feedback(&packets).await;
                        }
                    }
                }
            }
            if let Some(mut r) = rec.take() {
                r.close();
            }
        });
    }

    /// Add a local audio source to a leg that was created receive-only (screening →
    /// user escalation, §14.4 step 3); the next [`ForgeLeg::create_offer`] re-offers
    /// `sendrecv`. No-op if a source exists.
    pub async fn add_source(&mut self, source: Source) -> Result<()> {
        if self.source != Source::None || source == Source::None {
            return Ok(());
        }
        self.pc.lock().await.set_direction(Direction::SendRecv);
        self.source = source;
        self.sending.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Create an SDP offer (also used for re-offers, §12.8).
    pub async fn create_offer(&self) -> Result<String> {
        let sdp = self.pc.lock().await.create_offer().await.at("create_offer")?;
        self.ensure_pump().await;
        Ok(sdp)
    }

    /// Apply a remote offer and produce the SDP answer.
    pub async fn accept_offer(&self, sdp: &str) -> Result<String> {
        let answer = {
            let mut pc = self.pc.lock().await;
            pc.set_remote_offer(sdp).await.at("set_remote_offer")?;
            pc.create_answer().await.at("create_answer")?
        };
        self.ensure_pump().await;
        Ok(answer)
    }

    /// Apply the remote answer.
    pub async fn set_answer(&self, sdp: &str) -> Result<()> {
        self.pc.lock().await.set_remote_answer(sdp).await.at("set_remote_answer")
    }

    /// Add a remote candidate (from a verified `info`).
    pub async fn add_remote_candidate(&self, c: &Candidate) -> Result<()> {
        self.pc.lock().await.add_ice_candidate_str(&c.candidate).await.at("add candidate")
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
        if let Some(v) = self.video.clone().filter(|v| v.cfg.source.is_some()) {
            tokio::spawn(send_video(v, self.pc.clone(), self.sending.clone()));
        }
        if self.source == Source::None {
            return;
        }
        let (pc, src, sending, frames) = (self.pc.clone(), self.source.clone(), self.sending.clone(), self.frames_out.clone());
        let tap_out = self.tap_out.clone();
        tokio::spawn(async move {
            let sender = match pc.lock().await.sender() {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("forge sender unavailable: {e}");
                    return;
                }
            };
            source::pump(src, sending, frames, tap_out, move |data: Bytes| {
                let sender = sender.clone();
                // Frames offered before ICE/DTLS complete are dropped, not fatal
                // (the session is ACTIVE but the transport may still be connecting).
                Box::pin(async move {
                    if let Err(e) = sender.send_audio(data, FRAME_SAMPLES as u32).await {
                        tracing::trace!("frame dropped: {e}");
                    }
                    true
                })
            })
            .await;
        });
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        Stats {
            packets_in: self.packets_in.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            frames_out: self.frames_out.load(Ordering::Relaxed),
            video_frames_in: self.video.as_ref().map_or(0, |v| v.frames_in.load(Ordering::Relaxed)),
            video_frames_out: self.video.as_ref().map_or(0, |v| v.frames_out.load(Ordering::Relaxed)),
            keyframes_asked: self.video.as_ref().map_or(0, |v| v.keyframes_asked.load(Ordering::Relaxed)),
        }
    }

    /// Stop sending and close the peer connection.
    pub async fn close(&self) {
        self.sending.store(false, Ordering::SeqCst);
        self.pc.lock().await.close();
    }
}

/// The video sender, once the section is negotiated and the transport exists.
async fn video_sender(pc: &Mutex<PeerConnection>) -> Option<VideoSender> {
    pc.lock().await.video_sender().ok()
}

/// Send the host's frames while the leg is sending (§14.1), keeping each packet for retransmission; frames that come
/// while it is held are dropped, not queued.
async fn send_video(v: Arc<Video>, pc: Arc<Mutex<PeerConnection>>, sending: Arc<AtomicBool>) {
    let Some(feed) = v.cfg.source.clone() else { return };
    let mut feed = feed.0.lock().await;
    let mut sender: Option<VideoSender> = None;
    // Impl: the first sequence number is taken from the clock, as RFC 3550 §5.1 asks it not be predictable
    let mut seq = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos() as u16);
    while let Some(frame) = feed.recv().await {
        if !sending.load(Ordering::SeqCst) {
            continue;
        }
        if sender.is_none() {
            sender = video_sender(&pc).await;
        }
        let Some(s) = sender.as_ref() else {
            tracing::trace!("video frame dropped: no video section negotiated");
            continue;
        };
        let coded = CodedFrame { timestamp: frame.timestamp, keyframe: frame.keyframe, data: frame.data };
        let payloads = match packetize(s.codec(), &coded, VIDEO_MAX_PAYLOAD) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("video frame not packetized: {e}");
                continue;
            }
        };
        let last = payloads.len().saturating_sub(1);
        for (i, payload) in payloads.into_iter().enumerate() {
            let header = RtpHeader {
                version_flags: 0x80,
                marker_payload_type: ((i == last) as u8) << 7 | (s.payload_type() & 0x7f),
                sequence_number: seq,
                timestamp: coded.timestamp,
                ssrc: s.ssrc(),
            };
            let packet = RtpPacket { header, csrc_list: vec![], extension: None, payload, padding_len: 0 }.to_bytes().freeze();
            v.rtx.lock().unwrap_or_else(|e| e.into_inner()).push(seq, packet.clone());
            if let Err(e) = s.send_packet(packet).await {
                tracing::trace!("video packet dropped: {e}");
            }
            seq = seq.wrapping_add(1);
        }
        v.frames_out.fetch_add(1, Ordering::Relaxed);
    }
}

/// What arrives on the video section: frames assembled for the host, losses NACKed, a keyframe asked for when one
/// cannot be repaired; and the far end's feedback on what this side sends.
struct Inbound {
    v: Arc<Video>,
    pc: Arc<Mutex<PeerConnection>>,
    sender: Option<VideoSender>,
    assembler: Option<FrameAssembler>,
    gate: KeyframeRequestGate,
    /// Sequence numbers already NACKed, so each is asked for once.
    nacked: std::collections::BTreeSet<u16>,
    first: bool,
}

impl Inbound {
    fn new(v: Arc<Video>, pc: Arc<Mutex<PeerConnection>>) -> Inbound {
        Inbound { v, pc, sender: None, assembler: None, gate: KeyframeRequestGate::new(KEYFRAME_INTERVAL),
                  nacked: Default::default(), first: true }
    }

    async fn sender(&mut self) -> Option<&VideoSender> {
        if self.sender.is_none() {
            self.sender = video_sender(&self.pc).await;
        }
        self.sender.as_ref()
    }

    async fn rtcp(&mut self, packet: RtcpPacket) {
        if let Some(s) = self.sender().await {
            if let Err(e) = s.send_rtcp(&[packet]).await {
                tracing::trace!("video feedback not sent: {e}");
            }
        }
    }

    async fn packet(&mut self, pkt: RtpPacket) {
        let media_ssrc = pkt.header.ssrc;
        if self.assembler.is_none() {
            let codec = self.pc.lock().await.negotiated_video().map(|n| n.codec);
            let Some(codec) = codec else { return };
            self.assembler = Some(FrameAssembler::new(codec));
        }
        let Some(assembler) = self.assembler.as_mut() else { return };
        let mut ask = false;
        for ev in assembler.push(pkt) {
            match ev {
                AssemblerEvent::Frame(f) => {
                    if self.first {
                        self.first = false;
                        tracing::debug!("first video frame (keyframe: {})", f.keyframe);
                    }
                    self.v.frames_in.fetch_add(1, Ordering::Relaxed);
                    if let Some(sink) = &self.v.cfg.sink {
                        let _ = sink.send(VideoFrame { data: f.data, keyframe: f.keyframe, timestamp: f.timestamp });
                    }
                }
                AssemblerEvent::Lost { .. } | AssemblerEvent::Invalid { .. } => ask = true,
            }
        }
        // what is still missing; of it, what has not been asked for yet
        let still = assembler.missing();
        self.nacked.retain(|s| still.contains(s));
        let missing: Vec<u16> = still.into_iter().filter(|s| !self.nacked.contains(s)).collect();
        let needs_keyframe = ask || assembler.needs_keyframe();
        if !missing.is_empty() {
            self.nacked.extend(missing.iter().copied());
            let own = self.sender().await.map_or(0, VideoSender::ssrc);
            self.rtcp(RtcpPacket::TransportFeedback(RtpFeedback::nack(own, media_ssrc, &missing))).await;
        }
        if needs_keyframe && self.gate.allow() {
            self.v.keyframes_asked.fetch_add(1, Ordering::Relaxed);
            let own = self.sender().await.map_or(0, VideoSender::ssrc);
            self.rtcp(RtcpPacket::PayloadFeedback(PsFeedback::pli(own, media_ssrc))).await;
        }
    }

    /// The far end's feedback on this side's video: retransmit what it NACKs, pass on keyframe and bitrate requests.
    async fn feedback(&mut self, packets: &[RtcpPacket]) {
        let Some(own) = self.sender().await.map(VideoSender::ssrc) else { return };
        for p in packets {
            match p {
                RtcpPacket::TransportFeedback(f) if f.media_ssrc == own => {
                    if let TransportFeedback::Nack(entries) = &f.kind {
                        let lost: Vec<u16> = entries.iter().flat_map(|e| e.lost()).collect();
                        let resend: Vec<Bytes> = {
                            let rtx = self.v.rtx.lock().unwrap_or_else(|e| e.into_inner());
                            rtx.lookup(&lost).into_iter().map(|(_, b)| b.clone()).collect()
                        };
                        if let Some(s) = self.sender.as_ref() {
                            for b in resend {
                                let _ = s.send_packet(b).await;
                            }
                        }
                    }
                }
                RtcpPacket::PayloadFeedback(f) => {
                    let request = match &f.kind {
                        PayloadFeedback::Pli if f.media_ssrc == own => Some(VideoRequest::Keyframe),
                        PayloadFeedback::Fir(entries) if entries.iter().any(|e| e.ssrc == own) => Some(VideoRequest::Keyframe),
                        PayloadFeedback::Remb { bitrate_bps, ssrcs } if ssrcs.contains(&own) => {
                            Some(VideoRequest::Bitrate((*bitrate_bps / 1000).min(u32::MAX as u64) as u32))
                        }
                        _ => None,
                    };
                    if let (Some(r), Some(tx)) = (request, &self.v.cfg.requests) {
                        let _ = tx.send(r);
                    }
                }
                _ => {}
            }
        }
    }
}
