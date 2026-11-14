//! Call glue: what each host used to write around [`Core`] for an interactive call. [`Calls`] reads the SDP out of
//! offers and answers, buffers ICE candidates until they may be sent, gates media on the signed answer, answers by
//! policy, places a sealed call once more in clear when it is refused, and runs recording consent. It has no I/O: the
//! host keeps the media stack, does the media work [`Calls`] asks for ([`MediaRequest`]) and hands the results back
//! ([`MediaResult`]).
//!
//! Spec: §12.12 (candidates ride in signed `info`, ACTIVE-only), §14.1 (media starts on the signed answer), §14.4
//! (screening answers with a leg that sends nothing; escalation re-offers with the local source), §16.3 (SDP rides as
//! `transports[0].sdp`), §10.4 and §11.3 (a sealed body refused as an unknown critical extension: the sender MAY send
//! a new message in clear, once), C§3–C§4 (the other side's recording declaration is rendered, holds our media, or is
//! declined; a callee never answers before accepting it).

use std::collections::HashMap;

use dsip_session::{Emission, LocalEvent, MediaCommand, SessionState};
use serde_json::{json, Value};

use crate::core::{Command, Core, CoreEvent, Invite};
use crate::error::Result;

pub use dsip_recording::AcceptPolicy;

/// Seconds a call rings while it waits on the user.
pub const RING_TIMEOUT_S: i64 = 120;
/// Seconds a call rings before an automatic answer or decline.
pub const AUTO_RING_TIMEOUT_S: i64 = 60;

/// What happens to an incoming call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnswerPolicy {
    /// Ring and wait for [`CallCommand::Accept`], [`CallCommand::Screen`] or [`CallCommand::Decline`].
    #[default]
    Ring,
    /// Answer at once (`answered_by` `user`).
    Accept,
    /// Answer at once in screening mode (`answered_by` `screening`, §14.4).
    Screen,
    /// Ring, then decline.
    Decline,
    /// Neither ring nor answer: the relay expires the leg with the invite and tells the caller (§12.7 rule 6).
    Silent,
    /// The host decides: an incoming call is left OFFERED, with no event of its own (the host sees the core's
    /// `Received`), for the host's [`CallCommand::Alert`], [`CallCommand::AcceptAs`] or a local event. A gateway
    /// answers when its other leg does.
    Host,
}

/// How [`Calls`] behaves.
#[derive(Debug, Clone, Copy)]
pub struct CallsConfig {
    /// The host has a media stack: offers and answers carry SDP, and media requests are emitted.
    pub media: bool,
    /// What happens to an incoming call.
    pub answer: AnswerPolicy,
    /// What to do when the other side declares recording (C§4).
    pub recording: AcceptPolicy,
    /// One call at a time: an invite that arrives while another call is up is declined `user.busy`, and
    /// the user is not asked.
    ///
    /// Impl: the host's choice, not a protocol rule; §15 lists `user.busy` for a callee that takes no more calls.
    pub one_call: bool,
}

impl Default for CallsConfig {
    fn default() -> CallsConfig {
        CallsConfig { media: true, answer: AnswerPolicy::Ring, recording: AcceptPolicy::Ask, one_call: false }
    }
}

/// Media work for the host. The ones that produce SDP are answered with [`Calls::media`].
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify))]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum MediaRequest {
    /// Create an SDP offer on the session's media leg, making the leg if it has none, and answer
    /// [`MediaResult::Offer`]. With `add_source`, add the local source first (escalating from screening, §14.4).
    Offer {
        /// Session id.
        session: String,
        /// Add the local source before offering.
        add_source: bool,
        /// The offer carries video (B§3.4): the leg needs a video section, so the SDP matches the descriptors (B§2.1).
        video: bool,
    },
    /// Answer `offer` on the session's media leg, making the leg if it has none, and answer [`MediaResult::Answer`].
    /// With `screening`, on a fresh leg that sends nothing (§14.4).
    Answer {
        /// Session id.
        session: String,
        /// The remote SDP offer.
        offer: String,
        /// Screening mode.
        screening: bool,
    },
    /// Apply the remote SDP answer.
    ApplyAnswer {
        /// Session id.
        session: String,
        /// The remote SDP answer.
        sdp: String,
    },
    /// Add remote ICE candidates, as the peer's signed `info` carried them (§12.12).
    RemoteCandidates {
        /// Session id.
        session: String,
        /// The candidates (`{candidate, sdp_mid, sdp_m_line_index}`).
        #[cfg_attr(feature = "ts", tsify(type = "unknown[]"))]
        candidates: Vec<Value>,
    },
    /// Start sending media (§14.1: only after the signed answer).
    StartSending {
        /// Session id.
        session: String,
    },
    /// Stop sending media until [`MediaRequest::StartSending`] (C§4: a recording not yet accepted).
    HoldSending {
        /// Session id.
        session: String,
    },
    /// Close the session's media leg.
    Close {
        /// Session id.
        session: String,
    },
}

/// The host's answer to a [`MediaRequest`], or a media event.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify))]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum MediaResult {
    /// The SDP offer asked for by [`MediaRequest::Offer`].
    Offer {
        /// Session id.
        session: String,
        /// The SDP.
        sdp: String,
    },
    /// The SDP answer asked for by [`MediaRequest::Answer`].
    Answer {
        /// Session id.
        session: String,
        /// The SDP.
        sdp: String,
    },
    /// A local ICE candidate; `None` is the end of candidates.
    Candidate {
        /// Session id.
        session: String,
        /// The candidate (`{candidate, sdp_mid, sdp_m_line_index}`), or `None` at the end.
        #[serde(default)]
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        candidate: Option<Value>,
    },
    /// Local ICE candidates gathered together: once ACTIVE they go in one signed `info` (§12.12).
    Candidates {
        /// Session id.
        session: String,
        /// The candidates (`{candidate, sdp_mid, sdp_m_line_index}`).
        #[cfg_attr(feature = "ts", tsify(type = "unknown[]"))]
        candidates: Vec<Value>,
    },
}

/// Something about a call the application shows or acts on.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify))]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
pub enum CallEvent {
    /// An incoming call rings and waits on the user.
    Ringing {
        /// Session id.
        session: String,
    },
    /// An incoming call is left unanswered ([`AnswerPolicy::Silent`]).
    Silent {
        /// Session id.
        session: String,
    },
    /// The caller offered no SDP: the call is answered without media.
    NoOffer {
        /// Session id.
        session: String,
    },
    /// The peer sent an `update`: [`CallCommand::AnswerUpdate`] or [`CallCommand::RejectUpdate`].
    UpdateOffered {
        /// Session id.
        session: String,
        /// The update id.
        id: String,
    },
    /// A recording consent emission (C§4): `{render}`, `{accepted}`, `{send}` or `{blocked}`.
    Recording {
        /// Session id.
        session: String,
        /// The emission, as `dsip_recording::Consent` writes it.
        #[cfg_attr(feature = "ts", tsify(type = "unknown"))]
        emission: Value,
    },
    /// Our media is held until the other side's recording is accepted (C§4).
    RecordingHeld {
        /// Session id.
        session: String,
    },
    /// Our media is sent again after the recording was accepted.
    SendingResumed {
        /// Session id.
        session: String,
    },
    /// [`CallCommand::AcceptRecording`] with nothing to accept.
    NothingToAccept {
        /// Session id.
        session: String,
    },
    /// A sealed call was refused as an unknown critical extension and is placed once more in clear, as a new
    /// session (§10.4, §11.3).
    ResentInClear {
        /// The refused session.
        old: String,
        /// The new session.
        new: String,
        /// Who refused it.
        by: String,
    },
}

/// What [`Calls`] hands the host: the core's events (transmit the frames, show the rest), media work, and call events.
/// Serialized as `{"media_request": …}`, `{"call": …}`, or the core event as it stands (`{"send": …}`, …).
#[derive(Debug, serde::Serialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify))]
// tsify does not follow a variant's `untagged`
#[cfg_attr(feature = "ts", tsify(type = "{ media_request: MediaRequest } | { call: CallEvent } | CoreEvent"))]
#[allow(clippy::large_enum_variant)] // an output is built once and consumed at once
pub enum CallOut {
    /// Media work for the host.
    #[serde(rename = "media_request")]
    Media(MediaRequest),
    /// Something about a call.
    #[serde(rename = "call")]
    Call(CallEvent),
    /// An event of the core, as [`Core`] returns it.
    #[serde(untagged)]
    Core(CoreEvent),
}

/// What the application asks of a call.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[cfg_attr(feature = "ts", derive(tsify::Tsify))]
#[serde(tag = "command", rename_all = "snake_case")]
#[non_exhaustive]
pub enum CallCommand {
    /// Answer (`answered_by` `user`).
    Accept {
        /// Session id.
        session: String,
    },
    /// Answer in screening mode (§14.4).
    Screen {
        /// Session id.
        session: String,
    },
    /// Ring an incoming call left to the host ([`AnswerPolicy::Host`]): `progress ringing` goes out (§12.4).
    Alert {
        /// Session id.
        session: String,
        /// Seconds it rings before it is declined `user.no-answer` (T-Ring-Local); [`RING_TIMEOUT_S`] when `None`.
        #[serde(default)]
        #[cfg_attr(feature = "ts", tsify(optional))]
        ring_timeout: Option<i64>,
    },
    /// Answer with this `answered_by` token (§14.3; a registry value, e.g. `gateway`). A call still OFFERED is
    /// alerted first (§12.4).
    AcceptAs {
        /// Session id.
        session: String,
        /// The `answered_by` token.
        answered_by: String,
    },
    /// Decline a ringing call.
    Decline {
        /// Session id.
        session: String,
    },
    /// Cancel a call we placed.
    Cancel {
        /// Session id.
        session: String,
    },
    /// End the call.
    Hangup {
        /// Session id.
        session: String,
    },
    /// Re-offer (§12.8), e.g. after changing our recording declaration.
    Update {
        /// Session id.
        session: String,
    },
    /// Escalate from screening: add the local source and re-offer `answered_by` `user` (§14.4 step 3).
    Escalate {
        /// Session id.
        session: String,
    },
    /// Answer the peer's outstanding update.
    AnswerUpdate {
        /// Session id.
        session: String,
    },
    /// Reject the peer's outstanding update (`media.unsupported`).
    RejectUpdate {
        /// Session id.
        session: String,
    },
    /// Send an empty `info`.
    Info {
        /// Session id.
        session: String,
    },
    /// Accept the other side's recording (C§4); a call held for it is answered now.
    AcceptRecording {
        /// Session id.
        session: String,
    },
    /// Decline the other side's recording (C§4): reject a ringing call, or end an answered one.
    DeclineRecording {
        /// Session id.
        session: String,
    },
}

/// What a call waits on the host's media for.
#[derive(Debug, Clone)]
enum Awaiting {
    Place { to: String, invite: Box<Invite> },
    Accept { answered_by: String },
    Update { answered_by: Option<&'static str> },
    AnswerUpdate { in_reply_to: String },
}

/// One call's glue state.
struct Call {
    /// For a call we placed: whom, and what the invite carried (the clear resend places it again).
    placed: Option<(String, Invite)>,
    remote_offer: Option<String>,
    pending_update: Option<String>,
    candidates: Vec<Option<Value>>,
    consent: dsip_recording::Consent,
    /// An automatic answer held until the recording is accepted (C§4): `answered_by`.
    deferred: Option<String>,
    awaiting: Option<Awaiting>,
    /// Already placed once more in clear (§10.4: once).
    in_clear: bool,
    /// Media started (the engine's `start` for this session has been acted on).
    started: bool,
}

impl Call {
    fn new(callee: bool, policy: AcceptPolicy) -> Call {
        Call {
            placed: None,
            remote_offer: None,
            pending_update: None,
            candidates: vec![],
            consent: dsip_recording::Consent::new(callee, policy),
            deferred: None,
            awaiting: None,
            in_clear: false,
            started: false,
        }
    }
}

/// The call glue, beside a [`Core`]: every method takes the core it drives and returns what the host acts on, the
/// core's own events included, in order.
pub struct Calls {
    cfg: CallsConfig,
    calls: HashMap<String, Call>,
}

impl Calls {
    /// Call glue with this configuration.
    pub fn new(cfg: CallsConfig) -> Calls {
        Calls { cfg, calls: HashMap::new() }
    }

    /// The configuration.
    pub fn config(&self) -> &CallsConfig {
        &self.cfg
    }

    /// Whether the other side's recording holds our media in `session` (C§4).
    pub fn holds_media(&self, session: &str) -> bool {
        self.calls.get(session).is_some_and(|c| c.consent.hold_media())
    }

    /// The other side's recording in `session` as consent sees it (C§4): `{disclosure, pending, hold_media, …}`, the
    /// shape of `dsip_recording::Consent::snapshot`; `None` for a session that is not a call here.
    pub fn consent(&self, session: &str) -> Option<Value> {
        self.calls.get(session).map(|c| c.consent.snapshot())
    }

    /// Place a call to `to`; returns the new session id. With media, the invite waits for the host's SDP offer.
    ///
    /// Spec: §12.4 (invite), §16.3 (SDP in the transport descriptor).
    pub fn place(&mut self, core: &mut Core, to: &str, invite: Invite, now: i64) -> Result<(String, Vec<CallOut>)> {
        let session = core.new_id(now);
        let mut call = Call::new(false, self.cfg.recording);
        call.placed = Some((to.to_string(), invite.clone()));
        self.calls.insert(session.clone(), call);
        let out = self.offer_or_place(core, &session, to.to_string(), invite, now)?;
        Ok((session, out))
    }

    fn offer_or_place(&mut self, core: &mut Core, session: &str, to: String, invite: Invite, now: i64) -> Result<Vec<CallOut>> {
        if self.cfg.media {
            let video = invite.patch.video.unwrap_or(core.video());
            if let Some(c) = self.calls.get_mut(session) {
                c.awaiting = Some(Awaiting::Place { to, invite: Box::new(invite) });
            }
            return Ok(vec![CallOut::Media(MediaRequest::Offer { session: session.to_string(), add_source: false, video })]);
        }
        self.run(core, Command::PlaceCall { session: session.to_string(), to, invite }, now)
    }

    /// Pass the core's events through the glue: every event is returned as [`CallOut::Core`], followed by what the
    /// glue does about it. Hosts call this with the output of [`Core::inbound`], [`Core::tick`] and [`Core::resolved`].
    pub fn observe(&mut self, core: &mut Core, events: Vec<CoreEvent>, now: i64) -> Result<Vec<CallOut>> {
        let mut out = vec![];
        for ev in events {
            let reactions = self.react(core, &ev, now)?;
            out.push(CallOut::Core(ev));
            out.extend(reactions);
        }
        // A call that ended before its media started gets no `stop`: its glue state goes now.
        self.calls.retain(|s, c| c.started || !matches!(core.endpoint().session(s).map(|x| x.state), Some(SessionState::Ended)));
        Ok(out)
    }

    /// Run a core command and observe its events.
    fn run(&mut self, core: &mut Core, cmd: Command, now: i64) -> Result<Vec<CallOut>> {
        let events = core.command(cmd, now)?;
        self.observe(core, events, now)
    }

    fn local(&mut self, core: &mut Core, ev: LocalEvent, now: i64) -> Result<Vec<CallOut>> {
        self.run(core, Command::Engine(ev), now)
    }

    fn react(&mut self, core: &mut Core, ev: &CoreEvent, now: i64) -> Result<Vec<CallOut>> {
        match ev {
            CoreEvent::Received { message, identity, payload, .. } => {
                let sid = message.session_id().to_string();
                self.received(core, &sid, &message.msg_type, message.reason.as_deref(), &message.id, identity, payload, now)
            }
            CoreEvent::Emission(Emission::Media(m)) => self.media_command(core, *m, now),
            _ => Ok(vec![]),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn received(&mut self, core: &mut Core, sid: &str, msg_type: &str, reason: Option<&str>, id: &str, identity: &str, payload: &Value,
                now: i64) -> Result<Vec<CallOut>> {
        let mut out = vec![];
        // §10.4, §11.3: a relay or callee without sealed-body/1.0 refuses a sealed invite as an unknown critical
        // extension; the sender MAY send a new message in clear, once.
        if matches!(msg_type, "error" | "reject") && reason == Some("session.unsupported-critical-extension") && core.seal() {
            if let Some(old) = self.refused_call(core, sid) {
                return self.resend_in_clear(core, &old, identity, now);
            }
        }
        let media = self.cfg.media;
        let remote_sdp = payload.pointer("/transports/0/sdp").and_then(Value::as_str).map(String::from);
        let offered = core.endpoint().session(sid).map(|s| s.state) == Some(SessionState::Offered);
        if msg_type == "invite" && offered && self.cfg.one_call && self.busy(core, sid) {
            // §12.4: a callee rejects from ALERTING
            let mut out = self.local(core, LocalEvent::Alert { session: sid.to_string(), ring_timeout: Some(AUTO_RING_TIMEOUT_S) }, now)?;
            out.extend(self.local(core, LocalEvent::Decline { session: sid.to_string(), reason: Some("user.busy".into()) }, now)?);
            return Ok(out);
        }
        if msg_type == "invite" && offered {
            let mut call = Call::new(true, self.cfg.recording);
            call.remote_offer = remote_sdp.clone();
            self.calls.insert(sid.to_string(), call);
        }
        let Some(call) = self.calls.get_mut(sid) else { return Ok(out) };
        // C§4: the other side's recording declaration: render it, hold our media, or decline
        let mut decline: Option<String> = None;
        if matches!(msg_type, "invite" | "answer" | "update") {
            for e in call.consent.received(msg_type, payload.get("recording")) {
                if let Some(send) = e.get("send") {
                    decline = send["type"].as_str().map(String::from);
                }
                out.push(CallOut::Call(CallEvent::Recording { session: sid.to_string(), emission: e }));
            }
            if call.consent.hold_media() {
                if media {
                    out.push(CallOut::Media(MediaRequest::HoldSending { session: sid.to_string() }));
                }
                out.push(CallOut::Call(CallEvent::RecordingHeld { session: sid.to_string() }));
            }
            if decline.as_deref() == Some("bye") {
                out.extend(self.local(core, LocalEvent::Hangup { session: sid.to_string(), reason: Some(dsip_recording::DECLINED.into()) }, now)?);
            }
        }
        let call = self.calls.get_mut(sid).expect("call");
        match msg_type {
            "invite" if offered => {
                let silent = matches!(self.cfg.answer, AnswerPolicy::Silent | AnswerPolicy::Host);
                if media && !silent && remote_sdp.is_none() {
                    out.push(CallOut::Call(CallEvent::NoOffer { session: sid.to_string() }));
                }
                let policy = if decline.is_some() {
                    None // C§4: declined by standing policy — ring, then reject policy.recording-declined
                } else if call.consent.pending() && matches!(self.cfg.answer, AnswerPolicy::Accept | AnswerPolicy::Screen) {
                    // C§4: never answer before acceptance
                    call.deferred = Some(if self.cfg.answer == AnswerPolicy::Screen { "screening" } else { "user" }.to_string());
                    Some(AnswerPolicy::Ring)
                } else {
                    Some(self.cfg.answer)
                };
                let s = sid.to_string();
                match policy {
                    None => {
                        out.extend(self.local(core, LocalEvent::Alert { session: s.clone(), ring_timeout: Some(AUTO_RING_TIMEOUT_S) }, now)?);
                        out.extend(self.local(core, LocalEvent::Decline { session: s, reason: Some(dsip_recording::DECLINED.into()) }, now)?);
                    }
                    Some(AnswerPolicy::Accept | AnswerPolicy::Screen) => {
                        out.extend(self.local(core, LocalEvent::Alert { session: s.clone(), ring_timeout: Some(AUTO_RING_TIMEOUT_S) }, now)?);
                        let answered_by = if self.cfg.answer == AnswerPolicy::Screen { "screening" } else { "user" };
                        out.extend(self.answer(core, &s, answered_by, now)?);
                    }
                    Some(AnswerPolicy::Decline) => {
                        out.extend(self.local(core, LocalEvent::Alert { session: s.clone(), ring_timeout: Some(AUTO_RING_TIMEOUT_S) }, now)?);
                        out.extend(self.local(core, LocalEvent::Decline { session: s, reason: None }, now)?);
                    }
                    Some(AnswerPolicy::Silent) => out.push(CallOut::Call(CallEvent::Silent { session: s })),
                    Some(AnswerPolicy::Host) => {}
                    Some(AnswerPolicy::Ring) => {
                        out.extend(self.local(core, LocalEvent::Alert { session: s.clone(), ring_timeout: Some(RING_TIMEOUT_S) }, now)?);
                        out.push(CallOut::Call(CallEvent::Ringing { session: s }));
                    }
                }
            }
            "update" => {
                call.pending_update = Some(id.to_string());
                if media {
                    call.remote_offer = remote_sdp;
                }
                out.push(CallOut::Call(CallEvent::UpdateOffered { session: sid.to_string(), id: id.to_string() }));
            }
            "answer" => {
                if let (true, Some(sdp)) = (media, remote_sdp) {
                    out.push(CallOut::Media(MediaRequest::ApplyAnswer { session: sid.to_string(), sdp }));
                }
            }
            "info" if media && payload["about"] == "transport:webrtc" => {
                let candidates = payload["data"]["candidates"].as_array().cloned().unwrap_or_default();
                out.push(CallOut::Media(MediaRequest::RemoteCandidates { session: sid.to_string(), candidates }));
            }
            _ => {}
        }
        Ok(out)
    }

    /// Whether a call other than `sid` is up: placed and waiting on its offer, or a session not yet ended.
    fn busy(&self, core: &Core, sid: &str) -> bool {
        self.calls.keys().any(|s| s != sid && !matches!(core.endpoint().session(s).map(|x| x.state), Some(SessionState::Ended)))
    }

    /// The call a sealed-body refusal is about: the session it names, or else the one call we placed that is still
    /// unanswered (a relay's `error` may name none).
    fn refused_call(&self, core: &Core, sid: &str) -> Option<String> {
        let ours = |s: &str| self.calls.get(s).is_some_and(|c| c.placed.is_some() && !c.in_clear);
        if ours(sid) {
            return Some(sid.to_string());
        }
        let unanswered: Vec<&String> = self
            .calls
            .keys()
            .filter(|s| ours(s) && matches!(core.endpoint().session(s).map(|x| x.state), None | Some(SessionState::Inviting | SessionState::Proceeding)))
            .collect();
        match unanswered.as_slice() {
            [one] => Some((*one).clone()),
            _ => None,
        }
    }

    fn resend_in_clear(&mut self, core: &mut Core, old: &str, by: &str, now: i64) -> Result<Vec<CallOut>> {
        let Some(call) = self.calls.remove(old) else { return Ok(vec![]) };
        let Some((to, invite)) = call.placed else { return Ok(vec![]) };
        let mut out = vec![];
        if self.cfg.media {
            out.push(CallOut::Media(MediaRequest::Close { session: old.to_string() }));
        }
        core.set_seal(false);
        let new = core.new_id(now);
        let mut fresh = Call::new(false, self.cfg.recording);
        fresh.placed = Some((to.clone(), invite.clone()));
        fresh.in_clear = true;
        self.calls.insert(new.clone(), fresh);
        out.push(CallOut::Call(CallEvent::ResentInClear { old: old.to_string(), new: new.clone(), by: by.to_string() }));
        out.extend(self.offer_or_place(core, &new, to, invite, now)?);
        Ok(out)
    }

    /// The engine's media command (§14.1). It names no session: it is about the call the engine just moved, found by
    /// state — `start` for an ACTIVE call whose media has not started, `stop` for one that has ended.
    fn media_command(&mut self, core: &mut Core, m: MediaCommand, now: i64) -> Result<Vec<CallOut>> {
        if !self.cfg.media {
            return Ok(vec![]);
        }
        let mut out = vec![];
        let mut sessions: Vec<String> = self.calls.keys().cloned().collect();
        sessions.sort();
        for sid in sessions {
            let state = core.endpoint().session(&sid).map(|s| s.state);
            let Some(call) = self.calls.get_mut(&sid) else { continue };
            let hold = call.consent.hold_media();
            match m {
                MediaCommand::Start if state == Some(SessionState::Active) && !call.started => {
                    call.started = true;
                    if !hold {
                        out.push(CallOut::Media(MediaRequest::StartSending { session: sid.clone() })); // §14.1: only now
                    }
                    out.extend(self.flush(core, &sid, now)?);
                }
                MediaCommand::ApplyUpdate if state == Some(SessionState::Active) && call.started && !hold => {
                    out.push(CallOut::Media(MediaRequest::StartSending { session: sid.clone() }));
                }
                MediaCommand::Stop if call.started && matches!(state, None | Some(SessionState::Ended)) => {
                    out.push(CallOut::Media(MediaRequest::Close { session: sid.clone() }));
                    self.calls.remove(&sid);
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// Send the buffered candidates in a signed `info` once the session is ACTIVE (§12.12).
    fn flush(&mut self, core: &mut Core, sid: &str, now: i64) -> Result<Vec<CallOut>> {
        let active = core.endpoint().session(sid).map(|s| s.state) == Some(SessionState::Active);
        let Some(call) = self.calls.get_mut(sid) else { return Ok(vec![]) };
        if call.candidates.is_empty() || !active {
            return Ok(vec![]);
        }
        let batch = std::mem::take(&mut call.candidates);
        let end = batch.iter().any(Option::is_none);
        let candidates: Vec<Value> = batch.into_iter().flatten().collect();
        self.run(core, Command::Info { session: sid.to_string(), data: json!({"candidates": candidates, "end_of_candidates": end}) }, now)
    }

    /// Answer `sid`: with media and a remote offer, ask the host for the SDP answer first.
    fn answer(&mut self, core: &mut Core, sid: &str, answered_by: &str, now: i64) -> Result<Vec<CallOut>> {
        let media = self.cfg.media;
        let Some(call) = self.calls.get_mut(sid) else { return Ok(vec![]) };
        if let (true, Some(offer)) = (media, call.remote_offer.take()) {
            call.awaiting = Some(Awaiting::Accept { answered_by: answered_by.to_string() });
            let screening = answered_by == "screening";
            return Ok(vec![CallOut::Media(MediaRequest::Answer { session: sid.to_string(), offer, screening })]);
        }
        self.accept(core, sid.to_string(), answered_by.to_string(), None, now)
    }

    /// Answer now: a session still OFFERED is alerted first (§12.4: a callee answers from ALERTING).
    fn accept(&mut self, core: &mut Core, session: String, answered_by: String, sdp: Option<String>, now: i64) -> Result<Vec<CallOut>> {
        let mut out = vec![];
        if core.endpoint().session(&session).map(|s| s.state) == Some(SessionState::Offered) {
            out.extend(self.local(core, LocalEvent::Alert { session: session.clone(), ring_timeout: Some(AUTO_RING_TIMEOUT_S) }, now)?);
        }
        out.extend(self.run(core, Command::Accept { session, answered_by: Some(answered_by), sdp }, now)?);
        Ok(out)
    }

    /// Hand back the result of a [`MediaRequest`], or a local candidate.
    pub fn media(&mut self, core: &mut Core, result: MediaResult, now: i64) -> Result<Vec<CallOut>> {
        match result {
            MediaResult::Candidate { session, candidate } => {
                let Some(call) = self.calls.get_mut(&session) else { return Ok(vec![]) };
                call.candidates.push(candidate);
                self.flush(core, &session, now)
            }
            MediaResult::Candidates { session, candidates } => {
                let Some(call) = self.calls.get_mut(&session) else { return Ok(vec![]) };
                call.candidates.extend(candidates.into_iter().map(Some));
                self.flush(core, &session, now)
            }
            MediaResult::Offer { session, sdp } | MediaResult::Answer { session, sdp } => {
                let Some(awaiting) = self.calls.get_mut(&session).and_then(|c| c.awaiting.take()) else { return Ok(vec![]) };
                let sdp = Some(sdp);
                let cmd = match awaiting {
                    Awaiting::Place { to, invite } => {
                        let mut invite = *invite;
                        invite.sdp = sdp;
                        Command::PlaceCall { session, to, invite }
                    }
                    Awaiting::Accept { answered_by } => return self.accept(core, session, answered_by, sdp, now),
                    Awaiting::Update { answered_by } => {
                        let id = core.new_id(now);
                        Command::Update { session, id, answered_by: answered_by.map(String::from), sdp }
                    }
                    Awaiting::AnswerUpdate { in_reply_to } => Command::AnswerUpdate { session, in_reply_to, answered_by: Some("user".into()), sdp },
                };
                self.run(core, cmd, now)
            }
        }
    }

    /// Re-offer: with media, ask the host for the SDP offer first; escalating adds the local source (§14.4).
    fn update(&mut self, core: &mut Core, session: String, escalate: bool, now: i64) -> Result<Vec<CallOut>> {
        let answered_by = escalate.then_some("user");
        if let (true, Some(call)) = (self.cfg.media, self.calls.get_mut(&session)) {
            call.awaiting = Some(Awaiting::Update { answered_by });
            let video = core.video();
            return Ok(vec![CallOut::Media(MediaRequest::Offer { session, add_source: escalate, video })]);
        }
        let id = core.new_id(now);
        self.run(core, Command::Update { session, id, answered_by: answered_by.map(String::from), sdp: None }, now)
    }

    /// Do what the application asks of a call.
    pub fn command(&mut self, core: &mut Core, cmd: CallCommand, now: i64) -> Result<Vec<CallOut>> {
        let media = self.cfg.media;
        // A call ended before the host produced its offer never reached the engine: it is dropped here.
        if let CallCommand::Cancel { session } | CallCommand::Hangup { session } = &cmd {
            if core.endpoint().session(session).is_none() && self.calls.remove(session).is_some() {
                return Ok(if media { vec![CallOut::Media(MediaRequest::Close { session: session.clone() })] } else { vec![] });
            }
        }
        match cmd {
            CallCommand::Accept { session } => self.answer(core, &session, "user", now),
            CallCommand::AcceptAs { session, answered_by } => self.answer(core, &session, &answered_by, now),
            CallCommand::Alert { session, ring_timeout } => {
                self.local(core, LocalEvent::Alert { session, ring_timeout: Some(ring_timeout.unwrap_or(RING_TIMEOUT_S)) }, now)
            }
            CallCommand::Screen { session } => self.answer(core, &session, "screening", now),
            CallCommand::Decline { session } => self.local(core, LocalEvent::Decline { session, reason: None }, now),
            CallCommand::Cancel { session } => self.local(core, LocalEvent::Cancel { session }, now),
            CallCommand::Hangup { session } => self.local(core, LocalEvent::Hangup { session, reason: None }, now),
            CallCommand::Info { session } => self.local(core, LocalEvent::Info { session }, now),
            CallCommand::Update { session } => self.update(core, session, false, now),
            CallCommand::Escalate { session } => self.update(core, session, true, now),
            CallCommand::AnswerUpdate { session } => {
                let Some(call) = self.calls.get_mut(&session) else { return Ok(vec![]) };
                let Some(in_reply_to) = call.pending_update.take() else { return Ok(vec![]) };
                if let (true, Some(offer)) = (media, call.remote_offer.take()) {
                    call.awaiting = Some(Awaiting::AnswerUpdate { in_reply_to });
                    return Ok(vec![CallOut::Media(MediaRequest::Answer { session, offer, screening: false })]);
                }
                self.run(core, Command::AnswerUpdate { session, in_reply_to, answered_by: Some("user".into()), sdp: None }, now)
            }
            CallCommand::RejectUpdate { session } => {
                let Some(in_reply_to) = self.calls.get_mut(&session).and_then(|c| c.pending_update.take()) else { return Ok(vec![]) };
                self.local(core, LocalEvent::RejectUpdate { session, in_reply_to, reason: "media.unsupported".into() }, now)
            }
            CallCommand::AcceptRecording { session } => {
                let Some(call) = self.calls.get_mut(&session) else { return Ok(vec![]) };
                let emitted = call.consent.accept();
                if emitted.is_empty() {
                    return Ok(vec![CallOut::Call(CallEvent::NothingToAccept { session })]);
                }
                let deferred = call.deferred.take();
                let mut out: Vec<CallOut> =
                    emitted.into_iter().map(|e| CallOut::Call(CallEvent::Recording { session: session.clone(), emission: e })).collect();
                if let Some(answered_by) = deferred {
                    out.extend(self.answer(core, &session, &answered_by, now)?);
                } else if media && core.endpoint().session(&session).map(|s| s.state) == Some(SessionState::Active) {
                    out.push(CallOut::Media(MediaRequest::StartSending { session: session.clone() }));
                    out.push(CallOut::Call(CallEvent::SendingResumed { session }));
                }
                Ok(out)
            }
            CallCommand::DeclineRecording { session } => {
                let Some(call) = self.calls.get_mut(&session) else { return Ok(vec![]) };
                call.deferred = None;
                let mut out = vec![];
                for e in call.consent.decline_now() {
                    let reason = Some(dsip_recording::DECLINED.to_string());
                    let ev = if e["send"]["type"] == "reject" {
                        LocalEvent::Decline { session: session.clone(), reason }
                    } else {
                        LocalEvent::Hangup { session: session.clone(), reason }
                    };
                    out.push(CallOut::Call(CallEvent::Recording { session: session.clone(), emission: e }));
                    out.extend(self.local(core, ev, now)?);
                }
                Ok(out)
            }
        }
    }
}
