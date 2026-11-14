//! The phone's task: it owns the agent and the media legs, takes commands from the handles, and tells each call's
//! handle where its call is.
//!
//! Spec: §12.4 (states read from the endpoint's sessions), §12.11 (hanging up: cancel, decline or bye by state),
//! §16.3 and §12.12 (SDP and candidates for the call glue), §14.1 (sending starts when the call glue says so).

use std::collections::{HashMap, VecDeque};

use tokio::sync::{mpsc, watch};

use dsip_endpoint::{CallCommand, MediaRequest};
use dsip_session::{Emission, Role, SessionState, UiEvent};
use dsip_transport::agent::{Agent, AgentEvent};

use crate::presence::Presence;
use crate::{Call, CallState, Cmd, IncomingCall, IssuedGrant, Line, Media, Result};

/// One call the handles follow.
struct Track {
    state: watch::Sender<CallState>,
    error: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    #[cfg_attr(not(feature = "media"), allow(dead_code))] // only a native leg hears anything
    heard: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg_attr(not(feature = "media"), allow(dead_code))]
    video: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

pub(crate) struct Runner {
    agent: Agent,
    cmds: mpsc::UnboundedReceiver<Cmd>,
    line: Line,
    incoming: mpsc::UnboundedSender<IncomingCall>,
    issued: mpsc::UnboundedSender<IssuedGrant>,
    calls: HashMap<String, Track>,
    presence: Presence,
    /// Requests to our relay waiting on its answer, by id (W§4.2).
    requests: HashMap<String, tokio::sync::oneshot::Sender<Result<dsip_transport::wake::Answer>>>,
    /// Wakes the task once a second while presence needs the clock.
    ticker: Option<tokio::task::JoinHandle<()>>,
    #[cfg(feature = "media")]
    legs: legs::Legs,
}

impl Drop for Runner {
    fn drop(&mut self) {
        if let Some(t) = self.ticker.take() {
            t.abort();
        }
    }
}

/// What one batch of events said about calls, read before their states are.
#[derive(Default)]
struct Batch {
    /// The `reason` of messages, by session.
    reasons: HashMap<String, String>,
    /// The `answered_by` of answers, by session.
    answered_by: HashMap<String, String>,
    /// Sessions whose callee rings.
    ringing: Vec<String>,
    /// The engine's `Ended` and `Answered` emissions, which name no session.
    ended: VecDeque<String>,
    answered: VecDeque<String>,
}

impl Runner {
    pub(crate) fn new(agent: Agent, cmds: mpsc::UnboundedReceiver<Cmd>, line: Line, incoming: mpsc::UnboundedSender<IncomingCall>,
                      issued: mpsc::UnboundedSender<IssuedGrant>, presence: watch::Sender<std::collections::BTreeMap<String, crate::Presence>>, (media, turn): (Media, Option<dsip_transport::turn::TurnClient>)) -> Runner {
        #[cfg(not(feature = "media"))]
        let _ = (media, turn);
        Runner {
            #[cfg(feature = "media")]
            legs: legs::Legs::new(media, turn, line.wake.clone()),
            agent,
            cmds,
            line,
            incoming,
            issued,
            calls: HashMap::new(),
            presence: Presence::new(presence),
            requests: HashMap::new(),
            ticker: None,
        }
    }

    pub(crate) async fn run(mut self) -> Result<()> {
        loop {
            let events = match self.agent.next().await {
                Ok(events) => events,
                Err(e) => {
                    self.end_all("transport.closed");
                    return Err(e.into());
                }
            };
            self.observe(events).await?;
            loop {
                match self.cmds.try_recv() {
                    Ok(Cmd::Close) | Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.agent.save_contacts()?;
                        self.agent.close().await;
                        self.end_all("transport.closed");
                        return Ok(());
                    }
                    Ok(cmd) => self.command(cmd).await?,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                }
            }
            if self.presence.active() {
                self.presence.tick(&mut self.agent).await;
                if self.ticker.is_none() {
                    let wake = self.line.wake.clone();
                    self.ticker = Some(tokio::spawn(async move {
                        let mut every = tokio::time::interval(std::time::Duration::from_secs(1));
                        loop {
                            every.tick().await;
                            wake.notify_one();
                        }
                    }));
                }
            }
            #[cfg(feature = "media")]
            let heard = self.legs.events(&mut self.agent).await.unwrap_or_else(|e| {
                // a candidate that could not be handed on: the call's ICE goes with the others, or its timers end it
                tracing::warn!("media events: {e}");
                vec![]
            });
            for session in heard {
                if let Some(t) = self.calls.get(&session) {
                    t.heard.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }

    async fn command(&mut self, cmd: Cmd) -> Result<()> {
        match cmd {
            Cmd::Place { to, invite, via, reply } => {
                let placed = match &via {
                    Some(relay) => self.agent.place_via(&to, invite, relay).await,
                    None => self.agent.place(&to, invite).await,
                };
                let placed = placed.map(|session| {
                    let via = self.agent.route_of(&session).map(String::from);
                    let mut call = self.track(session, CallState::Calling);
                    call.via = via;
                    call
                });
                let _ = reply.send(placed.map_err(Into::into));
            }
            Cmd::Call(c) => {
                if let Err(e) = self.agent.call(c).await {
                    tracing::warn!("call command: {e}");
                }
            }
            Cmd::HangUp(session) => self.hang_up(session).await,
            Cmd::SetPresence(state) => self.presence.set(&mut self.agent, state).await,
            Cmd::Watch { target, via } => self.presence.watch(&mut self.agent, target, via),
            Cmd::Unwatch(target) => self.presence.unwatch(&mut self.agent, &target),
            Cmd::Grant { request, reply } => {
                let r = request;
                let granted = self.agent.grant_request(&r.introduction, &r.requester, r.scope, r.valid_until, None).await;
                let _ = reply.send(granted.map_err(Into::into));
            }
            Cmd::HoldGrant { grant, reply } => {
                let _ = reply.send(self.agent.hold_grant(&grant).await.map_err(Into::into));
            }
            Cmd::HoldKeyAgreement(credential) => {
                if !self.agent.hold_key_agreement(&credential) {
                    tracing::debug!("a hint's key agreement delegation did not verify");
                }
            }
            Cmd::Revoke { identity, reply } => {
                let now = dsip_transport::now_s();
                let ids: Vec<String> = self.agent.endpoint().contacts.grants_issued.iter()
                    .filter(|(_, g)| g.identity == identity && g.valid_until > now)
                    .map(|(id, _)| id.clone())
                    .collect();
                let mut n = 0;
                for id in ids {
                    match self.agent.revoke_grant(&id).await {
                        Ok(true) => n += 1,
                        Ok(false) => {}
                        Err(e) => {
                            let _ = reply.send(Err(e.into()));
                            return Ok(());
                        }
                    }
                }
                let _ = reply.send(self.agent.save_contacts().map(|_| n).map_err(Into::into));
            }
            Cmd::Wake { ask, reply } => {
                let (device, relay, now) = (self.agent.device_did().to_string(), self.agent.relay().did.clone(), dsip_transport::now_s());
                let payload = match ask {
                    crate::WakeAsk::Register { registration, seal_key, kinds } => {
                        let kinds: Option<Vec<&str>> = kinds.as_ref().map(|k| k.iter().map(String::as_str).collect());
                        dsip_wake::register_message(&device, &relay, &registration, seal_key.as_ref(), kinds.as_deref(), now)
                    }
                    crate::WakeAsk::Remove => dsip_wake::remove_message(&device, &relay, now),
                };
                // the requests the relay never answered are let go with the next
                self.requests.retain(|_, r| !r.is_closed());
                match self.agent.request(payload, 30).await {
                    Ok(id) => {
                        self.requests.insert(id, reply);
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e.into()));
                    }
                }
            }
            Cmd::Close => unreachable!("handled by run"),
        }
        Ok(())
    }

    fn track(&mut self, session: String, state: CallState) -> Call {
        let (tx, rx) = watch::channel(state);
        let (error, heard) = (std::sync::Arc::default(), std::sync::Arc::<std::sync::atomic::AtomicBool>::default());
        let video = std::sync::Arc::<std::sync::atomic::AtomicBool>::default();
        self.calls.insert(session.clone(), Track { state: tx, error: std::sync::Arc::clone(&error), heard: std::sync::Arc::clone(&heard),
                                                   video: std::sync::Arc::clone(&video) });
        Call { session, via: None, state: rx, error, heard, video, line: self.line.clone() }
    }

    async fn observe(&mut self, events: Vec<AgentEvent>) -> Result<()> {
        let mut b = Batch::default();
        for ev in events {
            match ev {
                AgentEvent::Received { payload, .. } if self.presence.received(&self.agent, &payload) => {}
                AgentEvent::Reconnected { .. } => self.presence.bound(&mut self.agent).await,
                AgentEvent::Reply { in_reply_to, frame } => {
                    if let Some(reply) = self.requests.remove(&in_reply_to) {
                        let _ = reply.send(self.agent.read_reply(&in_reply_to, &frame).map_err(Into::into));
                    }
                }
                AgentEvent::Received { message, identity, display_name, .. } => {
                    let sid = message.session_id().to_string();
                    if let Some(r) = &message.reason {
                        b.reasons.insert(sid.clone(), r.clone());
                    }
                    match message.msg_type.as_str() {
                        "answer" => {
                            if let Some(a) = &message.answered_by {
                                b.answered_by.insert(sid.clone(), a.clone());
                            }
                        }
                        "progress" if message.status.as_deref() == Some("ringing") => b.ringing.push(sid.clone()),
                        "error" => {
                            // a refused invite is answered in reply to it, and an invite's id is its session (§12.2)
                            let about = message.session.clone().or_else(|| message.in_reply_to.clone()).unwrap_or_default();
                            if let (Some(t), Some(r)) = (self.calls.get(&about), &message.reason) {
                                if let Ok(mut e) = t.error.lock() {
                                    *e = Some(r.clone());
                                }
                            }
                        }
                        "invite" if !self.calls.contains_key(&sid)
                            && self.agent.endpoint().session(&sid).is_some_and(|s| s.role == Role::Responder) =>
                        {
                            let call = self.track(sid, CallState::Ringing);
                            let _ = self.incoming.send(IncomingCall { call, from: identity, display_name });
                        }
                        _ => {}
                    }
                }
                AgentEvent::GrantIssued { to, grant } => {
                    self.agent.save_contacts()?;
                    let _ = self.issued.send(IssuedGrant { to, grant });
                }
                AgentEvent::Emission(Emission::Keys { scope, .. }) => {
                    // P§12.5: the scope's epoch rose; our record goes again under the new key
                    self.agent.save_contacts()?;
                    self.presence.rekeyed(&mut self.agent, &scope).await;
                }
                AgentEvent::Emission(Emission::Ui(UiEvent::Ended { reason })) => b.ended.push_back(reason),
                AgentEvent::Emission(Emission::Ui(UiEvent::Answered { answered_by })) => b.answered.push_back(answered_by),
                AgentEvent::Media(req) => {
                    let session = media_session(&req);
                    if let Err(e) = self.media(req).await {
                        // a call's media failing ends that call, not the phone and every call after it
                        tracing::warn!("media for {}: {e}; the call ends", session.as_deref().unwrap_or("a call"));
                        if let Some(session) = session {
                            if let Some(t) = self.calls.get(&session) {
                                if let Ok(mut err) = t.error.lock() {
                                    *err = Some(format!("media: {e}"));
                                }
                            }
                            self.hang_up(session).await;
                        }
                    }
                }
                _ => {}
            }
        }
        self.update(b);
        Ok(())
    }

    /// Tell each handle where its call is now.
    fn update(&mut self, mut b: Batch) {
        let mut over = vec![];
        for (sid, t) in &self.calls {
            let now = self.agent.endpoint().session(sid).map(|s| s.state);
            let shown = t.state.borrow().clone();
            let next = match now {
                Some(SessionState::Ended) => {
                    over.push(sid.clone());
                    let reason = b.reasons.remove(sid).or_else(|| b.ended.pop_front()).unwrap_or_else(|| "unknown".into());
                    Some(CallState::Ended { reason })
                }
                Some(SessionState::Active) if !matches!(shown, CallState::Answered { .. }) => {
                    let answered_by = b.answered_by.remove(sid).or_else(|| b.answered.pop_front()).unwrap_or_else(|| "user".into());
                    Some(CallState::Answered { answered_by })
                }
                _ if shown == CallState::Calling && b.ringing.contains(sid) => Some(CallState::Ringing),
                _ => None,
            };
            if let Some(n) = next {
                t.state.send_replace(n);
            }
        }
        for sid in over {
            self.calls.remove(&sid);
        }
    }

    /// End `session` as its state allows: hang up once answered, decline as the callee, cancel as the caller.
    async fn hang_up(&mut self, session: String) {
        let s = self.agent.endpoint().session(&session).map(|s| (s.role, s.state));
        let cmd = match s {
            Some((_, SessionState::Ended)) => return,
            Some((_, SessionState::Active)) => CallCommand::Hangup { session },
            Some((Role::Responder, _)) => CallCommand::Decline { session },
            // placed: cancel before the answer (§12.11); a call still waiting on its offer is cancelled too
            _ => CallCommand::Cancel { session },
        };
        if let Err(e) = self.agent.call(cmd).await {
            tracing::warn!("hanging up: {e}");
        }
    }

    fn end_all(&mut self, reason: &str) {
        for (_, t) in self.calls.drain() {
            t.state.send_replace(CallState::Ended { reason: reason.into() });
        }
    }

    #[cfg(feature = "media")]
    async fn media(&mut self, req: MediaRequest) -> Result<()> {
        // whether the call carries video: its leg has a video section, and the answer did not refuse it (B§2.1)
        let video = match &req {
            MediaRequest::Offer { session, .. } | MediaRequest::Answer { session, .. } => Some((session.clone(), None)),
            MediaRequest::ApplyAnswer { session, sdp } => Some((session.clone(), Some(legs::offers_video(sdp)))),
            _ => None,
        };
        self.legs.request(&mut self.agent, req).await?;
        if let Some((session, answered)) = video {
            let on = self.legs.video(&session) && answered.unwrap_or(true);
            if let Some(t) = self.calls.get(&session) {
                t.video.store(on, std::sync::atomic::Ordering::Relaxed);
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "media"))]
    async fn media(&mut self, req: MediaRequest) -> Result<()> {
        tracing::warn!("media request without the media feature: {req:?}");
        Ok(())
    }
}

#[cfg(feature = "media")]
mod legs {
    //! One native media leg per call, as the call glue asks.
    //!
    //! Spec: §16.3 (SDP in `transports[0].sdp`), §14.4 (a screening leg sends nothing; escalation adds the source),
    //! §12.12 (local candidates for signed `info`, remote ones from it), §14.1 (send only once told).

    use std::collections::HashMap;
    use std::sync::Arc;

    use tokio::sync::{mpsc, Notify};

    use dsip_endpoint::{MediaRequest, MediaResult};
    use dsip_media::{Candidate, MediaConfig, MediaEvent, MediaLeg, Source, TurnConfig};
    use dsip_transport::agent::Agent;
    use dsip_transport::turn::{TurnClient, TurnCredentials};

    use crate::{Media, Result};

    struct Leg {
        leg: MediaLeg,
        screening: bool,
        /// Whether it allocates on a TURN server.
        turn: bool,
        /// Whether it has a video section.
        video: bool,
    }

    /// Whether an SDP offer or answer carries video: an `m=video` section with a port (B§2.1; port 0 is a refused one).
    pub(super) fn offers_video(sdp: &str) -> bool {
        sdp.lines().any(|l| l.strip_prefix("m=video ").is_some_and(|rest| !rest.starts_with("0 ")))
    }

    /// The description a leg is asked for.
    enum Describe<'a> {
        Offer,
        Answer(&'a str),
    }

    async fn ask(leg: &MediaLeg, what: &Describe<'_>) -> dsip_media::Result<String> {
        match what {
            Describe::Offer => leg.create_offer().await,
            Describe::Answer(offer) => leg.accept_offer(offer).await,
        }
    }

    pub(super) struct Legs {
        cfg: Option<MediaConfig>,
        turn: Option<TurnClient>,
        /// The last credentials `turn` gave.
        turned: Option<TurnCredentials>,
        /// Until when (unix seconds) calls go without TURN: its server did not answer in time.
        turn_down_until: i64,
        legs: HashMap<String, Leg>,
        tx: mpsc::UnboundedSender<(String, MediaEvent)>,
        rx: mpsc::UnboundedReceiver<(String, MediaEvent)>,
        wake: Arc<Notify>,
    }

    impl Legs {
        /// Seconds before TURN credentials expire that new ones are asked for: a call outlasts the ones it started with
        /// only by the allocation the TURN server already granted.
        const TURN_MARGIN_S: i64 = 300;
        /// How long a leg with TURN may take to describe itself: the media stack allocates on the TURN server before
        /// its offer or answer is ready, and an unreachable one would hold the call for its whole retransmission
        /// schedule.
        const TURN_WAIT: std::time::Duration = std::time::Duration::from_secs(4);
        /// Seconds calls go without TURN after its server did not answer.
        const TURN_DOWN_S: i64 = 300;

        pub(super) fn new(media: Media, turn: Option<TurnClient>, wake: Arc<Notify>) -> Legs {
            let cfg = match media {
                Media::Native(c) => Some(c),
                Media::None => None,
            };
            let (tx, rx) = mpsc::unbounded_channel();
            Legs { cfg, turn, turned: None, turn_down_until: 0, legs: HashMap::new(), tx, rx, wake }
        }

        /// Whether `session`'s leg has a video section.
        pub(super) fn video(&self, session: &str) -> bool {
            self.legs.get(session).is_some_and(|l| l.video)
        }

        /// Make a leg for `session`, its events forwarded to the phone's task: with a video section only for a call
        /// whose offer carries video (B§2.1: the SDP matches the descriptors), and only if the phone has video.
        async fn open(&mut self, session: &str, screening: bool, video: bool) -> Result<()> {
            let Some(cfg) = &self.cfg else { return Ok(()) };
            let mut cfg = cfg.clone();
            if screening {
                cfg.source = Source::None;
            }
            if !video || screening {
                cfg.video = None;
            }
            let video = cfg.video.is_some();
            cfg.turn.extend(self.turn_servers().await);
            let turn = !cfg.turn.is_empty();
            let mut leg = MediaLeg::new(cfg).await?;
            let mut events = leg.take_events();
            let (tx, wake, sid) = (self.tx.clone(), self.wake.clone(), session.to_string());
            tokio::spawn(async move {
                while let Some(e) = events.recv().await {
                    if tx.send((sid.clone(), e)).is_err() {
                        break;
                    }
                    wake.notify_one();
                }
            });
            if let Some(old) = self.legs.insert(session.into(), Leg { leg, screening, turn, video }) {
                old.leg.close().await;
            }
            Ok(())
        }

        /// The TURN servers for a new leg: the credentials kept, or new ones once they are near expiry; none when there
        /// is no [`TurnClient`], it fails, or the TURN server lately did not answer.
        async fn turn_servers(&mut self) -> Vec<TurnConfig> {
            let Some(client) = &self.turn else { return vec![] };
            let now = dsip_transport::now_s();
            if now < self.turn_down_until {
                return vec![];
            }
            if !self.turned.as_ref().is_some_and(|c| c.fresh(now, Self::TURN_MARGIN_S)) {
                match client.fetch(now).await {
                    Ok(c) => self.turned = Some(c),
                    Err(e) => tracing::warn!("no TURN for this call, direct paths only: {e}"),
                }
            }
            let fresh = self.turned.as_ref().filter(|c| c.fresh(now, 0));
            fresh.into_iter().flat_map(|c| &c.servers)
                .map(|s| TurnConfig { uri: s.uri.clone(), username: s.username.clone(), password: s.credential.clone() })
                .collect()
        }

        /// The offer or answer of `session`'s leg. A leg with TURN that is not ready within [`Self::TURN_WAIT`], or
        /// fails, is made again without it, and calls go without TURN for [`Self::TURN_DOWN_S`].
        async fn describe(&mut self, session: &str, what: Describe<'_>) -> Result<String> {
            let Some(l) = self.legs.get(session) else { return Err(crate::Error::Missing("media leg")) };
            let (turn, screening, video) = (l.turn, l.screening, l.video);
            if !turn {
                return Ok(ask(&l.leg, &what).await?);
            }
            let why = match tokio::time::timeout(Self::TURN_WAIT, ask(&l.leg, &what)).await {
                Ok(Ok(sdp)) => return Ok(sdp),
                Ok(Err(e)) => e.to_string(),
                Err(_) => format!("no answer within {:?}", Self::TURN_WAIT),
            };
            tracing::warn!("TURN: {why}; calls go without it for {} s", Self::TURN_DOWN_S);
            self.turn_down_until = dsip_transport::now_s() + Self::TURN_DOWN_S;
            self.open(session, screening, video).await?;
            let l = self.legs.get(session).expect("opened");
            Ok(ask(&l.leg, &what).await?)
        }

        pub(super) async fn request(&mut self, agent: &mut Agent, req: MediaRequest) -> Result<()> {
            match req {
                MediaRequest::Offer { session, add_source, video } => {
                    if !self.legs.contains_key(&session) {
                        self.open(&session, false, video).await?;
                    }
                    let source = self.cfg.as_ref().map(|c| c.source.clone());
                    let Some(l) = self.legs.get_mut(&session) else { return Ok(()) };
                    if let (true, Some(source)) = (add_source, source) {
                        l.leg.add_source(source).await?; // §14.4 step 3
                        l.screening = false;
                    }
                    let sdp = self.describe(&session, Describe::Offer).await?;
                    agent.media(MediaResult::Offer { session, sdp }).await?;
                }
                MediaRequest::Answer { session, offer, screening } => {
                    if self.legs.get(&session).is_none_or(|l| screening && !l.screening) {
                        self.open(&session, screening, offers_video(&offer)).await?;
                    }
                    if !self.legs.contains_key(&session) {
                        return Ok(());
                    }
                    let sdp = self.describe(&session, Describe::Answer(&offer)).await?;
                    agent.media(MediaResult::Answer { session, sdp }).await?;
                }
                MediaRequest::ApplyAnswer { session, sdp } => {
                    if let Some(l) = self.legs.get(&session) {
                        l.leg.set_answer(&sdp).await?;
                    }
                }
                MediaRequest::RemoteCandidates { session, candidates } => {
                    if let Some(l) = self.legs.get(&session) {
                        for c in candidates.into_iter().filter_map(|c| serde_json::from_value::<Candidate>(c).ok()) {
                            l.leg.add_remote_candidate(&c).await.ok();
                        }
                    }
                }
                MediaRequest::StartSending { session } => {
                    if let Some(l) = self.legs.get(&session) {
                        l.leg.start_sending();
                    }
                }
                MediaRequest::HoldSending { session } => {
                    if let Some(l) = self.legs.get(&session) {
                        l.leg.hold_sending();
                    }
                }
                MediaRequest::Close { session } => {
                    if let Some(l) = self.legs.remove(&session) {
                        l.leg.close().await;
                    }
                }
                other => tracing::warn!("unhandled media request {other:?}"),
            }
            Ok(())
        }

        /// Hand the call glue the local candidates the legs gathered; the sessions whose first packet arrived.
        pub(super) async fn events(&mut self, agent: &mut Agent) -> Result<Vec<String>> {
            let mut heard = vec![];
            while let Ok((session, e)) = self.rx.try_recv() {
                match e {
                    MediaEvent::Candidate(c) if self.legs.contains_key(&session) => {
                        let candidate = c.map(|c| serde_json::to_value(c).unwrap_or_default());
                        agent.media(MediaResult::Candidate { session, candidate }).await?;
                    }
                    MediaEvent::FirstPacket => heard.push(session),
                    _ => {}
                }
            }
            Ok(heard)
        }
    }
}

/// The session a media request is for.
fn media_session(req: &MediaRequest) -> Option<String> {
    match req {
        MediaRequest::Offer { session, .. }
        | MediaRequest::Answer { session, .. }
        | MediaRequest::ApplyAnswer { session, .. }
        | MediaRequest::RemoteCandidates { session, .. }
        | MediaRequest::StartSending { session }
        | MediaRequest::HoldSending { session }
        | MediaRequest::Close { session } => Some(session.clone()),
        _ => None,
    }
}
