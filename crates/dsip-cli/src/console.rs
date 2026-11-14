//! Interactive `call` / `answer` console over the transport agent.
//!
//! Spec: §25.1 "CLI test tool"; §26 example flow. Every transition is printed
//! with the spec section it implements.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

use dsip_core::ulid::Ulid;
use dsip_media::{Candidate, MediaConfig, MediaEvent, MediaLeg, Source};
use dsip_transport::{AnswerPolicy, CallCommand, CallEvent, CallsConfig, Invite, MediaRequest, MediaResult};
use dsip_session::{Emission, LocalEvent, MediaCommand, TimerAction, UiEvent};
use dsip_transport::agent::{Agent, AgentConfig, AgentEvent};
use dsip_transport::identity::Identity;
use dsip_transport::resolver::build_resolver;
use dsip_transport::tls;

/// Shared connection options.
pub struct ConsoleOpts {
    /// Identity directory.
    pub identity: PathBuf,
    /// Relay URL (None = default or hint-discovered).
    pub relay: Option<String>,
    /// CA/self-signed cert to trust.
    pub ca: Option<PathBuf>,
    /// Offer video.
    pub video: bool,
    /// Scripted commands (`;`-separated, `sleep N` allowed) instead of stdin.
    pub script: Option<String>,
    /// DID document files for the resolver.
    pub did_documents: Vec<PathBuf>,
    /// Timer overrides.
    pub t_establish: Option<i64>,
    /// T-Ring.
    pub t_ring: Option<i64>,
    /// T-Ring-Local.
    pub t_ring_local: Option<i64>,
    /// DHT bootstrap peers.
    pub dht: Vec<libp2p::Multiaddr>,
    /// Publish our reachability hint after binding.
    pub publish_hint: bool,
    /// Hint TTL.
    pub hint_ttl: i64,
    /// Pkarr relays (DHT Hints Profile §9).
    pub pkarr_relays: Vec<String>,
    /// Publish our `_dsip` records to the Pkarr relays and/or the Mainline DHT.
    pub publish_pkarr: bool,
    /// Publish this device's own zone (§9.1) rather than the identity's.
    pub pkarr_device: bool,
    /// Use the Mainline DHT directly for Pkarr.
    pub mainline: bool,
    /// A number binding to present as a `tel` claim on our invites (Number Attestation N§4).
    pub tn_binding: Option<PathBuf>,
    /// The binding policy file for verifying callers' bound numbers (N§3.4).
    pub tn_policy: Option<PathBuf>,
    /// The address book for the identity-change warning (N§5).
    pub contacts: Option<PathBuf>,
    /// dsip-nodes to look numbers up on, for `--to tel:+…` (N§6 route 1).
    pub tn_nodes: Vec<String>,
    /// Number authorities to ask at `/.well-known/dsip/tn/<tn>` (N§6 route 2).
    pub tn_authorities: Vec<String>,
    /// A gateway's DID for numbers no binding resolves (N§4.1).
    pub gateway: Option<String>,
    /// The tel URI to put on the invite as `destination` when calling through a gateway (set by `run`).
    pub destination: Option<String>,
    /// Declare this side recorded by this recorder identity (Recording Profile C§3).
    pub recorded_by: Option<String>,
    /// Declare nothing until `record on`.
    pub record_later: bool,
    /// A second device of our identity that opens the recorder leg (C§6).
    pub record_device: Option<PathBuf>,
    /// Taps on the call's media for the recorder leg: (inbound, outbound).
    pub fork_taps: Option<(tokio::sync::mpsc::UnboundedSender<dsip_media::Bytes>, tokio::sync::mpsc::UnboundedSender<dsip_media::Bytes>)>,
    /// The declared recording purpose.
    pub record_purpose: String,
    /// `ask`, `always` or `never` when the other side declares recording (C§4).
    pub recording_accept: String,
    /// Mainline bootstrap nodes (empty: the public ones).
    pub mainline_bootstrap: Vec<String>,
    /// §10.4: seal outbound session bodies (`sealed-body/1.0`).
    pub seal: bool,
    /// P§12: seal this identity's presence (keys in grants, rotation when a share ends).
    pub seal_presence: bool,
    /// Media source spec (`none` disables media).
    pub media: String,
    /// Record inbound audio here.
    pub record: Option<PathBuf>,
    /// STUN servers.
    pub stun: Vec<String>,
    /// TURN servers for relay candidates.
    pub turn: Vec<dsip_media::TurnConfig>,
    /// Force ICE to use only relay candidates (symmetric-NAT path).
    pub relay_only: bool,
    /// Media backend: `webrtc-rs` | `forge`.
    pub media_backend: String,
}

/// What a callee needs to check callers' bound numbers (Number Attestation N§3.4–N§5).
struct TnContext {
    policy: dsip_number::Policy,
    /// DID documents as JSON, for `alsoKnownAs` (the typed resolver keeps only keys and services).
    documents: std::collections::HashMap<String, serde_json::Value>,
    contacts: Vec<dsip_number::Contact>,
}

impl TnContext {
    fn load(opts: &ConsoleOpts) -> Result<TnContext> {
        let read = |p: &PathBuf| -> Result<serde_json::Value> { Ok(serde_json::from_slice(&std::fs::read(p)?)?) };
        let mut policy = dsip_number::Policy::default();
        if let Some(p) = &opts.tn_policy {
            policy = dsip_number::Policy::from_json(&read(p)?);
            println!("numbers   {} STI-CA anchor(s), {} x5u chain(s) — callers' bound numbers are verified   N§3.4",
                     policy.trust_anchors.len(), policy.certificates.len());
        }
        let mut documents = std::collections::HashMap::new();
        for f in &opts.did_documents {
            let v = read(f)?;
            let docs: Vec<serde_json::Value> = if v.get("id").is_some() { vec![v] } else { v.as_object().into_iter().flatten().map(|(_, d)| d.clone()).collect() };
            for d in docs {
                if let Some(id) = d["id"].as_str() {
                    documents.insert(id.to_string(), d.clone());
                }
            }
        }
        let contacts = match &opts.contacts {
            Some(p) => read(p)?.as_array().into_iter().flatten().map(|c| dsip_number::Contact {
                name: c["name"].as_str().unwrap_or_default().into(),
                did: c["did"].as_str().unwrap_or_default().into(),
                numbers: c["numbers"].as_array().into_iter().flatten().filter_map(|n| n.as_str().map(String::from)).collect(),
            }).collect(),
            None => vec![],
        };
        Ok(TnContext { policy, documents, contacts })
    }

    /// Number → DID (N§6 routes 1 and 2, N§7): every binding the nodes and the authorities return, pooled, verified in
    /// full against its own DID's document, the newest winning. Both are hints tiers: a node or an authority can
    /// withhold, never forge (§8.1); an authority's name stays on the answer it served (`served_by`).
    async fn lookup(&self, tn: &str, nodes: &[String], authorities: &[String]) -> Result<String> {
        anyhow::ensure!(!nodes.is_empty() || !authorities.is_empty(),
                        "calling a number needs --tn-node (a dsip-node serving /dsip/v1/tn/) or --tn-authority (a carrier's .well-known/dsip/tn/)");
        let http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build()?;
        let mut bindings: Vec<serde_json::Value> = vec![];
        for n in nodes {
            let url = format!("{}/dsip/v1/tn/{}", n.trim_end_matches('/'), tn.replace('+', "%2B"));
            match http.get(&url).send().await.and_then(|r| r.error_for_status()) {
                Ok(r) => {
                    let v: serde_json::Value = r.json().await.unwrap_or_default();
                    let got = v["bindings"].as_array().cloned().unwrap_or_default();
                    println!("number    {tn}: {} binding(s) from {n}   N§6 (hints tier)", got.len());
                    bindings.extend(got.into_iter().filter(|b| !bindings.contains(b)).collect::<Vec<_>>());
                }
                Err(e) => println!("number    {tn}: {n} did not answer ({e})"),
            }
        }
        // route 2: each authority's answer as the README's `authority` check sees it: {authority, status, body}
        let mut answers: Vec<serde_json::Value> = vec![];
        for a in authorities {
            let url = format!("{}/.well-known/dsip/tn/{}", a.trim_end_matches('/'), tn.replace('+', "%2B"));
            let (status, body) = match http.get(&url).send().await {
                Ok(r) => {
                    let st = r.status().as_u16();
                    (serde_json::json!(st), r.json::<serde_json::Value>().await.unwrap_or(serde_json::Value::Null))
                }
                Err(e) => {
                    println!("number    {tn}: authority {a} did not answer ({e})");
                    (serde_json::Value::Null, serde_json::Value::Null)
                }
            };
            if status == serde_json::json!(200) {
                println!("number    {tn}: {} binding(s) from authority {a}   N§6 (route 2)", body["bindings"].as_array().map_or(0, Vec::len));
            } else if !status.is_null() {
                println!("number    {tn}: authority {a} answered {status}");
            }
            answers.push(serde_json::json!({"authority": a, "status": status, "body": body}));
        }
        bindings.extend(dsip_number::pool_answers(&answers).into_iter().filter(|b| !bindings.contains(b)).collect::<Vec<_>>());
        let docs: serde_json::Map<String, serde_json::Value> = self.documents.clone().into_iter().collect();
        let Some(s) = dsip_number::select(tn, &bindings, &docs, dsip_transport::now_s(), &self.policy) else {
            anyhow::bail!("{tn}: no binding verified (none found, or none whose DID claims the number back)   N§3.4");
        };
        let by = s.attested_by.as_deref().map(|b| format!(" by {b}")).unwrap_or_default();
        let served = dsip_number::served_by(&answers, &s.binding);
        let served = if served.is_empty() { String::new() } else { format!("; served by {}", served.join(", ")) };
        println!("number    {tn} → {}  (attested{by}; the DID claims it back{served})   N§3.4, N§6", s.did);
        if !s.others.is_empty() {
            println!("  ⚠  {tn} is also bound to {} — the newer binding is used   N§7", s.others.join(", "));
        }
        Ok(s.did)
    }
}

/// The media leg of the current session. The call glue (`dsip_endpoint::calls`) says what to do with it.
struct Media {
    leg: MediaLeg,
    /// Made for screening: recvonly, no local source (§14.4).
    screening: bool,
}

async fn next_media(m: &mut Option<Media>) -> MediaEvent {
    match m {
        Some(media) => media.leg.next_event().await.unwrap_or_else(|| MediaEvent::State("closed".into())),
        None => std::future::pending().await,
    }
}

fn media_enabled(opts: &ConsoleOpts) -> bool {
    opts.media != "none" || opts.record.is_some()
}

/// Place a call to `to`: attach a held grant and our number claim; the call glue asks for the media offer.
///
/// Spec: §12.4 (invite), §19.4 (held grant), §16.3 (SDP in the transport descriptor).
async fn start_call(agent: &mut Agent, opts: &ConsoleOpts, to: &str) -> Result<String> {
    let mut invite = Invite::default();
    if let Some(g) = agent.endpoint().contacts.held_from(to, dsip_transport::now_s()) {
        println!("contacts  holding grant …{} from {} — attached to the invite   §19.4", sid8(&g), short(to));
    }
    // Number Attestation N§4: our bound number rides as a `tel` claim; the callee verifies it against our identity
    if let Some(path) = &opts.tn_binding {
        let binding = std::fs::read_to_string(path)?.trim().to_string();
        let b = dsip_number::parse_binding(&binding).map_err(|r| anyhow::anyhow!("--tn-binding: {}", r.0))?;
        let number = b.payload["tn"].as_str().unwrap_or_default().to_string();
        println!("claims    tel {number} with a binding (x5u {}) → invite identity.claims   N§4", b.header["x5u"].as_str().unwrap_or_default());
        invite.claims = vec![serde_json::json!({"type": "tel", "number": number, "binding": binding})];
    }
    if let Some(d) = &opts.destination {
        invite.patch.destination = Some(d.as_str().into()); // N§4.1
    }
    Ok(agent.place(to, invite).await?)
}

async fn new_leg(opts: &ConsoleOpts, screening: bool) -> Result<Media> {
    let source = if screening { Source::None } else { Source::parse(&opts.media)? };
    let backend = dsip_media::Backend::parse(&opts.media_backend)?;
    let leg = MediaLeg::new(MediaConfig { source, record: opts.record.clone(), stun: opts.stun.clone(), turn: opts.turn.clone(), backend,
                                         send_only: false, tap_in: opts.fork_taps.as_ref().map(|t| t.0.clone()),
                                         tap_out: opts.fork_taps.as_ref().map(|t| t.1.clone()), video: None }).await?;
    Ok(Media { leg, screening })
}

/// Do the media work the call glue asks for, and hand back the SDP it waits on.
///
/// Spec: §16.3 (SDP in `transports[0].sdp`), §14.4 (a screening leg sends nothing; escalation adds the source),
/// §12.12 (remote candidates from signed `info`), §14.1 (send only once told).
async fn handle_media(agent: &mut Agent, media: &mut Option<Media>, opts: &ConsoleOpts, req: MediaRequest) -> Result<()> {
    match req {
        MediaRequest::Offer { session, add_source, .. } => {
            let fresh = media.is_none();
            if fresh {
                *media = Some(new_leg(opts, false).await?);
            }
            let Some(m) = media.as_mut() else { return Ok(()) };
            if add_source {
                // §14.4 step 3: the screening leg was recvonly; add our source and re-offer sendrecv
                m.leg.add_source(Source::parse(&opts.media)?).await?;
            }
            let sdp = relay_only_sdp(m.leg.create_offer().await?, opts.relay_only);
            if fresh {
                println!("media     WebRTC offer created ({} bytes SDP, backend {}) → rides in invite.transports[0].sdp   §16.3 (spec-gap 16)", sdp.len(), m.leg.backend().name());
            }
            agent.media(MediaResult::Offer { session, sdp }).await?;
        }
        MediaRequest::Answer { session, offer, screening } => {
            if media.as_ref().is_none_or(|m| screening && !m.screening) {
                if let Some(old) = media.take() {
                    old.leg.close().await;
                }
                *media = Some(new_leg(opts, screening).await?);
            }
            let Some(m) = media.as_mut() else { return Ok(()) };
            let sdp = relay_only_sdp(m.leg.accept_offer(&offer).await?, opts.relay_only);
            println!("  media   WebRTC answer created ({} bytes SDP, backend {}) → answer.transports[0].sdp", sdp.len(), m.leg.backend().name());
            agent.media(MediaResult::Answer { session, sdp }).await?;
        }
        MediaRequest::ApplyAnswer { sdp, .. } => {
            if let Some(m) = media.as_ref() {
                m.leg.set_answer(&sdp).await?;
                println!("  media   remote WebRTC answer applied");
            }
        }
        MediaRequest::RemoteCandidates { candidates, .. } => {
            if let Some(m) = media.as_ref() {
                let cands: Vec<Candidate> = candidates.into_iter().filter_map(|c| serde_json::from_value(c).ok()).collect();
                for c in &cands {
                    if opts.relay_only && !c.candidate.contains("typ relay") { continue; }
                    m.leg.add_remote_candidate(c).await.ok();
                }
                println!("  media   {} remote ICE candidate(s) applied from signed info   §12.12", cands.len());
            }
        }
        MediaRequest::StartSending { .. } => {
            if let Some(m) = media.as_ref() {
                m.leg.start_sending(); // §14.1: only now, after the signed answer (C§4: and accepted)
            }
        }
        MediaRequest::HoldSending { .. } => {
            if let Some(m) = media.as_ref() {
                m.leg.hold_sending();
            }
        }
        MediaRequest::Close { .. } => {
            if let Some(m) = media.take() {
                let st = m.leg.stats();
                println!("  media   closed — received {} RTP packets / {} bytes, sent {} Opus frames", st.packets_in, st.bytes_in, st.frames_out);
                m.leg.close().await;
            }
        }
        other => println!("  media   unhandled request {other:?}"),
    }
    Ok(())
}

const DEFAULT_RELAY: &str = "wss://127.0.0.1:8443/dsip";

/// Role-specific behavior.
pub enum Mode {
    /// Place a call to this DID.
    Call {
        /// Callee identity or device DID.
        to: String,
    },
    /// Wait for calls; `auto` = accept | screen | decline | silent | none.
    Answer {
        /// Automatic policy.
        auto: String,
        /// §19.4 policy.
        first_contact: bool,
        /// Pre-authorized contact tokens.
        tokens: Vec<String>,
    },
    /// Send an introduction and wait for the outcome.
    Introduce {
        /// Recipient identity.
        to: String,
        /// Purpose.
        purpose: String,
        /// Contact token.
        token: Option<String>,
        /// Seconds to wait before reporting silence.
        wait: u64,
    },
}

fn short(did: &str) -> String {
    if did.len() > 24 { format!("{}…{}", &did[..16], &did[did.len() - 6..]) } else { did.to_string() }
}

/// One line for a Recording Profile consent emission (C§4).
fn print_recording(e: &serde_json::Value) {
    if let Some(r) = e.get("render") {
        let purpose = r["purpose"].as_str().map(|p| format!("  purpose {p}")).unwrap_or_default();
        match r["state"].as_str() {
            Some("off") => println!("  ⏺  recording ended (recorder {})   C§4", short(r["recorder"].as_str().unwrap_or(""))),
            Some(s) => println!("  ⏺  RECORDED: the other side declares recording {s} by {}{purpose}   C§3", short(r["recorder"].as_str().unwrap_or(""))),
            None => {}
        }
    } else if let Some(a) = e.get("accepted") {
        println!("  ⏺  recording by {} accepted ({})   C§4", short(a["recorder"].as_str().unwrap_or("")), a["by"].as_str().unwrap_or(""));
    } else if let Some(s) = e.get("send") {
        println!("  ⏺  declining to be recorded → {} {}   C§4", s["type"].as_str().unwrap_or(""), dsip_recording::DECLINED);
    } else if e.get("blocked").is_some() {
        println!("  ⏺  not answering before the recording is accepted   C§4");
    }
}

fn sid8(s: &str) -> &str {
    &s[s.len().saturating_sub(8)..]
}

fn print_emission(e: &Emission) {
    match e {
        Emission::Timer { action, name } => match action {
            TimerAction::Start { seconds } => println!("  ⏱  {name} start ({seconds} s)                      §12.9"),
            _ => println!("  ⏱  {name} {}                             §12.9", action.as_str()),
        },
        Emission::Media(m) => println!("  ♫  media {m}                                   §14.1"),
        Emission::Ui(ui) => {
            let f = ui.fields().iter().map(|(k, v)| format!("{k}={}", v.as_str().map(String::from).unwrap_or_else(|| v.to_string()))).collect::<Vec<_>>().join(" ");
            let sec = match ui {
                UiEvent::Progress { .. } => "§12.10",
                UiEvent::Answered { .. } => "§14.3",
                UiEvent::Offered | UiEvent::Ended { .. } => "§12.4",
                UiEvent::UpdateOffered | UiEvent::UpdateRejected { .. } => "§12.8",
                UiEvent::MissedCall => "§12.11",
                UiEvent::GlareRetry => "§12.6",
                UiEvent::IntroductionReceived { .. } | UiEvent::Granted { .. } | UiEvent::IntroductionRejected { .. } => "§19.4",
                UiEvent::Error { .. } => "§15",
                _ => "§12",
            };
            let extra = if matches!(ui, UiEvent::Answered { answered_by } if answered_by == "screening") { "  ← SCREENING MODE (§14.4)" } else { "" };
            println!("  ◆  {} {f}{extra}                         {sec}", ui.kind());
        }
        Emission::Info { about } => println!("  ℹ  info for {about}                          §12.12"),
        Emission::Refused(r) => println!("  ✗  refused: {r}"),
        Emission::Keys { action, scope, epoch } => println!("  🔑 presence key {scope} {} to epoch {epoch}        P§12.5", action.as_str()),
        Emission::Revoke(ids) => {
            let ids: Vec<String> = ids.iter().map(|g| format!("…{}", sid8(g))).collect();
            println!("  ⊘  grant-revocation to our relay: {}        P§7, P§12.5", ids.join(", "))
        }
        Emission::Drop(r) => println!("  ·  dropped: {r}"),
        Emission::Send(_) | Emission::Deliver { .. } | Emission::Forward { .. } | Emission::Queue { .. } | Emission::Dequeue { .. } => {}
    }
}

fn print_state(agent: &Agent, sid: &str) {
    if let Some(s) = agent.endpoint().session(sid) {
        let sub = if s.renegotiating() { " [RENEGOTIATING]" } else { "" };
        println!("  ── session …{} {:?} {:?}{sub}", sid8(sid), s.role, s.state);
    }
}

/// Run the console.
/// With `--relay-only`, drop every non-relay `a=candidate` line from an SDP so
/// only the TURN-relayed path can pair — forces Run 3's relay↔relay on a host
/// where the direct (host) path would otherwise win. Relay candidates still
/// trickle via signed `info` (§12.12).
fn relay_only_sdp(sdp: String, on: bool) -> String {
    if !on {
        return sdp;
    }
    let mut out: String = sdp
        .lines()
        .filter(|l| !l.starts_with("a=candidate") || l.contains("typ relay"))
        .collect::<Vec<_>>()
        .join("\r\n");
    out.push_str("\r\n");
    out
}

/// A running recorder leg (C§6): stop, pause, and its task.
type ForkHandle = (tokio::sync::oneshot::Sender<()>, tokio::sync::watch::Sender<bool>, tokio::task::JoinHandle<Result<()>>);

pub async fn run(opts: ConsoleOpts, mode: Mode) -> Result<()> {
    let mut opts = opts;
    // C§6: taps on the call's media feed the recorder leg, started once the media flows
    let mut fork_feeds: Option<(dsip_media::Feed, dsip_media::Feed)> = None;
    if opts.recorded_by.is_some() && opts.record_device.is_some() {
        let (tin, peer_feed) = dsip_media::Feed::channel();
        let (tout, self_feed) = dsip_media::Feed::channel();
        opts.fork_taps = Some((tin, tout));
        fork_feeds = Some((self_feed, peer_feed));
    }
    let mut fork: Option<ForkHandle> = None;
    let mut peer_identity: Option<String> = None;
    let id = Identity::load(&opts.identity)?;
    let my_identity = id.meta.identity.clone();
    println!("identity  {}  (\"{}\")", id.meta.identity, id.meta.display_name);
    println!("device    {}", id.meta.device);
    let tn = TnContext::load(&opts)?;
    // Number Attestation N§6–N§7: `--to tel:+…` is looked up on the hints tier, verified, and becomes a DID
    let mode = match mode {
        Mode::Call { to } if to.starts_with("tel:") => {
            let number = to[4..].to_string();
            let looked = if opts.tn_nodes.is_empty() && opts.tn_authorities.is_empty() && opts.gateway.is_some() {
                Err(anyhow::anyhow!("no --tn-node or --tn-authority to look it up on"))
            } else {
                tn.lookup(&number, &opts.tn_nodes, &opts.tn_authorities).await
            };
            match (looked, &opts.gateway) {
                (Ok(did), _) => Mode::Call { to: did },
                // N§4.1: a number no binding resolves is a PSTN number; the gateway named by `to` dials it
                (Err(e), Some(gw)) => {
                    println!("number    {number}: {e}\nnumber    {number} → PSTN through gateway {}, as the invite's destination   N§4.1", short(gw));
                    opts.destination = Some(format!("tel:{number}"));
                    Mode::Call { to: gw.clone() }
                }
                (Err(e), None) => return Err(e),
            }
        }
        m => m,
    };
    // a document given with --did-document is used as it is; only a callee without one is fetched
    let fetch: Vec<String> = match &mode {
        Mode::Call { to } | Mode::Introduce { to, .. } if !tn.documents.contains_key(to) => vec![to.clone()],
        _ => vec![],
    };
    let resolver = build_resolver(&opts.did_documents, &fetch).await?;

    // Discovery (§8.1): DID document first; did:key has none, so the hints tier may name the peer's relay.
    let dht = if opts.dht.is_empty() { None } else { Some(crate::hints::join(&opts.dht).await?) };
    let mut relay_url = opts.relay.clone();
    if let (Mode::Call { to }, Some(h)) = (&mode, &dht) {
        if relay_url.is_none() {
            if let Some(hint) = crate::hints::discover(h, to).await? {
                relay_url = hint.endpoints.first().map(|e| e.uri.clone());
            }
        }
    }
    // …or the Pkarr carrier of the hints tier (v0.9, DHT Hints Profile §9)
    let pkarr = crate::pkarr_cli::Pkarr::new(&opts.pkarr_relays, opts.mainline, &opts.mainline_bootstrap).await?;
    if let (Mode::Call { to }, None, Some(p)) = (&mode, &relay_url, &pkarr) {
        if let Some(hint) = p.discover(to).await? {
            relay_url = hint.endpoints.first().and_then(|e| e["uri"].as_str()).map(String::from);
        }
    }
    let relay_url = relay_url.unwrap_or_else(|| DEFAULT_RELAY.to_string());
    // Recording Profile C§4: our consent to the other side's declaration; the answer policy for incoming calls
    let accept_policy = match opts.recording_accept.as_str() {
        "always" => dsip_recording::AcceptPolicy::Always,
        "never" => dsip_recording::AcceptPolicy::Never,
        _ => dsip_recording::AcceptPolicy::Ask,
    };
    let auto = match &mode {
        Mode::Answer { auto, .. } => auto.clone(),
        _ => String::new(),
    };
    let answer = match auto.as_str() {
        "accept" => AnswerPolicy::Accept,
        "screen" => AnswerPolicy::Screen,
        "decline" => AnswerPolicy::Decline,
        "silent" => AnswerPolicy::Silent,
        _ => AnswerPolicy::Ring,
    };
    let cfg = AgentConfig {
        relay_url: relay_url.clone(),
        tls: tls::client_config(opts.ca.as_deref())?,
        video: opts.video,
        t_establish: opts.t_establish,
        t_ring: opts.t_ring,
        t_ring_local: opts.t_ring_local,
        first_contact_required: matches!(&mode, Mode::Answer { first_contact: true, .. }),
        seal: opts.seal,
        presence: opts.seal_presence.then(|| dsip_transport::PresenceSealing { sealed: ["main".to_string()].into(), t_rotate: None }),
        peer_dialer: None,
        dialer: None,
        did_resolver: None,
        calls: Some(CallsConfig { media: media_enabled(&opts), answer, recording: accept_policy, one_call: false }),
    };
    let mut agent = Agent::connect(id, cfg, resolver).await?;
    if let Mode::Answer { first_contact, tokens, .. } = &mode {
        if *first_contact {
            println!("policy    first contact required — ungranted invites are rejected policy.first-contact-required   §19.4");
        }
        for t in tokens {
            agent.local(LocalEvent::IssueToken { token: t.clone(), grant_id: Ulid::generate().to_string() }).await?;
            println!("policy    contact token pre-authorized (auto-grant once)   §19.4");
        }
        let held = agent.endpoint().contacts.grants_issued.len();
        if held > 0 {
            println!("contacts  {held} grant(s) issued previously (contacts.json)");
        }
    }
    println!("relay     {}  capabilities {}   §13.2 hello bound", short(&agent.relay().did), agent.relay().capabilities);
    if opts.publish_hint {
        let Some(h) = &dht else { anyhow::bail!("--publish-hint needs --dht <bootstrap>") };
        crate::hints::publish(h, &Identity::load(&opts.identity)?, &relay_url, opts.hint_ttl).await?;
    }
    let mut republish = tokio::time::interval(Duration::from_secs((opts.hint_ttl.max(3) as u64) * 2 / 3));
    republish.tick().await;
    if opts.publish_pkarr {
        let Some(p) = &pkarr else { anyhow::bail!("--publish-pkarr needs --pkarr-relay <https://…> or --mainline") };
        // a hint is best-effort (§8.1): a failed publish is reported and tried again at the next re-sign
        if let Err(e) = if opts.pkarr_device {
                p.publish_device(&Identity::load(&opts.identity)?, &relay_url, opts.hint_ttl as u32).await
            } else {
                p.publish(&Identity::load(&opts.identity)?, &relay_url, opts.hint_ttl as u32).await
            } {
            println!("hint       pkarr publish failed, retrying at the next re-sign: {e}");
        }
    }

    // command source: script or stdin
    let (ctx, mut crx) = mpsc::unbounded_channel::<String>();
    if let Some(script) = opts.script.clone() {
        tokio::spawn(async move {
            for cmd in script.split(';').map(str::trim).filter(|c| !c.is_empty()) {
                if let Some(n) = cmd.strip_prefix("sleep ") {
                    tokio::time::sleep(Duration::from_secs_f64(n.trim().parse().unwrap_or(1.0))).await;
                } else if ctx.send(cmd.to_string()).is_err() {
                    break;
                }
            }
        });
    } else {
        tokio::spawn(async move {
            let mut lines = BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                if ctx.send(l).is_err() {
                    break;
                }
            }
        });
    }

    let mut current: Option<String> = None;
    // Recording Profile C§3: our declaration
    if let (Some(r), false) = (&opts.recorded_by, opts.record_later) {
        agent.set_recording(Some(serde_json::json!({"state": "on", "recorder": r, "purpose": opts.record_purpose})));
        println!("recording this side is recorded by {}  (purpose {}) — declared on every invite/answer/update   C§3", short(r), opts.record_purpose);
    }
    let mut intro_deadline: Option<tokio::time::Instant> = None;
    let mut cmds_closed = false;
    let mut media: Option<Media> = None;
    match &mode {
        Mode::Call { to } => {
            current = Some(start_call(&mut agent, &opts, to).await?);
            println!("(commands: cancel | update | answer-update | reject-update | info | hangup | quit)");
        }
        Mode::Introduce { to, purpose, token, wait } => {
            agent.local(LocalEvent::Introduce { id: Ulid::generate().to_string(), to: to.clone(), purpose: Some(purpose.clone()),
                                                 contact_token: token.clone() }).await?;
            println!("   purpose \"{purpose}\" — no session, no media; may not ring; silence is a valid outcome   §19.4");
            intro_deadline = Some(tokio::time::Instant::now() + Duration::from_secs(*wait));
        }
        Mode::Answer { .. } => {
            println!("waiting… (commands: accept | screen | decline | escalate | answer-update | reject-update | info | hangup | requests | grant [id] [audience=NAME] [for=SECONDS] | reject-intro [id] | revoke <grant> | regrant [grant] [audience=NAME] [for=SECONDS] [calls-only] | quit)");
        }
    }

    loop {
        tokio::select! {
            events = agent.next() => {
                for ev in events? {
                    match ev {
                        // the grant's Sent follows and is printed
                        AgentEvent::GrantIssued { .. } => {}
                        // the console sends no request whose answer comes back as a reply
                        AgentEvent::Reply { .. } => {}
                        AgentEvent::Sent { msg_type, session, to } => {
                            println!("→ {msg_type:<8} to {}  session …{}", short(&to), sid8(&session));
                            print_state(&agent, &session);
                        }
                        AgentEvent::Received { message, identity, display_name, payload } => {
                            let name = display_name.map(|n| format!(" \"{n}\"")).unwrap_or_default();
                            let extra = match message.msg_type.as_str() {
                                "progress" => format!(" status={}", message.status.clone().unwrap_or_default()),
                                "answer" => format!(" answered_by={}", message.answered_by.clone().unwrap_or_default()),
                                "reject" | "cancel" | "bye" | "error" => format!(" reason={}", message.reason.clone().unwrap_or_default()),
                                _ => String::new(),
                            };
                            println!("← {:<8} from {}{name} (device {}){extra}   ✓ signature, delegation, replay, schema",
                                     message.msg_type, short(&identity), short(&message.from));
                            // §18.1: show the verification basis — never a badge. A gateway's PSTN
                            // caller (a `tel` claim) shows the caller headline and the attestation.
                            let claims: Vec<serde_json::Value> = payload.pointer("/identity/claims").and_then(|c| c.as_array()).cloned().unwrap_or_default();
                            if matches!(message.msg_type.as_str(), "invite" | "introduction") {
                                if let Some(line) = claims.iter().find_map(dsip_core::trust::tel_caller_line) {
                                    println!("  ☎  {line}   (via gateway {})", short(&identity));
                                }
                                // Number Attestation N§4–N§5: the caller's own bound numbers, verified against the
                                // identity that signed this invite; a number now on another identity is said out loud
                                for c in &claims {
                                    let doc = tn.documents.get(&identity).cloned().unwrap_or(serde_json::Value::Null);
                                    match dsip_number::check_claim(c, &identity, &doc, dsip_transport::now_s(), &tn.policy) {
                                        dsip_number::ClaimOutcome::Ignored => {}
                                        dsip_number::ClaimOutcome::Attested { line, issued, attested_by, .. } => {
                                            println!("  ☎  {line}   N§4");
                                            let tel = c["number"].as_str().unwrap_or_default();
                                            if let Some(w) = dsip_number::identity_change(&tn.contacts, tel, &identity, attested_by.as_deref(), issued) {
                                                println!("  ⚠  {w}   N§5");
                                            }
                                        }
                                        dsip_number::ClaimOutcome::Dropped { reason, line } => {
                                            let shown = line.unwrap_or_else(|| "a number".into());
                                            println!("  ☎  {shown} — number binding refused: {reason}   N§4, §18.2");
                                        }
                                    }
                                }
                                println!("  🔎 trust: {}   §18.1", dsip_core::trust::verification_basis(&identity, &claims));
                            }
                            // §6.3 / G§7: a gateway.downgraded error names what crossing the PSTN lost.
                            if message.msg_type == "error" && message.reason.as_deref() == Some("gateway.downgraded") {
                                let losses: Vec<&str> = payload.pointer("/detail/losses").and_then(|l| l.as_array())
                                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
                                println!("  ⚠  {}", dsip_core::trust::downgrade_summary(&losses));
                            }
                            let sid = message.session_id().to_string();
                            if matches!(message.msg_type.as_str(), "invite" | "answer") {
                                peer_identity = Some(identity.clone());
                            }
                            print_state(&agent, &sid);
                            // the call glue has already rung, answered or declined it by policy
                            if message.msg_type == "invite" && agent.endpoint().session(&sid).is_some_and(|s| s.role == dsip_session::Role::Responder) {
                                current = Some(sid.clone());
                            }
                            if message.msg_type == "introduction" {
                                println!("  ✉  REQUEST (not a call): \"{}\" — type grant / reject-intro, or ignore (silence is a valid outcome)",
                                         message.purpose.clone().unwrap_or_default());
                            }
                        }
                        AgentEvent::Emission(e) => {
                            print_emission(&e);
                            // C§6: the recorder leg, from our second device, once media flows
                            if let (Emission::Media(MediaCommand::Start), Some(_)) = (&e, media.as_ref()) {
                                if let (Some((self_feed, peer_feed)), Some(dev), Some(rec), Some(of), Some(peer)) =
                                    (fork_feeds.take(), opts.record_device.clone(), opts.recorded_by.clone(), current.clone(), peer_identity.clone()) {
                                    let me = my_identity.clone();
                                    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
                                    let (pause_tx, pause_rx) = tokio::sync::watch::channel(false);
                                    let f = crate::record_fork::Fork { device: dev, relay: relay_url.clone(), ca: opts.ca.clone(), recorder: rec,
                                        of, me: me.clone(), peer: peer.clone(), backend: opts.media_backend.clone(),
                                        feeds: vec![(me, self_feed), (peer, peer_feed)] };
                                    fork = Some((stop_tx, pause_tx, tokio::spawn(crate::record_fork::run(f, stop_rx, pause_rx))));
                                }
                            }
                            if let Emission::Ui(ui) = &e {
                                if matches!(ui, UiEvent::Granted { .. } | UiEvent::IntroductionRejected { .. }) && intro_deadline.is_some() {
                                    agent.save_contacts()?;
                                    agent.close().await;
                                    println!("bye.");
                                    return Ok(());
                                }
                            }
                        }
                        AgentEvent::Media(req) => handle_media(&mut agent, &mut media, &opts, req).await?,
                        AgentEvent::Call(ev) => match ev {
                            CallEvent::Ringing { .. } => println!("  ☎  RINGING — type accept / screen / decline"),
                            // a device that is bound but never responds: no progress, answer or reject. The relay
                            // expires the leg with the invite and tells the caller (§12.7 rule 6, spec-gap 132)
                            CallEvent::Silent { .. } => println!("  ☎  invite received — staying silent (--auto silent)"),
                            CallEvent::NoOffer { .. } => println!("  media   caller offered no SDP; answering without media"),
                            CallEvent::UpdateOffered { .. } => println!("  ☎  update offered — type answer-update / reject-update"),
                            CallEvent::Recording { emission, .. } => print_recording(&emission),
                            CallEvent::RecordingHeld { .. } => {
                                println!("  ⏺  holding our media until you accept — type accept-recording / decline-recording   C§4")
                            }
                            CallEvent::SendingResumed { .. } => println!("  media   sending resumed"),
                            CallEvent::NothingToAccept { .. } => println!("nothing to accept"),
                            CallEvent::ResentInClear { new, by, .. } => {
                                println!("seal      sealed body refused by {} — placing the call again in clear   §10.4, §11.3", short(&by));
                                current = Some(new);
                            }
                            other => println!("  ☎  {other:?}"),
                        },
                        AgentEvent::Rejected(code, detail) => println!("✗ inbound rejected: {code} {detail}"),
                        AgentEvent::Reconnected { attempts } => println!("↻ reconnected after {attempts} attempt(s)           §13.2"),
                    }
                }
                agent.save_contacts()?;
            }
            ev = next_media(&mut media) => {
                match ev {
                    MediaEvent::Candidate(c) => {
                        // --relay-only: signal only relay candidates (keep the
                        // end-of-candidates `None` marker).
                        let keep = !opts.relay_only
                            || c.as_ref().map(|cd| cd.candidate.contains("typ relay")).unwrap_or(true);
                        if let (true, Some(session)) = (keep, current.clone()) {
                            let candidate = c.map(serde_json::to_value).transpose()?;
                            agent.media(MediaResult::Candidate { session, candidate }).await?;
                        }
                    }
                    MediaEvent::State(st) => {
                        println!("  media   webrtc {st}   (DTLS-SRTP)");
                        if st == "closed" { media = None; }
                    }
                    MediaEvent::FirstPacket => println!("  media   ♫ first inbound RTP packet (SRTP decrypted) — media is flowing"),
                }
            }
            _ = async { tokio::time::sleep_until(intro_deadline.unwrap()).await }, if intro_deadline.is_some() => {
                println!("·  no response — silence is the default outcome and means nothing (§19.4)");
                break;
            }
            _ = republish.tick(), if opts.publish_hint || opts.publish_pkarr => {
                // Re-sign before expiry (§8.3: expired records are invalid); the node re-announces in between.
                if let Some(h) = &dht {
                    crate::hints::publish(h, &Identity::load(&opts.identity)?, &relay_url, opts.hint_ttl).await?;
                }
                if let (true, Some(p)) = (opts.publish_pkarr, &pkarr) {
                    // DHT Hints Profile §9: the identity key re-signs before expires_at (re-announcing never extends it);
                    // a failed publish is reported and tried again at the next re-sign, never fatal to the session
                    if let Err(e) = if opts.pkarr_device {
                p.publish_device(&Identity::load(&opts.identity)?, &relay_url, opts.hint_ttl as u32).await
            } else {
                p.publish(&Identity::load(&opts.identity)?, &relay_url, opts.hint_ttl as u32).await
            } {
                        println!("hint       pkarr publish failed, retrying at the next re-sign: {e}");
                    }
                }
            }
            cmd = crx.recv(), if !cmds_closed => {
                let Some(cmd) = cmd else {
                    // Script finished (without `quit`) → done. Stdin EOF with no script → keep serving.
                    if opts.script.is_some() { break }
                    cmds_closed = true;
                    continue;
                };
                let mut parts = cmd.splitn(2, ' ');
                let verb = parts.next().unwrap_or("").to_string();
                let arg = parts.next().map(str::trim).filter(|a| !a.is_empty()).map(String::from);
                let verb = verb.as_str();
                // Recording Profile C§3–C§4 commands
                let cmd = match verb {
                    "accept-recording" | "decline-recording" => {
                        let Some(session) = current.clone() else { println!("nothing to accept"); continue };
                        agent.call(if verb == "accept-recording" { CallCommand::AcceptRecording { session } }
                                   else { CallCommand::DeclineRecording { session } }).await?;
                        continue;
                    }
                    "record" => {
                        let Some(r) = &opts.recorded_by else { println!("no recorder configured (--recorded-by <did>)"); continue };
                        let state = match arg.as_deref() { Some("pause") => "paused", Some("off") => "off", _ => "on" };
                        let decl = if state == "off" { serde_json::json!({"state": "off"}) }
                                   else { serde_json::json!({"state": state, "recorder": r, "purpose": opts.record_purpose}) };
                        println!("recording declared {state} — sent with an update   C§3");
                        if let Some((_, pause, _)) = &fork {
                            let _ = pause.send(state != "on");
                        }
                        agent.set_recording(Some(decl));
                        "update".to_string()
                    }
                    _ => cmd.clone(),
                };
                let latest_request = || agent.requests().last().map(|(id, _)| id.clone());
                let year = dsip_transport::now_s() + 31_536_000;
                match verb {
                    "requests" => {
                        for (id, identity) in agent.requests() { println!("  ✉  …{}  from {}", sid8(&id), short(&identity)); }
                        continue;
                    }
                    "grant" => {
                        // `grant [id] [audience=NAME] [for=SECONDS]`: P§6 a presence audience, P§7 a time-boxed share
                        let words: Vec<&str> = arg.as_deref().unwrap_or("").split_whitespace().collect();
                        let audience = words.iter().find_map(|w| w.strip_prefix("audience=")).map(|a| if opts.seal_presence { agent.audience_tag(a) } else { a.to_string() }); // P§12.1: a sealed audience goes as its tag
                        let until = match words.iter().find_map(|w| w.strip_prefix("for=")).map(str::parse::<i64>) {
                            Some(Ok(secs)) if secs > 0 => dsip_transport::now_s() + secs,
                            Some(_) => { println!("for= wants a number of seconds"); continue; }
                            None => year,
                        };
                        let id = words.iter().find(|w| !w.contains('=')).map(|w| w.to_string());
                        if let Some(intro) = id.or_else(latest_request) {
                            agent.local(LocalEvent::Grant { introduction: intro, id: Ulid::generate().to_string(), scope: vec!["dsip.invite".into(), "dsip.subscribe".into()], valid_until: until, presence_audience: audience }).await?;
                        } else { println!("no pending request"); }
                        agent.save_contacts()?;
                        continue;
                    }
                    "regrant" => {
                        // `regrant [grant] [audience=NAME] [for=SECONDS] [calls-only]`: a grant that follows a grant we
                        // issued (§19.4, spec-gap 150) — another audience or length, or calls without presence (P§7)
                        let words: Vec<&str> = arg.as_deref().unwrap_or("").split_whitespace().collect();
                        let audience = words.iter().find_map(|w| w.strip_prefix("audience=")).map(|a| if opts.seal_presence { agent.audience_tag(a) } else { a.to_string() }); // P§12.1: a sealed audience goes as its tag
                        let until = match words.iter().find_map(|w| w.strip_prefix("for=")).map(str::parse::<i64>) {
                            Some(Ok(secs)) if secs > 0 => dsip_transport::now_s() + secs,
                            Some(_) => { println!("for= wants a number of seconds"); continue; }
                            None => year,
                        };
                        let scope: Vec<String> = if words.contains(&"calls-only") { vec!["dsip.invite".into()] } else { vec!["dsip.invite".into(), "dsip.subscribe".into()] };
                        let old = words.iter().find(|w| !w.contains('=') && **w != "calls-only").map(|w| w.to_string())
                            .or_else(|| agent.endpoint().contacts.grants_issued.keys().last().cloned());
                        let Some(old) = old else { println!("no grant issued"); continue; };
                        let id = Ulid::generate().to_string();
                        if agent.regrant(&old, id.clone(), scope, until, audience).await? {
                            println!("→ grant-revocation  …{}  to our relay; → grant  …{} follows it   §19.4", sid8(&old), sid8(&id));
                        } else { println!("no live grant {old} issued, or an audience that is not a token"); }
                        agent.save_contacts()?;
                        continue;
                    }
                    "reject-intro" => {
                        if let Some(intro) = arg.clone().or_else(latest_request) {
                            agent.local(LocalEvent::RejectIntroduction { introduction: intro, reason: Some("user.declined".into()) }).await?;
                        } else { println!("no pending request"); }
                        continue;
                    }
                    "revoke" => {
                        // no argument: every grant we issued
                        let grants: Vec<String> = match arg.clone() {
                            Some(g) => vec![g],
                            None => agent.endpoint().contacts.grants_issued.keys().cloned().collect(),
                        };
                        for g in grants {
                            // §19.4, P§7: the revocation goes to our relay too, which ends what the grant admitted there
                            if agent.revoke_grant(&g).await? { println!("→ grant-revocation  …{}  to our relay   P§7", sid8(&g)); } else { println!("no grant {g} issued"); }
                        }
                        agent.save_contacts()?;
                        continue;
                    }
                    "token" => {
                        if let Some(t) = arg.clone() { agent.local(LocalEvent::IssueToken { token: t, grant_id: Ulid::generate().to_string() }).await?; }
                        continue;
                    }
                    "quit" => break,
                    _ => {}
                }
                let Some(sid) = current.clone() else {
                    if cmd == "quit" { break }
                    println!("no session yet");
                    continue;
                };
                let session = sid;
                let call = match cmd.as_str() {
                    "cancel" => CallCommand::Cancel { session },
                    "hangup" => CallCommand::Hangup { session },
                    "accept" => CallCommand::Accept { session },
                    "screen" => CallCommand::Screen { session },
                    "decline" => CallCommand::Decline { session },
                    "update" => CallCommand::Update { session },
                    "escalate" => CallCommand::Escalate { session },
                    "answer-update" => CallCommand::AnswerUpdate { session },
                    "reject-update" => CallCommand::RejectUpdate { session },
                    "info" => CallCommand::Info { session },
                    "quit" => break,
                    other => { println!("unknown command {other}"); continue }
                };
                agent.call(call).await?;
            }
        }
    }
    if let Some(m) = media.take() {
        let st = m.leg.stats();
        println!("media     received {} RTP packets / {} bytes, sent {} Opus frames", st.packets_in, st.bytes_in, st.frames_out);
        m.leg.close().await;
    }
    if let Some((stop, _, task)) = fork.take() {
        let _ = stop.send(());
        if let Ok(Err(e)) = task.await {
            println!("  ⏺  recorder leg error: {e}");
        }
    }
    agent.close().await;
    if let Some(h) = dht {
        h.shutdown().await;
    }
    println!("bye.");
    Ok(())
}
