//! `dsip-testkit` — an in-process DSIP network for tests: a relay embedded in the test ([`dsip_relay::RelayServer`])
//! and agents bound to it over in-memory pipes. No sockets, no ports, no TLS, so tests run side by side, and every
//! agent is the same [`Agent`] that runs over `wss`: only its [`Dialer`] differs.
//!
//! ```no_run
//! # async fn demo() {
//! use dsip_testkit::Network;
//! use dsip_transport::CallEvent;
//!
//! let net = Network::new();
//! let mut alice = net.device("Alice").await;
//! let mut bob = net.device("Bob").await;
//! let session = alice.call(&bob.identity()).await;
//! bob.expect("ringing", |e| matches!(e, dsip_transport::agent::AgentEvent::Call(CallEvent::Ringing { .. })).then_some(())).await;
//! # let _ = session;
//! # }
//! ```
//!
//! Identities are `did:key`, with fresh keys in a directory the [`Network`] removes when dropped. Time is the wall
//! clock: a test that waits on a protocol timer waits for it, so tests shorten timers through [`AgentConfig`].
//!
//! Spec: none (infrastructure)

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod hints;
pub use hints::hints_node;
pub mod push;
pub use push::PushGateway;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dsip_core::did::StaticResolver;
use dsip_core::keys::KeyPair;
use dsip_endpoint::{AnswerPolicy, CallCommand, CallsConfig, Invite};
use dsip_relay::{RelayConfig, RelayServer};
use dsip_session::SessionState;
use dsip_transport::agent::{Agent, AgentConfig, AgentEvent, PeerDialer};
use dsip_transport::conn::{DialFuture, Dialer};
use dsip_transport::identity::Identity;

/// How long [`Device::expect`] waits before it fails the test.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// The URL agents name the first network's relay by; nothing resolves it, the [`Dialer`] supplies the stream. Every
/// further [`Network`] in the process has its own ([`Network::url`]), so a test can route a call through another
/// relay ([`Network::peers`]).
pub const RELAY_URL: &str = "wss://relay.testkit.invalid/dsip";

static NETWORKS: AtomicU64 = AtomicU64::new(0);

/// A relay in this process, and the directory its devices' identities live in.
pub struct Network {
    relay: RelayServer,
    clock: tokio::task::JoinHandle<()>,
    dir: PathBuf,
    names: AtomicU64,
    url: String,
}

impl Network {
    /// An open relay with the binary's defaults. Call within a Tokio runtime: the relay's clock runs on it.
    pub fn new() -> Network {
        Network::with(RelayConfig::default())
    }

    /// A relay configured by `cfg` (a private relay, short retention, tight rate limits).
    pub fn with(cfg: RelayConfig) -> Network {
        let relay = RelayServer::new(KeyPair::generate(), StaticResolver::default(), cfg);
        let clock = relay.spawn_clock();
        let n = NETWORKS.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("dsip-testkit-{}-{n}", std::process::id()));
        let url = if n == 0 { RELAY_URL.to_string() } else { format!("wss://relay-{n}.testkit.invalid/dsip") };
        Network { relay, clock, dir, names: AtomicU64::new(0), url }
    }

    /// A relay that wakes its devices through `gateway` (W§5).
    pub fn waking(gateway: &PushGateway) -> Network {
        Network::with(RelayConfig { wake: Some(gateway.waker()), ..RelayConfig::default() })
    }

    /// The relay.
    pub fn relay(&self) -> &RelayServer {
        &self.relay
    }

    /// The URL agents name this relay by.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// A [`PeerDialer`] that reaches each of `nets`' relays by its [`Network::url`], for calls placed through another
    /// relay ([`Agent::place_via`]).
    pub fn peers(nets: &[&Network]) -> Arc<dyn PeerDialer> {
        Arc::new(Peers(nets.iter().map(|n| (n.url.clone(), n.dialer())).collect()))
    }

    /// A [`Dialer`] to the relay: each dial is a fresh pipe and a fresh connection on the relay.
    pub fn dialer(&self) -> Arc<dyn Dialer> {
        Arc::new(Pipe { relay: self.relay.clone(), n: AtomicU64::new(0) })
    }

    /// A new identity with one device, named `name` (its display name claim).
    pub fn identity(&self, name: &str) -> Identity {
        Identity::init(&self.slot(name), name, None, None).expect("identity")
    }

    /// Another device of `of`'s identity, with its own device key and delegation (§7.4).
    pub fn device_of(&self, of: &Identity, name: &str) -> Identity {
        Identity::init(&self.slot(name), name, None, Some(&of.dir)).expect("second device")
    }

    /// An agent configuration that dials this relay, runs the call glue without media and rings incoming calls.
    pub fn config(&self) -> AgentConfig {
        AgentConfig {
            relay_url: self.url.clone(),
            tls: None,
            video: false,
            t_establish: None,
            t_ring: None,
            t_ring_local: None,
            first_contact_required: false,
            seal: false,
            did_resolver: Some(Arc::new(StaticResolver::default())),
            calls: Some(CallsConfig { media: false, answer: AnswerPolicy::Ring, ..CallsConfig::default() }),
            dialer: Some(self.dialer()),
            presence: None,
            peer_dialer: None,
        }
    }

    /// Bind `id` with `cfg`.
    pub async fn connect(&self, id: Identity, cfg: AgentConfig) -> Device {
        let name = id.meta.display_name.clone();
        let agent = Agent::connect(id, cfg, StaticResolver::default()).await.expect("bound");
        Device { name, agent, backlog: VecDeque::new() }
    }

    /// A new identity named `name`, bound with [`Network::config`].
    pub async fn device(&self, name: &str) -> Device {
        self.connect(self.identity(name), self.config()).await
    }

    fn slot(&self, name: &str) -> PathBuf {
        let n = self.names.fetch_add(1, Ordering::Relaxed);
        let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
        self.dir.join(format!("{n}-{safe}"))
    }
}

impl Default for Network {
    fn default() -> Network {
        Network::new()
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        self.clock.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Pipes to an embedded relay.
struct Pipe {
    relay: RelayServer,
    n: AtomicU64,
}

impl Dialer for Pipe {
    fn dial(&self) -> DialFuture {
        let (ours, theirs) = tokio::io::duplex(1 << 17);
        let relay = self.relay.clone();
        let peer = format!("pipe-{}", self.n.fetch_add(1, Ordering::Relaxed));
        tokio::spawn(async move {
            let _ = relay.accept(theirs, &peer).await;
        });
        Box::pin(async move { Ok(Box::new(ours) as Box<dyn dsip_transport::conn::Io>) })
    }
}

/// Several networks' relays by URL.
struct Peers(Vec<(String, Arc<dyn Dialer>)>);

impl PeerDialer for Peers {
    fn dial(&self, url: &str) -> Option<DialFuture> {
        self.0.iter().find(|(u, _)| u == url).map(|(_, d)| d.dial())
    }
}

/// A bound agent, with the events it has not yet been asked about. Derefs to its [`Agent`].
pub struct Device {
    /// The display name it was made with, for failure messages.
    pub name: String,
    /// The agent.
    pub agent: Agent,
    backlog: VecDeque<AgentEvent>,
}

impl Device {
    /// The identity DID: what a caller addresses.
    pub fn identity(&self) -> String {
        self.agent.identity_did().to_string()
    }

    /// The device DID.
    pub fn device(&self) -> String {
        self.agent.device_did().to_string()
    }

    /// Wait for the first event `f` picks, within [`TIMEOUT`]; the events before it are passed over and the ones after
    /// it kept for the next call. Panics, listing what arrived, when none does.
    pub async fn expect<T>(&mut self, what: &str, mut f: impl FnMut(&AgentEvent) -> Option<T>) -> T {
        let mut seen = vec![];
        let found = tokio::time::timeout(TIMEOUT, async {
            loop {
                while let Some(e) = self.backlog.pop_front() {
                    if let Some(t) = f(&e) {
                        return t;
                    }
                    seen.push(format!("{e:?}"));
                }
                let events = self.agent.next().await.unwrap_or_else(|e| panic!("{}: {e}", self.name));
                self.backlog.extend(events);
            }
        })
        .await;
        match found {
            Ok(t) => t,
            Err(_) => panic!("{}: no {what} within {TIMEOUT:?}; saw:\n  {}", self.name, seen.join("\n  ")),
        }
    }

    /// Wait, within [`TIMEOUT`], until `session` is in `state` (the events on the way are kept for
    /// [`Device::expect`]). Panics when it does not get there.
    pub async fn until(&mut self, session: &str, state: SessionState) {
        let reached = tokio::time::timeout(TIMEOUT, async {
            while self.agent.endpoint().session(session).map(|s| s.state) != Some(state) {
                let events = self.agent.next().await.unwrap_or_else(|e| panic!("{}: {e}", self.name));
                self.backlog.extend(events);
            }
        })
        .await;
        if reached.is_err() {
            let now = self.agent.endpoint().session(session).map(|s| s.state);
            panic!("{}: {session} not {state:?} within {TIMEOUT:?} (it is {now:?})", self.name);
        }
    }

    /// Take events for `d`, keeping them for the next [`Device::expect`]: a device that is not waiting still answers
    /// its relay and runs its timers only while something drives it.
    pub async fn pump(&mut self, d: Duration) {
        let _ = tokio::time::timeout(d, async {
            loop {
                let events = self.agent.next().await.unwrap_or_else(|e| panic!("{}: {e}", self.name));
                self.backlog.extend(events);
            }
        })
        .await;
    }

    /// Place a call to `to` through the call glue; returns the session id.
    pub async fn call(&mut self, to: &str) -> String {
        self.agent.place(to, Invite::default()).await.unwrap_or_else(|e| panic!("{}: placing a call: {e}", self.name))
    }

    /// Ask the call glue for `cmd`.
    pub async fn command(&mut self, cmd: CallCommand) {
        self.agent.call(cmd).await.unwrap_or_else(|e| panic!("{}: {e}", self.name))
    }
}

impl std::ops::Deref for Device {
    type Target = Agent;
    fn deref(&self) -> &Agent {
        &self.agent
    }
}

impl std::ops::DerefMut for Device {
    fn deref_mut(&mut self) -> &mut Agent {
        &mut self.agent
    }
}
