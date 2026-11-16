//! `dsip-mailbox` — the mailbox/hub service binary: flags, the TLS certificate, then
//! [`dsip_mailbox::MailboxServer`] on a TLS port.
//!
//! Spec: none (infrastructure)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Parser;

use dsip_mailbox::service::blob_endpoint;
use dsip_mailbox::{MailboxConfig, MailboxServer};
use dsip_transport::logging::LogTo;
use dsip_transport::tls;

#[derive(Parser)]
#[command(name = "dsip-mailbox", version, about = "DSIP mailbox and hub service (Messaging Profile 1.0)",
    after_help = "dsip-mailbox admin --help: operate a running mailbox (enrolments, release) through its status port")]
struct Args {
    /// TOML config file: each key is one of these flags in snake_case (`config.example.toml`); a flag given here
    /// wins over the file.
    #[arg(long)]
    config: Option<PathBuf>,
    /// State directory: service key, TLS certificate.
    #[arg(long)]
    state: PathBuf,
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:9443")]
    listen: SocketAddr,
    /// An identity this mailbox serves (repeatable; its DID document, or its reachability hint, names this service).
    #[arg(long = "owner")]
    owners: Vec<String>,
    /// Serve up to this many further identities that enrol by binding here with a verified `hello` (spec-gap 115):
    /// an operator's mailbox open to `did:key` identities, as the browser client's are. Unset: only `--owner`.
    #[arg(long)]
    serve_any: Option<usize>,
    /// Hints nodes (`https://host:port`, repeatable) asked for the `DSIPMailbox` hint of a member identity that has no
    /// DID document (M§4.2; DHT Hints Profile §10), when fanning out to it.
    #[arg(long = "hints-node")]
    hints_nodes: Vec<String>,
    /// TLS certificate chain (PEM) to serve under instead of the self-signed one; with `--key`.
    #[arg(long, requires = "key")]
    cert: Option<PathBuf>,
    /// The certificate's private key (PEM).
    #[arg(long)]
    key: Option<PathBuf>,
    /// DID document files (re-read when resolving, so documents may be written after startup).
    #[arg(long = "resolver-file")]
    resolver_files: Vec<PathBuf>,
    /// Do not fetch `did:web` documents over HTTPS (§7.2): only the --resolver-file documents, and `did:key`, verify.
    #[arg(long)]
    no_fetch_did_web: bool,
    /// Seconds a fetched `did:web` document is reused before it is fetched again.
    #[arg(long, default_value_t = dsip_transport::resolver::DidWebResolver::TTL_S)]
    did_web_ttl: u64,
    /// PEM certificates trusted, besides the public web PKI, for fetching `did:web` documents (a private CA).
    #[arg(long)]
    did_web_ca: Option<PathBuf>,
    /// Trust anchor for dialling peer mailboxes.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Admit policy (M§5.7): `grant` (default) or `open`.
    #[arg(long, default_value = "grant")]
    admit: String,
    /// Introductions (and grants) allowed per sender identity and per recipient inbox within `--intro-window` (§19.4).
    #[arg(long, default_value_t = 5)]
    intro_limit: usize,
    /// Rate-limit window for introductions, seconds (§19.4).
    #[arg(long, default_value_t = 3600)]
    intro_window: i64,
    /// Introductions held per recipient inbox (§19.4, RECOMMENDED 16).
    #[arg(long, default_value_t = 16)]
    inbox_cap: usize,
    /// Largest blob accepted on the blob endpoint, bytes (M§4.3 `max_blob_bytes`).
    #[arg(long, default_value_t = 16_777_216)]
    max_blob_bytes: i64,
    /// The owner's storage quota, bytes: stored items plus blobs (M§4.3 `quota_bytes`; spec-gap 99). Deposits and
    /// uploads that would exceed it are refused `mailbox.quota-exceeded`.
    #[arg(long, default_value_t = 10_737_418_240)]
    quota_bytes: i64,
    /// How long a moved group's new hub is held off while the old hub's last items are missing, seconds
    /// (M§7.4, RECOMMENDED 300; spec-gap 71).
    #[arg(long, default_value_t = dsip_messaging::mailbox::HANDOVER_WAIT_S)]
    handover_wait: i64,
    /// How long a hub keeps fanning out to a member identity that acknowledges nothing, seconds: past it, that
    /// identity's queues are dropped and a returning device re-joins by external commit (M§4.4 `mls_retention_s`,
    /// RECOMMENDED 2,592,000; spec-gap 119).
    #[arg(long, default_value_t = dsip_messaging::hub::MLS_RETENTION_S)]
    mls_retention: i64,
    /// End the enrolment of an enrolled identity once none of its devices has completed a verified `hello` within
    /// `--mls-retention` (M§4.1 idle expiry, a MAY; spec-gap 130): everything held for it is deleted and its place in
    /// `--serve-any` is freed. Configured `--owner` identities never expire.
    #[arg(long)]
    release_idle: bool,
    /// Enrol only identities that present an admission code issued with `dsip-mailbox admin admission-new` (M§4.1
    /// "Admission codes", spec-gap 185), within `--serve-any`: a hosted mailbox that admits those who signed up, not
    /// whoever finds it. Its `hello` says `enrolment: "admission"`.
    #[arg(long, requires = "serve_any")]
    admission: bool,
    /// Wake sleeping devices through their push gateways (Wake Profile, draft): answer `wake-register`, advertise
    /// `wake` in the mailbox's `hello`, and ask a device's gateway to wake it when an item is stored for its identity
    /// (`message`, at most one a minute per device). Registrations are kept in `<state>/wake-registrations.json`.
    #[arg(long)]
    wake: bool,
    /// A gateway devices may register through (repeatable, W§4.2); unset: any.
    #[arg(long, requires = "wake")]
    wake_gateway: Vec<String>,
    /// Fault injection for demos: never deliver hub fan-out to this peer mailbox (a hub that dies before delivering).
    #[arg(long)]
    drop_fanout_to: Option<String>,
    /// Extra hostnames or addresses for the self-signed certificate (a mailbox dialled across hosts; same as the
    /// relay's). The first one is also the host of the advertised `blob_endpoint` (M§4.3), since a wildcard
    /// `--listen` address is not one a peer can dial.
    #[arg(long)]
    host: Vec<String>,
    /// Serve `GET /status` (JSON; `?detail=1` adds each owner's storage and each hub), `GET /metrics`
    /// (Prometheus) and the admin commands (`dsip-mailbox admin`) on this address, plain HTTP. Keep it on loopback
    /// (`dsipctl mailbox-status`).
    #[arg(long)]
    status_listen: Option<SocketAddr>,
    /// Where log lines go: `auto` is journald under systemd, standard error elsewhere. `RUST_LOG` filters.
    #[arg(long, value_enum, default_value_t)]
    log: LogTo,
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    if dsip_transport::admin::invoked() {
        return Ok(dsip_transport::admin::run("dsip-mailbox", dsip_mailbox::service::ADMIN_COMMANDS).await);
    }
    let args: Args = dsip_transport::config_file::parse();
    dsip_transport::logging::init(args.log);
    std::fs::create_dir_all(&args.state)?;
    let mut hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into()];
    hosts.extend(args.host.iter().cloned());
    let (cert, keyfile) = match (&args.cert, &args.key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()), // a real certificate: browsers bind here (client stage 6)
        _ => tls::ensure_self_signed(&args.state, &hosts)?,
    };
    // SIGHUP reads the certificate again (a renewal): new connections get it, bound devices stay bound
    let certs = tls::Certificates::load(&cert, &keyfile)?;
    certs.reload_on_sighup()?;
    dsip_transport::shutdown::exit_on_terminate()?;
    anyhow::ensure!(!args.owners.is_empty() || args.serve_any.is_some(), "give --owner <did> (repeatable) and/or --serve-any <n>");

    let mut cfg = MailboxConfig::new(args.state.clone(), blob_endpoint(&args.listen, args.host.first().map(String::as_str)));
    cfg.owners = args.owners.clone();
    cfg.serve_any = args.serve_any;
    cfg.hints_nodes = args.hints_nodes;
    cfg.resolver_files = args.resolver_files;
    cfg.did_web = dsip_transport::resolver::web_documents(!args.no_fetch_did_web, args.did_web_ttl, args.did_web_ca.as_deref())?;
    cfg.ca = args.ca;
    cfg.admit = args.admit;
    cfg.intro_limit = args.intro_limit;
    cfg.intro_window = args.intro_window;
    cfg.inbox_cap = args.inbox_cap;
    cfg.max_blob_bytes = args.max_blob_bytes;
    cfg.quota_bytes = args.quota_bytes;
    cfg.handover_wait = args.handover_wait;
    cfg.mls_retention = args.mls_retention;
    cfg.release_idle = args.release_idle;
    cfg.admission = args.admission;
    cfg.drop_fanout_to = args.drop_fanout_to;
    if args.wake {
        // a gateway's document: the --resolver-file documents, then (unless fetching is off) its did:web document
        let held: Arc<dyn dsip_transport::DidResolver> = Arc::new(dsip_transport::resolver::build_resolver(&cfg.resolver_files, &[]).await?);
        let docs: Arc<dyn dsip_transport::DidResolver> = if args.no_fetch_did_web {
            held
        } else {
            let mut web = dsip_transport::DidWebResolver::new();
            if let Some(ca) = &args.did_web_ca {
                web = web.with_ca(&std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?)?;
            }
            Arc::new(dsip_transport::Chain(held, Arc::new(web)))
        };
        let mut client = dsip_transport::wake::WakeClient::new(docs);
        if let Some(ca) = &args.did_web_ca {
            client = client.with_ca(&std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?)?;
        }
        let gateways = (!args.wake_gateway.is_empty()).then(|| args.wake_gateway.clone());
        tracing::info!("waking devices through {} (Wake Profile)", gateways.as_ref().map_or("any gateway".to_string(), |g| g.join(", ")));
        cfg.wake = Some(dsip_transport::waker::WakeConfig { client, gateways, store: Some(args.state.join("wake-registrations.json")) });
    }

    // Bound before the state is reloaded: a connection waits in the backlog until the accept loop starts.
    let listener = tokio::net::TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    let server = MailboxServer::open(cfg)?;
    tracing::info!("mailbox {} for {} on wss://{}/dsip (ca {}){}", server.did(), args.owners.join(", "), args.listen, cert.display(),
        args.serve_any.map(|n| format!(", enrolling up to {n} more (spec-gap 115){}", if args.admission { " by admission code (spec-gap 185)" } else { "" })).unwrap_or_default());
    if let Some(addr) = args.status_listen {
        server.spawn_status(addr);
    }
    server.spawn_tasks();
    server.serve_tls(listener, certs.acceptor()).await?;
    Ok(ExitCode::SUCCESS)
}
