//! `dsip-push`: a push gateway (Wake Profile, draft). Spec: W§2–W§5 (the library, `dsip_push`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use dsip_core::keys::KeyPair;
use dsip_push::providers::{Apns, Fcm, Recorder};
use dsip_push::{Gateway, GatewayConfig, Limits, Provider};
use dsip_transport::logging::LogTo;
use dsip_transport::tls;
use tokio::net::TcpListener;

/// A DSIP push gateway: devices enrol their APNs or FCM token here; relays and mailboxes ask it to wake them.
#[derive(Parser, Debug)]
#[command(name = "dsip-push", version)]
struct Args {
    /// TOML config file: each key is one of these flags in snake_case (`config.example.toml`); a flag given here
    /// wins over the file.
    #[arg(long)]
    config: Option<PathBuf>,
    /// The gateway's DID, a did:web whose document this gateway serves (`did:web:push.example.com`).
    #[arg(long)]
    did: String,
    /// The DSIPWake endpoint named in that document. Default: `https://<the DID's host>/wake`.
    #[arg(long)]
    endpoint: Option<String>,
    /// Address to listen on (HTTPS).
    #[arg(long, default_value = "0.0.0.0:8445")]
    listen: SocketAddr,
    /// State directory: the gateway's signing key seed, its handle key and, without --cert, a self-signed certificate.
    #[arg(long, default_value = "dsip-push-state")]
    state: PathBuf,
    /// TLS certificate chain (PEM). Without it a self-signed certificate is written to the state directory.
    #[arg(long, requires = "key")]
    cert: Option<PathBuf>,
    /// TLS private key (PEM).
    #[arg(long, requires = "cert")]
    key: Option<PathBuf>,
    /// An app this gateway pushes for, `provider:app` (repeatable): `apns:org.example.app.voip` (calls), `apns:org.example.app` (messages), `fcm:my-project`.
    #[arg(long = "app", required = true)]
    apps: Vec<String>,
    /// The APNs signing key (`AuthKey_XXXXXXXXXX.p8`).
    #[arg(long, requires_all = ["apns_key_id", "apns_team"])]
    apns_key: Option<PathBuf>,
    /// The APNs key's id.
    #[arg(long)]
    apns_key_id: Option<String>,
    /// The Apple developer team id.
    #[arg(long)]
    apns_team: Option<String>,
    /// The FCM service account's JSON key file.
    #[arg(long)]
    fcm_service_account: Option<PathBuf>,
    /// Deliver nothing: append every push to this file as a JSON line instead (testing, setting up).
    #[arg(long, conflicts_with_all = ["apns_key", "fcm_service_account"])]
    record_to: Option<PathBuf>,
    /// Wakes per handle per minute.
    #[arg(long, default_value_t = Limits::default().per_handle)]
    per_handle: usize,
    /// Wakes per waker per minute.
    #[arg(long, default_value_t = Limits::default().per_waker)]
    per_waker: usize,
    /// DID document JSON files of did:web wakers (repeatable), used before fetching.
    #[arg(long)]
    did_document: Vec<PathBuf>,
    /// Do not fetch did:web documents of wakers over HTTPS: only --did-document files, and did:key, verify.
    #[arg(long)]
    no_fetch_did_web: bool,
    /// PEM roots trusted, besides the public web PKI, for fetching did:web documents.
    #[arg(long)]
    did_web_ca: Option<PathBuf>,
    /// Where log lines go: `auto` is journald under systemd, standard error elsewhere. `RUST_LOG` filters.
    #[arg(long, value_enum, default_value_t)]
    log: LogTo,
}

/// A 32-byte secret kept as hex in `path`, made on first use.
fn secret(path: &std::path::Path) -> Result<[u8; 32]> {
    if path.exists() {
        let hex = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut out = [0u8; 32];
        let bytes = hex.trim().as_bytes();
        if bytes.len() != 64 {
            bail!("{} does not hold 32 bytes of hex", path.display());
        }
        for (i, c) in bytes.chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(c)?, 16)?;
        }
        return Ok(out);
    }
    let s: [u8; 32] = rand::random();
    std::fs::write(path, s.iter().map(|b| format!("{b:02x}")).collect::<String>()).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(s)
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    let args: Args = dsip_transport::config_file::parse();
    dsip_transport::logging::init(args.log);
    std::fs::create_dir_all(&args.state)?;
    if !args.did.starts_with("did:web:") {
        bail!("--did must be a did:web: its document names the DSIPWake endpoint (W§2)");
    }
    let key = KeyPair::from_seed(secret(&args.state.join("push.key"))?);
    let handle_key = secret(&args.state.join("handle.key"))?;
    let host = dsip_transport::resolver::did_web_url(&args.did)?
        .strip_prefix("https://")
        .and_then(|r| r.split('/').next())
        .map(String::from)
        .context("the DID's host")?;
    let endpoint = args.endpoint.clone().unwrap_or_else(|| format!("https://{host}/wake"));

    let mut apps = vec![];
    for a in &args.apps {
        let (p, app) = a.split_once(':').with_context(|| format!("--app {a}: expected provider:app"))?;
        apps.push((p.to_string(), app.to_string()));
    }
    let mut providers: HashMap<String, Arc<dyn Provider>> = HashMap::new();
    if let Some(path) = &args.record_to {
        let r: Arc<dyn Provider> = Arc::new(Recorder::to_file(path.clone()));
        providers.insert("apns".into(), r.clone());
        providers.insert("fcm".into(), r);
        tracing::warn!("recording pushes to {} instead of delivering them", path.display());
    }
    if let (Some(k), Some(id), Some(team)) = (&args.apns_key, &args.apns_key_id, &args.apns_team) {
        let p8 = std::fs::read_to_string(k).with_context(|| format!("reading {}", k.display()))?;
        providers.insert("apns".into(), Arc::new(Apns::new(team, id, &p8)?));
    }
    if let Some(f) = &args.fcm_service_account {
        let sa = serde_json::from_slice(&std::fs::read(f).with_context(|| format!("reading {}", f.display()))?)?;
        providers.insert("fcm".into(), Arc::new(Fcm::new(&sa)?));
    }
    for (p, app) in &apps {
        if !providers.contains_key(p) {
            bail!("--app {p}:{app}: no {p} credentials (--apns-key, --fcm-service-account) and no --record-to");
        }
    }

    let resolver = dsip_transport::resolver::build_resolver(&args.did_document, &[]).await?;
    let web = dsip_transport::resolver::web_documents(!args.no_fetch_did_web, dsip_transport::DidWebResolver::TTL_S, args.did_web_ca.as_deref())?;
    let limits = Limits { per_handle: args.per_handle, per_waker: args.per_waker, ..Limits::default() };
    let gateway = Arc::new(Gateway::new(GatewayConfig { key, did: args.did.clone(), handle_key, apps, providers, resolver, web, limits }));

    let mut hosts = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    hosts.push(host.split(':').next().unwrap_or(&host).to_string());
    let (cert, keyfile) = match (&args.cert, &args.key) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => tls::ensure_self_signed(&args.state, &hosts)?,
    };
    let certs = tls::Certificates::load(&cert, &keyfile)?;
    certs.reload_on_sighup()?;
    dsip_transport::shutdown::exit_on_terminate()?;
    let tcp = TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    tracing::info!("push gateway {} at {endpoint} (listening on {}, certificate {})", args.did, args.listen, cert.display());
    dsip_push::server::serve(gateway, &endpoint, tcp, certs.acceptor()).await?;
    Ok(ExitCode::SUCCESS)
}
