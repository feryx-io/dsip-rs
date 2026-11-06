//! The Rust vector runner — one verdict per vector, compared to `expect`.
//!
//! Spec: none (infrastructure). Mirrors `impl/tools/dsipvec/harness.py`
//! stage for stage; see `impl/vectors/README.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde_json::{json, Map, Value};

use dsip_core::envelope::{self, accept_verdict, Context, Envelope};
use dsip_core::{RejectCode, Verdict};
use dsip_schema::{check_payload, SemanticContext};
use dsip_broadcast::{evaluate_publication, Authority, AuthorityEvent, Subscriber};
use dsip_session::{Endpoint, EndpointConfig, Event, Relay, RelayEvent};

/// The suite: `DSIP_VECTORS` if set, else `impl/vectors` of the DSIP repository this workspace sits in, or of its
/// `spec/` submodule (dsip-rs).
pub fn default_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("DSIP_VECTORS") {
        return dir.into();
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [manifest.join("../../vectors"), manifest.join("../../spec/impl/vectors")];
    candidates.iter().find(|d| d.is_dir()).unwrap_or(&candidates[0]).clone()
}

struct Outcome {
    id: String,
    ok: bool,
    expected: Value,
    actual: Value,
    note: Option<String>,
}

fn load(dir: &Path, only: Option<&str>) -> Result<Vec<Value>> {
    let mut paths = vec![];
    for kind in std::fs::read_dir(dir)? {
        let kind = kind?.path();
        if !kind.is_dir() {
            continue;
        }
        for f in std::fs::read_dir(&kind)? {
            let f = f?.path();
            if f.extension().is_some_and(|e| e == "json") {
                paths.push(f);
            }
        }
    }
    paths.sort();
    let mut out = vec![];
    for p in paths {
        let v: Value = serde_json::from_slice(&std::fs::read(&p).with_context(|| p.display().to_string())?)?;
        let id = v["vector"].as_str().unwrap_or("");
        if only.is_none_or(|o| id.starts_with(o)) {
            out.push(v);
        }
    }
    Ok(out)
}

/// Run all vectors under `dir`. Returns the failure count.
pub fn run(dir: &Path, only: Option<&str>, json_out: Option<&Path>, verbose: bool) -> Result<usize> {
    let vectors = load(dir, only)?;
    let mut outcomes = vec![];
    for v in &vectors {
        let id = v["vector"].as_str().unwrap_or("?").to_string();
        let o = std::panic::catch_unwind(|| run_one(v));
        outcomes.push(match o {
            Ok(Ok((ok, expected, actual))) => Outcome { id, ok, expected, actual, note: None },
            Ok(Err(e)) => Outcome { id, ok: false, expected: v["expect"].clone(), actual: Value::Null, note: Some(e.to_string()) },
            Err(_) => Outcome { id, ok: false, expected: v["expect"].clone(), actual: Value::Null, note: Some("panic".into()) },
        });
    }
    let mut by_kind: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut failures = 0;
    for o in &outcomes {
        let kind = o.id.split('/').next().unwrap_or("").to_string();
        let e = by_kind.entry(kind).or_default();
        e.1 += 1;
        if o.ok {
            e.0 += 1;
        } else {
            failures += 1;
        }
        if !o.ok || verbose {
            println!("[{}] {}", if o.ok { "PASS" } else { "FAIL" }, o.id);
            if !o.ok {
                if let Some(n) = &o.note {
                    println!("       {n}");
                }
                if o.id.starts_with("state/") {
                    if let Some(step) = first_bad_step(&o.expected, &o.actual) {
                        println!("       step {}:", step);
                        println!("         expected: {}", o.expected[step]);
                        println!("         actual:   {}", o.actual[step]);
                    }
                } else {
                    println!("       expected: {}", o.expected);
                    println!("       actual:   {}", o.actual);
                }
            }
        }
    }
    for (k, (ok, n)) in &by_kind {
        println!("{k:10} {ok:3}/{n:<3}");
    }
    println!("\n{} vectors, {} failures", outcomes.len(), failures);
    if let Some(p) = json_out {
        let m: Map<String, Value> = outcomes.iter().map(|o| (o.id.clone(), json!({"ok": o.ok, "actual": o.actual}))).collect();
        std::fs::write(p, serde_json::to_string_pretty(&Value::Object(m))?)?;
    }
    Ok(failures)
}

fn first_bad_step(expected: &Value, actual: &Value) -> Option<usize> {
    let (e, a) = (expected.as_array()?, actual.as_array()?);
    (0..e.len().max(a.len())).find(|&i| e.get(i) != a.get(i))
}

/// Returns (ok, expected, actual). For state traces both are step arrays.
fn run_one(v: &Value) -> Result<(bool, Value, Value)> {
    let kind = v["kind"].as_str().unwrap_or("");
    let actual = match kind {
        "envelope" | "transport" | "dht" => envelope_like(v),
        "payload" => {
            let schema = v["input"]["schema"].as_str().unwrap_or("");
            match dsip_schema::validate_payload_as(schema, &v["input"]["payload"]) {
                Ok(()) => Verdict::accept().to_expect(),
                Err(e) => Verdict::reject(RejectCode::SchemaInvalid).detail(e).to_expect(),
            }
        }
        "semantic" => check_payload(&v["input"]["payload"], &SemanticContext::from_vector(&v["context"])).to_expect(),
        "broadcast" => broadcast(v),
        "media-binding" => dsip_webrtc_binding::run_vector(v),
        "gateway" => dsip_gateway::run_vector(v),
        "messaging" => dsip_messaging::run_vector(v),
        "trust" => dsip_core::trust::run_vector(v),
        "did-webvh" => dsip_core::webvh::run_vector(v),
        "device-events" => dsip_events::run_vector(v),
        "recording" => dsip_recording::run_vector(v),
        "wake" => dsip_wake::run_vector(v),
        "key-agreement" => dsip_schema::key_agreement::run_vector(v),
        "tn-binding" => dsip_number::run_vector(v),
        "alias-transparency" => dsip_kt::run_vector(v),
        "pkarr" => dsip_core::pkarr::run_vector(v),
        "presence" => dsip_broadcast::presence::run_vector(v),
        "state" => return state(v),
        other => anyhow::bail!("unknown kind {other}"),
    };
    Ok((actual == v["expect"], v["expect"].clone(), actual))
}

fn envelope_like(v: &Value) -> Value {
    let resolver = Context::resolver_from_vector(&v["context"]);
    let ctx = Context::from_vector(&v["context"], &resolver);
    let env = match Envelope::from_value(&v["input"]["envelope"]) {
        Ok(e) => e,
        Err(verdict) => return verdict.to_expect(),
    };
    let frame = v["input"]["frame"].as_str();
    let ver = match envelope::verify(&env, &ctx, frame) {
        Ok(ver) => ver,
        Err(verdict) => return verdict.to_expect(),
    };
    // §13.2 binding state: nothing but hello before a verified hello
    if v["context"]["hello_verified"] == Value::Bool(false) && ver.msg_type() != "hello" {
        return Verdict::reject_with(RejectCode::HelloRequired, "transport.hello-required").to_expect();
    }
    let size = frame.map(str::len).unwrap_or_else(|| env.frame().len());
    if v["kind"] == "dht" {
        return dht_tail(v, &ver, &ctx);
    }
    let mut sem_ctx = SemanticContext::from_vector(&v["context"]);
    sem_ctx.encoded_size = Some(size);
    let pv = check_payload(&ver.payload, &sem_ctx);
    if !pv.ok() {
        return pv.to_expect();
    }
    let mut out = accept_verdict(&ver).to_expect();
    for (k, val) in pv.extra {
        out[k] = val;
    }
    out
}

fn dht_tail(v: &Value, _ver: &envelope::Verified, ctx: &Context) -> Value {
    // The crate owns the hint semantics; the runner only feeds it the frame and the existing record.
    let frame = env_frame(&v["input"]["envelope"]);
    let existing = v["context"].get("existing").and_then(|e| Envelope::from_value(e).ok());
    dsip_dht::record::evaluate(&frame, ctx, existing.as_ref()).to_expect()
}

fn env_frame(env: &Value) -> String {
    Envelope::from_value(env).map(|e| e.frame()).unwrap_or_default()
}

fn broadcast(v: &Value) -> Value {
    let resolver = Context::resolver_from_vector(&v["context"]);
    let ctx = Context::from_vector(&v["context"], &resolver);
    let sem = SemanticContext::from_vector(&v["context"]);
    let pub_env = match Envelope::from_value(&v["input"]["publication"]) {
        Ok(e) => e,
        Err(verdict) => return verdict.to_expect(),
    };
    let prov: Vec<Envelope> = v["input"]["provenance"].as_array().into_iter().flatten().filter_map(|e| Envelope::from_value(e).ok()).collect();
    let strs = |k: &str| -> Vec<String> {
        v["input"]["capabilities"][k].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect()
    };
    match evaluate_publication(&pub_env, &prov, &strs("codecs"), &strs("transports"), &ctx, &sem) {
        Ok((signer, r)) => r.to_expect(&signer),
        Err(verdict) => verdict.to_expect(),
    }
}

#[allow(clippy::large_enum_variant)] // one per trace vector, held on the stack for the run
enum Component {
    Endpoint(Endpoint),
    Relay(Relay),
    Authority(Authority),
    Subscriber(Subscriber),
}

impl Component {
    fn step(&mut self, event: &Value) -> Result<Vec<Value>> {
        Ok(match self {
            Component::Endpoint(ep) => {
                let ev: Event = serde_json::from_value(event.clone()).with_context(|| format!("event {event}"))?;
                ep.step(&ev).iter().map(|e| e.to_json()).collect()
            }
            Component::Relay(rl) => {
                let ev: RelayEvent = serde_json::from_value(event.clone()).with_context(|| format!("event {event}"))?;
                rl.step(&ev).iter().map(|e| e.to_json()).collect()
            }
            Component::Authority(a) => {
                let ev: AuthorityEvent = serde_json::from_value(event.clone()).with_context(|| format!("event {event}"))?;
                a.step(&ev)
            }
            Component::Subscriber(s) => s.step(event),
        })
    }

    fn snapshot(&self, key: &str, expected: &Value) -> Value {
        let names = || -> Vec<String> { expected.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default() };
        match (self, key) {
            (Component::Endpoint(ep), "sessions") => ep.snapshot(names()),
            (Component::Endpoint(ep), "contacts") => ep.contacts.snapshot(),
            (Component::Endpoint(ep), "presence_keys") => ep.keys.snapshot(&ep.contacts),
            (Component::Relay(rl), "attempts") => rl.snapshot(names()),
            (Component::Relay(rl), "inbox") => rl.inbox_snapshot(),
            (Component::Authority(a), "publications") => a.snapshot_publications(),
            (Component::Authority(a), "presence") => a.snapshot_presence(),
            (Component::Authority(a), "subscriptions") => a.snapshot_subscriptions(),
            (Component::Subscriber(s), "subscriptions") => s.snapshot(),
            _ => Value::Null,
        }
    }
}

fn state(v: &Value) -> Result<(bool, Value, Value)> {
    let ctx = &v["context"];
    let steps = v["input"]["steps"].as_array().context("steps")?;
    let mut comp = match ctx["component"].as_str().unwrap_or("endpoint") {
        "relay" => Component::Relay(Relay::with_retention(ctx["start"].as_i64().unwrap_or(0), ctx["offline_retention_s"].as_i64().unwrap_or(86_400))),
        "authority" => Component::Authority(Authority::from_vector(ctx)),
        "subscriber" => Component::Subscriber(Subscriber::new(ctx["start"].as_i64().unwrap_or(0))),
        _ => Component::Endpoint(Endpoint::new(EndpointConfig::from_vector(ctx))),
    };
    let mut expected = vec![];
    let mut actual = vec![];
    let mut ok = true;
    for st in steps {
        let exp = &st["expect"];
        let emit = comp.step(&st["event"])?;
        let mut act = json!({"emit": emit});
        let mut exp_norm = json!({"emit": exp["emit"]});
        for (k, ev) in exp.as_object().into_iter().flatten() {
            if k == "emit" {
                continue;
            }
            exp_norm[k] = ev.clone();
            act[k] = comp.snapshot(k, ev);
        }
        ok &= exp_norm == act;
        expected.push(exp_norm);
        actual.push(act);
    }
    Ok((ok, Value::Array(expected), Value::Array(actual)))
}
