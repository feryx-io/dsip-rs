//! `dsip-messaging` — the protocol rules of the DSIP Messaging Profile 1.0 (v0.8 draft,
//! `v1.0/dsip-messaging-profile-v1.0.md`, cited `M§n`). Pure: no MLS library, no network.
//! MLS is abstracted to what a hub or mailbox can observe, as relay traces abstract signatures.
//!
//! Spec: sections owned by this crate — M§5 (profile messages: the two-layer model, lifetimes,
//! `MAX_MLS_BYTES`, the deposit class table — [`checks`]), M§8/M§10/M§11/M§12 (content objects,
//! receipts, activity, archive keys — [`checks`]), M§6.5–M§6.8 and M§7.3 (hub ordering,
//! sequencing, fan-out order, membership rules, external joins — [`hub`]), M§4.4, M§5.4–M§5.7,
//! M§6.6, M§12.2, M§14.2 (mailbox modes, sync and push, KeyPackage directory, group registration,
//! archive first-wins, first-contact authorization — [`mailbox`]), M§4.1 (whom a mailbox serves, release and idle
//! expiry of an enrolment — [`enrolment`]), M§6.5 (client seq gaps), M§5.4/M§8.5 (durable delivery state across restarts), M§7.2/M§7.5
//! (conversation convergence), M§10 and M§11.2 (receipts, watermarks, activity) and M§13.2
//! (voicemail offer — [`client`]), M§6.2/M§6.3/M§8.4/M§11.1/M§12.2 (the MLS layer: extension
//! encoding, the leaf authentication service, AES-GCM formats — [`mls_wire`]).
//!
//! Impl: every rule here is pinned by `impl/vectors/messaging/`; the Python reference is
//! `impl/tools/dsipvec/messaging.py`. The profile is a draft written before implementation, so
//! its open choices are spec-gaps 31–44 (`impl/docs/spec-gaps.md`).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod checks;
pub mod client;
pub mod enrolment;
pub mod first_contact;
pub mod hub;
pub mod mailbox;
pub mod mls_wire;
pub mod schemas;
pub mod verify;
pub mod wire;

use serde_json::{json, Value};

/// Run one `messaging/` vector and return the value to compare with its `expect`.
///
/// Spec: none (infrastructure) — dispatches on `input.check`.
pub fn run_vector(v: &Value) -> Value {
    let inp = &v["input"];
    if let Some(out) = mls_wire::run_check(inp["check"].as_str().unwrap_or(""), v) {
        return out;
    }
    if let Some(out) = first_contact::run_check(inp["check"].as_str().unwrap_or(""), inp) {
        return out;
    }
    match inp["check"].as_str().unwrap_or("") {
        "payload" => {
            let name = inp["schema"].as_str().unwrap_or("");
            if schemas::schema_ok(name, &inp["payload"]) {
                checks::accept()
            } else {
                checks::reject("schema-invalid", None)
            }
        }
        "message" => checks::check_message(&inp["payload"]),
        "object" => checks::check_object(&inp["object"], &v["context"]),
        "conversation-ext" => checks::check_conversation_ext(&inp["extension"]),
        "external-join" => checks::check_external_join(inp),
        "leave-proposals" => checks::leave_proposals(inp),
        "roster-change" => checks::check_roster_change(inp),
        "conversation-update" => checks::check_conversation_update(&inp["before"], &inp["after"]),
        "mailbox-select" => client::select_mailbox(inp),
        "mailbox-switch" => client::mailbox_switch(inp),
        "registration-on-removal" => client::registration_on_removal(inp),
        "blob-put" => mailbox::blob_put(inp),
        "blob-get" => mailbox::blob_get(inp),
        "blob-replicate" => mailbox::blob_replicate(inp),
        "blob-fetch" => client::blob_fetch(inp),
        "items-blobs" => mailbox::items_blobs(inp),
        "items-pages" => mailbox::items_pages(v),
        "blob-sources" => client::blob_sources(inp),
        "voicemail-offer" => client::voicemail_offer(inp),
        "call-event" => client::call_event_decision(inp),
        "peer-timeline" => client::peer_timeline(inp),
        "direct-select" => client::select_direct(inp["candidates"].as_array().map(Vec::as_slice).unwrap_or(&[])),
        "successor-check" => client::check_successor(inp),
        "successor-select" => client::select_successor(inp["candidates"].as_array().map(Vec::as_slice).unwrap_or(&[])),
        "client-trace" => {
            let mut c = client::Client::new(&v["context"]);
            trace(inp, |ev| (c.step(ev), c.snapshot()))
        }
        "gap-trace" => {
            let mut g = client::GapTracker::new(&v["context"]);
            trace(inp, |ev| (g.step(ev), g.snapshot()))
        }
        "resume-trace" => {
            let mut r = client::Resume::new(&v["context"]);
            trace(inp, |ev| (r.step(ev), r.snapshot()))
        }
        "successor-trace" => {
            let mut t = client::SuccessorTracker::new(&v["context"]);
            trace(inp, |ev| (t.step(ev), t.snapshot()))
        }
        "commit-retry-trace" => {
            let mut c = client::CommitRetry::new(&v["context"]);
            trace(inp, |ev| (c.step(ev), c.snapshot()))
        }
        "hub-outage-trace" => {
            let mut o = client::HubOutage::new(&v["context"]);
            trace(inp, |ev| (o.step(ev), o.snapshot()))
        }
        "move-arrival-trace" => {
            let mut a = client::MoveArrival::new(&v["context"]);
            trace(inp, |ev| (a.step(ev), a.snapshot()))
        }
        "enrolment-trace" => {
            let mut e = enrolment::Enrolment::new(&v["context"]);
            trace(inp, |ev| (e.step(ev), e.snapshot()))
        }
        "history-trace" => {
            let mut h = client::History::new(&v["context"]);
            trace(inp, |ev| (h.step(ev), h.snapshot()))
        }
        "hub-trace" => {
            let mut h = hub::Hub::new(&v["context"]);
            trace(inp, |ev| (h.step(ev), h.snapshot()))
        }
        "mailbox-trace" => {
            let mut m = mailbox::Mailbox::new(&v["context"]);
            trace(inp, |ev| (m.step(ev), m.snapshot()))
        }
        other => json!({"error": format!("unknown messaging check {other}")}),
    }
}

fn trace(inp: &Value, mut step: impl FnMut(&Value) -> (Vec<Value>, Value)) -> Value {
    let steps: Vec<Value> = inp["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|st| {
            let (emit, state) = step(&st["event"]);
            json!({"emit": emit, "state": state})
        })
        .collect();
    json!({"steps": steps})
}
