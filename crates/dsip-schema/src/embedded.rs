//! Schema texts embedded from the canonical spec folder.
//!
//! Spec: §10.3 — "JSON Schema files for every message type accompany this
//! specification and are normative for payload shape." The files are read
//! from `v1.0/…/schemas/` at compile time; `build.rs` fails the build if they
//! drift from `generate_schemas.py`. Switching the path *is* the schema-layer
//! migration between spec revisions (v0.6 → v0.7 on 2026-08-21).

macro_rules! schema {
    ($name:literal) => {
        ($name, include_str!(concat!(env!("DSIP_SPEC"), "/v1.0/dsip-schemas-v1.0/dsip-schemas/schemas/", $name, ".schema.json")))
    };
}

/// `(name, json text)` for every schema in the v0.9 set (message types, the envelope and
/// dispatcher, and the WebRTC Media Binding's `info.data` schema).
pub const SCHEMAS: &[(&str, &str)] = &[
    schema!("invite"),
    schema!("progress"),
    schema!("answer"),
    schema!("reject"),
    schema!("cancel"),
    schema!("update"),
    schema!("info"),
    schema!("bye"),
    schema!("error"),
    schema!("hello"),
    schema!("introduction"),
    schema!("grant"),
    schema!("publish"),
    schema!("subscribe"),
    schema!("notify"),
    schema!("unpublish"),
    schema!("provenance"),
    schema!("key-rotation"),
    schema!("delegation-revocation"),
    schema!("reachability-hint"),
    schema!("key-agreement-delegation"),
    schema!("alias-monitor"),
    schema!("presence"),
    schema!("grant-revocation"),
    schema!("webrtc-info-data"),
    schema!("dtmf-info-data"),
    schema!("envelope"),
    schema!("message"),
];
