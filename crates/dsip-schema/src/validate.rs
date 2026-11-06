//! JSON Schema (draft 2020-12) validation with native `type` dispatch.
//!
//! Spec: §10.3; §15.2 (the reason wire structure — `reason` required, `detail` ≤ 1024,
//! `retry_after` — is enforced here by the payload schemas). Impl: `message.schema.json`'s
//! `oneOf` dispatcher is not used;
//! dispatch is a match on `type`, which avoids cross-file `$ref` resolution
//! and yields the same result because every payload schema pins `type` with
//! `const`. Format assertions are off, matching the Python harness
//! (`jsonschema` validates `format` only with an explicit checker).

use std::collections::HashMap;
use std::sync::OnceLock;

use jsonschema::Validator;
use serde_json::Value;

use dsip_core::registry::MESSAGE_TYPES;
use dsip_core::{RejectCode, Verdict};

use crate::embedded::SCHEMAS;

/// Names of the embedded spec schemas.
pub const SCHEMA_NAMES: &[&str] = &[
    "invite", "progress", "answer", "reject", "cancel", "update", "info", "bye", "error", "hello", "introduction",
    "grant", "publish", "subscribe", "notify", "unpublish", "provenance", "key-rotation", "reachability-hint", "key-agreement-delegation",
    "webrtc-info-data", "dtmf-info-data", "envelope", "message",
];

/// `info.data` schemas by `about` (§12.12): validated for the bindings this implementation
/// speaks; an unimplemented `about` leaves `data` unchecked (ignored, never rejected).
pub const BINDING_DATA_SCHEMAS: &[(&str, &str)] = &[("transport:webrtc", "webrtc-info-data"), ("media:dtmf", "dtmf-info-data")];

fn compiled() -> &'static HashMap<&'static str, Validator> {
    static CELL: OnceLock<HashMap<&'static str, Validator>> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut m = HashMap::new();
        for (name, text) in SCHEMAS.iter() {
            if *name == "message" {
                continue; // relative $refs; dispatched natively instead
            }
            // An embedded schema that does not parse or compile is left out, so its messages are refused
            // ("no schema") rather than the process panicking on the first message; `all_schemas_compile_and_dispatch`
            // fails the build on such a schema.
            let Ok(schema) = serde_json::from_str::<Value>(text) else { continue };
            let Ok(v) = jsonschema::options().should_validate_formats(false).build(&schema) else { continue };
            m.insert(*name, v);
        }
        m
    })
}

/// The compiled validator for a schema name, if embedded.
pub fn schema_for(name: &str) -> Option<&'static Validator> {
    compiled().get(name)
}

/// Validate `instance` against the named schema. Returns the first error message on failure.
pub fn validate_against(name: &str, instance: &Value) -> Result<(), String> {
    let v = schema_for(name).ok_or_else(|| format!("no schema named {name}"))?;
    match v.iter_errors(instance).next() {
        None => Ok(()),
        Some(e) => Err(format!("{} at {}", e, e.instance_path())),
    }
}

/// Validate `payload` as message type `schema`, plus — for `info` — its `data` against the
/// binding schema named by `about` when that binding is in [`BINDING_DATA_SCHEMAS`] (§12.12;
/// WebRTC Media Binding Appendix A).
pub fn validate_payload_as(schema: &str, payload: &Value) -> Result<(), String> {
    validate_against(schema, payload)?;
    if schema == "info" {
        if let Some(about) = payload.get("about").and_then(Value::as_str) {
            if let Some((_, data_schema)) = BINDING_DATA_SCHEMAS.iter().find(|(a, _)| *a == about) {
                validate_against(data_schema, payload.get("data").unwrap_or(&Value::Null)).map_err(|e| format!("data: {e}"))?;
            }
        }
    }
    Ok(())
}

/// Stage 13: dispatch on `type` and validate. `unknown-type` for types outside the message set.
pub fn validate(payload: &Value) -> Verdict {
    let Some(t) = payload.get("type").and_then(Value::as_str) else { return Verdict::reject(RejectCode::UnknownType) };
    if !MESSAGE_TYPES.contains(&t) {
        return Verdict::reject(RejectCode::UnknownType);
    }
    match validate_payload_as(t, payload) {
        Ok(()) => Verdict::accept(),
        Err(e) => Verdict::reject(RejectCode::SchemaInvalid).detail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_schemas_compile_and_dispatch() {
        for n in SCHEMA_NAMES.iter().filter(|n| **n != "message") {
            assert!(schema_for(n).is_some(), "{n}");
        }
        assert!(schema_for("reachability-hint").is_some());
        assert!(schema_for("webrtc-info-data").is_some());
        assert_eq!(validate(&serde_json::json!({"type": "transfer"})).code, Some(RejectCode::UnknownType));
        assert_eq!(validate(&serde_json::json!({"type": "bye"})).code, Some(RejectCode::SchemaInvalid));
    }
}
