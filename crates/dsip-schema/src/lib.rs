//! `dsip-schema` — the v0.7 JSON Schema set, embedded at build time, plus the
//! stateless post-schema semantic checks.
//!
//! Spec: sections owned by this crate — §10.3 (schemas are normative for payload
//! shape), §11 (version negotiation, delegated to `dsip-core`), §9.3
//! (subscription caps, anti-enumeration), §13.2 (`hello` anti-splicing),
//! §14.2 (selection ⊆ offer), §15 (registry effects), §19.4 (introduction
//! size, grant↔introduction), §7.5 (`key-rotation` signer/subject rules), §12.12
//! (`info.data` validated per binding), §22.2 (`integrity` registry fallback).
//!
//! Pipeline stages 12–14 of `impl/vectors/README.md`. Stateful checks (state
//! machine, outstanding updates, `info` ACTIVE-only) live in `dsip-session`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod embedded;
pub mod key_agreement;
pub mod sealed;
pub mod semantic;
pub mod validate;

pub use semantic::{check_payload, check_semantic, registry_effects, selection_is_subset, SemanticContext};
pub use validate::{schema_for, validate, validate_against, SCHEMA_NAMES, validate_payload_as};
