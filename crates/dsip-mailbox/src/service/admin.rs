//! The mailbox's admin commands (`dsip-mailbox admin …`, on the status port): the enrolments against `--serve-any`,
//! releasing one, and the admission codes of a mailbox that enrols by code (`--admission`).
//!
//! Spec: none (infrastructure). Releasing an enrolment does what M§4.1 says an ended one does (everything held for
//! the identity deleted, its bindings closed, its place freed): the operator's end of it is spec-gap 164. Admission
//! codes are given out of band (M§4.1 "Admission codes", spec-gap 185): 128 random bits, base64url, as M§4.1 asks.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::status::{owners, quota_pct};
use super::Service;

/// The commands, for the binary's `admin` subcommand.
pub const COMMANDS: &[dsip_transport::admin::Command] = &[
    dsip_transport::admin::Command {
        name: "enrolments",
        about: "The identities enrolled within --serve-any, and the configured ones",
        arg: None,
        write: false,
        show: show_enrolments,
    },
    dsip_transport::admin::Command {
        name: "release",
        about: "End an enrolment: delete everything held for the identity, close its bindings, free its place",
        arg: Some(("identity", "DID")),
        write: true,
        show: show_released,
    },
    dsip_transport::admin::Command {
        name: "admission-new",
        about: "Issue an admission code for USES enrolments (1 for one person), valid DAYS days if given (--admission)",
        arg: Some(("spec", "USES[:DAYS]")),
        write: true,
        show: show_issued,
    },
    dsip_transport::admin::Command {
        name: "admissions",
        about: "The admission codes issued, with the uses left and when each expires",
        arg: None,
        write: false,
        show: show_admissions,
    },
    dsip_transport::admin::Command {
        name: "admission-revoke",
        about: "Withdraw an admission code; enrolments it made stay",
        arg: Some(("code", "CODE")),
        write: true,
        show: show_revoked,
    },
];

/// Answer one admin command.
pub(super) fn answer(st: &mut Service, command: &str, args: &BTreeMap<String, String>, write: bool, now: i64) -> Value {
    match (command, write) {
        ("enrolments", _) => enrolments(st, now),
        ("release", true) => {
            let Some(identity) = args.get("identity") else { return json!({"error": "release needs identity=<did>"}) };
            if st.enrolment.is_configured(identity) {
                return json!({"error": format!("{identity} is configured (--owner), not enrolled: remove it from the configuration")});
            }
            if st.enrolment.operator_release(identity).is_empty() {
                return json!({"error": format!("{identity} is not enrolled here")});
            }
            let row = owners(st, now).into_iter().find(|r| &r.identity == identity);
            st.end_enrolment(identity, "operator");
            json!({"released": identity, "items": row.as_ref().map(|r| r.items), "used_bytes": row.as_ref().map(|r| r.used_bytes),
                "devices_closed": row.as_ref().map(|r| r.devices_bound), "free": free(st)})
        }
        ("release", false) => json!({"error": "release changes state: send it as a POST (dsip-mailbox admin release <did>)"}),
        ("admission-new", true) => {
            if !st.enrolment.admits_by_code() {
                return json!({"error": "this mailbox does not enrol by admission code: start it with --admission"});
            }
            let Some((uses, days)) = args.get("spec").and_then(|s| parse_spec(s)) else {
                return json!({"error": "admission-new needs USES[:DAYS], e.g. 1 or 1:30"});
            };
            let code = new_code();
            let expires_at = days.map(|d| now + d * 86_400);
            st.enrolment.issue_code(&code, uses, expires_at);
            st.persist();
            json!({"code": code, "uses": uses, "expires_at": expires_at})
        }
        ("admissions", _) => json!({
            "admission": st.enrolment.admits_by_code(),
            "codes": st.enrolment.codes().iter().map(|(code, c)| json!({"code": code, "uses": c.uses, "expires_at": c.expires_at,
                "expired": c.expires_at.is_some_and(|t| now >= t)})).collect::<Vec<_>>(),
        }),
        ("admission-revoke", true) => {
            let Some(code) = args.get("code") else { return json!({"error": "admission-revoke needs code=<code>"}) };
            if !st.enrolment.revoke_code(code) {
                return json!({"error": "no such admission code"});
            }
            st.persist();
            json!({"revoked": code})
        }
        ("admission-new" | "admission-revoke", false) => json!({"error": format!("{command} changes state: send it as a POST")}),
        _ => json!({"error": format!("no admin command {command:?} (enrolments, release, admission-new, admissions, admission-revoke)")}),
    }
}

/// `USES[:DAYS]`: at least one use; days, if given, at least one.
fn parse_spec(s: &str) -> Option<(u32, Option<i64>)> {
    let (uses, days) = match s.split_once(':') {
        Some((u, d)) => (u, Some(d.parse::<i64>().ok().filter(|d| *d > 0)?)),
        None => (s, None),
    };
    Some((uses.parse::<u32>().ok().filter(|u| *u > 0)?, days))
}

/// A new admission code: 128 random bits, base64url (22 characters).
fn new_code() -> String {
    let bytes: [u8; 16] = rand::random();
    dsip_core::b64::encode(&bytes)
}

fn show_issued(v: &Value) -> String {
    let expires = v["expires_at"].as_i64().map_or("does not expire".to_string(), |t| format!("expires at {t} (unix s)"));
    format!("{}\n{} use(s), {expires}\n", v["code"].as_str().unwrap_or("?"), v["uses"])
}

fn show_admissions(v: &Value) -> String {
    let codes = v["codes"].as_array().map_or(&[][..], Vec::as_slice);
    let mut out = if v["admission"] == json!(true) {
        format!("enrolment by admission code: {} code(s)\n", codes.len())
    } else {
        "enrolment is not by admission code (--admission off)\n".to_string()
    };
    for c in codes {
        let state = if c["expired"] == json!(true) {
            "expired".to_string()
        } else {
            c["expires_at"].as_i64().map_or("no expiry".to_string(), |t| format!("expires at {t}"))
        };
        out += &format!("  {}  {} use(s) left, {state}\n", c["code"].as_str().unwrap_or("?"), c["uses"]);
    }
    out
}

fn show_revoked(v: &Value) -> String {
    format!("revoked {}\n", v["revoked"].as_str().unwrap_or("?"))
}

fn free(st: &Service) -> Option<usize> {
    st.serve_any.map(|n| n.saturating_sub(st.enrolment.entries().len()))
}

fn enrolments(st: &Service, now: i64) -> Value {
    let rows: BTreeMap<String, _> = owners(st, now).into_iter().map(|r| (r.identity.clone(), r)).collect();
    let row = |identity: &str| {
        let r = rows.get(identity);
        json!({"identity": identity, "items": r.map(|r| r.items), "used_bytes": r.map(|r| r.used_bytes),
            "quota_pct": r.map(|r| quota_pct(r.used_bytes, st.quota_bytes)), "devices": r.map(|r| r.devices),
            "devices_bound": r.map(|r| r.devices_bound)})
    };
    let enrolled: Vec<Value> = st
        .enrolment
        .entries()
        .iter()
        .map(|(identity, seen)| {
            let mut v = row(identity);
            v["last_hello_s"] = json!(now - seen);
            v["released_in_s"] = json!(st.release_idle.then(|| st.mls_retention - (now - seen)));
            v
        })
        .collect();
    json!({
        "serve_any": st.serve_any, "free": free(st), "release_idle": st.release_idle, "mls_retention_s": st.mls_retention,
        "enrolled": enrolled,
        "configured": st.configured.iter().map(|c| row(c)).collect::<Vec<_>>(),
    })
}

fn ago(s: i64) -> String {
    match s {
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3600),
        s => format!("{} d", s / 86_400),
    }
}

fn show_enrolments(v: &Value) -> String {
    let mut out = match v["serve_any"].as_u64() {
        Some(n) => format!("serve-any {n}: {} enrolled, {} free", v["enrolled"].as_array().map_or(0, Vec::len), v["free"]),
        None => "serve-any off: configured owners only".to_string(),
    };
    if v["release_idle"] == json!(true) {
        out += &format!("; released after {} without a hello", ago(v["mls_retention_s"].as_i64().unwrap_or(0)));
    }
    out += "\n";
    let line = |r: &Value, extra: String| {
        format!("  {}  {} items, {} bytes, {}/{} devices bound{extra}\n", r["identity"].as_str().unwrap_or("?"),
            r["items"].as_u64().unwrap_or(0), r["used_bytes"].as_i64().unwrap_or(0),
            r["devices_bound"].as_u64().unwrap_or(0), r["devices"].as_u64().unwrap_or(0))
    };
    for r in v["enrolled"].as_array().into_iter().flatten() {
        let mut extra = format!(", last hello {} ago", ago(r["last_hello_s"].as_i64().unwrap_or(0)));
        if let Some(n) = r["released_in_s"].as_i64() {
            extra += &format!(", released in {}", ago(n.max(0)));
        }
        out += &line(r, extra);
    }
    let configured = v["configured"].as_array().map_or(&[][..], Vec::as_slice);
    if !configured.is_empty() {
        out += "configured:\n";
        for r in configured {
            out += &line(r, String::new());
        }
    }
    out
}

fn show_released(v: &Value) -> String {
    format!("released {}: deleted {} items ({} bytes), closed {} binding(s); {} free\n", v["released"].as_str().unwrap_or("?"),
        v["items"].as_u64().unwrap_or(0), v["used_bytes"].as_i64().unwrap_or(0), v["devices_closed"].as_u64().unwrap_or(0),
        v["free"].as_u64().map_or("no serve-any".to_string(), |n| n.to_string()))
}
