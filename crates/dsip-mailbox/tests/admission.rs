//! A mailbox that enrols only by admission code, end to end in one process: its `hello` says so; a device of an
//! identity it does not serve is refused until its `mailbox-config` carries a code the operator issued, which enrols
//! the identity and is spent; the same code then admits no one else; a code never issued is refused; a code survives
//! a restart.
//!
//! Spec: M§4.1 "Admission codes", M§4.3 `enrolment`, M§5.7 `admission`, M§14.3 (spec-gap 185).

use std::time::Duration;

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::version::Supported;
use dsip_mailbox::{wire, MailboxConfig, MailboxServer};
use dsip_transport::conn::{ConnectParams, Connection};
use dsip_transport::now_s;
use dsip_transport::verify::SeenIds;
use serde_json::{json, Value};

struct Keys {
    identity: KeyPair,
    device: KeyPair,
    delegation: Envelope,
}

fn keys() -> Keys {
    let (identity, device) = (KeyPair::generate(), KeyPair::generate());
    let now = now_s();
    let p = dsip_core::delegation::delegation_payload(&identity.did(), &device.did(), now - 60, now + 86_400,
        &["dsip.signaling", "dsip.messaging"]);
    let delegation = sign(&p, &identity, &identity.kid());
    Keys { identity, device, delegation }
}

async fn bind(server: &MailboxServer, k: &Keys) -> Connection {
    let (ours, theirs) = tokio::io::duplex(1 << 17);
    let s = server.clone();
    tokio::spawn(async move {
        let _ = s.accept(theirs).await;
    });
    let params = ConnectParams {
        url: "wss://mailbox.invalid/dsip".into(),
        tls: None,
        device: &k.device,
        on_behalf_of: Some(k.identity.did()),
        delegations: vec![k.delegation.clone()],
        supported: Supported::all_known(),
    };
    Connection::over(ours, &params, &StaticResolver::default(), &mut SeenIds::default()).await.expect("bound")
}

fn payload(frame: &str) -> Value {
    let env = Envelope::from_frame(frame).unwrap();
    serde_json::from_slice(&dsip_core::b64::decode(&env.payload).unwrap()).unwrap()
}

/// Send `type` with `fields` from `k`'s device to the mailbox; its answer.
async fn ask(conn: &mut Connection, k: &Keys, mailbox: &str, kind: &str, fields: Value) -> Value {
    let env = wire::message(&k.device, kind, mailbox, now_s(), wire::TTL_S, fields);
    let id = wire::payload_of(&env).unwrap()["id"].as_str().unwrap().to_string();
    conn.send(&env).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let p = payload(&conn.recv().await.unwrap().expect("open"));
            if p["in_reply_to"] == id {
                return p;
            }
        }
    })
    .await
    .expect("answered")
}

fn reason(a: &Value) -> Option<&str> {
    (a["type"] == "error").then(|| a["reason"].as_str().unwrap_or_default())
}

fn open(dir: &std::path::Path) -> MailboxServer {
    let mut cfg = MailboxConfig::new(dir.to_path_buf(), "https://mailbox.invalid/blobs".into());
    cfg.serve_any = Some(8);
    cfg.admission = true;
    MailboxServer::open(cfg).unwrap()
}

#[tokio::test]
async fn an_identity_enrols_with_a_code_its_operator_issued() {
    let dir = std::env::temp_dir().join(format!("dsip-mailbox-admission-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let server = open(&dir);
    let mbx = server.did().to_string();

    let issued = server.admin("admission-new", &[("spec", "1")], true).await;
    let code = issued["code"].as_str().expect("a code").to_string();
    assert_eq!(code.len(), 22, "128 bits, base64url: {issued}");

    // the hello says how this mailbox enrols (M§4.3)
    let bob = keys();
    let mut b = bind(&server, &bob).await;
    assert_eq!(b.relay.capabilities["mailbox"]["enrolment"], "admission");

    // a sync carries no code: admission required; a code never issued: refused; nothing spent
    assert_eq!(reason(&ask(&mut b, &bob, &mbx, "sync", json!({"since": null})).await), Some("mailbox.admission-required"));
    let wrong = ask(&mut b, &bob, &mbx, "mailbox-config", json!({"subject": bob.identity.did(), "admission": "not-a-code"})).await;
    assert_eq!(reason(&wrong), Some("mailbox.admission-refused"));

    // the issued code enrols Bob; his sync is then served
    let ok = ask(&mut b, &bob, &mbx, "mailbox-config", json!({"subject": bob.identity.did(), "admission": code})).await;
    assert_eq!(ok["type"], "accepted", "{ok}");
    assert_eq!(ask(&mut b, &bob, &mbx, "sync", json!({"since": null})).await["type"], "items");

    // spent: Carol cannot use it
    let carol = keys();
    let mut c = bind(&server, &carol).await;
    let spent = ask(&mut c, &carol, &mbx, "mailbox-config", json!({"subject": carol.identity.did(), "admission": code})).await;
    assert_eq!(reason(&spent), Some("mailbox.admission-refused"));

    // a code issued for Carol survives a restart
    let carols = server.admin("admission-new", &[("spec", "1:30")], true).await["code"].as_str().unwrap().to_string();
    drop((b, c, server));
    let server = open(&dir);
    let listed = server.admin("admissions", &[], false).await;
    assert!(listed["codes"].as_array().unwrap().iter().any(|x| x["code"] == carols.as_str() && x["uses"] == 1), "{listed}");
    let mut c = bind(&server, &carol).await;
    let ok = ask(&mut c, &carol, &mbx, "mailbox-config", json!({"subject": carol.identity.did(), "admission": carols})).await;
    assert_eq!(ok["type"], "accepted", "{ok}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn codes_found_by_trying_are_rate_limited() {
    let dir = std::env::temp_dir().join(format!("dsip-mailbox-admission-limit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let server = open(&dir);
    let mbx = server.did().to_string();
    let code = server.admin("admission-new", &[("spec", "1")], true).await["code"].as_str().unwrap().to_string();
    let mallory = keys();
    let mut m = bind(&server, &mallory).await;
    for n in 0..5 {
        let a = ask(&mut m, &mallory, &mbx, "mailbox-config", json!({"subject": mallory.identity.did(), "admission": format!("guess-{n}")})).await;
        assert_eq!(reason(&a), Some("mailbox.admission-refused"));
    }
    // past the limit even the right code is not looked at (M§14.3)
    let a = ask(&mut m, &mallory, &mbx, "mailbox-config", json!({"subject": mallory.identity.did(), "admission": code})).await;
    assert_eq!(reason(&a), Some("policy.rate-limited"));
    let listed = server.admin("admissions", &[], false).await;
    assert_eq!(listed["codes"][0]["uses"], 1, "not spent: {listed}");
    let _ = std::fs::remove_dir_all(&dir);
}
