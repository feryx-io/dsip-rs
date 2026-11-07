//! A device registering with its mailbox to be woken for messages, through the messenger's own API (W§4.2; the
//! mailbox's owner operation, spec-gap 176): the mailbox advertises waking, takes a registration naming it, refuses one
//! naming another waker, and ends one removed. `tests/wake.rs` has the wakes a registration brings.
//!
//! Spec: W§4.2, W§4.4, M§4.1.

use dsip_core::keys::KeyPair;
use dsip_mailbox::{MailboxConfig, MailboxServer};
use dsip_messaging_device::MemoryStore;
use dsip_messenger::{Config, Engine, Host, Messenger, Output};
use dsip_testkit::{push, PushGateway};
use dsip_transport::identity::Identity;
use dsip_transport::now_s;
use dsip_transport::wake::{enrol, Answer};
use serde_json::{json, Value};

struct Quiet;

impl Host<MemoryStore> for Quiet {
    async fn output(&mut self, _engine: &Engine<MemoryStore>, _out: Output) {}
}

/// A mailbox serving any identity, waking through `gw`, and Bob's device bound to it.
async fn bound(tag: &str, gw: &PushGateway) -> (Messenger<MemoryStore>, String, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("dsip-messenger-wake-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = dsip_transport::tls::ensure_self_signed(&dir, &["127.0.0.1".into(), "localhost".into()]).unwrap();
    let tls = dsip_transport::tls::acceptor(&cert, &key).unwrap();
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("wss://127.0.0.1:{}/dsip", tcp.local_addr().unwrap().port());
    let mut cfg = MailboxConfig::new(dir.join("mailbox"), uri.replace("wss://", "https://").replace("/dsip", "/blobs"));
    cfg.serve_any = Some(4);
    cfg.wake = Some(gw.waker());
    let server = MailboxServer::open(cfg).unwrap();
    server.spawn_tasks();
    let did = server.did().to_string();
    tokio::spawn(async move { server.serve_tls(tcp, tls).await });

    let id = Identity::init(&dir.join("bob"), "Bob", None, None).unwrap();
    let engine_identity = dsip_messenger::engine_identity(&id.meta.identity, &id.device, id.identity_key().unwrap(), &id.delegation, "Bob");
    let engine = Engine::open(&engine_identity, &did, &uri, MemoryStore::default(), &Value::Null, now_s() as f64).unwrap();
    let cfg = Config { identity: id.meta.identity.clone(), device: id.device.clone(), delegation: id.delegation.clone(), mailbox: (did.clone(), uri),
                       resolver_files: vec![], ca: Some(cert), media_dir: dir.join("media"), host_key: "test".into() };
    let mut mx = Messenger::new(engine, cfg, vec![]).unwrap();
    mx.connect(&mut Quiet).await.unwrap();
    (mx, did, dir)
}

/// A registration for `waker`, enrolled at `gw`.
async fn registration(gw: &PushGateway, waker: &str) -> Value {
    let wake_key = KeyPair::generate();
    let handle = enrol(&gw.client, &gw.did, &wake_key, "fcm", push::APP, "fcm-token-bob", None).await.expect("enrolled");
    dsip_wake::registration(&wake_key, waker, &gw.did, &handle, now_s())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_device_registers_with_its_mailbox_and_removes_it() {
    let gw = PushGateway::start().await;
    let (mut mx, mailbox, dir) = bound("register", &gw).await;
    assert_eq!(mx.mailbox_wake().map(|w| w["profiles"].clone()), Some(json!(["wake/0.1"])));
    let reg = registration(&gw, &mailbox).await;
    assert_eq!(mx.wake_register(&mut Quiet, reg, None).await.unwrap(), Answer::Accepted { handle: None });
    assert_eq!(mx.wake_remove(&mut Quiet).await.unwrap(), Answer::Accepted { handle: None });
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registration_naming_another_waker_is_refused_by_the_mailbox() {
    let gw = PushGateway::start().await;
    let (mut mx, _mailbox, dir) = bound("mismatch", &gw).await;
    let reg = registration(&gw, "did:web:another.mailbox.example").await;
    let answer = mx.wake_register(&mut Quiet, reg, None).await.unwrap();
    assert!(matches!(&answer, Answer::Refused { reason, .. } if reason == "wake.waker-mismatch"), "{answer:?}");
    let _ = std::fs::remove_dir_all(dir);
}
