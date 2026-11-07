//! Messaging between two `did:key` identities, each with its own mailbox, found through reachability hints alone: no
//! DID documents anywhere. Each device enrols at its mailbox (spec-gap 115) and publishes a hint naming it on a hints
//! node (DHT Hints Profile §10); Alice's device finds Bob's mailbox through Bob's hint to fetch his KeyPackages, her
//! mailbox (the conversation's hub) finds it the same way to fan the welcome out, and her text reaches Bob.
//!
//! Spec: M§4.2 (a mailbox found through a hint, for an identity with no document), §8.1 rule 6, §8.3 (the winning
//! record), M§5.5, M§7.2, M§14.2 (the grant Bob gave Alice), DHT Hints Profile §2, §10.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use dsip_mailbox::{MailboxConfig, MailboxServer};
use dsip_messaging_device::{Event, MemoryStore, Ui};
use dsip_messenger::{Config, Engine, Host, Messenger, Output};
use dsip_transport::hints::{HintsClient, Published};
use dsip_transport::identity::Identity;
use dsip_transport::now_s;

/// A hints node's HTTP API, reduced to what this test needs: the latest frame per subject. A real node verifies what
/// it stores; here every reader verifies (§8.3), which is what the test is about.
async fn hints_node() -> String {
    let held: Arc<Mutex<HashMap<String, String>>> = Arc::default();
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", tcp.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = tcp.accept().await else { return };
            let held = held.clone();
            tokio::spawn(async move {
                let mut buf = vec![];
                let mut chunk = [0u8; 8192];
                // one request: the headers, then a body of content-length bytes
                let (head, body) = loop {
                    let n = s.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(i) = text.find("\r\n\r\n") {
                        let len = text[..i].lines().find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                        if buf.len() >= i + 4 + len {
                            break (text[..i].to_string(), String::from_utf8_lossy(&buf[i + 4..i + 4 + len]).to_string());
                        }
                    }
                };
                let line = head.lines().next().unwrap_or("").to_string();
                let (status, reply) = if let Some(did) = line.strip_prefix("GET /dsip/v1/hints/").and_then(|r| r.split(' ').next()) {
                    match held.lock().unwrap().get(did) {
                        Some(f) => ("200 OK", json!({"hints": [f]}).to_string()),
                        None => ("404 Not Found", "{}".to_string()),
                    }
                } else if line.starts_with("POST /dsip/v1/hints ") {
                    let subject = dsip_core::envelope::Envelope::from_frame(&body).ok()
                        .and_then(|e| dsip_core::b64::decode(&e.payload))
                        .and_then(|p| serde_json::from_slice::<Value>(&p).ok())
                        .and_then(|p| p["subject"].as_str().map(String::from));
                    match subject {
                        Some(sub) => {
                            held.lock().unwrap().insert(sub, body);
                            ("202 Accepted", json!({"acknowledged": 0}).to_string())
                        }
                        None => ("400 Bad Request", "{}".to_string()),
                    }
                } else {
                    ("404 Not Found", "{}".to_string())
                };
                let resp = format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}", reply.len());
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    url
}

/// A mailbox serving any identity that enrols, on 127.0.0.1 under the shared test certificate, finding other
/// identities' mailboxes through `hints`.
async fn mailbox(dir: &std::path::Path, name: &str, tls: &tokio_rustls::TlsAcceptor, hints: &str) -> (String, String) {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("wss://127.0.0.1:{}/dsip", tcp.local_addr().unwrap().port());
    let mut cfg = MailboxConfig::new(dir.join(name), format!("{}/blobs", uri.replace("wss://", "https://").trim_end_matches("/dsip")));
    cfg.serve_any = Some(4);
    cfg.hints_nodes = vec![hints.to_string()];
    cfg.ca = Some(dir.join("cert.pem"));
    let server = MailboxServer::open(cfg).unwrap();
    server.spawn_tasks();
    let did = server.did().to_string();
    let acceptor = tls.clone();
    tokio::spawn(async move { server.serve_tls(tcp, acceptor).await });
    (did, uri)
}

/// What a test device hears.
#[derive(Default)]
struct Ears {
    joined: Vec<String>,
    texts: Vec<(String, String)>,
    /// Everything else, to show when a step does not come.
    other: Vec<String>,
}

impl Host<MemoryStore> for Ears {
    async fn output(&mut self, _engine: &Engine<MemoryStore>, out: Output) {
        match out {
            Output::Event(Event::Ui(Ui::Joined { group, .. })) => self.joined.push(group),
            Output::Event(Event::Ui(Ui::Message { from, object, .. })) if object["kind"] == "text" => {
                self.texts.push((from, object["text"].as_str().unwrap_or("").to_string()))
            }
            other => self.other.push(format!("{other:?}").chars().take(300).collect()),
        }
    }
}

/// A `did:key` device bound to its mailbox, with KeyPackages uploaded, its hint published, syncing live.
async fn device(dir: &std::path::Path, name: &str, mailbox: (String, String), hints: &str) -> (Messenger<MemoryStore>, Ears, String) {
    let id = Identity::init(&dir.join(name), name, None, None).unwrap();
    let identity = id.meta.identity.clone();
    let now = now_s();
    let engine_identity = dsip_messenger::engine_identity(&identity, &id.device, id.identity_key().unwrap(), &id.delegation, name);
    let engine = Engine::open(&engine_identity, &mailbox.0, &mailbox.1, MemoryStore::default(), &Value::Null, now as f64).unwrap();
    let cfg = Config { identity: identity.clone(), device: id.device.clone(), delegation: id.delegation.clone(), mailbox: mailbox.clone(),
                       resolver_files: vec![], ca: Some(dir.join("cert.pem")), media_dir: dir.join(name).join("media"), host_key: "test".into() };
    let pem = std::fs::read(dir.join("cert.pem")).unwrap();
    let mut mx = Messenger::new(engine, cfg, vec![]).unwrap().with_hints(HintsClient::new(vec![hints.into()], Some(&pem)).unwrap());
    let mut ears = Ears::default();
    mx.connect(&mut ears).await.unwrap();
    let frame = mx.engine_mut().key_packages_frame(2, now as f64).unwrap();
    mx.send_frame(&mut ears, &frame).await.unwrap();
    mx.settle(&mut ears).await;
    mx.sync(&mut ears, true).await.unwrap();
    mx.settle(&mut ears).await;
    // M§4.2: a did:key identity's mailbox is in its hint, published once the mailbox has bound it
    let advertised = dsip_transport::hints::endpoints(None, Some((&mailbox.0, &mailbox.1)));
    let hint = dsip_transport::hints::reachability(&identity, &id.device, &id.delegation, &advertised, now, now, 3600);
    let published = HintsClient::new(vec![hints.into()], None).unwrap().publish(&hint).await;
    assert!(matches!(published[0].1, Published::Accepted { .. }), "{published:?}");
    (mx, ears, identity)
}

/// Pump `mx` until `done` holds of what it heard.
async fn pump(mx: &mut Messenger<MemoryStore>, ears: &mut Ears, what: &str, done: impl Fn(&Ears) -> bool) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while !done(ears) {
            tokio::select! {
                Some(frame) = mx.recv() => mx.received(ears, frame).await,
                _ = tokio::time::sleep(Duration::from_millis(200)) => mx.tick(ears).await,
            }
            mx.settle(ears).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}: joined {:?}, texts {:?}, other {:#?}", ears.joined, ears.texts, ears.other));
}

#[tokio::test(flavor = "multi_thread")]
async fn did_key_identities_message_through_mailboxes_found_by_their_hints() {
    let dir = std::env::temp_dir().join(format!("dsip-discovery-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = dsip_transport::tls::ensure_self_signed(&dir, &["127.0.0.1".into(), "localhost".into()]).unwrap();
    let tls = dsip_transport::tls::acceptor(&cert, &key).unwrap();
    let hints = hints_node().await;
    let a_box = mailbox(&dir, "mailbox-a", &tls, &hints).await;
    let b_box = mailbox(&dir, "mailbox-b", &tls, &hints).await;
    let (mut alice, mut a_ears, _alice_did) = device(&dir, "alice", a_box, &hints).await;
    let (mut bob, mut b_ears, bob_did) = device(&dir, "bob", b_box.clone(), &hints).await;

    // Alice's device finds Bob's mailbox through his hint (no document holds it)
    assert_eq!(alice.discover_mailbox(&bob_did).await.unwrap(), b_box);

    // Bob lets Alice write (M§14.2), and she creates a direct conversation with him
    let now = now_s() as f64;
    let grant = bob.engine_mut().grant(&alice.config().identity.clone(), None, now);
    alice.engine_mut().set_grants(&BTreeMap::from([(bob_did.clone(), grant)]));
    let answer = alice.fetch_key_packages(&mut a_ears, &bob_did, None).await.unwrap();
    alice.engine_mut().key_package_devices(&bob_did, &answer, now).unwrap();
    let frames = alice.engine_mut().create_direct(&bob_did, &answer, None, now).unwrap();
    // the group the creation registers (M§6.6), as dsip-msg reads it
    let group = frames.first().and_then(|f| dsip_core::envelope::Envelope::from_frame(f).ok()).and_then(|e| dsip_mailbox::wire::payload_of(&e))
        .and_then(|p| p["groups"][0]["group"].as_str().map(String::from)).expect("a group");
    alice.send_frames(&mut a_ears, &frames).await.unwrap();
    alice.settle(&mut a_ears).await;
    // her mailbox, the hub, fans the welcome out to Bob's, found through the same hint
    pump(&mut bob, &mut b_ears, "Bob joins", |e| e.joined.contains(&group)).await;

    let conversation = alice.engine().conversations(now).into_iter().find(|c| c.group == group).unwrap().conversation;
    let obj = json!({"object": "content", "id": alice.engine_mut().new_id(now), "conversation": conversation, "sender": alice.config().identity,
                     "sent_at": now as i64, "purpose": "message", "kind": "text", "content_type": "text/plain", "text": "found you"});
    let sent = alice.engine_mut().send(&group, &obj, now).unwrap();
    alice.send_frame(&mut a_ears, &sent.send).await.unwrap();
    alice.settle(&mut a_ears).await;
    pump(&mut bob, &mut b_ears, "Bob reads it", |e| !e.texts.is_empty()).await;
    assert_eq!(b_ears.texts[0].1, "found you");
    let _ = std::fs::remove_dir_all(&dir);
}
