//! The messaging device as a library: opened over any store, its state taken back (a browser's old message keys made
//! again), the
//! Recording Profile's rule for a recorder sibling, and the events a host renders from.
//!
//! Spec: M§5.4 (state kept with the MLS state, spec-gap 44), M§7.1 (the personal group), M§12.3 (a new device joins
//! the personal group first), C§5 (a recorder device joins conversations only; a recorded conversation is rendered),
//! M§6.5 (a commit that lost a conflict is re-proposed), M§9.4 (an outage), M§13.3 (call events), M§5.3 and M§9.3 (a host
//! that waits for every deposit's answer, and deposits them again on a new binding without syncing).

use serde_json::{json, Value};

use dsip_core::delegation::delegation_payload;
use dsip_core::envelope::{sign, Envelope};
use dsip_core::keys::KeyPair;
use dsip_messaging::wire;
use dsip_messaging_device::messenger::Messenger;
use dsip_messaging_device::{MemoryStore, ReceiptPolicy};
use dsip_mls::Device;

const NOW: i64 = 1_790_000_000;
const PLAIN: &[&str] = &["dsip.signaling", "dsip.messaging"];
const RECORDER: &[&str] = &["dsip.signaling", "dsip.messaging", "dsip.record"];

fn delegation(identity: &KeyPair, device: &KeyPair, caps: &[&str]) -> dsip_core::envelope::Envelope {
    sign(&delegation_payload(&identity.did(), &device.did(), NOW - 3600, NOW + 7 * 86400, caps), identity, &identity.kid())
}

fn identity_json(identity: &KeyPair, device: &KeyPair) -> String {
    json!({"identity": identity.did(), "display_name": "Alice", "device_seed_hex": hex(&device.seed()),
           "controller_seed_hex": hex(&identity.seed()), "delegation": delegation(identity, device, PLAIN).frame()}).to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One KeyPackage of `device`, a device of `identity` with `caps`, base64url.
fn kp(identity: &KeyPair, device: &KeyPair, caps: &[&str]) -> String {
    let e = delegation(identity, device, caps);
    let d = Device::new(device.clone(), format!("{}.{}.{}", e.protected, e.payload, e.signature));
    dsip_core::b64::encode(&d.key_package().unwrap())
}

/// A `key-packages` answer holding one KeyPackage of `device`, a device of `identity` with `caps`.
fn key_packages(identity: &KeyPair, device: &KeyPair, caps: &[&str]) -> Value {
    json!({"type": "key-packages", "key_packages": [kp(identity, device, caps)]})
}

#[test]
fn opened_over_any_store() {
    let (alice, phone) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"));
    let id = identity_json(&alice, &phone);
    let mut m = Messenger::open(&id, "did:key:mbx", "wss://mbx.example/dsip", MemoryStore::default(), &Value::Null,
                                NOW as f64).unwrap();
    m.create_personal(NOW as f64).unwrap();
    let personal = m.personal().unwrap();

    // what it keeps comes back: the personal group, and the MLS group under it from the same store
    let state = m.state();
    assert_eq!(state["personal"], json!(personal));
    assert_eq!(state["convs"][&personal]["kind"], "personal");

    // the browser's record is that state with its MLS storage, and opens as the same device
    let mut browser = Messenger::new(&id, "did:key:mbx", "wss://mbx.example/dsip", None, NOW as f64).unwrap();
    browser.create_personal(NOW as f64).unwrap();
    let record = browser.save();
    let saved: Value = serde_json::from_str(&record).unwrap();
    assert_eq!(saved["state"], browser.state());
    let reopened = Messenger::new(&id, "did:key:mbx", "wss://mbx.example/dsip", Some(record), NOW as f64).unwrap();
    assert_eq!(reopened.personal(), browser.personal());
    assert_eq!(reopened.state()["convs"], browser.state()["convs"], "the group reloads from the saved MLS storage");

    // a message the browser saved keyed without its sender (`conversation:id`) is keyed with it (M§8.5)
    let mut saved: Value = serde_json::from_str(&reopened.save()).unwrap();
    let obj = json!({"object": "content", "conversation": "c", "sender": alice.did(), "id": "x", "text": "hi"});
    saved["state"]["messages"] = json!([{"group": personal, "key": "c:x", "sender": alice.did(), "object": obj, "seq": 1, "mine": true}]);
    let old = Messenger::new(&id, "did:key:mbx", "wss://mbx.example/dsip", Some(saved.to_string()), NOW as f64).unwrap();
    assert_eq!(old.state()["messages"][0]["key"], json!(format!("c|{}|x", alice.did())));
}

#[test]
fn a_recorder_sibling_never_joins_the_personal_group() {
    let (alice, phone) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"));
    let mut m = Messenger::new(&identity_json(&alice, &phone), "did:key:mbx", "wss://mbx.example/dsip", None, NOW as f64).unwrap();
    m.create_personal(NOW as f64).unwrap();
    let personal = m.personal().unwrap();

    let recorder = KeyPair::from_fixture_name("alice-recorder");
    let err = m.add_device(&personal, &recorder.did(), &key_packages(&alice, &recorder, RECORDER), NOW as f64).unwrap_err();
    assert!(err.0.contains("is a recorder device"), "{err}");

    // a plain sibling is proposed (M§12.3)
    let laptop = KeyPair::from_fixture_name("alice-laptop");
    assert!(m.add_device(&personal, &laptop.did(), &key_packages(&alice, &laptop, PLAIN), NOW as f64).is_ok());
}

/// A mailbox that hosts every group and accepts everything: each deposit gets the next seq (M§5.3).
struct Hub {
    key: KeyPair,
    seq: i64,
}

impl Hub {
    fn new() -> Hub {
        Hub { key: KeyPair::from_fixture_name("mailbox"), seq: 0 }
    }

    fn did(&self) -> String {
        self.key.did()
    }

    /// Send what the device returned, answer it, and feed the answers back until nothing more is sent: the events.
    fn drive(&mut self, m: &mut Messenger, out: impl serde::Serialize) -> Vec<Value> {
        let mut events = vec![];
        let mut queue: Vec<Value> = self::events(out);
        while let Some(e) = (!queue.is_empty()).then(|| queue.remove(0)) {
            let frame = match (&e, e.get("send")) {
                (Value::String(f), _) => f.clone(),
                (_, Some(Value::String(f))) if !f.is_empty() => f.clone(),
                _ => {
                    events.push(e);
                    continue;
                }
            };
            let env = Envelope::from_frame(&frame).unwrap();
            let p = wire::payload_of(&env).unwrap();
            let extra = if p["type"] == "deposit" && p["class"] != "archive" {
                self.seq += 1;
                json!({"seq": self.seq})
            } else {
                json!({})
            };
            let reply = wire::accepted(&self.key, p["from"].as_str().unwrap(), NOW, p["id"].as_str().unwrap(), extra);
            queue.extend(self::events(m.inbound(&reply.frame(), NOW as f64)));
        }
        events
    }
}

fn ui<'a>(events: &'a [Value], kind: &str) -> Vec<&'a Value> {
    events.iter().filter(|e| e["ui"] == kind).collect()
}

#[test]
fn rekey_remove_device_and_rotate_the_archive_key() {
    let (alice, phone, laptop) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"),
                                  KeyPair::from_fixture_name("alice-laptop"));
    let mut hub = Hub::new();
    let mut m = Messenger::open(&identity_json(&alice, &phone), &hub.did(), "wss://mbx.example/dsip", MemoryStore::default(), &Value::Null,
                                NOW as f64).unwrap();
    let out = m.create_personal(NOW as f64).unwrap();
    let ev = hub.drive(&mut m, &out);
    assert_eq!(ui(&ev, "archive_key_created").len(), 1, "{ev:?}");
    let personal = m.personal().unwrap();

    // a sibling joins the personal group (M§12.3)
    let out = json!([{"send": m.add_device(&personal, &laptop.did(), &key_packages(&alice, &laptop, PLAIN), NOW as f64).unwrap()}]);
    let ev = hub.drive(&mut m, &out);
    assert_eq!(ui(&ev, "committed")[0]["device"], json!(laptop.did()));
    let epoch = ui(&ev, "committed")[0]["epoch"].as_u64().unwrap();

    // its leaf still verifies: only its own identity may remove it as lapsed (M§7.3)
    assert!(m.remove_lapsed_leaf(&personal, &laptop.did(), NOW as f64).unwrap_err().0.contains("still verifies"));

    // a rekey moves the epoch
    let out = json!([{"send": m.rekey(&personal, NOW as f64).unwrap()}]);
    let ev = hub.drive(&mut m, &out);
    assert_eq!(ui(&ev, "committed")[0]["epoch"], json!(epoch + 1));

    // removed by credential, then a new archive key, sent after the merge: in the epoch the laptop is not in (M§12.4)
    let out = m.remove_device(&laptop.did(), NOW as f64).unwrap();
    let ev = hub.drive(&mut m, &out);
    let committed = ev.iter().position(|e| e["ui"] == "committed").expect("committed");
    let created = ev.iter().position(|e| e["ui"] == "archive_key_created").expect("a new archive key");
    assert!(committed < created, "{ev:?}");
    assert_eq!(m.state()["archive_keys"].as_object().unwrap().len(), 2);
    assert!(m.remove_device(&laptop.did(), NOW as f64).unwrap_err().0.contains("no group holds"));
}

#[test]
fn activity_sealed_opened_and_attributed() {
    let (alice, phone, bob, bob_phone) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"),
                                          KeyPair::from_fixture_name("bob"), KeyPair::from_fixture_name("bob-phone"));
    let mut hub = Hub::new();
    let mut m = Messenger::open(&identity_json(&alice, &phone), &hub.did(), "wss://mbx.example/dsip", MemoryStore::default(), &Value::Null,
                                NOW as f64).unwrap();
    let out = m.create_direct(&bob.did(), &key_packages(&bob, &bob_phone, PLAIN), None, NOW as f64).unwrap();
    let ev = hub.drive(&mut m, &out);
    let gid = ui(&ev, "committed")[0]["group"].as_str().unwrap().to_string();

    // not disclosed: nothing goes out (M§10.5)
    let ev = events(m.activity(&gid, "typing", "active", NOW as f64));
    assert_eq!(ev[0]["ui"], "activity_not_sent", "{ev:?}");

    // disclosed: a sealed ephemeral deposit (M§11.1)
    m.set_receipt_policy(ReceiptPolicy { activity: true, ..ReceiptPolicy::default() }, NOW as f64);
    let ev = events(m.activity(&gid, "typing", "active", NOW as f64 + 6.0));
    let frame = ev.iter().find_map(|e| e["send"].as_str()).expect("a deposit");
    let dep = wire::payload_of(&Envelope::from_frame(frame).unwrap()).unwrap();
    assert_eq!((dep["class"].as_str(), dep["group"].as_str()), (Some("ephemeral"), Some(gid.as_str())));
    assert!(dep["sealed"].is_string() && dep.get("mls").is_none());

    // pushed back, it opens under the epoch's key and is attributed to a member's device (M§11.1)
    // a pushed ephemeral item: never stored, so no cursor (M§11.2, spec-gap 49)
    let item = json!({"class": "ephemeral", "group": gid, "sealed": dep["sealed"], "expires_at": NOW + 16});
    let push = wire::items(&hub.key, &phone.did(), NOW, None, vec![item.clone()], Value::Null);
    let ev = events(m.inbound(&push.frame(), NOW as f64 + 6.0));
    let shown = ui(&ev, "activity");
    assert!(!shown.is_empty(), "{ev:?}");
    assert_eq!((shown[0]["from"].as_str(), shown[0]["activity"].as_str()), (Some(alice.did().as_str()), Some("typing")), "{ev:?}");

    // tampered: dropped
    let mut bad = item;
    bad["sealed"] = json!(dsip_core::b64::encode(b"not sealed for this epoch at all"));
    let push = wire::items(&hub.key, &phone.did(), NOW, None, vec![bad], Value::Null);
    let ev = events(m.inbound(&push.frame(), NOW as f64 + 7.0));
    assert_eq!(ui(&ev, "dropped").len(), 1, "{ev:?}");
}

#[test]
fn first_contact_and_any_object_sent() {
    let (alice, phone, bob, bob_phone) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"),
                                          KeyPair::from_fixture_name("bob"), KeyPair::from_fixture_name("bob-phone"));
    let mut hub = Hub::new();
    let mut m = Messenger::open(&identity_json(&alice, &phone), &hub.did(), "wss://mbx.example/dsip", MemoryStore::default(), &Value::Null,
                                NOW as f64).unwrap();

    // an introduction sealed to bob's key agreement key (a did:key's, M§6.9), announced to our own mailbox first
    let intro: Value = serde_json::to_value(m.introduce(&bob.did(), "lunch?", false, NOW as f64).unwrap()).unwrap();
    let notice = wire::payload_of(&Envelope::from_frame(intro["send"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(notice["introductions_sent"], json!([intro["id"]]));
    let deposit = m.first_contact_frame("did:key:bobs-mailbox", "introduction", &bob.did(), intro["envelope"].as_str().unwrap(), NOW as f64);
    let item = json!({"cursor": "c1", "class": "introduction", "envelope": wire::payload_of(&Envelope::from_frame(&deposit).unwrap()).unwrap()["envelope"]});
    // bob's side reads it as a request, its purpose opened with his identity key
    let resolver = dsip_core::did::StaticResolver::default();
    let got = dsip_messaging_device::first_contact::received(&item, &bob.did(), &dsip_core::envelope::Context::new(NOW, &resolver), NOW, Some(&bob.seed()));
    assert!(matches!(got, dsip_messaging_device::first_contact::Received::Request(ref r) if r.purpose.as_deref() == Some("lunch?")), "{got:?}");

    // a grant, and the release that is not kept pending (it would release the next binding too)
    let grant = m.grant(&bob.did(), None, NOW as f64);
    assert_eq!(grant.split('.').count(), 3);
    assert!(m.accept_request("nope", NOW as f64).is_err());
    let release = wire::payload_of(&Envelope::from_frame(&m.release(NOW as f64)).unwrap()).unwrap();
    assert_eq!(release["release"], true);

    // any object goes out under an item id the hub's `sent` names
    let out = m.create_direct(&bob.did(), &key_packages(&bob, &bob_phone, PLAIN), None, NOW as f64).unwrap();
    let ev = hub.drive(&mut m, &out);
    let gid = ui(&ev, "committed")[0]["group"].as_str().unwrap().to_string();
    let conversation = m.state()["convs"][&gid]["conversation"].clone();
    let obj = json!({"object": "content", "id": "01J0000000000000000000EVNT", "conversation": conversation, "sender": alice.did(),
                     "sent_at": NOW, "kind": "event", "event": {"source": "ups-1"}});
    let sent: Value = serde_json::to_value(m.send(&gid, &obj, NOW as f64).unwrap()).unwrap();
    let item = sent["item"].as_str().unwrap().to_string();
    let ev = hub.drive(&mut m, json!([{"send": sent["send"]}]));
    assert_eq!(ui(&ev, "sent")[0]["item"], json!(item));
}

#[test]
fn messages_deleted_on_this_device_stay_deleted() {
    let (alice, phone, bob, bob_phone) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"),
                                          KeyPair::from_fixture_name("bob"), KeyPair::from_fixture_name("bob-phone"));
    let mut hub = Hub::new();
    let id = identity_json(&alice, &phone);
    let mut m = Messenger::open(&id, &hub.did(), "wss://mbx.example/dsip", MemoryStore::default(), &Value::Null, NOW as f64).unwrap();
    let out = m.create_direct(&bob.did(), &key_packages(&bob, &bob_phone, PLAIN), None, NOW as f64).unwrap();
    let ev = hub.drive(&mut m, &out);
    let gid = ui(&ev, "committed")[0]["group"].as_str().unwrap().to_string();
    for text in ["one", "two", "three"] {
        m.send_text(&gid, text, NOW as f64).unwrap();
    }
    let texts = |m: &Messenger| m.thread(&gid).iter().map(|x| x["object"]["text"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(texts(&m), ["one", "two", "three"]);

    let two = m.thread(&gid)[1]["object"]["id"].as_str().unwrap().to_string();
    assert!(m.forget_message(&gid, &two));
    assert!(!m.forget_message(&gid, &two), "already gone");
    assert!(!m.forget_message("no-such-group", "x"));
    assert_eq!(texts(&m), ["one", "three"]);

    // kept deleted across a restart: the state says so, and the shown set it rebuilds holds the key
    let state = m.state();
    assert_eq!(state["forgotten"].as_array().map(Vec::len), Some(1));
    let mut browser = Messenger::new(&id, &hub.did(), "wss://mbx.example/dsip", None, NOW as f64).unwrap();
    let mut saved: Value = serde_json::from_str(&browser.save()).unwrap();
    saved["state"]["forgotten"] = state["forgotten"].clone();
    browser = Messenger::new(&id, &hub.did(), "wss://mbx.example/dsip", Some(saved.to_string()), NOW as f64).unwrap();
    assert_eq!(browser.state()["forgotten"], state["forgotten"]);

    // the whole thread; the conversation stays
    assert_eq!(m.forget_thread(&gid), 2);
    assert!(m.thread(&gid).is_empty());
    assert_eq!(m.state()["forgotten"].as_array().map(Vec::len), Some(3));
    assert!(m.conversations(NOW as f64).iter().any(|c| c.group == gid));
    m.send_text(&gid, "four", NOW as f64).unwrap();
    assert_eq!(texts(&m), ["four"]);
}

/// The deposit id of the frame `send`.
fn deposit_id(send: &str) -> String {
    wire::payload_of(&Envelope::from_frame(send).unwrap()).unwrap()["id"].as_str().unwrap().to_string()
}

/// What a step returned, as the JSON a host reads.
fn events(out: impl serde::Serialize) -> Vec<Value> {
    serde_json::from_value(serde_json::to_value(out).unwrap()).unwrap()
}

#[test]
fn events_carry_what_a_host_prints() {
    let (alice, phone, bob, bob_phone, bob_rec) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"),
        KeyPair::from_fixture_name("bob"), KeyPair::from_fixture_name("bob-phone"), KeyPair::from_fixture_name("bob-recorder"));
    let mut hub = Hub::new();
    let mut m = Messenger::open(&identity_json(&alice, &phone), &hub.did(), "wss://mbx.example/dsip", MemoryStore::default(), &Value::Null,
                                NOW as f64).unwrap();
    let out = m.create_personal(NOW as f64).unwrap();
    hub.drive(&mut m, &out);

    // the commit says what it did; the conversation is recorded by Bob's recorder, which Alice has to accept (C§5)
    let kps = json!({"type": "key-packages", "key_packages": [kp(&bob, &bob_phone, PLAIN), kp(&bob, &bob_rec, RECORDER)]});
    let out = m.create_direct(&bob.did(), &kps, None, NOW as f64).unwrap();
    let ev = hub.drive(&mut m, &out);
    let committed = ui(&ev, "committed")[0].clone();
    assert_eq!((committed["op"]["op"].as_str(), committed["op"]["peer"].as_str()), (Some("add"), Some(bob.did().as_str())));
    let gid = committed["group"].as_str().unwrap().to_string();
    let rec = ui(&ev, "recording");
    assert_eq!(rec.len(), 1, "{ev:?}");
    assert_eq!(rec[0]["new"], json!([{"device": bob_rec.did(), "subject": bob.did(), "own": false}]));
    assert_eq!((rec[0]["ended"].as_bool(), rec[0]["may_send"].as_bool()), (Some(false), Some(false)));
    assert!(m.send_text(&gid, "hi", NOW as f64).is_err());
    let accepted: Value = serde_json::to_value(m.accept_recording(&gid, NOW as f64).unwrap()).unwrap();
    let ev = hub.drive(&mut m, &accepted["frames"]);
    assert!(ui(&ev, "recording").is_empty(), "the same recorders: nothing new to render {ev:?}");

    // a rekey that lost a conflict: which commit, at which epoch; re-proposed after the sync while still needed (M§6.5)
    let frame = m.rekey(&gid, NOW as f64).unwrap();
    let refusal = wire::error(&hub.key, &phone.did(), NOW, Some(&deposit_id(&frame)), "mailbox.commit-conflict", None);
    let ev = events(m.inbound(&refusal.frame(), NOW as f64));
    let conflict = ui(&ev, "conflict")[0].clone();
    assert_eq!((conflict["op"]["op"].as_str(), conflict["epoch"].as_u64()), (Some("update"), committed["epoch"].as_u64()), "{ev:?}");
    let caught_up = wire::items(&hub.key, &phone.did(), NOW, Some("01J0000000000000000000SYNC"), vec![], Value::Null);
    let ev = events(m.inbound(&caught_up.frame(), NOW as f64));
    let again = ui(&ev, "repropose")[0].clone();
    assert_eq!((again["op"]["op"].as_str(), again["epoch"].as_u64()), (Some("update"), committed["epoch"].as_u64()), "{ev:?}");
    assert!(again["attempt"].as_u64().is_some());
    let ev = hub.drive(&mut m, &ev);
    assert_eq!(ui(&ev, "committed")[0]["op"]["op"], "update");

    // a missed call: the event sent, its item, and whether this identity had it already (M§13.3, spec-gap 63)
    let leg = json!({"session": "01K742SG00XZRF7H1Z8WN9CGAD", "peer": bob.did(), "alerted": true, "answered_here": false, "ended_by": "remote", "reason": ""});
    let r: Value = serde_json::to_value(m.call_ended_item(&serde_json::from_value(leg.clone()).unwrap(), NOW as f64).unwrap()).unwrap();
    assert_eq!((r["event"]["outcome"].as_str(), r["event"]["direction"].as_str(), r["fresh"].as_bool()), (Some("missed"), Some("inbound"), Some(true)));
    let ev = hub.drive(&mut m, json!([{"send": r["send"]}]));
    assert_eq!(ui(&ev, "sent")[0]["item"], r["item"]);
    let r: Value = serde_json::to_value(m.call_ended_item(&serde_json::from_value(leg.clone()).unwrap(), NOW as f64).unwrap()).unwrap();
    assert_eq!(r["fresh"], false, "already recorded");
    let unalerted = json!({"session": "01K742SG00XZRF7H1Z8WN9CGAE", "peer": bob.did(), "alerted": false, "ended_by": "remote"});
    let r: Value = serde_json::to_value(m.call_ended_item(&serde_json::from_value(unalerted.clone()).unwrap(), NOW as f64).unwrap()).unwrap();
    assert!(r["event"].is_null() && r["send"] == "");
    assert!(m.call_ended(&serde_json::from_value(unalerted.clone()).unwrap(), NOW as f64).unwrap().is_empty());

    // the hub is down: the retry names the item waiting, and its accepted says it went out after the outage (M§9.4)
    let sent: Value = serde_json::to_value(m.send(&gid, &json!({"object": "content", "id": "01J0000000000000000000DOWN",
        "conversation": m.state()["convs"][&gid]["conversation"], "sender": alice.did(), "sent_at": NOW, "kind": "text", "text": "down?"}),
        NOW as f64).unwrap()).unwrap();
    let down = wire::error(&hub.key, &phone.did(), NOW, Some(&deposit_id(sent["send"].as_str().unwrap())), "mailbox.hub-unreachable", None);
    let ev = events(m.inbound(&down.frame(), NOW as f64));
    let retry = ui(&ev, "hub_retry")[0].clone();
    assert_eq!(retry["item"], sent["item"], "{ev:?}");
    let later = NOW as f64 + retry["in"].as_f64().unwrap();
    let out = m.tick(later);
    let ev = hub.drive(&mut m, &out);
    let back = ui(&ev, "sent")[0].clone();
    assert_eq!((back["item"].clone(), back["after_outage"].as_bool()), (sent["item"].clone(), Some(true)), "{ev:?}");
}

#[test]
fn a_host_that_waits_for_its_commands_and_syncs_when_asked() {
    let (alice, phone, bob, bob_phone, bob_rec) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"),
        KeyPair::from_fixture_name("bob"), KeyPair::from_fixture_name("bob-phone"), KeyPair::from_fixture_name("bob-recorder"));
    let mut hub = Hub::new();
    let mut m = Messenger::open(&identity_json(&alice, &phone), &hub.did(), "wss://mbx.example/dsip", MemoryStore::default(), &Value::Null,
                                NOW as f64).unwrap();
    assert!(m.settled(), "nothing done yet");
    let out = m.create_personal(NOW as f64).unwrap();
    assert!(!m.settled(), "the GroupInfo awaits its answer (M§5.3)");
    hub.drive(&mut m, &out);
    assert!(m.settled(), "answered, and the archive key that followed too");

    // the devices an answer would add, as the pinned rule picks them (C§5); the commit counts them
    let kps = json!({"type": "key-packages", "key_packages": [kp(&bob, &bob_phone, PLAIN), kp(&bob, &bob_rec, RECORDER)]});
    let devices: Value = serde_json::to_value(m.key_package_devices(&bob.did(), &kps, NOW as f64).unwrap()).unwrap();
    assert_eq!(devices, json!([{"device": bob_phone.did(), "recorder": false}, {"device": bob_rec.did(), "recorder": true}]));
    let refused = json!({"type": "error", "reason": "mailbox.first-contact-required"});
    assert!(m.key_package_devices(&bob.did(), &refused, NOW as f64).unwrap_err().0.contains("first-contact-required"));
    let out = m.create_direct(&bob.did(), &kps, None, NOW as f64).unwrap();
    let ev = hub.drive(&mut m, &out);
    let committed = ui(&ev, "committed")[0].clone();
    assert_eq!(committed["op"]["devices"], 2, "{committed}");
    let gid = committed["group"].as_str().unwrap().to_string();
    let receipts: Value = m.receipt_state(&gid);
    assert!(receipts["read_through"].is_object(), "{receipts}");
    assert_eq!(m.receipt_state("no-such-group"), Value::Null);
    assert_eq!(m.successor(&gid), None);

    // a commit in flight is unsettled; a new binding deposits it again without a sync, unless the host asks for one
    m.rekey(&gid, NOW as f64).unwrap();
    assert!(!m.settled());
    let types = |frames: Vec<String>| -> Vec<String> {
        frames.iter()
            .map(|f| wire::payload_of(&Envelope::from_frame(f).unwrap()).unwrap()["type"].as_str().unwrap().to_string()).collect()
    };
    assert_eq!(types(m.rebind(NOW as f64)), ["deposit"], "the same commit again (M§9.3), no sync");
    assert_eq!(types(m.on_bound(NOW as f64)), ["deposit", "sync"]);

    // refused for a conflict: unsettled until the sync shows the commit is still needed and it is proposed again
    let pending = m.rebind(NOW as f64);
    let refusal = wire::error(&hub.key, &phone.did(), NOW, Some(&deposit_id(&pending[0])), "mailbox.commit-conflict", None);
    let ev = events(m.inbound(&refusal.frame(), NOW as f64));
    assert!(!ui(&ev, "conflict").is_empty() && !m.settled(), "{ev:?}");
    let caught_up = wire::items(&hub.key, &phone.did(), NOW, Some("01J0000000000000000000SYNC"), vec![], Value::Null);
    let ev = events(m.inbound(&caught_up.frame(), NOW as f64));
    assert!(!ui(&ev, "repropose").is_empty(), "{ev:?}");
    let ev = hub.drive(&mut m, &ev);
    assert_eq!(ui(&ev, "committed")[0]["op"]["op"], "update");
    assert!(m.settled(), "{ev:?}");
}
