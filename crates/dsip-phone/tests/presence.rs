//! Presence between phones on the testkit's in-process relays: a grant issued in answer to an introduction that came
//! another way (as at a mailbox) and held by its grantee, a watch it admits, the relay's assertion and then a record
//! the watched device signed, a watch no grant admits, a watch through the relay a `did:key`'s hint names, and sealed
//! records: read with the keys a grant carried, and rotated when a grant is withdrawn.
//!
//! Spec: P§3 (records to the authority, verified by the subscriber), P§4, P§6 (private unless granted; a grant in
//! `claims` admits), §9.3, §19.4, M§14.1, §8.1 (a hint says where to try), P§7 (withdrawing a share), P§12.3–P§12.5
//! (keys in a grant, opening, rotation and re-granting).

use std::collections::BTreeMap;
use std::time::Duration;

use dsip_phone::{GrantRequest, Phone, Presence};
use dsip_testkit::Network;

async fn phone(net: &Network, name: &str) -> Phone {
    Phone::builder().identity(net.identity(name)).dialer(net.dialer()).build().await.expect("phone")
}

async fn sealing_phone(net: &Network, name: &str) -> Phone {
    Phone::builder().identity(net.identity(name)).dialer(net.dialer()).seal_presence().build().await.expect("phone")
}

/// Wait until `phone` shows a presence for `target` that `want` accepts.
async fn until(phone: &Phone, target: &str, what: &str, want: impl Fn(&Presence) -> bool) -> Presence {
    let mut rx = phone.presence();
    let got = tokio::time::timeout(dsip_testkit::TIMEOUT, async {
        loop {
            if let Some(p) = rx.borrow_and_update().get(target).filter(|p| want(p)) {
                return p.clone();
            }
            rx.changed().await.expect("the phone runs");
        }
    })
    .await;
    got.unwrap_or_else(|_| panic!("{what}: {:?}", phone.presence().borrow().clone()))
}

/// `grantor` answers an introduction from `grantee` with a grant that shares presence, and `grantee` holds it.
async fn grant(grantor: &Phone, grantee: &Phone) {
    let request = GrantRequest {
        introduction: dsip_core::ulid::Ulid::generate().to_string(),
        requester: grantee.identity().into(),
        scope: vec!["dsip.invite".into(), "dsip.message".into(), "dsip.subscribe".into()],
        valid_until: dsip_transport::now_s() + 86_400,
    };
    let frame = grantor.grant_request(request).await.unwrap().expect("a grant");
    assert!(grantee.hold_grant(&frame).await.unwrap(), "the grantee holds it");
}

#[tokio::test]
async fn a_granted_watcher_sees_the_relays_claim_then_the_record_the_device_signed() {
    let net = Network::new();
    let alice = phone(&net, "Alice").await;
    let bob = phone(&net, "Bob").await;
    grant(&bob, &alice).await;

    alice.watch(bob.identity()).await;
    // §9.3: bound, and no device of his has said more: his relay's claim
    let p = until(&alice, bob.identity(), "Bob's relay says he is there", |p| p.source == "assertion").await;
    assert_eq!(p.state, "available");

    bob.set_presence(Some("busy"));
    let p = until(&alice, bob.identity(), "Bob's busy record", |p| p.source == "record").await;
    assert_eq!((p.state.as_str(), p.token.as_str(), p.unreadable), ("busy", "busy", 0));

    alice.unwatch(bob.identity());
    tokio::time::timeout(dsip_testkit::TIMEOUT, async {
        while alice.presence().borrow().contains_key(bob.identity()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("nothing shown once unwatched");
}

#[tokio::test]
async fn presence_is_private_unless_granted() {
    let net = Network::new();
    let alice = phone(&net, "Alice").await;
    let bob = phone(&net, "Bob").await;
    bob.set_presence(Some("away"));
    // P§6: no grant of Bob's to present; the relay refuses, and nothing is shown
    alice.watch(bob.identity()).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(alice.presence().borrow().clone(), BTreeMap::new());
}

#[tokio::test]
async fn a_grant_is_held_only_by_its_grantee() {
    let net = Network::new();
    let (alice, bob, carol) = (phone(&net, "Alice").await, phone(&net, "Bob").await, phone(&net, "Carol").await);
    let request = GrantRequest {
        introduction: dsip_core::ulid::Ulid::generate().to_string(),
        requester: alice.identity().into(),
        scope: vec!["dsip.subscribe".into()],
        valid_until: dsip_transport::now_s() + 60,
    };
    let frame = bob.grant_request(request).await.unwrap().expect("a grant");
    assert!(!carol.hold_grant(&frame).await.unwrap(), "addressed to Alice");
    assert!(!alice.hold_grant("not.a.grant").await.unwrap());
    assert!(alice.hold_grant(&frame).await.unwrap());
}

#[tokio::test]
async fn a_did_key_bound_elsewhere_is_watched_at_the_relay_its_hint_names() {
    // §8.1: Bob has no document; his hint names his relay, which is not Alice's
    let (mine, theirs) = (Network::new(), Network::new());
    let node = dsip_testkit::hints_node().await;
    let hints = dsip_transport::hints::HintsClient::new(vec![node], None).unwrap();
    let bob_id = theirs.identity("Bob");
    let now = dsip_transport::now_s();
    let endpoints = dsip_transport::hints::endpoints(Some(theirs.url()), None);
    hints.publish(&dsip_transport::hints::reachability(&bob_id.meta.identity, &bob_id.device, &bob_id.delegation, &endpoints, now, now, 3600)).await;
    let bob = Phone::builder().identity(bob_id).relay(theirs.url()).dialer(theirs.dialer()).build().await.unwrap();
    let peers = Network::peers(&[&mine, &theirs]);
    let alice = Phone::builder()
        .identity(mine.identity("Alice"))
        .relay(mine.url())
        .dialer(mine.dialer())
        .hints(hints)
        .configure(move |c| c.peer_dialer = Some(peers))
        .build()
        .await
        .unwrap();
    grant(&bob, &alice).await;

    bob.set_presence(Some("dnd"));
    alice.watch(bob.identity()).await;
    let p = until(&alice, bob.identity(), "Bob's record, through his relay", |p| p.source == "record").await;
    assert_eq!(p.state, "dnd");
}

#[tokio::test]
async fn sealed_records_are_read_with_the_keys_a_grant_carried() {
    let net = Network::new();
    let alice = phone(&net, "Alice").await;
    let bob = sealing_phone(&net, "Bob").await;
    grant(&bob, &alice).await;
    bob.set_presence(Some("away"));
    alice.watch(bob.identity()).await;
    // P§12.2, P§12.4: sealed to the relay, opened by the grantee with the key its grant carried
    let p = until(&alice, bob.identity(), "Bob's sealed record, opened", |p| p.source == "record").await;
    assert_eq!((p.state.as_str(), p.unreadable), ("away", 0));
}

#[tokio::test]
async fn withdrawing_a_grant_rotates_the_keys_and_the_other_grantees_get_new_ones() {
    let net = Network::new();
    let (alice, carol) = (phone(&net, "Alice").await, phone(&net, "Carol").await);
    let bob = sealing_phone(&net, "Bob").await;
    grant(&bob, &alice).await;
    grant(&bob, &carol).await;
    bob.set_presence(Some("busy"));
    for w in [&alice, &carol] {
        w.watch(bob.identity()).await;
        until(w, bob.identity(), "Bob busy", |p| p.state == "busy" && p.source == "record").await;
    }

    // P§7: Alice's share ends at Bob's relay; P§12.5: main rotates, and Carol's grant is followed by one with main.1
    assert_eq!(bob.revoke_grants_to(alice.identity()).await.unwrap(), 1);
    let issued = tokio::time::timeout(dsip_testkit::TIMEOUT, bob.issued_grant()).await.expect("a re-grant").expect("the phone runs");
    assert_eq!(issued.to, carol.identity());
    assert!(carol.hold_grant(&issued.grant).await.unwrap(), "Carol holds the grant that follows hers");

    tokio::time::timeout(dsip_testkit::TIMEOUT, async {
        while alice.presence().borrow().contains_key(bob.identity()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Alice no longer sees Bob");
    // Bob's record went again under the new key, which only Carol holds
    bob.set_presence(Some("dnd"));
    let p = until(&carol, bob.identity(), "Bob dnd, under the new key", |p| p.state == "dnd").await;
    assert_eq!(p.unreadable, 0);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!alice.presence().borrow().contains_key(bob.identity()), "the revoked grant admits no longer");
}

#[tokio::test]
async fn the_relay_carries_a_sealed_record_it_cannot_read() {
    let net = Network::new();
    let bob = sealing_phone(&net, "Bob").await;
    let mut dave = net.device("Dave").await;
    let request = GrantRequest {
        introduction: dsip_core::ulid::Ulid::generate().to_string(),
        requester: dave.identity(),
        scope: vec!["dsip.subscribe".into()],
        valid_until: dsip_transport::now_s() + 3600,
    };
    let frame = bob.grant_request(request).await.unwrap().expect("a grant");
    assert!(dave.agent.hold_grant(&frame).await.unwrap());
    bob.set_presence(Some("busy"));
    tokio::time::sleep(Duration::from_millis(500)).await;

    let p = serde_json::json!({"dsip": {"core": "1.0", "min_core": "1.0", "profiles": ["broadcast/1.0", "presence/0.2"], "extensions": [], "critical": []},
                               "type": "subscribe", "to": dave.agent.relay().did.clone(), "target": bob.identity(), "events": ["presence"],
                               "expires_in": 600, "claims": dave.agent.presence_claims(bob.identity())});
    dave.agent.send_payload(p, 30).await.unwrap();
    let records = dave
        .expect("a notify with Bob's record", |e| match e {
            dsip_transport::agent::AgentEvent::Received { payload, .. } if payload["type"] == "notify" => {
                payload["body"]["records"].as_array().filter(|r| !r.is_empty()).cloned()
            }
            _ => None,
        })
        .await;
    let (record, _) = dave.agent.verify_record(records[0]["frame"].as_str().unwrap()).expect("it verifies");
    // P§12.2: kid and sealed_state in place of state, under presence/0.2
    assert!(record.get("state").is_none(), "{record}");
    assert_eq!(record["kid"], "main.0");
    assert_eq!(record["sealed_state"].as_str().map(str::len), Some(208));
    assert!(dave.agent.presence_key(bob.identity(), "main.0").is_some(), "the grant carried main.0");
}

#[tokio::test]
async fn a_sibling_seals_at_the_epoch_another_device_rotated_to() {
    let net = Network::new();
    let bob_id = net.identity("Bob");
    let sibling = net.device_of(&bob_id, "Bob's laptop");
    let bob = Phone::builder().identity(bob_id).dialer(net.dialer()).seal_presence().build().await.unwrap();
    let laptop = Phone::builder().identity(sibling).dialer(net.dialer()).seal_presence().build().await.unwrap();
    let alice = phone(&net, "Alice").await;
    grant(&bob, &alice).await;
    laptop.set_presence(Some("away"));
    bob.set_presence(Some("busy"));
    tokio::time::sleep(Duration::from_secs(1)).await;

    // P§12.5: the phone rotates main; Dave, granted afterwards, holds only main.1
    assert_eq!(bob.revoke_grants_to(alice.identity()).await.unwrap(), 1);
    tokio::time::sleep(Duration::from_secs(1)).await;
    let dave = phone(&net, "Dave").await;
    grant(&bob, &dave).await;
    dave.watch(bob.identity()).await;
    // the laptop saw main.1 in the phone's record through its own watch and sealed again under it
    let p = until(&dave, bob.identity(), "both of Bob's devices readable", |p| p.source == "record" && p.unreadable == 0).await;
    assert!(["busy", "away"].contains(&p.state.as_str()), "{p:?}");
}
