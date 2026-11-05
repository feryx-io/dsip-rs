//! A phone registering to be woken (W§4.2) through the phone's own API: enrolled at a gateway, registered with its
//! relay, asleep, then woken for a call with a hint it opens; a registration the relay refuses, one removed, and a
//! relay that wakes no one.
//!
//! Spec: W§3, W§4.2, W§4.4, W§5.1, W§6.

use std::time::Duration;

use dsip_core::keys::KeyPair;
use dsip_phone::Phone;
use dsip_testkit::{push, Network, PushGateway};
use dsip_transport::wake::{enrol, Answer};
use serde_json::{json, Value};

async fn phone(net: &Network, name: &str) -> Phone {
    Phone::builder().identity(net.identity(name)).dialer(net.dialer()).build().await.expect("phone")
}

/// Enrol `token` at the gateway and register `bob` with his relay; the relay's answer and the seal secret.
async fn register(gw: &PushGateway, net: &Network, bob: &Phone, token: &str) -> (Answer, [u8; 32]) {
    let wake_key = KeyPair::generate();
    let handle = enrol(&gw.client, &gw.did, &wake_key, "fcm", push::APP, token, None).await.expect("enrolled");
    let reg = dsip_wake::registration(&wake_key, net.relay().did(), &gw.did, &handle, dsip_transport::now_s());
    let (secret, public) = dsip_wake::seal_keys();
    (bob.wake_register(reg, Some(public), None).await.expect("an answer"), secret)
}

/// The pushes, once there are `n`.
async fn pushes(gw: &PushGateway, n: usize) -> Vec<Value> {
    tokio::time::timeout(dsip_testkit::TIMEOUT, async {
        loop {
            let p = gw.recorder.pushes();
            if p.len() >= n {
                return p;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{n} pushes never came: {:?}", gw.recorder.pushes()))
}

#[tokio::test]
async fn a_registered_phone_asleep_is_woken_for_a_call_with_a_hint_it_opens() {
    let gw = PushGateway::start().await;
    let net = Network::waking(&gw);
    let bob = phone(&net, "Bob").await;
    let wake = bob.relay_wake().expect("the relay wakes");
    assert!(wake["profiles"].as_array().unwrap().contains(&json!("wake/0.1")), "{wake}");
    let (answer, secret) = register(&gw, &net, &bob, "fcm-token-bob").await;
    assert_eq!(answer, Answer::Accepted { handle: None });
    let bob_identity = bob.identity().to_string();
    bob.close().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let alice = phone(&net, "Alice").await;
    let call = alice.call(&bob_identity).await.expect("placed");
    let p = pushes(&gw, 1).await;
    let data = &p[0]["data"]["dsip-wake"];
    assert_eq!((p[0]["class"].as_str(), p[0]["token"].as_str()), (Some("call"), Some("fcm-token-bob")));
    assert_eq!(data["session"].as_str(), Some(call.session()));
    let hint = dsip_wake::open_hint(&data["sealed"], call.session(), &secret).expect("the hint opens");
    assert_eq!(hint, json!({"from": alice.device(), "on_behalf_of": alice.identity()}));
}

#[tokio::test]
async fn a_registration_naming_another_waker_is_refused() {
    let gw = PushGateway::start().await;
    let net = Network::waking(&gw);
    let bob = phone(&net, "Bob").await;
    let wake_key = KeyPair::generate();
    let handle = enrol(&gw.client, &gw.did, &wake_key, "fcm", push::APP, "fcm-token", None).await.expect("enrolled");
    let reg = dsip_wake::registration(&wake_key, "did:web:another.relay.example", &gw.did, &handle, dsip_transport::now_s());
    let answer = bob.wake_register(reg, None, None).await.expect("an answer");
    assert!(matches!(&answer, Answer::Refused { reason, .. } if reason == "wake.waker-mismatch"), "{answer:?}");
}

#[tokio::test]
async fn a_removed_registration_wakes_nothing() {
    let gw = PushGateway::start().await;
    let net = Network::waking(&gw);
    let bob = phone(&net, "Bob").await;
    let (answer, _) = register(&gw, &net, &bob, "fcm-token-bob").await;
    assert_eq!(answer, Answer::Accepted { handle: None });
    assert_eq!(bob.wake_remove().await.expect("an answer"), Answer::Accepted { handle: None });
    let bob_identity = bob.identity().to_string();
    bob.close().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let alice = phone(&net, "Alice").await;
    let _call = alice.call(&bob_identity).await.expect("placed");
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert!(gw.recorder.pushes().is_empty(), "{:?}", gw.recorder.pushes());
}

#[tokio::test]
async fn a_relay_that_wakes_no_one_says_nothing_of_it() {
    let net = Network::new();
    let bob = phone(&net, "Bob").await;
    assert!(bob.relay_wake().is_none());
}

#[tokio::test]
async fn an_enrolment_for_an_app_the_gateway_does_not_push_for_is_refused() {
    let gw = PushGateway::start().await;
    let err = enrol(&gw.client, &gw.did, &KeyPair::generate(), "fcm", "another.app", "t", None).await.unwrap_err();
    assert!(matches!(&err, dsip_transport::wake::WakeError::Refused(r) if r == "wake.unsupported-app"), "{err}");
}
