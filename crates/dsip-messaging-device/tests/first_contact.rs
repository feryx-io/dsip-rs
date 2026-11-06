//! Introductions and grants received from the mailbox, as both clients read them.
//!
//! Spec: M§14.1, M§6.9, core §19.4, §7.4.

use serde_json::{json, Value};

use dsip_core::did::StaticResolver;
use dsip_core::envelope::{encode_payload, sign_bytes, Context};
use dsip_core::keys::KeyPair;
use dsip_messaging::first_contact::{seal_introduction, x25519_from_ed25519_seed, x25519_public};
use dsip_messaging::wire;
use dsip_messaging_device::first_contact::{received, Received};

const NOW: i64 = 1_790_000_000;

fn item(class: &str, key: &KeyPair, p: &Value) -> Value {
    let e = sign_bytes(&encode_payload(p), key, &key.kid(), vec![]);
    json!({"cursor": "c1", "class": class, "envelope": format!("{}.{}.{}", e.protected, e.payload, e.signature)})
}

fn introduction(from: &str, to: &str, purpose: &str) -> Value {
    json!({"dsip": wire::version_block(), "type": "introduction", "id": wire::new_id(NOW), "from": from, "to": to,
        "identity": {"display_name": from}, "purpose": purpose, "issued_at": NOW, "expires_at": NOW + 7 * 86_400})
}

#[test]
fn introductions_checked_then_opened() {
    let (alice, bob) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("bob"));
    let resolver = StaticResolver::default();
    let ctx = Context::new(NOW, &resolver);
    let seed = bob.seed();

    // a sealed purpose opens with the identity key (M§6.9, spec-gap 55); a device without it keeps the request unread
    let mut p = introduction(&alice.did(), &bob.did(), "lunch?");
    seal_introduction(&mut p, "lunch?", &x25519_public(&x25519_from_ed25519_seed(&seed)), &[9; 32]);
    let it = item("introduction", &alice, &p);
    let Received::Request(r) = received(&it, &bob.did(), &ctx, NOW, Some(&seed)) else { panic!("a request") };
    assert_eq!((r.from.as_str(), r.purpose.as_deref(), r.sealed), (alice.did().as_str(), Some("lunch?"), true));
    let Received::Request(r) = received(&it, &bob.did(), &ctx, NOW, None) else { panic!("a request") };
    assert_eq!((r.purpose, r.sealed), (None, true));

    // a plain purpose is read either way
    let plain = item("introduction", &alice, &introduction(&alice.did(), &bob.did(), "hi"));
    let Received::Request(r) = received(&plain, &bob.did(), &ctx, NOW, None) else { panic!("a request") };
    assert_eq!((r.purpose.as_deref(), r.sealed), (Some("hi"), false));

    // never both purpose and sealed (M§14.1): refused whether or not this device could open it
    let mut both = p.clone();
    both["purpose"] = json!("visible");
    for seed in [Some(&seed), None] {
        let got = received(&item("introduction", &alice, &both), &bob.did(), &ctx, NOW, seed);
        assert!(matches!(got, Received::BadIntroduction { ref code, .. } if code == "introduction-purpose-and-sealed"), "{got:?}");
    }

    // sealed to someone else: does not open
    let mut other = introduction(&alice.did(), &bob.did(), "x");
    seal_introduction(&mut other, "x", &x25519_public(&x25519_from_ed25519_seed(&alice.seed())), &[9; 32]);
    let got = received(&item("introduction", &alice, &other), &bob.did(), &ctx, NOW, Some(&seed));
    assert!(matches!(got, Received::BadIntroduction { ref code, .. } if code == "sealed-open-failed"), "{got:?}");

    // for another identity, expired, or delivered under the other class: does not verify
    assert_eq!(received(&plain, &alice.did(), &ctx, NOW, None), Received::DoesNotVerify);
    assert_eq!(received(&plain, &bob.did(), &ctx, NOW + 8 * 86_400, None), Received::DoesNotVerify);
    let mut wrong_class = plain.clone();
    wrong_class["class"] = json!("grant");
    assert_eq!(received(&wrong_class, &bob.did(), &ctx, NOW, None), Received::DoesNotVerify);
}

#[test]
fn grants_kept_for_messaging() {
    let (alice, bob) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("bob"));
    let resolver = StaticResolver::default();
    let ctx = Context::new(NOW, &resolver);
    let grant = |scope: Value| json!({"dsip": wire::version_block(), "type": "grant", "id": wire::new_id(NOW), "from": bob.did(),
        "to": alice.did(), "session": "S1", "scope": scope, "valid_until": NOW + 30 * 86_400, "issued_at": NOW, "expires_at": NOW + 30});

    let it = item("grant", &bob, &grant(json!(["dsip.message"])));
    let Received::Grant(g) = received(&it, &alice.did(), &ctx, NOW + 3600, None) else { panic!("a grant") };
    assert_eq!((g.from.as_str(), g.request.as_str(), g.envelope.as_str()), (bob.did().as_str(), "S1", it["envelope"].as_str().unwrap()));
    // held past its delivery expiry, not past valid_until (§19.4)
    assert_eq!(received(&it, &alice.did(), &ctx, NOW + 31 * 86_400, None), Received::DoesNotVerify);

    let got = received(&item("grant", &bob, &grant(json!(["dsip.call"]))), &alice.did(), &ctx, NOW, None);
    assert!(matches!(got, Received::NoMessageScope { ref from, .. } if *from == bob.did()), "{got:?}");
}

#[test]
fn a_purpose_sealed_to_a_delegated_key_opens_with_it_and_one_sealed_to_the_derived_key_still_does() {
    // core §7.3 (spec-gap 179): a device holding the delegated secret first, then the derived one
    use dsip_messaging_device::first_contact::received_with;
    let (alice, bob) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("bob"));
    let resolver = StaticResolver::default();
    let ctx = Context::new(NOW, &resolver);
    let delegated = [7u8; 32];
    let secrets = [delegated, x25519_from_ed25519_seed(&bob.seed())];
    let opened = |pk: [u8; 32], secrets: &[[u8; 32]]| {
        let mut p = introduction(&alice.did(), &bob.did(), "lunch?");
        seal_introduction(&mut p, "lunch?", &pk, &[9; 32]);
        match received_with(&item("introduction", &alice, &p), &bob.did(), &ctx, NOW, secrets) {
            Received::Request(r) => r.purpose,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(opened(x25519_public(&delegated), &secrets), Some("lunch?".into()), "sealed to the delegated key");
    assert_eq!(opened(x25519_public(&secrets[1]), &secrets), Some("lunch?".into()), "a sender that has not seen it");
    // a device holding only the delegated key opens what is sealed to it, and nothing sealed to the derived key
    assert_eq!(opened(x25519_public(&delegated), &secrets[..1]), Some("lunch?".into()));
}
