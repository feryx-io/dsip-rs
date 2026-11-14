# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases follow `RELEASING.md`:
CalVer workspace tags over per-crate [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- `dsip-messaging`: `client::voicemail_offer` answers the voicemail's `kind` with every offer: `video` only when the
  attempt offered video (`call_video`) and the callee's entry `accepts` `video`, else `audio` (DSIP spec-gap 184,
  M§13.2). `dsip-wasm`'s `voicemail_offer` takes an optional `call_video` and reads `accepts` from the entry.
- DSIP spec: `spec/video-gaps-181-184` (5402a04; spec-gaps 181–184, video codecs and video voicemail).
- `dsip-media`: video (B§3.4). `MediaConfig.video` (`VideoConfig`: codecs, a `VideoFeed` of coded frames to send, a
  sink for the frames received, a channel for the far end's `VideoRequest`s, `max_kbps`) gives a leg a video section
  after its audio one. On the forge backend frames are packetized (`forge_rtp::video`), kept for retransmission and
  resent on NACK; received packets are assembled into whole frames, losses NACKed, and a keyframe asked for (PLI, at
  most every 500 ms) when one cannot be repaired; the far end's PLI, FIR and REMB reach the host as `Keyframe` and
  `Bitrate`. The webrtc-rs backend refuses video (`Error::VideoUnsupported`) for now. `Stats` counts video frames
  in and out and keyframes asked for. Breaking: `MediaConfig` and `Stats` gain fields.
- `dsip-endpoint`: an answer's `media[]` follows its SDP: a section the SDP refused (port 0) is left out, and each
  codec is the one the `m=` line put first (B§2.1). Before, a refused video section was still described, and a
  caller checking the answer ended the call `media.failed`.
- `dsip-phone`: video per call. `Phone::video_call` offers video (when the phone's `Media::Native` has a video
  section, `Media::video`); `Phone::call` stays audio only, so a callee whose answer to video its caller would refuse
  (dsip-rs before this release described a refused section, B§2.1) is never offered it. An incoming call gets a video
  section only when its offer carries a live `m=video`. `Call::video` says whether a call carries video.
- `dsip-endpoint`: `InvitePatch::video` offers video in one invite whatever `CoreConfig::video` says;
  `MediaRequest::Offer` gains `video` so the host's leg matches the descriptors (B§2.1); `Core::video`. Breaking:
  `InvitePatch` and `MediaRequest::Offer` gain fields.

## [2026-11-11.2] — workspace release

A phone whose mailbox sends a frame too large for the connection asks for fewer items instead of asking again for the
same ones, and the vector suite now checks that a mailbox's pages fit the frame cap, against the mailbox's own paging
(DSIP spec-gap 180). DSIP spec: `poc-v1.0.6` (was `poc-v1.0.5`).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.1 |
| `dsip-cli` | 0.3.0 |
| `dsip-core` | 0.2.0 |
| `dsip-dht` | 0.2.0 |
| `dsip-endpoint` | 0.4.0 |
| `dsip-events` | 0.2.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.4.2 (was 0.4.1) |
| `dsip-media` | 0.1.1 |
| `dsip-messaging` | 0.5.0 (was 0.4.0) |
| `dsip-messaging-device` | 0.6.0 (was 0.5.0) |
| `dsip-messenger` | 0.6.1 (was 0.6.0) |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.6.0 |
| `dsip-push` | 0.1.1 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.3.1 |
| `dsip-schema` | 0.2.0 |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.3.0 |
| `dsip-transport` | 0.11.0 (was 0.10.0) |
| `dsip-wake` | 0.2.0 |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes**: none. `dsip-messaging`, `dsip-messaging-device` and `dsip-transport` take minor bumps for new API
(#58).

### Added

- `dsip-messaging-device`, `dsip-messenger`: a device whose mailbox sends a frame over the cap (closed with 1009) syncs
  again with half the `limit`, at least 1, instead of the same `sync` (M§5.4, spec-gap 180); one that sent none asks
  for 100. At 1 the redial's backoff is the wait. The reduced `limit` is not saved, so a restart drops it.
  `Messenger::too_large`, `Resume::too_large`; `dsip_transport::conn::OVERSIZE_FRAME` names the error.
- `dsip-messaging`: the `items-pages` vectors (M§5.4, spec-gap 180) run against `wire::fit_items`, the mailbox
  service's paging by bytes, moved here from `dsip-mailbox`; `resume-trace` `too_large`.

### Changed

- `dsip-mailbox`: pages with `dsip_messaging::wire::fit_items`, the function the vectors test; unchanged in behaviour
  (#58).

## [2026-11-11.1] — workspace release

The mailbox's sync pages fit the transport's frame cap: a phone with many messages waiting no longer loops
reconnecting. Only `dsip-mailbox` changes. DSIP spec: `poc-v1.0.5`, unchanged.

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.1 |
| `dsip-cli` | 0.3.0 |
| `dsip-core` | 0.2.0 |
| `dsip-dht` | 0.2.0 |
| `dsip-endpoint` | 0.4.0 |
| `dsip-events` | 0.2.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.4.1 (was 0.4.0) |
| `dsip-media` | 0.1.1 |
| `dsip-messaging` | 0.4.0 |
| `dsip-messaging-device` | 0.5.0 |
| `dsip-messenger` | 0.6.0 |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.6.0 |
| `dsip-push` | 0.1.1 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.3.1 |
| `dsip-schema` | 0.2.0 |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.3.0 |
| `dsip-transport` | 0.10.0 |
| `dsip-wake` | 0.2.0 |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes**: none (a patch).

### Fixed

- `dsip-mailbox`: a sync's `items` envelope fits the 65,536-byte `ws/1.0` cap (M§5.4, §13.2). A page is sent as the
  longest prefix whose frame fits, with `next` its last cursor, and the device syncs on from there. Pages were bounded
  by count alone: a phone with 54 items waiting (44,756 bytes, about 80 KB as one frame) refused the frame, reconnected
  and synced from the start again, every second, and showed its mailbox as not connected.

## [2026-11-11] — workspace release

Phones on mobile networks: TURN for calls' media, and a phone that survives its relay connection being closed while
it is locked. Attachments and deleting messages on a device. The first release under the feryx-io organization: its
images are `ghcr.io/feryx-io/dsip-relay`, `-mailbox`, `-push` and `-node` (earlier releases' images stay under
`ghcr.io/thevoiceguy`). DSIP spec: `poc-v1.0.5`, unchanged.

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.1 |
| `dsip-cli` | 0.3.0 |
| `dsip-core` | 0.2.0 |
| `dsip-dht` | 0.2.0 |
| `dsip-endpoint` | 0.4.0 |
| `dsip-events` | 0.2.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.4.0 |
| `dsip-media` | 0.1.1 |
| `dsip-messaging` | 0.4.0 |
| `dsip-messaging-device` | 0.5.0 (was 0.4.0) |
| `dsip-messenger` | 0.6.0 (was 0.5.0) |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.6.0 (was 0.5.0) |
| `dsip-push` | 0.1.1 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.3.1 |
| `dsip-schema` | 0.2.0 |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.3.0 |
| `dsip-transport` | 0.10.0 (was 0.9.0) |
| `dsip-wake` | 0.2.0 |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes**: none. The additions are new public API (minor bumps).

The services are unchanged in behaviour and rebuilt; their packages and images link to feryx-io.

### Added

- `dsip-transport`: `turn::TurnClient`, short-lived TURN credentials from a relay's `/turn` (the ones the browser
  client already uses).
- `dsip-phone`: `PhoneBuilder::turn`. Before a call's media starts, the phone asks for credentials, keeps them until
  five minutes before they expire, and gives the leg the relay's TURN servers. A call whose credentials cannot be had
  goes without TURN. So does one whose TURN server is not ready within 4 s; the leg is made again without it, and calls
  skip TURN for 5 minutes. Calls between a phone on a mobile network and a desktop behind a home NAT rang but carried
  no audio.
- `dsip-messaging-device`: `Messenger::forget_message` and `Messenger::forget_thread` delete one message, or a whole
  thread, on this device only; nothing is sent. The keys of deleted messages are saved (`forgotten` in the state), so
  a copy from the archive or MLS is not shown again.
- `dsip-messenger`: `Messenger::upload_blob` seals a payload and uploads it to the identity's mailbox (M§8.4 rules
  1–2, M§5.6), returning an `UploadedBlob` for the content object; `dsip-messaging-device`: `blob::attachment_content`
  makes the `image` and `file` objects (`purpose` `attachment`, M§8.2). Hosts other than the CLI can now send files.

### Fixed

- `dsip-transport`: a message to the agent's relay that fails to send is a connection lost, as a failure to receive
  already was: the agent reconnects (§13.2) and sends it on the new connection, instead of returning the error from
  whatever sent it. One to another relay that fails closes that connection, as a failure to receive on it does. A
  phone whose connection the system closed while it was locked found out only on its next call, and the failure
  stopped `dsip-phone`: every call after it said "the phone has closed" until the app restarted.
- `dsip-phone`: a call's media failing (its leg, its offer or answer, its candidates) ends that call, with the error
  on it, rather than the phone.

- `dsip-messenger`: a fetched blob is kept under its content id and its `name`, made safe for any file system, or an
  extension for its media type (`blob::file_name`). Every blob was written as `<id>.ogg`, an image or a file too.
- `dsip-messaging-device`: a request (`Messenger::requests`) keeps the introduction's `identity` claims. The name an
  introduction offers was dropped, so the app showed its sender by DID alone.
- `dsip-transport`: `tls::client_config` falls back to webpki-roots (Mozilla's roots) where the platform's store
  cannot be read, and always returns a config. On Android every `wss` connection (relay, mailbox, a peer's relay)
  failed with "no native root CA certificates found".

## [2026-11-10] — workspace release

Devices without the identity key (app plan A6, decision 5 (a)). DSIP spec: `poc-v1.0.5`, unchanged (2,513 vectors, 0
failures).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.1 |
| `dsip-cli` | 0.3.0 |
| `dsip-core` | 0.2.0 |
| `dsip-dht` | 0.2.0 |
| `dsip-endpoint` | 0.4.0 |
| `dsip-events` | 0.2.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.4.0 |
| `dsip-media` | 0.1.1 |
| `dsip-messaging` | 0.4.0 |
| `dsip-messaging-device` | 0.4.0 |
| `dsip-messenger` | 0.5.0 (was 0.4.0) |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.5.0 |
| `dsip-push` | 0.1.1 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.3.1 |
| `dsip-schema` | 0.2.0 |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.3.0 |
| `dsip-transport` | 0.9.0 (was 0.8.0) |
| `dsip-wake` | 0.2.0 |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes** (#47):
- `dsip_transport::identity::Identity.controller` is `Option<KeyPair>`: use `identity_key()`, which returns
  `Error::NoIdentityKey` on a device that joined without it.
- `did_web_document` and `derived_key_agreement_secret` return `Result`; `key_agreement_secret` returns an `Option`.
- `dsip_messenger::engine_identity_with` takes the identity key as `Option<&KeyPair>`.

The services are unchanged in behaviour and rebuilt.

### Added
- `Identity::delegate_device(device, now)`: the identity's delegation of another device (§7.4), with this device's own
  capabilities.
- `Identity::join(dir, identity, name, device, delegation, key_agreement)`: a device that joins without the identity
  key. It holds its own key, the identity's delegation of it and the identity's key agreement key (§7.3), so it opens
  what is sealed to the identity and signs nothing as it.
- `Identity::load` reads an identity folder without `controller.key`.

## [2026-11-09] — workspace release

The `did:web` document for an identity on its own domain (app plan A6d). DSIP spec: `poc-v1.0.5`, unchanged (2,513
vectors, 0 failures).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.1 |
| `dsip-cli` | 0.3.0 |
| `dsip-core` | 0.2.0 |
| `dsip-dht` | 0.2.0 |
| `dsip-endpoint` | 0.4.0 |
| `dsip-events` | 0.2.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.4.0 |
| `dsip-media` | 0.1.1 |
| `dsip-messaging` | 0.4.0 |
| `dsip-messaging-device` | 0.4.0 |
| `dsip-messenger` | 0.4.0 |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.5.0 |
| `dsip-push` | 0.1.1 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.3.1 |
| `dsip-schema` | 0.2.0 |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.3.0 |
| `dsip-transport` | 0.8.0 (was 0.7.0) |
| `dsip-wake` | 0.2.0 |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

No breaking changes. The services are unchanged in behaviour and rebuilt.

### Added
- `Identity::did_web_document(relay, mailbox, also_known_as)` (#45): the DID document a `did:web` identity serves. It
  holds the identity key as `#key-1`, its key agreement key under `keyAgreement` (the delegated one when it holds one,
  §7.3), and `DSIPSignaling` and `DSIPMailbox` services. A `did:web` is reached by its document alone (§8.1).

### Changed
- `Identity::rehome_did_web` writes `did.json` with `keyAgreement`, after re-issuing the key agreement delegation for
  the new subject.

## [2026-11-08] — workspace release

Key agreement delegation (DSIP spec-gap 179), the push gateway's APNs message topic (spec-gap 178), and identity key
files readable by their owner alone. DSIP spec: `poc-v1.0.5` (was `poc-v1.0.4`; DSIP Core 1.0; 2,513 vectors, 0
failures).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.1 |
| `dsip-cli` | 0.3.0 (was 0.2.0) |
| `dsip-core` | 0.2.0 (was 0.1.0, now its own version line) |
| `dsip-dht` | 0.2.0 (was 0.1.0, now its own version line) |
| `dsip-endpoint` | 0.4.0 (was 0.3.0) |
| `dsip-events` | 0.2.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.4.0 |
| `dsip-media` | 0.1.1 |
| `dsip-messaging` | 0.4.0 (was 0.3.1) |
| `dsip-messaging-device` | 0.4.0 (was 0.3.0) |
| `dsip-messenger` | 0.4.0 (was 0.3.0) |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.5.0 (was 0.4.0) |
| `dsip-push` | 0.1.1 (was 0.1.0) |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.3.1 |
| `dsip-schema` | 0.2.0 (was 0.1.1) |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.3.0 |
| `dsip-transport` | 0.7.0 (was 0.6.0) |
| `dsip-wake` | 0.2.0 |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes:**
- `dsip_core::RejectCode` has a new variant, `KeyAgreementInvalid` (#42).
- `dsip_dht::record::Hint` has a new public field, `key_agreement` (#43).
- `dsip_transport::identity::Identity` has a new public field, `key_agreement` (#43).

A `match` without a wildcard, or a struct literal, needs the new item. The services are unchanged in behaviour, except
that `dsip-push` sends a message push on the handle's own topic: `dsip-relay` 0.3.1, `dsip-mailbox` 0.4.0,
`dsip-push` 0.1.1, `dsip-node` 0.1.1 and `dsip-web` 0.1.1 are rebuilt.

### Added
- Key agreement delegation (core §7.3, spec-gap 179): an identity-signed `KeyAgreementDelegation` names an independent
  X25519 key, so an identity's devices open what is sealed to it without holding its signing key.
  - `dsip_schema::key_agreement` (#42): verify, choose the current one, and give a DID's recipient key (its document's,
    else the delegation's, else the did:key derived key).
  - `dsip-dht` refuses a hint whose `key_agreement` member does not verify; the vector runner runs `key-agreement/`.
  - `Identity` (#43):
    - holds one (`key-agreement.json`, 0600);
    - `issue_key_agreement`, and `derived_key_agreement_secret(n)`, derived from the identity key so every device
      holding it derives the same key;
    - `key_agreement_secret(s)` for opening.
  - `Core::hold_key_agreement`, and sealing to the held key: sealed bodies, a grant's presence keys, and the
    messenger's introductions.
  - The phone and the messenger take the credential from the hints they look up.
  - `hints::reachability_with` carries it.
  - `received_with`, `open_sealed_introduction_with`, `engine_identity_with`.

### Fixed
- `dsip-push`: an APNs message push goes on the handle's own topic (the alert token's), not the VoIP topic with `.voip`
  stripped, which APNs refused (spec-gap 178; #39).
- `Identity::init` writes `controller.key` and `device.key` readable by their owner alone (0600; #41).

## [2026-11-07] — workspace release

The device side of waking (app plan stage A5d). DSIP spec: `poc-v1.0.4`, unchanged (DSIP Core 1.0; 2,476 vectors, 0
failures).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.1 |
| `dsip-cli` | 0.2.0 |
| `dsip-core` | 0.1.0 |
| `dsip-dht` | 0.1.0 |
| `dsip-endpoint` | 0.3.0 |
| `dsip-events` | 0.2.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.4.0 |
| `dsip-media` | 0.1.1 |
| `dsip-messaging` | 0.3.1 |
| `dsip-messaging-device` | 0.3.0 |
| `dsip-messenger` | 0.3.0 (was 0.2.0) |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.4.0 (was 0.3.0) |
| `dsip-push` | 0.1.0 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.3.1 |
| `dsip-schema` | 0.1.1 |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.3.0 (was 0.2.0) |
| `dsip-transport` | 0.6.0 (was 0.5.0) |
| `dsip-wake` | 0.2.0 (was 0.1.1) |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes** (#37): `dsip_transport::agent::AgentEvent` has a new variant, `Reply`, and
`dsip_transport::wake::WakeError` a new variant, `Refused`; a `match` on either without a wildcard needs an arm. The
services are unchanged in behaviour: `dsip-relay` 0.3.1, `dsip-mailbox` 0.4.0, `dsip-push` 0.1.0, `dsip-node` 0.1.1 and
`dsip-web` 0.1.1 are rebuilt.

### Added

- The device side of the Wake Profile (W§3, W§4.2), for the app (#37):
  - `dsip_transport::wake::enrol` (`wake-enrol` at a gateway; the handle) and `read_reply` (a waker's answer, verified
    against its documents).
  - `dsip_wake::registration` (a device's signed `WakeRegistration`) and `seal_keys` (the X25519 key a call's hint is
    sealed to).
  - `Agent::request` and `Agent::read_reply`: a request on the binding whose answer comes back to the host as
    `AgentEvent::Reply` (the endpoint's pipeline knows only the core's types and drops `wake-accepted`).
  - `Phone::relay_did`, `relay_wake`, `wake_register`, `wake_remove`; `Messenger::mailbox_wake`, `wake_register`,
    `wake_remove` (the mailbox's owner operation, spec-gap 176).
  - `dsip_testkit::PushGateway` (dsip-push over local HTTPS with the recording provider) and `Network::waking`.

## [2026-11-06] — workspace release

dsip-rs builds on Windows (found building dsip-app there, app plan stage A3). DSIP spec: `poc-v1.0.4`, unchanged
(DSIP Core 1.0; 2,476 vectors, 0 failures).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.1 |
| `dsip-cli` | 0.2.0 |
| `dsip-core` | 0.1.0 |
| `dsip-dht` | 0.1.0 |
| `dsip-endpoint` | 0.3.0 |
| `dsip-events` | 0.2.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.4.0 |
| `dsip-media` | 0.1.1 (was 0.1.0) |
| `dsip-messaging` | 0.3.1 (was 0.3.0) |
| `dsip-messaging-device` | 0.3.0 |
| `dsip-messenger` | 0.2.0 |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.3.0 |
| `dsip-push` | 0.1.0 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.3.1 |
| `dsip-schema` | 0.1.1 (was 0.1.0) |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.2.0 |
| `dsip-transport` | 0.5.0 |
| `dsip-wake` | 0.1.1 (was 0.1.0) |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

No breaking changes. The services are unchanged: `dsip-relay` 0.3.1, `dsip-mailbox` 0.4.0, `dsip-push` 0.1.0,
`dsip-node` 0.1.1 and `dsip-web` 0.1.1 are rebuilt from the same code.

### Fixed

- Building on Windows (found building dsip-app there):
  - The schema freshness checks (`dsip-schema`, `dsip-messaging`, `dsip-wake`) compare without line endings. The
    generator writes CRLF on Windows, so every schema read as drift.
  - `dsip-media` takes forge-media at its release `v2026.11.01` (was 663f53f). `forge-rtp`'s SRTP crypto crates
    there are dependencies on every platform; they sat under its unix-only table, so it did not build on Windows.

## [2026-11-05] — workspace release

Sealed presence on the native phone (app plan stage A2). DSIP spec: `poc-v1.0.4` (was `poc-v1.0.3`): DSIP Core 1.0,
with §9.3 stating that a subscription is the subscribing device's (spec-gap 177); 2,476 vectors, 0 failures.

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.1 (was 0.1.0) |
| `dsip-cli` | 0.2.0 |
| `dsip-core` | 0.1.0 |
| `dsip-dht` | 0.1.0 |
| `dsip-endpoint` | 0.3.0 (was 0.2.0) |
| `dsip-events` | 0.2.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.4.0 |
| `dsip-media` | 0.1.0 |
| `dsip-messaging` | 0.3.0 |
| `dsip-messaging-device` | 0.3.0 (was 0.2.0) |
| `dsip-messenger` | 0.2.0 |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.3.0 (was 0.2.0) |
| `dsip-push` | 0.1.0 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.3.1 (was 0.3.0) |
| `dsip-schema` | 0.1.0 |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.2.0 |
| `dsip-transport` | 0.5.0 (was 0.4.0) |
| `dsip-wake` | 0.1.0 |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes** (API):
- `dsip_transport::agent::AgentEvent` gains a variant, `GrantIssued` (#30): an exhaustive `match` on it must add an
  arm (or `_`).

The relay's authority now keeps one subscription per subscribing device (spec-gap 177): `dsip-relay` 0.3.1, whose
own code is unchanged, takes the fix through `dsip-broadcast` 0.1.1. `dsip-mailbox` 0.4.0, `dsip-push` 0.1.0,
`dsip-node` 0.1.1 and `dsip-web` 0.1.1 are rebuilt from the same code.

### Added

- `dsip-phone`: presence (Presence Profile draft, in clear: `presence/0.1`). `Phone::set_presence` publishes this
  device's state to its relay and keeps it fresh (P§3, P§8); `Phone::watch` follows another identity's, subscribing
  at the relay that answers for it (a `did:key`'s hint names it, §8.1, over the connection a call there would use),
  presenting the grants held from it (P§6), renewing before the hour's subscription lapses and asking again a minute
  after a refusal; `Phone::presence` shows each watched identity as P§4 combines its devices (`Presence`: state,
  token, and whether a record or the relay's claim says so).
- Grants that travel through a mailbox (M§14.1) on the calling side too: `Core::grant_request` /
  `Agent::grant_request` / `Phone::grant_request` answer an introduction that came another way with a grant issued
  as one through the relay is (so it can be withdrawn or followed), returned compact for the host to deposit;
  `Core::hold_grant` / `Agent::hold_grant` / `Phone::hold_grant` hold a grant received that way, checked as a
  credential, so it is presented where a grant admits (a presence `subscribe`): it opens the presence keys the grant
  carries and takes a grant that follows one held (§19.4, spec-gap 150), as one through the relay is, returning what
  holding it emitted with whether it is held.
- `dsip-transport`: `Agent::sign`, `Agent::relay_at` (bind at another relay and return its DID),
  `Agent::send_frame` (to our relay or another), and `Agent::keep_peer` (keep a connection to another relay open
  with no call through it).
- `dsip-messaging-device`: `Messenger::grant_held`, the signed grant held from an identity.
- `dsip-phone`: sealed presence (P§12, `presence/0.2`). `PhoneBuilder::seal_presence` seals this device's records,
  so the relay routes them without reading them, and puts the keys in the grants the phone issues (P§12.3); watches
  list `presence/0.2` and open sealed records with the keys held grants carried (`Presence::unreadable` counts the
  ones they do not open, P§12.4). `Phone::revoke_grants_to` withdraws a grantee's grants at the relay (P§7), which
  rotates the keys; every other grant is then followed by one carrying the new keys (P§12.5), handed to the host by
  `Phone::issued_grant` to deliver the way the first went, and the record goes again under the new key. A sealing
  phone watches its own identity and seals at the epoch a sibling rotated to.
- `dsip-transport`: `AgentEvent::GrantIssued` (a grant the agent sent, compact, for a host that also delivers it
  another way) and `Agent::presence_sealed`.

### Fixed

- `dsip-broadcast` (the relay's authority): a subscription is the subscribing device's (§9.3, spec-gap 177). A
  renewal and `expires_in: 0` matched per subscriber identity, so a second device of one identity subscribing to the
  same target replaced the first device's subscription, which stopped being notified.
- `dsip-messaging-device`: a grant read from the mailbox whose `from` is the signing device (as a calling engine
  signs it) is the identity's that the device's delegation binds it to (§7.4), as wherever a grant is checked as a
  credential; it was taken as the device's.

## [2026-11-04] — workspace release

Native calls through another relay (app plan stage A2). DSIP spec: `poc-v1.0.3`, unchanged (DSIP Core 1.0 with the
Wake Profile draft `wake/0.1`; 2,475 vectors, 0 failures).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.0 |
| `dsip-cli` | 0.2.0 |
| `dsip-core` | 0.1.0 |
| `dsip-dht` | 0.1.0 |
| `dsip-endpoint` | 0.2.0 |
| `dsip-events` | 0.2.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.4.0 |
| `dsip-media` | 0.1.0 |
| `dsip-messaging` | 0.3.0 |
| `dsip-messaging-device` | 0.2.0 |
| `dsip-messenger` | 0.2.0 |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.2.0 (was 0.1.0) |
| `dsip-push` | 0.1.0 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.3.0 |
| `dsip-schema` | 0.1.0 |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.2.0 (was 0.1.0) |
| `dsip-transport` | 0.4.0 (was 0.3.0) |
| `dsip-wake` | 0.1.0 |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes** (API; no behaviour change for an agent that places no call through another relay):
- `dsip_transport::agent::AgentConfig` gains a public field, `peer_dialer` (#27): a struct literal must add
  `peer_dialer: None`.

The services are unchanged: `dsip-relay` 0.3.0, `dsip-mailbox` 0.4.0, `dsip-push` 0.1.0, `dsip-node` 0.1.1 and
`dsip-web` 0.1.1 are rebuilt from the same code.

### Added

- Calls through another relay (§8.1), as the browser client places them. `Agent::place_via(to, invite, relay)` binds
  this device at the callee's relay, on one connection shared by every call through it, and sends the session's
  envelopes over it; frames from every connection reach the one endpoint core. The connection closes once no call
  uses it, and is not redialled if it drops. A relay that does not bind within 8 s leaves the call to our own.
  `AgentConfig::peer_dialer` reaches other relays without `wss` (`dsip-testkit`: `Network::url`, `Network::peers`).
  `Agent::route_of` and `Agent::peer_relays` say where calls go.
- `dsip-phone`: `PhoneBuilder::hints` looks up a `did:key` callee's hint before the invite (§8.1 rule 6: never for an
  identity with a document); when it names another relay, the call goes through it (`Call::via`).
- `dsip-testkit`: `hints_node()`, a hints node's HTTP API in the test process; every network after the first has its
  own relay URL.

## [2026-11-03] — workspace release

Waking a sleeping device (app plan stage A1), and native discovery through hints. DSIP spec: `poc-v1.0.3` (DSIP Core
1.0 with the Wake Profile draft `wake/0.1`, spec-gaps 169–176; 2,475 vectors, 0 failures).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.0 |
| `dsip-cli` | 0.2.0 (was 0.1.0) |
| `dsip-core` | 0.1.0 |
| `dsip-dht` | 0.1.0 |
| `dsip-endpoint` | 0.2.0 (was 0.1.0) |
| `dsip-events` | 0.2.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.4.0 (was 0.3.0) |
| `dsip-media` | 0.1.0 |
| `dsip-messaging` | 0.3.0 |
| `dsip-messaging-device` | 0.2.0 |
| `dsip-messenger` | 0.2.0 (was 0.1.0) |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.1.0 |
| `dsip-push` | 0.1.0 (new) |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.3.0 (was 0.2.0) |
| `dsip-schema` | 0.1.0 |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.1.0 |
| `dsip-transport` | 0.3.0 (was 0.2.0) |
| `dsip-wake` | 0.1.0 (new) |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes** (API; no behaviour changes for a deployment that does not turn waking on):
- `dsip_relay::RelayConfig` and `dsip_mailbox::MailboxConfig` gain a public field, `wake` (#23, #24): a struct literal
  that names every field must add `wake: None`. `RelayConfig::default()` and `MailboxConfig::new` set it.

The packages: `dsip-relay_0.3.0-1_<arch>.deb`, `dsip-mailbox_0.4.0-1_<arch>.deb`, and the new
`dsip-push_0.1.0-1_<arch>.deb` and image `ghcr.io/thevoiceguy/dsip-push`. The push gateway's unit is installed
disabled: it needs its DID, apps and credentials first (`/etc/dsip-push/push.toml`). `dsip-node` (0.1.1) and
`dsip-web` (0.1.1) are unchanged. Waking is off unless `--wake` is given to the relay or the mailbox.

### Added

- `dsip-wake` 0.1.0: the rules of the Wake Profile (draft `wake/0.1`, spec-gaps 169–175), waking a sleeping device
  through a push gateway (app plan stage A1). A waker's checks on a `wake-register` and its state (`Waker`: which
  held invites and stored items wake which devices, and when a registration ends), the push gateway's checks on a
  `wake-enrol` and a `wake` and the push it forwards, and the hint sealed to the device. Sans-I/O: the relay, the
  mailbox and `dsip-push` below run it. `dsip vectors run` (`dsip-cli`) runs the `wake/` vectors (2,475 in all).
- `dsip-push` 0.1.0: the push gateway an app's publisher runs (Wake Profile W§2–W§5). A device enrols its APNs or
  FCM token and gets a handle sealed under the gateway's key, so the gateway keeps no table; a waker's `wake` is
  checked and handed to APNs (HTTP/2, an ES256 provider token) or FCM (HTTP v1, a service account); a token the
  provider reports unknown ends its handle; wakes are rate-limited per handle and per waker. It serves its own
  `did:web` document naming its `DSIPWake` endpoint. `--record-to FILE` delivers nothing and records each push.
- `dsip-relay`: `--wake` (and `--wake-gateway`) makes the relay a waker. It answers `wake-register`, advertises
  `wake` in its `hello`, keeps registrations across a restart, and when it holds an invite for a registered device
  that is not bound, it sends the device's gateway a `call` wake, with the caller sealed to the device, then
  `call-ended` if the invite is cancelled or expires before the device binds.
- `dsip-mailbox`: `--wake` (and `--wake-gateway`) makes the mailbox a waker too. It answers `wake-register` (an owner
  operation, so an identity it does not serve enrols by it or is refused `mailbox.not-served`; spec-gap 176),
  advertises `wake` with the kind `message`, and when it stores an item for an identity it wakes that identity's
  registered devices that are not bound, at most once a minute each (never for an `ephemeral` deposit). Revoking a
  device's delegation, or releasing the identity, ends its registration.
- `dsip-push` is packaged like the other services: static binaries for amd64 and arm64, a `.deb` whose hardened unit
  is installed disabled (it needs its DID, apps and credentials first; `install-credential` puts the APNs key or the
  FCM service account where the sandboxed service alone can read it), and the image `ghcr.io/thevoiceguy/dsip-push`, tested by
  `crates/dsip-push/packaging/test.sh` in CI and released with the others. It reads a `--config` file as the others do.
- `dsip-transport`: `hints`, the hints tier for native clients over the hints nodes' HTTP API (DHT Hints Profile
  §10). `HintsClient::lookup` returns the winning record of every node's (§8.3) and `publish` posts one;
  `reachability` signs this device's hint (its relay, and for a `did:key` identity its mailbox, M§4.2), as the
  browser client does.
- `dsip-messenger`: `Messenger::discover_mailbox` finds another identity's mailbox in §8.1's order: the document files,
  then its `did:web` document fetched (`with_did_web`), then for an identity with no document its hint
  (`with_hints`), reused for 60 s. KeyPackage fetches and first contact use it, so a native client can message
  `did:key` identities as the browser client does (`crates/dsip-mailbox/tests/discovery.rs`: two `did:key`
  identities on two mailboxes, found through hints alone).
- `dsip-transport`: `wake::WakeClient`, the HTTPS exchange with a gateway (its endpoint from its DID document, its
  signed answer verified), and `waker::Wakes`, a waker's registrations and the wakes it sends, shared by the relay
  and the mailbox.
- `dsip-endpoint`: `verify::verify_profile_frame`, the envelope pipeline for a companion profile's message types.

## [2026-11-02] — workspace release

The Device Events Profile becomes normative 1.0. DSIP spec: `poc-v1.0.2` (DSIP Core 1.0 with Device Events Profile
1.0, spec-gaps 165–168; 2,359 vectors, 0 failures).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.0 |
| `dsip-cli` | 0.1.0 |
| `dsip-core` | 0.1.0 |
| `dsip-dht` | 0.1.0 |
| `dsip-endpoint` | 0.1.0 |
| `dsip-events` | 0.2.0 (was 0.1.0) |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.3.0 (was 0.2.1) |
| `dsip-media` | 0.1.0 |
| `dsip-messaging` | 0.3.0 (was 0.2.0) |
| `dsip-messaging-device` | 0.2.0 (was 0.1.0) |
| `dsip-messenger` | 0.1.0 |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.1.0 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.2.0 |
| `dsip-schema` | 0.1.0 |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.1.0 |
| `dsip-transport` | 0.2.0 |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes** (behaviour; no API is removed or changed):
- A member refuses a `device-event` from a device whose delegation lacks `dsip.events` (spec-gap 165). A gateway on
  this release asks for it (`dsip-msg --gateway`, implied by its listeners and `--heartbeat`), but an MLS leaf keeps
  the delegation it joined with. **A gateway already in an alarm group must be removed and added again** (its new key
  packages carry `dsip.events`); until then, members on this release refuse its events.
- A `device-event` or `alarm-ack` whose body breaks E§5's shape is refused (`content-body`, spec-gap 166).
- The gateway's SNMPv3 answers change (spec-gap 168, below).

The packages: `dsip-mailbox_0.3.0-1_<arch>.deb`, `dsip-web-0.1.1.tar.gz`; `dsip-relay` (0.2.0) and `dsip-node`
(0.1.1) are unchanged.

### Added

- **Device Events Profile 1.0** (DSIP spec-gaps 165–168), its last rules before it became final:
  - A member refuses a `device-event` whose sender leaf's delegation lacks `dsip.events` (`delegation-capability`):
    only a gateway raises alarms. `dsip_messaging::checks::check_object` reads the context's `leaf_capabilities`,
    which `dsip-messaging-device` fills from the sender's MLS leaf. `dsip-msg --gateway` puts `dsip.events` in the
    device's delegation, and any gateway listener or `--heartbeat` implies it.
  - `device-event` and `alarm-ack` bodies have a minimal shape (`content-body`); the alarm list ignores an `alarm-ack`
    whose state is neither `ack` nor `closed`.
  - Hold-down: a report from an SNMP inform is never held, and drops a clear held for its alarm
    (`dsip_events::HoldDown::report` takes `inform: true`); the gateway does this for every inform's event.
  - `dsip_events::usm::snmp_answer` and the vector check `snmp-answer`: the gateway's SNMPv3 Reports and Responses
    byte for byte.

### Changed

- **The gateway's SNMPv3 answers** (DSIP spec-gap 168): a Report's request-id is 0 (it was the request's when the
  PDU could be read); a USM Response copies the inform's contextEngineID and contextName (it used the gateway's engine
  ID and ""); a Response's `msgFlags` are the inform's auth and priv bits only (a TSM one kept other bits). pysnmp
  accepts all three, at authNoPriv and authPriv with MD5, SHA and SHA-256.

### Fixed

- The browser client's messages view rebuilt its conversation list, the group's member list and the add-member select
  on every render, and it re-renders on each receipt and archive deposit. A Remove button replaced between press and
  release got no click (Firefox fires none), and a member chosen to add could be reset. They are rebuilt only when what
  they show changes now, as the contacts and requests views already were. This was `web/test/messaging-group.mjs`'s
  intermittent 40-second timeout; the test now checks that a render which changes nothing keeps the buttons.

## [2026-11-01] — workspace release

A maintenance release: the mailbox's `--version`, and the packaging tests' intermittent failures fixed. DSIP spec:
`poc-v1.0.1` (unchanged; 2,325 vectors, 0 failures).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.0 |
| `dsip-cli` | 0.1.0 |
| `dsip-core` | 0.1.0 |
| `dsip-dht` | 0.1.0 |
| `dsip-endpoint` | 0.1.0 |
| `dsip-events` | 0.1.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.2.1 (was 0.2.0) |
| `dsip-media` | 0.1.0 |
| `dsip-messaging` | 0.2.0 |
| `dsip-messaging-device` | 0.1.0 |
| `dsip-messenger` | 0.1.0 |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.1.0 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.2.0 |
| `dsip-schema` | 0.1.0 |
| `dsip-session` | 0.2.0 |
| `dsip-testkit` | 0.1.0 |
| `dsip-transport` | 0.2.0 |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes:** none.

The mailbox package becomes `dsip-mailbox_0.2.1-1_<arch>.deb`; the relay and hints-node packages are unchanged
(`dsip-relay_0.2.0-1`, `dsip-node_0.1.1-1`).

### Added

- `dsip-mailbox --version` and `dsip-msg --version`, as `dsip-relay` and `dsip-node` have; the packaging test checks
  that each installed service prints its package's version (#15).

### Fixed

- The packaging tests and seven demos failed intermittently: a check `… | grep -q` under `set -o pipefail` failed when
  `grep -q` stopped at its match and the writer died of SIGPIPE, though the line was there. They read to the end now
  (`grep >/dev/null`) (#14). Tests only.

## [2026-10-31] — workspace release

The service nodes: the relay, the mailbox and the hints node as products, from config files to signed release
packages (`docs/dsip-service-nodes-plan.md`, S1–S8). DSIP spec: `poc-v1.0.1` (DSIP Core 1.0 with spec-gap 164;
2,325 vectors, 0 failures).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.0 |
| `dsip-cli` | 0.1.0 |
| `dsip-core` | 0.1.0 |
| `dsip-dht` | 0.1.0 |
| `dsip-endpoint` | 0.1.0 |
| `dsip-events` | 0.1.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.2.0 (was 0.1.0) |
| `dsip-media` | 0.1.0 |
| `dsip-messaging` | 0.2.0 (was 0.1.0) |
| `dsip-messaging-device` | 0.1.0 |
| `dsip-messenger` | 0.1.0 |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.1 (was 0.1.0) |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.1.0 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.2.0 (was 0.1.0) |
| `dsip-schema` | 0.1.0 |
| `dsip-session` | 0.2.0 (was 0.1.0) |
| `dsip-testkit` | 0.1.0 |
| `dsip-transport` | 0.2.0 (was 0.1.0) |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes:**
- `dsip_relay::RelayConfig` and `dsip_mailbox::MailboxConfig` gain `did_web` (#4), and `RelayConfig` gains
  `queue_store` (#5). Struct literals need them, or `..Default::default()`.
- `dsip_mailbox::store::Store::retain` takes a predicate, `impl Fn(&str) -> bool`, instead of a slice of cursors (#6).
- `dsip_transport::status::Page` gains `Admin` and is no longer `Copy` (#7).

The service packages change their names with their versions: `dsip-relay_0.2.0-1_<arch>.deb`,
`dsip-mailbox_0.2.0-1_<arch>.deb`, `dsip-node_0.1.1-1_<arch>.deb`.

### Added

- **Config files for the relay and the mailbox** (service-nodes plan S1). `dsip-relay --config <file>` and
  `dsip-mailbox --config <file>` read a TOML file whose keys are their flags in `snake_case`. A flag on the command
  line wins, and a repeatable one replaces the file's list. An unknown key is an error. Each crate has a
  `config.example.toml` explaining every key, which a test checks against the binary. The mechanism is
  `dsip_transport::config_file`, behind dsip-transport's new `cli` feature.
- **`did:web` over HTTPS in the relay and the mailbox** (S2). Both fetch the `did:web` documents a frame needs (its
  signer, its delegations' issuers, and the grants a `subscribe` presents) before verifying it, after their document
  files, which still answer first (§8.1). A document is reused for `--did-web-ttl` (300 s). A DID whose fetch failed
  is not fetched again for 60 s, and fetches are capped per frame and in flight. `--did-web-ca` adds PEM roots and
  `--no-fetch-did-web` turns fetching off. `dsip_transport::resolver` gains `WebDocuments`, `Over`, `web_documents`,
  `DidWebResolver::with_ca` and `DidWebResolver::cached`. `demos/did-web-demo.sh` runs in CI.
- **The relay's queue on disk** (S3). `dsip-relay` keeps its store-and-forward queue and the recipients it knows
  in `<state>/queue.redb`. A restarted relay, even one that was killed, delivers what it held within each
  envelope's deadline, and a known, offline recipient stays known (§13.3). After each step only the queues it touched
  are rewritten, durably. `dsip_relay::store::QueueStore`; `dsip_session::fork::Relay` gains `known_recipients` and
  `restore` (`Known`; `Queued` is now serde). `demos/relay-restart-demo.sh` runs in CI.
- **The mailbox's state in SQLite** (S4). `dsip-mailbox` keeps its state in `<state>/mailbox.sqlite` instead of
  `mailbox-state.json`, which was rewritten whole after every change (spec-gap 59). Each stored item is a row,
  holding the machine's record and the payload. It is written when the item is stored and deleted when the machine
  drops it. The rest is saved as parts (per owner, per hubbed group, per kind), and only the parts that changed are
  written, in one durable transaction. A mailbox upgraded from the JSON file imports it once and renames it
  `mailbox-state.json.imported`. A save's cost no longer grows with the items held: `store_stress` measures about
  42,000 deposits/s at 1,000, 10,000 and 100,000 items held, and about 1.45 KB on disk per 1 KB item.
  `dsip_messaging::mailbox::Mailbox` gains `changes`, `saved`, `all_stored`, `record` and
  `full_state_without_items`.
- **Operating the relay and the mailbox** (S5).
  - **Certificate reload on `SIGHUP`.** Both binaries read their certificate and key again on `SIGHUP`. New TLS
    handshakes get the renewed certificate, and connections already open, and the devices bound on them, are
    untouched. A renewal that does not load (a half-written file, a key that is not the certificate's) is logged
    and the previous certificate stays in service. `dsip_transport::tls::Certificates`.
  - **Admin commands on the status port.** `dsip-relay admin bindings` lists the bound devices, each with the
    address it bound from and for how long. `dsip-mailbox admin enrolments` lists the enrolled identities against
    `--serve-any` (storage, devices bound, last `hello`, when idle expiry releases them) and the configured owners.
    `dsip-mailbox admin release <did>` ends an enrolment: everything held for the identity is deleted and its
    bindings closed, as when it releases itself (M§4.1 "By its operator", spec-gap 164). The
    commands find the service from `--status <addr>`, or from `status_listen` in its `--config` file, and print
    JSON with `--json`. A command that changes state is a `POST` carrying an `x-dsip-admin` header, so a web page
    cannot send one. `dsip_transport::admin`, `dsip_transport::status::request`;
    `dsip_messaging::enrolment::Enrolment` gains `operator_release`, the `enrolment-trace` event
    `operator_release`, and `is_configured`.
  - **journald.** `--log auto|journald|stderr`. When standard error is the journal (`JOURNAL_STREAM` names it),
    `auto` logs to the journal natively, with each line's level as its priority, so `journalctl -p warning` works.
    Elsewhere it logs to standard error, as before.
    `dsip_transport::logging`.
  - `demos/operating-demo.sh` runs in CI.
- **Packages for the relay and the mailbox** (S6). `packaging/build.sh [--image]` builds, for `dsip-relay` and
  `dsip-mailbox`:
  - static musl binaries for x86_64 and aarch64, and their tarballs;
  - a `.deb` for each architecture, and `SHA256SUMS`;
  - with `--image`, a distroless image.

  Each `.deb` installs:
  - the config `/etc/dsip-relay/relay.toml` or `/etc/dsip-mailbox/mailbox.toml`, a conffile kept on upgrade and
    removal;
  - a `DynamicUser` unit with the same sandbox as dsip-node's, whose `ExecReload` sends SIGHUP;
  - `/usr/libexec/<service>/install-certificate`. As certbot's `--deploy-hook`, it copies the renewed pair into the
    service's state directory (the service cannot read `/etc/letsencrypt`) and reloads the service in place.

  `packaging/build.sh dsip-web` packs the browser client as `dsip-web-<version>.tar.gz` for the relay's `--www`.
  `packaging/test.sh` runs in CI. It installs both `.debs` on one systemd host and runs the images locked down. In
  both it checks that the relay's queued invite and certificate, and the mailbox's enrolment and service key,
  survive a crash and a restart. It also checks that a certificate renewal reaches the running relay. dsip-mailbox
  gains the feature `static`: SQLite and OpenSSL compiled in.
- **One host, one name** (S7, `docs/one-host.md`). The relay, the mailbox, the hints node and coturn on one machine
  behind one DNS name. The relay on 443 serves the browser client, `/config.json`, `/turn` and the hints node at
  `/dsip/v1/`; the mailbox on 9443 uses the same certificate. Two ways to set it up:
  - `packaging/one-host/configure` sets up the three installed `.deb`s and coturn. It writes the configs, the client's
    defaults (naming the mailbox by its service DID), port 443's drop-in and one certbot hook for both services. Run
    it again after a change: it restarts only what changed.
  - `packaging/one-host/compose/` (`compose.yaml` and `./init`) runs the images. The relay, the mailbox and the node
    share one network namespace, so they reach each other on loopback as on a host, and the node trusts the relay's
    `X-Forwarded-For`.

  `packaging/one-host/test.sh` runs both ways in CI, checking a renewal and an unchanged second run.
- **Releases carry the services** (S8). A `vYYYY.MM.DD` tag runs `.github/workflows/release.yml`. It builds and
  tests every service's packages as CI does, then publishes:
  - the GitHub release, its notes from the tag's changelog section;
  - every service's tarballs and `.deb`s (amd64, arm64), the `dsip-web` tarball, `dsip-one-host-<release>.tar.gz`
    and one `SHA256SUMS`, each file attested (`gh attestation verify`);
  - the images `ghcr.io/thevoiceguy/dsip-relay`, `-mailbox` and `-node` for linux/amd64 and linux/arm64, tagged
    with the release and `latest`, signed with cosign (keyless) and attested.

  A pull request that changes the release, or a manual run, is a dry run. `packaging/release-assets.sh` gathers the
  files and writes the notes.

### Removed

- **dsip-node's own releases.** The `dsip-node-v*` tags and `dsip-node-release.yml` give way to the workspace release.

### Fixed

- **The services' images took 10 s to stop, and were then killed.** As PID 1 in a container, `dsip-relay`,
  `dsip-mailbox` and `dsip-node` ignored `SIGTERM`, so `docker stop` waited out its timeout and sent `SIGKILL`. A
  queued invite could expire in that window: the packages test caught it in CI. They now exit on `SIGTERM` or
  `SIGINT` (`dsip_transport::shutdown`); each writes its state as it changes, so nothing is lost.
- **The mailbox kept every item's payload forever.** When the machine dropped an item (queue-mode deletion,
  retention, pending-group expiry), its payload stayed in memory and in the saved state. It now goes with the item.

### Changed

- **`spec/` moves to DSIP `poc-v1.0.1`**, DSIP Core 1.0 with spec-gap 164 (M§4.1: a mailbox's operator MAY end an
  enrolment), from a commit between tags. 2,325 vectors, 0 failures. The release workflow requires `spec/` on a tag.
- `dsip_mailbox::store::Store::retain` takes a predicate. `Store` no longer has to be saved whole.
- **Breaking:** `dsip_relay::RelayConfig` and `dsip_mailbox::MailboxConfig` gain a `did_web` field (`None` by
  default: the library fetches nothing unless asked), and `RelayConfig` a `queue_store` field (`None`: in memory, as
  before). Struct literals need them, or `..Default::default()`.
- **Breaking:** `dsip_transport::status::Page` gains `Admin` and is no longer `Copy`; a service's status renderer
  answers it.

## [2026-10-29] — workspace release

The first release. DSIP spec: `poc-v1.0` (DSIP Core 1.0 and its profiles; 2,323 vectors, 0 failures).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.0 |
| `dsip-cli` | 0.1.0 |
| `dsip-core` | 0.1.0 |
| `dsip-dht` | 0.1.0 |
| `dsip-endpoint` | 0.1.0 |
| `dsip-events` | 0.1.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.1.0 |
| `dsip-media` | 0.1.0 |
| `dsip-messaging` | 0.1.0 |
| `dsip-messaging-device` | 0.1.0 |
| `dsip-messenger` | 0.1.0 |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.0 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.1.0 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.1.0 |
| `dsip-schema` | 0.1.0 |
| `dsip-session` | 0.1.0 |
| `dsip-testkit` | 0.1.0 |
| `dsip-transport` | 0.1.0 |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes:** none; this is the first release.

### Added

- **The move from DSIP.** Every crate of the DSIP reference implementation, its workspace, `demos/`, the browser
  client (`web/`) and the stack's documents (`docs/`) come from DSIP's `impl/`, with their history (`git
  filter-repo`). Every crate is 0.1.0.
- **`spec/`.** DSIP as a git submodule at `poc-v1.0`: DSIP Core 1.0 and its profiles (`spec/v1.0/`), the schemas
  the crates embed, and the conformance suite (`spec/impl/vectors/`: 2,323 vectors, 0 failures).
- **Docs:** `README.md`, `CLAUDE.md`, `RELEASING.md` (siphon-rs's model), and `CHANGELOG.md`.
- **Public before the first release.** The repository went public on 2026-10-29, so that CI runs.
- **CI:** build, clippy, tests, docs, the vector suite and every demo; the wasm build and the browser client's
  tests; the dsip-node packages, and their release on a `dsip-node-v*` tag.
