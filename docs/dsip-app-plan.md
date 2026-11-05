# The DSIP app: the official client on Windows, macOS, Linux, Android and iOS

*Plan, draft, 2026-10-31. The products after the service nodes (`dsip-service-nodes-plan.md`, S1–S8, released in
`v2026.10.31`). It draws on Anvil (github.com/thevoiceguy/anvil), our multiplatform SIP softphone, which has already
solved most of what an app needs around the protocol: a toolkit, the system call screens, packaging and updates.*

## 1. Goal

A person installs the DSIP app on any of five platforms and, with no account anywhere, has an identity, contacts
reached by first contact (§19.4), calls (§12, WebRTC Media Binding 1.0) and messages (Messaging Profile 1.0) that
are end to end encrypted, presence they choose to share (Presence Profile), and their other devices (§7.4). A call
rings a phone that is asleep, on the lock screen, like any other call. The app looks and behaves the same everywhere.

The browser client (`dsip-client-plan.md`, M7) stays what it is: the reference client that needs no install. This app
is the product. Its non-goals list (no accounts, no recovery, no push, no packaging) is exactly what this plan adds.

Not in scope for 1.0: video (the binding has it; the app is audio first, as Anvil is), SIP accounts in the same app
(§4 decision 2), the gateway to the PSTN (Gateway Profile 1.0 exists; an app that dials numbers through one is
later), compliance recording (Recording Profile, draft), and number attestation (draft).

## 2. Where things stand

| | Exists | Missing for the app |
|---|---|---|
| Protocol | Core 1.0, WebRTC Media Binding 1.0, Messaging Profile 1.0, Device Events 1.0 final; 2,359 vectors, three implementations | **waking a sleeping device** (§3, stage A1): nothing in DSIP lets a relay or mailbox wake an app; Presence Profile still a draft |
| Engine | sans-I/O and shared by native and wasm: `dsip-endpoint` (§12), `dsip-messaging-device` (the `Messenger`) | — |
| Native facades | `dsip-phone` (calls, native audio through `dsip-media`), `dsip-messenger` (the mailbox host loop, SQLite store), testkit, examples | one state model for a whole app (stage A2), an API another language can call |
| Media | `dsip-media` on forge-media's WebRTC (DTLS-SRTP, ICE, Opus) | echo cancellation and the platforms' audio (Anvil's `anvil-audio`: cpal with sonora, WebRTC's AEC3 in Rust, on the desktops; the phones' voice modes, AVAudioSession and Oboe, are host-owned and still to come in Anvil too) |
| Services | relay, mailbox, hints node: packaged, signed, deployed (L1/L2) | a push gateway (A1) |
| A client | the browser client, end to end over the WAN | every native concern: system call screens, push, background, key storage, packaging, updates |
| Keys | device delegations, second devices, `did:web` rotation (§7.4, §7.5) | keys in the platforms' keystores; **backup and recovery** (A6) |

## 3. Stages

Each stage ends in something a person can use, and lands as PRs with tests in CI. Spec work comes first and stays
vectors first: a stage that needs protocol waits for its vectors, Python, impl-ts, then dsip-rs.

- **A0. Decisions** (§4). The owner settles them; this plan is updated to match.
- **A1. Waking a device (spec, then services).** The one protocol gap. iOS and Android end a background app's
  sockets, so an incoming call or message must arrive as a push (PushKit and CallKit on iOS, FCM high priority on
  Android). The shape, as Anvil does for SIP with RFC 8599:
  - a device gives its relay (calls) and its mailbox (messages) a **push address**: a push gateway's URI and an
    opaque, gateway-issued token, in its `hello` or its `mailbox-config`;
  - when the relay would hold an envelope for that device (§13.3) or the mailbox has an item for it, it asks the
    gateway to wake it, signed by the relay's or mailbox's DID, with nothing in it but the event's kind and an id;
  - the **push gateway** is the app publisher's: only the publisher holds the APNs key and FCM account, so a relay
    run by anyone else cannot push to the official app directly. It checks the request's signer against the token's
    binding, and forwards to APNs or FCM;
  - the woken app binds, receives the invite or the item through DSIP as usual, and on iOS rings CallKit at once
    with what the push said, then fills in the caller from the verified invite (Apple's rule: every VoIP push
    reports a call; Anvil's `docs/PLATFORM_INTEGRATION.md` "A call shown from a push").
  Questions it must answer, each a spec-gap: what the push payload may carry (a caller's name on the lock screen means
  sealing it to the device); how a token is bound to one relay or mailbox so it cannot be used by others to wake the
  phone; retries and expiry; what the relay does when the device does not bind in time (§12.10 T-Establish already
  ends the call). Delivered as a profile document, vectors, the three implementations, then the relay, the mailbox
  and a `dsip-push` gateway service packaged like the others.
  *Status (2026-10-31):* the profile is DSIP's Wake Profile draft (`wake/0.1`, `W§n`; spec-gaps 169–175, all
  decided as drafted), pinned by the `wake/` vectors on which the three implementations agree; its rules are the
  `dsip-wake` crate. The relay wakes (`dsip-relay --wake`) through `dsip-push`, the gateway service, tested end to
  end in `crates/dsip-push/tests/relay_wake.rs`; the mailbox wakes for stored items (`dsip-mailbox --wake`,
  `crates/dsip-mailbox/tests/wake.rs`); `dsip-push` is packaged (`.deb`, image) and tested like the other services.
  Left for A1: delivery through Apple's and Google's services, which needs the app's APNs key and Firebase project. The
  device side's protocol is here for the app (A5d): `dsip_transport::wake::enrol`, `dsip_wake::registration` and
  `seal_keys`, `Phone::wake_register` (the relay, its answer read apart from the endpoint, which knows only the core's
  types) and `Messenger::wake_register` (the mailbox), tested against `dsip_testkit::PushGateway`.
- **A2. The running client (`dsip-app` crate).** The app as a long-lived thing, as Anvil's `anvil-app` is: it owns
  the identity, a `dsip-phone` and a `dsip-messenger`, keeps the state a screen shows (identity, devices, contacts and
  their grants, conversations, calls, presence, settings), and publishes every change on one stream. Commands go in;
  the screens only read. A local control socket with a CLI (`dsip-app run`, `dsip-app call <did>`) drives the same
  state, so the CLI and the app cannot behave differently, and CI tests the client without a UI. Native audio
  through `anvil-audio` (decision 4).
- **A3. The desktop app.** A Flutter app over `dsip-app` through `flutter_rust_bridge` (decision 1): first run (make
  an identity, or join as a second device of one), contacts and first contact, calls, conversations, presence,
  devices, settings. Every string localized from the start; screens tested against a fake client; golden screenshots
  per platform. Linux, Windows and macOS in CI.
- **A4. Desktop distribution.** Installers on a release tag (Inno Setup per user on Windows, a universal `.dmg` on
  macOS, `.deb` and AppImage on Linux), each installed and started in CI before publishing; an auto-updater with an
  Ed25519-signed manifest, as Anvil's `anvil-update`; code signing and notarization once the certificates exist.
- **A5. Mobile.** Android and iOS builds (cargokit for the Rust core); the system call screens: CallKit, and a
  self-managed `ConnectionService` with a foreground service during a call; audio routing (earpiece, speaker,
  Bluetooth); then A1's push wired in, so a sleeping phone rings and a message arrives. Anvil's U4 and U5 are the
  pattern, including the path where a push starts the core without Flutter (JNI on Android, a C ABI on iOS).
- **A6. Keys, backup and recovery.** Device keys stored under the platform's protection (Keychain, Android Keystore,
  DPAPI on Windows, the Secret Service on Linux). DSIP's keys are Ed25519, which neither the Secure Enclave (P-256
  only) nor the Keychain's own key generation (RSA and NIST curves) makes. On iOS the key is made by CryptoKit
  (`Curve25519.Signing.PrivateKey`) and kept as a Keychain item, encrypted at rest by Data Protection and, if chosen,
  usable only after Face ID or the passcode (`SecAccessControl`); it signs in the app's memory, unlike a key that
  never leaves the Enclave. `ThisDeviceOnly` keeps it off backups and iCloud; a synchronizable item lets iCloud
  Keychain carry it, end to end encrypted, to the person's other Apple devices (decision 5). The identity key is the hard part: it signs
  every delegation, and a `did:key` identity cannot rotate (§7.5), so losing it is losing the identity. The stage
  decides where it lives (decision 5) and gives a backup a person can actually keep.
- **A7. Release.** Accessibility, localization, store listings, TestFlight and Play, signed builds of all five from
  one tag.

## 4. Decisions

1. **Toolkit.** (a) **Flutter** with `flutter_rust_bridge`, as Anvil chose (its `docs/APP.md` §2): stable on all five
   platforms, draws the same pixels on each, maintained plugins for CallKit, ConnectionService, push, the audio
   session and the tray, and a Rust API called directly from Dart with async and streams. Cost: Dart, and about
   20 MB (desktop) and 10 MB (mobile) of runtime. (b) Native UIs (SwiftUI, Compose, a desktop toolkit) over a UniFFI
   layer: the best fit per platform, three or four UIs to keep in step. (c) Tauri 2 around the browser client's page:
   the most reuse on desktop, but WebViews render differently and phone-call integration on Tauri mobile is young.
   *Draft: (a). Anvil has shown it on all five, CallKit and ConnectionService included.*
2. **One app or two.** (a) A separate DSIP app that shares Anvil's foundations. (b) DSIP as an account type inside
   Anvil, beside SIP. (b) reuses the most, but Anvil is FCP's tenant-branded softphone and its model is SIP's
   (registration, lines, park, BLF); a DSIP identity is not an account at a provider. *Draft: (a), and revisit once
   both exist: a SIP account in the DSIP app, or the reverse, is then a feature.*
3. **Where it lives.** (a) A new repository, `dsip-app`, depending on dsip-rs by release tag (RELEASING.md
   "Downstream"), with the Flutter app outside the Cargo workspace as Anvil's `app/` is. (b) In dsip-rs. *Draft: (a):
   dsip-rs is the stack and its services; the app has its own release cadence, signing secrets and store listings.*
4. **What is shared with Anvil, and how.** Anvil has generic pieces: `anvil-audio` (cpal, sonora echo cancellation,
   device enumeration), `anvil-update` (the signed manifest and per-installer updates), and on the Dart side the
   mobile call bridge, the packaging scripts and the design system. (a) Git dependencies on Anvil's tags for the two
   crates now, and a shared Flutter package when the second app needs the same Dart. (b) Move the shared pieces into
   their own repository first. (c) Copy them. *Draft: (a); the crates are already independent of SIP.* Both media
   stacks are forge-media, so the audio path is the same code.
5. **Where the identity key lives** (A6). (a) On the first device, in its keystore, with an encrypted export the
   person keeps (a file or a printed code); later devices hold only device keys and delegations. (b) Only in the
   export: every device, the first included, runs on a delegation, and adding a device needs the export. (c) A
   `did:web` identity by default for people with a domain, which can rotate (§7.5). (d) A platform's end-to-end
   encrypted keychain sync (iCloud Keychain on Apple, Google's on Android) as the backup, for people who stay on one
   platform. *Draft: (a) for 1.0, (c) and (d) offered; a recovery design that needs no file and no platform is a
   later profile.*
6. **The push gateway.** (a) The publisher runs one `dsip-push` for the official app; any relay or mailbox can use it
   through tokens bound to them. (b) Every operator runs their own, and builds the app with their own push keys, as
   a branded Anvil does. *Draft: (a) for the official app, (b) possible for branded builds.*
7. **Audio first.** Calls are audio in 1.0; video when the app's call screens and media are settled. *Draft: yes.*

## 5. Out of scope, and why

- **A hosted account service or a directory.** DSIP has no accounts; finding people is first contact, `did:web`
  names and hints (§8). A directory is a service of its own.
- **Contact discovery by phone number** in 1.0: Number Attestation is a draft, and uploading address books is a
  privacy design of its own.
- **Group calls.** The core has forking, not conferencing; a conference service is a product of its own.
- **Interop with Anvil's SIP accounts** in 1.0 (decision 2).

## 6. Risks

| risk | consequence | mitigation |
|---|---|---|
| A1 takes longer than the app | mobile calls only ring while the app is open | A2–A4 do not depend on it; desktop ships first |
| Apple's VoIP push rules | an app that misses reporting a call has its pushes cut off | every push reports a call at once (Anvil's tested path); A1's payload is designed for it |
| identity key loss | a person loses their identity | decision 5; the export offered at first run, not later |
| a push gateway sees traffic patterns | metadata (when a device is woken, by which relay) | payloads carry no content and no caller in clear; documented as A1's privacy section |
| two apps sharing code | Anvil's changes break the DSIP app | shared crates pinned by tag; the shared surface kept small |
