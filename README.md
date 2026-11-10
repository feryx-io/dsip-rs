# dsip-rs

A Rust stack for **DSIP** (Decentralized Session Initiation Protocol), an identity-first protocol for signalling,
media negotiation and messaging. Build DSIP applications on it: softphones, chat clients, bots, gateways, relays and
mailboxes.

**Status: pre-release.** It implements DSIP Core 1.0 and its profiles, and passes the whole conformance
suite: 2,325 vectors from DSIP. The first release is `v2026.10.29` (`RELEASING.md`). Start
with the [usage guide](docs/dsip-rs-guide.md).

## How it relates to the other projects

- **[DSIP](https://github.com/feryx-io/DSIP)** holds the specification, the JSON Schemas, the conformance vectors,
  the Python reference harness and a second, TypeScript implementation. It is where the spec changes and where
  vectors are written. This repository grew there as its reference implementation (`impl/`) and keeps that history.
  DSIP is the `spec/` submodule here, pinned to a tag.
- **[siphon-rs](https://github.com/thevoiceguy/siphon-rs)**, the SIP stack, is a sibling. dsip-rs follows its
  conventions: the release model in [`RELEASING.md`](RELEASING.md), facades over low-level crates, storage behind
  traits, and a testkit. The gateway uses siphon-rs for its SIP leg, and the media path uses forge-media. Both are
  git dependencies pinned to a rev.

## Layout

```
crates/
  Facades
    dsip-phone             place and take calls: Phone, Call, IncomingCall, native media
    dsip-messenger         a messaging device: the mailbox connection, reconnects, fetches, persistence
  Services (a library each, with a thin binary)
    dsip-relay             the relay: hello binding, forking, store-and-forward, presence (§13)
    dsip-mailbox           the mailbox and hub service (M§4), and dsip-msg, a console messaging client
    dsip-node              a deployable hints node: overlay, Mainline DHT (Pkarr), HTTP hints API
    dsip-gateway           SIP/PSTN gateway (Gateway Profile 1.0, G§); feature `host` for the B2BUA
    dsip-push              the push gateway (Wake Profile, draft): enrolments, wakes, APNs and FCM
  Runtime and features
    dsip-transport         the tokio ws/1.0 binding (§13.2): connections, reconnects, the Agent
    dsip-media             native WebRTC media (forge-media or webrtc-rs)
    dsip-messaging-device  the Messaging Profile device on OpenMLS, shared with the browser
    dsip-mls               the OpenMLS binding; feature `sqlite` for persistent device state
    dsip-broadcast         Verified Broadcast (§22), subscriptions (§9.3), presence publisher and watch
    dsip-dht               signed reachability hints (§8.5); never authoritative
    dsip-number            Number Attestation (draft, N§)
    dsip-recording         Recording Profile consent (draft, C§)
    dsip-wake              Wake Profile (draft, W§): registrations, wakes, the push gateway's checks, the sealed hint
    dsip-events            Device Events Profile (draft, E§)
    dsip-kt                alias transparency building blocks (draft, T§)
  Engines, sans-I/O
    dsip-core              identifiers, DIDs, keys, signed envelopes (§7, §10)
    dsip-schema            Core 1.0 JSON Schemas, embedded, and the semantic checks (§10.3)
    dsip-session           the §12 state machine, timers, races; the §12.7 relay leg tracker
    dsip-endpoint          the endpoint core: verify → §12 engine → build and sign
    dsip-webrtc-binding    WebRTC Media Binding 1.0 rules (B§)
    dsip-messaging         Messaging Profile 1.0 rules: messages, hub and mailbox state machines (M§)
  Hosts and tools
    dsip-wasm              the endpoint and the messaging device for the browser, with TypeScript types
    dsip-cli               `dsip`: identities, calls, signing, and `dsip vectors run`
    dsip-testkit           an in-process network for tests: no sockets, no ports
web/                       the browser client, on dsip-wasm (web/README.md)
demos/                     self-verifying wire demos, each run in CI
packaging/                 the services' .debs, images and tarballs (build.sh, test.sh); one-host/: the relay,
                           mailbox, hints node and coturn on one host behind one name (docs/one-host.md)
docs/                      the usage guide, the design note (build order, decisions), client and node plans
spec/                      DSIP, as a git submodule at a tag: v1.0/ (spec text, schemas), impl/vectors/ (the suite)
```

## Build and test

```bash
git clone --recurse-submodules https://github.com/feryx-io/dsip-rs   # or: git submodule update --init
cargo build --workspace
cargo test --workspace
cargo run -p dsip-cli -- vectors run         # the conformance suite: 2,475 vectors, 0 failures
cargo clippy --workspace --all-targets --all-features -- -D warnings
bash demos/echo-bot-demo.sh                   # any demo; CI runs them all
web/build.sh && web/test/run.sh firefox       # the browser client and its tests
```

The toolchain is pinned in `rust-toolchain.toml`. The messaging crates need OpenMLS's minimum Rust (1.91). The rest
of the workspace targets 1.85. `python3` is needed at build time for the schema freshness check, and by some demos.

## Following the spec

When DSIP tags a new spec version, move the submodule (`git -C spec checkout <tag>`), then run
`cargo run -p dsip-cli -- vectors run` and the tests. Change the code until they pass again, and record the move
in `CHANGELOG.md`. A vector that looks wrong is a finding for DSIP. Never work around one here.

## Licence

MIT or Apache-2.0, at your option. The spec in `spec/` keeps DSIP's licences: CC BY 4.0 for the prose, MIT or
Apache-2.0 for the schemas and vectors.
