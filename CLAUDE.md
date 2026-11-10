# CLAUDE.md — dsip-rs

## What this repository is

dsip-rs is the Rust stack for DSIP. It holds the engines, the runtime, the facades (`dsip-phone`, `dsip-messenger`),
the services (relay, mailbox, hints node, gateway), the browser client (`web/`) and the demos. It grew as the
reference implementation in the DSIP repository (github.com/feryx-io/DSIP, `impl/`), and its history comes
from there. Read `docs/dsip-stack-design.md` before structural changes, and `docs/dsip-rs-guide.md` for how the
pieces are meant to be used.

**DSIP is upstream for everything normative**: the specification, the JSON Schemas, the conformance vectors, the
Python harness, the TypeScript second implementation and the spec-gap decisions. Here DSIP is the `spec/`
submodule, pinned to a tag. dsip-rs is measured against it.

## Non-negotiable rules

1. **The vectors are the contract.** `cargo run -p dsip-cli -- vectors run` runs every vector in
   `spec/impl/vectors`, and it stays at zero failures. A refactor changes no verdict.
2. **Vectors before code, in DSIP.** New stateful behaviour (a transition, a timer, a race) starts as a vector in
   DSIP. There the Python harness and `impl-ts` agree on it first. Then the submodule moves here and the Rust
   follows. Expected outcomes are written by hand from the spec, never recorded from this code. DSIP's CI runs
   three-way parity (Python, this Rust, TypeScript) against a pinned dsip-rs commit.
3. **`spec/` is never edited here.** It moves only to a DSIP tag or commit, deliberately, and the move is recorded
   in `CHANGELOG.md`. A vector or schema that looks wrong is a finding for DSIP: draft the spec-gap text there.
   Never weaken a vector, or route around one, to make code pass.
4. **No silent spec choices.** Where code resolves something the spec leaves open, add an `Impl:` line, and draft a
   spec-gap for DSIP if it is a genuine ambiguity.
5. **Verification order is untouchable.** core → schema → session: a message reaching `dsip-session` has already
   passed signature, replay and shape checks. Signatures are over the received bytes. Never re-serialize on the
   verify path (§10.2), and never "canonicalize".
6. **Authority order (§8.1):** DID document > alias resolution > cache > hints. The DHT and Pkarr are a hints tier
   only. No code path treats a hint, a cache entry or a relay claim as authoritative.
7. **Registry values stay open.** Reason tokens, `answered_by`, `progress.status` and other registry-governed values
   are never closed enums: shape validation plus membership checks, with category fallback (§15).
8. **Wire format at parse (§10.3):** UTF-8 only, integer timestamps, floats rejected, in `dsip-core`.
9. **Keep the engines portable.** The sans-I/O crates (core, schema, session, endpoint, webrtc-binding, messaging)
   take no tokio, no sockets and no filesystem. Time comes in as an argument, so they build for wasm.

## Documentation standard

- `#![deny(missing_docs)]` is on in every library crate. Every module, public type and public function has a doc
  comment.
- Normative code cites the spec with a `Spec:` line, using the current (1.0) section: `Spec: §12.6`,
  `Spec: M§6.5`. A local decision gets an `Impl:` line. `Spec:` is a citation and `Impl:` a decision; never mix
  them. Modules with no normative content say `Spec: none (infrastructure)`. Crate `lib.rs` names the sections the
  crate owns.
- Cite the core spec as `§n`, and the profiles as `B§n` (WebRTC binding), `M§n` (messaging), `G§n` (gateway),
  `R§n` (RTP/SRTP), `T§n` (alias transparency), `E§n` (device events), `C§n` (recording), `N§n` (number
  attestation), `P§n` (presence). The text is in `spec/v1.0/`.
- DSIP's `impl/tools/spec_lint.py` checks the `Spec:` headers and builds the coverage table from a checkout of this
  repository.

## Conventions

- **Releases:** CalVer workspace tags over per-crate SemVer, and a changelog listing every crate's version and its
  breaking changes (`RELEASING.md`, siphon-rs's model).
- **Lints:** `cargo clippy --workspace --all-targets --all-features -- -D warnings` on the toolchain pinned in
  `rust-toolchain.toml`, plus `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`. Formatting matches the
  surrounding code (about 120 columns).
- **Style:** inject hooks (metrics, capture, rate limits); never use process-wide set-once globals.
- **Dependencies:** inter-crate dependencies are `path` only. siphon-rs and forge-media are git dependencies pinned
  to a rev.
- **Demos** are self-verifying and each runs in CI. Check the names and ports in `demos/` before adding one.

## Commands

```bash
git submodule update --init                  # spec/
cargo build --workspace
cargo test --workspace
cargo run -p dsip-cli -- vectors run         # the conformance suite
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
web/build.sh && web/test/run.sh firefox      # browser client tests (local Chromium may lack libnss3)
```

`target/debug` grows without bound and has filled the disk before: `cargo clean --profile dev` when short of space.
Python installs here need `--break-system-packages`.

## Things not to do

- Do not edit `spec/`, and do not add probe vectors anywhere.
- Do not add DHT authority, DHT-stored presence, or Sybil "solutions".
- Do not extend the gateway past Gateway Profile 1.0: no production outbound STIR signing, no video across the
  gateway, no SIP 3xx as forking, no REFER.
- Do not treat prose example ids like `01HZINVITEABC` as valid ULIDs.
