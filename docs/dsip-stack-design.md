# A DSIP stack for developers — design note

**Status:** a design note, written 2026-10-17 at poc-v0.16 and decided 2026-10-18, for when the specs settle. It does not start work. It
records what a developer-facing DSIP stack would contain, how it relates to siphon-rs, what in today's PoC is and is
not library-shaped, and the order to build it in. The decisions are in [§9](#9-decisions-the-owner-2026-10-18).

## 1. The goal

A set of Rust crates (with a browser build) that a developer uses to build a DSIP application — a softphone, a
chat client, a contact-centre agent, a relay or mailbox operator's service — without reading the spec first. The
model is siphon-rs for SIP: layered crates, an integrated high-level API over a low-level one, pluggable storage
and transport, and a reference daemon.

What the stack is measured against is already built: the 2,130 vectors in `impl/vectors` and the second
implementation that passes them. A stack crate that implements normative behaviour passes the vectors for it;
that rule carries over unchanged.

## 2. What exists today

About 40k lines of Rust in 21 crates (all 0.1.0, none published) and about 2,300 lines of browser JavaScript.

**Already in good shape for a library:**
- **A sans-I/O core.** `dsip_session::Endpoint::step(&Event) -> Vec<Emission>` and `fork::Relay::step` are pure;
  time enters as an `Advance` event; `next_deadline()` says when to call again. `dsip_endpoint::Core` adds framing,
  verification and signing on top, still without I/O (`inbound(frame, now)`, `local(event, now)`, `tick(now)`).
  This is a stronger base than siphon-rs has: there, only the transaction FSMs are sans-I/O and everything above
  them runs on tokio.
- **Pure rule crates.** `dsip-messaging` (the client, hub and mailbox state machines), `dsip-webrtc-binding`,
  `dsip-broadcast`, `dsip-number`, `dsip-recording`, `dsip-events` and `dsip-kt` hold the rules with no I/O, and are
  pinned by vectors.
- **Every public item documented** (`#![deny(missing_docs)]`), with `Spec:` lines.
- **Runtime splits that already work:** a `wasm` feature on dsip-core and dsip-endpoint, `node` on dsip-dht, `host`
  on dsip-gateway.

**Not library-shaped:**

1. **Each host reimplements the same protocol glue.** The CLI (`dsip-cli/src/console.rs`, 976 lines), the browser
   (`web/app.js`, 1,967 lines) and the gateway (`dsip-gateway/src/host/call.rs`) each drive `Core`/`Agent`
   themselves. Each one does its own:
   - ICE candidate buffering until the session is active, and the signed `info` that carries the candidates
     (§12.12; console.rs:253–263, app.js:500–523);
   - SDP plumbing: reading `/transports/0/sdp` out of a JSON payload, then accept-offer or set-answer;
   - media gating on `Emission::Media("start")` (§14.1);
   - relay discovery, hint publishing and re-signing, number lookups.

   Some logic lives in only one host:
   - **CLI only:** the seal fallback (resend once in clear after `session.unsupported-critical-extension`, §10.4;
     console.rs:599–615) and call-recording consent (C§4; console.rs:629–665).
   - **Browser only:** the trust UI for incoming calls.

   So the hosts already behave differently, and a new application would have to write all of this a fourth time.
   This is the main thing a stack fixes.
2. **The messaging client is written twice, and neither copy is a library:**
   - the native `dsip-msg` binary (a private `struct Client`, plus stdin commands, plus an SNMP/syslog gateway in the
     same 4,324-line file);
   - the wasm `Messenger` (2,946 lines).

   The mailbox service is likewise binary-only.
3. **The API is stringly typed:**
   - **Errors:** `anyhow::Result` is returned from `Core`, `Agent`, `MediaLeg` and `Identity`.
   - **Emissions:** `Emission::Media(&'static str)`, timer actions as `&'static str`, and
     `Ui { kind, fields: Vec<(&str, Value)> }`.
   - **Rejections:** `CoreEvent::Rejected { code: String }`.
   - **Payloads:** `Received { payload: Value }`, read with JSON pointers.
   - **Messaging:** about 100 `dsip-messaging` functions take or return `serde_json::Value`.
   - **Parameters through setters:** `set_sdp` fills a single pending slot before `local(Accept)`, and `set_info_data`,
     `set_claims` and `set_invite_patch` work the same way. `LocalEvent::Info` itself carries no data.
4. **Nothing is pluggable:**
   - **Resolver:** `Core::new` and `Agent::connect` take a concrete `StaticResolver`. `did:web` documents are
     prefetched into it, and `Resolver::resolve` is synchronous and returns an `Option`.
   - **Transport:** `Agent` is wired to tokio-tungstenite, with no transport trait.
   - **Storage:** contacts are a `contacts.json` that `Agent` reads and writes itself, and seen-ids reset on reconnect.
     The only storage abstraction is OpenMLS's provider.
5. **Key custody is a PoC shortcut.**
   - `dsip_transport::Identity` is a directory holding the controller key next to the device key.
   - `Agent` derives the identity's unseal key from the controller seed (agent.rs:108–111).
   - A real device should hold only its device key and its delegation (§7.3–7.5). That is how the browser client
     already works, which is why it cannot be sealed to at the identity.
   - The identity bundle has three shapes: the CLI directory, `IdentityKeys`, and the wasm identity JSON.
6. **Few examples and a few panics.**
   - **Examples:** module docs map spec sections rather than show usage. Apart from one dsip-dht stress example there
     are no `examples/`.
   - **Panics:** `unreachable!` in `Endpoint` (endpoint.rs:534, :665) and a schema-compile `panic!`.

## 3. Relationship to siphon-rs

siphon-rs is the user's production SIP stack (18 crates, CalVer workspace tags over per-crate SemVer, consumed as
git dependencies). It and DSIP already meet in two places:
- the gateway, which uses siphon-rs UAC/UAS (`dsip-gateway`'s `host` feature);
- `forge-sdp`, which builds on siphon-rs's SDP.

**Options:**

| | What it means | For | Against |
|---|---|---|---|
| **A. A separate stack with the same conventions** | Its own workspace. It copies siphon-rs's release model and API patterns, and depends on the few siphon-rs crates that genuinely fit. | The protocols share little code: SIP is text over UDP/TCP with transactions; DSIP is signed JSON envelopes over a WebSocket binding with sans-I/O state machines. Each keeps its own pace. | Two release trains to keep in step for the gateway. |
| **B. Extract shared crates first** | Move the generic parts of siphon-rs (rate limiting, metrics traits, TLS config, SDP) into a common workspace both depend on. | One copy of each. | A refactor of a production stack, for parts that are small and not the hard part. siphon-rs's metrics and HEP hooks are set-once process globals, which a library should not copy. |
| **C. DSIP inside the siphon-rs workspace** | dsip-* crates beside sip-*. | One repository, one release. | Couples DSIP's spec-driven churn to a production SIP stack's releases. The vectors, three-way parity and impl-ts would move with it or split from it. |

**Recommendation: A.**
- **Copy from siphon-rs:**
  - the release model (`RELEASING.md`: CalVer workspace tags, per-crate SemVer, minor = breaking before 1.0, a
    CHANGELOG listing every crate's version and its breaking changes);
  - the two-tier API (low-level builders plus a builder-configured `Integrated*` facade);
  - store traits with sync and async adapters;
  - a testkit crate;
  - the doc rules it shares with this repo (`///` on everything, citations in comments).
- **Reuse:** `sip-sdp` through `forge-sdp` for SDP, as the media path already does; `sip-identity` for the
  STIR/PASSporT work in `dsip-number` and the gateway.
- **Don't copy:** process-global hooks (`set_transport_metrics`, `set_emitter`, global rate limits). Inject them.

## 4. Layering

From the bottom up. The rule `core → schema → session` (a message reaching session has passed signature, replay and
shape checks) stays as it is.

| Layer | Crates (today's names) | Changes for the stack |
|---|---|---|
| 0. Identity and wire | dsip-core, dsip-schema | Typed errors; an async `Resolver` with errors (`did:web` fetches on demand, with caching); one `Identity` / `DeviceCredentials` type that never needs the controller key on a device; the controller key behind a `Signer` trait so it can live in a vault or hardware. |
| 1. Engines (sans-I/O) | dsip-session, dsip-messaging, dsip-webrtc-binding, dsip-broadcast, dsip-recording | Typed `Emission` and `Ui` enums. Registry-governed values stay open (CLAUDE.md: no closed enums for reason tokens, `answered_by`, `progress.status`): newtypes with known constants, never a closed enum. Parameters travel on the event (`Accept { sdp, answered_by }`), not through setters. |
| 2. Endpoint core (sans-I/O) | dsip-endpoint | The one place the host glue in §2 item 1 moves to: candidate buffering, SDP offer/answer, media gating, seal fallback, recording consent, auto-answer policy, first-contact grants. The host gives it frames, time and media events, and gets back frames to send, media commands and app events. |
| 3. Runtimes | dsip-transport (tokio), a wasm host | A `Transport` trait (ws/1.0 today, others later) with a tokio-tungstenite implementation and a browser one. Reconnect and backoff, and storage traits for contacts, seen-ids and the session store. |
| 4. Features | dsip-media, discovery (dsip-dht record side, Pkarr, dsip-number), dsip-mls, dsip-events | Each behind a feature flag. Discovery as one `Discover` interface over DID document → alias → cache → hints, keeping §8.1's order inside the crate where an app cannot reorder it. |
| 5. Facades | new: `dsip-phone`, `dsip-messenger` | What most apps hold: `Phone::builder()…build()`, `phone.call(did) -> CallHandle` (await progress, answer, end; a stream of events), an `IncomingCall` to accept, screen, decline or let ring. `Messenger` for groups, direct chats, blobs and history. |
| Services | dsip-relay, dsip-mailbox, dsip-node | Each a library with a thin binary, so an operator can embed a relay, or a relay and mailbox in one process. |
| Test | new: `dsip-testkit` | Because the engines are sans-I/O, an in-memory network (endpoints, relays, mailboxes, a clock) is easy to build: deterministic multi-party tests with no sockets. siphon-rs cannot do this above the transaction layer. Plus the vector runner as a library, so a downstream implementation can run the suite. |

The browser gets the same layers 0–2 and the facades through wasm, with a typed TypeScript API generated from the
Rust types in place of today's JSON strings. Its host shrinks to a socket, a timer, IndexedDB and `RTCPeerConnection`.

## 5. What stays out

- **The spec process.** The vector generator, the Python harness, parity, fuzzing and `impl-ts` stay where they are.
  The stack is measured by them, as the PoC is.
- **Draft profiles by default.** The RTP/SRTP binding, alias transparency, device events, recording, number
  attestation and the hints profile are drafts. They are off-by-default features until each reaches 1.0.
- **Anything the PoC leaves out of scope:** gateway work past Gateway Profile 1.0, DHT authority, Sybil
  defences (CLAUDE.md).

## 6. Build order

Everything before stage 4 can happen in this workspace, where three-way parity keeps applying. Stages 1–3 make the
PoC better on their own terms: each removes duplicated glue from the reference client and the CLI.

1. **Typed core APIs.**
   - typed errors in place of `anyhow` in library crates;
   - typed `Emission`, `Ui` and `CoreEvent`;
   - parameters on events instead of setters;
   - an async resolver trait;
   - no panics on input paths.

   The vectors and parity show nothing regressed.
2. **The host glue moves into `dsip-endpoint`.** It takes console.rs's candidate, SDP, gating, seal, consent and
   policy logic; the CLI becomes a thin host. The browser moves onto it next, which gives it the seal fallback and
   recording consent it lacks today. Then the gateway.

   *Status (2026-10-18):* done. 2a `dsip_endpoint::calls` with the CLI on it (#200); 2b the browser (#201); 2c the
   gateway, whose controller decides when the DSIP leg rings and answers (`AnswerPolicy::Host`), with a declared
   recording accepted by policy pending spec-gap 133.
3. **One messaging client.** A library client extracted from `dsip-msg` and the wasm `Messenger`, over storage
   traits (SQLite natively, IndexedDB in the browser). `dsip-msg` keeps the device-events gateway as its own
   module.
   *Plan (2026-10-18).* The library is a new crate, `dsip-messaging-device` (OpenMLS 0.9, so Rust 1.91 like dsip-mls;
   a `sqlite` feature for the native store, never on wasm32). It takes the wasm `Messenger`'s shape: sans-I/O, every
   deposit pending until its answer, the host doing the I/O. dsip-msg today waits inline for each answer, so it becomes
   a host of that shape. Stages, each with no behaviour change and every vector, parity run, CI demo and web test
   green: 3a the item processing (`process`, `Outcome`); 3a′ dsip-msg's device-events gateway split into its own module;
   3b pure helpers (key-package selection, archive records, blobs, call records, recording state); 3c a `Store` trait
   (SQLite natively, memory with rollback in the browser) with both on-disk formats unchanged; 3d the inbound pipeline;
   3e the outbound side (deposits, outbox, outages, re-deposits; the riskiest); 3f commits and their retries; 3g
   history and receipts; 3h successor groups; 3i what only one client has, behind `Config`; 3j thin hosts. A
   browser↔dsip-msg demo comes before 3d: nothing tests the two clients against each other today.

   *Status (2026-10-19):* 3a the shared `process` (#204); 3a′ dsip-msg's `events` module, which holds the gateway and
   the alarm lists (E§3–E§6), so what remains in `dsip-msg.rs` is the messaging client and its host (#205); 3b the pure
   helpers both clients now call: `key_packages`, `recording`, `blob`, `archive`, `calls`.
   3c the `Store` trait: an OpenMLS provider that also keeps the device's state values and runs a closure
   atomically. dsip-msg's `SqliteProvider` is one (feature `sqlite`), and the browser's provider is now `MemoryStore`,
   which keeps its save format and can roll back both maps. Neither client calls the trait yet (3d does), so the
   browser still neither rolls back nor acknowledges an unprocessable item.
   3d, first part: inbound routing (`inbound::route`). Both clients decide in it where an item goes before MLS (ephemeral,
   duplicate, first contact, archive, GroupInfo, own deposit, pre-join history, held behind a gap, or processed with
   what the gap releases) and record the decisions that need no processing. What each client does with an MLS
   outcome stays in the host until the state it writes (outbox, receipts, history, successors) is shared in 3e–3h.
   3e is split in three, since the clients differ most here: the browser tracks every deposit by id until its
   answer arrives, while dsip-msg awaits each answer inline. 3e-1 is the shared `Outbox`: the items pending per group
   and their `HubOutage`, advanced on every tick. That fixes dsip-msg, whose outage clock stood still while the hub
   was up: an outage starting after more than `hub_timeout` from the group's first deposit triggered the successor at
   once, with no retries. 3e-2 is the deposit registry, `Deposits<P>`: what each deposit awaiting an answer was (`P`
   stays the host's), the hub it was addressed to, the no-answer watch, and the deposits deferred until the group's
   new hub hosts it; the browser's four maps become one. 3e-3 puts dsip-msg on the same registry. A command still
   waits for its own deposit's answer, since what it prints and writes follows from that answer, but the answer now
   reaches it through `inbound` and the registry; an answer read during a nested wait is kept for the command waiting
   for it, where it used to be dropped. The outbox's re-deposits no longer wait at all: each answer is acted on when it
   arrives, a deposit unanswered after 20 s counts as the hub unreachable, and a moved group's new hub that does not
   host it yet gets the same bytes again from the tick, as in the browser. `hub-return-demo.sh` covers the flush when
   the hub comes back, which no demo did. Commits keep waiting inline until 3f.
   3f: commits. The retry decisions were already shared (the vector-pinned `CommitRetry`); what each client repeated
   around them is now `commits`: `build` for a change (Add, Remove, Update, MoveHub, the pending proposals of a leave),
   the deposit fields with the welcome and grants, the leaves of an identity (authenticated) or of a device (by
   credential), and `Retry`, which reads `CommitRetry`'s actions as types. How a client drives the retries stays its
   own: dsip-msg's command waits through the sync and re-proposal, the browser re-proposes from `after_sync`; they
   become one with the thin hosts (3j).
   3g: history and receipts. The two vector-pinned machines are wrapped once, their decisions read as types:
   `Receipts` (delivered, read, played, activity, and the receipts to archive) and `History` (show, duplicate,
   apply, hold, pre-join, archive), with `archive_records` for what an archive decision asks for and `Restored` for
   archived history waiting for its conversation. Two fixes came with it. Every receipts event now advances the
   machine's clock first and returns what the advance decided: the browser advanced and discarded, so a read
   watermark held back by the 5 s interval was lost when a sync came before the next tick. And what of a device's own
   accepted objects is history is now one rule (content; a read watermark; a call event): dsip-msg treated every
   object re-sent from the outbox after an outage as content, so a receipt sent after an outage became a timeline
   entry, was archived as one and was booked in its own receipt state.
   3h: successor groups. `Successors` reads the vector-pinned `SuccessorTracker`'s decisions as types (`Create`: use,
   create re-adding these peers, refuse; `Converge`: join, leave, decline, first contact) and is persisted as the
   tracker itself, so both saved formats are unchanged. It also answers where a conversation lives now and which
   groups make up its thread, and `creator` gives the identity a successor's welcome is checked against (leaf 0).
   How each client hands the dead group's pending items over stays its own (below).
   3i is in parts, as 3e was. 3i-1 is `Config` with a preset per client (`Config::DSIP_MSG`, `Config::BROWSER`),
   holding the options whose code is now shared: the no-answer timeout, the object key, whether a commit other than
   an Add deposits its welcome, the still-needed test for an Add of a named device, the roster recorded for the
   successor checks, and whether a received archive key replaces one held. Each client reads its own preset, so
   nothing changes. The other options are in code each client still has to itself; they go behind `Config` as that
   code is shared, the last with the thin hosts (3j).
   3i-2: the gap timeout. Advancing the gap trackers and clearing a group whose gap did not fill in time (its held
   items dropped, its seq positions passing everything seen) is now `Inbound::gap_timeouts`, and `Config::rejoin_gaps`
   says whether the device then re-joins by external commit. M§6.5 says it does, so the browser's `false` is a
   shortfall to close rather than a choice: its gap trackers now keep wall time like dsip-msg's, so turning the option
   on, with a web test of it, is what is left.
   3i-3: an item that cannot be processed. Processing an item and committing it with the delivery state is now
   `Inbound::commit_processed`. With `Config::roll_back_unprocessable`, a failure rolls back both (spec-gap 44) and the
   item is then committed as handled, so it is acknowledged rather than redelivered after every sync (spec-gap 138,
   drafted). dsip-msg had this; the browser keeps its `false` (no rollback; the item uncommitted) until the option is
   turned on there with a web test, as with the gap timeout. One fix came with it: when the item that filled a seq gap
   could not be processed, the held items it released were dropped, since routing had already taken them out of the
   held items. With the rollback they are now processed as after any other item; the browser still drops them while
   its option is off.
   3i-4: received receipts. A sync's content and receipts are collected in `receipts::Batch`, per group, and each
   conversation's machine is stepped once with its share when the sync's items are done (M§10.2);
   `receipts::receipt_target` sends a receipt received in the personal group, a sibling's undisclosed read watermark,
   to the conversation it names (spec-gap 52). With `Config::batch_receipts` a receipt joins the batch (dsip-msg); the
   browser keeps its `false`, stepping each receipt at once in the group it arrived in, so a sibling's watermark
   reaches the personal group's machine instead of its conversation's: another shortfall to turn on with a web test.
   The browser's content batch, which lived in each conversation, is now the same `Batch`.
   3i-5: `ProcessOptions`, the item-processing options (what the object check sees, recorder content, call records
   kept, proposals stored), is `Config::process`: each client's preset carries what it passed, and the browser's own
   constant goes. What remains differs in code each client still has to itself (commits and their retries after a
   conflict, re-deposits on reconnect, successor creation and the handover of pending items, call events, the blob
   `tried` input, sealed introductions); it goes behind `Config` with the thin hosts (3j).
   3j is in parts too. 3j-1: what a received call event is (#224: history state wherever it came from, archived once
   by session; the call log is `CallLog`), introductions and grants received (`first_contact::received`: verified as
   credentials, the introduction checked under M§14.1, its sealed purpose opened when the device holds the identity
   key, kept unread when it does not), and what each blob source answered (`blob::tried`, `blob::retry_delay_s`). One
   fix came with it: the browser read a plain purpose without checking the introduction, so one carrying both
   `purpose` and `sealed` became a request.
   3j-2: the browser's `Messenger`, already sans-I/O, is `dsip_messaging_device::messenger::Messenger`, its refusals a
   plain `Error`; `dsip-wasm` keeps the same JavaScript API as a wrapper that forwards every method. Nothing changes
   for the browser. dsip-msg moves onto it next, its differences behind `Config`.
   3j-3, dsip-msg onto the `Messenger`, is in four parts, since the `Messenger` has to do everything dsip-msg does
   before dsip-msg can hand it its groups. 3j-3a: the `Messenger` is opened over any `Store` with a `Config` and a gap
   timeout, and its delivery state is a value (`state`) a native host keeps with its MLS state in one transaction; the
   browser's `new` and `save` are that over `MemoryStore`, their record unchanged. A fix came with it: the browser
   added a recorder sibling to the personal group, where it would hold every archive key (C§5); it now joins the
   conversations only. 3j-3b: what only dsip-msg does (rekey, removing a device or a lapsed leaf by credential and
   rotating the archive key, a move to any hub, any content object sent with its item id, issuing grants and answering
   requests, introductions, release, activity). 3j-3c: events carrying what dsip-msg prints (item ids, a call's
   direction, a removed group's kind, re-proposals, recording changes). 3j-3d: dsip-msg hosts the `Messenger`; its
   saved state is migrated on first load (decided 2026-10-20) and its output lines stay as the demos read them.
   3j-3b is in two halves. The first: rekey, removal by credential (a lapsed leaf; a device of this identity from
   every group, its new archive key sent once the personal group's commit is merged), and a move to any hub. The
   second: `send` for any object, naming the outbox item the hub's `sent` answers; activity sealed and opened
   (M§11) under a receipt policy the host sets (`set_receipt_policy`; the browser's `set_read_disclosed` is that
   policy's read and played); grants, introductions (sealed to a `did:key`'s converted key too, which dsip-msg could
   not do), answering requests, and release, with the peer mailbox's connection left to the host as for KeyPackage
   fetches. The browser now opens activity a peer sends; it sends none, its policy's activity being off.
   3j-3c: the events say what dsip-msg prints. A commit, a conflict (with the epoch it lost at), a re-proposal (a new
   event) and a commit no longer needed name the operation; `sent` says whether the item went out after an outage,
   and the outage's retry names the item waiting; a successor's due hand-over lists the pending items, and the
   hand-over the new item each went out as; `removed` has the group's kind; a call event its direction;
   `call_ended_item` returns the event sent with its item and whether the identity had it already; a request whether
   it was sealed and whether its purpose was on the wire; a message its whole object and sending device; and a
   conversation newly recorded, or no longer recorded, is an event (`recording`), as dsip-msg rendered it. One
   difference is settled: content from a recorder leaf is dropped by both (C§5's **content**); dsip-msg also dropped a
   recorder's other objects, which now are processed as any member's. Left for 3j-3d, where dsip-msg takes the
   `Messenger`'s behaviour unless a demo shows a reason not to: the outbox following deposits from the first or from
   the first failure; recording acceptance kept by conversation (dsip-msg kept it by group, migrated); declining a
   recording; a re-join replacing the group; a second direct conversation with one peer; history and status across
   conversations; the own-deposit digests never pruned; the default gap timeout (60 s or 300 s).
   3j-3d: dsip-msg hosts the `Messenger`. It moves the `Messenger`'s frames over its `wss` connection, keeps the
   clock, fetches KeyPackages, blobs and first-contact answers on connections of their own, and prints the events as
   the lines the demos read; every demo that drives it passes unchanged. Whatever set deposits going — a command, a
   frame, the clock — is settled (`Messenger::settled`: every deposit answered, no refused commit waiting for its sync)
   before the next command is read, so commands still run one at a time; a binding sends what the last one left unanswered (`Messenger::rebind`) and syncs only when told,
   as dsip-msg always did. The `Messenger`'s state is written beside its MLS state after every step, and each item
   commits with its delivery state in one transaction (spec-gap 44; `crash-next` still exits inside it). State from
   the dsip-msg before is migrated on first load (decided 2026-10-20), its old keys cleared. The open differences went
   the `Messenger`'s way, no demo showing a reason not to: the outbox follows deposits from the first failure;
   recording acceptance is kept by conversation; declining a recording is leaving (M§7.3), not forgetting the group; a
   re-join is refused while the device is in the group; a second direct conversation with one peer is refused; history
   and status are per conversation; the own-deposit digests are kept. dsip-msg keeps its 300 s gap timeout as its flag's
   default. Found on the way: a device's own copy fanned back without its `accepted` (the binding lost before the
   answer) did not count for the gap tracker, so the next handshake was held behind a gap that was not one; it now
   counts (spec-gap 69) for both clients, and may release what a gap held.
   3j-4: what only the old dsip-msg used goes: the outbox's `track` flag (an outage machine is made when the hub
   first proves unreachable, as 3j-3d decided), `Outbox::outage_mut`, `CallLog::to_map` (`from_map` stays, for the
   migration) and `History::is_prejoin`; `inbound::gap_tracker` is private to the routing. With that, 3j is done and so
   is stage 3: one messaging client, `dsip-messaging-device`, hosted by the browser and by dsip-msg, each host moving
   frames, keeping the clock and doing the network fetches. What still differs is the `Config` options listed next,
   each to go once decided; the browser's shortfalls (`rejoin_gaps`, `roll_back_unprocessable`, `batch_receipts`)
   first, each with a web test.
   The browser's shortfalls closed: all three options go, both clients doing what M§6.5, spec-gaps 44 and 138, and
   M§10.2 with spec-gap 52 ask. A seq gap that does not fill re-joins by external commit, and the `Messenger`'s gap
   timeout defaults to M§6.5's RECOMMENDED 300 s (the browser's was 60; a setting now, as the hub timeout is). An item
   that cannot be processed is rolled back with its delivery state (the browser's `MemoryStore` restores both maps)
   and committed as handled, so it is acknowledged. A received receipt joins the sync's batch, a sibling's private
   watermark booked to the conversation it names. The web tests: `messaging-gaps` (a push lost on its way, so the
   rekey after it is held and the device re-joins when the gap stays open; a message from an epoch the receiver has
   moved two past, unprocessable, then not redelivered after a reload) and a step of `messaging-devices` (a sibling's
   private read applied to the conversation, with the archived copy of it kept back so only the receipt can carry it);
   each fails on the code before. The test library holds or drops what a page's sockets receive, from an init script.

   The last options go, and `Config` with them (2026-10-21): the `Messenger` behaves one way for both hosts, which set
   only its timeouts. Decided by the spec: the dedup key carries the sender (M§8.5; the browser's saved messages are
   keyed again on load); the object check is given the sender's device, so a `call-record` passes it (C§9) and is kept
   when this device is a record-keeper; a leaver's proposals are stored and committed (M§7.3, spec-gap 125; dsip-msg
   gains `leave`, and `group-demo.sh` has Alice's dsip-msg commit Carol's); and a welcome a commit produces is always
   deposited (M§7.2). Left to the host: the no-answer timeout (spec-gap 72 sets none; `set_no_answer_timeout`, 60 s
   unless set, dsip-msg `--no-answer-timeout` 20). Decided by the user: an Add of a named device is not needed while any
   leaf carries its credential (a second leaf would repeat its signature key, which MLS refuses); the roster recorded
   for the successor checks, and re-added by a successor's creator, is every leaf's delegation subject, lapsed leaves
   included (spec-gap 139); and the first archive key under an `akid` is kept, a different one reported (spec-gap 140).
   Found on the way: dsip-msg's `decline-recording` sent nothing, reading the leave's `[{send}]` as frames.

   Where the two clients behaved differently, stage 3 kept each behaviour behind an option until it was decided: the
   dedup key (with or without the sender); 20 s or 60 s before a deposit with no answer is an outage; a group's roster
   recorded for the successor checks only when every leaf authenticates (dsip-msg) or from the leaves that do
   (browser); proposals stored (browser); a welcome produced by a Remove deposited (dsip-msg) or dropped (browser); an
   Add of a named device still needed while no leaf has its credential (dsip-msg) or no authenticated leaf is that
   device (browser); archive keys overwritten or kept. Decided earlier: when a call event is recorded (3j-1); the blob `tried` input (shared, 3j-1); a sealed
   introduction opened without the identity key (shared, 3j-1: a device without the key keeps it unread); recorder
   content and acceptance keys (3j-3c); and with dsip-msg on the `Messenger` (3j-3d), the `Messenger`'s way for frames
   verified after the hello, receipt policy and activity, re-proposing once the sync is answered rather than waiting
   for the epoch to move, re-deposits of commits, GroupInfo and config on a new binding, `mailbox-config joined` after
   an external join, a successor made with one commit for all its members, and the dead group's pending items
   re-encrypted as new objects once the successor holds them; and dsip-msg's way for an unprocessable item, a seq gap
   that does not fill, and receipts received (the browser's shortfalls, closed after 3j).

   **The typed browser boundary** (decision 4; started 2026-10-26 at poc-v0.17, before stage 4 because it does not
   wait for core 1.0). *Today:* `dsip-wasm` passes JSON strings both ways in its hundred or so exported functions and
   methods, the page parses and stringifies them (77 `JSON.parse` in `app.js` alone), and the generated `.d.ts` says
   `string` everywhere. The library `Messenger` speaks strings too, so `dsip-msg` parses them as well. *Target:* values
   cross as JavaScript objects, typed by declarations generated from the Rust types.
   - **tsify 0.5**, with `Ts<T>` on parameters and returns (its `into_wasm_abi` is deprecated: a failed conversion
     throws past the wasm frames and leaks), maps as plain objects. The serde derives sit on the library types; the
     tsify derive is behind a `ts` feature, so native builds do not carry it. JSON payloads are `unknown`.
     Registry-governed values are `string` in TypeScript, never a union (CLAUDE.md).
   - **Saved records stay strings**: the identity file, the contact file and the `Messenger`'s save are storage
     formats, unchanged.
   - **The page stays plain JavaScript with no build step**: `// @ts-check` and JSDoc types imported from
     `pkg/dsip_wasm.d.ts`, and `tsc --noEmit` in CI (TypeScript a web devDependency). A checked file cannot drift
     from the Rust types unseen.
   - **The engine's `Emission`** is the vectors' shape (README, kind `state`): flattened and irregular (`{"ui": …,
     "reason"}`, `{"timer": …, "name", "seconds"}`, `{"send": {…}}`), which serde cannot derive without reshaping
     `dsip-session`. Its TypeScript type is written by hand, and `tsc` checks it against every emission in the
     state vectors: the contract types it, not the implementation. B2 does the same for the session and contacts
     snapshots (kind `state`) and a frame's verdict (kinds `envelope`, `payload`, `semantic`); the check found the
     first hand-written `SessionSnapshot` wrong (`outstanding_update` is `{id, direction}`, not an id).

   Parts, each with no behaviour change, no vector change, and every web test and CI job green:
   - **B1** (done, #256)**:** the tooling and the call path: `CallOut`, `CoreEvent`, `MediaRequest`, `MediaResult`, `CallEvent`,
     `CallCommand`, `Invite` and `Emission` typed; `Endpoint`'s `place`, `call`, `media`, `local`, `inbound`, `tick`
     and `resolved`; `host/engine.js` under check.
   - **B2:** the rest of `Endpoint` (presence, contacts, requests, sessions, recording) and the free functions
     (identity, hints, numbers, verification, the renderers). `dsip-number`'s `ClaimOutcome`, `Selected` and
     `Contact` carry the derives (behind its `ts` feature); the values the libraries build as JSON cross as JSON
     with a declared type (`Json` is `unknown`; `Sessions`, `Contacts`, `Verdict`, `Consent`, `Mailbox`,
     `Voicemail` are declared by hand). A result that may be absent is `T | undefined` (it was the string `null`).
   - **B3:** the `Messenger` typed in the library: its inputs and outputs are Rust types, which `dsip-msg` reads
     instead of JSON, and `dsip-wasm` exports them. In three parts, as it is a 3,000-line JSON-native machine:
     - **B3a:** the step outputs: `Event` (`{send}`, `{ui}`, `{sync}`, `{refused}`, `{error}`, …) with `Ui`, one
       variant per kind the hosts render (64), built where they were built as `json!`. The step methods return
       `Vec<Event>` and the frames-only ones `Vec<String>`; they serialize as before, so the hosts change only at
       their edge (dsip-msg converts once in `handle`, `dsip-wasm` returns the same JSON text).
     - **B3b:** the structured results and inputs (`call_ended_item`, `call_record`, `accept_recording`,
       `conversations`, `thread`, blobs, `introduce`, the `*_json` parameters), and the tsify derives behind a `ts`
       feature.
       *Done:* `types.rs` holds what a call builds for its answer (`Hub`, `Outage`, `ArchiveKey`, `Available`,
       `CallEnded`, `CallRecorded`, `RecordingAccepted`, `Sent`, `Conversation`, `SealedBlob`, `FetchDecision`,
       `KeyPackageDevice`, `Introduction`, `Granted`) and the host's inputs that are not wire payloads (`CallLeg`,
       `BlobRef`, `ReceiptPolicy`; `blob::Tried` both ways); `relay_hello` is the endpoint's `RelayHello` or the
       reject code. What the `Messenger` keeps as it was received or saved (the thread's messages, the call log,
       records, the roster log, requests, a receipts snapshot) and wire payloads (a `key-packages` answer, a content
       object, a manifest, a call record's leg) stay JSON values (`unknown`), as B2 left the libraries' JSON. `dsip-msg`
       reads the types; `dsip-wasm` still speaks JSON text, parsing each parameter at its edge as leniently as the
       library did and serializing each result. The declarations (`Event`, `Ui` and the above, `ts` on in
       `dsip-wasm`) are in `pkg/dsip_wasm.d.ts` and pass `tsc`.
     - **B3c:** `dsip-wasm` returns objects and the page reads them; dsip-msg matches on the types.
       *Done:* the `Messenger`'s methods take and return objects (`Ts<T>`; a list of library values is `T[]`, frames
       `string[]`, the JSON it keeps `unknown[]`), with four wrappers in `dsip-wasm` (`Events`, `Outages`, `Grants`,
       `ByIdentity`); its save and the identity it is made from stay JSON text, and what it throws stays the string it
       was. The library types carry tsify's `missing_as_null` and `hashmap_as_object`, as B2's do: an absent value
       is `null`, as in the JSON text the page read, so its checks did not change, and a map is a plain object. The
       page drops 41 `JSON.parse` and the `JSON.stringify` of every argument; `host/relay.js` reads one `relay_hello`
       shape from the `Endpoint` and the `Messenger`. dsip-msg matches on `Event`, `Ui` (every one of the 64 kinds,
       no fallback) and `OpInfo`, and reads `Conversation`s, printing the lines it printed.
   - **B4:** `app.js` under check, with the last parsing and stringifying of boundary values gone.
    *Done:* every file of the page is under `// @ts-check`: `host/` strict (`tsconfig.json`), `app.js` by
    `tsconfig.app.json`, strict but for implicit `any` and null checks, which over 2,500 lines of DOM code are
    noise (1,318 errors, none about the boundary) rather than drift; `npm run types` runs both and CI runs it. The
    boundary's globals are typed (`Engine`, `Relay`, `Messenger`, the verified hellos), and `$` is `any` on
    purpose: the check is for the values crossing the wasm boundary, not the DOM's element kinds. The JSON the
    `Messenger` keeps (`unknown`) is read through shapes declared beside their readers (`CallRecord`,
    `HeldRecord`, `TimelineEntry`, `RosterEntry`, `IntroductionRequest`). What is left of `JSON.parse` and
    `JSON.stringify` is storage (the identity, the contact file, the `Messenger`'s save), the DID document text a
    `did:web` identity hosts, frames decoded for log lines, and settings. The check found: hint verdicts never
    carry `detail` (the page logged nothing where `reason` was), an `ignored` number claim rendered `undefined`, and
    four `unknown` fields with fixed shapes, now Rust types (`Conversation`'s `recorded`, `may_send`, `recorders`,
    `recorders_pending` as `Recorder`; `Available`'s `conversation`, `kind`, `hub`).

4. **Facades, testkit, examples.** `dsip-phone`, `dsip-messenger`, `dsip-testkit`; runnable examples (a
   20-line softphone, a chat bot, an embedded relay); a usage guide.

   *Plan (2026-10-27, at poc-v1.0).* The products that follow (desktop and mobile clients, relay, DHT and mailbox
   nodes) are built on what this stage leaves, so the services become libraries as well as the facades. In parts,
   each with no behaviour change and every vector, parity run, fuzz seed, CI demo and web test green:
   - **4a, the relay as a library.** `dsip_relay::RelayServer` (a `RelayConfig`, its clock, the status port, a TLS
     listener, and one connection over any byte stream); the `dsip-relay` binary parses flags and hosts it. A client
     `Connection` runs over a TLS socket or any stream (`Connection::over`), so a relay and its devices can share a
     process. Example: `embedded_relay`.
   - **4b, the testkit.** `dsip-testkit`: an in-process network (a relay, devices with `did:key` identities bound
     over pipes) for multi-party tests without sockets or ports; the `Agent` dials through a `Dialer`, so the
     same agent runs on the testkit and on `wss`.
   - **4c, `dsip-phone`.** `Phone::builder()…build()`, `phone.call(did) -> Call` (await its outcome, hang up, its
     events), incoming calls to accept, screen, decline or let ring, native media through `dsip-media` or none.
     Tested on the testkit. Example: a softphone of about 20 lines.
   - **4d, the mailbox and `dsip-messenger`.** The mailbox service as a library with a thin binary; `dsip-messenger`,
     the native host loop of the `Messenger` that dsip-msg runs today (hub connections, the SQLite store), with
     dsip-msg on it. The testkit gains a mailbox. Example: a chat bot.
   - **4e, the guide.** A usage guide for building on the stack, and the examples built in CI.

   *Status (2026-10-27):* 4a done: `RelayServer` with the binary on it, `Connection::over`, a call through a relay
   embedded in a test over in-memory pipes (`dsip-relay/tests/in_process.rs`), and `examples/embedded_relay.rs`.
   4b done: `dsip_transport::conn::Dialer` (`AgentConfig::dialer`, used for the first connection and every
   reconnect) and `dsip-testkit`: `Network` (an embedded relay, `did:key` identities, second devices), `Device`
   (an `Agent` with `expect`, `until`, `call`, `command`), checked by a call, a forked call, an unknown recipient and a
   replaced connection, all in-process.
   4c done: `dsip-phone`. `Phone::builder()` (identity, relay or dialer, TLS, answer and recording policy, media,
   `configure` for the agent) → `Phone::call` / `Phone::incoming` → `Call` (state, `outcome`, `ended`, `hang_up`,
   `error`, `media_received`) and `IncomingCall` (accept, screen, decline). A task owns the agent and one native leg
   per call; `Agent::waker` lets it take commands without cancelling `Agent::next`. An `error` changes no call state
   (§12.7 rule 6): a call refused `transport.unknown-recipient` ends by T-Establish, as in both clients, and the
   `Call` keeps the refusal. Eight tests on the testkit, native audio both ways included; `examples/softphone.rs`.
   4d, first part: the mailbox as a library. `dsip_mailbox::MailboxServer` (`open` from a `MailboxConfig`, which
   loads the saved state; `spawn_tasks` for fan-out retries, idle release and blob replication; `spawn_status`;
   `serve_tls`; `accept` over any stream, a WebSocket or a blob request), with a typed `dsip_mailbox::service::Error`;
   the `dsip-mailbox` binary parses flags and hosts it. A device binds to an embedded mailbox over a pipe
   (`tests/in_process.rs`).
   4d, second part: `dsip-messenger`. `Messenger<S: Store>` holds the engine (the `Messenger` of
   `dsip-messaging-device`) and does what dsip-msg did around it: the mailbox connection and its §13.2 reconnects,
   requests that wait for their answers, KeyPackages fetched from other identities' mailboxes, blobs fetched and retried
   (spec-gap 106), successors created when a hub is gone (M§7.5, M§9.4), and the state written after every step. The
   application implements `Host`: each `Output` reaches it in order, with the engine to read, so dsip-msg prints the
   lines it printed. dsip-msg is now its commands and its console (`Console: Host`), the device-events gateway included;
   all 25 of its demos pass unchanged. `examples/echo_bot.rs`.
   4e done: [the usage guide](dsip-rs-guide.md) (which crate for what, identities, `dsip-phone`, `dsip-messenger`,
   embedded relay and mailbox, the testkit, what is not there yet). Every example is built by CI's clippy
   `--all-targets`, and the chat bot runs end to end in CI (`demos/echo-bot-demo.sh`: it grants dsip-msg first
   contact, joins the conversation and answers each text). `dsip_messenger::did_document` and `engine_identity`
   came out of dsip-msg for it. The testkit's mailbox is left for when a test needs one.

5. **Its own repository and release.** Move the stack crates (or the whole of `impl/`) out when core reaches 1.0,
   tag the first CalVer release, and switch the gateway to git dependencies on it. The vectors move with the spec,
   not the stack.

   *Plan (2026-10-29, decisions 6–9 below).* `feryx-io/dsip-rs` takes every crate, the workspace, `demos/` and
   `web/`, with their history. DSIP keeps the spec, the schemas, the vectors, `tools/` (the Python harness, parity,
   fuzzing, spec_lint, the WAN testbed) and `impl-ts`. In parts:
   - **5a, the spec found from either layout (DSIP).** The schema build scripts find the DSIP root (`DSIP_SPEC`, or
     the repository the workspace sits in, or a `spec/` submodule) and pass it to `include_str!`. The vector suite
     is found the same way (`DSIP_VECTORS`, `impl/vectors`, or `spec/impl/vectors`), by dsip-cli and the web type
     check. The same code builds in both repositories.
   - **5b, the repository (private).** `git filter-repo` of DSIP keeps `impl/crates`, `impl/demos`, `impl/web`, the
     workspace files and the stack's documents (this note, the guide, the client plan), moved to the root. `spec/`
     is DSIP as a submodule at `poc-v1.0`. README, CLAUDE.md, RELEASING.md (siphon-rs's model) and CHANGELOG come
     from the 2026-10-16 seed. Its CI runs what DSIP's runs on the code: build, clippy, tests, docs, the Rust
     vector runner, the demos, the wasm build and the web tests. From 5b to 5d, DSIP's copy of the code is frozen:
     changes go to dsip-rs, and DSIP's CI keeps checking parity with the frozen copy.
   - **5c, the first release.** `v2026.10.29`, every crate at `0.1.0` (listed in the tag and the changelog). The
     repository went public before it, on 2026-10-29 (decision 8).
   - **5d, DSIP without the code.** DSIP drops `impl/crates`, `impl/demos`, `impl/web` and the workspace. Its CI
     checks out dsip-rs at a pinned commit for the Rust side of parity and fuzzing, and for spec_lint's coverage
     table. CLAUDE.md, the overview and the deploy recipe follow.

   The gateway's siphon-rs and forge-media dependencies are already git dependencies pinned to a rev; nothing
   outside this workspace depends on the DSIP crates yet.

**When to start:** stages 1 and 2 are worth doing once the next spec version shows no core churn. The endpoint
state machine and envelope rules have not changed after v0.12. v0.13–v0.16 changed the profiles, added one core
message (`alias-monitor`, v0.14) and changed relay behaviour (§12.7, §13.3 in v0.16; Appendix A.10–A.13). Stage 4 waited for the core spec's 1.0, final 2026-10-27 at tag `poc-v1.0` as `v1.0/` (the v0.17 text declared normative, with §11.4's rule for 1.x); it is unblocked.

## 7. Risks

- **Parity during refactors.** Stages 1–3 move code that vectors pin. Each stage lands with the full suite,
  three-way parity and the fuzz seeds green, and no vector changes, since the stack must not change behaviour.
- **API churn ahead of spec churn.** A facade designed before the spec settles gets redesigned. That is why stage 4
  waits.
- **wasm size.** dsip-wasm already carries OpenMLS. Feature flags must keep a calls-only browser build small.
- **MSRV.** dsip-mls needs Rust 1.91 for OpenMLS while the rest is 1.85; the messaging feature sets the stack's MSRV
  unless it is split out.

## 8. What a developer would write (target, not today)

```rust
let phone = dsip_phone::Phone::builder()
    .credentials(DeviceCredentials::load(&store)?)   // device key + delegation; no controller key
    .relay("wss://relay.example:8443/dsip")
    .discovery(Discovery::default())                 // DID document → alias → cache → hints (§8.1)
    .media(WebRtc::audio())
    .build().await?;

let call = phone.call("did:web:bob.example").await?;
match call.outcome().await? {
    Outcome::Answered { answered_by, .. } => { /* media is flowing */ call.hang_up().await?; }
    Outcome::Ended(reason) => println!("not reached: {reason}"),   // e.g. transport.no-response
}
```

Today the equivalent is the select loop in `console.rs`, around 500 lines.

## 9. Decisions (the owner, 2026-10-18)

1. **Relationship to siphon-rs: A.** A separate stack with siphon-rs's conventions ([§3](#3-relationship-to-siphon-rs)).
2. **Where it grows: this workspace until core 1.0**, so the vectors, three-way parity and fuzzing check every stage;
   it moves out at stage 5.
3. **The first consumer: the browser client.** The facades are shaped around it, and stage 2 moves it onto
   `dsip-endpoint` right after the CLI.
4. **The browser API: TypeScript types generated from the Rust types** over wasm, in place of the JSON-string
   boundary.
5. **Name: `dsip-rs`**, the repository and umbrella name; the crates keep their `dsip-*` names. The licence stays
   `MIT OR Apache-2.0`, as the workspace and siphon-rs already are.

Decisions for stage 5 (the owner, 2026-10-29):

6. **What moves: all the crates and the demos**, and the workspace with them. The spec, vectors, tools and `impl-ts`
   stay in DSIP.
7. **Spec inputs: DSIP as a git submodule (`spec/`)**, pinned to a tag and moved forward on purpose.
8. **Private first**, public at the first CalVer release. *Changed 2026-10-29:* public at once, before the release:
   GitHub Actions minutes for a private repository were not available, and CI had to run.
9. **The browser client moves with dsip-rs**: it is built from dsip-wasm and its tests check the crates.
