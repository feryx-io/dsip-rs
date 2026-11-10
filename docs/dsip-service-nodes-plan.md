# Service nodes: the relay, the mailbox and the hints node as products

*Plan, 2026-10-29. The first of the products after the stack's stage 5. The user chose it first: the clients need
servers to point at, and most of the work exists already.*

## 1. Goal

An operator can run DSIP's three services from a package: a **relay** (§13), a **mailbox and hub** (M§4) and a
**hints node** (DHT Hints Profile §10). Each has a config file, a sandboxed systemd unit, a container image, real TLS
certificates, upgrades that keep its state, and status and metrics. They can also run together on one host behind one
name, the way the WAN testbed's L1 and L2 do today. The browser client is served by that host's relay.

Not in scope: hosted service, billing, a web admin console, the desktop or mobile clients, and TURN, which stays
coturn (§5).

## 2. Where each service stands

| | dsip-node (hints) | dsip-relay | dsip-mailbox |
|---|---|---|---|
| Library | `dsip_node` | `RelayServer` (4a) | `MailboxServer` (4d-1) |
| Configuration | TOML file; every key also a flag; unknown keys an error | flags only | flags only |
| Packages | static musl binaries, `.deb`, container image, `SHA256SUMS`, release workflow (`dsip-node-v*` tags; S8: the workspace release) | none: built from source by the WAN testbed's `node-setup.sh` | the same as the relay |
| systemd unit | shipped; `DynamicUser`, sandboxed (`systemd-analyze security`: 1.1) | written by `node-setup.sh`, runs as root | the same as the relay |
| State on restart | kept: identity, peers, records (`redb`), Mainline routing | relay key and certificate kept; **the store-and-forward queue is lost** (memory only) | kept, but the **whole service state is one JSON file, rewritten after every change** (spec-gap 59) |
| `did:web` identities | n/a | **document files only** (`--did-document`) | **document files only** (`--resolver-file`) |
| Certificates | behind a TLS proxy | `--cert`/`--key`; a renewal **restarts** the relay | the same; renewal restarts it |
| Status | `/dsip/v1/node`, `/metrics` | `--status-listen`: `/status`, `/metrics` | the same as the relay |
| Admin | none needed | none | **none:** stale enrolments filled the WAN mailboxes (32 of 32), cleared by hand with a temporary `--mls-retention` |

dsip-node is the model. The relay and the mailbox need the same packaging, plus four things the WAN found or the table
shows: a queue that survives a restart, a mailbox store that does not rewrite everything per change, `did:web`
resolution over HTTPS, and an admin command.

## 3. Stages

Each stage is a dsip-rs PR. Vectors, parity, fuzz seeds, every CI demo and the web tests stay green throughout. A
stage that changes behaviour a vector can see starts with the vector in DSIP (CLAUDE.md rule 2).

- **S1, configuration files.** *Done: keys are the flags in `snake_case`, flat, through `dsip_transport::config_file`.* `dsip-relay` and `dsip-mailbox` read a TOML file (`/etc/dsip-relay/relay.toml`,
  `/etc/dsip-mailbox/mailbox.toml`), using dsip-node's pattern: every key also a flag, flags win, unknown keys are
  an error, and every key is explained in a `config.example.toml`. Existing flags keep their names, so the demos and
  `node-setup.sh` work unchanged.
- **S2, `did:web` over HTTPS.** *Done: `dsip_transport::resolver::WebDocuments`, fetched before verification;
  `--did-web-ttl`, `--did-web-ca`, `--no-fetch-did-web`; `demos/did-web-demo.sh`.* Both services resolve `did:web` identities with `dsip_transport::resolver`
  (`DidWebResolver`, which reuses a document for a configured TTL; `Chain` puts the document files first, so
  they still work as overrides). Authority order is unchanged (§8.1): a fetched document is authoritative, a cached one only within its
  lifetime, and a hint never.
- **S3, the relay's queue on disk.** *Done: `<state>/queue.redb` (`dsip_relay::store`), with the known recipients;
  `demos/relay-restart-demo.sh`.* The store-and-forward queue (§13.3: `inbox_cap`, `queue_budget_bytes`,
  `offline_retention_s`) is kept in a `redb` file in the state directory, as dsip-node keeps its records. A
  restarted relay delivers what it held, within each envelope's retention. A demo restarts a relay with a queued
  invite and an offline callee.
- **S4, the mailbox store.** *Done: `<state>/mailbox.sqlite` (`dsip_mailbox::db`): an item a row, the rest in parts
  written when changed; the JSON imported once; `store_stress` about 42,000 deposits/s, flat from 1,000 to 100,000
  items held, about 1.45 KB per 1 KB item. Payloads of dropped items were never freed before; now they are.* Items, cursors and enrolments are written per change to an embedded database, rather
  than the whole state rewritten as JSON. A mailbox upgraded from the JSON file imports it once. Blobs stay files.
  `mailbox-restart-demo.sh` and the enrolment demo cover it, plus a load measurement like dsip-node's
  `store_stress` (items per second, disk per item).
- **S5, operating.** *Done: `dsip_transport::tls::Certificates` (SIGHUP re-reads the files; a bad renewal keeps
  the certificate served), `dsip-relay admin bindings` and `dsip-mailbox admin enrolments | release <did>`
  (`dsip_transport::admin`; a changing command is a POST with `x-dsip-admin`), `--log auto|journald|stderr`;
  `demos/operating-demo.sh`. The deploy hook's `systemctl reload` and the units' `ExecReload` come with the packages
  (S6); the testbed's hook, in DSIP's `node-setup.sh`, moves with S7.* Certificates reload on `SIGHUP` without dropping bound devices; the Let's Encrypt deploy hook
  sends `SIGHUP` instead of restarting. Add an admin command (`dsip-mailbox admin enrolments | release <did>`,
  `dsip-relay admin bindings`) on the loopback status port. Logs go to journald.
- **S6, packages.** For each of `dsip-relay` and `dsip-mailbox`:
  - static musl binaries and their tarballs;
  - a `.deb` whose config is a conffile, kept on upgrade;
  - a sandboxed `DynamicUser` unit;
  - a distroless container image;
  - a `packaging/test.sh` that installs the package under systemd and in a container, and checks that state
    survives a restart in both.

  The browser client ships as `dsip-web`, a tarball of the built `web/`, which the relay serves with `--www`.
- **S7, one host, one name.** *Done: `docs/one-host.md`; `packaging/one-host/configure` for the `.deb`s,
  `packaging/one-host/compose/` (`./init`), `packaging/one-host/test.sh`. Decided: the relay on 443 (decision 6).* A single-host recipe: the relay on 443, or 8443 behind a proxy, serving the client,
  proxying the node at `/dsip/v1/`, minting TURN credentials; the mailbox; the hints node; coturn. It comes as a
  `compose.yaml`, and as an install guide for the three `.deb`s, with the DNS names, ports and certificates
  spelled out. `node-setup.sh` on the WAN testbed becomes a thin wrapper over the packages, and L1 and L2 are
  re-provisioned from them as the check.
- **S8, releases.** *Done: `.github/workflows/release.yml` on a `vYYYY.MM.DD` tag (a dry run on a pull request that
  changes it, or by hand), `packaging/release-assets.sh` (the files, one `SHA256SUMS`, the notes); images signed with
  cosign (keyless) and every file and image attested; `dsip-node-release.yml` removed.* The CalVer workspace release builds and attaches every service's artifacts: tarballs, `.deb`s,
  `SHA256SUMS` and images pushed to `ghcr.io/feryx-io/dsip-relay`, `-mailbox` and `-node`. That replaces
  dsip-node's own `dsip-node-v*` tags. The images are signed.

S1 and S2 come first: everything later assumes a config file, and an operator with `did:web` users needs S2 before
anything else.

## 4. Decisions

*Decided 2026-10-29: the user took every draft below.*

1. **Packages per service, or one server package.** (a) three packages, `dsip-relay`, `dsip-mailbox` and
   `dsip-node`, plus `dsip-web`, and a compose file and guide for a single host. (b) One `dsip-server` package with
   all three and a role switch. *Draft: (a).* Operators who want only a hints node, or a relay without messaging,
   install one, and dsip-node already ships that way.
2. **The mailbox's database.** (a) SQLite, already linked into the mailbox for MLS device state. (b) `redb`, as
   dsip-node uses. *Draft: (a).* It is one embedded database for the whole process, queries are easy for the admin
   command, and nothing new is linked.
3. **Relay queue persistence.** (a) On disk, S3. (b) Memory only, documented: the relay advertises
   `offline_retention_s`, and losing the queue on a restart breaks that for every queued envelope. *Draft: (a).*
4. **Release tags.** (a) The CalVer workspace release carries every service's artifacts (S8). (b) Per-service tags,
   as dsip-node does now. *Draft: (a),* so one name pins a server set that was tested together.
5. **Container registry.** `ghcr.io/feryx-io/…`, which dsip-node's README already names. *Draft: yes.*
6. **The relay's port on one host** (S7). (a) 443, the relay terminating TLS itself: the client's address has no port.
   The unit gains `CAP_NET_BIND_SERVICE` and loses its private user namespace (exposure 1.1 → 1.5); in compose,
   Docker publishes 8443 as 443. (b) 8443 behind a proxy on 443. *Chosen in S7: (a).* A proxy adds a service to
   configure and renew for, and an HTTP proxy hides each client's address from the relay, which passes it on for the
   hints node's per-client limit. `configure --port 8443` stays possible, as on the WAN testbed, whose identities
   already name `:8443`.

## 5. Out of scope, and why

- **TURN.** coturn is mature and speaks the TURN REST API the relay mints credentials for; S7 configures it.
- **A web admin console.** The status ports and the admin command are enough to operate it; a console is a product
  of its own.
- **Multi-host high availability.** One relay holds a device's binding. Several relays for one identity is spec
  territory (§13, forking across relays works already), not packaging.
- **Mailbox quotas and billing.** `quota_bytes` exists per owner; pricing is the operator's.
