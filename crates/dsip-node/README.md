# dsip-node

A DSIP reachability-hints node. One process, three faces:

- **a member of the DSIP overlay** (libp2p Kademlia, `/dsip/hints/0.6`): device-signed and `did:web` hints;
- **a participant in the BitTorrent Mainline DHT**, holding Pkarr packets: `did:key` hints, and any other Pkarr
  application's packets;
- **an HTTP hints API** (DHT Reachability Hints Profile §10), for clients that join neither DHT, such as browsers.
  It speaks Pkarr's relay interface (`GET`/`PUT /<z32>`), so existing Pkarr clients use it unchanged.

**It is a hints tier, never an authority** (DSIP core §8.1). It verifies every record before storing or serving it,
and clients verify again. A node can withhold a hint or serve an older one; it cannot forge one. It carries no
messages, media or presence. Design and measurements: `impl/docs/dsip-node-plan.md`, `impl/docs/dht-findings.md`.

## Install

| | |
|---|---|
| **Debian / Ubuntu** | `apt install ./dsip-node_<version>_<arch>.deb`. This installs `/usr/bin/dsip-node`, `/etc/dsip-node/config.toml` (a conffile, kept on upgrade) and `dsip-node.service`, enabled and started. |
| **Any Linux** | Unpack `dsip-node-<version>-linux-<arch>.tar.gz` (a static binary, no dependencies). Install `dsip-node.service` and `config.example.toml` from the tarball by hand. |
| **Container** | `docker run -d -p 8080:8080 -p 4610:4610 -p 6881:6881/udp -v dsip-node:/var/lib/dsip-node ghcr.io/feryx-io/dsip-node`, or `compose.yaml`. |

The package starts at once with its default config. To start with your own instead (another HTTP port, bootstrap
nodes), put `/etc/dsip-node/config.toml` in place first and install with `-o Dpkg::Options::=--force-confold`.

The packages and the image (`ghcr.io/feryx-io/dsip-node:<release>`, e.g. `2026.11.02`, signed) come with each
dsip-rs workspace release, verified by its `SHA256SUMS` (RELEASING.md). To build everything yourself, run `packaging/build.sh --image`; to test it as an
operator would, run `packaging/test.sh`.

## Ports

| port | what | expose? |
|---|---|---|
| 4610/tcp | the DSIP overlay | yes, for peers to reach you |
| 6881/udp | the Mainline DHT | yes, for server mode (`[mainline] server = true`) |
| 8080/tcp | the HTTP hints API and `/metrics` | through a TLS reverse proxy; the package binds it to 127.0.0.1 |

## Configure

Edit `/etc/dsip-node/config.toml`; every key is explained in `config.example.toml`. A flag of the same name overrides
a key (`dsip-node --help`), and a misspelt key is an error.
- **Join an overlay:** add its bootstrap nodes to `[overlay] bootstrap`, as `/dns4/<name>/tcp/4610/p2p/<PeerId>`.
- **Mainline bootstrap:** list your other nodes in `[mainline] bootstrap` (`host:6881`) with a public node that
  answers (`dht.libtorrent.org:25401`). The list replaces the library's defaults, some of which may not answer, and a
  node relies on it whenever its saved routing nodes (`mainline-nodes` in the state directory) have dwindled.
- **On the WAN testbed** `ROLE=hints HINTS_PEERS=<a running node> tools/wan/node-setup.sh` writes both bootstrap
  lists for you, reading each peer's PeerId from its `/dsip/v1/node` (`tools/wan/README.md`, "Hints nodes").
- **Find your node's PeerId:** `curl localhost:8080/dsip/v1/node`, or look in the log at start.
- **Size the record store:** overlay records live in `overlay-records.redb` in the state directory. A browser's
  device-signed hint takes about 2.9 KB on disk, so the default `[overlay] max_records = 1000000` needs about 3 GB.
  Memory is the store's page cache, `store_cache_mb` (default 256), however many records it holds. Past
  `max_records` new keys are refused. `/dsip/v1/node` shows `records` against `max_records`, plus `replicated` and
  `pruned` from the paced pass that re-announces the store once per `republish_secs` (default 1200). A node upgraded
  from an `overlay-records.jsonl` imports it once, then renames it `.imported`. Measured with
  `cargo run --release -p dsip-dht --example store_stress -- --records 1000000 --dir <disk path>`.
- **Behind a reverse proxy on the same host** (dsip-relay's `--node-proxy`, or a TLS proxy): set `[limits]
  trust_x_forwarded_for = true`, so rate limits apply per client, not per proxy. The header is honoured only on
  loopback connections; anything else is limited by its own address.

## Security posture

- **Package:** the systemd unit runs under `DynamicUser` with no capabilities, `ProtectSystem=strict`, a
  `@system-service` syscall filter, W^X memory and a private `/var/lib/dsip-node`. `systemd-analyze security
  dsip-node` rates it 1.1, "OK".
- **Container:** distroless, non-root (65532); it runs with a read-only root and `cap_drop: [ALL]`.
- **The identity key** (`overlay.key`) is created with mode 0600. Keep the state directory: it holds the node's
  PeerId, learned peers, held records, and its Mainline routing nodes and public address, so a restart rejoins in
  seconds on both DHTs. Every record read back from it is verified again.
- **Held Pkarr packets** are served at once, and looked for again on Mainline at most once a minute; one past its
  TTL is looked for before it is served, so a publisher's re-signed packet replaces it.
- **Flooding peers:** a peer that fails 20 verifications in 60 s is banned for `ban_secs`. Its PUTs are dropped
  unverified and it leaves the routing table.
  - `ban_ip = true` also refuses its address **before** the handshake. Measured, this cuts a flood's CPU by about
    70%, but it refuses honest peers behind the same NAT as well.
  - Closing a flooder's connection by PeerId was measured to cost **more**: it redials, and each refusal costs a
    handshake.
- **HTTP:** 120 requests per client IP per minute (429 beyond); `/metrics` is never limited.

## Operate

- **`GET /metrics`** (Prometheus) reports:
  - overlay peers, records, PUTs by reason, bans and refused connections;
  - Mainline mode and size;
  - Pkarr packets held and PUT outcomes;
  - HTTP requests by route and status.
- **`GET /dsip/v1/node`** reports the PeerId, overlay and Mainline status, packets held and the version.
- **Logs** go to the journal, or to stdout in a container: plain text, one line per refusal with its reason.
