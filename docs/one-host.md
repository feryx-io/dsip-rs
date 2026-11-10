# One host, one name

*Service nodes S7 (docs/dsip-service-nodes-plan.md). Tested by `packaging/one-host/test.sh`.*

DSIP's three services and coturn on one machine behind one DNS name, say `dsip.example.com`:

- the **relay** (§13) on 443, which also serves the browser client, the client's defaults (`/config.json`), TURN
  credentials (`/turn`) and the hints node's API (`/dsip/v1/`);
- the **mailbox and hub** (M§4) on 9443, under the same certificate;
- the **hints node** (DHT Hints Profile §10), behind the relay on loopback;
- **coturn** for STUN and TURN.

A browser opens `https://dsip.example.com/` and needs nothing else: the page, the relay it binds to, its hints node,
its mailbox and its TURN server are all that name. There are two ways to run it: the `.deb` packages under systemd
(§4), or a compose file with the container images (§5). Both are set up by one script, run again whenever something
changes.

## 1. Ports and names

| Port | What | Open to |
|---|---|---|
| 443/tcp | relay: `wss://<name>/dsip`, the client, `/config.json`, `/turn`, `/dsip/v1/` | everyone |
| 9443/tcp | mailbox: `wss://<name>:9443/dsip` and its blob endpoint | everyone |
| 3478/udp, 3478/tcp | coturn: STUN and TURN | everyone |
| 49160–49200/udp | coturn's relayed media | everyone |
| 4610/tcp | hints node: the DSIP overlay (libp2p) | everyone |
| 6881/udp | hints node: the Mainline DHT (Pkarr) | everyone |
| 80/tcp | certbot's HTTP-01 challenge, while it runs | everyone, or closed between renewals |
| 127.0.0.1:8080 | hints node HTTP API, reached through the relay | loopback |
| 127.0.0.1:9101, :9102 | relay and mailbox `/status`, `/metrics` and `admin` | loopback |

DNS: one `A` record (and `AAAA` if the host has IPv6) for the name. Users' `did:web` identities are served by their
own web hosts, not this one; their documents name this host's relay (`wss://dsip.example.com/dsip`) and mailbox
(`wss://dsip.example.com:9443/dsip`) as endpoints.

The hints node's API is not published on its own port. Clients reach it at `https://<name>/dsip/v1/`; the relay passes
each one's address to the node as `X-Forwarded-For`, which the node trusts from loopback only, so its per-client limit
counts browsers, not the relay. Other hints nodes find this one over the overlay and Mainline, not over HTTP.

## 2. Why 443, and not 8443 behind a proxy

The relay terminates TLS itself, and is the only service on the name that speaks HTTPS, so it takes 443: the client's
address carries no port. Under systemd that costs the unit one capability, `CAP_NET_BIND_SERVICE`, and its private
user namespace, in which a capability cannot bind the host's ports (`systemd-analyze security dsip-relay`: 1.1 without,
measured by the test with). In compose the container keeps 8443 and Docker publishes it as 443.

A host whose 443 belongs to a web server already can run the relay on 8443 (`--port 8443`) with the client at
`https://<name>:8443/`, or forward 443 to it at the TCP level (SNI routing, e.g. nginx `stream` with `ssl_preread`).
Either way the relay sees each client's own connection. Neither is tested here, and an HTTP reverse proxy is not
recommended: the relay always speaks TLS, so the proxy would re-encrypt to it, and the relay would see every client as
the proxy's address, which it passes to the hints node for its per-client limit.

## 3. The certificate

One certificate for the name, used by both the relay and the mailbox. With certbot, while nothing else listens on 80:

```sh
certbot certonly --standalone -d dsip.example.com
```

The services run as systemd `DynamicUser`s (or as the images' user 65532), which cannot read `/etc/letsencrypt`. The
setup script copies the pair into each service's own state directory, and installs a deploy hook that does the same on
every renewal and reloads both with `SIGHUP`: connected devices stay connected. Nothing else is needed for renewals;
certbot's timer runs them.

## 4. With the packages

On Debian 12 or 13, or Ubuntu 22.04 or later:

```sh
# the three services, the browser client and dsip-one-host-<release>.tar.gz (configure, the compose directory):
# a release's files (https://github.com/feryx-io/dsip-rs/releases; sha256sum -c SHA256SUMS), or built with
#   packaging/build.sh dsip-relay dsip-mailbox dsip-web  and  crates/dsip-node/packaging/build.sh
apt install ./dsip-relay_*_amd64.deb ./dsip-mailbox_*_amd64.deb ./dsip-node_*_amd64.deb coturn certbot
mkdir -p /usr/local/share/dsip-web
tar -xzf dsip-web-*.tar.gz --strip-components 1 -C /usr/local/share/dsip-web
certbot certonly --standalone -d dsip.example.com

packaging/one-host/configure --name dsip.example.com \
  --cert-dir /etc/letsencrypt/live/dsip.example.com --www /usr/local/share/dsip-web \
  --serve-any 32 --release-idle --coturn --public-ip 203.0.113.10
```

`--serve-any 32` lets up to 32 identities enrol at the mailbox by binding (the browser client's `did:key`
identities, spec-gap 115), and `--release-idle` ends an enrolment none of whose devices has connected for
`mls_retention` (30 days), freeing its place (M§4.1). `--owner <did>` (repeatable) names identities whose DID documents
name this mailbox; they never expire. `--public-ip` is the address coturn relays on, which must be on one of the
host's interfaces.

`configure` writes these files, keeping the previous version of each beside it as `.bak-<time>`, and restarts only the
services whose files changed:

| File | What |
|---|---|
| `/etc/dsip-relay/relay.toml` | the relay on 443: the certificate, the client, `/config.json`, the hints node at `/dsip/v1/`, TURN |
| `/etc/dsip-relay/client.json` | the client's defaults: this origin as its hints node, this mailbox with its service DID |
| `/etc/systemd/system/dsip-relay.service.d/one-host.conf` | port 443's capability |
| `/etc/dsip-mailbox/mailbox.toml` | the mailbox on 9443 under the same certificate, whom it serves |
| `/etc/dsip-node/config.toml` | only `trust_x_forwarded_for = true`; bootstrap nodes and ports are yours to edit |
| `/etc/turnserver.conf`, `/etc/dsip-relay/turn.secret` | coturn with the TURN REST API's shared secret (`--coturn`) |
| `/var/lib/dsip-relay/turn.secret` | the secret's copy the relay reads: its `DynamicUser` cannot read root's |
| `/etc/letsencrypt/renewal-hooks/deploy/dsip-one-host` | a renewal of the name's certificate installs it into both services |

Edit the scripts' options rather than these files: the next `configure` rewrites them. The hints node's config is the
exception, where `configure` changes one key. With a TURN server elsewhere, give `--turn-uri turn:<host>:3478
--turn-secret-file <its secret>` instead of `--coturn`.

To join other hints nodes, list them in `/etc/dsip-node/config.toml` (`[overlay] bootstrap` and `[mainline]
bootstrap`; the comments there explain both) and `systemctl restart dsip-node`.

## 5. With compose

On a host with Docker and the compose plugin, from a copy of `packaging/one-host/compose/` (say `/srv/dsip`):

```sh
cd /srv/dsip
cp env.example .env && $EDITOR .env           # DSIP_NAME, PUBLIC_IP, DSIP_SERVE_ANY
mkdir www && tar -xzf dsip-web-*.tar.gz --strip-components 1 -C www
certbot certonly --standalone -d dsip.example.com \
  --deploy-hook "/srv/dsip/init --certificate \$RENEWED_LINEAGE"
./init --certificate /etc/letsencrypt/live/dsip.example.com
```

The relay, the mailbox and the hints node share one network namespace, held by a `pause` container that publishes
the ports, so they reach each other on 127.0.0.1 exactly as on a host, and a restarted service keeps its network.
coturn runs on the host's network. State lives in the volumes `dsip_dsip-relay`, `dsip_dsip-mailbox` and
`dsip_dsip-node`. `init` writes `./tls`, `./turn.secret`, `./turnserver.conf` and `./client.json`; mailbox owners go
in `mailbox.toml`, other hints nodes in `node.toml`, then `./init` again.

## 6. Checking it

```sh
curl -s https://dsip.example.com/config.json      # the client's defaults, the mailbox's service DID
curl -s https://dsip.example.com/dsip/v1/node     # the hints node, through the relay
curl -s https://dsip.example.com/turn             # short-lived TURN credentials
dsip-relay admin --config /etc/dsip-relay/relay.toml bindings
dsip-mailbox admin --config /etc/dsip-mailbox/mailbox.toml enrolments
```

In compose, the admin commands run in their containers: `docker compose exec dsip-mailbox dsip-mailbox admin --config
/etc/dsip-mailbox/mailbox.toml enrolments`. Then open `https://dsip.example.com/` in two browsers, add each other as
contacts and call; a call between two networks that block each other's media is relayed by coturn.

## 7. Running it

- **Logs:** `journalctl -u dsip-relay -u dsip-mailbox -u dsip-node`, or `docker compose logs`.
- **Upgrades:** `apt install ./<new>.deb` keeps the configs (conffiles) and restarts the service; state is kept across
  versions (S3, S4). In compose, a new `DSIP_VERSION` and `docker compose up -d`.
- **Backups:** the state directories `/var/lib/dsip-relay` (the relay's key and its queue), `/var/lib/dsip-mailbox`
  (the service key, `mailbox.sqlite` and blobs) and `/var/lib/dsip-node`, or the three volumes. The mailbox's service
  key is its DID: losing it means every enrolled identity enrols again.
- **Ending an enrolment:** `dsip-mailbox admin ... release <did>` (M§4.1, spec-gap 164).
