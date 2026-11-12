#!/usr/bin/env bash
# Presence Profile (P§3–P§7): presence is private by default, so Bob's relay refuses Alice until Bob grants her
# contact; the grant carries dsip.subscribe and she presents it (P§6). Two of Bob's devices publish their own signed
# presence records to his relay (the authority); Alice watches his presence, verifies each record herself and combines
# them (P§4). Bob's phone is busy, so Bob is busy; the phone leaves, its record outlives the unbind by T-Presence-Grace
# and is then dropped, so Bob is what his laptop says; the laptop switches to a state newer than Alice's client knows,
# shown as available with the token raw (P§5). Last, Bob revokes the grant at his relay, which ends her watch (P§7).
# Self-verifying.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-presence-demo}; rm -rf "$D"; mkdir -p "$D"
R=wss://127.0.0.1:8463/dsip
$B/dsip identity init --dir "$D/alice" --name Alice >/dev/null
$B/dsip identity init --dir "$D/bob-phone" --name Bob >/dev/null
$B/dsip identity init --dir "$D/bob-laptop" --name Bob --controller-from "$D/bob-phone" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob-phone/identity.json'))['identity'])")
$B/dsip-relay --listen 127.0.0.1:8463 --state "$D/relay" --presence-grace 2 >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT; sleep 1.5; CA="$D/relay/cert.pem"
# the message again last: CI keeps only the tail of a demo's output
fail() { echo "FAIL: $*"; for f in "$D"/*.log; do echo "--- $f"; cat "$f"; done; echo "FAIL: $*"; exit 1; }

echo "=== private by default: Alice has no grant of Bob's, so his relay refuses her (P§6, §9.2)"
$B/dsip answer --identity "$D/bob-phone" --relay $R --ca "$CA" --first-contact --script "sleep 8; grant; sleep 3; quit" >"$D/grant.log" 2>&1 & G=$!
sleep 1.5
$B/dsip presence watch --identity "$D/alice" --relay $R --ca "$CA" --target "$BOB" --wait 3 >"$D/refused.log" 2>&1 || true
grep -E "reject" "$D/refused.log" | sed 's/^ */  /'
grep -q 'reject   "policy.blocked"' "$D/refused.log" || fail "the relay did not refuse a watcher with no grant"

echo "=== Alice introduces herself; Bob grants her contact (scope dsip.invite + dsip.subscribe, §19.4)"
$B/dsip introduce --identity "$D/alice" --relay $R --ca "$CA" --to "$BOB" --purpose "presence demo" --wait 15 >"$D/intro.log" 2>&1
wait $G
grep -q "granted" "$D/intro.log" || fail "Bob's grant did not reach Alice"
echo "  granted"

echo "=== Bob's phone publishes busy (it binds, so the relay knows Bob), his laptop away; Alice watches Bob"
$B/dsip presence publish --identity "$D/bob-phone" --relay $R --ca "$CA" --state busy --lifetime 60 --wait 8 >"$D/phone.log" 2>&1 & PHONE=$!
sleep 1
$B/dsip presence publish --identity "$D/bob-laptop" --relay $R --ca "$CA" --state away --then 13:focusing --lifetime 60 --wait 20 \
  >"$D/laptop.log" 2>&1 & LAPTOP=$!
sleep 1
$B/dsip presence watch --identity "$D/alice" --relay $R --ca "$CA" --target "$BOB" --wait 18 >"$D/watch.log" 2>&1

grep -E "presenting|presence:|device |assertion:" "$D/watch.log" | sed 's/^ */  /'
grep -q "presenting 1 grant" "$D/watch.log" || fail "Alice did not present Bob's grant"
grep -q "presence: busy  (from a device's signed record)" "$D/watch.log" || fail "Bob was not busy while his phone was"
grep -q "presence: away  (from a device's signed record)" "$D/watch.log" || fail "Bob did not become away once the phone's record was dropped"
grep -q "presence: available (shown raw: focusing)" "$D/watch.log" || fail "the unknown state was not shown as available with its token"
[ "$(grep -c '✓ verified' "$D/watch.log")" -ge 3 ] || fail "records were not verified by the watcher"
! grep -q "did not verify" "$D/watch.log" || fail "a record did not verify"
# order: busy, then away, then focusing
python3 - "$D/watch.log" <<'EOF' || fail "the states came in the wrong order"
import sys, re
seen = [m.group(1) for m in re.finditer(r"presence: (\S+)", open(sys.argv[1]).read())]
firsts = [s for i, s in enumerate(seen) if s not in seen[:i]]
assert firsts.index("busy") < firsts.index("away") < firsts.index("available"), firsts
EOF
wait $PHONE || fail "Bob's phone exited with status $? while publishing"
wait $LAPTOP || fail "Bob's laptop exited with status $? while publishing"
! grep -q "^← error" "$D/phone.log" "$D/laptop.log" || fail "the authority refused a record"

echo "=== Bob's phone revokes the grant at his relay; Alice's watch ends at once (P§7, §19.4)"
$B/dsip presence watch --identity "$D/alice" --relay $R --ca "$CA" --target "$BOB" --wait 30 >"$D/revoked.log" 2>&1 & W=$!
# the revocation must reach a live subscription: wait for the watch's first notify, not a fixed delay
for _ in $(seq 100); do grep -q "presence:" "$D/revoked.log" && break; sleep 0.2; done
grep -q "presence:" "$D/revoked.log" || fail "Alice's watch was not admitted before the revocation"
$B/dsip answer --identity "$D/bob-phone" --relay $R --ca "$CA" --script "sleep 2; revoke; sleep 2; quit" >"$D/revoke.log" 2>&1
wait $W || true
grep -E "grant-revocation" "$D/revoke.log" | sed 's/^ */  /' || true
grep -E "terminated|reason" "$D/revoked.log" | sed 's/^ */  /' || true
grep -q "reason policy.terminated" "$D/revoked.log" || fail "the revocation did not end Alice's watch with policy.terminated"
$B/dsip presence watch --identity "$D/alice" --relay $R --ca "$CA" --target "$BOB" --wait 3 >"$D/after.log" 2>&1 || true
grep -q 'reject   "policy.blocked"' "$D/after.log" || fail "a revoked grant still admitted Alice"
echo
echo "PASS: the relay refused a watcher without a grant and admitted her with Bob's; each device signed its own record;"
echo "      the watcher verified them and combined them (busy > away), the phone's record outlived its unbind by the"
echo "      grace and was then dropped, an unknown state showed as available, and revoking the grant ended the watch."
