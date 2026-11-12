#!/usr/bin/env bash
# Presence audiences and time-boxed shares (P§6, P§7): Bob grants Alice his `family` audience, and Carol a share of
# 25 s with no audience. His phone publishes two records, each signed by itself: `available` for everyone it shares
# with and `busy` for family (P§6). Alice, admitted by the family grant, sees busy; Carol sees only the record with no
# audience, available. When Carol's share reaches its valid_until the relay ends her watch (policy.terminated), and a
# renewal is refused. Last, Bob narrows Alice's grant to calls only with a grant that follows it (spec-gap 150): his
# phone revokes the old grant at the relay, which ends her watch, and a new watch is refused. Self-verifying.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-presence-audiences-demo}; rm -rf "$D"; mkdir -p "$D"
R=wss://127.0.0.1:8464/dsip
$B/dsip identity init --dir "$D/alice" --name Alice >/dev/null
$B/dsip identity init --dir "$D/carol" --name Carol >/dev/null
$B/dsip identity init --dir "$D/bob" --name Bob >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")
$B/dsip-relay --listen 127.0.0.1:8464 --state "$D/relay" >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT; sleep 1.5; CA="$D/relay/cert.pem"
# the message again last: CI keeps only the tail of a demo's output
fail() { echo "FAIL: $*"; for f in "$D"/*.log; do echo "--- $f"; cat "$f"; done; echo "FAIL: $*"; exit 1; }

# grant_to WHO OPTIONS: WHO introduces herself; Bob grants the latest request with OPTIONS (§19.4)
grant_to() {
  $B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --first-contact --script "sleep 4; grant $2; sleep 2; quit" \
    >"$D/grant-$1.log" 2>&1 & local G=$!
  sleep 1.5
  $B/dsip introduce --identity "$D/$1" --relay $R --ca "$CA" --to "$BOB" --purpose "audiences demo" --wait 12 >"$D/intro-$1.log" 2>&1
  wait $G
  grep -q "granted" "$D/intro-$1.log" || fail "Bob's grant did not reach $1"
}

echo "=== Bob grants Alice his family audience, and Carol a 25 s share with no audience (P§6, P§7)"
grant_to alice "audience=family"
grant_to carol "for=25"
SHARE_START=$(date +%s)
grep -h "→ grant" "$D/grant-alice.log" "$D/grant-carol.log" | sed 's/^ */  /'

echo "=== Bob's phone publishes available for everyone, busy for family: two records, each signed (P§6)"
$B/dsip presence publish --identity "$D/bob" --relay $R --ca "$CA" --state available --audience family=busy --lifetime 60 --wait 40 \
  >"$D/publish.log" 2>&1 & PUB=$!
sleep 1.5
grep "→ presence" "$D/publish.log" | sed 's/^ */  /'
[ "$(grep -c '→ presence' "$D/publish.log")" -ge 2 ] || fail "the phone did not publish both records"
grep -q "→ presence busy (audience family)" "$D/publish.log" || fail "no family record"

echo "=== Alice (family) and Carol (no audience) watch Bob"
$B/dsip presence watch --identity "$D/alice" --relay $R --ca "$CA" --target "$BOB" --wait 5 >"$D/alice.log" 2>&1
grep -E "presenting|presence:" "$D/alice.log" | sed 's/^/  alice: /'
grep -q "presence: busy  (from a device's signed record)" "$D/alice.log" || fail "Alice, in family, did not see busy"
LEFT=$(( SHARE_START + 25 - $(date +%s) ))
$B/dsip presence watch --identity "$D/carol" --relay $R --ca "$CA" --target "$BOB" --wait $(( LEFT + 6 )) >"$D/carol.log" 2>&1 || true
grep -E "presenting|presence:|terminated|reason" "$D/carol.log" | sed 's/^/  carol: /'
grep -q "presence: available  (from a device's signed record)" "$D/carol.log" || fail "Carol did not see the record with no audience"
! grep -q "presence: busy" "$D/carol.log" || fail "Carol saw the family record"
grep -q "reason policy.terminated" "$D/carol.log" || fail "Carol's watch did not end when her share did"

echo "=== Carol's share is over: a new watch is refused (P§7)"
$B/dsip presence watch --identity "$D/carol" --relay $R --ca "$CA" --target "$BOB" --wait 3 >"$D/after.log" 2>&1 || true
grep -q 'reject   "policy.blocked"' "$D/after.log" || fail "an ended share still admitted Carol"
echo "  refused: policy.blocked"

# one device key binds once (§13.2: a second hello replaces the first): the phone's publisher is done before Bob's
# phone runs the regrant
wait $PUB
! grep -q "^← error" "$D/publish.log" || fail "the authority refused a record"

echo "=== Bob narrows Alice's grant to calls only: a grant that follows it, the old one revoked at his relay (§19.4, P§7)"
ALICE=$(python3 -c "import json;print(json.load(open('$D/alice/identity.json'))['identity'])")
AGRANT=$(python3 -c "import json;g=json.load(open('$D/bob/contacts.json'))['grants_issued'];print(next(k for k,v in g.items() if v['identity']=='$ALICE'))")
$B/dsip presence watch --identity "$D/alice" --relay $R --ca "$CA" --target "$BOB" --wait 12 >"$D/narrowed.log" 2>&1 & W=$!
sleep 2
$B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --script "sleep 2; regrant $AGRANT audience=Family; regrant $AGRANT calls-only; sleep 2; quit" >"$D/regrant.log" 2>&1
wait $W || true
grep -E "no live grant|follows it" "$D/regrant.log" | sed 's/^ */  /' || true
grep -q "an audience that is not a token" "$D/regrant.log" || fail "a regrant naming an audience that is not a token was not refused"
grep -q "follows it" "$D/regrant.log" || fail "Bob's phone did not send the following grant"
python3 -c "import json;g=json.load(open('$D/bob/contacts.json'))['grants_issued'];n=[v for v in g.values() if v['identity']=='$ALICE'];assert len(n)==1 and n[0]['scope']==['dsip.invite'],n" \
  || fail "Bob does not hold exactly one calls-only grant for Alice"
grep -q "reason policy.terminated" "$D/narrowed.log" || fail "the narrowed grant did not end Alice's watch"
echo "  Alice's watch: ended, policy.terminated; Bob now holds one grant for her: [dsip.invite]"
$B/dsip presence watch --identity "$D/alice" --relay $R --ca "$CA" --target "$BOB" --wait 3 >"$D/after-narrow.log" 2>&1 || true
grep -q 'reject   "policy.blocked"' "$D/after-narrow.log" || fail "the old grant still admitted Alice after it was followed"
echo "  a new watch: refused, policy.blocked"
echo
echo "PASS: one device published a record per audience; the family grant saw busy, the plain share saw available"
echo "      only, and the 25 s share ended Carol's watch at its valid_until, after which she was refused; a grant that"
echo "      followed Alice's narrowed it to calls only, ending her watch."
