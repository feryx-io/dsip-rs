#!/usr/bin/env bash
# Sealed presence (P§12): Bob seals his presence, so his relay carries states it cannot read. The grants his phone
# issues carry the keys (sealed to the grantee, P§12.3); Alice and Carol open his records with them, while Dave, whose
# grant was issued without keys, sees his records but cannot read them (P§12.4). Bob's phone ends Alice's share: it
# revokes her grant at the relay, rotates `main` to epoch 1 and re-grants Carol with the new key (P§12.5). His laptop,
# watching its own identity, sees the phone's record at epoch 1 and seals there too. Carol reads both devices; Alice
# is refused. Self-verifying.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-presence-sealed-demo}; rm -rf "$D"; mkdir -p "$D"
R=wss://127.0.0.1:8468/dsip
for n in alice carol dave; do $B/dsip identity init --dir "$D/$n" --name "${n^}" >/dev/null; done
$B/dsip identity init --dir "$D/bob-phone" --name Bob >/dev/null
$B/dsip identity init --dir "$D/bob-laptop" --name Bob --controller-from "$D/bob-phone" >/dev/null
did() { python3 -c "import json;print(json.load(open('$D/$1/identity.json'))['identity'])"; }
BOB=$(did bob-phone); ALICE=$(did alice)
$B/dsip-relay --listen 127.0.0.1:8468 --state "$D/relay" --presence-grace 2 >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT; sleep 1.5; CA="$D/relay/cert.pem"
# the message again last: CI keeps only the tail of a demo's output
fail() { echo "FAIL: $*"; for f in "$D"/*.log; do echo "--- $f"; cat "$f"; done; echo "FAIL: $*"; exit 1; }
C=(--relay $R --ca "$CA")

# $1 grantee, $2 extra answer flags: the grantee introduces itself and Bob's phone grants it (§19.4)
grant() {
  $B/dsip answer --identity "$D/bob-phone" "${C[@]}" --first-contact $2 --script "sleep 8; grant; sleep 3; quit" >"$D/grant-$1.log" 2>&1 & local G=$!
  sleep 1.5
  $B/dsip introduce --identity "$D/$1" "${C[@]}" --to "$BOB" --purpose "sealed presence demo" --wait 15 >"$D/intro-$1.log" 2>&1
  wait $G
  grep -q "granted" "$D/intro-$1.log" || fail "Bob's grant did not reach $1"
}

echo "=== Bob's phone grants Alice and Carol with sealed presence, Dave without (P§12.3)"
grant alice --seal-presence; grant carol --seal-presence; grant dave ""
held() { python3 -c "import json;print(' '.join(sorted(json.load(open('$D/$1/contacts.json')).get('presence_held',{}).get('$BOB',{}))))"; }
for n in alice carol dave; do echo "  $n holds keys: $(held $n)"; done
[ "$(held alice)" = "main.0" ] && [ "$(held carol)" = "main.0" ] || fail "the sealed grants did not carry main.0"
[ -z "$(held dave)" ] || fail "Dave's grant carried keys"

echo "=== Bob's phone publishes busy, sealed; Alice and Dave watch"
$B/dsip presence publish --identity "$D/bob-phone" "${C[@]}" --sealed --state busy --lifetime 60 --wait 7 >"$D/phone1.log" 2>&1 & P=$!
sleep 1.5
$B/dsip presence watch --identity "$D/alice" "${C[@]}" --target "$BOB" --wait 3 >"$D/alice1.log" 2>&1 &
$B/dsip presence watch --identity "$D/dave" "${C[@]}" --target "$BOB" --wait 3 >"$D/dave1.log" 2>&1
wait $P
grep -E "sealed under" "$D/phone1.log" | head -1 | sed 's/^ */  /'
grep -E "presence:|device " "$D/alice1.log" | sed 's/^ */  alice: /' | head -2
grep -E "presence:|device " "$D/dave1.log" | sed 's/^ */  dave:  /' | head -2
grep -q "sealed under main.0" "$D/phone1.log" || fail "the phone did not seal under main.0"
grep -q "presence: busy" "$D/alice1.log" && grep -q "sealed main.0 .* opened" "$D/alice1.log" || fail "Alice did not open Bob's record"
grep -q "unreadable: no key for main.0" "$D/dave1.log" || fail "Dave read a record he holds no key for"
! grep -q "presence: busy" "$D/dave1.log" || fail "Dave was shown a state he cannot read"

echo "=== Bob's phone ends Alice's share: revocation at the relay, main rotates, Carol is re-granted (P§7, P§12.5)"
AG=$(python3 -c "import json;print(next(k for k,g in json.load(open('$D/bob-phone/contacts.json'))['grants_issued'].items() if g['identity']=='$ALICE'))")
$B/dsip answer --identity "$D/carol" "${C[@]}" --script "sleep 7; quit" >"$D/carol-online.log" 2>&1 & CO=$!
sleep 1.5
$B/dsip answer --identity "$D/bob-phone" "${C[@]}" --seal-presence --script "sleep 1; revoke $AG; sleep 3; quit" >"$D/revoke.log" 2>&1
wait $CO
grep -E "grant-revocation|presence key" "$D/revoke.log" | sed 's/^ */  /'
grep -q "grant-revocation to our relay: …${AG: -8}" "$D/revoke.log" || fail "Alice's grant was not revoked at the relay"
grep -q "presence key main rotated to epoch 1" "$D/revoke.log" || fail "main did not rotate"
echo "  carol holds keys: $(held carol)"
[ "$(held carol)" = "main.0 main.1" ] || fail "Carol was not re-granted with main.1"

echo "=== the phone publishes dnd at epoch 1; the laptop, watching its own identity, moves there too"
$B/dsip presence publish --identity "$D/bob-phone" "${C[@]}" --sealed --state dnd --lifetime 60 --wait 16 >"$D/phone2.log" 2>&1 & P=$!
sleep 1.5
$B/dsip presence publish --identity "$D/bob-laptop" "${C[@]}" --sealed --state away --then 6:away --lifetime 60 --wait 12 >"$D/laptop.log" 2>&1 & L=$!
sleep 8
$B/dsip presence watch --identity "$D/carol" "${C[@]}" --target "$BOB" --wait 3 >"$D/carol.log" 2>&1
$B/dsip presence watch --identity "$D/alice" "${C[@]}" --target "$BOB" --wait 3 >"$D/alice2.log" 2>&1 || true
wait $P $L
grep -E "sealed under|presence key" "$D/laptop.log" | sed 's/^ */  laptop: /'
grep -E "presence:|device " "$D/carol.log" | sed 's/^ */  carol: /' | head -3
grep -q "sealed under main.1" "$D/phone2.log" || fail "the phone did not seal at epoch 1"
grep -q "presence key main seen to epoch 1" "$D/laptop.log" || fail "the laptop did not see the phone's epoch"
grep -q "sealed under main.1" "$D/laptop.log" || fail "the laptop did not move to epoch 1"
grep -q "presence: dnd" "$D/carol.log" || fail "Carol did not read Bob's dnd"
[ "$(grep -c 'sealed main.1 .* opened' "$D/carol.log")" -ge 2 ] || fail "Carol did not open both devices' records"
grep -q 'reject   "policy.blocked"' "$D/alice2.log" || fail "Alice's revoked grant still admitted her"
! grep -q "^← error" "$D/phone1.log" "$D/phone2.log" "$D/laptop.log" || fail "the authority refused a record"
echo
echo "PASS: the relay routed sealed records it cannot read; grants carried the keys and Alice and Carol opened them,"
echo "      Dave's keyless grant showed the records as unreadable; ending Alice's share revoked her grant, rotated main"
echo "      and re-granted Carol with main.1; the laptop adopted the phone's epoch from its own watch."
