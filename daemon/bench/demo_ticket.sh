#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Demo of wardend (root policy mode) against test processes (the gateway is not touched):
#   1) root waits for a ticket; `wardend approve` signs it with a test device key;
#      children (background, python -> os.system -> sh) pass without questions;
#   2) deny_always is cut immediately (rm -rf /, dd of=/dev/...), even inside an approved root;
#   3) setsid inside an approved root is a delegating spawn, a new root (second ticket);
#   4) TOCTOU: the "evil" process swaps argv from a second thread; the device approves only
#      SAFE-ARG; stop-verify kills swapped images before the first instruction;
#   5) journal: hash chain + supervisor signature, verify-journal.
set -u
cd "$(dirname "$0")/.."
GO=${GO:-$HOME/sdk/go/bin/go}
[ -x ./wardend ] && [ ./wardend -nt main.go ] || "$GO" build -o wardend . || exit 1
D=$(mktemp -d /tmp/wardend-demo.XXXXXX)
KEYF=$(mktemp)
trap 'rm -rf "$D" "$KEYF"' EXIT
./wardend keygen > "$KEYF"
chmod 600 "$KEYF"
DEV=$(sed -n 's/^deviceId=//p' "$KEYF")
PUB=$(sed -n 's/^pubkey=//p' "$KEYF")
SOCK="$D/wardend.sock"
# "approved root" mode (policy_mode root); tripwire tests are in tripwire_e2e_test.go
W=(./wardend run --mode ticket --policy-mode root --state-dir "$D" --gateway-db off --relay-url off --trust "$DEV:$PUB")
hr() { printf '\n==== %s ====\n' "$*"; }

hr "1. root waits for a ticket, children pass"
"${W[@]}" --ttl 30s -- sh -c 'bash -c "ls -d /tmp; (sleep 0.2; ls -d /etc) & wait; python3 -c \"import os; os.system(\\\"echo from-python-child\\\")\""' &
WPID=$!
for _ in $(seq 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
sleep 1
echo "--- status before signing (exec is held in the kernel):"
./wardend status --socket "$SOCK" | grep -E '"pending"|"roots"'
echo "--- device signing:"
./wardend approve --socket "$SOCK" --key-file "$KEYF" --count 1 --timeout 10s
wait $WPID

hr "2. deny_always: rm -rf / and dd of=/dev/null are cut without questions"
( sleep 0.5; ./wardend approve --socket "$SOCK" --key-file "$KEYF" --count 1 --timeout 10s >/dev/null ) &
"${W[@]}" --ttl 10s --quiet -- sh -c 'rm -rf / 2>&1; echo "rm rc=$?"; bash -c "dd if=/dev/zero of=/dev/null count=1 2>&1; echo dd rc=\$?"'
wait

hr "3. setsid inside an approved root = new root (approving only the first)"
( sleep 0.5; ./wardend approve --socket "$SOCK" --key-file "$KEYF" --match '^bash' --count 1 --timeout 10s >/dev/null ) &
"${W[@]}" --ttl 2s --quiet -- sh -c 'bash -c "setsid nohup ls -d /tmp 2>&1 & wait"'
wait

hr "4. TOCTOU: evil multi-threaded process, stop-verify"
cc -O1 -pthread -o "$D/evil" bench/evil_argv.c || exit 1
printf '{"service_allow":[{"id":"demo-evil","path":"^%s$"}]}\n' "$D/evil" > "$D/policy.json"
( sleep 0.3; ./wardend approve --socket "$SOCK" --key-file "$KEYF" --match '^/bin/echo SAFE-ARG$' --count 0 --timeout 8s >/dev/null ) &  # others (swapped at read time) are refused by TTL
"${W[@]}" --ttl 300ms --quiet --policy "$D/policy.json" --toctou-roots stop -- \
  bash -c "for i in \$(eval echo {1..40}); do $D/evil 2>/dev/null; done" > "$D/evil.out" 2>&1
wait
echo "echo printed: $(sort "$D/evil.out" | uniq -c | tr '\n' ' ')"
python3 - "$D/journal.jsonl" <<'EOF'
import json, sys
kills = approved = 0
for l in open(sys.argv[1]):
    e = json.loads(l)
    if e["kind"] == "toctou_kill": kills += 1
    if e["kind"] == "exec" and e["data"].get("class") == "root" and e["data"]["argv"][:1] == ["/bin/echo"] and e["data"]["decision"] == "allow": approved += 1
print(f"approved echo SAFE-ARG: {approved}, of which killed by stop-verify (kernel copied wrong argv): {kills}")
EOF

hr "5. journal"
python3 - "$D/journal.jsonl" <<'EOF'
import json, sys, collections
c = collections.Counter()
for l in open(sys.argv[1]):
    e = json.loads(l)
    c[e["kind"] + (":" + e["data"]["class"] + ":" + e["data"]["decision"] if e["kind"] == "exec" else "")] += 1
for k, v in sorted(c.items()): print(f"  {v:4d}  {k}")
EOF
KEY=$(python3 -c "import json,sys; print(json.loads(open(sys.argv[1]).readline())['data']['journalKey'])" "$D/journal.jsonl")
./wardend verify-journal --pubkey "$KEY" "$D/journal.jsonl"
echo "--- tampering one entry:"
sed '5s/"allow"/"deny"/' "$D/journal.jsonl" > "$D/tampered.jsonl"
./wardend verify-journal --pubkey "$KEY" "$D/tampered.jsonl"
exit 0
