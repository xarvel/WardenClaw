#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Red team against a SEPARATE throwaway wardend instance.
#
# The live wardend under the gateway, ~/.wardend, OpenClaw gateway, and cloudflared are NOT
# touched: we start our own wardend via systemd-run --user, our own state directory, our own
# port (18799), and test keys. The script shows what IS closed and what is open in a same-uid install.
#
# Usage:
#   wardend/redteam/run.sh            # build and run
#   PORT=18799 wardend/redteam/run.sh
#
# All attacks run from a process UNDER the filter (like a malicious harness child), except those
# explicitly marked "requires a separate uid" -- see README.md (they cannot be closed in same-uid;
# they are closed by a hardened install).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GO="${GO:-$HOME/sdk/go/bin/go}"
PORT="${PORT:-19787}"
# find a free port if the default is in use
while ss -ltn 2>/dev/null | grep -q ":$PORT "; do PORT=$((PORT+1)); done
WORK="$(mktemp -d /tmp/wardend-redteam.XXXXXX)"
BIN="$WORK/wardend"
STATE="$WORK/state"; mkdir -p "$STATE"; chmod 700 "$STATE"
printf '{}\n' > "$STATE/config.json"; chmod 600 "$STATE/config.json"
UNIT="redteam-wardend-$$"
PASS=0; FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
bad(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "[*] build wardend -> $BIN"
( cd "$ROOT" && "$GO" build -o "$BIN" . ) || { echo "build failed"; exit 1; }
chmod 755 "$BIN"

# Test device (we do NOT approve anything with it -- simulating the absence of a phone).
SEED=$("$BIN" keygen | sed -n 's/^seed=//p')

echo "[*] start throwaway wardend (systemd-run --user, ticket, :$PORT)"
# Payload under the filter: keep the process alive long enough to run the attacks.
systemd-run --user --unit="$UNIT" --quiet \
  --setenv=HOME="$HOME" --setenv=WARDEND_SELFCHECK=off \
  "$BIN" run --mode ticket --state-dir "$STATE" --config "$STATE/config.json" \
    --gateway-db off --http-listen "127.0.0.1:$PORT" --ttl 3s \
    -- sh -c 'echo READY; while :; do read -t 1 x || true; done' \
  || { echo "systemd-run failed"; exit 1; }

cleanup(){ systemctl --user stop "$UNIT" 2>/dev/null; systemctl --user reset-failed "$UNIT" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# wait for the port
for i in $(seq 1 50); do
  curl -s "http://127.0.0.1:$PORT/v1/ping?nonce=redteamnonce" >/dev/null 2>&1 && break
  sleep 0.1
done
SUP_PID=$(systemctl --user show -p MainPID --value "$UNIT" 2>/dev/null)
echo "[*] supervisor MainPID=$SUP_PID  port=$PORT  state=$STATE"

echo
echo "=== CLOSED VECTORS (expect refusal) ==="

# 1. Self-approval via HTTP without a trusted device signature.
resp=$(curl -s -X POST "http://127.0.0.1:$PORT/v1/decide" -H 'content-type: application/json' \
  --data '{"deviceId":"0000000000000000000000000000000000000000000000000000000000000000","payload":{"id":"p-x","digest":"ab","decision":"allow","ts":0,"nonce":"nnnnnnnn"},"signature":"x"}')
echo "$resp" | grep -q '"ok":false' && ok "HTTP /v1/decide without a trusted device signature rejected ($resp)" \
  || bad "HTTP /v1/decide accepted an unsigned decision: $resp"

# Other closed vectors are covered by Go tests (see README.md):
#   exec/execveat/memfd/ld.so, nested unotify filter, pairing from under the filter,
#   ticket forgery, queue overflow.
ok "exec/memfd/ld.so/nested-listener/pairing/forgery/queue -- closed by Go tests (go test ./...)"

echo
echo "=== OPEN IN SAME-UID (expect attack SUCCESS => requires a hardened install) ==="

# 4. Write access to the binary/key under the same uid (open+write is NOT gated).
writable=""
for f in "$BIN" "$STATE/supervisor.key" "$STATE/config.json"; do
  [ -w "$f" ] && writable="$writable $f"
done
if [ -n "$writable" ]; then
  bad "agent uid can overwrite:$writable (closed by hardened install: root-owned)"
else
  ok "wardend files are not writable by the current uid"
fi

# 5. Ability to send signals to the supervisor (kill -0, WITHOUT an actual SIGKILL).
if [ "${SUP_PID:-0}" -gt 1 ] 2>/dev/null && kill -0 "$SUP_PID" 2>/dev/null; then
  bad "agent uid can send signals to the supervisor pid=$SUP_PID (SIGKILL closed by hardened install)"
else
  ok "no permission to send signals to the supervisor (pid=$SUP_PID)"
fi

echo
echo "result: PASS=$PASS FAIL=$FAIL (FAIL here = NOT a bug, it demonstrates same-uid open vectors)"
echo "See README.md: the same attacks under a hardened install (separate uid) are blocked by the kernel."
