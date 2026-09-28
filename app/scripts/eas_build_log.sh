#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Fetches the brotli-compressed logs of a failed EAS build and prints them as plain text.
# Usage: scripts/eas_build_log.sh <build-id> [out-file]
set -euo pipefail

BUILD_ID="${1:?build id required}"
OUT="${2:-/tmp/eas_build_log.txt}"
cd "$(dirname "$0")/.."
. scripts/script-env.sh

export EXPO_TOKEN
EXPO_TOKEN="${EXPO_TOKEN:-$(tr -d '\n' < "${WARDENCLAW_EXPO_TOKEN_FILE:-$HOME/.config/wardenclaw/expo_token}")}"

# build:view does not support --non-interactive, only --json
npx eas-cli build:view "$BUILD_ID" --json > /tmp/eas_build_view.json 2>/tmp/eas_build_view.err || {
  echo "build:view failed:" >&2; cat /tmp/eas_build_view.err >&2; exit 1; }

node -e '
const fs = require("fs");
const zlib = require("zlib");
const https = require("https");
const v = JSON.parse(fs.readFileSync("/tmp/eas_build_view.json", "utf8"));
const b = Array.isArray(v) ? v[0] : v;
const logs = b.logFiles || [];
console.error("status=" + b.status + " logFiles=" + logs.length);
if (!logs.length) { console.error("no logFiles"); process.exit(2); }
const url = logs[0];
https.get(url, res => {
  const chunks = [];
  res.on("data", c => chunks.push(c));
  res.on("end", () => {
    const raw = Buffer.concat(chunks);
    let text;
    try { text = zlib.brotliDecompressSync(raw).toString("utf8"); }
    catch (e) {
      try { text = zlib.gunzipSync(raw).toString("utf8"); }
      catch (e2) { text = raw.toString("utf8"); }
    }
    fs.writeFileSync(process.argv[1], text);
    console.error("written " + text.length + " chars to " + process.argv[1]);
  });
}).on("error", e => { console.error(e.message); process.exit(3); });
' "$OUT"

echo "=== What went wrong / compilation errors ==="
grep -nE '^e: |What went wrong|FAILURE:|error:|Execution failed' "$OUT" | head -40 || true
