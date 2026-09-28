#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Starts an EAS Android build without waiting and prints its id. The token is read internally, never printed.
# Usage: scripts/eas_build.sh [profile]   (default: bench, arm64-v8a only, two llama.rn variants)
# Next step: scripts/eas_wait_install.sh <id>  (waits, downloads the APK to $WARDENCLAW_APK_DIR and installs via adb)
# Token: $EXPO_TOKEN, or the file $WARDENCLAW_EXPO_TOKEN_FILE (default: ~/.config/wardenclaw/expo_token).
# production and preview are refused if any non-empty EXPO_PUBLIC_WARDENCLAW_* is found (check-build-env.mjs).
set -euo pipefail
PROFILE="${1:-bench}"
cd "$(dirname "$0")/.."
node scripts/check-build-env.mjs "$PROFILE"
. scripts/script-env.sh
export EXPO_TOKEN
EXPO_TOKEN="${EXPO_TOKEN:-$(tr -d '\n' < "${WARDENCLAW_EXPO_TOKEN_FILE:-$HOME/.config/wardenclaw/expo_token}")}"
npx -y eas-cli@latest build --platform android --profile "$PROFILE" --non-interactive --no-wait --json > /tmp/eas_build_start.json 2>/tmp/eas_build_start.err || {
  echo "eas build failed:" >&2; tail -30 /tmp/eas_build_start.err >&2; exit 1; }
python3 -c "import json; d=json.load(open('/tmp/eas_build_start.json')); d=d[0] if isinstance(d,list) else d; print(d['id'])"
