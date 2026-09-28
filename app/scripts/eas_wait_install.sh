#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Waits for an EAS build by id, downloads the APK and installs it via adb. Log: /tmp/eas_wait.log
BID="$1"
cd "$(dirname "$0")/.." || exit 1
. scripts/script-env.sh
APK_DIR="${WARDENCLAW_APK_DIR:-$PWD/build/apk}"
OUT="$APK_DIR/wardenclaw-$BID.apk"
export EXPO_TOKEN="${EXPO_TOKEN:-$(tr -d '\n' < "${WARDENCLAW_EXPO_TOKEN_FILE:-$HOME/.config/wardenclaw/expo_token}")}"
mkdir -p "$APK_DIR"
for i in $(seq 1 120); do
  J=$(npx -y eas-cli@latest build:view "$BID" --json 2>/dev/null)
  ST=$(echo "$J" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
  echo "$(date +%T) status=$ST"
  case "$ST" in
    FINISHED)
      URL=$(echo "$J" | python3 -c "import json,sys; print(json.load(sys.stdin)['artifacts']['buildUrl'])")
      curl -sL -o "$OUT" "$URL" && ls -la "$OUT"
      adb install -r "$OUT"; echo "install_exit=$?"
      echo "DONE"; exit 0;;
    ERRORED|CANCELED) echo "$J" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('error'))"; echo "FAILED"; exit 1;;
  esac
  sleep 60
done
echo "TIMEOUT"
