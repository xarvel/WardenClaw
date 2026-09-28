# SPDX-License-Identifier: GPL-3.0-or-later
# Shared helpers for app/scripts/local/*.sh. Sourced, not executed.
#
# Build location. By default the scripts do NOT build inside the checkout: they copy the
# monorepo (without node_modules, ios/, android/, build outputs) to a staging directory and
# build there. This keeps multi-gigabyte Pods, Gradle caches and macOS node_modules out of
# the checkout, which matters when the checkout is a synced folder (Resilio, Dropbox, iCloud).
#   WC_STAGE_DIR   staging directory       (default: ~/.cache/wardenclaw/stage)
#   WC_IN_PLACE=1  build in the checkout itself (plain git clones, CI)
#   WC_OUT_DIR     where artifacts go       (default: ~/WardenClaw-builds)

set -euo pipefail

if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLD=""; C_OFF=""
fi

say()  { printf '%s==>%s %s\n' "$C_BLD" "$C_OFF" "$*"; }
ok()   { printf '  %sok%s    %s\n' "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '  %swarn%s  %s\n' "$C_YEL" "$C_OFF" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Paths of the checkout this script lives in.
WC_SRC_APP="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WC_SRC_ROOT="$(cd "$WC_SRC_APP/.." && pwd)"
WC_OUT_DIR="${WC_OUT_DIR:-$HOME/WardenClaw-builds}"
WC_STAGE_DIR="${WC_STAGE_DIR:-$HOME/.cache/wardenclaw/stage}"

is_macos() { [ "$(uname -s)" = "Darwin" ]; }
need_macos() { is_macos || die "this step needs macOS with Xcode (running on $(uname -s))"; }

# EXPO_PUBLIC_* values are baked into the JS bundle. A distributable profile (production, preview)
# must not carry personal EXPO_PUBLIC_WARDENCLAW_* values from eas.json, the shell or env files
# next to the build (scripts/check-build-env.mjs prints names, never values). Call after stage.
check_build_env() {
  node "$WC_SRC_APP/scripts/check-build-env.mjs" "$1" --local --app-dir "$WC_APP" \
    || die "personal EXPO_PUBLIC_WARDENCLAW_* values in a '$1' build (see above)"
}

# eas-cli: a global install if present, otherwise the latest one through npx.
eas_cli() {
  if have eas; then eas "$@"; else npx -y eas-cli@latest "$@"; fi
}

need_eas_login() {
  local who
  if who="$(eas_cli whoami 2>/dev/null)" && [ -n "$who" ]; then
    ok "EAS account: $who"
  else
    die "not logged in to EAS. Run once: eas login   (or export EXPO_TOKEN)"
  fi
}

# Copies the checkout to WC_STAGE_DIR (or uses it in place) and sets WC_APP / WC_ROOT.
# Idempotent: rsync only transfers what changed; generated dirs in the stage are kept
# (excluded paths are never deleted on the receiving side). Local env files (app/.env,
# app/.env.local, ...) are never staged: Metro in the stage must not see personal values.
stage() {
  if [ "${WC_IN_PLACE:-0}" = "1" ]; then
    WC_ROOT="$WC_SRC_ROOT"; WC_APP="$WC_SRC_APP"
    say "building in place: $WC_APP"
    return
  fi
  have rsync || die "rsync not found"
  mkdir -p "$WC_STAGE_DIR"
  say "staging $WC_SRC_ROOT -> $WC_STAGE_DIR"
  rsync -a --delete \
    --exclude '/app/node_modules/' --exclude '/app/ios/' --exclude '/app/android/' \
    --exclude '/app/build/' --exclude '/app/.expo/' --exclude '/app/.test-build*/' \
    --exclude 'node_modules/' --exclude '.sync/' --exclude '.DS_Store' \
    --exclude '*.!sync' --exclude '/app/targets/.build/' --exclude '/app/targets/.swiftpm/' \
    --include '/app/.env.example' --exclude '/app/.env' --exclude '/app/.env.*' \
    "$WC_SRC_ROOT/" "$WC_STAGE_DIR/"
  # copies left in the stage by older versions of this script
  find "$WC_STAGE_DIR/app" -maxdepth 1 -name '.env*' ! -name '.env.example' -type f -delete
  WC_ROOT="$WC_STAGE_DIR"; WC_APP="$WC_STAGE_DIR/app"
  git -C "$WC_ROOT" rev-parse --git-dir >/dev/null 2>&1 \
    || die "$WC_ROOT is not a git repository (EAS needs git). Is .git missing in the checkout?"
}

# npm ci in $WC_APP when package-lock.json changed since the last install.
deps() {
  local lock_hash marker
  lock_hash="$(shasum -a 256 "$WC_APP/package-lock.json" 2>/dev/null | cut -d' ' -f1 || sha256sum "$WC_APP/package-lock.json" | cut -d' ' -f1)"
  marker="$WC_APP/node_modules/.wc-lock-sha256"
  if [ -f "$marker" ] && [ "$(cat "$marker")" = "$lock_hash" ]; then
    ok "node_modules up to date"
    return
  fi
  say "npm ci (first run downloads llama.rn native artifacts, a few hundred MB)"
  (cd "$WC_APP" && npm ci --no-audit --no-fund)
  echo "$lock_hash" > "$marker"
}

# CNG: ios/ and android/ are generated from app.json and config plugins, never committed.
prebuild() {
  local platform="$1"
  say "expo prebuild --platform $platform --clean"
  (cd "$WC_APP" && CI=1 npx expo prebuild --platform "$platform" --clean --no-install)
}

stamp() { date +%Y%m%d-%H%M%S; }

out_dir() { mkdir -p "$WC_OUT_DIR"; printf '%s' "$WC_OUT_DIR"; }

# Newest file in WC_OUT_DIR matching a glob, or empty.
latest_artifact() {
  local pattern="$1" f newest=""
  shopt -s nullglob
  for f in "$WC_OUT_DIR"/$pattern; do
    if [ -z "$newest" ] || [ "$f" -nt "$newest" ]; then newest="$f"; fi
  done
  shopt -u nullglob
  printf '%s' "$newest"
}
