#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Local Android builds (macOS or Linux). Nothing is built on EAS servers.
#
#   scripts/local/android.sh eas [bench|preview|production]
#       eas build --local. Signed with the keystore stored in EAS (same key as the cloud builds,
#       so it installs over them). bench (default): APK, arm64-v8a only, fastest.
#       preview: APK, all ABIs. production: AAB for Google Play.
#   scripts/local/android.sh gradle [apk|aab]
#       No EAS at all: expo prebuild + ./gradlew assembleRelease / bundleRelease, signed with a
#       local upload keystore (see "keystore" below). For forks and offline builds.
#       WC_ABIS=arm64-v8a limits the ABIs (much faster); WC_VERSION_CODE overrides versionCode.
#   scripts/local/android.sh keystore
#       Creates a local upload keystore in ~/.config/wardenclaw/ (outside the repo) for "gradle".
#   scripts/local/android.sh install [apk]
#       adb install -r of the given or newest APK in WC_OUT_DIR. ANDROID_SERIAL picks the phone.
# Environment: WC_OUT_DIR, WC_STAGE_DIR, WC_IN_PLACE (see lib.sh), EXPO_TOKEN (optional).
source "$(dirname "$0")/lib.sh"

CMD="${1:-eas}"
[ $# -gt 0 ] && shift

KEYSTORE_ENV="${WC_KEYSTORE_ENV:-$HOME/.config/wardenclaw/upload-keystore.env}"

need_android_sdk() {
  if [ -z "${ANDROID_HOME:-}" ]; then
    if [ -d "$HOME/Library/Android/sdk" ]; then export ANDROID_HOME="$HOME/Library/Android/sdk"
    else die "ANDROID_HOME is not set (scripts/local/doctor.sh android shows how to install the SDK)"; fi
  fi
  [ -d "$ANDROID_HOME" ] || die "ANDROID_HOME=$ANDROID_HOME does not exist"
  if [ -z "${JAVA_HOME:-}" ] && is_macos && /usr/libexec/java_home -v 17 >/dev/null 2>&1; then
    JAVA_HOME="$(/usr/libexec/java_home -v 17)"; export JAVA_HOME
  fi
}

find_adb() {
  if have adb; then echo adb
  elif [ -n "${ANDROID_HOME:-}" ] && [ -x "$ANDROID_HOME/platform-tools/adb" ]; then echo "$ANDROID_HOME/platform-tools/adb"
  else die "adb not found: install platform-tools (brew install --cask android-platform-tools)"; fi
}

# Adds a release signingConfig fed by Gradle properties (ORG_GRADLE_PROJECT_WC_UPLOAD_*),
# so passwords never land in a file inside the project. Applied to the freshly generated
# android/app/build.gradle; fails loudly if the Expo template changed shape.
patch_gradle() {
  local f="$WC_APP/android/app/build.gradle" vc="$1"
  [ -f "$f" ] || die "$f missing after prebuild"
  grep -q 'WC_UPLOAD_STORE_FILE' "$f" && return 0
  perl -0pi -e '
    s/(\n    buildTypes \{.*?\n        release \{\n(?:[ \t]*\/\/[^\n]*\n)*[ \t]*)signingConfig signingConfigs\.debug/$1signingConfig project.hasProperty("WC_UPLOAD_STORE_FILE") ? signingConfigs.release : signingConfigs.debug/s
      or die "release signingConfig not found\n";
    s/(\n    signingConfigs \{\n)/$1        release {\n            if (project.hasProperty("WC_UPLOAD_STORE_FILE")) {\n                storeFile file(WC_UPLOAD_STORE_FILE)\n                storePassword WC_UPLOAD_STORE_PASSWORD\n                keyAlias WC_UPLOAD_KEY_ALIAS\n                keyPassword WC_UPLOAD_KEY_PASSWORD\n            }\n        }\n/
      or die "signingConfigs block not found\n";
  ' "$f" || die "could not patch $f (Expo template changed?)"
  perl -pi -e "s/^(\\s*)versionCode \\d+\$/\${1}versionCode $vc/" "$f"
  grep -q "versionCode $vc" "$f" || die "could not set versionCode in $f"
  ok "release signing from ORG_GRADLE_PROJECT_WC_UPLOAD_*; versionCode $vc"
}

case "$CMD" in
  eas)
    PROFILE="${1:-bench}"
    case "$PROFILE" in production) EXT=aab ;; bench|preview|simulator) EXT=apk ;; *) die "unknown profile '$PROFILE' (bench | preview | production)";; esac
    need_android_sdk
    need_eas_login
    stage
    check_build_env "$PROFILE"
    OUT="$(out_dir)/wardenclaw-android-$PROFILE-$(stamp).$EXT"
    say "eas build --platform android --profile $PROFILE --local"
    (cd "$WC_APP" && eas_cli build --platform android --profile "$PROFILE" --local --non-interactive --output "$OUT")
    [ -f "$OUT" ] || die "build finished but $OUT is missing"
    say "artifact: $OUT"
    [ "$EXT" = apk ] && say "install: scripts/local/android.sh install '$OUT'"
    [ "$EXT" = aab ] && say "upload the .aab in Google Play Console (or: eas submit --platform android --path '$OUT')"
    ;;

  gradle)
    KIND="${1:-apk}"
    case "$KIND" in apk) TASK=assembleRelease; SRC_GLOB="app/build/outputs/apk/release/*.apk" ;;
                     aab) TASK=bundleRelease;   SRC_GLOB="app/build/outputs/bundle/release/*.aab" ;;
                     *) die "usage: $0 gradle [apk|aab]";; esac
    need_android_sdk
    if [ -f "$KEYSTORE_ENV" ]; then
      set -a
      # shellcheck disable=SC1090
      . "$KEYSTORE_ENV"
      set +a
    fi
    if [ -n "${WC_UPLOAD_KEYSTORE:-}" ]; then
      [ -f "$WC_UPLOAD_KEYSTORE" ] || die "WC_UPLOAD_KEYSTORE=$WC_UPLOAD_KEYSTORE does not exist"
      for v in WC_UPLOAD_KEY_ALIAS WC_UPLOAD_STORE_PASSWORD WC_UPLOAD_KEY_PASSWORD; do
        [ -n "${!v:-}" ] || die "$v is empty (set it in $KEYSTORE_ENV)"
      done
      export ORG_GRADLE_PROJECT_WC_UPLOAD_STORE_FILE="$WC_UPLOAD_KEYSTORE"
      export ORG_GRADLE_PROJECT_WC_UPLOAD_KEY_ALIAS="$WC_UPLOAD_KEY_ALIAS"
      export ORG_GRADLE_PROJECT_WC_UPLOAD_STORE_PASSWORD="$WC_UPLOAD_STORE_PASSWORD"
      export ORG_GRADLE_PROJECT_WC_UPLOAD_KEY_PASSWORD="$WC_UPLOAD_KEY_PASSWORD"
    elif [ "${WC_ALLOW_DEBUG_SIGNING:-0}" = "1" ]; then
      warn "no upload keystore: the release build is signed with the public debug key (testing only)"
    else
      die "no upload keystore. Create one with: $0 keystore
    (or set WC_ALLOW_DEBUG_SIGNING=1 for a throwaway test build)"
    fi
    stage
    check_build_env production # release APK/AAB for distribution: same rules as the production profile
    deps; prebuild android
    VC="${WC_VERSION_CODE:-$(git -C "$WC_SRC_ROOT" rev-list --count HEAD 2>/dev/null || echo 1)}"
    patch_gradle "$VC"
    GRADLE_ARGS=("$TASK" "--no-daemon")
    [ -n "${WC_ABIS:-}" ] && GRADLE_ARGS+=("-PreactNativeArchitectures=$WC_ABIS")
    say "./gradlew ${GRADLE_ARGS[*]}  (first run downloads Gradle and compiles the native code: 10-20 min)"
    (cd "$WC_APP/android" && ./gradlew "${GRADLE_ARGS[@]}")
    shopt -s nullglob
    # shellcheck disable=SC2206  # the glob is meant to expand
    FILES=("$WC_APP"/android/$SRC_GLOB)
    shopt -u nullglob
    [ "${#FILES[@]}" -gt 0 ] || die "no output matching android/$SRC_GLOB"
    OUT="$(out_dir)/wardenclaw-android-gradle-$(stamp).$KIND"
    cp "${FILES[0]}" "$OUT"
    say "artifact: $OUT"
    [ "$KIND" = apk ] && say "install: scripts/local/android.sh install '$OUT'"
    ;;

  keystore)
    have keytool || die "keytool not found (it comes with the JDK: brew install --cask zulu@17)"
    have openssl || die "openssl not found"
    DIR="$(dirname "$KEYSTORE_ENV")"
    KS="$DIR/upload.jks"
    if [ -f "$KEYSTORE_ENV" ] || [ -f "$KS" ]; then
      ok "keystore already exists: $KS ($KEYSTORE_ENV). Nothing to do."
      exit 0
    fi
    mkdir -p "$DIR"; chmod 700 "$DIR"
    PASS="$(openssl rand -hex 24)"
    say "creating $KS (RSA 4096, valid 30 years)"
    keytool -genkeypair -v -storetype PKCS12 -keystore "$KS" -alias upload -keyalg RSA -keysize 4096 \
      -validity 10950 -storepass "$PASS" -keypass "$PASS" -dname "CN=WardenClaw local build"
    umask 077
    cat > "$KEYSTORE_ENV" <<EOF
# Local Android upload keystore for scripts/local/android.sh gradle. Keep a backup: a lost key
# means installed apps cannot be updated (only reinstalled, which wipes the device key).
WC_UPLOAD_KEYSTORE=$KS
WC_UPLOAD_KEY_ALIAS=upload
WC_UPLOAD_STORE_PASSWORD=$PASS
WC_UPLOAD_KEY_PASSWORD=$PASS
EOF
    chmod 600 "$KS" "$KEYSTORE_ENV"
    ok "written $KEYSTORE_ENV. Back up both files somewhere safe."
    ;;

  install)
    APK="${1:-$(latest_artifact 'wardenclaw-android-*.apk')}"
    [ -n "$APK" ] && [ -f "$APK" ] || die "no .apk given and none found in $WC_OUT_DIR"
    case "$APK" in *.aab) die ".aab files cannot be installed directly; build an APK (eas bench/preview or gradle apk)";; esac
    ADB="$(find_adb)"
    DEVICES="$("$ADB" devices | awk 'NR>1 && $2=="device" {print $1}')"
    [ -n "$DEVICES" ] || die "no phone in 'adb devices' (USB debugging on? cable? authorize the computer on the phone)"
    if [ -z "${ANDROID_SERIAL:-}" ] && [ "$(printf '%s\n' "$DEVICES" | wc -l | tr -d ' ')" -gt 1 ]; then
      die "several devices connected, pick one: ANDROID_SERIAL=<serial> $0 install   ($(echo "$DEVICES" | tr '\n' ' '))"
    fi
    say "adb install -r $APK"
    if ! LOG="$("$ADB" install -r "$APK" 2>&1)"; then
      echo "$LOG" >&2
      if grep -q 'INSTALL_FAILED_UPDATE_INCOMPATIBLE' <<<"$LOG"; then
        die "the installed WardenClaw is signed with a different key (EAS vs local keystore).
    Uninstalling it deletes the device key and the journal: you would have to pair again.
    If that is fine: $ADB uninstall com.wardenclaw.app && $0 install '$APK'"
      fi
      die "adb install failed"
    fi
    ok "installed"
    ;;

  -h|--help|help)
    sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    die "unknown command '$CMD' (eas [profile] | gradle [apk|aab] | keystore | install [apk])"
    ;;
esac
