#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Checks the machine for local WardenClaw builds and prints what to install.
# Usage: scripts/local/doctor.sh [ios|android|all]   (default: all on macOS, android elsewhere)
# Exit code 0 = everything required for the chosen platforms is present.
source "$(dirname "$0")/lib.sh"

WANT="${1:-}"
if [ -z "$WANT" ]; then is_macos && WANT=all || WANT=android; fi
case "$WANT" in ios|android|all) ;; *) die "usage: $0 [ios|android|all]";; esac
want_ios()     { [ "$WANT" = ios ] || [ "$WANT" = all ]; }
want_android() { [ "$WANT" = android ] || [ "$WANT" = all ]; }

# Versions required by React Native 0.86 (node_modules/react-native/gradle/libs.versions.toml)
# and llama.rn 0.13 (prebuilt native libraries, CMake from the Android SDK).
ANDROID_PLATFORM="platforms;android-36"
ANDROID_BUILD_TOOLS="build-tools;36.0.0"
ANDROID_NDK_VER="27.1.12297006"
ANDROID_CMAKE_VER="3.22.1"
MIN_XCODE_MAJOR=16
MIN_FREE_GB=30

MISSING=0
TODO=()
miss() { MISSING=1; printf '  %smissing%s %s\n' "$C_RED" "$C_OFF" "$1"; [ -n "${2:-}" ] && TODO+=("$2"); return 0; }
opt()  { printf '  %soptional%s %s\n' "$C_YEL" "$C_OFF" "$1"; [ -n "${2:-}" ] && TODO+=("$2  # optional"); return 0; }

say "WardenClaw build doctor ($WANT) on $(uname -s) $(uname -m)"

if is_macos && ! have brew; then
  # shellcheck disable=SC2016  # printed for the user to run, not expanded here
  miss "Homebrew" '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
fi

# --- common -----------------------------------------------------------------
say "Common"
NVMRC="$(tr -d ' v\n' 2>/dev/null < "$WC_SRC_APP/.nvmrc" || echo 24)"
if have node; then
  NODE_V="$(node -p 'process.versions.node')"
  NODE_MAJOR="${NODE_V%%.*}"
  # react-native 0.86 engines: ^20.19.4 || ^22.13.0 || ^24.3.0 || >= 25
  if node -e '
    const [a,b]=process.versions.node.split(".").map(Number);
    const okv=(a===20&&b>=19)||(a===22&&b>=13)||(a===24&&b>=3)||a>=25;
    process.exit(okv?0:1)'; then
    ok "node $NODE_V"
    [ "$NODE_MAJOR" = "${NVMRC%%.*}" ] || warn "app/.nvmrc says $NVMRC; $NODE_V works but is not the tested major"
  else
    miss "node $NODE_V is too old for React Native 0.86 (need 20.19.4+, 22.13+ or 24.3+)" "brew install node@$NVMRC   # or: nvm install $NVMRC"
  fi
else
  miss "node" "brew install node@$NVMRC   # or: nvm install $NVMRC"
fi
have npm && ok "npm $(npm -v)" || true
if have git; then ok "git $(git --version | awk '{print $3}')"; else miss "git" "xcode-select --install"; fi
if have rsync; then ok "rsync"; else miss "rsync" "brew install rsync"; fi

if have eas; then
  ok "eas-cli $(eas --version 2>/dev/null | awk '{print $1}')"
else
  opt "eas-cli not installed globally (scripts fall back to npx eas-cli@latest)" "npm install -g eas-cli"
fi
if have watchman; then ok "watchman"; else opt "watchman (faster Metro file watching)" "brew install watchman"; fi

FREE_GB="$(df -Pk "$HOME" | awk 'NR==2 {print int($4/1024/1024)}')"
if [ "$FREE_GB" -ge "$MIN_FREE_GB" ]; then ok "free disk in \$HOME: ${FREE_GB} GB"
else miss "only ${FREE_GB} GB free in \$HOME; a first iOS + Android build needs about ${MIN_FREE_GB} GB (Xcode DerivedData, Pods, Gradle, NDK)"; fi

if [ -f "$WC_SRC_APP/.env" ]; then ok "app/.env present"
else miss "app/.env" "cp '$WC_SRC_APP/.env.example' '$WC_SRC_APP/.env'"; fi

# --- iOS --------------------------------------------------------------------
if want_ios; then
  say "iOS"
  if ! is_macos; then
    miss "iOS builds need macOS with Xcode"
  else
    XCPATH="$(xcode-select -p 2>/dev/null || true)"
    if [ -z "$XCPATH" ]; then
      miss "Xcode command line tools" "xcode-select --install"
    elif [[ "$XCPATH" == *CommandLineTools* ]]; then
      miss "xcode-select points to Command Line Tools, not Xcode" "sudo xcode-select -s /Applications/Xcode.app/Contents/Developer"
    fi
    if have xcodebuild && xcodebuild -version >/dev/null 2>&1; then
      XCV="$(xcodebuild -version | awk 'NR==1 {print $2}')"
      if [ "${XCV%%.*}" -ge "$MIN_XCODE_MAJOR" ]; then ok "Xcode $XCV ($XCPATH)"
      else miss "Xcode $XCV is too old (need $MIN_XCODE_MAJOR+)" "install the current Xcode from the App Store"; fi
      if xcodebuild -license check >/dev/null 2>&1; then ok "Xcode license accepted"
      else miss "Xcode license not accepted" "sudo xcodebuild -license accept"; fi
      if xcrun simctl list runtimes 2>/dev/null | grep -q '^iOS'; then ok "iOS simulator runtime"
      else opt "no iOS simulator runtime (only needed for ios.sh sim)" "xcodebuild -downloadPlatform iOS"; fi
      # The Apple Watch app (targets/watch) is embedded in every iOS build: without the watchOS
      # platform (an optional download since Xcode 15) the iOS build itself fails.
      if xcodebuild -showsdks 2>/dev/null | grep -q -- '-sdk watchos'; then ok "watchOS SDK (Apple Watch app)"
      else miss "watchOS platform in Xcode (the Apple Watch app is built into the iOS app)" "xcodebuild -downloadPlatform watchOS"; fi
      if xcrun simctl list runtimes 2>/dev/null | grep -q '^watchOS'; then ok "watchOS simulator runtime"
      else opt "no watchOS simulator runtime (only needed for ios.sh watch-sim)" "xcodebuild -downloadPlatform watchOS"; fi
    else
      miss "Xcode" "install Xcode from the App Store, open it once, then: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer"
    fi
    if have pod; then ok "CocoaPods $(pod --version)"; else miss "CocoaPods" "brew install cocoapods"; fi
    # swift test for the watch app's protocol code (app/targets/Package.swift); comes with Xcode
    if have swift; then ok "swift $(swift --version 2>/dev/null | sed -n 's/.*Swift version \([0-9.]*\).*/\1/p' | head -1) (ios.sh swift-test)"
    else opt "swift (for ios.sh swift-test)" "comes with Xcode: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer"; fi
    # eas build --local for iOS runs fastlane (gym) to archive and sign.
    if have fastlane; then ok "fastlane $(fastlane --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    else miss "fastlane (eas build --local uses it for iOS)" "brew install fastlane"; fi
    if [ "$(uname -m)" = "arm64" ] && ! /usr/bin/pgrep -q oahd 2>/dev/null; then
      opt "Rosetta 2 (a few older pods and tools still expect it)" "softwareupdate --install-rosetta --agree-to-license"
    fi
  fi
fi

# --- Android ----------------------------------------------------------------
if want_android; then
  say "Android"
  JAVA_OK=0
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then JAVA_BIN="$JAVA_HOME/bin/java"
  elif have java; then JAVA_BIN="$(command -v java)"; else JAVA_BIN=""; fi
  if [ -n "$JAVA_BIN" ] && "$JAVA_BIN" -version >/dev/null 2>&1; then
    JV="$("$JAVA_BIN" -version 2>&1 | awk -F'"' '/version/ {print $2}')"
    JMAJ="${JV%%.*}"
    if [ "$JMAJ" = "17" ]; then ok "JDK $JV"; JAVA_OK=1
    elif [ "$JMAJ" -ge 17 ] 2>/dev/null; then warn "JDK $JV found; React Native is tested with JDK 17 (newer JDKs usually work with Gradle 9)"; JAVA_OK=1
    fi
  fi
  if [ "$JAVA_OK" = 0 ]; then
    if is_macos; then
      miss "JDK 17" "brew install --cask zulu@17 && export JAVA_HOME=\$(/usr/libexec/java_home -v 17)"
    else
      miss "JDK 17" "install openjdk-17-jdk and set JAVA_HOME"
    fi
  elif [ -z "${JAVA_HOME:-}" ]; then
    warn "JAVA_HOME is not set (Gradle finds java on PATH, EAS local builds prefer JAVA_HOME)"
    is_macos && TODO+=("echo 'export JAVA_HOME=\$(/usr/libexec/java_home -v 17)' >> ~/.zprofile")
  fi

  SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  if [ -z "$SDK" ] && [ -d "$HOME/Library/Android/sdk" ]; then SDK="$HOME/Library/Android/sdk"; warn "ANDROID_HOME not set, using $SDK"; fi
  if [ -z "$SDK" ] || [ ! -d "$SDK" ]; then
    if is_macos; then
      miss "Android SDK (ANDROID_HOME)" "brew install --cask android-commandlinetools && echo 'export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools' >> ~/.zprofile"
    else
      miss "Android SDK (ANDROID_HOME)" "install the Android command line tools and set ANDROID_HOME"
    fi
  else
    [ -n "${ANDROID_HOME:-}" ] && ok "ANDROID_HOME=$ANDROID_HOME"
    [ -z "${ANDROID_HOME:-}" ] && TODO+=("echo 'export ANDROID_HOME=$SDK' >> ~/.zprofile")
    SDKMANAGER=""
    for c in "$SDK/cmdline-tools/latest/bin/sdkmanager" "$SDK"/cmdline-tools/*/bin/sdkmanager "$(command -v sdkmanager || true)"; do
      [ -n "$c" ] && [ -x "$c" ] && { SDKMANAGER="$c"; break; }
    done
    PKGS=()
    [ -d "$SDK/platforms/android-36" ]                 && ok "$ANDROID_PLATFORM"   || PKGS+=("$ANDROID_PLATFORM")
    [ -d "$SDK/build-tools/36.0.0" ]                   && ok "$ANDROID_BUILD_TOOLS" || PKGS+=("$ANDROID_BUILD_TOOLS")
    [ -d "$SDK/ndk/$ANDROID_NDK_VER" ]                 && ok "ndk;$ANDROID_NDK_VER" || PKGS+=("ndk;$ANDROID_NDK_VER")
    [ -d "$SDK/cmake/$ANDROID_CMAKE_VER" ]             && ok "cmake;$ANDROID_CMAKE_VER" || PKGS+=("cmake;$ANDROID_CMAKE_VER")
    [ -x "$SDK/platform-tools/adb" ]                   && ok "platform-tools (adb)" || PKGS+=("platform-tools")
    if [ "${#PKGS[@]}" -gt 0 ]; then
      if [ -z "$SDKMANAGER" ]; then
        miss "sdkmanager (Android cmdline-tools)" "brew install --cask android-commandlinetools"
        SDKMANAGER="sdkmanager"
      fi
      miss "Android SDK packages: ${PKGS[*]}" "yes | $SDKMANAGER --sdk_root=\"$SDK\" --licenses && $SDKMANAGER --sdk_root=\"$SDK\" $(printf '"%s" ' "${PKGS[@]}")"
    fi
  fi
  have keytool && ok "keytool" || true
  if ! have adb && [ -n "$SDK" ] && [ ! -x "$SDK/platform-tools/adb" ]; then
    opt "adb (to install the APK on a phone)" "brew install --cask android-platform-tools"
  fi
fi

echo
if [ "${#TODO[@]}" -gt 0 ]; then
  say "To install:"
  printf '  %s\n' "${TODO[@]}"
  echo
fi
if [ "$MISSING" = 0 ]; then
  say "${C_GRN}ready${C_OFF} for: $WANT"
else
  say "${C_RED}not ready${C_OFF}: fix the missing items above and run doctor again"
  exit 1
fi
