#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Local iOS builds on macOS. Nothing is built on EAS servers, so no build credits are used.
#
#   scripts/local/ios.sh [build]       App Store / TestFlight .ipa: eas build --local, profile production.
#                                      Signing comes from EAS (set up once with: eas credentials --platform ios).
#   scripts/local/ios.sh sim           Simulator .app without Apple signing (eas build --local, profile simulator),
#                                      installed into the booted simulator if there is one.
#   scripts/local/ios.sh sim-xcode     Same without EAS at all: expo prebuild + pod install + xcodebuild.
#   scripts/local/ios.sh xcode         Generate ios/ in the stage and open the workspace in Xcode
#                                      (fully local signing with your own team, for forks).
#   scripts/local/ios.sh submit [ipa]  Upload an .ipa to TestFlight (newest in WC_OUT_DIR by default).
#                                      With ASC_KEY_ID, ASC_ISSUER_ID and ASC_KEY_PATH set: xcrun altool,
#                                      otherwise eas submit (free, no build credits).
#   scripts/local/ios.sh watch-sim     Only the Apple Watch app (targets/watch), for the watchOS simulator,
#                                      installed into a booted watch simulator. No signing, no Pods.
#   scripts/local/ios.sh swift-test    swift test of the watch app's protocol code against protocol/vectors.
# Every iOS build also builds the Apple Watch app embedded in it (needs the watchOS platform in Xcode).
# Environment: WC_OUT_DIR, WC_STAGE_DIR, WC_IN_PLACE (see lib.sh), EXPO_TOKEN (optional).
source "$(dirname "$0")/lib.sh"

CMD="${1:-build}"
[ $# -gt 0 ] && shift

build_eas() {
  local profile="$1" ext="$2" out
  need_macos
  need_eas_login
  have pod || die "CocoaPods missing: brew install cocoapods   (scripts/local/doctor.sh ios lists everything)"
  have fastlane || die "fastlane missing: brew install fastlane   (eas build --local uses it for iOS)"
  stage
  check_build_env "$profile"
  out="$(out_dir)/wardenclaw-ios-$profile-$(stamp).$ext"
  say "eas build --platform ios --profile $profile --local"
  say "the first build takes 15-30 min (Pods, React Native and llama.rn JSI from source); later ones are faster"
  (cd "$WC_APP" && eas_cli build --platform ios --profile "$profile" --local --output "$out")
  [ -f "$out" ] || die "build finished but $out is missing"
  say "artifact: $out"
  LAST_OUT="$out"
}

install_sim_app() {
  local tarball="$1" dir app
  dir="${tarball%.tar.gz}"
  rm -rf "$dir"; mkdir -p "$dir"
  tar -xzf "$tarball" -C "$dir"
  app="$(find "$dir" -maxdepth 3 -name '*.app' -type d | head -1)"
  [ -n "$app" ] || die "no .app inside $tarball"
  say "simulator app: $app"
  if xcrun simctl list devices booted 2>/dev/null | grep -q Booted; then
    xcrun simctl install booted "$app"
    xcrun simctl launch booted com.wardenclaw.app >/dev/null || true
    ok "installed and launched in the booted simulator"
  else
    warn "no booted simulator: open Simulator.app, then: xcrun simctl install booted '$app'"
  fi
}

case "$CMD" in
  build)
    build_eas production ipa
    echo
    say "next: scripts/local/ios.sh submit '$LAST_OUT'"
    ;;

  sim)
    build_eas simulator tar.gz
    install_sim_app "$LAST_OUT"
    ;;

  sim-xcode)
    need_macos
    have pod || die "CocoaPods missing: brew install cocoapods"
    stage; deps; prebuild ios
    say "pod install"
    (cd "$WC_APP/ios" && pod install)
    DERIVED="$WC_APP/build/ios-sim"
    say "xcodebuild (Release, iphonesimulator, no code signing)"
    (cd "$WC_APP/ios" && xcodebuild \
      -workspace WardenClaw.xcworkspace -scheme WardenClaw -configuration Release \
      -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
      -derivedDataPath "$DERIVED" CODE_SIGNING_ALLOWED=NO build)
    APP="$DERIVED/Build/Products/Release-iphonesimulator/WardenClaw.app"
    [ -d "$APP" ] || die "no $APP after xcodebuild"
    TGZ="$(out_dir)/wardenclaw-ios-sim-xcode-$(stamp).tar.gz"
    tar -czf "$TGZ" -C "$(dirname "$APP")" WardenClaw.app
    say "artifact: $TGZ"
    install_sim_app "$TGZ"
    ;;

  xcode)
    need_macos
    have pod || die "CocoaPods missing: brew install cocoapods"
    stage; deps; prebuild ios
    (cd "$WC_APP/ios" && pod install)
    say "opening $WC_APP/ios/WardenClaw.xcworkspace"
    say "in Xcode: target WardenClaw > Signing & Capabilities > pick your Team (change the bundle id if com.wardenclaw.app is taken), then Product > Archive"
    open "$WC_APP/ios/WardenClaw.xcworkspace"
    ;;

  submit)
    need_macos
    IPA="${1:-$(latest_artifact 'wardenclaw-ios-production-*.ipa')}"
    [ -n "$IPA" ] && [ -f "$IPA" ] || die "no .ipa given and none found in $WC_OUT_DIR (build one: scripts/local/ios.sh build)"
    say "uploading $IPA"
    if [ -n "${ASC_KEY_ID:-}" ] && [ -n "${ASC_ISSUER_ID:-}" ] && [ -n "${ASC_KEY_PATH:-}" ]; then
      # altool looks for AuthKey_<id>.p8 in ~/.appstoreconnect/private_keys (among others).
      [ -f "$ASC_KEY_PATH" ] || die "ASC_KEY_PATH=$ASC_KEY_PATH does not exist"
      KEYDIR="$HOME/.appstoreconnect/private_keys"
      mkdir -p "$KEYDIR"; chmod 700 "$KEYDIR"
      [ -f "$KEYDIR/AuthKey_$ASC_KEY_ID.p8" ] || install -m 600 "$ASC_KEY_PATH" "$KEYDIR/AuthKey_$ASC_KEY_ID.p8"
      xcrun altool --validate-app -f "$IPA" -t ios --apiKey "$ASC_KEY_ID" --apiIssuer "$ASC_ISSUER_ID"
      xcrun altool --upload-app -f "$IPA" -t ios --apiKey "$ASC_KEY_ID" --apiIssuer "$ASC_ISSUER_ID"
    else
      need_eas_login
      stage
      (cd "$WC_APP" && eas_cli submit --platform ios --path "$IPA")
    fi
    say "uploaded. Processing in App Store Connect takes 5-30 min, then the build shows up in TestFlight."
    ;;

  watch-sim)
    need_macos
    xcodebuild -showsdks 2>/dev/null | grep -q -- '-sdk watchsimulator' || die "no watchOS simulator SDK: xcodebuild -downloadPlatform watchOS"
    stage; deps; prebuild ios
    DERIVED="$WC_APP/build/watch-sim"
    say "xcodebuild -target WardenClawWatch (Debug, watchsimulator, no code signing)"
    (cd "$WC_APP/ios" && xcodebuild -project WardenClaw.xcodeproj -target WardenClawWatch -configuration Debug \
      -sdk watchsimulator SYMROOT="$DERIVED" CODE_SIGNING_ALLOWED=NO build)
    APP="$DERIVED/Debug-watchsimulator/WardenClawWatch.app"
    [ -d "$APP" ] || die "no $APP after xcodebuild"
    WATCH="$(xcrun simctl list devices booted 2>/dev/null | grep -i 'watch' | grep -o '[0-9A-F-]\{36\}' | head -1)"
    if [ -n "$WATCH" ]; then
      xcrun simctl install "$WATCH" "$APP"
      xcrun simctl launch "$WATCH" com.wardenclaw.app.watchkitapp >/dev/null || true
      ok "installed into the booted watch simulator $WATCH (the simulator has no Secure Enclave: a software key stands in there)"
    else
      warn "no booted Apple Watch simulator: boot one in Simulator.app (File > Open Simulator > watchOS), then: xcrun simctl install <udid> '$APP'"
    fi
    ;;

  swift-test)
    have swift || die "swift not found (comes with Xcode)"
    stage
    say "swift test in $WC_APP/targets (protocol code of the watch app vs protocol/vectors)"
    (cd "$WC_APP/targets" && swift test)
    ;;

  -h|--help|help)
    sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  *)
    die "unknown command '$CMD' (build | sim | sim-xcode | xcode | submit [ipa] | watch-sim | swift-test)"
    ;;
esac
