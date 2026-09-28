---
title: Get the app
description: "Where to get a WardenClaw approver. The Android and iPhone apps, <!-- feature:appleWatch -->the Apple Watch app <!-- /feature -->and wardenctl for a laptop, and what exists before the first release."
---

# Get the app

An approver is a device with its own Ed25519 key that wardend trusts after pairing: the Android app, the iPhone app, <!-- feature:appleWatch -->the Apple Watch app <!-- /feature -->or `wardenctl` in a terminal on your laptop. The key stays on the device and never goes to the server. You need at least one approver; with two you can still approve when one is lost.

<div class="callout" role="note"><strong>No public app build yet.</strong> There is no APK in the releases, no public TestFlight and nothing in the stores. Until the first public build the phone apps are built from source (below). This page gets the download links when the builds are published. <code>wardenctl</code> ships with every daemon release.</div>

## Android

The app is an Expo project in `app/` of the repository. The build guide is [app/docs/BUILD.md](%REPO_URL%/blob/main/app/docs/BUILD.md), section "Android: APK and AAB": the `preview` profile gives an APK for all ABIs, `production` an AAB for Google Play. Builds run with `eas build --local` or fully locally, on macOS or Linux.

Install the APK on the phone, then [connect it to wardend](../connect-phone/).

## iPhone<!-- feature:appleWatch --> and Apple Watch<!-- /feature -->

The iOS app does what the Android app does<!-- feature:appleWatch --> and carries the Apple Watch app, an approver of its own with a key in the watch's Secure Enclave<!-- /feature -->. What works and what to set up in Apple Developer: [iPhone<!-- feature:appleWatch --> and Apple Watch<!-- /feature --><!-- feature:!appleWatch --> app<!-- /feature -->](../ios/).

Build it on a Mac with [app/docs/BUILD.md](%REPO_URL%/blob/main/app/docs/BUILD.md), section "iOS: TestFlight": `scripts/local/ios.sh` builds the `.ipa`, `scripts/local/ios.sh submit` uploads it to your own App Store Connect, and the build appears in your TestFlight after processing (5 to 30 minutes). Push notifications for the phone<!-- feature:appleWatch --> and the watch<!-- /feature --> need an APNs key on the server: [<!-- feature:appleWatch -->Apple Watch and APNs<!-- /feature --><!-- feature:!appleWatch -->Push notifications (APNs)<!-- /feature -->](../apns/).

## wardenctl on a laptop

`wardenctl` is the terminal counterpart of the app. It pairs with wardend over the same HTTP API and signs decisions with its own device key. Builds exist for macOS (arm64, amd64) and Linux (arm64, amd64).

**Run it on a different machine** from the agent's, never on the agent's host as the agent's user: there the agent could read the device key or run `wardenctl approve` itself. wardenctl refuses to start next to an accessible wardend (exit code 3).

Get the binary on the laptop itself, not through the agent's host:

- macOS: `wardenctl_darwin_arm64.tar.gz` or `wardenctl_darwin_amd64.tar.gz` from a daemon release;
- Linux: `wardenctl` inside `wardend_linux_arm64.tar.gz` or `wardend_linux_amd64.tar.gz` of the same release.

Check the archive against the release's `checksums.txt` before you unpack it (releases are not signed). On a Mac remove the Gatekeeper quarantine only from a file whose checksum checked out.<!-- feature:hardwareKey --> For a YubiKey over USB install the libfido2 tools (`brew install libfido2`, `apt install fido2-tools`).<!-- /feature --> The full guide: [daemon/cmd/wardenctl/README.md](%REPO_URL%/blob/main/daemon/cmd/wardenctl/README.md).

Pair it with the link that `wardend pair start` prints (see [Connect the phone](../connect-phone/#4-pair)):

```bash
wardenctl pair '<wardenclaw://pair?…>'
```

Then `wardenctl pending`, `wardenctl show <id>`, `wardenctl approve <id>`, `wardenctl deny <id>` or `wardenctl watch`. For scripts and test automation: [External approvers and test automation](../cli/#external-approvers-and-test-automation).

## The judge on the phone

The judge is the model the app asks for a verdict, at the address you set on the Mode tab. Use your own endpoint on a machine of yours, not the provider or the host the agent uses: a judge on the agent's host, or behind a key the agent already holds, sits inside the loop it is meant to check. The app warns when the judge address points at the host of a paired wardend server, and still lets you save it.

## The journal on the phone

Every card, verdict and decision lands in a local journal: an append-only SQLite table where each entry carries the hash of the previous one, kept out of the phone's cloud backup. The owner can clear it: the Journal tab has a "Clear journal" action, confirmed in a dialog and then with biometrics or the device passcode. Clearing removes the entries from this phone only; the server's journal (`wardend journal`, `wardend verify-journal`) is not affected. The wipe becomes the first entry of the new chain, with the number of entries removed and the hash of the old head, so a cleared journal never looks like a fresh one.

## Update the parts together

The app, wardend, wardenctl and the OpenClaw plugin speak one protocol, version 1 in the first release. The app checks the version of the server every time it connects. When they don't match, the Connect tab says which side to update, with the raw error under Details:

- "The server is older than the app: update wardend on the server." For the plugin: "The wardenclaw-gate plugin is older than the app: update the plugin on the OpenClaw gateway."
- "The app is older than the server: update the app."

While the versions don't match, the app takes the cards of that server off the feed, signs nothing for it and tries again every 30 seconds. wardenctl checks the version too and exits with code 4 when it doesn't match.

A request in a newer format than the app knows is not shown as a card. The feed shows a banner, "Requests this version cannot show: N", with the note "The server sent requests in a newer format. Update the app to see them. Until then they cannot be allowed here and will expire on the server." Such a request has no buttons, not even Deny: the app can't check what it would sign. It expires on the server like any unanswered request, and the command is refused.

## Next

[Connect the phone](../connect-phone/): an address the device can reach, pairing and a check.
