---
title: Get the app
description: "Where to get a WardenClaw approver. The Android and iPhone apps and wardenctl for a laptop, and what exists before the first release."
---

# Get the app

An approver is a device with its own Ed25519 key that wardend trusts after pairing: the Android app, the iPhone app or `wardenctl` in a terminal on your laptop. The key stays on the device and never goes to the server. You need at least one approver; with two you can still approve when one is lost.

<div class="callout" role="note"><strong>No public app build yet.</strong> There is no APK in the releases, no public TestFlight and nothing in the stores. Until the first public build the phone apps are built from source (below). This page gets the download links when the builds are published. <code>wardenctl</code> ships with every daemon release.</div>

## Android

The app is an Expo project in `app/` of the repository. The build guide is [app/docs/BUILD.md](%REPO_URL%/blob/main/app/docs/BUILD.md), section "Android: APK and AAB": the `preview` profile gives an APK for all ABIs, `production` an AAB for Google Play. Builds run with `eas build --local` or fully locally, on macOS or Linux.

Install the APK on the phone, then [connect it to wardend](../connect-phone/).

## iPhone

The iOS app does what the Android app does. What works and what to set up in Apple Developer: [iPhone app](../ios/).

Build it on a Mac with [app/docs/BUILD.md](%REPO_URL%/blob/main/app/docs/BUILD.md), section "iOS: TestFlight": `scripts/local/ios.sh` builds the `.ipa`, `scripts/local/ios.sh submit` uploads it to your own App Store Connect, and the build appears in your TestFlight after processing (5 to 30 minutes). Push notifications for an app you build yourself need a relay of your own with your APNs key: [Push notifications](../apns/).

## wardenctl on a laptop

`wardenctl` is the terminal counterpart of the app. It pairs with wardend through the same relay and signs decisions with its own device key. Builds exist for macOS (arm64, amd64) and Linux (arm64, amd64).

**Run it on a different machine** from the agent's, never on the agent's host as the agent's user: there the agent could read the device key or run `wardenctl approve` itself. wardenctl refuses to start next to an accessible wardend (exit code 3).

Get the binary on the laptop itself, not through the agent's host:

- macOS: `wardenctl_darwin_arm64.tar.gz` or `wardenctl_darwin_amd64.tar.gz` from a daemon release;
- Linux: `wardenctl` inside `wardend_linux_arm64.tar.gz` or `wardend_linux_amd64.tar.gz` of the same release.

Check the archive against the release's `checksums.txt` before you unpack it (releases are not signed). On a Mac remove the Gatekeeper quarantine only from a file whose checksum checked out.<!-- feature:hardwareKey --> For a YubiKey over USB install the libfido2 tools (`brew install libfido2`, `apt install fido2-tools`).<!-- /feature --> The full guide: [daemon/cmd/wardenctl/README.md](%REPO_URL%/blob/main/daemon/cmd/wardenctl/README.md).

Pair it with the link that `wardend pair start` prints (see [Connect the phone](../connect-phone/#1-pair)):

```bash
wardenctl pair '<wardenclaw://pair?…>'
```

Then `wardenctl pending`, `wardenctl show <id>`, `wardenctl approve <id>`, `wardenctl deny <id>` or `wardenctl watch`. For scripts and test automation: [External approvers and test automation](../cli/#external-approvers-and-test-automation).

## Modes on the phone

wardend has no modes: every launch outside an approved tree waits for a signed ticket from an approver and is refused when none comes in time. The Mode tab of the app decides what the phone does with a card:

- **Manual**, the default and the mode after every start: you sign every card.
- **Autopilot**: the judge model allows on its own below your risk threshold and denies on its own; the rest waits for you. Three denies in a row put the app back to Manual.
- **Observe**: the phone signs every card the moment it arrives, dangerous ones too, without the judge and without asking, and only writes the journal. Journal entries are marked "Signed in Observe", dangerous ones get a red DANGEROUS badge with the reasons; the banner and the service notification carry one summary line, there is no notification per card. A command that would run as root outside the gate, a card the phone could not verify, and a card the server wants a hardware key for still wait for you.

Autopilot and Observe are turned on with biometrics or the device passcode for one hour (Observe takes the same timer because it signs more), and Stop ends them at once. Harness service launches (the gateway's workers, `lsof`, `systemctl show`, the claude-cli pack, labelled `service` by wardend) are signed by rule in every mode and appear only in the journal; "Ask me about harness service launches too" on the Mode tab brings them to the feed.

## The judge on the phone

The judge is the model the app asks for a verdict, at the address you set on the Mode tab. Use your own endpoint on a machine of yours, not the provider or the host the agent uses: a judge on the agent's host, or behind a key the agent already holds, sits inside the loop it is meant to check. The app warns when the judge address points at the host of a paired wardend server, and still lets you save it.

A `wardenclaw://judge?url=<encoded>&model=<encoded>[&key=<encoded>]` link (as a QR or a tap) fills in the judge URL, the model name and, if the link carries `key`, the API key field on the Mode tab, nothing more: the form shows "Filled from a link" (or "…, including the API key"), and nothing is saved until you tap Save and confirm as the owner. A link that carries any other parameter is refused, and the Mode tab says why. The URL must be `https://`, or `http://` on localhost only; the key is 1–512 characters with no spaces. A link with `key` contains a secret: show its QR only to your own devices, as you would a pairing link.

## The journal on the phone

Every card, verdict and decision lands in a local journal: an append-only SQLite table where each entry carries the hash of the previous one, kept out of the phone's cloud backup. The owner can clear it: the Journal tab has a "Clear journal" action, confirmed in a dialog and then with biometrics or the device passcode. Clearing removes the entries from this phone only; the server's journal (`wardend journal`, `wardend verify-journal`) is not affected. The wipe becomes the first entry of the new chain, with the number of entries removed and the hash of the old head, so a cleared journal never looks like a fresh one.

## Update the parts together

The app, wardend and wardenctl speak one protocol, version 1 in the first release. The app checks the version of the server every time it connects. When they don't match, the Connect tab says which side to update, with the raw error under Details:

- "The server is older than the app: update wardend on the server."
- "The app is older than the server: update the app."

While the versions don't match, the app takes the cards of that server off the feed, signs nothing for it and tries again every 30 seconds. wardenctl checks the version too and exits with code 4 when it doesn't match.

A request in a newer format than the app knows is not shown as a card. The feed shows a banner, "Requests this version cannot show: N", with the note "The server sent requests in a newer format. Update the app to see them. Until then they cannot be allowed here and will expire on the server." Such a request has no buttons, not even Deny: the app can't check what it would sign. It expires on the server like any unanswered request, and the command is refused.

## Next

[Connect the phone](../connect-phone/): an address the device can reach, pairing and a check.
