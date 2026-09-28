---
title: Documentation
description: Where to start with WardenClaw. Try the exec gate in five minutes without root, or put it on a server for real, then the app, the phone connection and the references.
---

# Documentation

WardenClaw puts the risky commands of an AI agent on a Linux server behind a signature. `wardend` runs the agent under a seccomp filter, stops every exec that trips a rule right in the kernel, and lets it run only with an Ed25519 signature from a device you paired: the phone app, <!-- feature:appleWatch -->an Apple Watch <!-- /feature -->or `wardenctl` on your laptop. The signing key never lives on the server.

> Status: prototype. Flags and formats can still change.

## Two ways in

### Try it in 5 minutes

No root, no phone, no agent. Install wardend for your own user, run one command under it and approve it from a second terminal with a test key. You see what the kernel stops, what a signed decision does and what lands in the journal.

[Try it in 5 minutes](try/)

### Put it on a server for real

The hardened install: wardend as a root system service, the agent under its own user, so the model cannot turn the gate off. It starts in observe mode, where everything runs and is journaled.

1. [Install wardend](install/): the hardened install, steps 1 to 4.
2. [Get the app](app/): Android, iPhone, <!-- feature:appleWatch -->Apple Watch <!-- /feature -->or `wardenctl` on a laptop.
3. [Connect the phone](connect-phone/): an address the phone can reach, pairing and a check.
4. [Observe, check the forecast, then ticket](install/#step-5-observe-check-the-forecast-then-ticket): step 5 of the install.

## I want to…

- **see what gets stopped and why:** [How it works](../#how) on the main page, [Modes](cli/#modes) and [Policy modes](cli/#policy-modes) in the CLI reference.
- **know why the model can't just turn it off:** [Why the model can't turn it off](tamper-resistance/).
- **check the installer before I run it:** [Before you pipe into sudo](install/#before-you-pipe-into-sudo).
- **approve from a script or a laptop:** [External approvers and test automation](cli/#external-approvers-and-test-automation).
- **use an iPhone<!-- feature:appleWatch -->, an Apple Watch<!-- /feature --><!-- feature:hardwareKey --> or a YubiKey<!-- /feature -->:** [iPhone<!-- feature:appleWatch --> and Apple Watch<!-- /feature --><!-- feature:!appleWatch --> app<!-- /feature -->](ios/), [<!-- feature:appleWatch -->Apple Watch and APNs<!-- /feature --><!-- feature:!appleWatch -->Push notifications (APNs)<!-- /feature -->](apns/).
- **see a card on a locked phone:** [Notifications on a locked phone](notifications/).
- **look up a command, a flag or a config key:** [CLI reference](cli/).
- **step back to observe or remove it:** [Uninstall](uninstall/).
- **report a vulnerability:** [Security policy](../security/).
