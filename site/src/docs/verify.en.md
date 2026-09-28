---
title: Verify releases
description: The minisign key that signs every wardend release, where else it is published, what to do when it does not match and how the key can change.
---

# Verify releases

<div class="callout callout-danger" role="note" data-if="test-key"><strong>Test key, not for production systems.</strong> Until the first release this site shows a test signing key. Its secret half sits on a development machine, so the installer refuses to download anything signed with it, and a release is never built or signed with it.</div>

Every wardend release carries `checksums.txt`, the sha256 of each file, signed with minisign. The installer checks the signature before it writes anything. This page is for checking it yourself, and for knowing when not to trust what you see.

## The release key

<p class="release-key"><code>%MINISIGN_PUBKEY%</code></p>

Key ID `%MINISIGN_KEY_ID%`, the one minisign writes in the first line of a `.pub` file. The secret half is kept offline by the maintainer: not on a server, not in CI, not in a GitHub account.

## Where else it is published

This page, the README, `SECURITY.md` and the release notes all come from one GitHub repository, so whoever takes it over can change the key in all of them at once. Compare it with the other copies:

- **DNS of the project domain.** A TXT record with the same line: `dig +short TXT %KEY_DNS_NAME%` prints it, and it doesn't depend on GitHub.
- **Your installed system.** The first hardened install pins the key in `/etc/wardend/release.pub`. From then on upgrades check releases with the pinned key, not with the one on this site.
- **The installer.** `install.sh` of every release names the key in its `MINISIGN_PUBKEY=` line, and this site serves `install.sh` only after the release verifies with the key shown above.

If one of them differs, don't install. On a first install the DNS record is the only copy of the key outside GitHub, so compare it before you run the installer: the signature check alone catches a tampered script or archive, not a takeover of the repository. After the first install your pinned key protects upgrades.

## Check a release by hand

```shell
U=%RELEASES_URL%/latest/download
curl --proto '=https' --tlsv1.2 -fsSL --remote-name-all $U/checksums.txt $U/checksums.txt.minisig &&
  minisign -Vm checksums.txt -P %MINISIGN_PUBKEY%
```

minisign prints `Signature and comment signature verified` and `Trusted comment: wardend vX.Y.Z checksums.txt YYYY-MM-DD`: the signed version and the day it was signed. `sha256sum --ignore-missing -c checksums.txt` then checks the files you downloaded next to it. The whole sequence for the installer is in [Before you pipe into sudo](../install/#before-you-pipe-into-sudo).

## If it does not match

- The signature does not verify, the key differs from the DNS record, or the installer stops with "this machine pinned …": don't run anything, and don't delete `/etc/wardend/release.pub` to make it pass. An installer that stops has changed nothing.
- For a few minutes after a new release the site may still serve the previous `install.sh`, and `sha256sum` reports `FAILED` for it: try again later. A signature that fails to verify is never this case.
- Tell us privately: [Security policy](../../security/).

## When the key changes

The key never changes silently.

- **Planned change.** The old key signs a statement that names the new one: `release-key.txt` and `release-key.txt.minisig` in the release, with the trusted comment `wardend release-key <new key> <date>`. Installs pinned to the old key take the new one only with this statement, and it stays in the following releases, so an install that skipped a few releases still finds it. To check it yourself: `minisign -Vm release-key.txt -x release-key.txt.minisig -P <old key>`.
- **Two changes in a row** (A, then B, then C): an install pinned to A finds only the statement B to C, stops and explains why. Then do as for a leaked key.
- **Leaked or lost key.** A statement signed with a leaked key proves nothing, so there is none. The old key goes to the list of keys the installer refuses, the new one is published here, in `SECURITY.md` and in DNS. Pinned installs stop with an explanation: compare the new key with a copy outside GitHub, delete `/etc/wardend/release.pub` and run the installer again.

## Test keys

A key whose secret half has been on a development machine never installs anything from the network: the installer refuses it before the first download, and the release scripts refuse to build or sign a release with it. While this site shows such a key, the pages with the key and with the install command say so.
