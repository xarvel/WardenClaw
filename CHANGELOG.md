# Changelog

What each public release of WardenClaw brings and what to do when you upgrade. wardend, wardenctl,
the app, the OpenClaw plugin and the protocol are released together; daemon releases are tagged
`daemon/vX.Y.Z` ([release process](daemon/docs/release.md)).

## Unreleased: the first public release

### What's in it

- **wardend**, the Linux supervisor (Linux 5.19 or newer with systemd): runs the agent harness
  under a seccomp filter, stops every `execve` and `execveat` of its tree in the kernel and checks
  it against the rules (tripwire by default). A command that trips a rule waits for a signed
  ticket; a signed command is stopped again before its first instruction and compared with what
  was signed. Every exec and every decision lands in a hash-chained, signed journal
  (`wardend verify-journal`, with `--expect-head` to pin the chain head that `wardend status`
  reports, so a cut tail is caught too). wardend serves the phone over its own HTTP endpoint with signed
  responses, pairs devices (`wardend pair`), can send a push over ntfy or APNs, and checks its
  config before a restart (`wardend config-check`). `install.sh` sets up the hardened install:
  wardend as a root system service, the agent as its own user.
- **wardenctl**, the terminal approver for Linux and macOS: pairs with wardend and signs decisions
  with its own device key.
- **The WardenClaw app** for Android and iPhone: approval cards, signing with a device key,
  Manual, Observe and Autopilot, a risk judge on a model at a URL you set (one request at a time,
  and a warning when the judge lives on the agent's host), a hash-chained journal the owner can
  clear (the wipe becomes the first entry of the new chain).
- **wardenclaw-gate**, the optional OpenClaw plugin: gates OpenClaw's own tool calls and relays
  wardend cards through the gateway ([plugin/README.md](plugin/README.md)).
- **Protocol version 1** ([protocol/README.md](protocol/README.md)): the exec envelope v1 with the
  listed environment variables, canonical JSON, typed decision tickets, signed responses, pairing
  and the test vectors every implementation is tested against.

What it doesn't close yet: the "Not closed yet" line of the [README](README.md) and the
[threat model](site/src/docs/threat-model.en.md).

### Left out, behind flags

These are built and tested, but the release builds leave them out. They come back with a flag:

- **YubiKey** as a second factor: the Go build tag `hwkey` for wardend and wardenctl,
  `HARDWARE_KEY` in the plugin, a build flag in the app. How to bring it back:
  [daemon/docs/hwkey.md](daemon/docs/hwkey.md).
- **Apple Watch** as an approver: a build flag in the app.
- **The judge on the phone** (local models): a build flag in the app. The judge on a model at a
  URL stays in.

The app's flags and what each one removes from the build: [app/docs/release-scope.md](app/docs/release-scope.md).

### If you ran a test build before the release

- The protocol changed incompatibly while the builds were private, and the test builds carry no
  protocol version. Update every part together: wardend and wardenctl, the plugin and the app.
- The app and the plugin now check the protocol version. The app says in words which side to
  update ("The server is older than the app", "The app is older than the server") and signs
  nothing for a server of another version. The plugin's relay stops forwarding decisions to an
  incompatible wardend (`wardend_protocol_mismatch`). wardenctl exits with code 4.
- A request in an envelope version the app doesn't know is not shown as a card: the feed counts it
  and asks you to update the app, and the request expires on the server.
