# Changelog

What each public release of WardenClaw brings and what to do when you upgrade. wardend, wardenctl,
the app and the protocol are released together; daemon releases are tagged
`daemon/vX.Y.Z` ([release process](daemon/docs/release.md)).

## daemon/v0.1.0: the first public release

### What's in it

- **wardend**, the Linux supervisor (Linux 5.19 or newer with systemd): runs the agent harness
  under a seccomp filter, stops every `execve` and `execveat` of its tree in the kernel and checks
  it against the rules (tripwire by default). A command that trips a rule waits for a signed
  ticket; a signed command is stopped again before its first instruction and compared with what
  was signed. Every exec and every decision lands in a hash-chained, signed journal
  (`wardend verify-journal`, with `--expect-head` to pin the chain head that `wardend status`
  reports, so a cut tail is caught too). wardend reaches the phone through a relay over one outbound WebSocket,
  end-to-end encrypted, pairs devices (`wardend pair`), and checks its
  config before a restart (`wardend config-check`, with a distinct warning when `mode: ticket`,
  `relay_url: off` and no trusted device leave `wardend approve` as the only decision path). A relay
  that refuses the connection as `protocol_mismatch` is logged in one plain sentence naming which
  side is older, and shows as `relay.error` in `wardend status`. `install.sh` sets up the hardened
  install: wardend as a root system service, the agent as its own user; on a re-run it backs up
  the previous systemd unit as `.wardend-bak` and prints the changed lines before writing the new
  one, or keeps it with `--no-unit`.
- **wardenctl**, the terminal approver for Linux and macOS: pairs with wardend and signs decisions
  with its own device key. The one-shot commands (`pending`, `show`, `approve`, `deny`) resume the
  relay queue on connect and ack the frames they read, so nothing is redelivered next time.
- **The WardenClaw app** for Android and iPhone: approval cards, signing with a device key,
  Manual, Observe and Autopilot, a risk judge on a model at a URL you set (one request at a time,
  and a warning when the judge lives on the agent's host or on the relay's host), a hash-chained
  journal the owner can clear (the wipe becomes the first entry of the new chain). The relay resume
  state is kept per supervisor and device; a supervisor that reconnects to the relay is asked for
  its status again; a relay of another protocol version is named as such, with both sides to
  update; the refusals wardend and the relay can send have words on the card.
- **Protocol version 1** ([protocol/README.md](protocol/README.md)): the exec envelope v1 with the
  listed environment variables, canonical JSON, typed decision tickets, signed responses, pairing
  and the test vectors every implementation is tested against.
- **The release itself**: reproducible archives for linux/amd64, linux/arm64 and darwin/arm64
  (wardend) and darwin/arm64, darwin/amd64 (wardenctl), `install.sh`, `checksums.txt`, a CycloneDX
  SBOM of the Go module (`sbom.cdx.json`) and a provenance attestation over the checksums. The
  envelope parsers (canonical JSON, envelope, tickets, pairing requests, pair links, base64url) run
  under native Go fuzzing in CI on every push.

What it doesn't close yet: the "Not closed yet" line of the [README](README.md) and the
[threat model](site/src/docs/threat-model.en.md).

### Left out, behind flags

These are built and tested, but the release builds leave them out. They come back with a flag:

- **YubiKey** as a second factor: the Go build tag `hwkey` for wardend and wardenctl,
  a build flag in the app. How to bring it back:
  [daemon/docs/hwkey.md](daemon/docs/hwkey.md).
- **Apple Watch** as an approver: a build flag in the app.
- **The judge on the phone** (local models): a build flag in the app. The judge on a model at a
  URL stays in.

The app's flags and what each one removes from the build: [app/docs/release-scope.md](app/docs/release-scope.md).

### If you ran a test build before the release

- The OpenClaw gateway plugin `wardenclaw-gate` and the app's OpenClaw adapter (the connection
  through the OpenClaw gateway, its pairing with a setup code, the cards for OpenClaw's own tool
  calls) are removed. The relay is the only transport between the phone and wardend. Uninstall
  the plugin from OpenClaw and pair the phone with wardend (`wardend pair`). wardend still runs
  OpenClaw as a harness, as before.
- The protocol changed incompatibly while the builds were private, and the test builds carry no
  protocol version. Update every part together: wardend, wardenctl and the app.
- The app now checks the protocol version. It says in words which side to
  update ("The server is older than the app", "The app is older than the server") and signs
  nothing for a server of another version. wardenctl exits with code 4.
- A request in an envelope version the app doesn't know is not shown as a card: the feed counts it
  and asks you to update the app, and the request expires on the server.
