# Apple Watch and APNs: work log (server and protocol)

Work log of the agent building the server side of approval from the Apple Watch: ES256 device keys,
push token registration, sending to APNs. The iOS/watchOS side is written separately in `app/`.

## 2026-09-27

- Read: protocol/README.md, HARDWARE.md, daemon/README.md, envelope/, pairing.go, httpapi.go,
  supervisor.go (decide, checkHardware), config.go, selfcheck.go, ntfy.go.
- Decisions:
  - `deviceId` for es256 = hex(sha256(65 bytes of SEC1 uncompressed)), with no algorithm prefix: the
    key lengths differ (32 and 65), so a mix-up is impossible; the "sha256 of the raw key" rule is
    the same.
  - `alg` is part of the pairing signature string when it is passed (mandatory for es256); for old
    ed25519 clients the string is unchanged. `alg` is written to `trusted_devices`; tickets and
    requests are verified with the algorithm from the config, not from the request.
  - ECDSA signature: raw r||s (64 bytes) or DER. Low-S is not required: CryptoKit/Secure Enclave
    doesn't normalize S, and nothing in the protocol is addressed by signature bytes (replays are
    stopped by the nonce).
  - Requests with a body (push.register/unregister): the same headers, signature string
    `canonicalJson({action, body, deviceId, nonce, ts})`, body = the parsed JSON body.
- Done (step 1): envelope/devicekey.go (DeviceKey, ES256 raw/DER), Devices.Key → DeviceKey,
  alg in PairPayload/pairReq/trusted_devices, RequestBodySigningString, apns.go, push.go,
  config `apns`/`push_tokens`, selfcheck of the APNs key, status: trustedDevices with alg and push.
  Vectors protocol/vectors/es256_vectors.json (RFC 6979, reproducible). envelope tests green.
- Next: main package tests (watch_test.go), wardenctl status, protocol, site.
- Step 2: watch_test.go (es256 pairing, raw/DER/tampered tickets, hardware-required, push
  register/unregister/replay, HTTP/2 APNs mock: JWT, headers, payload, 410, push list/test over RPC),
  `wardend push list|test`, `wardenctl status` shows the key type. Gotcha: the alg column in
  `wardend pair list` can't go before "fingerprint" (the wardenctl e2e regexp), moved after it.
  All packages green (main is split into two runs with -run, wardenctl ~16 s).
- Next: protocol/README.md, site, go vet amd64/arm64, site build, commit.
- Step 3: protocol/README.md (sections 7 es256 and 8 push, vectors → section 9; the anchor in
  CONTRIBUTING.md fixed), HARDWARE.md (the watch and hardware_required), daemon README and docs/CLI.md,
  site: docs/apple-watch.en.md + pages, the `apns`/`push_tokens` lines in cli.en.md.
  Site built in /tmp/wc-site-build (npm ci + build, 10 pages). go vet linux/amd64, linux/arm64,
  darwin/arm64 (wardenctl) clean. Full test run green.
- The vector test in app/ is untouched: test-core.mjs reads three files by name, a new file doesn't
  break it. The iOS agent already reads es256_vectors.json from its SwiftPM package.
