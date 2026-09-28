# Second factor: hardware key (FIDO2 / YubiKey)

> **Not in the first release.** The protocol of the second signature is described here in full and stays in force, but the first release of wardend, wardenctl and the plugin doesn't include the feature. wardend built without the `hwkey` tag refuses to start with a non-empty `hardware_keys` in the config or `require_hardware` in the policy, and rejects a decision with `hw` as `hardware_not_configured`; the plugin rejects a decision with `hw` as `hw_not_in_release`. How to bring it back: [daemon/docs/hwkey.md](../daemon/docs/hwkey.md).

For high-risk commands a ticket carries a **second signature** made by a hardware security key (YubiKey 5 NFC, tapped against the phone). The phone's Ed25519 signature says "this device approved"; the key's FIDO2 assertion says "a human physically touched the key for exactly this ticket". A compromised phone alone can no longer approve a command covered by `require_hardware`.

Code (in `daemon/`): `hwkey/` (CBOR, COSE, authenticatorData, registration, assertion check), `envelope/ticket.go` (`HWChallenge`), `supervisor.go` (`checkHardware`), `hwcmd.go` (CLI). Test vectors: [`vectors/hw_vectors.json`](vectors/hw_vectors.json) (one copy, read by the tests of wardend, the app and the plugin).

> Status: prototype. Checked with a software authenticator in unit tests; not yet run against a real YubiKey (the app's native module needs a dev build).

## Ticket format

A ticket (decision body, [README §4](README.md#4-decision-ticket)) gains two **optional** fields; without them the format and the signing string are those of §4:

```json
{
  "deviceId": "<hex64>",
  "payload": {"type": "wardenclaw.ticket.exec.v1", "supervisorId": "<hex64>", "id": "wd-…", "digest": "<hex64>", "decision": "allow", "ts": 1790447985039, "nonce": "…", "risk": 90},
  "signature": "<base64url Ed25519 over the signing string>",
  "hw": {
    "credentialId": "<base64url>",
    "clientDataJSON": "<base64url>",
    "authenticatorData": "<base64url>",
    "signature": "<base64url>"
  }
}
```

- `payload.risk`: integer 0..100, the app judge's risk score. When present it is part of the device signing string: `canonicalJson({decision, deviceId, digest, id, nonce, risk, supervisorId, ts, type})`. When absent the string is the same without `risk`. Anything that isn't an integer in 0..100 is rejected with `risk_invalid`.
- `hw`: the FIDO2 assertion. It is **not** covered by the device signature. It is bound to the ticket through its challenge instead.

### Challenge

```
challenge      = sha256( canonicalJson({ type: "wardenclaw.hw.v1", ticket, deviceId, id, digest, decision, ts, nonce, supervisorId [, risk] }) )
clientDataJSON = {"type":"webauthn.get","challenge":"<base64url(challenge), no padding>","origin":"wardenclaw:app"}
clientDataHash = sha256(clientDataJSON)          ← what the app passes to CTAP2 authenticatorGetAssertion
signature      = key.sign( authenticatorData || clientDataHash )
```

`ticket` is the ticket type (`payload.type`): `type` stays the domain tag of the second factor. The challenge covers every field the device signs, plus that tag. An assertion therefore fits exactly one ticket: this wardend (`supervisorId`), this digest (so this envelope: argv, cwd, exe, process instance), this decision, this nonce and this risk. It can't be moved to another exec, turned from `deny` into `allow`, or reused as a device signature. The nonce is single-use, so the same assertion can't be replayed either, and the signCount check covers a cloned key.

### Relying party

- `rpId` = `"wardenclaw"` (per key in the config; `--rp-id` at registration). The app talks raw CTAP2 over NFC (Yubico `yubikit-android`), with no browser in between. A browser never issues assertions for the rpId `wardenclaw` (it isn't the domain of any site), so a phishing page can't get a signature for our rpId.
- `origin` must be exactly `wardenclaw:app` and `crossOrigin` must not be `true`.

## Verification (wardend)

For an `allow` decision, after the usual ticket checks (trusted device, `ts` window, Ed25519 signature, nonce, pending id, digest):

1. **Is the key needed?** Yes if the pending exec matched a static `require_hardware` rule (known at queue time), or a `min_score` rule matched and `payload.risk ≥ min_score`. If `hw` is present although not needed, it is still verified; an invalid one is rejected, and a valid one marks the root as hardware-approved.
2. `credentialId` is one of `hardware_keys` → else `hw_unknown_credential`.
3. `clientDataJSON`: `type == "webauthn.get"` (`hw_client_data_type`), `origin` (`hw_origin`), challenge equals the recomputed one (`hw_challenge_mismatch`).
4. `authenticatorData`: `rpIdHash == sha256(rp_id)` (`hw_rpid_mismatch`), the UP flag (user presence, the touch) is set (`hw_user_presence`), UV (PIN) if the key has `require_uv` (`hw_user_verification`), no attested-credential data (`hw_auth_data_invalid`).
5. Signature over `authenticatorData || sha256(clientDataJSON)` with the stored COSE key → else `hw_bad_signature`. EdDSA (COSE alg −8, Ed25519, raw 64-byte signature) and ES256 (alg −7, P-256, DER signature).
6. `signCount` strictly greater than the stored one (`hw_counter_replay`); `0`/`0` is accepted for authenticators without a counter. The new value goes to `hardware_counters` (atomic write + fsync) **before** the ticket is accepted; a failed write is `hw_counter_persist`. The counter is touched only after a valid signature.

A failed check rejects the decision (`ok:false`, the reason, `hardwareRule`), writes `decide_reject` to the journal and keeps the exec pending. The app can retry with a fresh nonce and another tap. When `ticket_ttl` runs out, the exec gets `EPERM`. `deny` never needs a key.

A missing `hw` gives `hardware_required`. A `hw` with no keys configured gives `hardware_not_configured`.

An `es256` device such as Apple Watch (see [`README.md`](README.md), section 7) has no NFC path to the key, so it cannot approve a card that needs the key: its `allow` gets `hardware_required`. The challenge covers `deviceId`, so an assertion made on the phone for the phone's ticket does not fit a watch ticket either (`hw_challenge_mismatch`).

## Policy

```json
"require_hardware": [
  {"id": "hw-delegating", "class": "delegating", "note": "sudo/systemd-run/docker/ssh… only with the key"},
  {"id": "hw-force-push", "argv0": "^git$", "argv_text": " push( .*)? (-f|--force)( |$)"},
  {"id": "hw-high-risk",  "class": "root|delegating", "min_score": 80}
]
```

- All fields of an ordinary rule (`path`, `argv0`, `caller`, `argv_text`, `argv_json`, `argv_none`, `argv`) with AND semantics. `argv0` also matches the basename of the real file, as with deny rules (`exec -a innocent sudo` doesn't slip through).
- `class`: an anchored regex over `root`, `delegating` or `inherit`; empty means any of them. `service` and `deny_always` never need a key.
- `min_score`: the rule fires only when the ticket carries `payload.risk ≥ min_score`. **This only tightens:** the score comes from the phone. A phone that lies can leave `risk` out, but it can't use the score to skip a static rule. Class and argv rules are the hard guarantee.
- **Inheritance:** an exec inside an approved tree (`inherit`) that matches a static rule does **not** inherit when its root was approved without the key. It becomes a new root that needs a ticket with the key (`meta.hardware.escalated`). A root approved with a valid assertion passes such execs to its subtree.
- The built-in defaults have no `require_hardware` rules. Add them in your `--policy` file only after registering a key: in `ticket` mode, matching roots are rejected until a key exists (wardend warns at start).

## What the app sees (`pending` → `meta.hardware`)

```json
"hardware": {
  "required": true,                  // static rule: the Allow button must ask for a tap
  "rule": "hw-delegating",
  "escalated": false,                // true: inherit → root because the tree had no key
  "minScore": 80,                    // if a score rule applies: tap when own risk ≥ minScore
  "challenge": "wardenclaw.hw.v1",
  "origin": "wardenclaw:app",
  "credentials": [{"id": "<credentialId>", "name": "YubiKey 5 NFC", "alg": "EdDSA", "rpId": "wardenclaw"}]
}
```

The app treats `credentials` as a hint. It keeps its own registered credential id and never trusts the list to decide which key to use.

## Registration

1. App → Mode → Hardware key → "Tap your YubiKey". The app runs CTAP2 `authenticatorMakeCredential` (rpId `wardenclaw`, user = the device id, EdDSA preferred, ES256 as fallback, resident key off, UP required). It shows a blob `wchw1:<base64url(JSON {credentialId, attestationObject, clientDataJSON, rpId, name})>`, ready to copy.
2. On the host: `wardend hw-register 'wchw1:…'` (or `--attestation`/`--client-data`, or `--cose-key` + `--credential-id`). The attestation is checked: rpIdHash, UP/AT flags, COSE key, clientDataJSON (`webauthn.create`, origin), and the `packed` signature (the Yubico x5c certificate or self). The AAGUID in the certificate must match authData. The certificate chain up to the Yubico root is **not** verified: trust comes from the owner pasting their own blob into their own host's config. The entry records this in `attestation`.
3. Restart wardend (the config is read at start).

Config entry (`hardware_keys`):

```json
{"id": "<credentialId b64url>", "name": "YubiKey 5 NFC", "rp_id": "wardenclaw", "alg": "EdDSA",
 "public_key": "<COSE_Key b64url>", "aaguid": "…", "require_uv": false,
 "attestation": "packed-x5c (chain not verified): CN=Yubico U2F EE Serial …", "added_at": "2026-09-26T21:00:00Z"}
```

## Threat notes

- The key signs a `clientDataHash` that the phone assembles, and the key has no screen. A touch proves that a person was at the key, not that the person saw this card: a compromised phone can show card A and obtain an assertion for ticket B. Binding the touch to what the person actually saw needs Android Protected Confirmation or a second device with its own display, such as `wardenctl` on another machine. The second factor is behind the `hwkey` build tag and is not part of the first release.
- A stolen phone plus a stolen key still approves. Set `require_uv: true` (`hw-register --require-uv`) to also require the key's FIDO2 PIN, which the app then asks for.
- A compromised gateway or plugin can't forge either signature, and since tickets are typed ([README §4](README.md#4-decision-ticket)) it can't get a real one for something the phone didn't show either: a decision on a tool call is a tool ticket, which wardend rejects, and the phone signs `allow` on an exec ticket only for an envelope whose digest it recomputed itself and whose command it showed. For exec records of wardend it can therefore only drop or delay decisions, which fails closed through the TTL. Tool calls are another matter: the plugin is where they are enforced, so a compromised plugin can let them through without asking anyone.
- A cloned key (theoretical for YubiKey) shows up as a `hw_counter_replay` as soon as the clone and the original are both used.
- Deleting `hw_counters.json` resets the replay protection to 0. The file lives in the 0700 state dir, and wardend refuses to start if it is corrupt.
