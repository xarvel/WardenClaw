---
title: Connect the phone
description: The phone needs nothing but internet. wardend dials the relay itself; pair the app by QR code and check the connection with wardend status.
---

# Connect the phone

**Time:** 5 minutes · **Needs:** wardend installed, a [device with the app](../app/), internet on the server and on the phone · **Result:** the app shows "Connected" and the server lists it as a trusted device

wardend listens on no network port. It keeps one outbound WebSocket to the relay (`relay_url`, by default `wss://relay.wardenclaw.dev`), and the app connects to the same relay. You need no tunnel, no public hostname and no open port: the server only has to reach the relay over outbound HTTPS.

Trust does not depend on the relay. Messages between wardend and a device are end-to-end encrypted (X25519 + XChaCha20-Poly1305), so the relay sees ciphertext. Every ticket is signed with the device key and bound to the digest of the command, and every card is signed with the supervisor key the phone pinned from the QR code. The relay can delay or drop a message, but it cannot read a card, forge one, or approve anything.

The commands below are for the [hardened install](../install/). In the single-user trial install drop `sudo`, and the config is `~/.wardend/config.json`.

## 1. Pair

Pair from your own terminal on the server, never from a chat with the agent. `pair start`, `approve`, `reject` and `revoke` refuse to run under wardend's filter, so the agent can't pair a device for itself.

```bash
sudo wardend pair start
```

It prints a QR code and waits. In the app open the **Connect** tab and tap **Scan QR**. The app shows the device fingerprint and waits for approval. On the server `pair start` shows the device's name and the same fingerprint and asks `Approve this device? [y/N]`: compare the fingerprint with the phone screen, then answer `y`. Anything else rejects the request.

Without a terminal (a script) or with `--no-wait`, `pair start` does not ask. Approve the request by its id:

```bash
sudo wardend pair list
sudo wardend pair approve <id>
```

A pairing request expires after 10 minutes. For `wardenctl` pass the `wardenclaw://pair?…` link that `pair start` prints: `wardenctl pair '<link>'`.

## 2. Check the connection

- The app shows **Connected** and the mode of the server.
- `sudo wardend pair list` lists the device among the trusted devices. If wardend has no connection to the relay, it adds the line `Not connected to the relay …`.
- `sudo wardend status | jq .relay` shows the relay state: `url`, `enabled`, `connected`, `devices` (the number of devices wardend serves through the relay) and `error`, if the relay could not be started.

There is no test card yet. In `observe`, where the install starts, nothing asks for a signature, so the feed stays empty: that is expected, not a broken connection. The first cards come after the switch to `ticket` ([install, step 5](../install/#step-5-observe-check-the-forecast-then-ticket)). Before that switch make sure the phone is paired and online: without a trusted device every command that trips a rule waits for the TTL and fails.

A spare device keeps the agent going when the phone is away: right after the phone, pair [`wardenctl`](../cli/#external-approvers-and-test-automation) on a laptop with a link from another `pair start`.

## If the phone is lost

The lost phone holds a device key that can approve commands: revoke it right away. Pairing a new phone needs no second device, only your terminal on the server:

```bash
sudo wardend pair list
sudo wardend pair revoke <deviceId prefix>
sudo wardend pair start     # scan the QR code with the new phone, compare the fingerprint, answer y
```

If you run the OpenClaw plugin `wardenclaw-gate`, revoke the phone there too: `pair revoke` changes wardend only, and the plugin trusts the devices of its own `trustedDeviceIds`. Delete the phone's id from `plugins.entries.wardenclaw-gate.config.trustedDeviceIds` in the gateway's `openclaw.json` (and from `devices`, if you listed it there) and save the file; the gateway reloads the plugin with the new list, and calls waiting for a decision are rejected. To cut the phone off the gateway entirely, also run `openclaw devices remove <deviceId>`.

Until a new device is paired, every command that needs a signature waits for the TTL and fails. If that takes a while, [step back to observe](../uninstall/#step-back-to-observe-instead) for the time being.

## If it does not connect

- **`pair list` says `Not connected to the relay`, or `status` shows `"connected": false`.** The server can't reach the relay. Check outbound HTTPS from the server to the host in `relay_url` (a firewall, a proxy, DNS). wardend retries by itself, with a pause that grows from 1 to 60 seconds; no restart is needed once the network is back.
- **`status` shows `"enabled": false`.** `relay_url` is `off` in the config: no device can reach this wardend. Remove the key (the default relay) or set your relay's address, check the config with [`wardend config-check`](../cli/#wardend-config-check) and restart wardend. The restart also restarts the agent.
- **A relay of your own.** `relay_url` takes the base address, `wss://host[:port]`, without `/v1/ws`. The app takes the relay address from the pairing QR code, so pair again after you change it. How to deploy the relay: [relay/README.md](%REPO_URL%/blob/main/relay/README.md).
- **The app does not accept the QR code.** The code is one-time and lives 5 minutes (`pair_code_ttl`): run `wardend pair start` again.
- **Cards don't show up on a locked phone.** [Notifications on a locked phone](../notifications/).
