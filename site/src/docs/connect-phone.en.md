---
title: Connect the phone
description: Give the phone an address of wardend it can reach (Cloudflare Tunnel, Tailscale or an SSH tunnel), put it into public_url, pair by QR code and check the connection.
---

# Connect the phone

**Time:** 10 to 20 minutes · **Needs:** wardend installed, a [device with the app](../app/), a way from the phone to the server · **Result:** the app shows "Connected" and the server lists it as a trusted device

wardend serves the apps itself: an HTTP endpoint on `http_listen`, by default `127.0.0.1:8787`, reachable only from the server. The phone needs an address of that endpoint it can reach. That address goes into the pairing QR code as `public_url`.

Trust does not depend on the transport. Every request of the app is signed with its device key, every ticket is signed separately and bound to the digest of the command, and every response of wardend is signed with the supervisor key the phone pinned from the QR code. A tunnel or a proxy in between can delay or drop a message, but it cannot forge a card, pass off a decision as its own or pose as the server. Without a signature only two requests are answered: `GET /v1/ping` (the supervisor id and the protocol version) and `POST /v1/pair`, which works only while a one-time code of `wardend pair start` is alive (10 wrong codes kill all codes).

The commands below are for the [hardened install](../install/). In the single-user trial install drop `sudo` and `--socket`, and the config is `~/.wardend/config.json`.

## 1. Choose how the phone reaches wardend

### Cloudflare Tunnel

The setup described in the repository (`daemon/deploy/CLOUDFLARE.md`): a separate hostname, for example `wardend.example.com`, in a Cloudflare tunnel you already run.

Cloudflare decrypts the traffic of the tunnel, so it sees the cards: commands, paths and the environment variables a card shows. It can't forge or approve anything, the signatures hold that. If Cloudflare seeing your cards is not acceptable, use Tailscale or an SSH tunnel ([Threat model](../threat-model/)).

- **Tunnel managed in the dashboard:** Zero Trust → Networks → Tunnels → your tunnel → Public Hostname → Add a public hostname. Subdomain `wardend`, your domain, empty path; Service `HTTP`, URL `127.0.0.1:8787`. The HTTP settings need no changes: the app's long poll of 25 seconds fits into Cloudflare's timeout of 100 seconds. The dashboard creates the CNAME `wardend` → `<tunnel-id>.cfargotunnel.com` itself.
- **Tunnel with a local `config.yml`:** add a rule above the catch-all, then the DNS record and a restart of cloudflared:

  ```yaml
  ingress:
    - hostname: wardend.example.com
      service: http://127.0.0.1:8787
    # … other rules …
    - service: http_status:404
  ```

  ```bash
  cloudflared tunnel route dns <tunnel> wardend.example.com
  ```

`127.0.0.1:8787` works when cloudflared runs on the host or with host networking. In a container on a bridge network `127.0.0.1` is the container itself: point cloudflared at the host's address in that network and set `http_listen` to it, never to `0.0.0.0` facing the outside.

**Don't put Cloudflare Access on this hostname.** The app talks to wardend with plain requests, without a browser, and cannot pass an Access login. For the same reason make sure Bot Fight Mode or a Managed Challenge doesn't answer the app with an HTML page. The symptom: the app says the response is not signed with the server key from the QR, and the cloudflared log shows no requests to the origin. The fix: a WAF "Skip" rule for the hostname, or Bot Fight Mode off.

### Tailscale (not tested yet)

The project has not tested Tailscale yet. In principle the phone and the server join one tailnet, and the endpoint gets an HTTPS address inside it: `tailscale serve` can publish a local port under the machine's `ts.net` name with a certificate (see the Tailscale documentation for the exact command). Put that address into `public_url` and run the check of step 3 from the phone's side of the tailnet. The phone then gets cards only while it is connected to the tailnet.

### SSH tunnel (not tested yet)

An SSH tunnel needs an SSH client on the device that keeps the port forward open the whole time. That fits `wardenctl` on a laptop better than a phone:

```bash
ssh -N -L 8787:127.0.0.1:8787 you@server
```

Then pair with the loopback address: `sudo wardend pair start --url http://127.0.0.1:8787 --socket /var/lib/wardend/wardend.sock`. `pair start` warns that a phone can't reach a local address; for the laptop behind the tunnel that is fine, and wardenctl accepts a loopback `http://` address without a warning. On a phone the same needs an SSH client app with a port forward running in the background, and the app then talks plain HTTP to `127.0.0.1`; whether the published builds allow that has not been checked.

## 2. Put the address into public_url

In `/etc/wardend/config.json` (the installer asks for it as `--public-url`):

```json
{
  "http_listen": "127.0.0.1:8787",
  "public_url": "https://wardend.example.com"
}
```

The single-user trial install writes the placeholder `https://wardend.example.com` into `~/.wardend/config.json`: replace it with your address. Without `public_url` the QR code carries `http://127.0.0.1:8787`, and `wardend pair start` warns that the phone can't reach it.

A config wardend can't read would stop wardend, and the agent with it, so check it with [`wardend config-check`](../cli/#wardend-config-check) before the restart. The restart also restarts the agent:

```bash
sudoedit /etc/wardend/config.json
sudo wardend config-check --config /etc/wardend/config.json && sudo systemctl restart wardend
```

For a one-off pairing you can pass the address as a flag instead: `wardend pair start --url https://wardend.example.com`.

## 3. Check the address

From another machine, ideally from the network the phone uses:

```bash
curl -s 'https://wardend.example.com/v1/ping?nonce=12345678' -D -
```

Expect status `200`, the body `{"ok":true,"service":"wardend","supervisorId":"…","v":1,…}` and the header `X-Wardend-Signature`. The `supervisorId` must be the one the server reports:

```bash
sudo wardend status --socket /var/lib/wardend/wardend.sock | jq -r .supervisorId
```

A different id, an HTML page or no answer means something else answers at this address: fix that before pairing.

## 4. Pair

Pair from your own terminal on the server, never from a chat with the agent. `pair start`, `approve`, `reject` and `revoke` refuse to run under wardend's filter, so the agent can't pair a device for itself.

```bash
sudo wardend pair start --socket /var/lib/wardend/wardend.sock
```

It prints a QR code and waits. In the app open the **Connect** tab and tap **Scan QR**. The app shows the device fingerprint and waits for approval. On the server compare the fingerprint with the phone screen, then approve:

```bash
sudo wardend pair list --socket /var/lib/wardend/wardend.sock
sudo wardend pair approve <id> --socket /var/lib/wardend/wardend.sock
```

A pairing request expires after 10 minutes. For `wardenctl` pass the `wardenclaw://pair?…` link that `pair start` prints: `wardenctl pair '<link>'`.

## 5. Check the connection

- The app shows **Connected** and the mode of the server.
- `sudo wardend pair list --socket /var/lib/wardend/wardend.sock` lists the device among the trusted devices and shows whether the HTTP endpoint is up.

There is no test card yet. In `observe`, where the install starts, nothing asks for a signature, so the feed stays empty: that is expected, not a broken connection. The first cards come after the switch to `ticket` ([install, step 5](../install/#step-5-observe-check-the-forecast-then-ticket)). Before that switch make sure the phone is paired and online: without a trusted device every command that trips a rule waits for the TTL and fails.

A spare device keeps the agent going when the phone is away: right after the phone, pair [`wardenctl`](../cli/#external-approvers-and-test-automation) on a laptop with a link from another `pair start`.

## If the phone is lost

The lost phone holds a device key that can approve commands: revoke it right away. Pairing a new phone needs no second device, only your terminal on the server:

```bash
sudo wardend pair list --socket /var/lib/wardend/wardend.sock
sudo wardend pair revoke <deviceId prefix> --socket /var/lib/wardend/wardend.sock
sudo wardend pair start --socket /var/lib/wardend/wardend.sock     # scan the QR code with the new phone
sudo wardend pair approve <id> --socket /var/lib/wardend/wardend.sock
```

If you run the OpenClaw plugin `wardenclaw-gate`, revoke the phone there too: `pair revoke` changes wardend only, and the plugin trusts the devices of its own `trustedDeviceIds`. Delete the phone's id from `plugins.entries.wardenclaw-gate.config.trustedDeviceIds` in the gateway's `openclaw.json` (and from `devices`, if you listed it there) and save the file; the gateway reloads the plugin with the new list, and calls waiting for a decision are rejected. To cut the phone off the gateway entirely, also run `openclaw devices remove <deviceId>`.

Until a new device is paired, every command that needs a signature waits for the TTL and fails. If that takes a while, [step back to observe](../uninstall/#step-back-to-observe-instead) for the time being.

## If it does not connect

- **The app says the response is not signed with the server key from the QR.** Something between the phone and wardend answers instead of wardend: a Cloudflare challenge page, an Access login, a different server at that address, or a supervisor whose key changed. Check `/v1/ping` with curl as in step 3; if the key really changed, pair again.
- **`wardend: http 127.0.0.1:8787: … address already in use`** in the log. Another process holds the port. wardend keeps running without the endpoint (`status.http.error`), so the phone can't connect. Free the port or set `http_listen`.
- **`pair start` warns about a local `http://127.…` address.** `public_url` is not set: step 2.
- **Cards don't show up on a locked phone.** [Notifications on a locked phone](../notifications/).
