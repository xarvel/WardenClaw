# Exposing the wardend endpoint through Cloudflare Tunnel (done by a human)

wardend listens on HTTP only at `127.0.0.1:8787` (`http_listen`). The phone needs a public
HTTPS address: a separate hostname in an already running tunnel, for example `wardend.example.com`.
This is text only; nothing here has been applied.

## Why this is safe without Cloudflare Access

Trust does not rest on the tunnel. Every request from the app is signed with the device key from
`trusted_devices`, every ticket is signed separately and bound to the envelope digest, every
response from wardend is signed with the supervisor key that the phone pinned via QR. The tunnel
(and Cloudflare) can only fail to deliver or delay a message: it cannot inject a card, read a
decision as its own, or impersonate the server. Without a signature, `GET /v1/ping` (supervisor
identifier) and `POST /v1/pair` (works only while the one-time code from `wardend pair start` is
alive; 10 wrong codes kill all codes) are accessible.

**Do not add Cloudflare Access to this hostname**: the app connects with `fetch` without a browser
and cannot complete an Access login. For the same reason, verify that Bot Fight Mode / Managed
Challenge does not respond with an HTML page to app requests (symptom: the app shows "Response is
not signed by the server key", cloudflared logs show no requests to the origin). If it does, add
a WAF "Skip" rule for the hostname or disable Bot Fight Mode.

## 1. Hostname in the tunnel

**Tunnel managed from the dashboard (remote-managed).** Zero Trust -> Networks -> Tunnels ->
your tunnel -> Public Hostname -> Add a public hostname:

- Subdomain `wardend`, Domain `example.com`, Path empty;
- Service: `HTTP`, URL `127.0.0.1:8787` (cloudflared in host-network or directly on the host; if
  cloudflared is in a container with a bridge network, `127.0.0.1` is the container: use the host
  address on that network and bind `http_listen` to it, but not `0.0.0.0` outward);
- Additional settings -> HTTP Settings: nothing needs changing (long-poll 25 s fits within
  Cloudflare's 100 s timeout).

The dashboard will create a CNAME `wardend` -> `<tunnel-id>.cfargotunnel.com` automatically.

**Tunnel with a local `config.yml` (locally-managed).** Add a rule above the catch-all:

```yaml
ingress:
  - hostname: wardend.example.com
    service: http://127.0.0.1:8787
  # ... other rules ...
  - service: http_status:404
```

and the DNS record: `cloudflared tunnel route dns <tunnel> wardend.example.com`, then restart
cloudflared.

## 2. Address in the wardend config

In `~/.wardend/config.json` (read by wardend on start):

```json
{
  "http_listen": "127.0.0.1:8787",
  "public_url": "https://wardend.example.com"
}
```

`public_url` goes into the pairing QR; without it the QR contains `http://127.0.0.1:8787`, and
`wardend pair start` will warn that the phone cannot reach it. You can pass the address as a flag
for a one-off: `wardend pair start --url https://wardend.example.com`. After changing the config,
restart the unit that runs wardend (for the OpenClaw gateway, restart the gateway).

## 3. Verification

```bash
curl -s 'https://wardend.example.com/v1/ping?nonce=12345678' -D -
```

Expected: `200`, body `{"ok":true,"service":"wardend","supervisorId":"…","v":1,…}` and header
`X-Wardend-Signature`. `supervisorId` matches `wardend status | jq -r .supervisorId`.
Then `wardend pair start` on the server and "Scan QR" in the app (Connect tab).

## 4. Notifications (optional)

`"ntfy_url": "https://ntfy.sh/<long-random-topic-name>"` in the config: on every new card wardend
sends "New request to approve" to the topic (without the command or the host; at most once every
10 s). Subscribe to the topic in the ntfy app on your phone. Anyone who knows the topic name can
see when cards appear and can send pushes to it, so the name should be long and random. For a
self-hosted ntfy server with a token, use `"ntfy_token"`.
