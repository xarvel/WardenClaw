# wardenclaw-relay

The untrusted carrier between `wardend` and the WardenClaw app: [`protocol/README.md`](../protocol/README.md), section 5.
A Cloudflare Worker with one Durable Object per supervisor channel. It routes end-to-end
encrypted frames by identity, queues what could not be delivered yet, and sends the push that
wakes a closed app. It reads nothing inside a frame's `body`.

```
src/index.ts     routes: /v1/ping, /v1/ws/<supervisorId>, /v1/frames/<supervisorId>/<id>
src/channel.ts   the Durable Object: hello, trusted devices, pairing window, queue, acks, resume, push tokens
src/frames.ts    frame shapes, limits and validation
src/push.ts      APNs (ES256 JWT) and FCM (service account) senders
src/crypto.ts    sha256, base64url, Ed25519 verification (WebCrypto)
src/canonical.ts canonical JSON, the same bytes as the plugin and the app
test/            vitest inside workerd (@cloudflare/vitest-pool-workers), Apple intercepted with fetchMock
```

## Run

```shell
npm ci
npm test            # workerd locally, no network
npm run typecheck
npm run dev         # http://localhost:8787
```

## Deploy

`relay.wardenclaw.dev` is a custom domain of the Worker (`wrangler.toml`); Cloudflare issues the
certificate. Secrets, never in the repository:

```shell
wrangler secret put APNS_KEY_P8          # the .p8 contents
wrangler secret put APNS_KEY_ID
wrangler secret put APNS_TEAM_ID
wrangler secret put APNS_TOPIC           # com.wardenclaw.app
wrangler secret put FCM_SERVICE_ACCOUNT  # the service account JSON
wrangler deploy
```

Without the push secrets the relay routes and queues; a closed app learns about cards when it is
opened. The `relay` workflow runs the tests on every change and deploys `main` with
`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` from the repository secrets.

## Self-hosting

The same Worker on your own account and hostname: change `pattern` in `wrangler.toml`, deploy,
and point `relay_url` in `/etc/wardend/config.json` at it. The app takes the relay address from
the pairing QR.
