// SPDX-License-Identifier: AGPL-3.0-or-later
// WardenClaw relay, the Worker entry (protocol/README.md): routes a channel's socket and side door
// to the Durable Object named by the supervisorId. Nothing is decided here.
//
//   GET /v1/ping                       liveness, no authentication
//   GET /v1/ws/<supervisorId>          WebSocket upgrade (challenge, hello, frames)
//   GET /v1/frames/<supervisorId>/<id> one undelivered frame for the Notification Service Extension

import { Channel, json, type Env } from "./channel";
import { ID_RE, MSG_ID_RE, PROTOCOL } from "./frames";

export { Channel };

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/v1/ping") {
      return json({ ok: true, service: "wardenclaw-relay", protocol: PROTOCOL, now: Date.now() });
    }
    let m = /^\/v1\/ws\/([0-9a-f]{64})$/.exec(url.pathname);
    if (m) {
      if (req.method !== "GET") return json({ ok: false, reason: "method_not_allowed" }, 405);
      const sid = m[1] as string;
      return env.CHANNEL.get(env.CHANNEL.idFromName(sid)).fetch(new Request(`https://channel/ws?sid=${sid}`, req));
    }
    m = /^\/v1\/frames\/([0-9a-f]{64})\/([0-9a-f]{32})$/.exec(url.pathname);
    if (m) {
      if (req.method !== "GET") return json({ ok: false, reason: "method_not_allowed" }, 405);
      const [sid, id] = [m[1] as string, m[2] as string];
      if (!ID_RE.test(sid) || !MSG_ID_RE.test(id)) return json({ ok: false, reason: "not_found" }, 404);
      return env.CHANNEL.get(env.CHANNEL.idFromName(sid)).fetch(new Request(`https://channel/frame?sid=${sid}&id=${id}`, { headers: req.headers }));
    }
    return json({ ok: false, reason: "not_found" }, 404);
  },
} satisfies ExportedHandler<Env>;
