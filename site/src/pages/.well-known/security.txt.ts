// SPDX-License-Identifier: Apache-2.0
// /.well-known/security.txt (RFC 9116), built from src/config.ts so a new domain or repository
// needs no edit here. Expires is set at build time, 300 days ahead: the site is rebuilt on every
// deploy, and a site nobody deploys for that long should not look maintained.
import { ADVISORY_URL, PRIVATE_REPORTING, SECURITY_EMAIL, SITE_URL } from "../../config";

export function GET() {
  const expires = new Date(Date.now() + 300 * 24 * 3600 * 1000);
  expires.setUTCHours(0, 0, 0, 0);
  const lines = [
    `Contact: mailto:${SECURITY_EMAIL}`,
    // GitHub private vulnerability reporting, once Settings → Code security has it on.
    ...(PRIVATE_REPORTING ? [`Contact: ${ADVISORY_URL}`] : []),
    `Expires: ${expires.toISOString().replace(/\.\d{3}Z$/, "Z")}`,
    `Policy: ${SITE_URL}/security/`,
    "Preferred-Languages: en",
    `Canonical: ${SITE_URL}/.well-known/security.txt`,
  ];
  return new Response(lines.join("\n") + "\n", { headers: { "Content-Type": "text/plain; charset=utf-8" } });
}
