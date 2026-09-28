// SPDX-License-Identifier: Apache-2.0
// WardenClaw next to agentsh (by Canyon Road): the block of the landing's "Compared" section and
// the page /compare/agentsh/. Same discipline as claims.ts: every cell is checked against a
// source before a release, and a statement that can't be traced is dropped or says "not verified".
//   agentsh cells: their own docs (https://www.agentsh.org/docs/, text generated 2026-06-29) and
//     the README of https://github.com/canyonroad/agentsh; `src` is the page that backs the cell.
//   WardenClaw cells: this repository; `ours` names the file.
// Their docs do not say what a TOTP code or a WebAuthn assertion is bound to, so nothing here says
// it is or is not bound to the operation.
// When agentsh ships a new version, re-read the sources, then change AGENTSH_VERSION and
// COMPARED_ON together. HTML is allowed in the cells (set:html); no em dashes.
import { REPO_URL } from "./config";

export const AGENTSH_VERSION = "v0.20.5";
export const COMPARED_ON = "2026-10-01";
export const AGENTSH_URL = "https://www.agentsh.org";
export const AGENTSH_REPO = "https://github.com/canyonroad/agentsh";
export const CORRECTIONS_URL = `${REPO_URL}/issues`;

const DOCS = `${AGENTSH_URL}/docs`;
const S = {
  intro: { label: "agentsh docs: overview", url: `${DOCS}/` },
  modes: { label: "agentsh docs: security modes", url: `${DOCS}/#security-modes` },
  scaling: { label: "agentsh docs: scaling with Canyon Road", url: `${DOCS}/#scaling` },
  platforms: { label: "agentsh docs: platform support", url: `${DOCS}/setup/#platform-overview` },
  auth: { label: "agentsh docs: authentication", url: `${DOCS}/features/#authentication` },
  steering: { label: "agentsh docs: steering", url: `${DOCS}/features/#redirect-steering` },
  policy: { label: "agentsh docs: policy model", url: `${DOCS}/policy-reference/#policy-overview` },
  starter: { label: "agentsh docs: starter policies", url: `${DOCS}/policy-reference/#starter-packs` },
  sandbox: { label: "agentsh docs: secure-sandbox", url: `${DOCS}/secure-sandbox/` },
  mcp: { label: "agentsh docs: MCP security", url: `${DOCS}/mcp-security/` },
  db: { label: "agentsh docs: database proxy", url: `${DOCS}/database-proxy/` },
  audit: { label: "agentsh docs: audit log integrity", url: `${DOCS}/observability/#audit-integrity` },
  readme: { label: "agentsh README", url: `${AGENTSH_REPO}#readme` },
  release: { label: `agentsh release ${AGENTSH_VERSION}`, url: `${AGENTSH_REPO}/releases/tag/${AGENTSH_VERSION}` },
};
interface Source { label: string; url: string }

export interface CompareRow {
  topic: string;
  wardenclaw: string;
  agentsh: string;
  /** Who is ahead on this row; "differs" when it is a trade-off and not a ranking. */
  ahead: "agentsh" | "WardenClaw" | "differs";
  /** Pages that back the agentsh cell. */
  src: Source[];
  /** Where the WardenClaw cell comes from in this repository. */
  ours: string;
  /** Shown in the compact table of the landing. */
  landing?: boolean;
}

export const AGENTSH_ROWS: CompareRow[] = [
  {
    topic: "What is intercepted",
    wardenclaw:
      "Program starts only: <code>execve</code> and <code>execveat</code> in the agent's process tree. A file write or a network connection made by a process that is already running is not gated.",
    agentsh:
      "File, network, process and signal activity, including subprocess trees; also Postgres-family database traffic and MCP tool calls.",
    ahead: "agentsh",
    src: [S.intro, S.db, S.mcp],
    ours: "site/src/claims.ts (SCOPE: \"Only exec is gated\"), daemon/seccomp.go",
    landing: true,
  },
  {
    topic: "Kernel mechanisms",
    wardenclaw: "seccomp user notification on exec. Linux 5.19 or newer.",
    agentsh:
      "seccomp, eBPF and FUSE in <code>full</code> mode, Landlock or ptrace where those are missing; <code>agentsh detect</code> reports which mode a host can enforce.",
    ahead: "agentsh",
    src: [S.modes],
    ours: "daemon/README.md, daemon/seccomp.go",
  },
  {
    topic: "Decisions a rule can make",
    wardenclaw: "Run, deny, or wait for a signed approval.",
    agentsh:
      "<code>allow</code>, <code>deny</code>, <code>approve</code>, <code>redirect</code>, <code>audit</code>, <code>soft_delete</code>. Redirect steers a command, a path or a connection to an approved alternative instead of failing it.",
    ahead: "agentsh",
    src: [S.policy, S.steering],
    ours: "daemon/policy/rules.go, site/src/docs/cli.en.md (policy modes)",
    landing: true,
  },
  {
    topic: "Platforms",
    wardenclaw: "Linux only.",
    agentsh:
      "Linux with full enforcement. Windows through WSL2 and macOS through a Lima VM run the Linux build. Native macOS (ESF+NE) scores 90% in their table and their README calls it alpha; native Windows scores 85% and waits for driver signing.",
    ahead: "agentsh",
    src: [S.platforms, S.readme],
    ours: "site/src/claims.ts (platforms)",
    landing: true,
  },
  {
    topic: "Maturity and packaging",
    wardenclaw:
      "A prototype in its first release, by one maintainer, with no independent security audit. One install script and release archives on GitHub.",
    agentsh:
      `${AGENTSH_VERSION}, Apache-2.0. Packages: .deb, .rpm, .apk, Arch, musl tarballs, a Homebrew cask for macOS. Starter policies, and an SDK (<code>@agentsh/secure-sandbox</code>) with adapters for hosted sandbox providers.`,
    ahead: "agentsh",
    src: [S.release, S.readme, S.starter, S.sandbox],
    ours: "site/src/claims.ts (eyebrow, description), AUTHORS, daemon/install.sh",
    landing: true,
  },
  {
    topic: "Fleet management",
    wardenclaw: "None. One wardend per machine, configured on that machine.",
    agentsh:
      "Watchtower, a separate Canyon Road product: central policies, approval routing to Slack, email and SMS, SIEM export, a kill switch. agentsh itself works standalone. We have not checked Watchtower's terms.",
    ahead: "agentsh",
    src: [S.scaling],
    ours: "daemon/README.md",
    landing: true,
  },
  {
    topic: "Where a human approves",
    wardenclaw:
      "The project's own phone app (Android, iOS): a push wakes it, and before it signs an allow for a dangerous or root command it asks for biometrics or the device passcode. Or <code>wardenctl</code> in a terminal.",
    agentsh:
      "Approval modes, quoted from their docs: \"<code>local_tty</code> - Terminal prompt (default)\", \"<code>totp</code> - Authenticator app codes\", \"<code>webauthn</code> - Hardware security keys (YubiKey)\", \"<code>api</code> - Remote approval via REST\". Routing to Slack, email and SMS is Watchtower.",
    ahead: "WardenClaw",
    src: [S.auth, S.scaling],
    ours: "app/src/core/safety.ts (needsOwnerCheck), relay/src/push.ts, site/src/docs/cli.en.md",
    landing: true,
  },
  {
    topic: "What an approval is",
    wardenclaw:
      "An Ed25519 signature made by a key stored on the phone, over the sha256 digest of the exact command envelope, with a single-use nonce and a ±60 s window. wardend verifies it before the kernel continues the exec.",
    agentsh:
      "A rule with <code>decision: approve</code> pauses the operation until a person answers; a timeout denies by default. Their docs do not describe what a TOTP code or a WebAuthn assertion is bound to, and we have not verified it.",
    ahead: "differs",
    src: [S.policy, S.auth],
    ours: "site/src/claims.ts (SCOPE: \"Forged and replayed approvals\"), protocol/README.md",
    landing: true,
  },
  {
    topic: "Audit log",
    wardenclaw:
      "Hash-chained journal, each record signed with the supervisor's Ed25519 key, so a third party checks it with the public key alone. Known gap: records cut from the end pass <code>wardend verify-journal</code>.",
    agentsh:
      "\"Audit logs can be chained with HMAC signatures for tamper detection\": HMAC-SHA256 or SHA512, verified with <code>agentsh audit verify</code> and the HMAC key, which can live in a KMS. Events export through OpenTelemetry.",
    ahead: "differs",
    src: [S.audit],
    ours: "daemon/journal/, site/src/claims.ts (SCOPE: \"A cut journal tail passes the check\")",
    landing: true,
  },
  {
    topic: "How the approver reaches the gate",
    wardenclaw:
      "wardend keeps one outbound WebSocket to a relay, so the machine needs no public address and no inbound port: wardend has no network listener, only a local unix socket. Messages are encrypted end to end (X25519, XChaCha20-Poly1305); the relay sees ciphertext. The cost: if the relay is unreachable no approval arrives and the command is denied, and the default relay is run by this project. Self-hosting it needs a Cloudflare account.",
    agentsh:
      "Local by default (a terminal prompt). Remote approval is the REST <code>api</code> mode of the agentsh server, or Watchtower. Their docs describe no relay service in between.",
    ahead: "differs",
    src: [S.auth, S.scaling],
    ours: "protocol/README.md (section 5), daemon/README.md (relay transport), relay/README.md",
  },
  {
    topic: "Keeping the agent away from root",
    wardenclaw:
      "The system install takes the agent's user out of the <code>sudo</code> and <code>docker</code> groups; root commands go through <code>wardend rootexec</code>, one command per approved card (read-only docker and systemctl run without one).",
    agentsh:
      "Policy rules on commands, files and signals, capability dropping, Landlock deny paths for container sockets. We found no equivalent of a per-command root broker in their docs; that is not a claim that none exists.",
    ahead: "differs",
    src: [S.modes, S.policy],
    ours: "site/src/docs/install.en.md, daemon/rootexec.go",
  },
];

export const AGENTSH_COPY = {
  subTitle: "agentsh, side by side",
  caption: `WardenClaw and agentsh, as of ${COMPARED_ON}, agentsh ${AGENTSH_VERSION}`,
  head: ["", "WardenClaw", "agentsh"],
  headFull: ["", "WardenClaw", "agentsh", "Ahead"],
  ahead: { agentsh: "agentsh", WardenClaw: "WardenClaw", differs: "Trade-off" },
  lead:
    "agentsh, by Canyon Road, is the closest tool in mechanics and the more complete one. It governs what a process does after it starts: files, network, signals, databases. WardenClaw gates one thing, the start of a program, and puts its effort into who says yes.",
  paragraphs: [
    "<strong>Where agentsh is ahead.</strong> Scope, platforms, packaging and age. If the agent's danger is a file it may overwrite or a host it may call from inside an allowed process, WardenClaw does not see it and agentsh does. agentsh can also redirect an operation instead of refusing it, runs outside Linux, and has a control plane for many machines.",
    "<strong>Where WardenClaw differs.</strong> The approval is a signature from a key on your phone over the digest of the exact command, checked by the gate, and the journal is signed so that anyone with the public key can verify it. The phone app with push is part of the open-source project. The machine opens no port to the network. The price is a dependency on a relay: when it is unreachable, commands that need a signature are denied.",
    "<strong>Which one to pick.</strong> You need rules for files and network, policy across a fleet, macOS or Windows, or audit export for compliance: agentsh. You run a self-hosted agent on a headless Linux machine and want a signed yes or no from your phone before a dangerous command starts: WardenClaw. They do not exclude each other. agentsh has a REST approval mode, but no integration between the two exists.",
  ],
  more: "Full table and sources",
  stamp: `As of ${COMPARED_ON}, agentsh ${AGENTSH_VERSION}, from their public docs and repository.`,
  corrections: "Something here is wrong or out of date? Open an issue",
  page: {
    title: "WardenClaw and agentsh compared",
    description:
      "An honest comparison of WardenClaw with agentsh by Canyon Road: what each intercepts, how a human approves, audit logs, platforms and maturity, with sources.",
    h1: "WardenClaw and agentsh",
    tableTitle: "Row by row",
    proseTitle: "In short",
    sourcesTitle: "Sources",
    sourcesLead:
      "Every statement about agentsh comes from its own documentation or repository. agentsh is a project of Canyon Road; WardenClaw is not affiliated with it. The pages behind each row:",
    oursLabel: "WardenClaw",
    back: "Back to the comparison on the landing page",
    method:
      "How this was made: we read the agentsh documentation (text generated 2026-06-29) and the repository README, and checked every WardenClaw cell against this repository. Nothing was measured or tested on agentsh. Where their docs are silent the cell says so.",
  },
};
