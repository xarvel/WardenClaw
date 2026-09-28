// SPDX-License-Identifier: Apache-2.0
// Key claims about the product, in one place. The landing (meta, hero, FAQ, status) takes them
// from here, and the build checks that README.md carries the English lines of README_CLAIMS
// (astro.config.mjs). Before every release, check each line against the code and the docs named
// next to it. Plain text only (no HTML, no Markdown): README and the site use the same words.
// The exception is SCOPE (what is closed and what is not): there `backticks` mark code, as in
// Markdown, and the site renders them with code() below.
// Rule: no em dashes.
// Text about a feature left out of the release goes through feat()/only() of config.ts (FEATURES).
import { feat, only, type Feature } from "./config";

export const CLAIMS = {
  en: {
    slogan: "Take back control.",
    eyebrow: "Open-source prototype · Linux 5.19+",
    title: "WardenClaw: two-factor approval for AI agents",
    h1: "Two-factor approval for AI agents.",
    // What needs a signature: policy_mode tripwire is the default (site/src/docs/cli.en.md, "Policy modes").
    description:
      "A kernel-level exec gate for AI agents on Linux. Risky commands wait for an Ed25519 signature from your phone, made with a key that never lives on the agent's host; the rest runs and is journaled. Fail-closed. Prototype.",
    sub:
      "WardenClaw stops the risky commands of an AI agent on your Linux server right in the kernel and runs them only after you sign them on your phone. The key never lives on the server, so even a hijacked agent can't approve itself.",
    what:
      "By default only commands that trip a rule wait for your signature, such as remote execution, package installs, publishing, reading secrets, destructive commands or changes to the agent's settings. Everything else runs and is journaled.",
    // Hardened install: site/src/docs/install.en.md, site/src/docs/tamper-resistance.en.md.
    root:
      "The recommended install runs wardend as a root system service and the agent as its own unprivileged user, so the model can't turn the guard off. A single-user trial needs no root, but there the model could stop wardend.",
    // http_listen and public_url: site/src/docs/connect-phone.en.md; the plugin: plugin/README.md.
    transport:
      "wardend serves the phone app itself over its own HTTP endpoint. The OpenClaw plugin is optional: it adds cards for OpenClaw's own tool calls.",
    platforms: `Linux 5.19 or newer with systemd. Approve on Android, iPhone${feat("appleWatch", ", Apple Watch")} or in a terminal with wardenctl.`,
    // FEATURES.hardwareKey. require_hardware: protocol/HARDWARE.md; what a touch proves: crypto
    // review of 2026-09-28, finding 5.
    secondFactor:
      "A YubiKey tap over NFC can be required for the rules you choose. It proves that a person touched the key, not what they saw.",
  },
};

// English claims that README.md must contain word for word (line breaks and spaces aside).
export const README_CLAIMS: (keyof typeof CLAIMS.en)[] = [
  "h1", "what", "root", "transport", "platforms", ...only("hardwareKey", "secondFactor" as const),
];

// README.md text of the features left out of the release (FEATURES in config.ts), word for word
// (line breaks and spaces aside). While a feature is out README.md carries `release` and not
// `full`; to bring it back set the flag and put `full` in place of `release`. The build checks
// both ways. `full` is the README.md text of 2026-09-28, before the release left the features out.
export const README_FEATURES: { feature: Feature; release: string; full: string }[] = [
  {
    feature: "appleWatch",
    release: "Approve on Android, iPhone or in a terminal with wardenctl.",
    full: "Approve on Android, iPhone, Apple Watch or in a terminal with wardenctl.",
  },
  {
    feature: "hardwareKey",
    release: "- Not closed yet: tripwire knows programs by name",
    full: "- A YubiKey tap over NFC can be required for the rules you choose. It proves that a person touched the key, not what they saw.\n- Not closed yet: tripwire knows programs by name",
  },
  {
    feature: "appleWatch",
    release: "the **WardenClaw app** (Expo / React Native, Android and iOS):",
    full: "the **WardenClaw app** (Expo / React Native, Android and iOS, with an Apple Watch app):",
  },
  {
    feature: "hardwareKey",
    release: "approval cards, signing,",
    full: "approval cards, signing, YubiKey over NFC,",
  },
  {
    feature: "phoneJudge",
    release: "risk judge on a model at a URL you set, journal",
    full: "on-device risk judge, journal",
  },
  {
    feature: "hardwareKey",
    release: "decision ticket, transport and pairing",
    full: "decision ticket, hardware second factor, transport and pairing",
  },
];

// What the product closes and what it doesn't yet: the "Closes / Not closed yet" block of the
// landing. Sources: closes from site/src/docs/tamper-resistance.en.md (vector table, every
// "Closed" cell has a test) and the TOCTOU section of the landing; notClosed from
// site/src/docs/cli.en.md (policy modes), tamper-resistance (same-user install) and the open
// findings of the crypto review of 2026-09-28 (4: environment, 5: YubiKey, only while
// FEATURES.hardwareKey is on, 6: journal). Finding 4 is closed in part: the card shows the
// variables of the list (protocol/README.md, section 3; daemon/envelope/env.go), the rest of the
// environment is signed only through envHash; the line says what is left.
// When a finding is closed in the code, drop its line here in the same commit.
interface Item { title: string; text: string }
export const SCOPE: Record<"en", { closes: Item[]; notClosed: Item[] }> = {
  en: {
    closes: [
      {
        title: "Every program start in the agent's tree.",
        text: "Each `execve` and `execveat` stops in the kernel and is checked against the rules, including starts from scripts and child processes. Starts through `memfd_create`, `fexecve`, a direct call of `ld.so` or a 32-bit call are gated or refused too.",
      },
      {
        title: "Forged and replayed approvals.",
        text: "A decision is an Ed25519 signature over the exact command with a single-use nonce and a ±60 s window, made with a key that never lives on the agent's host. The agent can't approve its own card through wardend's HTTP endpoint.",
      },
      {
        title: "A command swapped after approval.",
        text: "For a signed command wardend stops the new program before its first instruction and compares it with the signed envelope; a mismatch is killed.",
      },
      {
        title: "The model turning the guard off, in the hardened install.",
        text: "wardend runs as a root system service and the agent as its own user, so the kernel refuses the agent's signals, ptrace and memory writes against wardend, and its binary, config, key and unit belong to root. `redteam/hardened-check.sh` checks this as the agent user.",
      },
    ],
    notClosed: [
      {
        title: "Tripwire knows programs by name and by list.",
        text: "A multi-call binary (`busybox cat`, `busybox rm`), a file reader outside the list (`hexdump`) or a system program copied under another name runs as an ordinary start: journaled, no card. `--policy-mode root` asks about every new command instead, at the cost of many more cards.",
      },
      {
        title: "Only exec is gated.",
        text: "Interpreters (`python -c`, `node -e`), shell redirections, `LD_PRELOAD`, file writes and network inside a running process are not. Work handed to a daemon or another host (`docker`, `ssh`, `systemd-run`) is out of sight once approved, and work started outside wardend's tree (another login, cron) is not seen at all. Keep a sandbox around the agent.",
      },
      {
        title: "A single-user trial can be turned off.",
        text: "Without the hardened install wardend and the agent share a user, so the model can stop or rewrite wardend without a single exec.",
      },
      {
        title: "No post-check without a card.",
        text: "Starts that need no card are not re-checked after the kernel continues them. The TOCTOU stop-and-compare covers only commands that were signed.",
      },
      {
        title: "Same-inode swaps.",
        text: "Changing a file's content in place between check and exec is not caught; the binary hash is not part of the envelope yet.",
      },
      {
        title: "Only listed variables are shown.",
        text: "The card shows the environment variables from a list of those that change what a program does: the loader, shells, interpreters, git, proxies. The rest of the environment, including anything that looks like a secret, is signed only as a hash, so a variable outside the list can change an approved command without your seeing it.",
      },
      ...only("hardwareKey", {
        title: "A hardware key proves a touch.",
        text: "The optional YubiKey co-signature shows that a person touched the key at that moment, not what they saw: a compromised phone could show one card and ask the touch for another.",
      }),
      {
        title: "A cut journal tail passes the check.",
        text: "`wardend verify-journal` catches a record removed from the middle, not the last records removed from the end.",
      },
    ],
  },
};

// Plain text with `backticks` as HTML: the text is escaped, backticks become <code>.
export function code(s: string): string {
  const esc = s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return esc.replace(/`([^`]+)`/g, "<code>$1</code>");
}
