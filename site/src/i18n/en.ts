// SPDX-License-Identifier: Apache-2.0
// English copy, the only locale for now. Strings may contain inline HTML: <code>, <strong>, <em>.
// Another locale is one more file of this shape (Dict below) with its own path, pages under that
// path and CLAIMS/SCOPE entries in ../claims.ts.
// Rule: no em dashes anywhere in the copy.
// Key claims (what needs a signature, root, OpenClaw, platforms) live in ../claims.ts.
import { CLAIMS } from "../claims";
// Features left out of the release (src/config.ts, FEATURES): feat() picks the text.
import { feat } from "../config";

const C = CLAIMS.en;

export const en = {
  lang: "en",
  // og:locale of the pages.
  locale: "en_US",
  path: "/",
  meta: {
    title: C.title,
    description: C.description,
  },
  skip: "Skip to content",
  nav: {
    problem: "Problem",
    how: "How it works",
    modes: "Modes",
    security: "Security",
    compare: "Compare",
    faq: "FAQ",
    docs: "Docs",
    install: "Install",
    menu: "Menu",
    // The docs menu on narrow screens, folded into a <details> above the page.
    docsMenu: "Documentation menu",
    sections: "Sections",
    github: "GitHub",
    // Headings of a docs page, in the sidebar and in the folded menu.
    toc: "On this page",
  },
  // Sidebar of the docs pages, in groups: path under the language root ("docs/" is the overview).
  docsNav: {
    groups: [
      {
        title: "Get started",
        pages: [
          { path: "docs/", label: "Overview" },
          { path: "docs/how-it-works/", label: "How it works" },
          { path: "docs/try/", label: "Try it in 5 minutes" },
          { path: "docs/install/", label: "Install" },
          { path: "docs/app/", label: "Get the app" },
          { path: "docs/connect-phone/", label: "Connect the phone" },
        ],
      },
      {
        title: "Guides",
        pages: [
          { path: "docs/notifications/", label: "Notifications on a locked phone" },
          { path: "docs/ios/", label: feat("appleWatch", "iPhone and Apple Watch", "iPhone app") },
          { path: "docs/apns/", label: "Push notifications" },
          { path: "docs/uninstall/", label: "Uninstall" },
        ],
      },
      {
        title: "Reference",
        pages: [{ path: "docs/cli/", label: "CLI reference" }],
      },
      {
        title: "Security",
        pages: [
          { path: "docs/threat-model/", label: "Threat model" },
          { path: "docs/tamper-resistance/", label: "Why the model can't turn it off" },
          { path: "security/", label: "Report a vulnerability" },
        ],
      },
    ],
  },
  // While REPO_PUBLIC is false (src/config.ts), in place of every GitHub link.
  repoClosed: "The code opens with the first release",
  hero: {
    eyebrow: C.eyebrow,
    title: C.h1,
    // Project slogan. Short, no exclamation mark.
    slogan: C.slogan,
    sub: C.sub,
    points: [
      "<strong>Below the agent.</strong> The kernel sees every program the agent starts, including the ones launched by scripts and child processes.",
      "<strong>A signature, not a button.</strong> Ed25519 over the exact command, made on your phone. The agent can't produce one.",
      "<strong>Quiet until it matters.</strong> Routine work runs and is journaled; your phone gets what trips a rule. Keep your sandbox: this works on top of it.",
    ],
    facts: `Approve on Android, iPhone${feat("appleWatch", ", Apple Watch")} or in a terminal. Any agent harness; the OpenClaw plugin is optional.`,
    imgAlt: "Illustration: commands queue up in front of a padlock on the agent's server; the approval travels to a phone and comes back sealed with a signature.",
    // Both buttons lead to pages of this site (GitHub is the pill in the header).
    ctaTry: "Try it in 5 minutes",
    ctaHow: "How it works",
    note: "The code opens with the first release. Until then the docs describe the prototype as it is.",
    mock: {
      label: "Example approval card on the phone",
      badge: "EXEC · package install",
      title: "Install an npm package",
      cmd: "npm install left-pad@1.3.0",
      meta: "in /srv/projects/app · user agent · parent: bash ← claude",
      risk: "Risk 34 / 100",
      allow: "Allow once",
      deny: "Deny",
      foot: "Signs sha256 digest 9f3c…e1a0 with this device's Ed25519 key",
    },
  },
  // Right under the hero: where WardenClaw sits next to a sandbox and the harness's own approvals.
  layers: {
    kicker: "Where it fits",
    title: "Sandbox, built-in approvals, WardenClaw: three different jobs",
    covers: "What it covers",
    open: "What it leaves open",
    items: [
      {
        name: "Sandbox",
        who: "Claude Code and Codex sandboxes, Docker",
        covers: "Limits on where any code can reach: files, network, system calls, including code inside an interpreter.",
        open: "Whether this particular command should run at all.",
      },
      {
        name: "Built-in approvals",
        who: "Claude Code, Codex, OpenClaw",
        covers: "A question before each tool call the agent reports, answered with a button, a chat message or an allow-list.",
        open: "The answer is not signed and is checked on the same host as the agent. A child process of an approved script never shows up.",
      },
      {
        name: "WardenClaw",
        who: "Under any agent harness on Linux",
        covers: "Every program start in the agent's tree, checked in the kernel. The risky ones wait for a signature made off the server.",
        open: "What a running process does inside itself: interpreters, file writes, network. That stays with the sandbox.",
      },
    ],
    conclusion: "Use them together: the sandbox limits how far anything can reach, WardenClaw asks you about the risky steps inside those limits.",
  },
  // Second screen: the lists live in ../claims.ts (SCOPE).
  scope: {
    kicker: "Scope",
    title: "What it closes, and what it doesn't yet",
    closesTitle: "Closes",
    notClosedTitle: "Not closed yet",
    link: "The vector table and its tests",
    linkPath: "docs/tamper-resistance/#vector-table",
    threatLink: "Threat model",
  },
  problem: {
    kicker: "The problem",
    title: "The approval lives on the host it guards, and the agent can reach it",
    items: [
      {
        title: "Nobody at the screen",
        text: "An agent on a server keeps working while you sleep. Its permission prompt waits at a screen you are not looking at, so people widen the allow-list or switch on an auto mode, and whatever passes runs with the agent's rights.",
      },
      {
        title: "A button the agent's side trusts",
        text: "An approval is usually just an RPC call. Any client with the right scope, or a <code>/approve</code> typed in chat, resolves it. There is no signature, so the gate can't tell your \"yes\" from one produced inside the loop.",
      },
      {
        title: "A reviewer inside the blast radius",
        text: "Server-side auto-reviewers run on the same host, often on the same model, as the agent they review. If the host is compromised, it approves itself.",
      },
      {
        title: "Hooks only see what they are shown",
        text: "A plugin hook guards only the calls the agent framework chooses to report. A child process started by an approved script never shows up there.",
      },
    ],
  },
  how: {
    kicker: "How it works",
    title: "One signed decision per risky command, enforced below the agent",
    lead:
      "Two gates share one envelope format. <strong>wardend</strong> checks every program start in the agent's process tree at the syscall level. The optional <strong>OpenClaw plugin</strong> gates OpenClaw's own tool calls. Both send cards to the phone and accept nothing but a valid signature.",
    // The short flow; the two detailed diagrams live in docs/how-it-works (with their alt texts).
    flowLabel: "One command, in five steps",
    flow: [
      { t: "Agent", d: "starts a program, itself or through a script" },
      { t: "Kernel and wardend", d: "stop the start and check the rules; if none trips, it runs and is journaled" },
      { t: "Phone", d: "shows the card of a start that tripped a rule" },
      { t: "You", d: "sign allow or deny with the phone's key" },
      { t: "wardend", d: "checks the signature and answers the kernel: <code>CONTINUE</code> or <code>EPERM</code>" },
    ],
    detailLink: "Detailed diagrams",
    steps: [
      {
        title: "Freeze",
        text: "wardend runs the agent under a seccomp user-notification filter. Every <code>execve</code> in the tree stops in the kernel while the supervisor reads argv, cwd, the real binary and the parent chain from the stopped process and checks them against the rules. What trips no rule continues at once and is journaled. The plugin gates OpenClaw's tool calls (exec, Bash, Write, Edit) through <code>before_tool_call</code>.",
      },
      {
        title: "Describe",
        text: "A command that trips a rule becomes a canonical envelope and a sha256 digest, byte-identical in Go, JavaScript and TypeScript (shared test vectors). wardend sends it to the phone through a relay over one outbound WebSocket, encrypted end to end. Cards and decisions are signed, so the relay can't forge them.",
      },
      {
        title: "Sign",
        text: "The app recomputes the digest itself, shows what the command does, and signs <em>allow</em> or <em>deny</em> with the device's Ed25519 key. If the digest doesn't match the envelope, the only thing it will sign is deny.",
      },
      {
        title: "Verify and run",
        text: "wardend checks the trusted device, a ±60 s time window, a single-use nonce and the digest, then answers the kernel with CONTINUE or EPERM. What the approved command starts is checked on its own; only the same tool family passes for 10 minutes (<code>ssh</code> under <code>scp</code>). Every exec and decision lands in a hash-chained, signed journal.",
      },
    ],
  },
  modes: {
    kicker: "Who answers on the phone",
    title: "Start by pressing buttons. Hand over the routine when the numbers say so.",
    items: [
      {
        name: "Manual",
        tag: "You decide",
        text: "Every card waits for you. One line in plain words, a risk color, two big buttons: Allow once or Deny. The exact command, argv and process chain are one tap away.",
      },
      {
        name: "Observe",
        tag: "Judge suggests",
        text: "A judge proposes a verdict with a reason and a 0 to 100 risk score, and you still press the button. The journal records whether it matched you. Watch it for a while before you trust it.",
      },
      {
        name: "Autopilot",
        tag: "Judge decides, within rules",
        text: "The judge allows below your risk threshold and denies what it finds dangerous; everything else stays with you. A deterministic block-list (<code>rm -rf</code> on roots, <code>dd</code>, <code>mkfs</code>, <code>curl | sh</code>, gateway config, secrets) goes to you before any model sees it. Text aimed at the reviewer inside a command means deny. Three denials in a row fall back to Observe.",
      },
    ],
    // Three independent switches (site/src/docs/cli.en.md "Modes" and "Policy modes"; the app's Mode tab).
    switchesTitle: "Three switches, set separately",
    defaultTag: "default",
    switches: [
      {
        name: "What needs a signature",
        where: "server · <code>policy_mode</code>",
        opts: [
          { v: "tripwire", def: true, text: "only a start that trips a rule" },
          { v: "root", def: false, text: "every start outside an approved tree and every delegating spawn" },
        ],
      },
      {
        name: "Whether the answer is enforced",
        where: "server · <code>mode</code>",
        opts: [
          { v: "observe", def: true, text: "nothing waits; the journal records what would need a card" },
          { v: "deny-list", def: false, text: "only the <code>deny_always</code> rules block" },
          { v: "ticket", def: false, text: "what needs a signature waits for one" },
        ],
      },
      {
        name: "Who answers on the phone",
        where: "app · Mode tab",
        opts: [
          { v: "Manual", def: true, text: "you" },
          { v: "Observe", def: false, text: "the judge suggests, you press" },
          { v: "Autopilot", def: false, text: "the judge decides within your rules" },
        ],
      },
    ],
    switchesNote: "The server's observe and the phone's Observe are different things: the first enforces nothing, the second only means the judge suggests.",
    note: `The judge runs on the phone's side${feat("phoneJudge", ", on a model you pick (on-device or your own endpoint)", ": the app asks a model at a URL you set")}; the agent host never sees its prompt, its keys or its journal. Stop in the Mode tab switches back to Manual at once, and autopilot turns itself off after an hour.`,
  },
  security: {
    kicker: "Security, honestly",
    title: "What it guarantees and what we measured",
    failTitle: "Fail-closed by default",
    fail: [
      "No signed <em>allow</em> within the TTL (120 s): the exec gets <code>EPERM</code>.",
      "The supervisor dies: every exec in the tree gets <code>ENOSYS</code> until the service restarts.",
      "The queue is full (64 pending): <code>EAGAIN</code>, never an automatic allow.",
      "Plugin hook times out, is aborted or throws: the tool call is blocked.",
      "Forged, replayed, stale or foreign-key tickets are rejected (covered by tests).",
      "A process in the tree can't install its own notification filter to answer \"yes\" around wardend.",
    ],
    toctouTitle: "TOCTOU: the race the kernel leaves open",
    toctouText:
      "The kernel copies execve arguments after the supervisor answers, so another thread can swap argv in between. We ran a hostile binary that flips <code>argv[1]</code> between <code>SAFE-ARG</code> and <code>EVIL-ARG</code> in a loop, 40 runs per mode, with the device approving only <code>SAFE-ARG</code>.",
    toctouCaption: "Adversarial argv swap, 40 runs per mode",
    toctouHead: ["Mode", "Approved", "Ran with swapped argv", "Killed by post-check"],
    toctouRows: [
      ["off", "5", "4", "n/a"],
      ["poll", "7", "3", "7"],
      ["stop", "8", "0", "6"],
    ],
    toctouAfter:
      "<strong>stop</strong> (the default for commands that need a signature) sends SIGSTOP to the caller before CONTINUE. The new image halts before its first instruction, <code>/proc</code> exe and cmdline are compared with the signed envelope, and a mismatch is killed. A swapped program never executes a single instruction. Cost: about 1 to 1.5 ms per approved root.",
    tamperTitle: "Can the model turn wardend off?",
    tamperText:
      "Only if it runs as the same user. A malicious model that controls the harness shares that user's rights, so in a same-user install it could signal, ptrace or overwrite wardend without any exec. The strong guarantee needs a hardened install: wardend as a root system service, root-owned binary and config, the harness as an unprivileged child under its own user. That is the install we recommend. Every vector it closes is covered by a test.",
    tamperLink: "Why the model can't turn it off",
    installLink: "Recommended: hardened install",
    installNote: "One command, hardened by default, starts in observe mode. The release signature is checked before anything is written.",
  },
  numbers: {
    kicker: "Numbers",
    title: "Measured on a Raspberry Pi 5",
    items: [
      { value: "+0.35–0.55 ms", label: "per exec under the supervisor (1000 × <code>/bin/true</code>: 0.51 s → 1.06 s)" },
      { value: "3,162 → 819", label: "cards a day, <code>root</code> mode → <code>tripwire</code>, replaying a 25-hour journal of a busy agent (98,053 execs; peak 34 cards in 2 minutes)" },
      { value: "~20 ms", label: "added to a whole claude-cli turn" },
      { value: "310 µs", label: "median kernel receive-to-reply inside the supervisor (p95 510 µs)" },
    ],
  },
  compare: {
    kicker: "Compared",
    title: "Close neighbours, and where WardenClaw differs",
    caption: "WardenClaw compared with related tools",
    head: ["", "WardenClaw", "agentsh", "grith", "Claude Code Remote Control", "OpenClaw approvals"],
    rows: [
      ["Where the gate sits", "Kernel (seccomp on execve) + tool hook", "Kernel (seccomp user notify, Landlock, FUSE, eBPF)", "ptrace + seccomp", "Agent's permission prompt", "Gateway tool approvals"],
      ["Where you approve", `Phone app${feat("appleWatch", ", Apple Watch")} or <code>wardenctl</code> in a terminal`, "Local TTY, TOTP, WebAuthn, API", "Telegram, Slack, Discord, WhatsApp buttons", "Phone or web", "Mobile app, Control UI, <code>/approve</code> in chat"],
      ["Decision is a signature the gate verifies", "Yes: Ed25519, key off the host", "Not documented: approval is a terminal prompt, a TOTP code, a WebAuthn key or a REST call", "Nonce + HMAC webhook", "No", "No"],
      ["Automatic judge", "On the phone side, outside the host", "Policy rules", "LLM scoring on the host", "No", "Server-side reviewer on the gateway host"],
      ["Audit trail", "Hash chain + Ed25519 signatures, verifiable by a third party", "HMAC-chained audit", "Not assessed", "Not assessed", "Approval history (30 days)"],
      ["Status", "Prototype", "v0.20.5, Apache-2.0", "v0.3.4, MPL-2.0 + paid tiers", "Generally available", "Built into OpenClaw"],
    ],
    note: "Based on public docs and repositories as of September 2026. agentsh is the closest in mechanics and covers far more than exec; the detailed comparison follows.",
  },
  components: {
    kicker: "Components",
    title: "Three pieces, one envelope",
    items: [
      {
        name: "wardend",
        lang: "Go",
        text: "Supervisor on seccomp user notification. No cgo, no libseccomp, Linux 5.19+; in the recommended install a root system service with the agent as its own user. Tripwire rules with harness packs (claude-cli, OpenClaw) or the older root mode, TOCTOU stop-verify, the relay link and pairing for the phone, a signed journal and <code>wardend replay</code>.",
        link: "wardend",
      },
      {
        name: "wardenclaw-gate",
        lang: "OpenClaw plugin",
        text: "Optional. Gates OpenClaw's own tool calls through <code>before_tool_call</code> in observe or enforce mode, verifies signed decisions and keeps its own signed journal. It can also relay wardend exec cards through the gateway.",
        link: "gate",
      },
      {
        name: "WardenClaw app",
        lang: "Expo · TypeScript",
        text: `Pairs with wardend by QR code as a device with its own Ed25519 key in the phone's secure storage. Feed, Mode, Journal and Connection tabs; ${feat("phoneJudge", "an on-device risk judge", "a risk judge on a model at a URL you set")}; ${feat("hardwareKey", "an optional YubiKey co-signature over NFC; ")}an append-only journal with a hash chain. Android and iPhone${feat("appleWatch", ", with an Apple Watch app that approves on its own")}.`,
        link: "app",
      },
    ],
    // Link text of each component's source, {name} is the component.
    sourceOf: "{name} source",
  },
  status: {
    kicker: "Status",
    title: "Prototype, running on a Raspberry Pi 5 and a Pixel 9 Pro",
    // The screenshot is shown only while public/brand/app-feed.webp exists (Landing.astro): a
    // screenshot of the current app, in the language of this page.
    shotAlt: "The WardenClaw app on a Pixel 9 Pro: a feed of three exec cards (ls -la /tmp, rm -rf / --no-preserve-root, and a command with a note addressed to the AI reviewer), each with Allow and Deny buttons.",
    shotCaption: "The prototype app on a Pixel 9 Pro.",
    doneTitle: "Works today",
    done: [
      "Kernel gate for the whole tree: tripwire rules decide which starts need a signature",
      "Signed tickets end to end: phone → wardend → execve, with signed responses",
      "TOCTOU stop-verify, fail-closed paths, hash-chained journals",
      `Phone app with Manual, Observe and Autopilot; ${feat("appleWatch", "Apple Watch and wardenctl as approvers", "wardenctl as an approver in a terminal")}`,
    ],
    nextTitle: "Next",
    next: [
      "Programs known by their sha256, not only by name (busybox applets, renamed copies)",
      "One card when the plugin and the kernel see the same action",
      "Always-on background connection (a dev build with a foreground service)",
    ],
  },
  faq: {
    kicker: "FAQ",
    title: "Questions people ask first",
    items: [
      {
        q: "Why not just use a sandbox?",
        a: "Keep it. A sandbox limits where any code can reach, including code inside interpreters that tripwire doesn't see. It doesn't decide whether this particular command should run, and its own prompt is answered on the same host. WardenClaw asks about the risky steps inside those limits, with a signature made off the host. The two stack; isolation around the gate (Landlock) is on the roadmap.",
      },
      {
        q: "What if I lose my phone?",
        a: "The agent stops; it doesn't run free. Without a signature nothing new executes. On the host, run <code>wardend pair revoke</code> for that device (or remove it from <code>trusted_devices</code>, and from <code>trustedDeviceIds</code> if you use the plugin) and pair a new phone. The signing key lives in the phone's secure storage, never on the agent's host.",
      },
      {
        q: "Do I need root?",
        a: C.root + " The gate itself is <code>no_new_privs</code> plus a seccomp filter with a notification listener: no cgo, no libseccomp, Linux 5.19 or newer.",
      },
      {
        q: "Does it work on macOS?",
        a: "Not yet. The gate is built on Linux seccomp user notification. A macOS backend is planned, with no date.",
      },
      {
        q: "Won't I drown in prompts?",
        a: C.what + " How many cards that makes depends on the agent: replaying a busy agent's 25-hour journal gave 819 a day (3,162 in the older <code>root</code> mode). Run your own journal through <code>wardend replay</code> before you enforce, and let Autopilot take the routine.",
      },
      {
        q: "Is it only for OpenClaw?",
        a: "No. wardend supervises any Linux process and ships harness packs for claude-cli and OpenClaw. " + C.transport,
      },
    ],
  },
  footer: {
    product: "Product",
    docs: "Docs",
    security: "Security",
    project: "Project",
    try: "Try it in 5 minutes",
    app: "Get the app",
    connect: "Connect the phone",
    cli: "CLI reference",
    tamper: "Why the model can't turn it off",
    uninstall: "Uninstall",
    report: "Report a vulnerability",
    license: "Licenses: wardend AGPL-3.0, app GPL-3.0, plugin and protocol Apache-2.0, docs CC BY 4.0. WardenClaw is a trademark.",
    privacy: "No trackers, no cookies, no third-party requests.",
    made: "WardenClaw is an independent open-source project.",
  },
};

export type Dict = typeof en;
