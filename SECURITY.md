# Security policy

WardenClaw is an execution gate: bypasses of the gate are the most important
bugs we can get, so thank you for reporting them privately.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a vulnerability.** If you
opened one by mistake, close it and send the report by email; we do not discuss vulnerabilities
in public issues.

Email the maintainer at **valiullin.arthur@gmail.com**. GitHub private vulnerability reporting is
not turned on for this repository yet, so the **Report a vulnerability** button of the Security
tab is not there; this file will say so when it is.

<!-- Maintainer: private vulnerability reporting is off (GitHub API: enabled false, 2026-09-29).
Turn it on in Settings > Code security, set PRIVATE_REPORTING = true in site/src/config.ts and
replace the paragraph above with:
"Report it through GitHub private vulnerability reporting: open the repository's Security tab
and choose Report a vulnerability. Only the maintainers see the report, and we can discuss it
and prepare a fix and an advisory there. If you can't use GitHub, email the maintainer at
valiullin.arthur@gmail.com." -->

Please include what you found, the affected version or commit, how to reproduce it and the
impact you expect. A proof of concept helps a lot, but there is no PGP key for reports yet:
send the description and the impact first, without a working exploit, and we agree on a
private way to pass the details.

What to expect:

- an acknowledgement within 7 days;
- an assessment and a plan within 30 days;
- coordinated disclosure: we publish a fix and an advisory, and credit you unless you prefer
  otherwise. We ask for up to 90 days before public disclosure; tell us if you need a
  different timeline.

## Supported versions

WardenClaw is pre-1.0. Security fixes go to the `main` branch and the latest release only.

## Scope

In scope:

- forging, replaying or redirecting an approval: ticket or envelope signature bypass,
  digest confusion, canonical JSON divergence between implementations, nonce or time window
  bypass, pairing takeover;
- getting a command executed without a valid approval (for wardend: seccomp filter escape,
  TOCTOU between approval and execution, exec paths that are not gated);
- bypassing the second factor (hardware key) where a rule requires it;
- tampering with the hash-chained journal without detection;
- leaking device or supervisor keys.

Out of scope:

- attacks that need root on the gated machine, or control of the phone's OS;
- the known limits of the single-user (same-uid) installation described in the
  documentation (`site/src/docs/tamper-resistance.en.md`, published under `/docs/`): use the hardened install for a real security boundary;
- denial of service by the operator's own agent (it can always stop working);
- vulnerabilities in third-party dependencies with no WardenClaw-specific impact (report them
  upstream; tell us if WardenClaw needs to react).
