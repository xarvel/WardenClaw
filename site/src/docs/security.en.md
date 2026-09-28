---
title: Security policy
description: How to report a vulnerability in WardenClaw privately, what is in scope, how fast we answer and how to encrypt a report.
---

# Security policy

WardenClaw is an execution gate: a way around the gate is the most important bug you can find. Thank you for reporting it privately.

## How to report

**Please do not open a public issue, discussion or pull request for a vulnerability.**

<p data-if="no-advisories">Write to <a href="mailto:%SECURITY_EMAIL%">%SECURITY_EMAIL%</a>. GitHub private vulnerability reporting is not turned on for this repository yet.</p>

<p data-if="advisories">Report it through <strong>GitHub private vulnerability reporting</strong>: <a href="%ADVISORY_URL%">open a private report</a> (the <strong>Security</strong> tab of the repository, <strong>Report a vulnerability</strong>). Only the maintainers see it, and we prepare the fix and the advisory there. By email: <a href="mailto:%SECURITY_EMAIL%">%SECURITY_EMAIL%</a>.</p>

Please include what you found, the affected version or commit, how to reproduce it and the impact you expect. A proof of concept helps a lot.

## Encryption

There is no PGP key for reports yet. By email, send the description and the impact first, without a working exploit, and we agree on a private way to pass the details.

## Response times

- An acknowledgement within 7 days.
- An assessment and a plan within 30 days.
- Coordinated disclosure: we publish a fix and an advisory and credit you, unless you prefer otherwise. We ask for up to 90 days before public disclosure; tell us if you need a different timeline.

WardenClaw is pre-1.0. Security fixes go to the `main` branch and the latest release only.

## Scope

In scope:

- forging, replaying or redirecting an approval: ticket or envelope signature bypass, digest confusion, canonical JSON divergence between implementations, nonce or time window bypass, pairing takeover;
- getting a command executed without a valid approval (for wardend: seccomp filter escape, TOCTOU between approval and execution, exec paths that are not gated);
- bypassing the second factor (hardware key) where a rule requires it; <!-- feature-item:hardwareKey -->
- tampering with the hash-chained journal without detection;
- leaking device or supervisor keys.

Out of scope:

- attacks that need root on the gated machine, or control of the phone's OS;
- the known limits of the single-user (same-uid) installation described in [Why the model can't turn it off](../docs/tamper-resistance/): use the hardened install for a real security boundary;
- denial of service by the operator's own agent (it can always stop working);
- vulnerabilities in third-party dependencies with no WardenClaw-specific impact: report them upstream, and tell us if WardenClaw needs to react.

## Release integrity

Releases are not signed. The installer checks the archive against the release's `checksums.txt`, both from GitHub over TLS, and nothing more; how to check the installer yourself before piping it into `sudo`: [Install wardend](../docs/install/).

The same contacts in machine-readable form (RFC 9116): [/.well-known/security.txt](/.well-known/security.txt).
