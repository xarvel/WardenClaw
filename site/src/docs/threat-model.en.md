---
title: Threat model
description: What WardenClaw protects, where the trust boundaries run, what leaves the machine, what each adversary can and can't do, and where that is checked. With links to the tests and to what is not closed yet.
---

# Threat model

WardenClaw has one job: a risky command of an AI agent runs only after a person signs it on a device the agent can't reach. This page lists what that rests on, who can attack it and what stops them. The main adversary, a model that wants to turn its guard off, has its own page with every vector and its test: [Why the model can't turn it off](../tamper-resistance/).

## What it protects

- **The decision.** A command that trips a rule runs only with an Ed25519 signature of a paired device over the digest of its envelope: argv, cwd, the real binary, the parent chain, the environment variables of a list and a hash of the whole environment.
- **The approval keys.** Each approving device (the phone, <!-- feature:appleWatch -->the Apple Watch, <!-- /feature -->`wardenctl` in a terminal) has its own key. The agent's host keeps only the public keys of the devices you paired.
- **The record.** Every exec and every decision lands in a hash-chained journal signed by wardend; `wardend verify-journal` checks it.

## Trust boundaries

- **The agent's host.** In the hardened install wardend runs as a root system service and the agent as its own unprivileged user. The kernel and root are trusted, the agent's user is not. In a single-user trial this boundary does not exist.
- **The way to the phone.** A tunnel, a proxy or the network can delay or drop messages. Every request of the app, every ticket and every response of wardend is signed, and a response is bound to the request it answers, so nothing in between can forge or swap them. Messages are signed, not encrypted: a tunnel that terminates TLS (Cloudflare Tunnel does) can read the cards, commands and paths included.
- **Notifications.** A notification carries no command: the app fetches the card itself over the signed channel ([Notifications](../notifications/)).
- **The phone.** It holds the key, recomputes the digest itself and signs only deny when the digest doesn't match. Before it signs an allow on a dangerous card or a root, it asks for strong biometrics or the device code (before every allow, if you choose); a deny needs no check. On a phone without a screen lock there is nothing to ask for, and the app warns about it in its settings.
- **The judge.** It runs on the phone's side, on a model you pick; the agent's host never sees its prompt, its keys or its journal. A model at a URL gets every command it rates: the arguments, the listed environment variables, the working directory, the host and the process chain. Pick a provider you trust, or run your own model. In Autopilot it decides within your risk threshold, and the deterministic block-list goes to you before any model sees it.
- **Releases.** They are signed with minisign. The first hardened install pins the key in `/etc/wardend/release.pub`, and upgrades are checked with the pinned key. A first install checks against the key on GitHub and on this site; compare that key with the DNS copy on the project domain before running the installer ([Verify releases](../verify/)).

## What leaves the machine

| What | Goes to | When | What it carries |
|---|---|---|---|
| An APNs push | Apple | Only with an APNs key on the server | The card id and a fixed text, no command, host or path |
| An ntfy push | The ntfy server (ntfy.sh or your own) | Only with `ntfy_url` set | "New request to approve" under the title WardenClaw, at most once in 10 s. Whoever knows the topic sees when cards appear, that is the rhythm of the agent's work, and can send pushes to it: keep the topic long and random, or run your own server |
| The cards | The tunnel, when it terminates TLS (Cloudflare Tunnel does) | On every request of the app | The whole card: command, paths, listed environment variables, host. It can't forge or approve anything: the signatures stop that |
| The judge's prompt | The provider of the model at the URL you set | Only with a judge at a URL | Every command it rates: arguments, listed environment variables, working directory, host, process chain |

The app's journal stays out of the phone's cloud backup: on Android the app's backup is off, on iPhone the journal's folder is excluded from the iCloud backup.

## Adversaries

| Adversary | Can | Can't | Checked by |
|---|---|---|---|
| A hijacked model or agent (prompt injection, a malicious dependency) | Run what trips no rule; ask for a card | Run a risky command without your signature, sign for you, swap the command after approval, turn wardend off in the hardened install | `redteam/run.sh`, `redteam/hardened-check.sh`, the [vector table](../tamper-resistance/#vector-table) |
| The agent's user in a single-user trial | Stop, trace or rewrite wardend without a single exec | Nothing stops it: use the hardened install | `redteam/run.sh` shows these attacks succeed |
| Someone on the way to the phone (tunnel, proxy, network) | Delay or drop messages; read the cards if it terminates TLS | Forge a card or a decision, replay a ticket, pass off another response as the answer. A decision that never arrives ends in `EPERM` when the TTL runs out | `protocol/vectors/transport_vectors.json`, wardend's HTTP tests |
| A thief with your phone | On an unlocked phone, allow cards that are not dangerous (the default owner check covers dangerous cards and roots) | Allow a dangerous card without your biometrics or device code (on a phone with a screen lock); sign anything after `wardend pair revoke` | the app's owner check (`app/src/core/safety.ts`) |
| A judge that lies (Autopilot) | Allow what it rates below your threshold while Autopilot is on | Allow what is on the block-list; stay on for more than an hour | the app's judge (`app/src/core/decide.ts`, `controller.ts`) |
| A tampered install script or release | Get you to run it | Pass the minisign check; move a pinned install to another key without a statement signed by the old one | [Verify releases](../verify/) |

## What is not closed

The list of what WardenClaw doesn't close yet lives in one place, on the home page: [What it closes, and what it doesn't yet](../../#scope). The premises of the hardened install and what stays out of scope: [Honest premises](../tamper-resistance/#honest-premises-and-out-of-scope). The race between approval and exec, measured: [TOCTOU](../../#security).
