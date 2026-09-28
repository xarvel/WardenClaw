---
title: How it works
description: The two detailed diagrams of WardenClaw, the architecture from the agent to the phone and the life of one command from execve to CONTINUE or EPERM, why one action can bring two cards, with where to read on.
---

# How it works

The short version is on the [home page](../../#how): the kernel stops every program the agent starts, wardend checks it against the rules, and a command that trips one waits for a signature from your phone. Here are the two detailed diagrams.

## Architecture

![Architecture: the agent runs under wardend, which stops every execve through seccomp user notification and checks it against the rules. Cards that need a signature go end-to-end encrypted from wardend, through the relay it dials, to the WardenClaw phone app. The app signs allow or deny with its Ed25519 key, and wardend answers the kernel with CONTINUE or EPERM.](/brand/architecture.en.svg)

## The life of one command

![Lifecycle of one command: the kernel stops execve, wardend builds the envelope and digest, the phone shows the card and signs a ticket, wardend verifies it and answers CONTINUE or EPERM.](/brand/lifecycle.en.svg)

## Read on

- Which commands need a signature and how the rules work: [CLI reference](../cli/#policy-modes).
- Who can attack this and what stops them: [Threat model](../threat-model/).
- Why the model can't simply turn wardend off: [Why the model can't turn it off](../tamper-resistance/).
