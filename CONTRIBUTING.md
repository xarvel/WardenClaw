# Contributing to WardenClaw

Thank you for helping. Bug reports, reviews, tests and patches are all welcome.
Security problems go through a private channel instead: see [SECURITY.md](SECURITY.md).

This repository holds all parts of WardenClaw: the daemon and `wardenctl` (`daemon/`), the phone
app (`app/`), the OpenClaw plugin (`plugin/`), the protocol specification and test vectors
(`protocol/`) and the site with the user documentation (`site/`). Each part builds and tests on
its own; there is no root package and no npm workspaces.

## License of contributions

Each directory keeps its own license (the map is in [LICENSE](LICENSE)):

| path | license |
|---|---|
| `daemon/` | AGPL-3.0-or-later |
| `app/` | GPL-3.0-or-later with an additional permission for app stores (`app/COPYING.exceptions`); by contributing to the app you also agree that your contribution may be distributed under that permission |
| `plugin/`, `protocol/` | Apache-2.0 |
| `site/` | code Apache-2.0; documentation texts in `site/src/docs/` CC BY 4.0 |

Contributions are accepted under the license of the files they change
("inbound = outbound"). There is no contributor license agreement: you keep the copyright in
your work, and the project can only use it under that license. This is why every commit has to
carry a sign-off, see below.

## Developer Certificate of Origin (sign-off)

Every commit must include a `Signed-off-by` line, which certifies that you wrote the change or
otherwise have the right to submit it under the project's license, as described by the
Developer Certificate of Origin 1.1 quoted below:

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds the line for you (`git commit --amend -s` or `git rebase --signoff` fix
existing commits). Use a name you are known by; anonymous contributions can't be accepted. The
address may be a GitHub `noreply` address. Pull requests with unsigned commits are not merged:
the `dco` check (`.github/workflows/dco.yml`) runs on every pull request and fails, naming each
commit that has no `Signed-off-by` line.

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

If you want to be listed in [AUTHORS](AUTHORS), add yourself in the same pull request.

## Making a change

- New source files start with an SPDX line matching their directory, for example
  `// SPDX-License-Identifier: AGPL-3.0-or-later` in `daemon/`, `GPL-3.0-or-later` in `app/`,
  `Apache-2.0` in `plugin/` and `protocol/`.
- Keep changes focused; describe the reason in the commit message. A change that spans several
  parts (for example a protocol change) goes into one pull request with the spec, the vectors
  and all implementations. New documentation and commit messages are written in English.
- User documentation lives in `site/src/docs/`, in English; `daemon/docs/` holds developer notes
  only.
- Don't commit secrets, device keys, tokens, personal paths or host names. Test keys must be
  public test vectors (RFC 8032) or clearly synthetic values.

## Tests

CI runs one workflow per part, only when its paths changed (`.github/workflows/`); run the same
locally.

| part | commands |
|---|---|
| `daemon/` | `go vet ./...` and `go test -p 1 ./...`. The integration tests put processes under a seccomp filter of their own, which the kernel refuses inside a wardend tree: there they fail or are skipped. Run them yourself, from your own terminal outside wardend (not from an agent's session), or leave them to CI. Don't have an agent wrap them in `systemd-run --user` or a similar launcher: that runs code outside the gate, and wardend asks about it with a card saying so |
| `app/` | `npm ci`, `npx tsc --noEmit` (no errors), `npm test` (core tests in Node: canonical JSON and transport vectors, envelopes, hardware key logic, local judge prompts). Building the iOS and Android apps locally: [app/docs/BUILD.md](app/docs/BUILD.md) |
| `plugin/` | `npm ci`, `npm test` (node:test). The relay end-to-end test uses `daemon/wardend` when it is built (`cd daemon && go build .`) or `$WARDEND_BIN` |
| `site/` | `npm ci`, `npm run build` |
| `protocol/` | the vectors are checked by all three implementations: the daemon, app and plugin tests above read `protocol/vectors/` directly |

Changing the envelope, the ticket or the transport signing strings: update `protocol/*.md`,
regenerate the vectors (commands in [protocol/README.md](protocol/README.md#9-test-vectors))
and run the tests of the daemon, the app and the plugin. The vectors exist in one copy only;
never copy them into a component.
