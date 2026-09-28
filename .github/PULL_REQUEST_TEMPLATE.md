<!-- A fix for a vulnerability that is not public yet: do not open this pull request, email first (SECURITY.md). -->

## What and why

<!-- The problem and the change; link the issue if there is one. -->

## Before merging

- [ ] Every commit is signed off: `git commit -s`, or `git rebase --signoff` for existing commits.
      The `dco` check on this pull request refuses unsigned commits ([CONTRIBUTING.md](https://github.com/xarvel/WardenClaw/blob/main/CONTRIBUTING.md#developer-certificate-of-origin-sign-off)).
- [ ] The change is licensed like the directory it touches ([LICENSE](https://github.com/xarvel/WardenClaw/blob/main/LICENSE) has the map):
      `daemon/` AGPL-3.0-or-later, `app/` GPL-3.0-or-later with the app store permission,
      `plugin/` and `protocol/` Apache-2.0, `site/` Apache-2.0 with the docs under CC BY 4.0.
      New source files start with the SPDX line of their directory.
- [ ] The tests of every part I changed pass locally ([CONTRIBUTING.md, Tests](https://github.com/xarvel/WardenClaw/blob/main/CONTRIBUTING.md#tests)):
      `daemon/` `go vet ./... && go test -p 1 ./...` from a terminal outside wardend;
      `app/` `npm ci && npx tsc --noEmit && npm test`;
      `plugin/` `npm ci && npm test`;
      `site/` `npm ci && npm run build`.
- [ ] A change to the envelope, the ticket or the transport signing strings comes with `protocol/*.md`,
      the regenerated vectors in `protocol/vectors/` and the tests of the daemon, the app and the plugin,
      all in this pull request.
- [ ] No secrets, device keys, tokens, personal paths or host names.
