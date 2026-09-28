// SPDX-License-Identifier: Apache-2.0
// minisign keys never trusted for a download: test keys (their secret halves sit on development
// machines) and retired release keys. The same list as REFUSED_PUBKEYS in daemon/install.sh:
// astro.config.mjs refuses to build when they differ. Not in config.ts: the deploy workflow
// refuses a config.ts that mentions the test key.
export const REFUSED_PUBKEYS: string[] = [
  "RWRtZZCNqXGxFzK4Bx/67mlyraSSBoW2evVgCLiCgulBoLMmnrUanfsi", // 17B171A98D90656D, snapshot builds
  "RWRw9ehxcaUpiJHm/VOHH8vGVa3CpNii1AonJxlwbAaJbTDjdk385jYA", // 8829A57171E8F570, site deploy checks
];
