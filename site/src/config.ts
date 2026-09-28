// SPDX-License-Identifier: Apache-2.0
// Project identity and links used across the site. Change the name and the domain here only.
// Markdown docs use the same values through %KEY_NAME% placeholders
// (DOC_VARS below, replaced at build time by the Sätteri mdast plugin in astro.config.mjs).

export const PROJECT_NAME = "WardenClaw";
// public/CNAME repeats the domain (astro.config.mjs refuses to build when they differ).
export const DOMAIN = "wardenclaw.dev";
export const SITE_URL = `https://${DOMAIN}`;
// The site serves install.sh of the latest daemon release at its root, a copy checked against the
// release's checksums.txt before every deploy (.github/workflows/site-pages.yml,
// scripts/fetch-install-sh.sh). The release archives and checksums stay on GitHub (RELEASES_URL),
// install.sh downloads them there. Releases are not signed.
export const INSTALL_URL = `${SITE_URL}/install.sh`;
export const INSTALL_CMD = `curl -fsSL ${INSTALL_URL} | sudo sh`;

// The repository is public, so the site links to it. While this is false the GitHub pill,
// the "Source" lines and the footer say the code opens with the first release, and markdown
// links to REPO_URL become plain text. GITHUB_REPO is the one place to change the repository
// (same as GITHUB_REPO in daemon/install.sh).
export const REPO_PUBLIC = true;
export const GITHUB_REPO = "xarvel/WardenClaw";
export const REPO_URL = `https://github.com/${GITHUB_REPO}`;
export const RELEASES_URL = `${REPO_URL}/releases`;
export const WARDEND_URL = `${REPO_URL}/tree/main/daemon`;
export const GATE_URL = `${REPO_URL}/tree/main/plugin`;
export const APP_URL = `${REPO_URL}/tree/main/app`;
// TODO: replace with the published article URL.
export const ARTICLE_URL = `${REPO_URL}#readme`;
// GitHub private vulnerability reporting (SECURITY.md). The site links here only while
// PRIVATE_REPORTING is true.
export const ADVISORY_URL = `${REPO_URL}/security/advisories/new`;
// The maintainer's address: the security contact in /.well-known/security.txt, on /security/
// and in SECURITY.md.
export const SECURITY_EMAIL = "valiullin.arthur@gmail.com";
// GitHub API GET /repos/<owner>/<repo>/private-vulnerability-reporting returned enabled:false
// (2026-09-29). Turn the setting on (Settings → Code security), then set this to true.
export const PRIVATE_REPORTING = false;
// True while the site is built with the install.sh of a published daemon release: site-pages.yml
// runs scripts/fetch-install-sh.sh first, and on success it exports DAEMON_RELEASED_BUILD=1 for
// the build. While false, the try page says the installer is not there yet; a local build has no
// release and says so.
export const DAEMON_RELEASED = typeof process !== "undefined" && process.env.DAEMON_RELEASED_BUILD === "1";

// Features left out of the first release. They come back: a flag set to true brings back every
// text about its feature on the site (docs blocks between <!-- feature:NAME --> and
// <!-- /feature -->, menu entries, the landing, claims.ts) and makes the build ask for its
// README.md lines (README_FEATURES in claims.ts). How to mark text: site/README.md, "Features left out of a release".
export const FEATURES = {
  // A YubiKey co-signature (require_hardware rules, NFC in the app, wardenctl hw-register).
  hardwareKey: false,
  // The Apple Watch app, an approver of its own.
  appleWatch: false,
  // The risk judge on a model that runs on the phone itself (llama.rn, onnxruntime). The judge
  // on a model at a URL you set is not behind a flag.
  phoneJudge: false,
};
export type Feature = keyof typeof FEATURES;
// `on` while the feature is in, else `off`: inline mentions in TS strings.
export const feat = (name: Feature, on: string, off = ""): string => (FEATURES[name] ? on : off);
// The items while the feature is in, else nothing: `[a, ...only("appleWatch", b), c]`.
export const only = <T>(name: Feature, ...items: T[]): T[] => (FEATURES[name] ? items : []);
// Markers in a plain string (the frontmatter title and description of a doc):
// <!-- feature:NAME -->text<!-- /feature --> keeps the text while the feature is in,
// <!-- feature:!NAME -->text<!-- /feature --> while it is out.
const FEATURE_SPAN = /<!--\s*feature:(!?)(\w+)\s*-->([\s\S]*?)<!--\s*\/feature\s*-->/g;
export function featureOn(not: string, name: string): boolean {
  if (!(name in FEATURES)) throw new Error(`unknown feature "${name}"`);
  return FEATURES[name as Feature] !== (not === "!");
}
export const featureText = (s: string): string =>
  s.replace(FEATURE_SPAN, (_m, not: string, name: string, body: string) => (featureOn(not, name) ? body : ""));

// %KEY_NAME% in src/docs/*.md (text, inline code, code blocks, link URLs) becomes the value.
export const DOC_VARS: Record<string, string> = {
  PROJECT_NAME,
  INSTALL_URL,
  INSTALL_CMD,
  REPO_URL,
  RELEASES_URL,
  ADVISORY_URL,
  SECURITY_EMAIL,
};

// A raw HTML block in src/docs/*.md with data-if="NAME" is kept only while DOC_IF[NAME] is true
// (GitHub private reporting, the "no installer yet" note). While REPO_PUBLIC is false, markdown
// links to REPO_URL become plain text.
export const DOC_IF: Record<string, boolean> = {
  "repo-public": REPO_PUBLIC,
  "repo-private": !REPO_PUBLIC,
  advisories: PRIVATE_REPORTING,
  "no-advisories": !PRIVATE_REPORTING,
  "no-release": !DAEMON_RELEASED,
};
