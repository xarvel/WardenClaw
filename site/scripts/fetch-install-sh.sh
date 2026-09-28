#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# install.sh of the latest published wardend release, for the root of the site
# (https://<domain>/install.sh). Runs in .github/workflows/site-pages.yml before the deploy.
#
#   scripts/fetch-install-sh.sh OUT_DIR                     # GH_REPO=owner/repo, GH_TOKEN for gh
#   scripts/fetch-install-sh.sh OUT_DIR --from-dir DIR --tag daemon/vX.Y.Z   # local test, no gh
#
# The release is the one GitHub marks latest, the same one install.sh installs from
# (releases/latest/download). Its install.sh is copied to OUT_DIR/install.sh only when:
#   - checksums.txt.minisig verifies with MINISIGN_PUBKEY of src/config.ts, the key the site shows
#     (not a key from the release itself: that one would vouch for anything);
#   - the signed comment is "wardend <version> checksums.txt [YYYY-MM-DD]" with the version of the tag;
#   - the sha256 of install.sh is its line in the signed checksums.txt;
#   - the script trusts the same key, names the same domain and install URL as the site and
#     downloads from the releases of GH_REPO on GitHub.
# The file on the site is then byte for byte the install.sh of the signed release. Before that,
# GITHUB_REPO of src/config.ts has to be GH_REPO too: the docs link to its releases.
# No published release yet: copies nothing, warns and exits 0 (the site goes out without
# install.sh). Anything else wrong: exits 1, and the workflow deploys nothing.
# Needs minisign, sha256sum, sed, awk, and gh without --from-dir.
set -eu

DAEMON=wardend
TAG_PREFIX=daemon/
CONFIG=src/config.ts
FILES="install.sh checksums.txt checksums.txt.minisig"

# GitHub Actions annotation (plain stderr elsewhere) and a line in the job summary.
report() { # level message
	if [ "${GITHUB_ACTIONS:-}" = true ]; then
		printf '::%s title=install.sh::%s\n' "$1" "$(printf '%s' "$2" | sed 's/%/%25/g')"
	else
		printf '%s: %s\n' "$1" "$2" >&2
	fi
	if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then printf '%s\n\n' "$2" >>"$GITHUB_STEP_SUMMARY"; fi
}
die() {
	report error "$*"
	exit 1
}
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
absolute() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }

OUT=${1:?usage: scripts/fetch-install-sh.sh OUT_DIR [--from-dir DIR --tag daemon/vX.Y.Z]}
shift
FROM_DIR="" TAG=""
while [ $# -gt 0 ]; do
	case "$1" in
	--from-dir) [ $# -ge 2 ] || die "--from-dir needs a value"; FROM_DIR=$2; shift 2 ;;
	--tag) [ $# -ge 2 ] || die "--tag needs a value"; TAG=$2; shift 2 ;;
	*) die "unknown argument: $1" ;;
	esac
done
REPO=${GH_REPO:-}
[ -n "$REPO" ] || die "GH_REPO (owner/repo of the releases) is not set"
OUT=$(absolute "$OUT")
if [ -n "$FROM_DIR" ]; then
	[ -n "$TAG" ] || die "--from-dir needs --tag daemon/vX.Y.Z"
	[ -d "$FROM_DIR" ] || die "$FROM_DIR is not a directory"
	FROM_DIR=$(absolute "$FROM_DIR")
else
	[ -z "$TAG" ] || die "--tag only goes with --from-dir: the release is the one GitHub marks latest"
fi
cd "$(dirname "$0")/.."

# Values the site is built with; the published script has to agree with them.
cfg() { sed -n "s/^export const $1 = \"\([^\"]*\)\";.*/\1/p" "$CONFIG"; }
PUBKEY=$(cfg MINISIGN_PUBKEY)
DOMAIN=$(cfg DOMAIN)
SITE_REPO=$(cfg GITHUB_REPO)
[ -n "$PUBKEY" ] && [ -n "$DOMAIN" ] && [ -n "$SITE_REPO" ] ||
	die "cannot read MINISIGN_PUBKEY, DOMAIN and GITHUB_REPO from $CONFIG"
INSTALL_URL="https://$DOMAIN/install.sh"
# The docs link to the releases of GITHUB_REPO (the manual check downloads checksums from there).
[ "$(lower "$SITE_REPO")" = "$(lower "$REPO")" ] ||
	die "GITHUB_REPO in $CONFIG is \"$SITE_REPO\", the site is deployed from $REPO: its release and repository links would point elsewhere"

command -v minisign >/dev/null 2>&1 || die "minisign not found"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if [ -n "$FROM_DIR" ]; then
	_n=0
	for _f in $FILES; do
		if [ -f "$FROM_DIR/$_f" ]; then
			cp "$FROM_DIR/$_f" "$WORK/$_f"
			_n=$((_n + 1))
		fi
	done
	_none="no release files in $FROM_DIR"
else
	command -v gh >/dev/null 2>&1 || die "gh not found"
	# releases/latest skips drafts and pre-releases; 404 means nothing is published yet.
	if gh api "repos/$REPO/releases/latest" --jq .tag_name >"$WORK/tag" 2>"$WORK/err"; then
		TAG=$(cat "$WORK/tag")
		_n=1
	elif grep -q 'HTTP 404' "$WORK/err"; then
		_n=0
	else
		cat "$WORK/err" >&2
		die "cannot ask GitHub for the latest release of $REPO"
	fi
	_none="no published release in $REPO yet"
fi
if [ "$_n" = 0 ]; then
	report warning "$_none: the site is built without install.sh, $INSTALL_URL answers 404 until the first release is published"
	exit 0
fi

case "$TAG" in
"$TAG_PREFIX"v[0-9]*) ;;
*) die "the latest release of $REPO is \"$TAG\", not a $DAEMON release (${TAG_PREFIX}vX.Y.Z). install.sh downloads from releases/latest, so installs fail until a $DAEMON release is marked latest" ;;
esac
VERSION=${TAG#"$TAG_PREFIX"}

if [ -z "$FROM_DIR" ]; then
	# Missing assets are caught below: gh only fails when no pattern matches at all.
	gh release download "$TAG" --repo "$REPO" --dir "$WORK" \
		--pattern install.sh --pattern checksums.txt --pattern checksums.txt.minisig ||
		die "cannot download the assets of $TAG"
fi
for _f in $FILES; do
	[ -s "$WORK/$_f" ] || die "release $TAG has no $_f"
done

minisign -Vm "$WORK/checksums.txt" -x "$WORK/checksums.txt.minisig" -P "$PUBKEY" >"$WORK/minisign.out" 2>&1 || {
	cat "$WORK/minisign.out" >&2
	die "checksums.txt of $TAG is not signed by the release key of the site (MINISIGN_PUBKEY in $CONFIG): its install.sh is not published"
}
# The trusted comment is covered by the signature, as in install.sh:
# "<daemon> <version> checksums.txt", with the date sign-release.sh signed it (YYYY-MM-DD) at the end.
_tc=$(sed -n 3p "$WORK/checksums.txt.minisig")
_tc=${_tc#trusted comment: }
case "$_tc" in
"$DAEMON $VERSION checksums.txt" | "$DAEMON $VERSION checksums.txt "[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]) ;;
*) die "the signed comment of $TAG is \"$_tc\", expected \"$DAEMON $VERSION checksums.txt [YYYY-MM-DD]\"" ;;
esac

_want=$(awk '$2 == "install.sh" || $2 == "*install.sh" { print $1 }' "$WORK/checksums.txt")
[ -n "$_want" ] || die "the signed checksums.txt of $TAG does not list install.sh"
[ "$(printf '%s\n' "$_want" | wc -l | tr -d ' ')" = 1 ] || die "checksums.txt of $TAG lists install.sh twice"
_got=$(sha256sum "$WORK/install.sh" | cut -d' ' -f1)
[ "$_got" = "$_want" ] || die "install.sh of $TAG does not match the signed checksums.txt (sha256 $_got, signed $_want)"

# The script is signed; now it has to fit this site. Its identity block is read as text, never run.
sh_var() { sed -n "s/^$1=\"\([^\"]*\)\".*/\1/p" "$WORK/install.sh" | head -n 1; }
_v=$(sh_var MINISIGN_PUBKEY)
[ "$_v" = "$PUBKEY" ] ||
	die "install.sh of $TAG trusts the key $_v, the site shows $PUBKEY: installs would fail or the docs would name the wrong key"
_v=$(sh_var DOMAIN)
[ "$_v" = "$DOMAIN" ] || die "install.sh of $TAG names the domain $_v, the site is $DOMAIN"
_v=$(sh_var INSTALL_URL | sed "s|\${DOMAIN}|$DOMAIN|g")
[ "$_v" = "$INSTALL_URL" ] || die "install.sh of $TAG says it is served at $_v, the site serves it at $INSTALL_URL"
_v=$(sh_var GITHUB_REPO)
[ "$(lower "$_v")" = "$(lower "$REPO")" ] ||
	die "install.sh of $TAG downloads the releases of \"$_v\", the releases are in $REPO"
_v=$(sh_var RELEASES_URL | sed "s|\${GITHUB_REPO}|$_v|g")
[ "$(lower "$_v")" = "$(lower "https://github.com/$REPO/releases")" ] ||
	die "install.sh of $TAG downloads from $_v, the site sends people to https://github.com/$REPO/releases"

mkdir -p "$OUT"
cp "$WORK/install.sh" "$OUT/install.sh"
chmod 0644 "$OUT/install.sh"
report notice "install.sh of $TAG, signed and checked (sha256 $_got), goes to $INSTALL_URL"
