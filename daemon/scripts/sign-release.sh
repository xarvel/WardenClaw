#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Offline signing of a release (maintainer machine, never CI). Steps in docs/release.md.
#
#   git checkout daemon/v0.4.0                                      # clean checkout of the signed tag
#   scripts/release.sh daemon/v0.4.0                                # local reproducible build into dist/
#   gh release download daemon/v0.4.0 -p checksums.txt -D /tmp/ci   # checksums of the CI draft
#   scripts/sign-release.sh daemon/v0.4.0 /tmp/ci/checksums.txt
#
# Nothing is signed unless, first:
#   - dist/install.sh is install.sh of the tree and carries the release key, not a test one;
#   - the tag checks of release.sh pass again (annotated, SSH-signed by a signer from
#     allowed_signers, HEAD is the tag, empty git status), and the wardend binaries in dist/ carry
#     that commit with vcs.modified=false (go version -m);
#   - the CI checksums equal the local build (without them: only with --no-ci-compare);
#   - after a key change, release-key.txt is signed by the key of the release before.
# Then it prints the log and the diffstat since the previous release, for review, and signs into
# a temporary file. Only a signature that checks out with the key of dist/install.sh lands in dist/.
# The trusted comment "wardend <version> checksums.txt <date>" names the release for install.sh.
#
#   --no-ci-compare   sign the local build without the CI checksums
#   --allow-test-key  a test key in install.sh: local test runs only; the only way to sign a
#                     snapshot (v0.0.0-snapshot.*), which has no tag
#   MINISIGN_KEY      secret key file (default ~/.minisign/wardenclaw.key)
#   DIST              build directory (default dist)
#   GO                go, for the build info of the binaries (default go)
set -eu
cd "$(dirname "$0")/.."
. scripts/release-checks.sh

DIST=${DIST:-dist}
KEY=${MINISIGN_KEY:-$HOME/.minisign/wardenclaw.key}
GO=${GO:-go}
DAEMON=wardend
ALLOW_TEST_KEY="" NO_CI="" VERSION="" CI_SUMS=""

usage() {
	echo "usage: scripts/sign-release.sh [--no-ci-compare] [--allow-test-key] daemon/vX.Y.Z [ci-checksums.txt]" >&2
	exit 2
}
for a in "$@"; do
	case "$a" in
	--allow-test-key) ALLOW_TEST_KEY=1 ;;
	--no-ci-compare) NO_CI=1 ;;
	-*) usage ;;
	*)
		if [ -z "$VERSION" ]; then VERSION=$a
		elif [ -z "$CI_SUMS" ]; then CI_SUMS=$a
		else usage
		fi
		;;
	esac
done
VERSION=${VERSION#daemon/} # monorepo tag daemon/vX.Y.Z -> release version vX.Y.Z
case "$VERSION" in
v0.0.0-snapshot.*) TAG="" ;;
v[0-9]*.[0-9]*.[0-9]*) TAG=daemon/$VERSION ;;
*) usage ;;
esac

command -v minisign >/dev/null || rc_die "minisign not found"
[ -f "$DIST/checksums.txt" ] || rc_die "no $DIST/checksums.txt: run scripts/release.sh ${TAG:---snapshot} first"
for f in "$DIST"/*.tar.gz; do
	tar -xzOf "$f" --wildcards '*/VERSION' | grep -qx "$VERSION" || rc_die "$f is not a $VERSION build"
done

# 1. The key that this release's install.sh trusts, checked before anything is signed.
cmp -s "$DIST/install.sh" install.sh || rc_die "$DIST/install.sh is not install.sh of this tree: rebuild with scripts/release.sh"
PUB=$(pubkey_of "$DIST/install.sh")
if [ -z "$TAG" ]; then
	[ -n "$(test_key_reason "$DIST/install.sh")" ] && [ -n "$ALLOW_TEST_KEY" ] ||
		rc_die "$VERSION is a snapshot, not a release: it is signed only with a test key and --allow-test-key (local tests). A release comes from a signed tag"
else
	release_key_check "$DIST/install.sh"
fi

# 2. The tag, and the binaries are built from it.
if [ -n "$TAG" ]; then
	tag_check "$TAG"
	rotation_check "$TAG"
	commit=$(git rev-parse HEAD)
	for f in "$DIST"/"$DAEMON"_linux_*.tar.gz; do
		tar -xzOf "$f" --wildcards "*/$DAEMON" >"$RC_TMP/bin"
		bi=$("$GO" version -m "$RC_TMP/bin") || rc_die "cannot read the build info of $f ($GO version -m)"
		printf '%s\n' "$bi" | grep -q "vcs.revision=$commit" ||
			rc_die "$f is not built from $TAG ($commit): $(printf '%s\n' "$bi" | grep vcs.revision || echo 'no vcs.revision')"
		printf '%s\n' "$bi" | grep -q 'vcs.modified=false' || rc_die "$f was built from a modified tree (vcs.modified is not false)"
	done
	echo "binaries: built from $commit, clean tree"
fi

# 3. CI built the same bytes.
if [ -n "$CI_SUMS" ]; then
	if cmp -s "$CI_SUMS" "$DIST/checksums.txt"; then
		echo "CI checksums == local build: reproducible"
	else
		echo "CI checksums differ from the local build; NOT signing:" >&2
		diff "$CI_SUMS" "$DIST/checksums.txt" >&2 || true
		exit 1
	fi
elif [ -n "$NO_CI" ]; then
	echo "warning: --no-ci-compare: signing the local build without comparing it with CI" >&2
else
	rc_die "no CI checksums: pass checksums.txt of the CI draft (gh release download ${TAG:-<tag>} -p checksums.txt -D /tmp/ci), or --no-ci-compare to sign the local build alone"
fi

# 4. After a key change, the old key's statement ships with the release.
if [ -n "$TAG" ] && [ -n "$RC_OLD_KEY" ]; then
	minisign -Vm "$DIST/release-key.txt" -x "$DIST/release-key.txt.minisig" -P "$RC_OLD_KEY" >/dev/null ||
		rc_die "release-key.txt is not signed by the key of the release before ($RC_OLD_KEY)"
	case "$(sed -n 3p "$DIST/release-key.txt.minisig")" in
	"trusted comment: $DAEMON release-key $PUB" | "trusted comment: $DAEMON release-key $PUB "*) ;;
	*) rc_die "the signed comment of release-key.txt does not name the key of install.sh ($PUB)" ;;
	esac
	echo "key change: $RC_OLD_KEY -> $PUB, statement signed by the old key"
fi

# 5. What changed since the previous release: read it before typing the key password.
if [ -n "$TAG" ]; then
	prev=$(prev_release_tag "$TAG")
	if [ -n "$prev" ]; then
		echo "== $prev..$TAG, commits touching the release (daemon/, AUTHORS, allowed_signers, .github/):"
		git --no-pager log --oneline "$prev..$TAG" -- . ../AUTHORS ../allowed_signers ../.github
		echo "== diffstat $prev..$TAG:"
		git --no-pager diff --stat "$prev" "$TAG" -- . ../AUTHORS ../allowed_signers ../.github
	else
		echo "== the first release: $(git rev-list --count "$TAG") commits up to $TAG"
	fi
fi

# 6. Sign into a temporary file; only a signature by the key of install.sh goes to dist/.
date=$(date -u +%Y-%m-%d)
rm -f "$DIST/checksums.txt.minisig"
minisign -S -s "$KEY" -m "$DIST/checksums.txt" -x "$RC_TMP/checksums.txt.minisig" -t "$DAEMON $VERSION checksums.txt $date"
minisign -Vm "$DIST/checksums.txt" -x "$RC_TMP/checksums.txt.minisig" -P "$PUB" >/dev/null ||
	rc_die "$KEY is not the secret half of the key in install.sh ($PUB): nothing written to $DIST"
cp "$RC_TMP/checksums.txt.minisig" "$DIST/checksums.txt.minisig"
echo "signed: $DIST/checksums.txt.minisig ($DAEMON $VERSION checksums.txt $date); upload it to the draft release, then publish"
