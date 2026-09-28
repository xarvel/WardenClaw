#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Reproducible release build. Same tag + same Go version = byte-identical archives on any machine,
# which is how a maintainer checks the CI build before signing it (docs/release.md).
#
#   scripts/release.sh daemon/v0.4.0 # dist/ for a signed tag; the monorepo tags daemon releases
#                                    # daemon/vX.Y.Z, the version inside the release is vX.Y.Z
#                                    # (a bare v0.4.0 means the tag daemon/v0.4.0)
#   scripts/release.sh --snapshot    # local test build: v0.0.0-snapshot.<commit>, nothing published
#   --allow-test-key                 # with a tag: go on when install.sh carries a test key (local
#                                    # test runs of the release path only; CI never passes it)
#
# A release is built only from a checked tag (scripts/release-checks.sh, docs/release.md):
# install.sh carries the release key, not a test one; the tag is annotated and SSH-signed by a
# signer from allowed_signers; HEAD is the tag's commit; git status is empty, untracked files
# included; a changed release key comes with the old key's statement (release-key.txt).
#
# Output in dist/ (DIST=...): wardend_linux_{amd64,arm64}.tar.gz (wardend, wardenctl, deploy/,
# redteam/, install.sh, uninstall.sh, LICENSE, NOTICE, AUTHORS, README.md, VERSION),
# wardenctl_darwin_{arm64,amd64}.tar.gz, install.sh, release-key.txt(.minisig) after a key change,
# checksums.txt. The signature checksums.txt.minisig is made separately and offline
# (scripts/sign-release.sh). Needs Go (GO=...), git, ssh-keygen, GNU tar, gzip, sha256sum.
# Runs from daemon/ of the monorepo; AUTHORS comes from the repository root.
set -eu
cd "$(dirname "$0")/.."
ROOT=..
. scripts/release-checks.sh

DAEMON=wardend
CTL=wardenctl
GO=${GO:-go}
DIST=${DIST:-dist}
ALLOW_TEST_KEY=""

usage() {
	echo "usage: scripts/release.sh [--allow-test-key] daemon/vX.Y.Z | vX.Y.Z | --snapshot" >&2
	exit 2
}
VERSION="" TAG=""
for a in "$@"; do
	case "$a" in
	--allow-test-key) ALLOW_TEST_KEY=1 ;;
	--snapshot) [ -z "$VERSION" ] || usage; VERSION="v0.0.0-snapshot.$(git rev-parse --short=12 HEAD)" ;;
	daemon/v[0-9]*.[0-9]*.[0-9]*) [ -z "$VERSION" ] || usage; VERSION=${a#daemon/} TAG=$a ;;
	v[0-9]*.[0-9]*.[0-9]*) [ -z "$VERSION" ] || usage; VERSION=$a TAG=daemon/$a ;;
	*) usage ;;
	esac
done
[ -n "$VERSION" ] || usage

if [ -n "$TAG" ]; then
	release_key_check
	tag_check "$TAG"
	rotation_check "$TAG"
else
	rotation_check
	if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
		echo "warning: the work tree has local changes; the binaries record vcs.modified=true" >&2
	fi
fi

# Time of the release commit: the only timestamp that ends up in the archives.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export SOURCE_DATE_EPOCH
export CGO_ENABLED=0 GOFLAGS=-trimpath GOAMD64=v1 GOARM64=v8.0 LC_ALL=C TZ=UTC
LDFLAGS="-s -w -buildid= -X main.version=$VERSION"
# Build tags of a release, fixed here and not taken from the environment: CI and the maintainer's
# rebuild must produce the same bytes. The second factor (hardware keys, YubiKey: wardend
# hw-register, require_hardware, wardenctl touch) is the tag hwkey, left out of the first release;
# setting this line to TAGS="hwkey" puts it back into both binaries (docs/hwkey.md).
TAGS=""

echo "release $VERSION, $("$GO" version), SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH, tags: ${TAGS:-none}"

# uninstall.sh repeats the project identity of install.sh: a release with two different ones would
# print commands for another domain or remove another binary.
for v in DOMAIN INSTALL_URL UNINSTALL_DOCS_URL DAEMON CTL; do
	a=$(sed -n "s/^$v=\(\"[^\"]*\"\).*/\1/p" install.sh)
	b=$(sed -n "s/^$v=\(\"[^\"]*\"\).*/\1/p" uninstall.sh)
	[ -n "$a" ] && [ "$a" = "$b" ] || { echo "$v differs: install.sh $a, uninstall.sh $b" >&2; exit 1; }
done

rm -rf "$DIST"
mkdir -p "$DIST/stage"

build() { # goos goarch pkg out
	GOOS=$1 GOARCH=$2 "$GO" build -tags "$TAGS" -ldflags "$LDFLAGS" -o "$4" "$3"
}

pack() { # name: tar.gz with fixed order, owner and mtime, gzip without name/time
	find "$DIST/stage/$1" -type d -exec chmod 0755 {} +
	find "$DIST/stage/$1" -type f -exec chmod 0644 {} +
	for x in "$DIST/stage/$1/$DAEMON" "$DIST/stage/$1/$CTL" "$DIST/stage/$1/install.sh" "$DIST/stage/$1/uninstall.sh" \
		"$DIST/stage/$1"/deploy/*.sh "$DIST/stage/$1"/redteam/*.sh; do
		if [ -f "$x" ]; then chmod 0755 "$x"; fi
	done
	tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
		--format=gnu -C "$DIST/stage" -cf - "$1" | gzip -n -9 >"$DIST/$1.tar.gz"
	echo "  $DIST/$1.tar.gz"
}

for arch in amd64 arm64; do
	name="${DAEMON}_linux_${arch}"
	d="$DIST/stage/$name"
	mkdir -p "$d"
	build linux "$arch" . "$d/$DAEMON"
	build linux "$arch" ./cmd/wardenctl "$d/$CTL"
	cp -R deploy redteam "$d/"
	cp install.sh uninstall.sh LICENSE NOTICE README.md "$ROOT/AUTHORS" "$d/"
	printf '%s\n' "$VERSION" >"$d/VERSION"
	pack "$name"
done

for arch in arm64 amd64; do
	name="${CTL}_darwin_${arch}"
	d="$DIST/stage/$name"
	mkdir -p "$d"
	build darwin "$arch" ./cmd/wardenctl "$d/$CTL"
	cp LICENSE NOTICE "$d/"
	cp cmd/wardenctl/README.md "$d/README.md"
	printf '%s\n' "$VERSION" >"$d/VERSION"
	pack "$name"
done

cp install.sh "$DIST/install.sh"
# After a key change: ship the old key's hand-over statement for installs pinned to the old key.
if [ -f release-key.txt ]; then cp release-key.txt release-key.txt.minisig "$DIST/"; fi
rm -rf "$DIST/stage"
(
	cd "$DIST"
	set -- *.tar.gz install.sh
	if [ -f release-key.txt ]; then set -- "$@" release-key.txt release-key.txt.minisig; fi
	sha256sum -- "$@" | sort -k2 >checksums.txt
)
echo "  $DIST/checksums.txt"
cat "$DIST/checksums.txt"
