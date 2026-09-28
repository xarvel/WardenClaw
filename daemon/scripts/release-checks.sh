# SPDX-License-Identifier: AGPL-3.0-or-later
# Checks shared by scripts/release.sh, sign-release.sh and rotate-release-key.sh: sourced, not
# run, from daemon/.
# docs/release.md, sections "Keys" and "Signed Tags".
#
#   release_key_check [FILE]   FILE (install.sh) carries the release key, not a test one; the site has the same
#   tag_check TAG              TAG is signed by an allowed signer, HEAD is TAG, the tree is clean
#   rotation_check [TAG]       a changed release key comes with the old key's statement (release-key.txt)
#   prev_release_tag TAG       the daemon release tag before TAG in version order (empty for the first)
#
# ALLOW_TEST_KEY=1 turns the test-key refusal into a warning (local test runs only).
# ALLOWED_SIGNERS=FILE checks tags against that file instead of the repository's (see signers_for).

rc_die() {
	echo "error: $*" >&2
	exit 1
}

RC_TMP=$(mktemp -d) || rc_die "mktemp"
trap 'rm -rf "$RC_TMP"' EXIT
trap 'exit 130' INT TERM

pubkey_of() { sed -n 's/^MINISIGN_PUBKEY="\(.*\)"$/\1/p' "$1"; } # install.sh -> its release key
refused_of() { sed -n 's/^REFUSED_PUBKEYS="\(.*\)"$/\1/p' "$1"; }

# test_key_reason INSTALL_SH: why its key is a test key; empty output: it is not.
test_key_reason() {
	_p=$(pubkey_of "$1")
	if [ -z "$_p" ]; then
		echo "no MINISIGN_PUBKEY line"
		return 0
	fi
	for _k in $(refused_of "$1"); do
		if [ "$_k" = "$_p" ]; then
			echo "its key is listed in REFUSED_PUBKEYS"
			return 0
		fi
	done
	if grep -q 'TEST KEY' "$1"; then echo "the key is marked TEST KEY"; fi
	return 0
}

# release_key_check [INSTALL_SH]: refuse a test key before anything is built or signed.
release_key_check() {
	_is=${1:-install.sh}
	_why=$(test_key_reason "$_is")
	if [ -n "$_why" ]; then
		[ -n "${ALLOW_TEST_KEY:-}" ] ||
			rc_die "$_is carries a test signing key ($_why). A release needs the offline release key in MINISIGN_PUBKEY of daemon/install.sh and site/src/config.ts (docs/release.md, section "Keys"); --allow-test-key is for local test runs only"
		echo "warning: $_is carries a test signing key ($_why); --allow-test-key: a local test run, never publish it" >&2
	fi
	# The site shows the same key for the manual check and deploys install.sh only if the release
	# verifies with it (site/scripts/fetch-install-sh.sh).
	_cfg=../site/src/config.ts
	if [ -f "$_cfg" ]; then
		_s=$(sed -n 's/^export const MINISIGN_PUBKEY = "\(.*\)";.*$/\1/p' "$_cfg")
		[ "$_s" = "$(pubkey_of "$_is")" ] ||
			rc_die "site/src/config.ts has the release key \"$_s\", $_is has \"$(pubkey_of "$_is")\": they must be the same"
	fi
}

# prev_release_tag TAG: the release before TAG (versionsort.suffix: v1.0.0-rc.1 comes before v1.0.0).
prev_release_tag() {
	git -c versionsort.suffix=- tag -l 'daemon/v[0-9]*' --sort=v:refname |
		awk -v t="$1" '$0 == t { print p; exit } { p = $0 }'
}

# signers_for TAG: the allowed_signers file to check TAG against.
#   $ALLOWED_SIGNERS           the maintainer's own copy, if set;
#   the previous release tag   its allowed_signers: a signer added in a commit becomes trusted only
#                              for the release after the one that shipped it, so a tag and the
#                              commit it points to cannot vouch for themselves;
#   TAG itself                 only for the first signed release, with a note to check the file.
signers_for() {
	if [ -n "${ALLOWED_SIGNERS:-}" ]; then
		[ -f "$ALLOWED_SIGNERS" ] || rc_die "ALLOWED_SIGNERS=$ALLOWED_SIGNERS: no such file"
		echo "tag signers: $ALLOWED_SIGNERS (ALLOWED_SIGNERS)" >&2
		echo "$ALLOWED_SIGNERS"
		return 0
	fi
	_prev=$(prev_release_tag "$1")
	_f="$RC_TMP/allowed_signers"
	if [ -n "$_prev" ] && git show "$_prev:allowed_signers" >"$_f" 2>/dev/null; then
		echo "tag signers: allowed_signers of $_prev, the release before" >&2
	else
		git show "$1:allowed_signers" >"$_f" 2>/dev/null || rc_die "$1 has no allowed_signers at the repository root"
		echo "tag signers: allowed_signers of $1 itself (no earlier release has one): check who is in it" >&2
	fi
	echo "$_f"
}

# tag_check TAG: the build and the signature come only from a checked tag.
tag_check() {
	_t=$1
	git rev-parse -q --verify "refs/tags/$_t" >/dev/null || rc_die "no tag $_t in this clone (git fetch origin tag $_t)"
	[ "$(git cat-file -t "refs/tags/$_t")" = tag ] ||
		rc_die "$_t is a lightweight tag: release tags are annotated and signed (git tag -s, docs/release.md)"
	# Only an SSH signature: allowedSignersFile does not govern GPG, which trusts any key in the keyring.
	git cat-file tag "$_t" | grep -qx -e '-----BEGIN SSH SIGNATURE-----' ||
		rc_die "$_t has no SSH signature: release tags are signed with the maintainer's SSH key (docs/release.md)"
	_sig=$(signers_for "$_t")
	grep -q '^[^#[:space:]]' "$_sig" ||
		rc_die "allowed_signers lists nobody: the maintainer adds the public SSH key that signs release tags (docs/release.md, section "Signed Tags")"
	git -c gpg.ssh.allowedSignersFile="$_sig" verify-tag "$_t" ||
		rc_die "the signature of $_t does not check out against allowed_signers: not releasing"
	_h=$(git rev-parse HEAD)
	_c=$(git rev-parse "$_t^{commit}")
	[ "$_h" = "$_c" ] || rc_die "HEAD is $_h, $_t is $_c: check out the tag (git checkout $_t)"
	# Untracked files count too: Go sets vcs.modified=true from the full git status (cmd/go/internal/vcs).
	_dirty=$(git status --porcelain)
	if [ -n "$_dirty" ]; then
		printf '%s\n' "$_dirty" | head -n 20 >&2
		rc_die "the work tree is not a clean checkout of $_t (above, untracked files too)"
	fi
}

# rotation_check [TAG]: when the release key differs from the key of the release before TAG,
# installs pinned to the old key accept the new one only through a statement signed by the old key:
# daemon/release-key.txt and release-key.txt.minisig (scripts/rotate-release-key.sh). A statement
# in the tree must name the current key. Sets RC_OLD_KEY when the key changed.
rotation_check() {
	RC_OLD_KEY=""
	_pub=$(pubkey_of install.sh)
	if [ -f release-key.txt ] || [ -f release-key.txt.minisig ]; then
		[ -f release-key.txt ] && [ -f release-key.txt.minisig ] ||
			rc_die "release-key.txt and release-key.txt.minisig come together"
		[ "$(sed -n 1p release-key.txt)" = "$_pub" ] ||
			rc_die "release-key.txt hands over to another key than MINISIGN_PUBKEY of install.sh: a stale statement"
	fi
	[ -n "${1:-}" ] || return 0
	_prev=$(prev_release_tag "$1")
	[ -n "$_prev" ] || return 0
	_old=$(git show "$_prev:daemon/install.sh" 2>/dev/null | sed -n 's/^MINISIGN_PUBKEY="\(.*\)"$/\1/p')
	if [ -n "$_old" ] && [ "$_old" != "$_pub" ]; then
		[ -f release-key.txt ] ||
			rc_die "the release key changed since $_prev ($_old -> $_pub) but daemon/release-key.txt is missing: every install pinned to the old key would refuse this release (scripts/rotate-release-key.sh)"
		RC_OLD_KEY=$_old
	fi
	return 0
}
