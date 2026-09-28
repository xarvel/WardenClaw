# SPDX-License-Identifier: AGPL-3.0-or-later
# Checks shared by scripts/release.sh: sourced, not run, from daemon/.
# docs/release.md, section "Signed Tags".
#
#   tag_check TAG              TAG is signed by an allowed signer, HEAD is TAG, the tree is clean
#   prev_release_tag TAG       the daemon release tag before TAG in version order (empty for the first)
#
# ALLOWED_SIGNERS=FILE checks tags against that file instead of the repository's (see signers_for).

rc_die() {
	echo "error: $*" >&2
	exit 1
}

RC_TMP=$(mktemp -d) || rc_die "mktemp"
trap 'rm -rf "$RC_TMP"' EXIT
trap 'exit 130' INT TERM

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

# tag_check TAG: the build comes only from a checked tag.
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
