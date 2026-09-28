#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Release key change (docs/release.md, section "Key Rotation"). Installs pinned to the old key accept the
# new one only through a statement signed by the old key. On the maintainer's offline machine:
#
#   scripts/rotate-release-key.sh ~/.minisign/wardenclaw.key ~/.minisign/wardenclaw-new.pub
#
# Writes daemon/release-key.txt (the new public key, one line) and release-key.txt.minisig (signed
# with the old secret key, trusted comment "wardend release-key <new key> <date>"), checks it with
# the key install.sh carries now, the old one, and prints what else goes into the same commit.
# If the old key leaked, a statement proves nothing (anyone could sign one); instead the old key
# goes to REFUSED_PUBKEYS and pinned installs are re-pinned by hand (section "Key Rotation").
set -eu
cd "$(dirname "$0")/.."
. scripts/release-checks.sh

[ $# -eq 2 ] || {
	echo "usage: scripts/rotate-release-key.sh OLD_SECRET_KEY NEW_PUBLIC_KEY_FILE" >&2
	exit 2
}
command -v minisign >/dev/null || rc_die "minisign not found"
OLD=$(pubkey_of install.sh)
NEW=$(sed -n 2p "$2")
case "$NEW" in RW*) ;; *) rc_die "$2: no minisign public key on line 2" ;; esac
[ "$NEW" != "$OLD" ] || rc_die "$2 is the key install.sh already carries"
for k in $(refused_of install.sh); do
	[ "$k" != "$NEW" ] || rc_die "the new key is in REFUSED_PUBKEYS of install.sh"
done

printf '%s\n' "$NEW" >release-key.txt
minisign -S -s "$1" -m release-key.txt -x release-key.txt.minisig -t "wardend release-key $NEW $(date -u +%Y-%m-%d)"
if ! minisign -Vm release-key.txt -x release-key.txt.minisig -P "$OLD" >/dev/null; then
	rm -f release-key.txt release-key.txt.minisig
	rc_die "$1 is not the secret half of the key in install.sh ($OLD): no statement written"
fi
cat <<EOF
statement: daemon/release-key.txt and release-key.txt.minisig, $OLD -> $NEW
In the same commit:
  - MINISIGN_PUBKEY="$NEW" in daemon/install.sh and site/src/config.ts;
  - the new key in README.md, SECURITY.md and the DNS TXT record (docs/release.md, section "Keys");
  - the old key stays out of REFUSED_PUBKEYS: installs pinned to it follow the statement only
    while it is not refused.
Then a release as usual: release.sh and sign-release.sh check the statement against the release before.
EOF
