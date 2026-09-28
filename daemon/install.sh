#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# wardend installer.
#
#   curl -fsSL https://wardenclaw.dev/install.sh | sudo sh
#
# Default: hardened install (wardend as a root system service, the agent harness as a separate
# unprivileged user) in observe mode. Nothing is installed unless the release's checksums.txt
# carries a valid minisign signature from the release key (below, or the key an earlier install
# pinned) and the downloaded archive matches it.
# Flags: see usage() below or run with --help; when piping, pass them after `sh -s --`.
#
# The whole script is a set of function definitions and a call to main on the last line, so a
# download cut short cannot run a half-read script.

# ---- Project identity: change it here on a rename or a new domain (uninstall.sh repeats part) ----
PROJECT="WardenClaw"
DOMAIN="wardenclaw.dev"
# The site serves this file at INSTALL_URL: a copy of install.sh from the latest signed release,
# checked before every deploy (.github/workflows/site-pages.yml). Archives and checksums come
# from RELEASES_URL on GitHub.
INSTALL_URL="https://${DOMAIN}/install.sh"
DOCS_URL="https://${DOMAIN}/docs/install/"
UNINSTALL_DOCS_URL="https://${DOMAIN}/docs/uninstall/"
GITHUB_REPO="xarvel/WardenClaw"   # GitHub owner/repo of the releases (the monorepo)
RELEASES_URL="https://github.com/${GITHUB_REPO}/releases"
# Releases of the daemon are tagged daemon/vX.Y.Z in the monorepo (the Go convention for a module
# in the daemon/ subdirectory); the version itself (VERSION, signed comment) stays vX.Y.Z.
TAG_PREFIX="daemon/"
DAEMON="wardend"                  # binary, unit, /etc/<name>, /var/lib/<name>
CTL="wardenctl"
# minisign public key that verifies checksums.txt of every release: the release key, created and
# kept offline by the maintainer (2026-09-28, key id AEE3A4514E11F54F).
MINISIGN_PUBKEY="RWRP9RFOUaTjromMP2NoZJz+e9Mk6pNHqu+6IK3TL7jQkLabwOIk30mE"
# Keys never trusted for a download: test keys (their secret halves sit on development machines,
# where anyone could sign a "release" with them) and retired release keys. A local build signed
# by one of them installs only with --from-dir and --allow-test-key; it is never pinned.
#   17B171A98D90656D  test key of the snapshot builds (2026-09-27)
#   8829A57171E8F570  "someone else's key" of the site deploy checks (2026-09-28)
REFUSED_PUBKEYS="RWRtZZCNqXGxFzK4Bx/67mlyraSSBoW2evVgCLiCgulBoLMmnrUanfsi RWRw9ehxcaUpiJHm/VOHH8vGVa3CpNii1AonJxlwbAaJbTDjdk385jYA"
# ----------------------------------------------------------------------------------------------

MIN_KERNEL_MAJOR=5
MIN_KERNEL_MINOR=19
BIN_DIR="/usr/local/bin"
SHARE_DIR="/usr/local/share/${DAEMON}"
# From the release into SHARE_DIR (single-user: ~/.local/share/<name>); uninstall.sh runs from there.
SHARE_FILES="deploy redteam VERSION LICENSE NOTICE README.md install.sh uninstall.sh"
UNIT="/etc/systemd/system/${DAEMON}.service"
CONF_DIR="/etc/${DAEMON}"
STATE_DIR="/var/lib/${DAEMON}"
# The release key, pinned by the first hardened install: every later upgrade must be signed by it
# or by a key it handed over to (release-key.txt, see trusted_key below).
PINNED_KEY="$CONF_DIR/release.pub"
# Warn when "latest" is a release signed more than this many days ago (a frozen download).
STALE_DAYS=180

say() { printf '%s\n' "$*"; }
info() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}
run() {
	if [ -n "$DRY_RUN" ]; then
		printf '+ %s\n' "$*"
	else
		"$@"
	fi
}
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
	cat <<EOF
$PROJECT installer for $DAEMON.

  curl -fsSL $INSTALL_URL | sudo sh                  hardened install, asks two questions
  curl -fsSL $INSTALL_URL | sudo sh -s -- [flags]    the same with flags
  sudo $SHARE_DIR/install.sh             upgrade with the installed copy (no site involved)

  --agent-user NAME     harness user, created if missing (default: agent)
  --agent-home DIR      its home (default: existing home or /var/lib/NAME; not under /home)
  --harness-cmd 'CMD'   harness command, absolute paths, nothing under /home or /root
  --rw-paths 'D1 D2'    extra directories the harness may write to
  --public-url URL      external HTTPS URL of the phone endpoint (goes into the pairing QR)
  --http-listen ADDR    phone endpoint listen address (default 127.0.0.1:8787)
  --mode MODE           observe (default) | ticket | deny-list
  --ptrace-scope 2|skip kernel.yama.ptrace_scope (default 2)
  --with-wardenctl      also install the terminal approver (better kept on another machine)
  --single-user         trial install as your own user, no sudo (the model can disable it)
  --version vX.Y.Z      install this release instead of the latest
  --allow-downgrade     install a release older than the installed one (refused otherwise)
  --uninstall           remove $DAEMON, keep the journal: runs $SHARE_DIR/uninstall.sh, or the
                        one from the signed release; with --single-user the trial install, no sudo
  --purge               with --uninstall: also delete the journal and the config copy
  --remove-agent-user   with --uninstall: also delete the agent user and its group, if the
                        installer created them (its home with the harness data stays)
  --dry-run             print every step, change nothing, no root needed (also DRY_RUN=1)
  --from-dir DIR        take release files from DIR instead of downloading (local builds)
  --pubkey KEY          minisign public key to trust, only together with --from-dir; not pinned
  --allow-test-key      with --from-dir: accept a test key (local test builds only)
  -y, --yes             do not ask; a missing --harness-cmd becomes an error

The first hardened install pins the release key in $PINNED_KEY. Upgrades, from the
installed copy or from a new download, then need a release signed by that key; a new key is taken
only with a statement signed by the pinned one.

What each step does: $DOCS_URL
Removing it, what stays and why: $UNINSTALL_DOCS_URL
EOF
}

# ---- arguments ---------------------------------------------------------------------------------

need_val() { [ $# -ge 2 ] || die "$1 needs a value"; }

parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
		--agent-user) need_val "$@"; AGENT_USER=$2; shift 2 ;;
		--agent-user=*) AGENT_USER=${1#*=}; shift ;;
		--agent-home) need_val "$@"; AGENT_HOME=$2; shift 2 ;;
		--agent-home=*) AGENT_HOME=${1#*=}; shift ;;
		--harness-cmd) need_val "$@"; HARNESS_CMD=$2; shift 2 ;;
		--harness-cmd=*) HARNESS_CMD=${1#*=}; shift ;;
		--rw-paths) need_val "$@"; RW_PATHS=$2; RW_SET=1; shift 2 ;;
		--rw-paths=*) RW_PATHS=${1#*=}; RW_SET=1; shift ;;
		--public-url) need_val "$@"; PUBLIC_URL=$2; URL_SET=1; shift 2 ;;
		--public-url=*) PUBLIC_URL=${1#*=}; URL_SET=1; shift ;;
		--http-listen) need_val "$@"; HTTP_LISTEN=$2; shift 2 ;;
		--http-listen=*) HTTP_LISTEN=${1#*=}; shift ;;
		--mode) need_val "$@"; MODE=$2; shift 2 ;;
		--mode=*) MODE=${1#*=}; shift ;;
		--ptrace-scope) need_val "$@"; PTRACE_SCOPE=$2; shift 2 ;;
		--ptrace-scope=*) PTRACE_SCOPE=${1#*=}; shift ;;
		--version) need_val "$@"; VERSION=$2; shift 2 ;;
		--version=*) VERSION=${1#*=}; shift ;;
		--from-dir) need_val "$@"; FROM_DIR=$2; shift 2 ;;
		--from-dir=*) FROM_DIR=${1#*=}; shift ;;
		--pubkey) need_val "$@"; PUBKEY_OVERRIDE=$2; shift 2 ;;
		--pubkey=*) PUBKEY_OVERRIDE=${1#*=}; shift ;;
		--allow-test-key) ALLOW_TEST_KEY=1; shift ;;
		--allow-downgrade) ALLOW_DOWNGRADE=1; shift ;;
		--with-wardenctl) WITH_CTL=1; shift ;;
		--single-user) SINGLE_USER=1; shift ;;
		--uninstall) UNINSTALL=1; shift ;;
		--purge) PURGE=1; shift ;;
		--remove-agent-user) REMOVE_AGENT=1; shift ;;
		--dry-run) DRY_RUN=1; shift ;;
		-y | --yes) ASSUME_YES=1; shift ;;
		-h | --help) usage; exit 0 ;;
		*) die "unknown argument: $1 (see --help)" ;;
		esac
	done
	if [ -z "$UNINSTALL" ]; then
		[ -z "$PURGE" ] || die "--purge only works together with --uninstall"
		[ -z "$REMOVE_AGENT" ] || die "--remove-agent-user only works together with --uninstall"
	fi
	if [ -n "$REMOVE_AGENT" ] && [ -n "$SINGLE_USER" ]; then
		die "--remove-agent-user is for the hardened install; the single-user install has no agent user"
	fi
	case "$MODE" in observe | ticket | deny-list) ;; *) die "--mode $MODE: use observe, ticket or deny-list" ;; esac
	# 3 would also stop wardend from reading its children's memory and cannot be lowered until
	# reboot; 0 and 1 are weaker.
	case "$PTRACE_SCOPE" in 2 | skip) ;; *) die "--ptrace-scope $PTRACE_SCOPE: use 2 or skip" ;; esac
	VERSION=${VERSION#"$TAG_PREFIX"}
	case "$VERSION" in latest | v[0-9]*) ;; *) die "--version $VERSION: expected vX.Y.Z" ;; esac
	if [ -n "$PUBKEY_OVERRIDE" ]; then
		[ -n "$FROM_DIR" ] || die "--pubkey is only accepted together with --from-dir (local builds)"
		MINISIGN_PUBKEY=$PUBKEY_OVERRIDE
	fi
	[ -z "$ALLOW_TEST_KEY" ] || [ -n "$FROM_DIR" ] ||
		die "--allow-test-key is only accepted together with --from-dir: a download never trusts a test key"
}

# ---- questions: read from the terminal even when the script itself comes from a pipe -----------

tty_ok() { (: </dev/tty) 2>/dev/null; }

# ask VAR "question" "default"
ask() {
	_var=$1 _q=$2 _def=$3
	if [ -n "$ASSUME_YES" ]; then
		eval "$_var=\$_def"
		return 0
	fi
	if [ -t 0 ]; then
		_in=/dev/stdin
	elif tty_ok; then
		_in=/dev/tty
	else
		die "no terminal to ask \"$_q\"; pass the answer as a flag (see --help) and --yes"
	fi
	if [ -n "$_def" ]; then
		printf '%s [%s]: ' "$_q" "$_def" >&2
	else
		printf '%s: ' "$_q" >&2
	fi
	_ans=""
	IFS= read -r _ans <"$_in" || true
	[ -n "$_ans" ] || _ans=$_def
	eval "$_var=\$_ans"
}

confirm() {
	[ -z "$ASSUME_YES" ] || return 0
	_yn=""
	ask _yn "$1 [y/N]" ""
	case "$_yn" in y | Y | yes | YES) return 0 ;; esac
	die "cancelled, nothing changed"
}

# ---- platform checks ---------------------------------------------------------------------------

check_arch() {
	_os=$(uname -s)
	[ "$_os" = Linux ] || die "$DAEMON runs on Linux only (it gates execve with seccomp user notification); this is $_os. The approver for macOS ships as ${CTL}_darwin_*.tar.gz in $RELEASES_URL."
	_m=$(uname -m)
	case "$_m" in
	x86_64 | amd64) ARCH=amd64 ;;
	aarch64 | arm64) ARCH=arm64 ;;
	armv7* | armv8l) die "32-bit ARM ($_m) is not supported yet: the seccomp filter is built and tested for arm64 and x86_64 only. A 64-bit OS on the same board works (Raspberry Pi 3 and newer)." ;;
	*) die "CPU architecture $_m is not supported (x86_64 and aarch64 are)" ;;
	esac
}

check_platform() {
	check_arch
	_kv=$(uname -r)
	_kmaj=${_kv%%.*}
	_krest=${_kv#*.}
	_kmin=${_krest%%[!0-9]*}
	case "$_kmaj.$_kmin" in *[!0-9.]* | .* | *.) die "cannot parse the kernel version \"$_kv\"" ;; esac
	if [ "$_kmaj" -lt "$MIN_KERNEL_MAJOR" ] || { [ "$_kmaj" -eq "$MIN_KERNEL_MAJOR" ] && [ "$_kmin" -lt "$MIN_KERNEL_MINOR" ]; }; then
		die "kernel $_kv is too old: $DAEMON needs Linux ${MIN_KERNEL_MAJOR}.${MIN_KERNEL_MINOR}+ for SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (without it signals restart execve and every command turns into duplicate approval cards)"
	fi
	info "platform: Linux $_kv, $ARCH"

	if [ -z "$SINGLE_USER" ]; then
		have systemctl && [ -d /run/systemd/system ] ||
			die "the hardened install needs systemd as the init system (no /run/systemd/system). Without systemd use --single-user to try $DAEMON by hand"
		have bash || die "bash is required for the install steps (deploy/hardened-install.sh)"
		if [ -z "$DRY_RUN" ] && [ "$(id -u)" != 0 ]; then
			die "the hardened install needs root: curl -fsSL $INSTALL_URL | sudo sh   (or --dry-run to only print the steps)"
		fi
	elif [ "$(id -u)" = 0 ]; then
		die "--single-user installs for your own user: run it without sudo (curl -fsSL $INSTALL_URL | sh -s -- --single-user)"
	fi
}

check_tools() {
	for _t in tar gzip awk sed od dd; do
		have "$_t" || die "required tool not found: $_t"
	done
	if have sha256sum; then
		SHA256="sha256sum"
	elif have shasum; then
		SHA256="shasum -a 256"
	elif have openssl; then
		SHA256="openssl-sha256"
	else
		die "need sha256sum, shasum or openssl to check downloads"
	fi
	if have minisign; then
		VERIFIER=minisign
	elif have openssl && openssl pkeyutl -help 2>&1 | grep -q -- -rawin && openssl list -public-key-algorithms 2>/dev/null | grep -qi ed25519; then
		VERIFIER=openssl
	else
		die "need minisign or OpenSSL 3 (Ed25519) to verify the release signature. Install one of them (apt install minisign | openssl) and run again"
	fi
	if [ -z "$FROM_DIR" ]; then
		have curl || have wget || die "need curl or wget to download the release"
	fi
}

# ---- download and verification -----------------------------------------------------------------

fetch() { # url out
	if have curl; then
		curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"
	else
		wget --https-only -q -O "$2" "$1"
	fi
}

release_url() { # name -> URL of the file in the release
	if [ "$VERSION" = latest ]; then
		printf '%s/latest/download/%s' "$RELEASES_URL" "$1"
	else
		# the tag contains a slash: encode it (github.com/<repo>/releases/download/daemon%2Fv1.2.3/<file>)
		printf '%s/download/%s/%s' "$RELEASES_URL" "$(printf '%s%s' "$TAG_PREFIX" "$VERSION" | sed 's|/|%2F|g')" "$1"
	fi
}

get_file() { # name -> $WORK/name
	if [ -n "$FROM_DIR" ]; then
		[ -f "$FROM_DIR/$1" ] || die "$FROM_DIR/$1 not found"
		cp "$FROM_DIR/$1" "$WORK/$1"
	else
		_url=$(release_url "$1")
		fetch "$_url" "$WORK/$1" || die "download failed: $_url"
	fi
}

try_get_file() { # name -> $WORK/name, quietly; 1 if the release has no such file
	if [ -n "$FROM_DIR" ]; then
		[ -f "$FROM_DIR/$1" ] && cp "$FROM_DIR/$1" "$WORK/$1" && return 0
	elif fetch "$(release_url "$1")" "$WORK/$1" 2>/dev/null; then
		return 0
	fi
	rm -f "$WORK/$1"
	return 1
}

sha256_of() {
	if [ "$SHA256" = openssl-sha256 ]; then
		openssl dgst -sha256 -r "$1" | cut -d' ' -f1
	else
		$SHA256 "$1" | cut -d' ' -f1
	fi
}

b64d() { openssl base64 -d -A; }
hexbytes() { dd if="$1" bs=1 skip="$2" count="$3" 2>/dev/null | od -An -tx1 | tr -d ' \n'; }

# Verifies a minisign signature (prehashed "ED" or legacy "Ed") using OpenSSL 3 alone (no minisign binary).
# Format: https://jedisct1.github.io/minisign/ (public key: "Ed" | key id 8 | Ed25519 key 32;
# signature line: alg 2 | key id 8 | sig 64; global signature over sig || trusted comment).
verify_minisig_openssl() { # file sigfile pubkey
	_d="$WORK/mv"
	mkdir -p "$_d"
	printf '%s' "$3" | b64d >"$_d/pk" 2>/dev/null || return 1
	[ "$(wc -c <"$_d/pk" | tr -d ' ')" = 42 ] || return 1
	[ "$(hexbytes "$_d/pk" 0 2)" = 4564 ] || return 1
	_keyid=$(hexbytes "$_d/pk" 2 8)
	# SubjectPublicKeyInfo for Ed25519: 30 2a 30 05 06 03 2b 65 70 03 21 00 || key
	printf '\060\052\060\005\006\003\053\145\160\003\041\000' >"$_d/pk.der"
	dd if="$_d/pk" bs=1 skip=10 count=32 2>/dev/null >>"$_d/pk.der"

	sed -n 2p "$2" | b64d >"$_d/sig" 2>/dev/null || return 1
	[ "$(wc -c <"$_d/sig" | tr -d ' ')" = 74 ] || return 1
	[ "$(hexbytes "$_d/sig" 2 8)" = "$_keyid" ] || {
		warn "the signature was made by another key (key id $(hexbytes "$_d/sig" 2 8), expected $_keyid)"
		return 1
	}
	dd if="$_d/sig" bs=1 skip=10 count=64 2>/dev/null >"$_d/sig.raw"
	case "$(hexbytes "$_d/sig" 0 2)" in
	4544) openssl dgst -blake2b512 -binary "$1" >"$_d/msg" || return 1 ;; # "ED": BLAKE2b-512 prehash
	4564) cp "$1" "$_d/msg" ;;                                          # "Ed": legacy, raw file
	*) return 1 ;;
	esac
	openssl pkeyutl -verify -pubin -inkey "$_d/pk.der" -keyform DER -rawin \
		-in "$_d/msg" -sigfile "$_d/sig.raw" >/dev/null 2>&1 || return 1

	_tc=$(sed -n 3p "$2")
	case "$_tc" in "trusted comment: "*) ;; *) return 1 ;; esac
	_tc=${_tc#trusted comment: }
	{ cat "$_d/sig.raw"; printf '%s' "$_tc"; } >"$_d/gmsg"
	sed -n 4p "$2" | b64d >"$_d/gsig" 2>/dev/null || return 1
	openssl pkeyutl -verify -pubin -inkey "$_d/pk.der" -keyform DER -rawin \
		-in "$_d/gmsg" -sigfile "$_d/gsig" >/dev/null 2>&1
}

verify_sig() { # file sigfile pubkey: a good signature over file by this key
	if [ "$VERIFIER" = minisign ]; then
		minisign -Vm "$1" -x "$2" -P "$3" >/dev/null 2>&1
	else
		verify_minisig_openssl "$1" "$2" "$3"
	fi
}

signed_comment() { # sigfile -> its trusted comment (covered by the signature)
	_sc=$(sed -n 3p "$1")
	case "$_sc" in "trusted comment: "*) printf '%s' "${_sc#trusted comment: }" ;; esac
}

# ---- the release key: refused test keys, the pin, key changes ----------------------------------

key12() { printf '%s' "$1" | cut -c1-12; }

key_ok() { # a minisign public key line: "RW" and base64 of 42 bytes
	case "$1" in RW*) ;; *) return 1 ;; esac
	[ ${#1} -eq 56 ] || return 1
	case "$1" in *[!A-Za-z0-9+/=]*) return 1 ;; esac
	return 0
}

is_refused() { # a test or retired key (REFUSED_PUBKEYS)
	for _rk in $REFUSED_PUBKEYS; do
		[ "$1" != "$_rk" ] || return 0
	done
	return 1
}

# trusted_key: which key must have signed this release (TRUSTED_KEY), what is pinned (PINNED).
#   --pubkey (with --from-dir)    that key, for this run only, never pinned;
#   hardened, $PINNED_KEY exists  the pinned key. When this script carries another key, the release
#                                 must include a statement, signed by the pinned key, naming it
#                                 (rotate_key);
#   otherwise                     the key in this script; the first hardened install pins it.
trusted_key() {
	TRUSTED_KEY=$MINISIGN_PUBKEY PINNED="" NEW_PIN=""
	if [ -z "$SINGLE_USER" ] && [ -z "$PUBKEY_OVERRIDE" ]; then
		if [ -f "$PINNED_KEY" ]; then
			PINNED=$(sed -n 2p "$PINNED_KEY")
			key_ok "$PINNED" || die "$PINNED_KEY has no minisign public key on line 2. Restore it from the config backup in $STATE_DIR, or check the release key where $DOCS_URL says and write it there"
			is_refused "$PINNED" && die "the release key pinned in $PINNED_KEY ($(key12 "$PINNED")...) is retired: it was lost or leaked. Check the new key where $DOCS_URL says (not only on this site), remove $PINNED_KEY and run again. Nothing was changed."
			TRUSTED_KEY=$PINNED
		elif [ -d "$CONF_DIR" ] && [ ! -x "$CONF_DIR" ]; then
			[ -n "$DRY_RUN" ] || die "cannot read $CONF_DIR"
			warn "not root: $CONF_DIR is closed, so this dry run does not check a pinned release key"
		fi
	fi
	key_ok "$TRUSTED_KEY" || die "\"$TRUSTED_KEY\" is not a minisign public key"
	if is_refused "$TRUSTED_KEY"; then
		[ -n "$FROM_DIR" ] ||
			die "this installer trusts a TEST or retired release key ($(key12 "$TRUSTED_KEY")...), so it installs no published release. Take install.sh from $INSTALL_URL and check it as $DOCS_URL says. Nothing was changed."
		[ -n "$ALLOW_TEST_KEY" ] ||
			die "the release key $(key12 "$TRUSTED_KEY")... is a TEST or retired key: a local test build needs --allow-test-key. Nothing was changed."
		warn "TEST key $(key12 "$TRUSTED_KEY")...: a local test build, never for a real system; the key is not pinned"
	fi
	if [ -n "$PINNED" ] && [ "$MINISIGN_PUBKEY" != "$PINNED" ]; then
		rotate_key "$MINISIGN_PUBKEY" ||
			die "this installer trusts the release key $(key12 "$MINISIGN_PUBKEY")..., but this machine pinned $(key12 "$PINNED")... in $PINNED_KEY, and the release has no statement of the pinned key handing over to the new one. Nothing was changed. Upgrade with the installed copy (sudo $SHARE_DIR/install.sh); if the project announced a new key, check it where $DOCS_URL says"
	fi
}

# rotate_key [KEY]: take a new release key from release-key.txt of the release, a statement signed
# by the trusted (pinned) key. The file holds the new key on one line; the signed comment is
# "<daemon> release-key <new key> [date]". KEY given: the statement must name exactly it. The new
# key is trusted for this run and pinned after the install (NEW_PIN).
rotate_key() {
	try_get_file release-key.txt && try_get_file release-key.txt.minisig || return 1
	if ! verify_sig "$WORK/release-key.txt" "$WORK/release-key.txt.minisig" "$TRUSTED_KEY"; then
		warn "release-key.txt of this release is not signed by the key $(key12 "$TRUSTED_KEY")...: ignored"
		return 1
	fi
	_new=$(sed -n 1p "$WORK/release-key.txt")
	_rc=$(signed_comment "$WORK/release-key.txt.minisig")
	case "$_rc" in
	"$DAEMON release-key $_new" | "$DAEMON release-key $_new "*) ;;
	*)
		warn "the signed comment of release-key.txt (\"$_rc\") does not name the key in the file: ignored"
		return 1
		;;
	esac
	if ! key_ok "$_new" || is_refused "$_new"; then
		warn "release-key.txt hands over to a malformed, test or retired key: ignored"
		return 1
	fi
	if [ -n "${1:-}" ] && [ "$_new" != "$1" ]; then
		warn "release-key.txt hands over to $(key12 "$_new")..., not to $(key12 "$1")...: ignored"
		return 1
	fi
	info "release key change: $(key12 "$TRUSTED_KEY")... -> $(key12 "$_new")... (statement signed by the pinned key)"
	TRUSTED_KEY=$_new NEW_PIN=$_new
}

# pin_key: after a hardened install the trusted key goes to $PINNED_KEY (root, 0644).
pin_key() {
	if [ -n "$PUBKEY_OVERRIDE" ]; then
		warn "the key given with --pubkey is not pinned${PINNED:+; $PINNED_KEY stays as it is}"
		return 0
	fi
	if is_refused "$TRUSTED_KEY"; then return 0; fi
	[ "$TRUSTED_KEY" != "$PINNED" ] || return 0
	if [ -n "$DRY_RUN" ]; then
		printf '+ pin the release key %s... in %s\n' "$(key12 "$TRUSTED_KEY")" "$PINNED_KEY"
		return 0
	fi
	[ -d "$CONF_DIR" ] || die "no $CONF_DIR: cannot pin the release key"
	printf 'untrusted comment: %s release key, pinned by install.sh\n%s\n' "$PROJECT" "$TRUSTED_KEY" >"$PINNED_KEY.new" &&
		chown root:root "$PINNED_KEY.new" && chmod 0644 "$PINNED_KEY.new" && mv -f "$PINNED_KEY.new" "$PINNED_KEY" ||
		die "cannot write $PINNED_KEY"
	if [ -n "$PINNED" ]; then
		info "release key in $PINNED_KEY: $(key12 "$PINNED")... replaced by $(key12 "$TRUSTED_KEY")..."
	else
		info "release key pinned in $PINNED_KEY ($(key12 "$TRUSTED_KEY")...)"
	fi
}

# ---- versions: no silent downgrade, a warning for a stale "latest" ------------------------------

# ver_lt A B: version A comes before B (semver order of vX.Y.Z[-pre], build metadata ignored).
ver_lt() {
	awk -v a="$1" -v b="$2" '
	function cmpnum(x, y) { x += 0; y += 0; return (x < y) ? -1 : (x > y) }
	function cmpid(x, y,   xn, yn) {
		xn = (x ~ /^[0-9]+$/); yn = (y ~ /^[0-9]+$/)
		if (xn && yn) return cmpnum(x, y)
		if (xn != yn) return xn ? -1 : 1
		return (x < y) ? -1 : (x > y)
	}
	function cmpver(x, y,   xp, yp, i, c, xs, ys, xn, yn) {
		sub(/^v/, "", x); sub(/^v/, "", y); sub(/\+.*/, "", x); sub(/\+.*/, "", y)
		xp = ""; yp = ""
		if ((i = index(x, "-")) > 0) { xp = substr(x, i + 1); x = substr(x, 1, i - 1) }
		if ((i = index(y, "-")) > 0) { yp = substr(y, i + 1); y = substr(y, 1, i - 1) }
		split(x, xs, "."); split(y, ys, ".")
		for (i = 1; i <= 3; i++) if ((c = cmpnum(xs[i], ys[i])) != 0) return c
		if (xp == yp) return 0
		if (xp == "") return 1
		if (yp == "") return -1
		xn = split(xp, xs, "."); yn = split(yp, ys, ".")
		for (i = 1; i <= xn && i <= yn; i++) if ((c = cmpid(xs[i], ys[i])) != 0) return c
		return cmpnum(xn, yn)
	}
	BEGIN { exit (cmpver(a, b) < 0) ? 0 : 1 }'
}

check_downgrade() {
	if [ -n "$SINGLE_USER" ]; then _vf="$HOME/.local/share/$DAEMON/VERSION"; else _vf="$SHARE_DIR/VERSION"; fi
	[ -f "$_vf" ] || return 0
	_inst=$(cat "$_vf")
	ver_lt "$RELEASE" "$_inst" || return 0
	[ -n "$ALLOW_DOWNGRADE" ] ||
		die "$RELEASE is older than the installed $_inst: refusing to downgrade (a rolled-back or frozen download looks like this). To go back on purpose: --version $RELEASE --allow-downgrade. Nothing was changed."
	warn "downgrade $_inst -> $RELEASE (--allow-downgrade)"
}

days_of() { # YYYY-MM-DD -> days since 1970-01-01
	printf '%s\n' "$1" | awk -F- '{
		y = $1 + 0; m = $2 + 0; d = $3 + 0
		if (m <= 2) { y -= 1; m += 12 }
		print 365 * y + int(y / 4) - int(y / 100) + int(y / 400) + int((153 * (m - 3) + 2) / 5) + d - 719469
	}'
}

check_age() { # the signed date of the release against this machine's clock
	[ -n "$RELEASE_DATE" ] || return 0
	_today=$(date -u +%Y-%m-%d 2>/dev/null) || return 0
	_age=$(($(days_of "$_today") - $(days_of "$RELEASE_DATE")))
	if [ "$_age" -lt -2 ]; then
		warn "$RELEASE is signed on $RELEASE_DATE, in the future for this machine ($_today): check the clock"
	elif [ "$VERSION" = latest ] && [ "$_age" -gt "$STALE_DAYS" ]; then
		warn "the latest release, $RELEASE, was signed $_age days ago ($RELEASE_DATE). If $RELEASES_URL lists a newer one, this download is stale or frozen: stop and check"
	fi
}

verify_release() { # fetch the release into $WORK (or --from-dir), verify it; PKG = unpacked archive
	WORK=$(mktemp -d 2>/dev/null || mktemp -d -t "$DAEMON-install")
	[ -n "$WORK" ] && [ -d "$WORK" ] || die "cannot create a temporary directory"
	trap 'rm -rf "$WORK"' EXIT
	trap 'exit 130' INT TERM
	if [ -n "$FROM_DIR" ]; then
		info "release files from $FROM_DIR"
	else
		info "downloading $DAEMON ($VERSION) from $RELEASES_URL"
	fi
	trusted_key
	get_file checksums.txt
	get_file checksums.txt.minisig
	if ! verify_sig "$WORK/checksums.txt" "$WORK/checksums.txt.minisig" "$TRUSTED_KEY"; then
		# An installed copy from an older release may fetch a release signed by a new key; such a
		# release includes the pinned key's hand-over statement (release-key.txt).
		if [ -n "$PINNED" ] && [ -z "$NEW_PIN" ] && rotate_key &&
			verify_sig "$WORK/checksums.txt" "$WORK/checksums.txt.minisig" "$TRUSTED_KEY"; then
			:
		elif [ -n "$PINNED" ]; then
			die "SIGNATURE CHECK FAILED for checksums.txt: not signed by the $PROJECT release key pinned in $PINNED_KEY ($(key12 "$PINNED")...), and no statement of that key hands over to the one that signed it. Nothing was changed."
		else
			die "SIGNATURE CHECK FAILED for checksums.txt: not signed by the $PROJECT release key. Nothing was changed."
		fi
	fi
	# The trusted comment is covered by the signature and names the release:
	# "<daemon> <version> checksums.txt [<date signed, YYYY-MM-DD>]".
	_tc=$(signed_comment "$WORK/checksums.txt.minisig")
	set -f
	# shellcheck disable=SC2086 # split the comment into words on purpose
	set -- $_tc
	set +f
	{ [ $# -eq 3 ] || [ $# -eq 4 ]; } && [ "$1" = "$DAEMON" ] && [ "$3" = checksums.txt ] ||
		die "the signed comment \"$_tc\" does not describe a $DAEMON release; refusing"
	case "$2" in v[0-9]*) ;; *) die "the signed comment names no version: \"$_tc\"" ;; esac
	if [ "$VERSION" != latest ] && [ "$2" != "$VERSION" ]; then
		die "asked for $VERSION but the signature is for $2 (possible rollback); refusing"
	fi
	RELEASE=$2 RELEASE_DATE=""
	if [ $# -eq 4 ]; then
		case "$4" in
		[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]) RELEASE_DATE=$4 ;;
		*) die "the signed comment \"$_tc\" ends in \"$4\", not a date (YYYY-MM-DD); refusing" ;;
		esac
	fi
	_pin=""
	[ "$TRUSTED_KEY" != "$PINNED" ] || _pin=", pinned"
	info "signature: ok ($VERIFIER, key $(key12 "$TRUSTED_KEY")...$_pin, release $RELEASE${RELEASE_DATE:+ signed $RELEASE_DATE})"
	check_age

	TARBALL="${DAEMON}_linux_${ARCH}.tar.gz"
	_want=$(awk -v f="$TARBALL" '$2 == f || $2 == "*" f { print $1 }' "$WORK/checksums.txt")
	[ -n "$_want" ] || die "release $RELEASE has no build for linux/$ARCH ($TARBALL is not in checksums.txt)"
	[ "$(printf '%s\n' "$_want" | wc -l | tr -d ' ')" = 1 ] || die "checksums.txt lists $TARBALL twice; refusing"
	get_file "$TARBALL"
	_got=$(sha256_of "$WORK/$TARBALL")
	[ "$_got" = "$_want" ] || die "CHECKSUM MISMATCH for $TARBALL (got $_got, signed $_want). Nothing was changed."
	info "checksum: ok ($TARBALL)"

	mkdir "$WORK/x"
	tar -xzf "$WORK/$TARBALL" -C "$WORK/x" || die "cannot unpack $TARBALL"
	PKG="$WORK/x/${DAEMON}_linux_${ARCH}"
	for _f in "$DAEMON" "$CTL" VERSION uninstall.sh deploy/hardened-install.sh deploy/wardend.system.service redteam/hardened-check.sh; do
		[ -e "$PKG/$_f" ] || die "the release archive lacks $_f"
	done
	[ "$(cat "$PKG/VERSION")" = "$RELEASE" ] || die "archive VERSION $(cat "$PKG/VERSION") differs from the signed release $RELEASE"
}

# ---- hardened install --------------------------------------------------------------------------

install_share() { # copy SHARE_FILES of the release (deploy/, redteam/, the scripts, docs) to a root-owned place
	info "reference files: $SHARE_DIR"
	run rm -rf "$SHARE_DIR.new"
	run mkdir -p "$SHARE_DIR.new"
	for _f in $SHARE_FILES; do
		if [ -e "$PKG/$_f" ]; then run cp -R "$PKG/$_f" "$SHARE_DIR.new/"; fi
	done
	run chown -R root:root "$SHARE_DIR.new"
	run chmod -R go-w "$SHARE_DIR.new"
	run rm -rf "$SHARE_DIR"
	run mv "$SHARE_DIR.new" "$SHARE_DIR"
}

install_ctl() {
	[ -n "$WITH_CTL" ] || return 0
	warn "$CTL on the agent's host: keep its device key away from the agent user; a separate machine is safer"
	run install -o root -g root -m 0755 "$PKG/$CTL" "$BIN_DIR/$CTL"
}

hardened() {
	_existing=""
	[ -f "$UNIT" ] && [ -f "$CONF_DIR/config.json" ] && _existing=1
	_old=""
	[ -f "$SHARE_DIR/VERSION" ] && _old=$(cat "$SHARE_DIR/VERSION")

	if [ -n "$_existing" ] && [ -z "$HARNESS_CMD" ]; then
		# Upgrade or re-run: binaries, reference files, the agent's polkit guard and the key pin;
		# config, unit and user stay as they are.
		if [ -n "$_old" ]; then info "upgrade: $_old -> $RELEASE"; else info "existing install found, updating binaries to $RELEASE"; fi
		if [ -f "$BIN_DIR/$DAEMON" ] && [ "$(sha256_of "$BIN_DIR/$DAEMON")" = "$(sha256_of "$PKG/$DAEMON")" ]; then
			info "$BIN_DIR/$DAEMON is already $RELEASE"
		else
			run install -o root -g root -m 0755 "$PKG/$DAEMON" "$BIN_DIR/$DAEMON"
			_restart=1
		fi
		if [ -f "$SHARE_DIR/deploy/wardend.system.service" ] &&
			! cmp -s "$SHARE_DIR/deploy/wardend.system.service" "$PKG/deploy/wardend.system.service"; then
			warn "the unit template changed in $RELEASE. To re-render $UNIT run again with --harness-cmd '...' (and your --agent-user/--rw-paths)"
		fi
		install_share
		# Installs made before the polkit rule existed get it here: without it the agent can enable
		# linger for itself and run commands from its own systemd --user, outside the gate.
		_agent=$(sed -n 's/.*"child_user": *"\([^"]*\)".*/\1/p' "$CONF_DIR/config.json" | head -n 1)
		if [ -n "$_agent" ]; then
			ONLY_AGENT_GUARD=1 AGENT_USER="$_agent" DRY_RUN="$DRY_RUN" \
				bash "$PKG/deploy/hardened-install.sh" "$PKG/$DAEMON" || die "agent guard step failed (see above)"
		else
			warn "no child_user in $CONF_DIR/config.json: skipped the polkit rule for the agent user"
		fi
		if [ -n "$WITH_CTL" ] || [ -f "$BIN_DIR/$CTL" ]; then
			run install -o root -g root -m 0755 "$PKG/$CTL" "$BIN_DIR/$CTL"
		fi
		pin_key
		say ""
		if [ -n "${_restart:-}" ]; then
			say "Upgraded. The running $DAEMON keeps the old binary until a restart, which also restarts the harness:"
			say "  sudo systemctl restart $DAEMON"
		else
			say "Nothing to upgrade: $RELEASE is installed."
		fi
		say "Next upgrade: sudo $SHARE_DIR/install.sh   (the installed copy, checked against $PINNED_KEY)"
		return 0
	fi

	say ""
	say "Hardened install: $DAEMON runs as root, your agent's harness runs as a separate user"
	say "without sudo, and the model cannot switch the guard off. Start mode: $MODE."
	[ -n "$AGENT_USER" ] || ask AGENT_USER "User account for the agent harness" "agent"
	while [ -z "$HARNESS_CMD" ]; do
		[ -z "$ASSUME_YES" ] || die "--harness-cmd is required (the command that starts your agent harness, absolute paths)"
		say "Harness command: how the agent harness starts, with absolute paths, nothing under /home or /root."
		say "  example: /usr/bin/node /opt/openclaw/dist/index.js gateway --port 18789"
		ask HARNESS_CMD "Harness command" ""
	done
	[ -n "$RW_SET" ] || ask RW_PATHS "Extra directories the agent may write to (space-separated, empty for none)" ""
	[ -n "$URL_SET" ] || ask PUBLIC_URL "Public HTTPS URL of the phone endpoint, if you have a tunnel (empty to skip)" ""

	say ""
	say "  agent user:   $AGENT_USER${AGENT_HOME:+ (home $AGENT_HOME)}"
	say "  harness:      $HARNESS_CMD"
	say "  writable:     ${RW_PATHS:-(agent home only)}"
	say "  phone URL:    ${PUBLIC_URL:-(none, local $HTTP_LISTEN)}"
	say "  mode:         $MODE"
	say ""
	[ -n "$DRY_RUN" ] || confirm "Install $DAEMON $RELEASE with these settings?"

	if [ -n "$DRY_RUN" ]; then
		_script="$PKG/deploy/hardened-install.sh"
	else
		install_share
		_script="$SHARE_DIR/deploy/hardened-install.sh"
	fi
	# The root-side steps live in one place: deploy/hardened-install.sh from the same signed archive.
	env AGENT_USER="$AGENT_USER" AGENT_HOME="$AGENT_HOME" RW_PATHS="$RW_PATHS" \
		HARNESS_CMD="$HARNESS_CMD" MODE="$MODE" HTTP_LISTEN="$HTTP_LISTEN" PUBLIC_URL="$PUBLIC_URL" \
		PTRACE_SCOPE="$PTRACE_SCOPE" DRY_RUN="$DRY_RUN" NO_NEXT_STEPS=1 \
		bash "$_script" "$PKG/$DAEMON" || die "hardened install steps failed (see above)"
	if [ -n "$DRY_RUN" ]; then install_share; fi
	install_ctl
	pin_key

	_sock="$STATE_DIR/$DAEMON.sock"
	_home=$AGENT_HOME
	[ -n "$_home" ] || _home=$(getent passwd "$AGENT_USER" 2>/dev/null | cut -d: -f6)
	[ -n "$_home" ] || _home="/var/lib/$AGENT_USER"
	if [ "$(systemctl is-active "$DAEMON" 2>/dev/null || true)" = active ]; then
		_state="It is running the previous binary and unit: sudo systemctl restart $DAEMON to apply (restarts the harness)"
	else
		_state="It is NOT running yet"
	fi
	# An existing config is kept as is, so its mode wins over --mode on a re-run.
	_mode=$(sed -n 's/.*"mode": *"\([^"]*\)".*/\1/p' "$CONF_DIR/config.json" 2>/dev/null | head -n 1)
	[ -n "$_mode" ] || _mode=$MODE
	cat <<EOF

$DAEMON $RELEASE is installed (hardened, mode: $_mode). $_state.

Next steps (details: $DOCS_URL):
  1. Stop the harness's old service so it cannot start around $DAEMON, and move its data
     to the agent's home:  sudo rsync -a ~/.<harness>/ $_home/.<harness>/
                           sudo chown -R $AGENT_USER: $_home
  2. Start:   sudo systemctl enable --now $DAEMON
              ps -o user,pid,args --ppid "\$(systemctl show -p MainPID --value $DAEMON)"   # harness as $AGENT_USER
  3. Pair your phone from your own terminal (not from a chat with the agent); it prints a QR:
              sudo $DAEMON pair start --socket $_sock
              sudo $DAEMON pair approve <id> --socket $_sock
  4. About a week in observe: review what would have needed approval, add housekeeping to a policy,
     then set "mode": "ticket" in $CONF_DIR/config.json and  sudo systemctl restart $DAEMON
  5. Verify as the agent user (every attack must be refused, FAIL=0):
              sudo -u $AGENT_USER bash -s < $SHARE_DIR/redteam/hardened-check.sh

Upgrade:  sudo $SHARE_DIR/install.sh
  the installed copy downloads the new release and checks it against the release key pinned in
  $PINNED_KEY; it does not depend on the site. A downgrade needs --allow-downgrade.
Uninstall (keeps the journal):  sudo $SHARE_DIR/uninstall.sh
  it prints what it stops, removes and keeps before it asks; what stays and why: $UNINSTALL_DOCS_URL
EOF
}

# ---- single-user install -----------------------------------------------------------------------

single_user() {
	_bin="$HOME/.local/bin"
	_share="$HOME/.local/share/$DAEMON"
	_state="$HOME/.$DAEMON"
	cat >&2 <<EOF

!!! SINGLE-USER INSTALL: FOR TRYING $DAEMON OUT ONLY !!!
$DAEMON and the agent harness run as the same user ($(id -un)). A model with that user's rights
can kill $DAEMON, ptrace it, or rewrite its binary, config, key or unit and restart the harness
without the gate, all without a single execve. Use the default hardened install for real agents.

EOF
	[ -n "$DRY_RUN" ] || confirm "Install for $(id -un) anyway?"
	run mkdir -p "$_bin" "$_share"
	run install -m 0755 "$PKG/$DAEMON" "$_bin/$DAEMON"
	for _f in $SHARE_FILES; do
		if [ -e "$PKG/$_f" ]; then run cp -R "$PKG/$_f" "$_share/"; fi
	done
	run mkdir -p "$_state"
	run chmod 0700 "$_state"
	if [ -e "$_state/config.json" ]; then
		info "$_state/config.json exists, left as is"
	else
		run cp "$PKG/deploy/config.example.json" "$_state/config.json"
		run chmod 0600 "$_state/config.json"
	fi
	cat <<EOF

$DAEMON $RELEASE is installed for $(id -un) in $_bin (single-user, trial only).

Try it:   $DAEMON run --mode observe -- <harness command>
Pair:     $DAEMON pair start       (in another terminal, prints a QR)
Wrap a systemd user service: $_share/deploy/wardend-observe.conf and $DOCS_URL
When done trying, remove it and use the hardened install:
  $_share/uninstall.sh --single-user   (details: $UNINSTALL_DOCS_URL)
EOF
	case ":$PATH:" in *":$_bin:"*) ;; *) warn "$_bin is not in PATH" ;; esac
}

# ---- uninstall ---------------------------------------------------------------------------------
# The uninstall lives in uninstall.sh, which the install copies next to the reference files.
# --uninstall runs that copy, or the uninstall.sh of the release, downloaded and checked here the
# same way as for an install. Nothing unchecked runs.

root_only() { # FILE: FILE and its directory belong to root, and nobody else may write to them
	[ "$(find "$1" "${1%/*}" -prune -user 0 ! -perm -020 ! -perm -002 -print 2>/dev/null | wc -l | tr -d ' ')" = 2 ]
}

uninstall() {
	set --
	if [ -n "$SINGLE_USER" ]; then set -- "$@" --single-user; fi
	if [ -n "$PURGE" ]; then set -- "$@" --purge; fi
	if [ -n "$REMOVE_AGENT" ]; then set -- "$@" --remove-agent-user; fi
	if [ -n "$AGENT_USER" ]; then set -- "$@" --agent-user "$AGENT_USER"; fi
	if [ -n "$DRY_RUN" ]; then set -- "$@" --dry-run; fi
	if [ -n "$ASSUME_YES" ]; then set -- "$@" --yes; fi
	_copy="$SHARE_DIR/uninstall.sh"
	if [ -n "$SINGLE_USER" ]; then
		# A root shell must not run a file that the user, and so the model, can rewrite.
		[ "$(id -u)" != 0 ] || die "--single-user --uninstall removes the trial install of your own user: run it without sudo"
		_copy="$HOME/.local/share/$DAEMON/uninstall.sh"
	fi
	# --version or --from-dir asks for the uninstall.sh of that release instead of the copy.
	if [ -z "$FROM_DIR" ] && [ "$VERSION" = latest ] && [ -f "$_copy" ]; then
		if [ -n "$SINGLE_USER" ] || root_only "$_copy"; then
			info "running $_copy"
			exec sh "$_copy" "$@"
		fi
		warn "$_copy is not root-only (owner or mode changed): not running it, taking the signed release"
	fi
	check_arch
	check_tools
	verify_release
	info "running uninstall.sh of $RELEASE"
	sh "$PKG/uninstall.sh" "$@"
}

# ---- main --------------------------------------------------------------------------------------

main() {
	set -eu
	umask 022
	AGENT_USER="" AGENT_HOME="" HARNESS_CMD="" RW_PATHS="" RW_SET="" PUBLIC_URL="" URL_SET=""
	HTTP_LISTEN="127.0.0.1:8787" MODE="observe" PTRACE_SCOPE="2" VERSION="latest"
	FROM_DIR="" PUBKEY_OVERRIDE="" WITH_CTL="" SINGLE_USER="" UNINSTALL="" PURGE="" REMOVE_AGENT=""
	ALLOW_TEST_KEY="" ALLOW_DOWNGRADE="" ASSUME_YES="" DRY_RUN="${DRY_RUN:-}"
	TRUSTED_KEY="" PINNED="" NEW_PIN="" RELEASE="" RELEASE_DATE=""
	parse_args "$@"
	if [ -n "$UNINSTALL" ]; then
		uninstall
		return 0
	fi
	[ -z "$DRY_RUN" ] || info "DRY RUN: nothing will be changed, commands are only printed"

	check_platform
	check_tools
	verify_release
	check_downgrade

	if [ -n "$SINGLE_USER" ]; then
		single_user
	else
		hardened
	fi
}

main "$@"
