#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# wardend installer.
#
#   curl -fsSL https://wardenclaw.dev/install.sh | sudo sh
#
# Default: hardened install (wardend as a root system service, the agent harness as a separate
# unprivileged user) in observe mode. Nothing is installed unless the downloaded archive matches
# the release's checksums.txt, taken as GitHub serves it over TLS: releases are not signed.
# Flags: see usage() below or run with --help; when piping, pass them after `sh -s --`.
#
# The whole script is a set of function definitions and a call to main on the last line, so a
# download cut short cannot run a half-read script.

# ---- Project identity: change it here on a rename or a new domain (uninstall.sh repeats part) ----
PROJECT="WardenClaw"
DOMAIN="wardenclaw.dev"
# The site serves this file at INSTALL_URL: a copy of install.sh from the latest release, checked
# before every deploy (.github/workflows/site-pages.yml). Archives and checksums come from
# RELEASES_URL on GitHub.
INSTALL_URL="https://${DOMAIN}/install.sh"
DOCS_URL="https://${DOMAIN}/docs/install/"
UNINSTALL_DOCS_URL="https://${DOMAIN}/docs/uninstall/"
GITHUB_REPO="xarvel/WardenClaw"   # GitHub owner/repo of the releases (the monorepo)
RELEASES_URL="https://github.com/${GITHUB_REPO}/releases"
# Releases of the daemon are tagged daemon/vX.Y.Z in the monorepo (the Go convention for a module
# in the daemon/ subdirectory); the version itself (VERSION in the archive) stays vX.Y.Z.
TAG_PREFIX="daemon/"
DAEMON="wardend"                  # binary, unit, /etc/<name>, /var/lib/<name>
CTL="wardenctl"
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

  curl -fsSL $INSTALL_URL | sudo sh                  wraps the OpenClaw gateway it finds (one question)
  curl -fsSL $INSTALL_URL | sudo sh -s -- [flags]    the same with flags, or another harness
  sudo $SHARE_DIR/install.sh             upgrade with the installed copy (no site involved)

Without flags the installer looks for the OpenClaw gateway service of the user who ran sudo
(~/.config/systemd/user/openclaw-gateway.service) and wraps it in place: same user, same home,
same command and environment. What changes: the old user service is disabled and $DAEMON starts
the same command as root's child under that user; that user leaves the sudo and docker groups
(a human admin account keeps root: an existing sudoer, or <user>-admin created with the same
ssh keys); root for the agent goes through cards on the phone (sudo and docker shims,
docs/rootexec.md); mode observe, nothing is blocked yet. Flags only when there is no such
service or you want it different.

  --agent-user NAME     harness user, created if missing (default: agent)
  --agent-home DIR      its home (default: existing home or /var/lib/NAME; not under /home)
  --harness-cmd 'CMD'   harness command, absolute paths, nothing under /home or /root
  --rw-paths 'D1 D2'    extra directories the harness may write to
  --mode MODE           observe (default) | ticket | deny-list
  --ptrace-scope 2|skip kernel.yama.ptrace_scope (default 2)
  --root-exec           (flag installs) open the rootexec socket: the agent may ask for a command
                        as root through cards on the phone, sudo and docker shims on its PATH
                        (docs/rootexec.md); the wrapping install turns it on itself
  --no-root-exec        wrapping install without the rootexec socket and the shims
  --admin-user NAME     the human admin account that keeps root when the agent user leaves the
                        sudo and docker groups (default: an existing sudoer, else <user>-admin)
  --with-wardenctl      also install the terminal approver (better kept on another machine)
  --single-user         trial install as your own user, no sudo (the model can disable it)
  --version vX.Y.Z      install this release instead of the latest
  --allow-downgrade     install a release older than the installed one (refused otherwise)
  --uninstall           remove $DAEMON, keep the journal: runs $SHARE_DIR/uninstall.sh, or the
                        one from the release; with --single-user the trial install, no sudo
  --purge               with --uninstall: also delete the journal and the config copy
  --remove-agent-user   with --uninstall: also delete the agent user and its group, if the
                        installer created them (its home with the harness data stays)
  --dry-run             print every step, change nothing, no root needed (also DRY_RUN=1)
  --from-dir DIR        take release files from DIR instead of downloading (local builds)
  -y, --yes             do not ask; a missing --harness-cmd becomes an error

Releases are not signed: the archive is checked against the release's checksums.txt as GitHub
serves it, nothing more.

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
		--mode) need_val "$@"; MODE=$2; shift 2 ;;
		--mode=*) MODE=${1#*=}; shift ;;
		--ptrace-scope) need_val "$@"; PTRACE_SCOPE=$2; shift 2 ;;
		--ptrace-scope=*) PTRACE_SCOPE=${1#*=}; shift ;;
		--root-exec) ROOT_EXEC=1; shift ;;
		--no-root-exec) NO_ROOT_EXEC=1; shift ;;
		--admin-user) need_val "$@"; ADMIN_USER=$2; shift 2 ;;
		--admin-user=*) ADMIN_USER=${1#*=}; shift ;;
		--version) need_val "$@"; VERSION=$2; shift 2 ;;
		--version=*) VERSION=${1#*=}; shift ;;
		--from-dir) need_val "$@"; FROM_DIR=$2; shift 2 ;;
		--from-dir=*) FROM_DIR=${1#*=}; shift ;;
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
	for _t in tar gzip awk sed; do
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
	if [ -z "$FROM_DIR" ]; then
		have curl || have wget || die "need curl or wget to download the release"
	fi
}

# ---- download and checks -----------------------------------------------------------------

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

sha256_of() {
	if [ "$SHA256" = openssl-sha256 ]; then
		openssl dgst -sha256 -r "$1" | cut -d' ' -f1
	else
		$SHA256 "$1" | cut -d' ' -f1
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

verify_release() { # fetch the release into $WORK (or --from-dir), check it; PKG = unpacked archive
	WORK=$(mktemp -d 2>/dev/null || mktemp -d -t "$DAEMON-install")
	[ -n "$WORK" ] && [ -d "$WORK" ] || die "cannot create a temporary directory"
	trap 'rm -rf "$WORK"' EXIT
	trap 'exit 130' INT TERM
	if [ -n "$FROM_DIR" ]; then
		info "release files from $FROM_DIR"
	else
		info "downloading $DAEMON ($VERSION) from $RELEASES_URL"
	fi
	get_file checksums.txt
	fetch_archive
	RELEASE=$(cat "$PKG/VERSION")
	case "$RELEASE" in v[0-9]*) ;; *) die "the archive's VERSION is \"$RELEASE\", not vX.Y.Z; refusing" ;; esac
	if [ "$VERSION" != latest ] && [ "$RELEASE" != "$VERSION" ]; then
		die "asked for $VERSION but the archive is $RELEASE (possible rollback); refusing"
	fi
	info "release $RELEASE (the version comes from the archive; releases are not signed, checksums.txt is taken as ${FROM_DIR:-$RELEASES_URL} serves it)"
}

# fetch_archive: the archive for this machine, checked against checksums.txt in $WORK and unpacked
# (PKG).
fetch_archive() {
	TARBALL="${DAEMON}_linux_${ARCH}.tar.gz"
	_want=$(awk -v f="$TARBALL" '$2 == f || $2 == "*" f { print $1 }' "$WORK/checksums.txt")
	[ -n "$_want" ] || die "release ${RELEASE:-$VERSION} has no build for linux/$ARCH ($TARBALL is not in checksums.txt)"
	[ "$(printf '%s\n' "$_want" | wc -l | tr -d ' ')" = 1 ] || die "checksums.txt lists $TARBALL twice; refusing"
	get_file "$TARBALL"
	_got=$(sha256_of "$WORK/$TARBALL")
	[ "$_got" = "$_want" ] || die "CHECKSUM MISMATCH for $TARBALL (got $_got, listed $_want). Nothing was changed."
	info "checksum: ok ($TARBALL)"
	mkdir "$WORK/x"
	tar -xzf "$WORK/$TARBALL" -C "$WORK/x" || die "cannot unpack $TARBALL"
	PKG="$WORK/x/${DAEMON}_linux_${ARCH}"
	for _f in "$DAEMON" "$CTL" VERSION uninstall.sh deploy/hardened-install.sh deploy/wardend.system.service redteam/hardened-check.sh; do
		[ -e "$PKG/$_f" ] || die "the release archive lacks $_f"
	done
}

# ---- the harness to wrap -----------------------------------------------------------------------

# detect_openclaw: the OpenClaw gateway user service of the user who ran sudo (else of the first
# ordinary user that has one): AUTO_USER, AUTO_HOME, AUTO_UNIT, AUTO_UNITFILE, AUTO_CMD (its
# ExecStart, a drop-in override winning) and AUTO_ENV (a file with its Environment= lines, the
# drop-ins' after the unit's). Returns 1 when there is none: the flag questions follow.
detect_openclaw() {
	AUTO_USER="" AUTO_HOME="" AUTO_UNIT="${OPENCLAW_UNIT:-openclaw-gateway.service}" AUTO_UNITFILE="" AUTO_CMD="" AUTO_ENV=""
	_cands="${SUDO_USER:-} $(getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /(nologin|false)$/ { print $1 }')"
	for _c in $_cands; do
		_h=$(getent passwd "$_c" 2>/dev/null | cut -d: -f6)
		[ -n "$_h" ] || continue
		if [ -f "$_h/.config/systemd/user/$AUTO_UNIT" ]; then
			AUTO_USER=$_c AUTO_HOME=$_h AUTO_UNITFILE="$_h/.config/systemd/user/$AUTO_UNIT"
			break
		fi
	done
	[ -n "$AUTO_USER" ] || return 1
	AUTO_CMD=$(sed -n 's/^ExecStart=//p' "$AUTO_UNITFILE" | grep -v '^$' | tail -n 1)
	for _d in "$AUTO_UNITFILE.d"/*.conf; do
		[ -f "$_d" ] || continue
		_o=$(sed -n 's/^ExecStart=//p' "$_d" | grep -v '^$' | tail -n 1)
		[ -z "$_o" ] || AUTO_CMD=$_o
	done
	[ -n "$AUTO_CMD" ] || return 1
	AUTO_ENV="$WORK/harness.env"
	{
		sed -n '/^Environment=/p' "$AUTO_UNITFILE"
		for _d in "$AUTO_UNITFILE.d"/*.conf; do [ -f "$_d" ] && sed -n '/^Environment=/p' "$_d"; done
	} >"$AUTO_ENV"
	return 0
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

	# A re-run over a wrapping install (the unit runs the gateway of a user who still has his
	# openclaw-gateway.service): not the upgrade branch below, which leaves the unit alone, but the
	# wrapping install again. It re-renders the unit from this release's template (a fix in the
	# template reaches installed machines), takes the user out of the privileged groups again,
	# keeps his old service disabled and restarts wardend when the unit or the binary changed.
	# A rollback of the wrap ends up here too: the same command puts the wrap back.
	REWRAP=""
	if [ -n "$_existing" ] && [ -z "$HARNESS_CMD" ] && [ -z "$AGENT_USER" ]; then
		_agent=$(sed -n 's/.*--child-user \([^ \\]*\).*/\1/p' "$UNIT" 2>/dev/null | head -n 1)
		if [ -n "$_agent" ] && detect_openclaw && [ "$AUTO_USER" = "$_agent" ]; then REWRAP=1; fi
	fi

	if [ -n "$_existing" ] && [ -z "$HARNESS_CMD" ] && [ -z "$REWRAP" ]; then
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
		say ""
		if [ -n "${_restart:-}" ]; then
			say "Upgraded. The running $DAEMON keeps the old binary until a restart, which also restarts the harness:"
			say "  sudo systemctl restart $DAEMON"
		else
			say "Nothing to upgrade: $RELEASE is installed."
		fi
		say "Next upgrade: sudo $SHARE_DIR/install.sh   (the installed copy)"
		return 0
	fi

	say ""
	if [ -n "$REWRAP" ] || { [ -z "$HARNESS_CMD" ] && [ -z "$AGENT_USER" ] && detect_openclaw; }; then
		AUTO=1
		AGENT_USER=$AUTO_USER AGENT_HOME=$AUTO_HOME HARNESS_CMD=$AUTO_CMD HARNESS_ENV_FILE=$AUTO_ENV OLD_USER_UNIT=$AUTO_UNIT
		KEEP_HOME=1 STRIP_PRIV=1 AUTO_START=1
		[ -n "$NO_ROOT_EXEC" ] || ROOT_EXEC=1
		_adm=$ADMIN_USER
		if [ -z "$_adm" ]; then
			for _g in sudo wheel admin; do
				for _m in $(getent group "$_g" 2>/dev/null | cut -d: -f4 | tr ',' ' '); do
					if [ "$_m" != "$AGENT_USER" ] && [ "$(id -u "$_m" 2>/dev/null || echo 0)" -ge 1000 ]; then _adm=$_m; break 2; fi
				done
			done
		fi
		[ -n "$_adm" ] || _adm="${AGENT_USER}-admin (new: sudo without a password, the same ssh keys)"
		_priv=""
		for _g in sudo wheel admin docker lxd incus libvirt disk; do
			id -nG "$AGENT_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$_g" && _priv="$_priv $_g"
		done
		if [ -n "$REWRAP" ]; then
			say "Found the OpenClaw gateway of $AGENT_USER ($AUTO_UNITFILE) already wrapped by $DAEMON${_old:+ $_old}."
			say "Wrapping it again with $RELEASE: the unit is re-rendered from this release's template, the old"
			say "service stays disabled, $DAEMON restarts if the unit or the binary changed (the gateway with it)."
		else
			say "Found the OpenClaw gateway of $AGENT_USER: $AUTO_UNITFILE"
			say "$DAEMON wraps it in place: same user, same home, same command and environment."
		fi
		say ""
		say "  harness:      $HARNESS_CMD"
		say "  runs as:      $AGENT_USER (home $AGENT_HOME), a child of $DAEMON, under the exec gate"
		say "  old service:  $OLD_USER_UNIT is disabled; $DAEMON starts the same command (systemd unit wardend)"
		if [ -n "$_priv" ]; then
			say "  root:         $AGENT_USER leaves the groups$_priv; the admin account is $_adm"
		else
			say "  root:         $AGENT_USER has no privileged groups; the admin account is $_adm"
		fi
		if [ -n "$ROOT_EXEC" ]; then
			say "                the agent's sudo and docker become requests: read-only docker/systemctl run,"
			say "                the rest asks your phone once it is paired (mode observe until then: runs, journaled)"
		else
			say "                no rootexec: the agent has no way to root at all"
		fi
		say "  phone:        pair after the install; it reaches $DAEMON through the relay, nothing listens on this machine"
		say "  mode:         $MODE (nothing is blocked; a week of watching, then ticket)"
		say ""
		if [ -n "$REWRAP" ]; then
			[ -n "$DRY_RUN" ] || confirm "Wrap this gateway again with $DAEMON $RELEASE?"
		else
			[ -n "$DRY_RUN" ] || confirm "Install $DAEMON $RELEASE and wrap this gateway?"
		fi
	else
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

	say ""
	say "  agent user:   $AGENT_USER${AGENT_HOME:+ (home $AGENT_HOME)}"
	say "  harness:      $HARNESS_CMD"
	say "  writable:     ${RW_PATHS:-(agent home only)}"
	say "  mode:         $MODE"
	say ""
	[ -n "$DRY_RUN" ] || confirm "Install $DAEMON $RELEASE with these settings?"
	fi

	if [ -n "$DRY_RUN" ]; then
		_script="$PKG/deploy/hardened-install.sh"
	else
		install_share
		_script="$SHARE_DIR/deploy/hardened-install.sh"
	fi
	# The root-side steps live in one place: deploy/hardened-install.sh from the same checked archive.
	env AGENT_USER="$AGENT_USER" AGENT_HOME="$AGENT_HOME" RW_PATHS="$RW_PATHS" \
		HARNESS_CMD="$HARNESS_CMD" MODE="$MODE" \
		PTRACE_SCOPE="$PTRACE_SCOPE" ROOT_EXEC="$ROOT_EXEC" DRY_RUN="$DRY_RUN" NO_NEXT_STEPS=1 \
		KEEP_HOME="$KEEP_HOME" HARNESS_ENV_FILE="$HARNESS_ENV_FILE" OLD_USER_UNIT="$OLD_USER_UNIT" \
		STRIP_PRIV="$STRIP_PRIV" ADMIN_USER="$ADMIN_USER" AUTO_START="$AUTO_START" \
		bash "$_script" "$PKG/$DAEMON" || die "hardened install steps failed (see above)"
	if [ -n "$DRY_RUN" ]; then install_share; fi
	install_ctl

	if [ -n "$AUTO" ]; then
		_adm=$(sed -n 's/^\([^ ]*\) ALL=(ALL) NOPASSWD:ALL$/\1/p' /etc/sudoers.d/90-wardend-admin 2>/dev/null | head -n 1)
		cat <<EOF

$DAEMON $RELEASE is installed and running (mode: $MODE): the OpenClaw gateway of $AGENT_USER runs under it,
as before for everything but root. Check:  systemctl status $DAEMON   and your chat with the agent.

${_adm:+Administer this machine as $_adm from now on (ssh $_adm@$(hostname), the same key; a password: sudo passwd $_adm).
}Next (details: $DOCS_URL):
  1. Pair your phone, from your own terminal (not from a chat with the agent); it prints a QR:
              sudo $DAEMON pair start
     The phone reaches $DAEMON through the relay: this machine needs outbound HTTPS only, no open
     port, no tunnel.
  2. About a week in observe: sudo $DAEMON journal  shows what would have asked;
     then "mode": "ticket" in $CONF_DIR/config.json and  sudo systemctl restart $DAEMON
  3. Verify as the agent user (every attack must be refused, FAIL=0):
              sudo -u $AGENT_USER bash -s < $SHARE_DIR/redteam/hardened-check.sh

Upgrade:  sudo $SHARE_DIR/install.sh        Uninstall (keeps the journal):  sudo $SHARE_DIR/uninstall.sh
EOF
		return 0
	fi

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
              sudo $DAEMON pair start
              sudo $DAEMON pair approve <id>
  4. About a week in observe: review what would have needed approval, add housekeeping to a policy,
     then set "mode": "ticket" in $CONF_DIR/config.json and  sudo systemctl restart $DAEMON
  5. Verify as the agent user (every attack must be refused, FAIL=0):
              sudo -u $AGENT_USER bash -s < $SHARE_DIR/redteam/hardened-check.sh

Upgrade:  sudo $SHARE_DIR/install.sh
  the installed copy downloads the new release and checks it the way this install was checked;
  it does not depend on the site. A downgrade needs --allow-downgrade.
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

Try it:   $DAEMON wrap -- <harness command>   (pairs your phone on the first run, then asks it)
Observe:  $DAEMON run --mode observe -- <harness command>   (asks nobody, journals)
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
		warn "$_copy is not root-only (owner or mode changed): not running it, taking the release"
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
	AGENT_USER="" AGENT_HOME="" HARNESS_CMD="" RW_PATHS="" RW_SET=""
	MODE="observe" PTRACE_SCOPE="2" ROOT_EXEC="" NO_ROOT_EXEC="" VERSION="latest"
	ADMIN_USER="" KEEP_HOME="" HARNESS_ENV_FILE="" OLD_USER_UNIT="" STRIP_PRIV="" AUTO_START="" AUTO=""
	FROM_DIR="" WITH_CTL="" SINGLE_USER="" UNINSTALL="" PURGE="" REMOVE_AGENT=""
	ALLOW_DOWNGRADE="" ASSUME_YES="" DRY_RUN="${DRY_RUN:-}" RELEASE=""
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
