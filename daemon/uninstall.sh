#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# wardend uninstaller.
#
#   sudo /usr/local/share/wardend/uninstall.sh                hardened install
#   ~/.local/share/wardend/uninstall.sh --single-user         trial install of your own user
#
# install.sh copies this file there from the same signed release archive as the binaries. Without
# the copy, `curl -fsSL https://wardenclaw.dev/install.sh | sudo sh -s -- --uninstall` downloads the
# release, checks its signature and checksums as for an install and runs the uninstall.sh in it.
# The plan (what stops, goes, stays) is printed before the confirmation; a second run removes
# what is left or says there is nothing to remove. Flags: see usage() below or run with --help.
#
# The whole script is a set of function definitions and a call to main on the last line, so a
# copy cut short cannot run half of it.

# ---- Project identity: the same values as in install.sh (scripts/release.sh compares them) -----
DOMAIN="wardenclaw.dev"
INSTALL_URL="https://${DOMAIN}/install.sh"
UNINSTALL_DOCS_URL="https://${DOMAIN}/docs/uninstall/"
DAEMON="wardend"                  # binary, unit, /etc/<name>, /var/lib/<name>
CTL="wardenctl"
# ----------------------------------------------------------------------------------------------

BIN_DIR="/usr/local/bin"
SHARE_DIR="/usr/local/share/${DAEMON}"
UNIT="/etc/systemd/system/${DAEMON}.service"
UNIT_DROPINS="/etc/systemd/system/${DAEMON}.service.d"           # overrides from systemctl edit
WANTS_LINK="/etc/systemd/system/multi-user.target.wants/${DAEMON}.service"
CONF_DIR="/etc/${DAEMON}"
STATE_DIR="/var/lib/${DAEMON}"
# Written by deploy/hardened-install.sh: the sysctl file, the ptrace_scope value from before it,
# the polkit rule, and the name and uid of the agent user when the install created that user.
SYSCTL_FILE="/etc/sysctl.d/60-${DAEMON}-ptrace.conf"
PTRACE_BEFORE="$STATE_DIR/ptrace_scope.before"
POLKIT_RULE="/etc/polkit-1/rules.d/60-${DAEMON}-agent.rules"
AGENT_MARK="$STATE_DIR/created-agent-user"
NL='
'

# What the hardened install leaves on the machine and what this script does with it (the same
# list is on the uninstall page of the docs):
#
#   /usr/local/bin/wardend, /usr/local/bin/wardenctl         removed
#   /usr/local/share/wardend (deploy/, redteam/, install.sh,
#     uninstall.sh)                                            removed
#   /etc/systemd/system/wardend.service, wardend.service.d/    stopped and disabled first, then removed
#   /etc/wardend (config.json, policy.json)                    removed; copied before that, with the
#                                                              unit, to /var/lib/wardend/config-backup
#   /etc/sysctl.d/60-wardend-ptrace.conf                       removed; ptrace_scope set back to the
#                                                              value from before the install
#   /etc/polkit-1/rules.d/60-wardend-agent.rules               removed
#   /var/lib/wardend: supervisor.key, relay_enc.key,
#     wardend.sock, hw_counters.json, ptrace_scope.before      removed
#   /var/lib/wardend/journal.jsonl                             kept as journal.<time>.jsonl, with its
#                                                              public key in journal.<time>.pub
#   the agent user, its group and home, working directories
#     and the ACLs or groups given to the agent there          not touched
#   --remove-agent-user: the agent user and its group, only if created-agent-user says that the
#     installer created them; the home stays, root-only
#   --purge: also /var/lib/wardend (journals, config copies)
#
# The single-user install: the drop-in <unit>.service.d/wardend.conf is removed and its unit
# restarted without wardend, then ~/.local/bin/wardend, ~/.local/share/wardend and the keys and socket
# in ~/.wardend. The journal (renamed) and config.json stay; --purge
# deletes ~/.wardend.

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
Removes $DAEMON installed by $INSTALL_URL. Prints the plan first, then asks.

  hardened install:  sudo $SHARE_DIR/uninstall.sh [flags]
  trial install:     ~/.local/share/$DAEMON/uninstall.sh --single-user [flags]   (no sudo)

  --purge               also delete the journal and the config copy, kept by default
  --remove-agent-user   also delete the agent user and its group, if the installer created them
                        (its home with the harness data stays, root-only)
  --agent-user NAME     the agent user, when no config or config copy names it any more
  --single-user         the trial install of your own user, run without sudo
  --dry-run             print every step, change nothing, no root needed (also DRY_RUN=1)
  -y, --yes             do not ask

The same through the installer: curl -fsSL $INSTALL_URL | sudo sh -s -- --uninstall [flags]
What stays and why: $UNINSTALL_DOCS_URL
EOF
}

need_val() { [ $# -ge 2 ] || die "$1 needs a value"; }

parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
		--agent-user) need_val "$@"; AGENT_USER=$2; shift 2 ;;
		--agent-user=*) AGENT_USER=${1#*=}; shift ;;
		--single-user) SINGLE_USER=1; shift ;;
		--purge) PURGE=1; shift ;;
		--remove-agent-user) REMOVE_AGENT=1; shift ;;
		--uninstall) shift ;; # as in install.sh --uninstall, which runs this script
		--dry-run) DRY_RUN=1; shift ;;
		-y | --yes) ASSUME_YES=1; shift ;;
		-h | --help) usage; exit 0 ;;
		*) die "unknown argument: $1 (see --help)" ;;
		esac
	done
	if [ -n "$REMOVE_AGENT" ] && [ -n "$SINGLE_USER" ]; then
		die "--remove-agent-user is for the hardened install; the single-user install has no agent user"
	fi
}

# ---- questions: read from the terminal even when the script itself comes from a pipe -----------

ask() { # VAR "question"
	if [ -t 0 ]; then
		_in=/dev/stdin
	elif (: </dev/tty) 2>/dev/null; then
		_in=/dev/tty
	else
		die "no terminal to ask \"$2\"; --yes answers it"
	fi
	printf '%s: ' "$2" >&2
	_ans=""
	IFS= read -r _ans <"$_in" || true
	eval "$1=\$_ans"
}

confirm() {
	[ -z "$ASSUME_YES" ] || return 0
	_yn=""
	ask _yn "$1 [y/N]"
	case "$_yn" in y | Y | yes | YES) return 0 ;; esac
	die "cancelled, nothing changed"
}

confirm_word() { # WORD QUESTION: go on only if the answer is WORD (--yes answers it)
	[ -z "$ASSUME_YES" ] || return 0
	_w=""
	ask _w "$2"
	[ "$_w" = "$1" ] || die "cancelled, nothing changed"
}

# ---- helpers -----------------------------------------------------------------------------------

exists() { [ -e "$1" ] || [ -L "$1" ]; }

existing() { # PATH...: print the paths that exist, one per line
	for _p in "$@"; do
		if exists "$_p"; then printf '%s\n' "$_p"; fi
	done
}

remove() { # PATH...: rm -rf each path that exists
	for _p in "$@"; do
		if exists "$_p"; then run rm -rf "$_p"; fi
	done
}

json_str() { # KEY FILE: the first "KEY": "value" of a flat JSON file, or nothing
	sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" "$2" 2>/dev/null | head -n 1
}

stamp() { date -u +%Y%m%dT%H%M%SZ; }

# journal_pubkey KEYFILE: the public key of supervisor.key (hex Ed25519 seed), base64url as in
# `wardend status` (journalKey). Needs OpenSSL; prints nothing without it.
journal_pubkey() {
	have openssl || return 0
	_hex=$(tr -d ' \r\n' <"$1" 2>/dev/null) || return 0
	case "$_hex" in *[!0-9a-fA-F]*) return 0 ;; esac
	[ "${#_hex}" = 64 ] || return 0
	# PKCS#8 around an Ed25519 seed: 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 || seed
	_oct=$(printf '302e020100300506032b657004220420%s\n' "$_hex" | awk '{
		h = "0123456789abcdef"; s = tolower($0)
		for (i = 1; i < length(s); i += 2)
			printf "\\%03o", (index(h, substr(s, i, 1)) - 1) * 16 + index(h, substr(s, i + 1, 1)) - 1
	}')
	# shellcheck disable=SC2059 # the format is the octal-escaped DER built above
	printf "$_oct" | openssl pkey -inform DER -pubout -outform DER 2>/dev/null | tail -c 32 |
		openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# archive_journal DIR: rename DIR/journal.jsonl to journal.<time>.jsonl and write its public key
# next to it (while DIR/supervisor.key still exists). A later install then starts a new chain with
# a new key; appending to this file with another key would break `wardend verify-journal`.
archive_journal() {
	JOURNAL_KEPT="" JOURNAL_KEY=""
	[ -f "$1/journal.jsonl" ] || return 0
	_t=$(stamp)
	JOURNAL_KEPT="$1/journal.$_t.jsonl"
	if [ -f "$1/supervisor.key" ]; then JOURNAL_KEY=$(journal_pubkey "$1/supervisor.key"); fi
	run mv "$1/journal.jsonl" "$JOURNAL_KEPT"
	if [ -n "$JOURNAL_KEY" ]; then
		if [ -n "$DRY_RUN" ]; then
			printf '+ write %s: %s\n' "$1/journal.$_t.pub" "$JOURNAL_KEY"
		else
			printf '%s\n' "$JOURNAL_KEY" >"$1/journal.$_t.pub"
		fi
	fi
}

in_unit() { # UNIT: true if this process runs inside that systemd unit (its cgroup)
	[ -r /proc/self/cgroup ] || return 1
	while IFS= read -r _l; do
		case "$_l" in *"/$1" | *"/$1/"*) return 0 ;; esac
	done </proc/self/cgroup
	return 1
}

# created-agent-user has a line "NAME UID" for every agent user deploy/hardened-install.sh created.
mark_has() { [ -f "$AGENT_MARK" ] && grep -Fqx "$1 $2" "$AGENT_MARK"; } # NAME UID

mark_drop() { # NAME: forget that the installer created NAME
	[ -f "$AGENT_MARK" ] && awk -v u="$1" '$1 == u { f = 1 } END { exit !f }' "$AGENT_MARK" || return 0
	_rest=$(awk -v u="$1" '$1 != u' "$AGENT_MARK")
	if [ -z "$_rest" ]; then
		remove "$AGENT_MARK"
	elif [ -n "$DRY_RUN" ]; then
		printf '+ drop %s from %s\n' "$1" "$AGENT_MARK"
	else
		printf '%s\n' "$_rest" >"$AGENT_MARK"
	fi
}

# ptrace_restore: remove the sysctl file and set kernel.yama.ptrace_scope back to the value it had
# before the install (deploy/hardened-install.sh saved it). The kernel keeps the live value until
# it is changed or the machine reboots, so removing the file alone changes nothing now.
ptrace_restore() {
	_now=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true)
	_was=""
	if [ -f "$PTRACE_BEFORE" ]; then _was=$(tr -dc 0-9 <"$PTRACE_BEFORE" 2>/dev/null || true); fi
	_had_file=""
	if exists "$SYSCTL_FILE"; then
		_had_file=1
		run rm -f "$SYSCTL_FILE"
	fi
	case "$_was" in
	[0-3])
		if [ -z "$_now" ] || [ "$_now" = "$_was" ]; then
			:
		elif [ "$_now" = 3 ]; then
			warn "kernel.yama.ptrace_scope is 3, which the kernel keeps until reboot; after a reboot it is $_was again"
		else
			info "kernel.yama.ptrace_scope: $_now -> $_was (the value from before the install)"
			run sysctl -q -w "kernel.yama.ptrace_scope=$_was" || warn "could not set kernel.yama.ptrace_scope=$_was"
		fi
		;;
	*)
		if [ -n "$_had_file" ] && [ -n "$_now" ]; then
			say "  kernel.yama.ptrace_scope stays $_now until reboot; sudo sysctl --system applies the configured value now"
		fi
		;;
	esac
	remove "$PTRACE_BEFORE"
}

# ---- the agent user ----------------------------------------------------------------------------

# agent_user_check NAME RWPATHS: print what keeps the agent user from being deleted safely, return
# 1 if anything does. Deleting a user leaves its files and ACL entries to a bare uid, and the next
# system account created on the machine may get the same uid.
agent_user_check() {
	_u=$1 _rwp=$2 _bad=""
	_uid=$(id -u "$_u")
	_min=$(awk '$1 == "UID_MIN" { print $2; exit }' /etc/login.defs 2>/dev/null || true)
	case "$_min" in '' | *[!0-9]*) _min=1000 ;; esac
	if [ "$_uid" = 0 ] || [ "$_uid" -ge "$_min" ] || [ "$_u" = "${SUDO_USER:-}" ]; then
		_bad="$_bad$NL  $_u (uid $_uid) is not a system account (uid 1 to $((_min - 1))) like the one the installer creates: delete it by hand if you mean it"
	elif ! mark_has "$_u" "$_uid"; then
		_bad="$_bad$NL  $_u was not created by the installer (no \"$_u $_uid\" in $AGENT_MARK), so it stays: sudo userdel $_u if you mean it"
	fi
	for _c in "/var/spool/cron/crontabs/$_u" "/var/spool/cron/$_u"; do
		if [ -f "$_c" ]; then
			_bad="$_bad$NL  $_u has a crontab, which runs commands outside $DAEMON: sudo crontab -l -u $_u to read it, sudo crontab -r -u $_u to delete it"
		fi
	done
	_gid=$(getent group "$_u" 2>/dev/null | cut -d: -f3)
	set -f
	for _p in $_rwp; do
		[ -d "$_p" ] || continue
		if have getfacl && getfacl -c -n -p "$_p" 2>/dev/null | grep -Eq "^(default:)?user:$_uid:"; then
			_bad="$_bad$NL  $_p still gives $_u access by ACL: sudo setfacl -R -x u:$_u -x d:u:$_u $_p"
		fi
		if [ -n "$(find "$_p" -xdev -user "$_uid" -print 2>/dev/null | head -n 1)" ]; then
			_bad="$_bad$NL  $_p has files owned by $_u: sudo chown -R --from=$_u ${SUDO_USER:-<you>}: $_p"
		elif [ -n "$_gid" ] && [ -n "$(find "$_p" -xdev -group "$_gid" -print 2>/dev/null | head -n 1)" ]; then
			_bad="$_bad$NL  $_p has files of the group $_u: sudo find $_p -group $_u -exec chgrp <your group> {} +"
		fi
	done
	set +f
	[ -n "$_bad" ] || return 0
	say "The agent user $_u can't be deleted safely yet:$_bad"
	return 1
}

remove_agent_user() { # NAME HOME
	_u=$1 _h=$2
	if ! id "$_u" >/dev/null 2>&1; then
		say "  agent user $_u: already gone"
		mark_drop "$_u"
		return 0
	fi
	_uid=$(id -u "$_u")
	if [ -z "$DRY_RUN" ] && have pgrep && pgrep -u "$_uid" >/dev/null 2>&1; then
		die "processes of $_u are still running (pgrep -a -u $_u); stop them and run the uninstall again with --remove-agent-user"
	fi
	# The home keeps the harness data. Only root may enter it from now on: its files keep the
	# numeric uid, which a system account created later may get.
	if [ -n "$_h" ] && [ -d "$_h" ]; then
		case "$_h" in
		/ | /bin* | /boot* | /dev* | /etc* | /lib* | /opt | /proc* | /root* | /run* | /sbin* | /srv | /sys* | /tmp* | /usr* | /var | /var/lib | /var/tmp* | /home | /home/*)
			die "agent home $_h is a system or shared directory; refusing to change it" ;;
		esac
		if [ -n "$(find "$_h" -prune -user "$_uid" -print 2>/dev/null)" ]; then
			run chown root:root "$_h"
			run chmod 0700 "$_h"
		else
			warn "$_h does not belong to $_u: left as it is"
		fi
	fi
	remove "/var/lib/systemd/linger/$_u"
	run userdel "$_u"
	if getent group "$_u" >/dev/null 2>&1; then
		_members=$(getent group "$_u" | cut -d: -f4)
		if [ -n "$_members" ]; then
			warn "group $_u still has members ($_members): left in place"
		else
			run groupdel "$_u" || warn "could not delete group $_u"
		fi
	fi
	mark_drop "$_u"
	AGENT_REMOVED=$_u
}

# ---- hardened install --------------------------------------------------------------------------

uninstall_hardened() {
	[ -n "$DRY_RUN" ] || [ "$(id -u)" = 0 ] ||
		die "uninstall needs root: run it with sudo (--dry-run only prints the steps; the trial install of your own user: --single-user, without sudo)"
	if [ "$(id -u)" != 0 ]; then
		warn "not root: $CONF_DIR and $STATE_DIR can't be read, so this list can miss files there (sudo shows everything)"
	fi

	# What ran under wardend: read from the unit, or from the config backup an earlier uninstall kept.
	_old_bk=""
	for _b in "$STATE_DIR/config-backup" "$STATE_DIR"/config-backup.*; do
		if [ -d "$_b" ]; then _old_bk=$_b; fi
	done
	_unit_src=""
	if [ -f "$UNIT" ]; then
		_unit_src=$UNIT
	elif [ -n "$_old_bk" ] && [ -f "$_old_bk/$DAEMON.service" ]; then
		_unit_src="$_old_bk/$DAEMON.service"
	fi
	_agent=$(json_str child_user "$CONF_DIR/config.json")
	if [ -z "$_agent" ] && [ -n "$_old_bk" ]; then _agent=$(json_str child_user "$_old_bk/config.json"); fi
	if [ -n "$AGENT_USER" ]; then
		if [ -n "$_agent" ] && [ "$_agent" != "$AGENT_USER" ]; then
			die "--agent-user $AGENT_USER, but $DAEMON ran the harness as $_agent (child_user in its config); refusing"
		fi
		_agent=$AGENT_USER
	fi
	_home="" _harness="" _rw=""
	if [ -n "$_unit_src" ]; then
		_home=$(sed -n 's/^Environment=HOME=\([^ ]*\).*/\1/p' "$_unit_src" | head -n 1)
		_harness=$(sed -n 's/^[[:space:]]*-- //p' "$_unit_src" | head -n 1)
		set -f
		for _p in $(sed -n 's/^ReadWritePaths=//p' "$_unit_src" | head -n 1); do
			case "$_p" in "$STATE_DIR" | "$CONF_DIR" | "$_home") ;; *) _rw="$_rw $_p" ;; esac
		done
		set +f
		_rw=${_rw# }
	fi
	if [ -z "$_home" ] && [ -n "$_agent" ]; then _home=$(getent passwd "$_agent" 2>/dev/null | cut -d: -f6); fi

	_running=""
	if have systemctl; then
		case "$(systemctl is-active "$DAEMON" 2>/dev/null || true)" in
		active | activating | deactivating | reloading) _running=1 ;;
		esac
	fi
	_gone=$(existing "$BIN_DIR/$DAEMON" "$BIN_DIR/$CTL" "$SHARE_DIR" "$SHARE_DIR.new" "$UNIT" "$UNIT_DROPINS" \
		"$WANTS_LINK" "$CONF_DIR" "$SYSCTL_FILE" "$POLKIT_RULE")
	_state=$(existing "$STATE_DIR/supervisor.key" "$STATE_DIR/relay_enc.key" "$STATE_DIR/$DAEMON.sock" "$STATE_DIR/push_tokens.json" \
		"$STATE_DIR/hw_counters.json" "$PTRACE_BEFORE")
	_journal=""
	if [ -f "$STATE_DIR/journal.jsonl" ]; then _journal=1; fi
	_keys=""
	for _k in "$CONF_DIR"/*.p8; do
		if [ -f "$_k" ]; then _keys="$_keys ${_k##*/}"; fi
	done
	_keys=${_keys# }
	_purge=""
	if [ -n "$PURGE" ] && [ -d "$STATE_DIR" ]; then _purge=1; fi
	_user=""
	if [ -n "$REMOVE_AGENT" ] && [ -n "$_agent" ] && id "$_agent" >/dev/null 2>&1; then _user=1; fi

	if [ -z "$_gone$_state$_journal$_running$_purge$_user" ]; then
		say "Nothing to remove: $DAEMON is not installed here (hardened install)."
		if [ -n "$REMOVE_AGENT" ] && [ -n "$_agent" ]; then say "The agent user $_agent does not exist."; fi
		if [ -n "$REMOVE_AGENT" ] && [ -z "$_agent" ]; then
			say "No config or config copy names the agent user any more: if it still exists, delete it by hand."
		fi
		if [ -d "$STATE_DIR" ]; then
			say "$STATE_DIR is kept from an earlier uninstall (journal, config copy); --purge deletes it."
		fi
		_sh=$(getent passwd "${SUDO_USER:-}" 2>/dev/null | cut -d: -f6)
		if [ -n "$_sh" ] && { exists "$_sh/.local/bin/$DAEMON" || exists "$_sh/.$DAEMON"; }; then
			say "A single-user install of $SUDO_USER is here: remove it without sudo:"
			say "  curl -fsSL $INSTALL_URL | sh -s -- --single-user --uninstall"
		fi
		return 0
	fi
	if [ -n "$REMOVE_AGENT" ] && [ -z "$_agent" ]; then
		die "can't tell which user ran the harness (no child_user in $CONF_DIR/config.json or a config copy); pass --agent-user NAME"
	fi
	if [ -n "$_user" ] && ! agent_user_check "$_agent" "$_rw"; then
		[ -n "$DRY_RUN" ] || die "nothing was changed. Fix the above, or run without --remove-agent-user to remove only $DAEMON"
		warn "a real run would stop here, before changing anything"
	fi

	_stops=""
	if [ -f "$UNIT" ] || [ -n "$_running" ]; then _stops=1; fi
	say ""
	say "Uninstall $DAEMON (hardened install)"
	say ""
	if [ -n "$_stops" ]; then
		say "Stops:    $DAEMON, and with it the agent's harness${_agent:+ (user $_agent)}"
	fi
	if [ -n "$_gone$_state$_user" ]; then say "Removes:"; fi
	if [ -n "$_gone$_state" ]; then printf '%s\n%s\n' "$_gone" "$_state" | sed '/^$/d; s/^/  /'; fi
	if [ -n "$_user" ]; then
		say "  the agent user $_agent and its group (its home ${_home:-?} stays, root-only)"
	elif [ -n "$REMOVE_AGENT" ]; then
		say "  (the agent user $_agent does not exist any more)"
	fi
	if [ -n "$PURGE" ]; then
		say "Deletes for good (--purge), no undo: $STATE_DIR with every journal and config copy in it"
		# shellcheck disable=SC2012 # a listing for people to read
		if [ -d "$STATE_DIR" ]; then ls -lA "$STATE_DIR" 2>/dev/null | sed '1d; s/^/  /' || true; fi
		if [ -z "$_user" ] && [ -n "$_agent" ] && id "$_agent" >/dev/null 2>&1 && mark_has "$_agent" "$(id -u "$_agent")"; then
			say "  including $AGENT_MARK: after that --remove-agent-user no longer knows that the installer"
			say "  created $_agent. Add --remove-agent-user now, or delete the user by hand later."
		fi
	elif [ -n "$_journal" ] || [ -d "$CONF_DIR" ] || [ -f "$UNIT" ]; then
		say "Keeps, root-only in $STATE_DIR:"
		if [ -n "$_journal" ]; then
			say "  journal.jsonl, renamed journal.<time>.jsonl: the signed record of what the agent ran and who approved it"
		fi
		if [ -d "$CONF_DIR" ] || [ -f "$UNIT" ]; then
			say "  config-backup: a copy of $CONF_DIR and the unit${_keys:+, without the push keys ($_keys)}"
		fi
	fi
	say "Not touched:"
	if [ -z "$_user" ]; then
		say "  the agent user${_agent:+ $_agent} and its home${_home:+ $_home} with the harness data"
	fi
	say "  your working directories${_rw:+ ($_rw)} and the ACLs or groups you gave the agent there"
	say ""
	if [ -z "$DRY_RUN" ]; then
		if [ -n "$PURGE" ]; then
			confirm_word purge "Type purge to uninstall $DAEMON and delete $STATE_DIR"
		else
			confirm "Uninstall $DAEMON?"
		fi
	fi

	# 1. Stop. The harness runs as wardend's child, so this stops the agent too. A seccomp filter
	#    can't be taken off a running tree: the harness runs without it only after a fresh start.
	if have systemctl && [ -n "$_stops" ]; then
		info "stopping $DAEMON and the harness"
		run systemctl disable --now "$DAEMON" || run systemctl stop "$DAEMON" || true
		if [ -z "$DRY_RUN" ] && systemctl is-active --quiet "$DAEMON"; then
			die "$DAEMON is still running (sudo systemctl status $DAEMON); nothing was removed"
		fi
	fi
	if [ -z "$DRY_RUN" ] && have pgrep && pgrep -u 0 -x "$DAEMON" >/dev/null 2>&1; then
		warn "a $DAEMON process of root still runs outside the unit (pgrep -a -x $DAEMON); stop it by hand"
	fi

	# 2. A copy of the settings, unless --purge deletes it anyway.
	_bk=""
	if [ -z "$PURGE" ] && { [ -d "$CONF_DIR" ] || [ -f "$UNIT" ] || [ -d "$UNIT_DROPINS" ]; }; then
		_bk="$STATE_DIR/config-backup"
		if exists "$_bk"; then _bk="$STATE_DIR/config-backup.$(stamp)"; fi
		if [ ! -d "$STATE_DIR" ]; then run install -d -o root -g root -m 0700 "$STATE_DIR"; fi
		run install -d -o root -g root -m 0700 "$_bk"
		if [ -d "$CONF_DIR" ]; then run cp -a "$CONF_DIR/." "$_bk/"; fi
		if [ -f "$UNIT" ]; then run cp -a "$UNIT" "$_bk/$DAEMON.service"; fi
		if [ -d "$UNIT_DROPINS" ]; then run cp -a "$UNIT_DROPINS" "$_bk/$DAEMON.service.d"; fi
		# wardend sends no pushes and reads no *.p8; one found in the config is a push signing key
		# all the same: not kept.
		if [ -d "$CONF_DIR" ]; then run find "$_bk" -type f -name '*.p8' -exec rm -f {} +; fi
	fi

	# 3. The journal, renamed, with its public key (read from supervisor.key, which goes next).
	JOURNAL_KEPT="" JOURNAL_KEY=""
	if [ -z "$PURGE" ]; then archive_journal "$STATE_DIR"; fi

	# 4. The unit, its overrides and the enable link.
	if exists "$UNIT" || exists "$UNIT_DROPINS" || exists "$WANTS_LINK"; then
		remove "$UNIT" "$UNIT_DROPINS" "$WANTS_LINK"
		if have systemctl; then
			run systemctl daemon-reload
			run systemctl reset-failed "$DAEMON" 2>/dev/null || true
		fi
	fi

	# 5. Kernel and polkit settings, binaries, reference files (this script's copy too: the shell
	#    has read it by now), config and state.
	ptrace_restore
	remove "$POLKIT_RULE" "$BIN_DIR/$DAEMON" "$BIN_DIR/$CTL" "$SHARE_DIR" "$SHARE_DIR.new" "$CONF_DIR" "/usr/local/libexec/$DAEMON"
	remove "$STATE_DIR/supervisor.key" "$STATE_DIR/relay_enc.key" "$STATE_DIR/$DAEMON.sock" "$STATE_DIR/push_tokens.json" \
		"$STATE_DIR/hw_counters.json"

	# 6. The agent user (before --purge deletes the mark that says the installer created it).
	AGENT_REMOVED=""
	if [ -n "$_user" ]; then
		remove_agent_user "$_agent" "$_home"
	elif [ -n "$REMOVE_AGENT" ] && [ -n "$_agent" ]; then
		mark_drop "$_agent"
	fi
	if [ -n "$PURGE" ]; then remove "$STATE_DIR"; fi

	say ""
	if [ -n "$DRY_RUN" ]; then
		say "Dry run: nothing was changed. After a real run:"
	else
		say "$DAEMON is removed."
	fi
	if [ -z "$PURGE" ] && [ -n "$JOURNAL_KEPT$_bk" ]; then
		say "Kept, root-only:"
		if [ -n "$JOURNAL_KEPT" ]; then say "  $JOURNAL_KEPT"; fi
		if [ -n "$JOURNAL_KEY" ]; then
			say "  its public key $JOURNAL_KEY (also in ${JOURNAL_KEPT%.jsonl}.pub): copy it off this machine"
			say "  if you may need to prove later that this wardend wrote the journal"
		fi
		if [ -n "$_bk" ]; then say "  $_bk (config, policy, unit)"; fi
		say "Delete them when you no longer need them:  curl -fsSL $INSTALL_URL | sudo sh -s -- --uninstall --purge"
	fi
	if [ -n "$_stops" ]; then
		say ""
		say "The agent's harness is stopped. To run it again without $DAEMON:"
		if [ -n "$_harness" ]; then say "  it ran${_agent:+ as $_agent}: $_harness"; fi
		if [ -n "$_home" ]; then
			say "  its data is in $_home. Copy what you need back to your account and look through it"
			say "  first (the agent could write anything there), then start the service you used"
			say "  before $DAEMON, for example: systemctl --user enable --now openclaw-gateway"
		fi
	fi
	if [ -f "$STATE_DIR/stripped-groups" ]; then
		_sg=$(cat "$STATE_DIR/stripped-groups")
		_su=${_sg%% *}
		say ""
		say "The install took $_su out of the groups${_sg#"$_su"} (root stayed with the admin account, which"
		say "is not removed). To give them back:  for g in${_sg#"$_su"}; do gpasswd -a $_su \$g; done"
		say "Sudoers lines it commented out are next to their backups: /etc/sudoers.d/*.wardend-bak"
	fi
	if [ -n "$_agent" ] && [ -z "$_user" ] && id "$_agent" >/dev/null 2>&1; then
		say ""
		say "The agent user $_agent is kept: its home holds the harness data, and your working"
		say "directories may still carry its ACLs and files it owns. Once it is deleted they belong to a"
		say "bare uid that the next system account created here can get. Move the data, remove the"
		if [ -z "$PURGE" ] && mark_has "$_agent" "$(id -u "$_agent")"; then
			say "ACLs, take over its files, then:  curl -fsSL $INSTALL_URL | sudo sh -s -- --uninstall --remove-agent-user"
		else
			say "ACLs, take over its files, then delete it by hand (see the page below): sudo userdel $_agent"
		fi
	fi
	if [ -n "$AGENT_REMOVED" ]; then
		say ""
		say "The agent user $AGENT_REMOVED is deleted.${_home:+ Its home $_home is kept, root-only: delete it}"
		if [ -n "$_home" ]; then say "when you no longer need the harness data in it."; fi
	fi
	say ""
	say "Paired phones and wardenctl: $UNINSTALL_DOCS_URL"
}

# ---- single-user install -----------------------------------------------------------------------

uninstall_single() {
	[ "$(id -u)" != 0 ] || die "--single-user removes the trial install of your own user: run it without sudo"
	_bin="$HOME/.local/bin/$DAEMON" _share="$HOME/.local/share/$DAEMON" _state="$HOME/.$DAEMON"
	_units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

	# Units that start something through wardend. The documented drop-in (<unit>.service.d/
	# wardend.conf) is removed here; a unit that runs wardend any other way was written by hand,
	# and the uninstall stops until you take wardend out of it.
	_dropins="" _other=""
	for _f in "$_units"/*.service.d/*.conf "$_units"/*.service; do
		[ -f "$_f" ] || continue
		grep -Eq "(^|[/=[:space:]])$DAEMON run" "$_f" 2>/dev/null || continue
		case "$_f" in
		*.service.d/"$DAEMON".conf) _dropins="$_dropins$_f$NL" ;;
		*) _other="$_other  $_f$NL" ;;
		esac
	done
	if [ -n "$_other" ]; then
		die "these units start a program through $DAEMON, and not with the drop-in this script removes:
${_other}Take $DAEMON out of them by hand, systemctl --user daemon-reload, restart the unit, then run the uninstall again"
	fi
	_units_on="" _restart="" _mains=""
	while IFS= read -r _f; do
		[ -n "$_f" ] || continue
		_u=${_f%/*}
		_u=${_u##*/}
		_u=${_u%.d}
		if in_unit "$_u"; then
			die "this shell runs inside $_u, the unit $DAEMON wraps (a chat with the agent?). Restarting it would cut this uninstall off: run it from your own terminal"
		fi
		_units_on="$_units_on $_u"
		if have systemctl && systemctl --user is-active --quiet "$_u" 2>/dev/null; then
			_restart="$_restart $_u"
			_mains="$_mains $(systemctl --user show -p MainPID --value "$_u" 2>/dev/null || true)"
		fi
	done <<EOF
$_dropins
EOF
	# A wardend started by hand (wardend run -- ...) keeps running on its own: stop it first.
	_stray=""
	if have pgrep; then
		for _pid in $(pgrep -u "$(id -u)" -x "$DAEMON" 2>/dev/null || true); do
			case " $_mains " in *" $_pid "*) ;; *) _stray="$_stray $_pid" ;; esac
		done
	fi
	if [ -n "$_stray" ]; then
		[ -n "$DRY_RUN" ] || die "$DAEMON runs outside the units above (pid$_stray): stop it and the harness it wraps, then run the uninstall again. Nothing was changed"
		warn "$DAEMON runs outside the units above (pid$_stray): a real run would stop here"
	fi

	# A *.p8 found here is a push signing key (wardend reads none): removed like the supervisor key.
	_rm=$(existing "$_bin" "$_share" "$_state/supervisor.key" "$_state/relay_enc.key" "$_state/$DAEMON.sock" "$_state/push_tokens.json" \
		"$_state/hw_counters.json" "$_state"/*.p8)
	_journal=""
	if [ -f "$_state/journal.jsonl" ]; then _journal=1; fi
	_purge=""
	if [ -n "$PURGE" ] && [ -d "$_state" ]; then _purge=1; fi
	if [ -z "$_dropins$_rm$_journal$_purge" ]; then
		say "Nothing to remove: there is no single-user $DAEMON for $(id -un) here."
		if [ -d "$_state" ]; then say "$_state is kept from an earlier uninstall (journal, config); --purge deletes it."; fi
		if [ -f "$UNIT" ]; then say "A hardened install is here: curl -fsSL $INSTALL_URL | sudo sh -s -- --uninstall"; fi
		return 0
	fi

	say ""
	say "Uninstall $DAEMON (single-user install of $(id -un))"
	say ""
	for _u in $_restart; do say "Restarts: $_u, without $DAEMON (its current sessions drop)"; done
	say "Removes:"
	printf '%s%s\n' "$_dropins" "$_rm" | sed '/^$/d; s/^/  /'
	if [ -n "$PURGE" ]; then
		say "Deletes for good (--purge), no undo: $_state with the journal and config in it"
		# shellcheck disable=SC2012 # a listing for people to read
		if [ -d "$_state" ]; then ls -lA "$_state" 2>/dev/null | sed '1d; s/^/  /' || true; fi
	elif [ -d "$_state" ]; then
		say "Keeps, in $_state:"
		if [ -n "$_journal" ]; then say "  journal.jsonl, renamed journal.<time>.jsonl"; fi
		say "  config.json, policy.json and your other files there (not *.p8 keys)"
	fi
	if exists "$HOME/.local/bin/$CTL"; then
		say "Not touched: $HOME/.local/bin/$CTL (the installer did not put it there: wardenctl forget, then delete it)"
	fi
	say ""
	if [ -z "$DRY_RUN" ]; then
		if [ -n "$PURGE" ]; then
			confirm_word purge "Type purge to uninstall $DAEMON and delete $_state"
		else
			confirm "Uninstall $DAEMON for $(id -un)?"
		fi
	fi

	# 1. The harness first: without the drop-in and after a restart it runs without wardend. The
	#    binary goes only after that, or the next start of the unit would fail on a missing ExecStart.
	while IFS= read -r _f; do
		[ -n "$_f" ] || continue
		run rm -f "$_f"
		run rmdir "${_f%/*}" 2>/dev/null || true
	done <<EOF
$_dropins
EOF
	if [ -n "$_dropins" ] && have systemctl; then run systemctl --user daemon-reload; fi
	for _u in $_restart; do
		info "restarting $_u without $DAEMON"
		run systemctl --user restart "$_u" || warn "$_u did not restart: systemctl --user status $_u"
	done
	if [ -z "$DRY_RUN" ] && have pgrep && pgrep -u "$(id -u)" -x "$DAEMON" >/dev/null 2>&1; then
		warn "$DAEMON still runs (pgrep -a -x $DAEMON); the files below are removed anyway"
	fi

	# 2. The journal, renamed, with its public key; then the rest (this script's copy in
	#    ~/.local/share/wardend too: the shell has read it by now).
	JOURNAL_KEPT="" JOURNAL_KEY=""
	if [ -z "$PURGE" ]; then archive_journal "$_state"; fi
	remove "$_bin" "$_share" "$_state/supervisor.key" "$_state/relay_enc.key" "$_state/$DAEMON.sock" "$_state/push_tokens.json" \
		"$_state/hw_counters.json" "$_state"/*.p8
	if [ -n "$PURGE" ]; then remove "$_state"; fi

	say ""
	if [ -n "$DRY_RUN" ]; then
		say "Dry run: nothing was changed. After a real run:"
	else
		say "$DAEMON is removed for $(id -un)."
	fi
	for _u in $_units_on; do
		say "$_u runs without $DAEMON from now on: systemctl --user status $_u shows your harness as its main process."
	done
	if [ -z "$_units_on" ]; then
		say "No systemd unit started $DAEMON. If you ran it by hand, start your harness without the \"$DAEMON run --\" prefix."
	fi
	if [ -z "$PURGE" ] && [ -d "$_state" ]; then
		say "Kept in $_state: ${JOURNAL_KEPT:+${JOURNAL_KEPT##*/}, }config.json and your other files."
		if [ -n "$JOURNAL_KEY" ]; then say "The journal's public key: $JOURNAL_KEY (also in ${JOURNAL_KEPT%.jsonl}.pub)."; fi
		say "Delete them when no longer needed:  curl -fsSL $INSTALL_URL | sh -s -- --single-user --uninstall --purge"
	fi
	if [ -f "$UNIT" ]; then say "A hardened install is here too: curl -fsSL $INSTALL_URL | sudo sh -s -- --uninstall"; fi
	say "Paired phones and wardenctl: $UNINSTALL_DOCS_URL"
}

# ---- main --------------------------------------------------------------------------------------

main() {
	set -eu
	umask 022
	AGENT_USER="" SINGLE_USER="" PURGE="" REMOVE_AGENT="" ASSUME_YES="" DRY_RUN="${DRY_RUN:-}"
	parse_args "$@"
	[ -z "$DRY_RUN" ] || info "DRY RUN: nothing will be changed, commands are only printed"
	if [ -n "$SINGLE_USER" ]; then uninstall_single; else uninstall_hardened; fi
}

main "$@"
