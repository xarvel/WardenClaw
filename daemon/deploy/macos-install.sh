# SPDX-License-Identifier: AGPL-3.0-or-later
#
# wardend on macOS: the install steps install.sh runs after `uname -s` says Darwin. Not a program
# of its own: install.sh sources this file from the checked release archive (deploy/) and calls
# macos_install with its own variables and helpers (say/info/warn/die/run/have/ask/confirm,
# DRY_RUN, PKG, RELEASE, AGENT_USER, AGENT_HOME, HARNESS_CMD, MODE, WITH_CTL, ASSUME_YES).
#
# What it sets up (docs/macos.md):
#   /Library/Application Support/WardenClaw/wardend.app   the bundle: Contents/MacOS/wardend,
#                                                        Contents/Info.plist, and the provisioning
#                                                        profile when the release ships one
#   /etc/wardend/config.json                             root 0600: mode, child_user, agent_home,
#                                                        state_dir, root_exec off, gate defaults
#   /var/db/wardend                                      root 0700: key, journal, socket
#   /Library/LaunchDaemons/<label>.plist                 root 0644, from deploy/wardend.launchd.plist
#   /usr/local/share/wardend                             reference files, install.sh, uninstall.sh
#
# wardend runs as root (the Endpoint Security client needs it) and starts the harness as the agent
# user, by default the user who ran sudo. When that user has the OpenClaw gateway LaunchAgent
# (~/Library/LaunchAgents/ai.openclaw.gateway.plist, or the one of OPENCLAW_LABEL) the installer
# wraps it in place: the same command and environment, read from the plist with PlistBuddy, the
# LaunchAgent booted out and disabled, the LaunchDaemon under the SAME label (OpenClaw recognises a
# same-label system LaunchDaemon and leaves the lifecycle to it). Otherwise --harness-cmd and the
# label dev.wardenclaw.wardend.
#
# Honoured for tests (deploy_macos_test.go runs this in DRY_RUN on Linux): PLISTBUDDY= a stand-in
# for /usr/libexec/PlistBuddy, OPENCLAW_LABEL= the LaunchAgent label to look for.

MAC_APP_DIR="/Library/Application Support/${PROJECT}"
MAC_APP="$MAC_APP_DIR/${DAEMON}.app"
MAC_BIN="$MAC_APP/Contents/MacOS/${DAEMON}"
MAC_CONF_DIR="/etc/${DAEMON}"
MAC_STATE_DIR="/var/db/${DAEMON}"
MAC_LOG="/var/log/${DAEMON}.log"
MAC_DAEMONS="/Library/LaunchDaemons"
MAC_DEFAULT_LABEL="dev.wardenclaw.${DAEMON}"
MAC_BUNDLE_ID="dev.wardenclaw.${DAEMON}"
PLISTBUDDY="${PLISTBUDDY:-/usr/libexec/PlistBuddy}"
OPENCLAW_LABEL="${OPENCLAW_LABEL:-ai.openclaw.gateway}"

# ---- helpers ----------------------------------------------------------------------------------

xml_esc() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

# write_root FILE MODE: install stdin as FILE (root:wheel MODE); in DRY_RUN print it indented
write_root() {
	if [ -n "$DRY_RUN" ]; then
		printf '+ write %s (root %s):\n' "$1" "$2"
		sed 's/^/    /'
	else
		_tmp=$(mktemp) || die "cannot create a temporary file"
		cat >"$_tmp"
		install -o root -g wheel -m "$2" "$_tmp" "$1" || { rm -f "$_tmp"; die "cannot write $1"; }
		rm -f "$_tmp"
	fi
}

# plist_array FILE KEY: the strings of an array in a plist, one per line (PlistBuddy prints
# "Array {", one indented line per element, "}")
plist_array() {
	"$PLISTBUDDY" -c "Print :$2" "$1" 2>/dev/null | sed -e '1d' -e '$d' -e 's/^    //'
}

# plist_dict FILE KEY: the entries of a dict of strings, KEY=VALUE per line ("Dict {", "    K = V", "}")
plist_dict() {
	"$PLISTBUDDY" -c "Print :$2" "$1" 2>/dev/null | sed -e '1d' -e '$d' -e 's/^    //' -e 's/ = /=/'
}

mac_user_home() { # NAME -> home directory, or nothing
	if have dscl; then
		dscl . -read "/Users/$1" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p'
	elif have getent; then
		getent passwd "$1" 2>/dev/null | cut -d: -f6
	else
		eval printf '%s' "~$1" 2>/dev/null
	fi
}

mac_user_uid() { # NAME -> uid; in DRY_RUN an unknown user gets a stand-in
	id -u "$1" 2>/dev/null && return 0
	[ -n "$DRY_RUN" ] || die "user $1 does not exist"
	warn "user $1 does not exist here (dry run): using uid 501 in the plan"
	printf '501'
}

# detect_openclaw_mac: the gateway LaunchAgent of AGENT_USER: MAC_LA_PLIST, MAC_LABEL, the command
# in $MAC_ARGS (one argument per line) and the environment in $MAC_ENV (KEY=VALUE per line).
# Returns 1 when there is none.
detect_openclaw_mac() {
	MAC_LA_PLIST="$AGENT_HOME/Library/LaunchAgents/$OPENCLAW_LABEL.plist"
	[ -f "$MAC_LA_PLIST" ] || return 1
	[ -x "$PLISTBUDDY" ] || die "$PLISTBUDDY not found: cannot read $MAC_LA_PLIST (pass --harness-cmd to skip the plist)"
	MAC_ARGS="$WORK/harness.args" MAC_ENV="$WORK/harness.env"
	plist_array "$MAC_LA_PLIST" ProgramArguments >"$MAC_ARGS"
	[ -s "$MAC_ARGS" ] || return 1
	plist_dict "$MAC_LA_PLIST" EnvironmentVariables >"$MAC_ENV" || true
	MAC_LABEL=$OPENCLAW_LABEL
	return 0
}

# entitlement_check: the bundle binary must carry the Endpoint Security entitlement; a binary
# without it runs only on a development machine with SIP off.
entitlement_check() {
	if ! have codesign; then
		warn "codesign not found: cannot tell whether $1 carries the Endpoint Security entitlement"
		return 0
	fi
	if codesign -d --entitlements - "$1" 2>/dev/null | grep -q 'com.apple.developer.endpoint-security.client'; then
		info "entitlement: com.apple.developer.endpoint-security.client present"
		return 0
	fi
	warn "$1 is not signed with com.apple.developer.endpoint-security.client: without the entitlement es_new_client fails unless SIP is off and the boot-args carry amfi_get_out_of_my_way=1 — a development machine only. Apple grants the entitlement per Team ID; see docs/macos.md"
	MAC_DEV_MODE=1
}

# ---- the install ------------------------------------------------------------------------------

macos_install() {
	MAC_DEV_MODE="" MAC_LABEL="" MAC_LA_PLIST="" MAC_ARGS="" MAC_ENV=""
	[ -z "$SINGLE_USER" ] || die "--single-user is not available on macOS: the Endpoint Security client needs root (sudo wardend wrap -- <cmd> for a trial)"
	[ -z "$RW_SET" ] || warn "--rw-paths has no effect on macOS (no systemd sandbox); ignored"
	[ -z "$ROOT_EXEC" ] || warn "--root-exec: rootexec and the sudo/docker shims are not installed on macOS yet; ignored"
	[ -z "$ADMIN_USER" ] || warn "--admin-user has no effect on macOS: the agent user keeps its groups (docs/macos.md); ignored"
	for _f in deploy/macos-install.sh deploy/wardend.launchd.plist; do
		[ -e "$PKG/$_f" ] || die "the release archive lacks $_f"
	done

	# The agent user: --agent-user, else the user who ran sudo. Never root.
	[ -n "$AGENT_USER" ] || AGENT_USER=${SUDO_USER:-}
	[ -n "$AGENT_USER" ] || die "cannot tell the agent user: run the installer with sudo from that user's account, or pass --agent-user NAME"
	[ "$AGENT_USER" != root ] || die "the agent user must not be root: wardend runs as root and starts the command as another user (--agent-user NAME)"
	_uid=$(mac_user_uid "$AGENT_USER")
	[ "$_uid" != 0 ] || die "$AGENT_USER has uid 0; the agent user must not be root"
	if [ -z "$AGENT_HOME" ]; then
		AGENT_HOME=$(mac_user_home "$AGENT_USER")
		[ -n "$AGENT_HOME" ] || AGENT_HOME="/Users/$AGENT_USER"
	fi

	_existing=""
	[ -f "$MAC_BIN" ] && [ -f "$MAC_CONF_DIR/config.json" ] && _existing=1
	_old=""
	[ -f "$SHARE_DIR/VERSION" ] && _old=$(cat "$SHARE_DIR/VERSION")

	# Upgrade: the binary in the bundle and the reference files; config, plist and user stay.
	if [ -n "$_existing" ] && [ -z "$HARNESS_CMD" ]; then
		if [ -n "$_old" ]; then info "upgrade: $_old -> $RELEASE"; else info "existing install found, updating the binary to $RELEASE"; fi
		if [ "$(sha256_of "$MAC_BIN")" = "$(sha256_of "$PKG/$DAEMON")" ]; then
			info "$MAC_BIN is already $RELEASE"
		else
			run install -o root -g wheel -m 0755 "$PKG/$DAEMON" "$MAC_BIN"
			_restart=1
		fi
		install_share
		if [ -n "$WITH_CTL" ] || [ -f "$BIN_DIR/$CTL" ]; then
			run install -o root -g wheel -m 0755 "$PKG/$CTL" "$BIN_DIR/$CTL"
		fi
		entitlement_check "$MAC_BIN"
		_label=$(mac_installed_label || true)
		say ""
		if [ -n "${_restart:-}" ]; then
			say "Upgraded. The running $DAEMON keeps the old binary until a restart, which also restarts the harness:"
			say "  sudo launchctl kickstart -k system/${_label:-$MAC_DEFAULT_LABEL}"
		else
			say "Nothing to upgrade: $RELEASE is installed."
		fi
		say "Next upgrade: sudo $SHARE_DIR/install.sh   (the installed copy)"
		return 0
	fi

	# The harness: the OpenClaw LaunchAgent of the agent user, or --harness-cmd.
	say ""
	if [ -z "$HARNESS_CMD" ] && detect_openclaw_mac; then
		AUTO=1
		HARNESS_CMD=$(tr '\n' ' ' <"$MAC_ARGS" | sed 's/ $//')
		say "Found the OpenClaw gateway of $AGENT_USER: $MAC_LA_PLIST"
		say "$DAEMON wraps it in place: same user, same home, same command and environment."
	else
		MAC_LABEL=$MAC_DEFAULT_LABEL
		while [ -z "$HARNESS_CMD" ]; do
			[ -z "$ASSUME_YES" ] || die "--harness-cmd is required (the command that starts your agent harness, absolute paths); no OpenClaw LaunchAgent of $AGENT_USER found ($AGENT_HOME/Library/LaunchAgents/$OPENCLAW_LABEL.plist)"
			say "No OpenClaw gateway LaunchAgent of $AGENT_USER found. Harness command: how the agent harness starts, with absolute paths."
			say "  example: /usr/local/bin/node /opt/openclaw/dist/index.js gateway --port 18789"
			ask HARNESS_CMD "Harness command" ""
		done
		MAC_ARGS="$WORK/harness.args" MAC_ENV="$WORK/harness.env"
		printf '%s\n' $HARNESS_CMD >"$MAC_ARGS" # word split on purpose: the Linux installer splits the same way
		: >"$MAC_ENV"
	fi
	_first=$(head -n 1 "$MAC_ARGS")
	case "$_first" in /*) ;; *) die "the harness command must start with an absolute path: $_first" ;; esac

	say ""
	say "  harness:      $HARNESS_CMD"
	say "  runs as:      $AGENT_USER (uid $_uid, home $AGENT_HOME), a child of $DAEMON, under the Endpoint Security exec gate"
	if [ -n "$AUTO" ]; then
		say "  old service:  gui/$_uid/$MAC_LABEL is booted out and disabled; $DAEMON starts the same command as the"
		say "                system LaunchDaemon $MAC_LABEL (OpenClaw sees its own label there and leaves it alone)"
	else
		say "  service:      system LaunchDaemon $MAC_LABEL"
	fi
	say "  files:        $MAC_APP, $MAC_CONF_DIR, $MAC_STATE_DIR, $MAC_DAEMONS/$MAC_LABEL.plist, log $MAC_LOG"
	say "  root:         $AGENT_USER keeps its groups and its own sudo (which asks for a password); rootexec is not on macOS yet"
	say "  phone:        pair after the install; it reaches $DAEMON through the relay, nothing listens on this machine"
	say "  mode:         $MODE (nothing is blocked; a week of watching, then ticket)"
	say ""
	[ -n "$DRY_RUN" ] || confirm "Install $DAEMON $RELEASE${AUTO:+ and wrap this gateway}?"

	# 1. The old LaunchAgent: out of launchd and disabled, so a login cannot start a second gateway.
	if [ -n "$AUTO" ]; then
		info "the gateway LaunchAgent of $AGENT_USER: booting out and disabling gui/$_uid/$MAC_LABEL"
		run launchctl bootout "gui/$_uid/$MAC_LABEL" || true
		run launchctl disable "gui/$_uid/$MAC_LABEL" || warn "launchctl disable gui/$_uid/$MAC_LABEL failed; the LaunchAgent may start again at login"
	fi

	# 2. The bundle.
	info "bundle: $MAC_APP"
	run install -d -o root -g wheel -m 0755 "$MAC_APP_DIR" "$MAC_APP/Contents" "$MAC_APP/Contents/MacOS"
	run install -o root -g wheel -m 0755 "$PKG/$DAEMON" "$MAC_BIN"
	write_root "$MAC_APP/Contents/Info.plist" 0644 <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>$MAC_BUNDLE_ID</string>
	<key>CFBundleName</key>
	<string>$DAEMON</string>
	<key>CFBundleExecutable</key>
	<string>$DAEMON</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleVersion</key>
	<string>${RELEASE#v}</string>
	<key>CFBundleShortVersionString</key>
	<string>${RELEASE#v}</string>
	<key>LSBackgroundOnly</key>
	<true/>
</dict>
</plist>
EOF
	if [ -f "$PKG/deploy/embedded.provisionprofile" ]; then
		run install -o root -g wheel -m 0644 "$PKG/deploy/embedded.provisionprofile" "$MAC_APP/Contents/embedded.provisionprofile"
	else
		info "no embedded.provisionprofile in this release: the bundle has no Endpoint Security entitlement (development mode, see below)"
	fi
	entitlement_check "$PKG/$DAEMON"

	# 3. Config and state (root-only).
	run install -d -o root -g wheel -m 0700 "$MAC_STATE_DIR"
	run install -d -o root -g wheel -m 0700 "$MAC_CONF_DIR"
	if [ -e "$MAC_CONF_DIR/config.json" ]; then
		info "$MAC_CONF_DIR/config.json exists, left as is (check mode and child_user)"
	else
		write_root "$MAC_CONF_DIR/config.json" 0600 <<EOF
{
  "version": 1,
  "mode": "$MODE",
  "require_hardened": true,
  "child_user": "$AGENT_USER",
  "agent_home": "$AGENT_HOME",
  "state_dir": "$MAC_STATE_DIR",
  "root_exec": {"enabled": false},
  "gate": {"scope": "auto", "deadline_miss": "fail-closed"},
  "trusted_devices": []
}
EOF
	fi

	# 4. The LaunchDaemon plist from the template: the harness arguments one <string> each, its
	#    environment as <key>/<string> pairs (its PATH replaces the template's default PATH).
	_argsx="$WORK/harness.args.xml" _envx="$WORK/harness.env.xml"
	while IFS= read -r _a; do printf '\t\t<string>%s</string>\n' "$(xml_esc "$_a")"; done <"$MAC_ARGS" >"$_argsx"
	_has_path=""
	: >"$_envx"
	while IFS= read -r _kv; do
		[ -n "$_kv" ] || continue
		_k=${_kv%%=*} _v=${_kv#*=}
		[ "$_k" != PATH ] || _has_path=1
		printf '\t\t<key>%s</key><string>%s</string>\n' "$(xml_esc "$_k")" "$(xml_esc "$_v")" >>"$_envx"
	done <"$MAC_ENV"
	esc() { printf '%s' "$1" | sed -e 's/[\\#&]/\\&/g'; }
	_rendered=$(sed -e "s#@LABEL@#$(esc "$(xml_esc "$MAC_LABEL")")#g" \
		-e "s#@WARDEND@#$(esc "$(xml_esc "$MAC_BIN")")#g" \
		-e "s#@CONFIG@#$(esc "$MAC_CONF_DIR/config.json")#g" \
		-e "s#@STATE_DIR@#$(esc "$MAC_STATE_DIR")#g" \
		-e "s#@CHILD_USER@#$(esc "$(xml_esc "$AGENT_USER")")#g" \
		-e "s#@LOG@#$(esc "$MAC_LOG")#g" "$PKG/deploy/wardend.launchd.plist" |
		awk -v args="$_argsx" -v env="$_envx" '
			/^@HARNESS_ARGS@$/ { while ((getline l < args) > 0) print l; next }
			/^@HARNESS_ENV@$/ { while ((getline l < env) > 0) print l; next }
			{ print }')
	if [ -n "$_has_path" ]; then
		_rendered=$(printf '%s\n' "$_rendered" | grep -v '^		<key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin</string>$')
	fi
	# the comment block of the template is for readers of the template, not of the installed plist
	_rendered=$(printf '%s\n' "$_rendered" | awk '/^<!--/ { skip = 1 } skip { if (/-->$/) skip = 0; next } { print }')
	if printf '%s' "$_rendered" | grep -q '@[A-Z_]*@'; then die "unresolved placeholders remain in the LaunchDaemon plist"; fi
	_plist="$MAC_DAEMONS/$MAC_LABEL.plist"
	printf '%s\n' "$_rendered" | write_root "$_plist" 0644
	if [ -z "$DRY_RUN" ] && have plutil; then plutil -lint "$_plist" >/dev/null || die "$_plist does not parse (plutil -lint)"; fi

	# 5. Reference files, wardenctl, then launchd.
	install_share
	install_ctl
	info "starting: launchctl bootstrap system $_plist"
	if launchctl print "system/$MAC_LABEL" >/dev/null 2>&1; then
		run launchctl bootout "system/$MAC_LABEL" || true
	fi
	run launchctl bootstrap system "$_plist" || die "launchctl bootstrap failed: sudo launchctl print system/$MAC_LABEL and $MAC_LOG"
	if [ -z "$DRY_RUN" ]; then
		sleep 3
		if launchctl print "system/$MAC_LABEL" 2>/dev/null | grep -q 'state = running'; then
			info "$DAEMON is running under launchd as $MAC_LABEL"
		else
			warn "$MAC_LABEL is not running yet: sudo launchctl print system/$MAC_LABEL; tail $MAC_LOG"
		fi
	fi

	if [ -n "$AUTO" ]; then _what="the OpenClaw gateway of $AGENT_USER"; else _what="the harness of $AGENT_USER"; fi
	cat <<EOF

$DAEMON $RELEASE is installed (mode: $MODE): $_what runs under it as the LaunchDaemon $MAC_LABEL.
Check:  sudo launchctl print system/$MAC_LABEL   and   tail -f $MAC_LOG

Full Disk Access: the Endpoint Security client gets no events without it. System Settings > Privacy &
Security > Full Disk Access: add $MAC_APP (on a development machine with SIP off the
same can be granted with a row in the system TCC database; docs/macos.md).
${MAC_DEV_MODE:+
DEVELOPMENT MODE: the binary carries no Endpoint Security entitlement. es_new_client fails on a
stock Mac; it works only with SIP off and amfi_get_out_of_my_way=1 in the boot-args. Do not run an
agent you do not trust on such a machine; docs/macos.md tells the entitlement story.
}
Next (details: $DOCS_URL):
  1. Pair your phone, from your own terminal (not from a chat with the agent); it prints a QR:
              sudo $DAEMON pair start
  2. About a week in observe: sudo $DAEMON journal  shows what would have asked;
     then "mode": "ticket" in $MAC_CONF_DIR/config.json and  sudo launchctl kickstart -k system/$MAC_LABEL
  3. Not on macOS yet: rootexec and the sudo/docker shims (the agent keeps its own sudo, which asks
     for a password), the privileged-group strip. OpenClaw's doctor: OPENCLAW_SERVICE_REPAIR_POLICY=external.

Upgrade:  sudo $SHARE_DIR/install.sh        Uninstall (keeps the journal):  sudo $SHARE_DIR/uninstall.sh
EOF
}

# mac_installed_label: the label of the installed LaunchDaemon plist that runs the bundle binary
mac_installed_label() {
	for _p in "$MAC_DAEMONS"/*.plist; do
		[ -f "$_p" ] || continue
		if grep -qF "<string>$MAC_BIN</string>" "$_p" 2>/dev/null; then
			_b=${_p##*/}
			printf '%s' "${_b%.plist}"
			return 0
		fi
	done
	return 1
}
