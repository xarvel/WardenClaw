#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Hardened wardend installation (recommended): wardend runs as a system service under root;
# its binary, config, key, journal, and unit are root-owned; the agent harness runs as a
# CHILD of wardend under a SEPARATE unprivileged user (--child-user). The model under the
# harness uid then cannot send signals to wardend, ptrace it, or overwrite its files: these
# are kernel uid checks, not code promises.
#
# This script MODIFIES THE SYSTEM (requires root). Always do a dry run first:
#
#   DRY_RUN=1 AGENT_USER=agent \
#     HARNESS_CMD="/usr/bin/node /opt/openclaw/dist/index.js gateway --port 18789" \
#     daemon/deploy/hardened-install.sh ./daemon/wardend
#
# then the same with sudo and without DRY_RUN. Variables:
#   HARNESS_CMD   (required) harness command, absolute paths, not under /home, /root or /run/user
#   AGENT_USER    harness user, default: agent (created if absent)
#   AGENT_HOME    its home, default: an existing user's home, else /var/lib/$AGENT_USER
#                 (not under /home: ProtectHome)
#   RW_PATHS      additional writable directories for the harness, space-separated (workdirs)
#   MODE          observe (default, first week) | ticket | deny-list
#   PTRACE_SCOPE  2 (default) | skip: write kernel.yama.ptrace_scope to /etc/sysctl.d
#   ROOT_EXEC     non-empty: "root_exec": {"enabled": true} in the config: the rootexec socket
#                 (/run/wardend/rootexec.sock, root:<agent group> 0660) through which the agent
#                 asks for one command as root, each a card on the phone (docs/rootexec.md),
#                 plus the sudo and docker shims on the harness PATH
#   KEEP_HOME     non-empty: wrap an existing harness in place: its home may be under /home, its
#                 command too; the unit gets no ProtectHome/PrivateTmp/ProtectSystem/ProtectKernelTunables
#   HARNESS_ENV_FILE  file of Environment= lines copied into the unit (from the wrapped service)
#   OLD_USER_UNIT the harness's old systemd --user unit to disable and stop (openclaw-gateway.service)
#   STRIP_PRIV    non-empty: take the agent user out of the privileged groups and sudoers lines,
#                 after making sure a human admin account exists (ADMIN_USER, or the first other
#                 member of sudo/wheel/admin, or <agent>-admin created with the agent's ssh keys)
#   ADMIN_USER    the human admin account for STRIP_PRIV (see above)
#   AUTO_START    non-empty: systemctl enable --now wardend at the end and show the harness
#   NO_NEXT_STEPS non-empty: skip printing manual steps at the end (install.sh prints them)
#   ONLY_AGENT_GUARD non-empty: only step 6 (polkit rule, linger) for AGENT_USER; used by
#                 install.sh when upgrading an existing installation
#
# Normally this script is called by install.sh from a signed release archive; invoke it
# directly only when building from source.
#
# This script does NOT migrate harness data, does NOT stop the old harness service, and does
# NOT start wardend: those are manual steps (see output at the end and the "Installation" docs).
set -euo pipefail

WARDEND_BIN="${1:?usage: hardened-install.sh <path-to-built-wardend>}"
AGENT_USER="${AGENT_USER:-agent}"
if [ -z "${AGENT_HOME:-}" ] && getent passwd "$AGENT_USER" >/dev/null 2>&1; then
  AGENT_HOME="$(getent passwd "$AGENT_USER" | cut -d: -f6)"
fi
AGENT_HOME="${AGENT_HOME:-/var/lib/$AGENT_USER}"
RW_PATHS="${RW_PATHS:-}"
MODE="${MODE:-observe}"
PTRACE_SCOPE="${PTRACE_SCOPE:-2}"
HARNESS_CMD="${HARNESS_CMD:-}"
KEEP_HOME="${KEEP_HOME:-}"
HARNESS_ENV_FILE="${HARNESS_ENV_FILE:-}"
OLD_USER_UNIT="${OLD_USER_UNIT:-}"
STRIP_PRIV="${STRIP_PRIV:-}"
ADMIN_USER="${ADMIN_USER:-}"
AUTO_START="${AUTO_START:-}"
STRIPPED=""
DRY="${DRY_RUN:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$HERE/wardend.system.service"
UNIT=/etc/systemd/system/wardend.service
# Groups whose membership is root-equivalent or bypasses the uid boundary.
PRIV_GROUPS="root sudo wheel admin docker lxd incus libvirt disk"

run(){ echo "+ $*"; [ -n "$DRY" ] || "$@"; }
die(){ echo "ERROR: $*" >&2; exit 1; }
warn(){ echo "WARNING: $*" >&2; }

[ -n "$DRY" ] || [ "$(id -u)" = 0 ] || die "root required (or DRY_RUN=1 to preview steps)"

agent_guard(){ # step 6, called separately on upgrade: ONLY_AGENT_GUARD=1
  # Without this step the agent can get around the exec gate:
  # logind by default lets a user enable linger for itself (polkit, set-self-linger) via
  # D-Bus directly from the harness process. PID 1 then starts user@<uid>.service, and
  # `systemd-run --user` or a unit in ~/.config/systemd/user runs commands outside wardend's
  # seccomp filter (Seccomp: 0). Found in a live run on 2026-09-27 (docs/aws-hardened-test.md).
  # The rule denies all polkit actions to the agent user; root and the machine owner are unaffected.
  POLKIT_RULE=/etc/polkit-1/rules.d/60-wardend-agent.rules
  if [ -d /etc/polkit-1/rules.d ] || [ -d /usr/share/polkit-1/rules.d ]; then
    RULE="$(cat <<JS
// wardend hardened install: the agent user gets no polkit authorization at all, so it cannot
// enable systemd linger for itself and run commands from its own systemd --user manager,
// outside the wardend exec gate. Removed by /usr/local/share/wardend/uninstall.sh.
polkit.addRule(function(action, subject) {
    if (subject.user == "$AGENT_USER") {
        return polkit.Result.NO;
    }
});
JS
  )"
    if [ -n "$DRY" ]; then
      echo "+ write $POLKIT_RULE (root 0644): deny all polkit actions for $AGENT_USER"
    else
      install -d -m 0755 /etc/polkit-1/rules.d
      printf '%s\n' "$RULE" > "$POLKIT_RULE"
      chown root:root "$POLKIT_RULE"; chmod 0644 "$POLKIT_RULE"
      echo "  $POLKIT_RULE: all polkit actions for $AGENT_USER are denied"
    fi
  elif command -v pkaction >/dev/null 2>&1 || [ -d /etc/polkit-1/localauthority ]; then
    warn "polkit without rules.d (legacy .pkla): manually deny $AGENT_USER the org.freedesktop.login1.set-self-linger action"
  else
    echo "  no polkit: only root can enable linger"
  fi
  if [ -e "/var/lib/systemd/linger/$AGENT_USER" ]; then
    warn "$AGENT_USER has linger enabled (own systemd --user outside the gate): disabling"
    run loginctl disable-linger "$AGENT_USER"
  fi
  if id "$AGENT_USER" >/dev/null 2>&1 && systemctl is-active --quiet "user@$(id -u "$AGENT_USER").service" 2>/dev/null; then
    warn "$AGENT_USER has a running systemd --user: stopping"
    run systemctl stop "user@$(id -u "$AGENT_USER").service"
  fi
}

if [ -n "${ONLY_AGENT_GUARD:-}" ]; then
  # upgrade from install.sh: only the agent's own systemd --user guard
  echo "== polkit and logind: agent has no own systemd --user ($AGENT_USER) =="
  id "$AGENT_USER" >/dev/null 2>&1 || die "user $AGENT_USER not found"
  agent_guard
  exit 0
fi
[ -n "$DRY" ] && echo "### DRY_RUN: no changes will be made; commands are only printed"

echo "== 0. Prerequisites =="
[ -f "$WARDEND_BIN" ] || die "binary not found: $WARDEND_BIN (build: cd daemon && go build -o wardend .)"
[ -f "$TEMPLATE" ] || die "template not found: $TEMPLATE"
case "$MODE" in observe|ticket|deny-list) ;; *) die "MODE=$MODE: observe|ticket|deny-list";; esac
# 3 would also stop wardend from reading its children's memory and cannot be lowered until
# reboot; 0 and 1 are weaker.
case "$PTRACE_SCOPE" in 2|skip) ;; *) die "PTRACE_SCOPE=$PTRACE_SCOPE: 2 or skip";; esac
[ -n "$HARNESS_CMD" ] || die "HARNESS_CMD not set (harness command with absolute paths)"

# Kernel: SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV is required; added in 5.19.
kv="$(uname -r)"; kmaj="${kv%%.*}"; krest="${kv#*.}"; kmin="${krest%%[!0-9]*}"
if [ "$kmaj" -lt 5 ] || { [ "$kmaj" -eq 5 ] && [ "$kmin" -lt 19 ]; }; then
  die "kernel $kv, need 5.19 or newer (SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV)"
fi
echo "  kernel $kv: ok (need >= 5.19)"
command -v systemctl >/dev/null || die "systemd required"

under_hidden(){ [ -z "$KEEP_HOME" ] || return 1; case "$1" in /home|/home/*|/root|/root/*|/run/user|/run/user/*) return 0;; esac; return 1; }
first="${HARNESS_CMD%% *}"
case "$first" in /*) ;; *) die "HARNESS_CMD must start with an absolute path: $first";; esac
for w in $HARNESS_CMD; do
  case "$w" in /*) under_hidden "$w" && die "$w is under /home or /root: the unit hides them (ProtectHome). Reinstall the harness under /opt or /usr/local";; esac
done
[ -x "$first" ] || die "$first is not executable"
under_hidden "$AGENT_HOME" && die "AGENT_HOME=$AGENT_HOME is under /home or /root (hidden by ProtectHome): choose /var/lib/<user> (to move an existing user: usermod -m -d /var/lib/$AGENT_USER $AGENT_USER)"
for p in $RW_PATHS; do
  case "$p" in /*) ;; *) die "RW_PATHS: absolute path required: $p";; esac
  under_hidden "$p" && die "RW_PATHS: $p is under /home or /root (hidden by ProtectHome). Move it or edit the unit manually (ProtectHome=tmpfs + BindPaths=)"
  [ -d "$p" ] || die "RW_PATHS: directory not found: $p (a unit with a non-existent ReadWritePaths entry will not start)"
done
[ -z "$HARNESS_ENV_FILE" ] || [ -f "$HARNESS_ENV_FILE" ] || die "HARNESS_ENV_FILE not found: $HARNESS_ENV_FILE"
[ -z "$KEEP_HOME" ] || echo "  keep-home: the harness stays where it is ($AGENT_HOME); the unit drops ProtectHome, PrivateTmp, ProtectSystem and ProtectKernelTunables (the uid and the filter are the boundary)"

# strip_priv: root stays with a human account, not with the agent. First a human admin account
# that can sudo (ADMIN_USER, the first other member of sudo/wheel/admin, or <agent>-admin created
# with the agent's ssh keys and sudo without a password), then the agent leaves the privileged
# groups and every sudoers line that names it is commented out (backups .wardend-bak).
strip_priv(){
  echo "== 1a. Root stays with a human account, not with the agent =="
  if [ -z "$ADMIN_USER" ]; then
    for g in sudo wheel admin; do
      for m in $(getent group "$g" 2>/dev/null | cut -d: -f4 | tr ',' ' '); do
        if [ "$m" != "$AGENT_USER" ] && [ "$(id -u "$m" 2>/dev/null || echo 0)" -ge 1000 ]; then ADMIN_USER=$m; break 2; fi
      done
    done
  fi
  [ -n "$ADMIN_USER" ] || ADMIN_USER="${AGENT_USER}-admin"
  [ "$ADMIN_USER" != "$AGENT_USER" ] || die "ADMIN_USER must not be the agent user"
  if id "$ADMIN_USER" >/dev/null 2>&1; then
    echo "  admin account: $ADMIN_USER (exists)"
    id -nG "$ADMIN_USER" | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin' || run usermod -aG sudo "$ADMIN_USER"
  else
    echo "  admin account: creating $ADMIN_USER (sudo without a password, the agent's ssh keys, no password until you set one)"
    grp=sudo
    getent group docker >/dev/null 2>&1 && grp="$grp,docker"
    getent group adm >/dev/null 2>&1 && grp="$grp,adm"
    run useradd -m -s /bin/bash -G "$grp" "$ADMIN_USER"
    ah="/home/$ADMIN_USER"
    if [ -f "$AGENT_HOME/.ssh/authorized_keys" ]; then
      run install -d -m 0700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$ah/.ssh"
      run install -m 0600 -o "$ADMIN_USER" -g "$ADMIN_USER" "$AGENT_HOME/.ssh/authorized_keys" "$ah/.ssh/authorized_keys"
      echo "  ssh keys of $AGENT_USER copied: log in as $ADMIN_USER with the same key"
    else
      warn "$AGENT_HOME/.ssh/authorized_keys not found: set a password for $ADMIN_USER before you log out (passwd $ADMIN_USER)"
    fi
    if [ -n "$DRY" ]; then
      echo "+ write /etc/sudoers.d/90-wardend-admin: $ADMIN_USER ALL=(ALL) NOPASSWD:ALL"
    else
      printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$ADMIN_USER" > /etc/sudoers.d/90-wardend-admin
      chmod 0440 /etc/sudoers.d/90-wardend-admin
      visudo -c -q || die "sudoers check failed after /etc/sudoers.d/90-wardend-admin"
    fi
  fi
  for g in $PRIV_GROUPS; do
    if id -nG "$AGENT_USER" | tr ' ' '\n' | grep -qx "$g"; then
      run gpasswd -d "$AGENT_USER" "$g"
      STRIPPED="$STRIPPED $g"
    fi
  done
  for f in /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    if grep -qE "^[[:space:]]*$AGENT_USER[[:space:]]" "$f"; then
      echo "  $f names $AGENT_USER: commenting the line out (backup $f.wardend-bak)"
      if [ -z "$DRY" ]; then cp -p "$f" "$f.wardend-bak"; sed -i "s/^\([[:space:]]*$AGENT_USER[[:space:]]\)/# wardend: \1/" "$f"; fi
    fi
  done
  if grep -qE "^[[:space:]]*$AGENT_USER[[:space:]]" /etc/sudoers 2>/dev/null; then
    die "/etc/sudoers itself names $AGENT_USER: remove that line with visudo and run again"
  fi
  [ -n "$DRY" ] || visudo -c -q || die "sudoers check failed"
  [ -z "$STRIPPED" ] || echo "  $AGENT_USER removed from:$STRIPPED (restore: gpasswd -a $AGENT_USER <group>)"
  echo "  from now on, administer this machine as $ADMIN_USER; $AGENT_USER is the agent's account"
}
if [ -d /proc/sys/kernel/yama ]; then
  echo "  Yama: present, ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope)"
else
  warn "Yama LSM not in kernel: ptrace_scope cannot be set. The boundary remains (different uids) but without the second layer"
fi

echo "== 1. Harness user: $AGENT_USER ($AGENT_HOME) =="
CREATED_USER=""
if id "$AGENT_USER" >/dev/null 2>&1; then
  echo "  already exists: $(id "$AGENT_USER")"
  [ "$(id -u "$AGENT_USER")" != 0 ] || die "$AGENT_USER has uid 0"
else
  run useradd --system --user-group --create-home --home-dir "$AGENT_HOME" --shell /usr/sbin/nologin "$AGENT_USER"
  CREATED_USER=1
fi
[ -z "$STRIP_PRIV" ] || strip_priv
if id "$AGENT_USER" >/dev/null 2>&1; then
  bad=""
  for g in $(id -nG "$AGENT_USER"); do
    for pg in $PRIV_GROUPS; do [ "$g" = "$pg" ] && bad="$bad $g"; done
  done
  if [ -n "$bad" ] && [ -n "$DRY" ] && [ -n "$STRIP_PRIV" ]; then
    echo "  (dry run) $AGENT_USER is still in:$bad; the real run removes them above"
    bad=""
  fi
  [ -z "$bad" ] || die "$AGENT_USER is in privileged groups:$bad (root-equivalent). Remove: gpasswd -d $AGENT_USER <group>"
  echo "  no privileged groups: ok"
  [ -d "$AGENT_HOME" ] || die "home directory $AGENT_HOME not found (required in ReadWritePaths and as WorkingDirectory)"
  if [ "$(id -u)" = 0 ] && command -v sudo >/dev/null && [ -z "$DRY" ]; then
    if sudo -l -U "$AGENT_USER" 2>/dev/null | grep -q 'may run'; then
      die "$AGENT_USER has sudo rights (sudo -l -U $AGENT_USER). Remove them"
    fi
    echo "  sudoers: no rights, ok"
  else
    echo "  sudoers: will be checked on production run as root (sudo -l -U $AGENT_USER)"
  fi
fi

echo "== 2. Root-owned binary =="
# BIN_CHANGED / UNIT_CHANGED (step 4): a running wardend is restarted at the end only when one of
# them is set; a re-run that changes nothing leaves the harness alone.
BIN_CHANGED=""
if [ -f /usr/local/bin/wardend ] && cmp -s "$WARDEND_BIN" /usr/local/bin/wardend; then
  echo "  /usr/local/bin/wardend is already this binary"
else
  run install -o root -g root -m 0755 "$WARDEND_BIN" /usr/local/bin/wardend
  BIN_CHANGED=1
fi
# The agent's sudo: a symlink named sudo to wardend, first on the harness PATH (the unit sets it).
# Under the gate it is `wardend rootexec`; outside it hands over to /usr/bin/sudo (docs/rootexec.md).
SHIM_DIR=/usr/local/libexec/wardend/bin
if [ -n "${ROOT_EXEC:-}" ]; then
  echo "== 2a. sudo and docker shims for the agent: $SHIM_DIR/{sudo,docker} -> /usr/local/bin/wardend =="
  run install -d -o root -g root -m 0755 "$SHIM_DIR"
  run ln -sfn /usr/local/bin/wardend "$SHIM_DIR/sudo"
  run ln -sfn /usr/local/bin/wardend "$SHIM_DIR/docker"
elif [ -e "$SHIM_DIR/sudo" ]; then
  echo "  sudo shim $SHIM_DIR/sudo is present from an earlier install and stays (rootexec off: it refuses at connect)"
fi

echo "== 3. State and config directories (root, 0700) =="
run install -d -o root -g root -m 0700 /var/lib/wardend   # key, journal, socket
run install -d -o root -g root -m 0700 /etc/wardend       # config, policy
# what strip_priv took away, for uninstall.sh to name
[ -z "$STRIPPED" ] || [ -n "$DRY" ] || printf '%s%s\n' "$AGENT_USER" "$STRIPPED" > /var/lib/wardend/stripped-groups
# Users created by this installer: uninstall.sh --remove-agent-user removes only these,
# not users that already existed before installation.
MARK=/var/lib/wardend/created-agent-user
if [ -n "$CREATED_USER" ]; then
  if [ -n "$DRY" ]; then
    echo "+ append to $MARK: $AGENT_USER <uid>"
  else
    printf '%s %s\n' "$AGENT_USER" "$(id -u "$AGENT_USER")" >> "$MARK"
    chmod 0600 "$MARK"
  fi
fi
# root_exec: the socket the agent asks wardend through to run one command as root after a card
# (docs/rootexec.md). Off unless ROOT_EXEC is set; with it on, requests still pass only what the
# root_exec list of /etc/wardend/policy.json names (an empty list refuses everything).
RX_LINE='"root_exec": {"enabled": false},'
[ -z "${ROOT_EXEC:-}" ] || RX_LINE='"root_exec": {"enabled": true, "socket": "/run/wardend/rootexec.sock", "timeout": "10m"},'
CFG="$(mktemp)"; trap 'rm -f "$CFG"' EXIT
cat > "$CFG" <<JSON
{
  "version": 1,
  "mode": "$MODE",
  "require_hardened": true,
  "child_user": "$AGENT_USER",
  "state_dir": "/var/lib/wardend",
  "gateway_db": "off",
  "toctou_roots": "stop",
  $RX_LINE
  "trusted_devices": []
}
JSON
if [ -e /etc/wardend/config.json ]; then
  echo "  /etc/wardend/config.json already exists, leaving untouched (check mode and child_user)"
else
  [ -n "$DRY" ] && { echo "  config that will be written:"; sed 's/^/    /' "$CFG"; }
  run install -o root -g root -m 0600 "$CFG" /etc/wardend/config.json
fi

echo "== 4. System unit $UNIT =="
esc(){ printf '%s' "$1" | sed -e 's/[\\#&]/\\&/g'; }
RENDERED="$(sed -e "s#@AGENT_USER@#$(esc "$AGENT_USER")#g" \
                -e "s#@AGENT_HOME@#$(esc "$AGENT_HOME")#g" \
                -e "s#@RW_PATHS@#$(esc "$RW_PATHS")#g" \
                -e "s#@HARNESS_CMD@#$(esc "$HARNESS_CMD")#g" "$TEMPLATE")"
# the wrapped service's Environment= lines; with the shims, its PATH starts with their directory
if [ -n "$HARNESS_ENV_FILE" ] && [ -s "$HARNESS_ENV_FILE" ]; then
  ENV_TMP="$(mktemp)"
  if [ -n "${ROOT_EXEC:-}" ]; then
    sed 's#^Environment=PATH=#Environment=PATH=/usr/local/libexec/wardend/bin:#' "$HARNESS_ENV_FILE" > "$ENV_TMP"
  else
    cat "$HARNESS_ENV_FILE" > "$ENV_TMP"
  fi
  RENDERED="$(printf '%s\n' "$RENDERED" | awk -v f="$ENV_TMP" '/^@HARNESS_ENV@$/ { while ((getline l < f) > 0) print l; next } { print }')"
  rm -f "$ENV_TMP"
else
  RENDERED="$(printf '%s\n' "$RENDERED" | grep -v '^@HARNESS_ENV@$')"
fi
if [ -n "$KEEP_HOME" ]; then
  # No ProtectSystem/ProtectKernelTunables either: they would apply to the root commands rootexec
  # runs inside this unit (systemctl enable, a file in /etc, sysctl) and break the sudo the agent
  # had. Root-owned files are out of the agent's reach by uid; the filter is the gate.
  RENDERED="$(printf '%s\n' "$RENDERED" | sed -e '/^ProtectHome=/d' -e '/^PrivateTmp=/d' \
    -e '/^ProtectSystem=/d' -e '/^ReadWritePaths=/d' -e '/^ProtectKernelTunables=/d')"
fi
if printf '%s' "$RENDERED" | grep -v '^#' | grep -q '@[A-Z_]*@'; then die "unresolved placeholders remain in the unit"; fi
UNIT_CHANGED=1
if [ -f "$UNIT" ] && [ "$(cat "$UNIT" 2>/dev/null)" = "$RENDERED" ]; then UNIT_CHANGED=""; fi
if [ -n "$DRY" ]; then
  if [ -z "$UNIT_CHANGED" ]; then
    echo "  $UNIT is already this unit; it would be:"
  elif [ -f "$UNIT" ]; then
    echo "+ write $UNIT (root 0644); the lines that change (- installed, + rendered):"
    printf '%s\n' "$RENDERED" | diff "$UNIT" - | grep '^[<>]' | grep -v '^[<>] *#' | grep -v '^[<>] *$' | sed 's/^</    -/; s/^>/    +/' || true
    echo "  the whole unit:"
  else
    echo "+ write $UNIT (root 0644):"
  fi
  printf '%s\n' "$RENDERED" | grep -v '^#' | grep -v '^$' | sed 's/^/    /'
elif [ -z "$UNIT_CHANGED" ]; then
  echo "  $UNIT is already this unit"
else
  printf '%s\n' "$RENDERED" > "$UNIT"
  chown root:root "$UNIT"; chmod 0644 "$UNIT"
  command -v systemd-analyze >/dev/null && systemd-analyze verify "$UNIT" || true
fi

echo "== 5. Yama ptrace_scope =="
if [ "$PTRACE_SCOPE" = skip ]; then
  echo "  skipped (PTRACE_SCOPE=skip)"
elif [ -d /proc/sys/kernel/yama ]; then
  # 2 = ptrace only with CAP_SYS_PTRACE. wardend running as root is unaffected;
  # ordinary users will need sudo for strace/gdb -p.
  # Save the previous value for uninstall.sh to restore; only on the first install, before our
  # sysctl file exists (on a re-run the live value is already ours).
  BEFORE=/var/lib/wardend/ptrace_scope.before
  if [ ! -e /etc/sysctl.d/60-wardend-ptrace.conf ] && [ ! -e "$BEFORE" ]; then
    if [ -n "$DRY" ]; then
      echo "+ save previous value $(cat /proc/sys/kernel/yama/ptrace_scope) to $BEFORE"
    else
      cat /proc/sys/kernel/yama/ptrace_scope > "$BEFORE"
      chmod 0600 "$BEFORE"
    fi
  fi
  if [ -n "$DRY" ]; then
    echo "+ echo kernel.yama.ptrace_scope=$PTRACE_SCOPE > /etc/sysctl.d/60-wardend-ptrace.conf"
  else
    echo "kernel.yama.ptrace_scope=$PTRACE_SCOPE" > /etc/sysctl.d/60-wardend-ptrace.conf
  fi
  run sysctl -q -p /etc/sysctl.d/60-wardend-ptrace.conf
else
  echo "  Yama not in kernel, step skipped"
fi

if [ -n "$OLD_USER_UNIT" ]; then
  echo "== 5a. The harness's old service: $OLD_USER_UNIT of $AGENT_USER =="
  auid="$(id -u "$AGENT_USER")"
  if [ -d "/run/user/$auid" ]; then
    run runuser -u "$AGENT_USER" -- env "XDG_RUNTIME_DIR=/run/user/$auid" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$auid/bus" \
      systemctl --user disable --now "$OLD_USER_UNIT" || warn "systemctl --user could not stop $OLD_USER_UNIT; it stops with the user manager below"
  else
    echo "  no running user manager for $AGENT_USER"
  fi
  run rm -f "$AGENT_HOME/.config/systemd/user/default.target.wants/$OLD_USER_UNIT"
  echo "  $OLD_USER_UNIT stays in $AGENT_HOME/.config/systemd/user, disabled; wardend starts the same command"
fi

echo "== 6. polkit and logind: agent has no own systemd --user =="
if [ -n "$KEEP_HOME" ] && id "$AGENT_USER" >/dev/null 2>&1; then
  others="$(runuser -u "$AGENT_USER" -- env "XDG_RUNTIME_DIR=/run/user/$(id -u "$AGENT_USER")" systemctl --user list-unit-files --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | grep -v -e "^$OLD_USER_UNIT\$" | tr '\n' ' ' || true)"
  [ -z "$others" ] || warn "$AGENT_USER has other enabled user units: $others. They run outside the gate as the agent's user and stop with its user manager; move what you need to system units"
fi
agent_guard

echo "== 7. systemd =="
run systemctl daemon-reload
if [ -n "$AUTO_START" ]; then
  echo "== 8. Start =="
  if systemctl is-active --quiet wardend 2>/dev/null; then
    run systemctl enable wardend
    if [ -n "$UNIT_CHANGED$BIN_CHANGED" ]; then
      echo "  wardend is running with the previous${UNIT_CHANGED:+ unit}${BIN_CHANGED:+ binary}: restarting it (the harness restarts with it)"
      run systemctl restart wardend
    else
      echo "  wardend is running and nothing changed: no restart"
    fi
  else
    run systemctl enable --now wardend
  fi
  if [ -z "$DRY" ]; then
    sleep 3
    if systemctl is-active --quiet wardend; then
      echo "  wardend is active; the harness under it:"
      ps -o user,pid,args --ppid "$(systemctl show -p MainPID --value wardend)" 2>/dev/null | sed 's/^/    /'
    else
      die "wardend did not start: journalctl -u wardend -n 50 --no-pager"
    fi
  fi
fi

# install.sh (curl | sudo sh) prints its own "next steps" with installed paths.
[ -z "${NO_NEXT_STEPS:-}" ] || exit 0
cat <<EOF

Files installed. MANUAL steps next (details: docs, "Installation" section):
  1. Stop and disable the old harness service so it cannot start outside wardend
     (for a user unit: systemctl --user disable --now <unit>, remove the wardend drop-in if any).
  2. Migrate harness data to $AGENT_HOME and give it to $AGENT_USER:
       rsync -a <old-home>/.<harness>/ $AGENT_HOME/.<harness>/ && chown -R $AGENT_USER: $AGENT_HOME
     Shared workdirs: group or ACL (setfacl -R -m u:$AGENT_USER:rwX -m d:u:$AGENT_USER:rwX <dir>)
     and add them to RW_PATHS (re-run the script or edit ReadWritePaths in the unit).
  3. systemctl enable --now wardend
     ps -o user,pid,args --ppid "\$(systemctl show -p MainPID --value wardend)"   # harness running as $AGENT_USER
  4. Phone pairing (from your own terminal, not from the agent):
       sudo wardend pair start
  5. Verify: sudo -u $AGENT_USER bash -s < $(dirname "$HERE")/redteam/hardened-check.sh   # all PASS
  6. Run in observe for a week, review the journal, then set "mode": "ticket" in
     /etc/wardend/config.json and systemctl restart wardend.
  7. Uninstall (journal and config copy are kept): sudo sh $(dirname "$HERE")/uninstall.sh
     Details including what remains and how to restore the harness: docs, "Uninstall" section.
EOF
