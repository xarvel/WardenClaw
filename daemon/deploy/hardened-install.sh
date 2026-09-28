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
#   HTTP_LISTEN   app endpoint address, default 127.0.0.1:8787
#   PUBLIC_URL    external endpoint address for QR (tunnel), optional
#   PTRACE_SCOPE  2 (default) | skip: write kernel.yama.ptrace_scope to /etc/sysctl.d
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
HTTP_LISTEN="${HTTP_LISTEN:-127.0.0.1:8787}"
PUBLIC_URL="${PUBLIC_URL:-}"
PTRACE_SCOPE="${PTRACE_SCOPE:-2}"
HARNESS_CMD="${HARNESS_CMD:-}"
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

under_hidden(){ case "$1" in /home|/home/*|/root|/root/*|/run/user|/run/user/*) return 0;; esac; return 1; }
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
if id "$AGENT_USER" >/dev/null 2>&1; then
  bad=""
  for g in $(id -nG "$AGENT_USER"); do
    for pg in $PRIV_GROUPS; do [ "$g" = "$pg" ] && bad="$bad $g"; done
  done
  [ -z "$bad" ] || die "$AGENT_USER is in privileged groups:$bad (root-equivalent). Remove: gpasswd -d $AGENT_USER <group>"
  echo "  no privileged groups: ok"
  [ -d "$AGENT_HOME" ] || die "home directory $AGENT_HOME not found (required in ReadWritePaths and as WorkingDirectory)"
  if [ "$(id -u)" = 0 ] && command -v sudo >/dev/null; then
    if sudo -l -U "$AGENT_USER" 2>/dev/null | grep -q 'may run'; then
      die "$AGENT_USER has sudo rights (sudo -l -U $AGENT_USER). Remove them"
    fi
    echo "  sudoers: no rights, ok"
  else
    echo "  sudoers: will be checked on production run as root (sudo -l -U $AGENT_USER)"
  fi
fi

echo "== 2. Root-owned binary =="
run install -o root -g root -m 0755 "$WARDEND_BIN" /usr/local/bin/wardend

echo "== 3. State and config directories (root, 0700) =="
run install -d -o root -g root -m 0700 /var/lib/wardend   # key, journal, socket
run install -d -o root -g root -m 0700 /etc/wardend       # config, policy
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
PUB_LINE=""
[ -z "$PUBLIC_URL" ] || PUB_LINE="$(printf '\n  "public_url": "%s",' "$PUBLIC_URL")"
CFG="$(mktemp)"; trap 'rm -f "$CFG"' EXIT
cat > "$CFG" <<JSON
{
  "version": 1,
  "mode": "$MODE",
  "require_hardened": true,
  "child_user": "$AGENT_USER",
  "state_dir": "/var/lib/wardend",
  "http_listen": "$HTTP_LISTEN",$PUB_LINE
  "gateway_db": "off",
  "toctou_roots": "stop",
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
if printf '%s' "$RENDERED" | grep -q '@[A-Z_]*@'; then die "unresolved placeholders remain in the unit"; fi
if [ -n "$DRY" ]; then
  echo "+ write $UNIT (root 0644):"
  printf '%s\n' "$RENDERED" | grep -v '^#' | grep -v '^$' | sed 's/^/    /'
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

echo "== 6. polkit and logind: agent has no own systemd --user =="
agent_guard

echo "== 7. systemd =="
run systemctl daemon-reload

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
       sudo wardend pair start --socket /var/lib/wardend/wardend.sock
  5. Verify: sudo -u $AGENT_USER bash -s < $(dirname "$HERE")/redteam/hardened-check.sh   # all PASS
  6. Run in observe for a week, review the journal, then set "mode": "ticket" in
     /etc/wardend/config.json and systemctl restart wardend.
  7. Uninstall (journal and config copy are kept): sudo sh $(dirname "$HERE")/uninstall.sh
     Details including what remains and how to restore the harness: docs, "Uninstall" section.
EOF
