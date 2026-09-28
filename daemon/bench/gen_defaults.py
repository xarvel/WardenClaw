#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generator for the built-in policy: policy/defaults.json and harness packs policy/packs/*.json.

defaults.json holds the shared rules: deny_always, delegating (root mode), tripwire path zones,
and the gate binaries. Everything harness-specific lives in packs with path variables
(${AGENT_HOME}, ${CLAUDE_ROOT}, ${OPENCLAW_ROOT}, ...) instead of hard-coded /home/...:

  packs/claude-cli.json -- built from bench/claude-observe.jsonl (claude-cli 2.1.283 under wardend
      in observe mode): claude itself, its built-in rg, git probes, the env snapshot, and the
      snapshot's children. Variable parts (snapshot file path, home dir, PATH inside the heredoc,
      the random heredoc delimiter) are replaced by narrow patterns; the rest is a literal. After a
      claude-cli update the snapshot script may change -- it will then go to a card (fail-closed)
      and the rule must be regenerated from a fresh observe log.
  packs/openclaw.json -- internal workers and probes of the OpenClaw gateway 2026.9.x (wardend
      journal replay 26-28.09.2026), zones of its settings and
      secrets, and the CLI verbs that change the agent's settings.

    python3 bench/gen_defaults.py          # overwrite the three files
    python3 bench/gen_defaults.py --check  # compare with what is on disk (exit 1 if different)
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY = os.path.join(HERE, "..", "policy")
LOG = os.path.join(HERE, "claude-observe.jsonl")

META = set(r"\.+*?()|[]{}^$")


def lit(s: str) -> str:
    """Literal for Go RE2 (no anchors; anchors are added by rules.go)."""
    out = []
    for ch in s:
        if ch in META:
            out.append("\\" + ch)
        elif ch == "\n":
            out.append(r"\n")
        elif ch == "\t":
            out.append(r"\t")
        else:
            out.append(ch)
    return "".join(out)


def templ(s: str, subs):
    """subs: [(regex-in-python-matching-literal-part, go-regex-replacement)]. Literals for the
    spans between matches."""
    pat = re.compile("|".join("(" + p + ")" for p, _ in subs))
    out, pos = [], 0
    for m in pat.finditer(s):
        out.append(lit(s[pos:m.start()]))
        gi = next(i for i, g in enumerate(m.groups()) if g is not None)
        out.append(subs[gi][1])
        pos = m.end()
    out.append(lit(s[pos:]))
    return "".join(out)


# ---------------------------------------------------------------------------------------------
# defaults.json
# ---------------------------------------------------------------------------------------------
defaults = {
    "deny_always": [
        {"id": "rm-no-preserve-root", "argv0": r"^rm$", "argv_text": r"(^| )--no-preserve-root( |$)",
         "note": "rm --no-preserve-root"},
        {"id": "rm-recursive-root", "argv0": r"^rm$",
         "argv_text": r"^\S+( .*)? (-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)( .*)? (/|/\*|~|~/|\$HOME|/home|/home/[^/ ]+|/root|/etc|/usr|/var|/boot|/bin|/sbin|/lib|/lib64|/opt|/srv|/mnt|/mnt/[^/ ]+|/media)/?( |$)|^\S+( .*)? (/|/\*|~|/home|/home/[^/ ]+|/root|/etc|/usr|/var|/boot|/bin|/sbin|/lib|/opt|/srv|/mnt|/mnt/[^/ ]+)/?( .*)? (-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)( |$)",
         "note": "rm -r/-rf on the filesystem root, $HOME, and system directories"},
        {"id": "dd-to-device", "argv0": r"^dd$", "argv_text": r"(^| )of=/dev/", "note": "dd of=/dev/..."},
        {"id": "mkfs-and-partitioning", "argv0": r"^(mkfs(\..+)?|mke2fs|mkswap|wipefs|sfdisk|fdisk|cfdisk|parted|sgdisk|blkdiscard)$",
         "note": "filesystem creation, partitioning, and device wiping"},
        {"id": "shred-device", "argv0": r"^shred$", "argv_text": r"(^| )/dev/", "note": "shred on a device"},
        {"id": "chmod-chown-recursive-root", "argv0": r"^(chmod|chown|chgrp)$",
         "argv_text": r"^\S+( .*)? (-[a-zA-Z]*R[a-zA-Z]*|--recursive)( .*)? (/|/\*|/home|/etc|/usr|/var|/boot|/bin|/lib)/?( |$)",
         "note": "recursive chmod/chown on the root and system directories"},
    ],
    # harness-specific service_allow entries go in packs (policy/packs/*.json)
    "service_allow": [],
    # root mode: launches that move execution out of supervision are always a new root
    "delegating": [
        {"id": "session-detach", "argv0": r"^(setsid|daemon|start-stop-daemon|disown)$",
         "note": "session/tree detach: descendants may become orphaned and lose contact with the root"},
        {"id": "service-managers", "argv0": r"^(systemd-run|systemctl|service|busctl|dbus-send|gdbus|loginctl|machinectl)$",
         "note": "execution moves into systemd/D-Bus, outside the wardend tree"},
        {"id": "containers", "argv0": r"^(docker|podman|nerdctl|ctr|kubectl|lxc|lxc-attach|incus|firejail|bwrap|flatpak-spawn|distrobox|toolbox)$",
         "note": "execution moves into the container daemon, outside the wardend tree"},
        {"id": "multiplexers", "argv0": r"^(tmux|screen|zellij|abduco|dtach)$",
         "note": "the command may run in an already-running multiplexer server outside the tree"},
        {"id": "schedulers", "argv0": r"^(at|batch|crontab|anacron)$", "note": "deferred launch outside the tree"},
        {"id": "privilege-and-ns", "argv0": r"^(sudo|su|doas|pkexec|runuser|nsenter|unshare|chroot|setpriv|capsh)$",
         "note": "privilege or namespace change"},
        {"id": "remote", "argv0": r"^(ssh|mosh|rsh|scp|sftp)$", "note": "execution on a remote host"},
    ],
    "require_hardware": [],
    # tripwire mode: path zones (check order: secret -> config -> scratch -> work -> top -> other).
    # ${ANY_HOME} matches any home dir (agent home, /home/*, /root). Working and additional temp
    # dirs come from the install config (work_dirs, scratch_dirs); harness zones go in its pack.
    "zones": {
        "secret": [
            {"re": r"(?i)^${ANY_HOME}/\.ssh/", "not": r"(?i)^${ANY_HOME}/\.ssh/(known_hosts|[^/]*\.pub$)"},
            r"(?i)^${ANY_HOME}/\.gnupg(/|$)",
            r"(?i)^${ANY_HOME}/\.wardend/supervisor\.key",
            r"(?i)^/var/lib/wardend/supervisor\.key",
            r"(?i)^${ANY_HOME}/\.config/.*(token|credential|secret|password|\.key$|\.pem$|auth\.json$)",
            r"(?i)^${ANY_HOME}/\.(netrc|git-credentials|npmrc|pypirc)$",
            r"(?i)^${ANY_HOME}/\.(aws|kube|docker)/(credentials|config|config\.json)$",
            r"(?i)^/etc/(shadow|gshadow|sudoers)",
            r"(?i)/\.env(\.(local|production|prod|development|dev|test|staging))?$",
        ],
        "config": [
            r"^${ANY_HOME}/\.(bashrc|bash_profile|profile|zshrc|zprofile|bash_logout|inputrc|pam_environment)$",
            r"^${ANY_HOME}/\.config/(systemd|autostart|environment\.d)(/|$)",
            r"^${ANY_HOME}/\.local/bin(/|$)",
            r"^${ANY_HOME}/\.nvm(/|$)",
            r"^${ANY_HOME}/\.wardend(/|$)",
            r"^${ANY_HOME}/\.ssh(/|$)",
            r"^/(etc|usr|bin|sbin|lib|lib64|boot|opt|var/spool/cron|var/lib/wardend)(/|$)",
        ],
        "scratch": [
            r"^(/tmp|/var/tmp|/dev/shm|/run/user/[0-9]+)(/|$)",
            r"^${ANY_HOME}/(\.cache|\.npm/_npx|\.npm/_cacache|\.npm/_logs|\.gradle/caches|go/pkg/mod)(/|$)",
            r"^.*/(node_modules|dist|build|\.expo|\.next|target|__pycache__|\.gradle|\.test-build|\.turbo|coverage|\.venv|venv)(/|$)",
        ],
        "top": [
            r"^/(home|root|mnt|media|srv)?/?$",
            r"^/(mnt|media)/[^/]+/?$",
            r"^${ANY_HOME}/?$",
        ],
    },
    # gate CLI (guard rule); the running wardend binary and wardenctl next to it are added automatically
    "guard": r"^(${ANY_HOME}/\.local/bin|/usr/(local/)?s?bin)/(wardend|wardenctl)$",
}

# ---------------------------------------------------------------------------------------------
# packs/claude-cli.json
# ---------------------------------------------------------------------------------------------
CLAUDE_BIN = r"^${CLAUDE_ROOT}/versions/[0-9]+\.[0-9]+\.[0-9]+$"
entries = [json.loads(l) for l in open(LOG)]
snapshot = next(e["argv"][3] for e in entries if e["argv"][:3] == ["/bin/bash", "-c", "-l"])
snap_re = templ(snapshot, [
    (r"/home/[a-z_][a-z0-9_-]*/\.claude/shell-snapshots/snapshot-bash-[0-9]+-[a-z0-9]+\.sh",
     r"${AGENT_HOME}/\.claude/shell-snapshots/snapshot-bash-[0-9]+-[a-z0-9]+\.sh"),
    (r"/home/[a-z_][a-z0-9_-]*/\.bashrc", r"${AGENT_HOME}/\.bashrc"),
    (r"/home/[a-z_][a-z0-9_-]*/\.local/bin/claude", r"${CLAUDE_BIN}"),
    (r"export PATH=[^\n]*", r"export PATH=[^\n]*"),
    (r"PATH_END_[a-z0-9]+", r"PATH_END_[a-z0-9]+"),
])
bash_caller = r"^/usr/bin/bash$"
claude = {
    "pack": "claude-cli",
    "description": "Claude Code CLI, native install (a single binary per version). The claude process itself, "
                   "its built-in ripgrep, git probes, the shell environment snapshot and the snapshot's children. "
                   "Its Bash tool calls are separate execs and are checked by the rules.",
    "tested": ["2.1.283"],
    "family": "claude",
    "vars": {
        "CLAUDE_ROOT": ["${AGENT_HOME}/.local/share/claude", "/opt/claude"],
        "CLAUDE_BIN": ["${AGENT_HOME}/.local/bin/claude", "/usr/local/bin/claude"],
    },
    "detect": [{"var": "CLAUDE_ROOT", "command": r"^(/.*/claude)/versions/[0-9]+\.[0-9]+\.[0-9]+$"}],
    "runtime": CLAUDE_BIN,
    "service": [
        {"id": "claude", "path": CLAUDE_BIN, "argv0": r"^claude$",
         "note": "claude-cli itself (its Bash tool calls are separate execs and are checked by the rules)"},
        {"id": "rg", "path": CLAUDE_BIN, "argv0": r"^rg$", "caller": CLAUDE_BIN,
         "argv_none": r"^--pre(=.*)?$|^--pre-glob(=.*)?$",
         "note": "claude's built-in ripgrep (exec of itself with argv0=rg); --pre runs commands, not allowed"},
        {"id": "auth-status", "path": CLAUDE_BIN, "argv_json": r'^\["claude","auth","status"(,"[^"\\]*")*\]$',
         "note": "the gateway checks claude auth status"},
        {"id": "git-probe", "path": r"^/usr/bin/git$", "caller": CLAUDE_BIN,
         "argv_json": r'^\["(/usr/bin/)?git"(,"-c","(core\.askPass=|protocol\.ext\.allow=never|submodule\.recurse=false|log\.showSignature=false|gc\.auto=0|maintenance\.auto=false|core\.hooksPath=/dev/null|core\.fsmonitor=)")*(,"-C","[^"\\]*")?,"(ls-files|remote|rev-parse|status|log|show|branch|symbolic-ref|merge-base|diff)"(,"[^"\\]*")*\]$',
         "note": "claude's git probes: only known -c flags, only read-only subcommands; git children (pager, ext-diff) are checked separately"},
        {"id": "ps-probe", "path": r"^/usr/bin/dash$", "caller": CLAUDE_BIN,
         "argv": [r"(/bin/)?sh", r"-c", r"ps -o command= -p [0-9]+"]},
        {"id": "ps-command", "path": r"^/usr/bin/ps$", "argv": ["ps", "-o", "command=", "-p", "[0-9]+"]},
        {"id": "uname-probe", "path": r"^/usr/bin/dash$", "caller": CLAUDE_BIN,
         "argv": [r"(/usr/bin/|/bin/)?sh", "-c", lit(next(e["argv"][2] for e in entries if e["argv"][:2] == ["sh", "-c"]))]},
        {"id": "uname", "path": r"^/usr/bin/uname$", "argv": ["uname", "-[srm]"]},
        {"id": "bash-env", "path": r"^/usr/bin/bash$", "caller": CLAUDE_BIN, "argv": ["/bin/bash", "-c", "env"]},
        {"id": "env-print", "path": r"^/usr/bin/env$", "argv": ["env"], "note": "env without arguments only prints the environment"},
        {"id": "bash-snapshot", "path": r"^/usr/bin/bash$", "caller": CLAUDE_BIN,
         "argv": ["/bin/bash", "-c", "-l", "SNAPSHOT_FILE=" + snap_re.split("SNAPSHOT_FILE=", 1)[1]],
         "note": "claude-cli environment snapshot (bash -l, source ~/.bashrc); script text is a literal except for paths/PATH"},
        # snapshot-script children (from ~/.bashrc, /etc/profile.d, and the script itself): exact argv, bash caller only
        {"id": "snap-id", "path": r"^/usr/bin/id$", "caller": bash_caller, "argv": ["id", "-u"]},
        {"id": "snap-run-parts", "path": r"^/usr/bin/run-parts$", "caller": bash_caller,
         "argv": ["run-parts", "--list", "--regex", lit(r"^[a-zA-Z0-9_][a-zA-Z0-9._-]*\.sh$"), "/etc/profile.d"]},
        {"id": "snap-locale", "path": r"^/usr/bin/locale$", "caller": bash_caller, "argv": ["locale"]},
        {"id": "snap-rfkill", "path": r"^/usr/sbin/rfkill$", "caller": bash_caller, "argv": ["/usr/sbin/rfkill", "list", "wifi"]},
        {"id": "snap-grep", "path": r"^/usr/bin/grep$", "caller": bash_caller,
         "argv_json": r'^(\["grep","-q","Soft blocked: yes"\]|\["grep","-vE","\^_\[\^_\]"\]|\["grep","on"\])$'},
        {"id": "snap-head", "path": r"^/usr/bin/head$", "caller": bash_caller, "argv": ["head", "-n", "1000"]},
        {"id": "snap-cut", "path": r"^/usr/bin/cut$", "caller": bash_caller, "argv": ["cut", "-d ", "-f3"]},
        {"id": "snap-awk", "path": r"^/usr/bin/(mawk|gawk|awk)$", "caller": bash_caller, "argv": ["awk", lit('{print "set -o " $1}')]},
        {"id": "snap-sed", "path": r"^/usr/bin/sed$", "caller": bash_caller,
         "argv_json": r'^(\["sed","s/\^alias //g"\]|\["sed","s/\^/alias -- /"\])$'},
        {"id": "snap-cat", "path": r"^/usr/bin/cat$", "caller": bash_caller, "argv": ["cat"],
         "note": "cat without arguments: stdin to stdout (redirections were set up by the already-allowed parent)"},
    ],
    "zones": {
        "secret": [r"(?i)^${ANY_HOME}/\.claude/\.credentials\.json"],
        "config": [
            r"^${ANY_HOME}/\.local/share/claude(/|$)",
            r"^${CLAUDE_ROOT}(/|$)",
            r"^${ANY_HOME}/\.claude/(settings[^/]*\.json|CLAUDE\.md|hooks|commands|agents|plugins)",
        ],
    },
    "agent_config": [
        {"id": "claude-cli", "path": CLAUDE_BIN, "words": "raw",
         "verbs": {v: ["*", "!list", "!get"] for v in ("config", "mcp", "update", "install", "plugin")}},
    ],
}

# ---------------------------------------------------------------------------------------------
# packs/openclaw.json
# ---------------------------------------------------------------------------------------------
Q = r'"(?:[^"\\]|\\.)*"'          # one element of canonical JSON
GW = {"chain_all": r"/node$", "chain_max": 4}  # launched by the gateway itself (all ancestors are gateway node)
openclaw = {
    "pack": "openclaw",
    "description": "OpenClaw gateway 2026.9.x: its internal node workers and process supervisors, the probes the "
                   "gateway runs itself (git, systemd, lsof, gh token for the GitHub plugin, the egress proxy CA), "
                   "the zones of its settings and secrets, and the CLI verbs that change the agent's settings.",
    "tested": ["2026.9.6"],
    "family": "openclaw",
    "vars": {
        "OPENCLAW_ROOT": ["/usr/lib/node_modules/openclaw", "/usr/local/lib/node_modules/openclaw", "/opt/openclaw"],
        "OPENCLAW_HOME": ["${AGENT_HOME}/.openclaw"],
    },
    # pack root: from the command wardend launched (node .../openclaw/dist/index.js gateway)
    "detect": [{"var": "OPENCLAW_ROOT", "command": r"^(/.*/openclaw)/(?:dist/(?:index|entry)\.m?js|openclaw\.mjs)$"}],
    "service": [
        {"id": "worker", "path": r"/node$",
         "argv_json": r'^\[' + Q + r'(?:,"-(?:[^"\\]|\\.)*")*,"${OPENCLAW_ROOT}/dist/(?:[a-z0-9-]+/)*(?:[a-z0-9.-]+\.(?:worker|child)\.m?js|service-child-[a-z-]+\.m?js|spawn-broker/worker\.m?js)"(?:,|\])',
         "note": "internal workers and process supervisors of the gateway (node <root>/dist/.../*.worker.js); no inheritance: their children are checked independently"},
        None,  # service-child-launcher, defined below
        dict({"id": "gh-token", "path": r"/gh$", "argv": ["gh", "auth", "token", "--hostname", r"github\.com"],
              "note": "the gateway fetches its GitHub plugin token; gateway only (chain_all node)"}, **GW),
        dict({"id": "egress-proxy-ca", "path": r"/openssl$",
              "argv_json": r'^\["(?:[^"\\]*/)?openssl","req","-config","${OPENCLAW_HOME}/secret-egress-proxy/[^"\\]*"(,"[^"\\]*")*\]$',
              "note": "the gateway creates the CA for its egress proxy"}, **GW),
        dict({"id": "unit-probe", "path": r"/systemctl$",
              "argv_json": r'^\["systemctl","--user","show","openclaw-gateway(?:\.service)?"(?:,"--no-page")?,"(?:-p|--property)","[A-Za-z,]+"\]$',
              "note": "the gateway reads properties of its own unit"}, **GW),
        dict({"id": "systemd-version-probe", "path": r"/busctl$",
              "argv": ["busctl", "--user", "--auto-start=no", "get-property", r"org\.freedesktop\.systemd1",
                       r"/org/freedesktop/systemd1", r"org\.freedesktop\.systemd1\.Manager", "Version"]}, **GW),
        dict({"id": "port-probe", "path": r"/lsof$", "argv": [r"(/usr)?(/s?bin/)?lsof", "-nP", r"-iTCP:[0-9]+", "-sTCP:LISTEN", "-Fpc"]}, **GW),
        dict({"id": "login-env-probe", "path": r"/bash$", "argv": [r"(/usr)?/bin/bash", "-l", "-c", lit("printf '\\0'; env -0")],
              "note": "the gateway reads the login shell environment; profile children are checked independently"}, **GW),
        dict({"id": "git-probe", "path": r"/git$",
              "argv_json": r'^\["git","-c","maintenance\.autoDetach=false","-c","gc\.autoDetach=false","-C","[^"\\]*"(?:,"-c","core\.quotePath=false")?,"(?:rev-parse|diff|ls-files|status|log|show|symbolic-ref|merge-base|cat-file|for-each-ref)"(,"[^"\\]*")*\]$',
              "note": "the gateway reads git state of working directories"}, **GW),
        dict({"id": "git-read", "path": r"/git$",
              "argv_json": r'^\["git"(?:,"-C","[^"\\]*")?,"(?:rev-parse|status|config|remote)"(,"[^"\\]*")*\]$',
              "argv_none": r"^(--add|--unset(-all)?|--replace-all|--rename-section|--remove-section|--edit|-e|set-url|add|rm|remove|rename|set-head|set-branches|prune|update)$"}, **GW),
        dict({"id": "npm-query", "path": r"/npm-cli\.js$", "argv_json": r'^\["(?:[^"\\]*/)?npm","(?:root","-g"|config","get","[^"\\]*")\]$'}, **GW),
        dict({"id": "read-probe", "path": r"/(ps|getent|uname|id|hostname|whoami)$",
              "argv_none": r"^(-[a-zA-Z]*[bF]|--boot|--file)$",
              "note": "the gateway reads processes, users, and the hostname"}, **GW),
    ],
    "zones": {
        "secret": [
            r"(?i)^${ANY_HOME}/\.openclaw/(secrets|credentials|secret-egress-proxy)(/|$)",
            r"(?i)^${ANY_HOME}/\.openclaw/openclaw\.json",
            r"(?i)^${ANY_HOME}/\.openclaw/agents/[^/]+/agent/([^/]*auth[^/]*|[^/]*\.sqlite[^/]*|[^/]*credential[^/]*|[^/]*token[^/]*)$",
            r"(?i)^${OPENCLAW_HOME}/(secrets|credentials|secret-egress-proxy|openclaw\.json)(/|$)",
        ],
        "config": [
            r"^${ANY_HOME}/\.openclaw/(openclaw\.json|extensions|hooks|plugins|npm/projects)(/|$)",
            r"^${OPENCLAW_HOME}/(extensions|hooks|plugins|npm/projects)(/|$)",
            r"^${OPENCLAW_ROOT}(/|$)",
        ],
        "scratch": [r"^${ANY_HOME}/\.openclaw/tmp(/|$)", r"^${OPENCLAW_HOME}/tmp(/|$)"],
    },
    "agent_config": [
        {"id": "openclaw-cli", "entry": r"(^|/)openclaw(\.mjs)?$|/openclaw/dist/(index|entry)\.m?js$",
         "verbs": {
             "config": ["set", "unset", "patch", "edit", "apply", "import"],
             "cron": ["add", "edit", "rm", "remove", "delete", "enable", "disable", "update", "create"],
             "secrets": ["**"],
             "devices": ["approve", "reject", "remove", "clear", "revoke", "rotate"],
             "update": ["**"],
             "plugins": ["install", "uninstall", "enable", "disable", "update", "reload"],
             "mcp": ["login", "add", "remove", "logout", "set"],
             "approvals": ["set", "allow", "remove", "add"],
             "gateway": ["stop", "restart", "install", "uninstall", "start"],
             "agents": ["add", "remove", "edit", "set", "create", "delete"],
             "channels": ["add", "remove", "login", "logout"],
             "pairing": ["**"],
             "nodes": ["approve", "remove", "pair"],
         }},
    ],
}
# OOM wrapper the gateway uses to launch child processes on Linux (dist/linux-oom-score-*.mjs:
# OOM_SCORE_WRAP_SCRIPT and OOM_SCORE_RESTORE_EXEC_ENV_SCRIPT): /bin/sh -c '<script>' <program> ...
# The script is an exact literal; no inheritance: the program after exec is checked by its own rules.
OOM_WRAP = 'echo 1000 > /proc/self/oom_score_adj 2>/dev/null; exec "$0" "$@"'
OOM_RESTORE = "; ".join([
    'echo 1000 > /proc/self/oom_score_adj 2>/dev/null; if [ "${OC_INTERNAL_OOM_EXEC_BASH_ENV+x}" = x ]; then BASH_ENV="$OC_INTERNAL_OOM_EXEC_BASH_ENV"; export BASH_ENV; fi; unset OC_INTERNAL_OOM_EXEC_BASH_ENV',
    'if [ "${OC_INTERNAL_OOM_EXEC_ENV+x}" = x ]; then ENV="$OC_INTERNAL_OOM_EXEC_ENV"; export ENV; fi; unset OC_INTERNAL_OOM_EXEC_ENV',
    'if [ "${OC_INTERNAL_OOM_EXEC_CDPATH+x}" = x ]; then CDPATH="$OC_INTERNAL_OOM_EXEC_CDPATH"; export CDPATH; fi; unset OC_INTERNAL_OOM_EXEC_CDPATH',
    'if [ "${OC_INTERNAL_OOM_EXEC_PS4+x}" = x ]; then PS4="$OC_INTERNAL_OOM_EXEC_PS4"; export PS4; fi; unset OC_INTERNAL_OOM_EXEC_PS4; exec "$0" "$@"',
])


def jlit(s):
    """Literal string in canonical JSON (as in argv_json): JSON escaping, then RE2."""
    return lit(json.dumps(s, ensure_ascii=False)[1:-1])


openclaw["service"][1] = dict({
    "id": "oom-launcher", "path": r"^/usr/bin/dash$",
    "argv_json": r'^\["/bin/sh","-c","(?:' + jlit(OOM_WRAP) + "|" + jlit(OOM_RESTORE) + r')"(,"(?:[^"\\]|\\.)*")+\]$',
    "note": "OOM wrapper used by the gateway and its service supervisor to launch child processes (exec the program); "
            "the program is checked by its own rules; all ancestors are gateway node",
    "chain_all": r"/node$"})
# gh (GitHub plugin token) queries terminal capabilities; infocmp only reads terminfo
openclaw["service"].insert(3, {"id": "gh-infocmp", "path": r"/infocmp$", "caller": r"/gh$",
                               "note": "gh reads terminal capabilities"})


def dump(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


outs = {
    os.path.join(POLICY, "defaults.json"): dump(defaults),
    os.path.join(POLICY, "packs", "claude-cli.json"): dump(claude),
    os.path.join(POLICY, "packs", "openclaw.json"): dump(openclaw),
}
if "--check" in sys.argv[1:]:
    bad = [p for p, s in outs.items() if not os.path.exists(p) or open(p).read() != s]
    for p in bad:
        print("differs:", os.path.relpath(p, os.path.join(HERE, "..")))
    sys.exit(1 if bad else 0)
os.makedirs(os.path.join(POLICY, "packs"), exist_ok=True)
for p, s in outs.items():
    with open(p, "w") as f:
        f.write(s)
    print("wrote", os.path.relpath(p, os.path.join(HERE, "..")))
