// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

// Tripwire: every exec is checked against rules; no subtree trust. A signature is required
// only when a rule triggers (categories below); everything else is allowed and logged.
// Rules look at the real binary (basename realpath of the target) and argv; argv paths are
// resolved against cwd and zones (zones.go). Port of the replay classifier `rules.py: tripwire`.
//
// Categories:
//
//	delegate         execution leaves the gate: systemd-run, mutating systemctl, loginctl,
//	                 busctl/dbus-send except reads, tmux/screen, at, crontab (except -l)
//	container        docker/podman except reads, kubectl except reads, flatpak-spawn, distrobox ...
//	remote           ssh, scp, sftp, rsync host:..., nc/ncat/socat/telnet
//	privilege        nsenter/unshare/chroot/setpriv/capsh, apt install; sudo/su/doas/pkexec under
//	                 no_new_privs: refused with reason, no card (Hit.Refuse)
//	net-write        curl/wget with a body or write method to a non-loopback host
//	pkg-run          npm install/ci/exec, npx with -y/-p/pkg@version, pip install, go install ...
//	publish          git push, npm publish, gh writes, eas build/submit/update ...
//	destructive      rm -r/find -delete outside scratch, git reset --hard, clean -f, filter-branch ...
//	protected-write  write, delete, chmod in config and secret zones
//	outside-work     write and delete outside working directories and scratch
//	secret-read      printing tools on the secret zone; gh auth token
//	agent-config     agent settings via its CLI (rules in harness packs)
//	guard            live wardend CLI: pair, trust, devices, policy, keygen, hw ...
//	device           adb except reads, fastboot
//	cloud            aws/gcloud/az/terraform/kubectl/helm/flyctl/vercel/wrangler ...

import (
	"regexp"
	"strings"
)

// Hit is a triggered tripwire rule. Rule and Detail come only from a closed vocabulary
// (tool names and known verbs), never from raw agent text: they go to the journal, metrics,
// and the card shown next to argv.
type Hit struct {
	Category string `json:"category"`
	Rule     string `json:"rule"`
	Detail   string `json:"detail,omitempty"`
	Family   string `json:"family,omitempty"` // tool family for inheritance pairing
	Refuse   bool   `json:"refuse,omitempty"` // refuse without card (sudo under no_new_privs)
}

// ID returns "category/rule".
func (h *Hit) ID() string {
	if h == nil {
		return ""
	}
	return h.Category + "/" + h.Rule
}

// Label returns "category/rule detail" for humans.
func (h *Hit) Label() string {
	if h == nil {
		return ""
	}
	if h.Detail != "" {
		return h.ID() + " " + h.Detail
	}
	return h.ID()
}

// categoryNote holds notes for categories whose approved execs take execution outside the gate
// (shown on the card).
var categoryNote = map[string]string{
	"delegate":   "execution leaves the gate (systemd, D-Bus, multiplexer, scheduler): its children are not seen",
	"container":  "execution goes to the container daemon, outside the gate",
	"remote":     "anything can run on the other host, and any file can be sent there over stdin",
	"mount-ns":   "the caller unshared its mount namespace: the gate may resolve a different file than the kernel runs",
	"self-built": "the executable is owned or writable by the agent, so the name is not proof of what it is",
	CatLoaderEnv: "the program starts with LD_PRELOAD, LD_AUDIT or LD_LIBRARY_PATH set: code of another library runs inside it, however harmless the command looks (see the Environment block)",
}

// CatLoaderEnv is the category for execs with loader variables at the root (card always shown).
const CatLoaderEnv = "loader-env"

// CategoryNote returns the card note for a category (empty if none).
func CategoryNote(category string) string { return categoryNote[category] }

// ruleNote holds per-rule notes that are more specific than the category note.
// systemd-run: tests and previews typically ask to run "outside the gate"; the card states
// plainly what is being approved.
var ruleNote = map[string]string{
	"delegate/systemd-run": "outside the gate: systemd runs the command as a unit of its own; neither the command nor anything it starts is checked, and it goes on after the approval",
}

// HitNote returns the card note for a triggered rule: the rule-specific note if set, otherwise
// the category note.
func HitNote(h *Hit) string {
	if h == nil {
		return ""
	}
	if n := ruleNote[h.ID()]; n != "" {
		return n
	}
	return categoryNote[h.Category]
}

var (
	systemctlRO = set("status", "show", "cat", "is-active", "is-enabled", "is-failed", "is-system-running", "list-units",
		"list-unit-files", "list-timers", "list-sockets", "list-jobs", "list-dependencies", "list-automounts", "list-paths",
		"list-machines", "show-environment", "get-default", "help", "")
	systemctlVal = []string{"-p", "--property", "-t", "--type", "-s", "--signal", "-H", "--host", "-M", "--machine", "-n", "--lines",
		"-o", "--output", "--state", "--kill-whom", "--kill-value", "--root", "--what", "--job-mode", "--timestamp", "--message",
		"--image", "--drop-in", "--when"}
	systemctlVerbs = set("start", "stop", "restart", "reload", "try-restart", "reload-or-restart", "kill", "reset-failed", "enable",
		"disable", "reenable", "mask", "unmask", "edit", "set-property", "daemon-reload", "daemon-reexec", "link", "revert",
		"preset", "isolate", "set-environment", "unset-environment", "import-environment", "clean", "freeze", "thaw",
		"poweroff", "reboot", "halt", "suspend", "hibernate", "default", "rescue", "emergency", "exit", "switch-root",
		"add-wants", "add-requires", "set-default", "bind", "mount-image", "service-log-level", "service-log-target", "log-level")
	dockerRO    = set("ps", "inspect", "logs", "images", "version", "info", "stats", "top", "port", "events", "history", "search", "system df")
	dockerSubRO = map[[2]string]bool{
		{"image", "ls"}: true, {"image", "inspect"}: true, {"container", "ls"}: true, {"container", "inspect"}: true,
		{"container", "logs"}: true, {"network", "ls"}: true, {"network", "inspect"}: true, {"volume", "ls"}: true,
		{"volume", "inspect"}: true, {"context", "ls"}: true, {"context", "show"}: true, {"system", "df"}: true,
		{"compose", "ps"}: true, {"compose", "logs"}: true, {"compose", "config"}: true, {"compose", "ls"}: true,
		{"compose", "images"}: true, {"compose", "top"}: true, {"compose", "version"}: true,
	}
	dockerVerbs = set("run", "exec", "start", "stop", "restart", "kill", "rm", "rmi", "create", "build", "pull", "push", "cp",
		"commit", "tag", "login", "logout", "load", "save", "import", "export", "attach", "update", "pause", "unpause", "rename",
		"network", "volume", "image", "container", "system", "compose", "buildx", "builder", "plugin", "swarm", "service",
		"stack", "secret", "config", "node", "context", "trust", "manifest", "checkpoint", "wait", "diff")
	composeVerbs = set("up", "down", "start", "stop", "restart", "run", "exec", "build", "pull", "push", "rm", "create",
		"kill", "pause", "unpause", "scale", "cp", "watch", "wait", "attach", "")
	dbusRO = set("GetNameOwner", "ListNames", "ListActivatableNames", "NameHasOwner", "GetId", "Get", "GetAll", "Introspect",
		"Ping", "GetConnectionUnixUser", "GetConnectionUnixProcessID", "GetMachineId")
	busctlRO   = set("list", "status", "tree", "introspect", "get-property", "monitor", "capture", "help", "--version")
	loginctlRO = set("list-sessions", "list-users", "list-seats", "show-session", "show-user", "show-seat", "session-status",
		"user-status", "seat-status", "")
	loginctlVerbs = set("enable-linger", "disable-linger", "terminate-session", "terminate-user", "kill-session", "kill-user",
		"lock-session", "unlock-session", "lock-sessions", "unlock-sessions", "activate", "attach", "flush-devices")
	privTools   = set("sudo", "su", "doas", "pkexec", "runuser", "nsenter", "unshare", "chroot", "setpriv", "capsh", "newgrp", "sg", "sudoedit", "run0")
	refuseTools = set("sudo", "su", "doas", "pkexec", "sudoedit", "newgrp", "sg")
	remoteTools = set("ssh", "scp", "sftp", "mosh", "rsh", "sshpass", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "lftp")
	muxTools    = set("tmux", "screen", "zellij", "abduco", "dtach")
	cloudTools  = set("aws", "gcloud", "az", "terraform", "tofu", "pulumi", "kubectl", "helm", "doctl", "hcloud", "flyctl", "fly",
		"vercel", "wrangler", "netlify", "heroku", "firebase")
	adbShellRO = set("dumpsys", "getprop", "pidof", "cat", "ls", "df", "ps", "top", "uptime", "date", "id", "uname", "stat", "du",
		"logcat", "echo", "grep", "head", "tail", "wc", "true", "sleep", "find", "which", "free", "whoami", "printenv", "dmesg",
		"sed", "awk", "sort", "cut", "tr", "printf", "test", "[", "for", "do", "done", "if", "then", "else", "fi", "while", "in",
		"read", "basename", "dirname", "seq", "expr", "uniq", "tee", "readlink", "realpath", "getenforce", "cmd_", "exit",
		"false", "local", "export")
	adbRO        = set("devices", "get-state", "get-serialno", "version", "logcat", "pull", "start-server", "kill-server", "wait-for-device", "help", "-L", "features", "host-features")
	adbShellMut  = set("input", "am", "monkey", "uiautomator", "cmd", "settings", "pm", "rm", "run-as", "svc", "reboot", "setprop", "content", "appops", "service", "wm", "mv", "cp", "sh", "su")
	adbSubVerbs  = set("tap", "swipe", "keyevent", "text", "start", "force-stop", "broadcast", "kill", "instrument", "put", "delete", "install", "uninstall", "clear", "grant", "revoke", "disable", "enable", "uimode", "package", "dump", "set", "call", "startservice", "stopservice", "stack", "profile", "display", "overlay", "notification", "statusbar", "wifi", "data", "power", "usb", "nfc", "bluetooth")
	adbTopVerbs  = set("install", "install-multiple", "install-multi-package", "uninstall", "push", "sync", "shell", "exec-out", "root", "unroot", "remount", "reboot", "sideload", "disable-verity", "enable-verity", "tcpip", "usb", "forward", "reverse", "connect", "disconnect", "pair", "emu", "backup", "restore", "bugreport", "jdwp", "ppp", "keygen", "mdns")
	npmPkgRun    = set("install", "i", "ci", "add", "update", "up", "upgrade", "rebuild", "exec", "x", "init", "create", "install-test", "it")
	npmPublish   = set("publish", "unpublish", "deprecate", "dist-tag", "owner", "access", "token", "adduser", "login", "logout")
	easPublish   = set("build", "submit", "update", "deploy", "credentials", "secret", "env", "device", "channel", "branch", "webhook", "init", "project")
	easReadOnly  = set("build:view", "build:list", "project:info", "env:list", "channel:list", "branch:list")
	ghWrite      = map[[2]string]bool{}
	guardVerbs   = set("pair", "trust", "devices", "keygen", "hw", "hw-register", "policy", "config", "install", "uninstall", "untrust", "revoke", "run", "approve")
	secretTools  = set("cat", "head", "tail", "less", "more", "xxd", "od", "base64", "strings", "jq", "cp", "scp", "rsync", "dd", "openssl", "gpg", "age", "tar", "zip", "grep", "rg", "awk", "mawk", "gawk", "sed", "node")
	gitValOpts   = []string{"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
	gitSubs      = set("push", "reset", "clean", "checkout", "restore", "stash", "branch", "filter-branch", "filter-repo", "reflog", "update-ref")
	loopbackRx   = regexp.MustCompile(`^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|0\.0\.0\.0)$`)
	urlHostRx    = regexp.MustCompile(`^(?:https?|ftp|wss?)://(\[[^\]]+\]|[^/:?#]+)`)
	bareHostRx   = regexp.MustCompile(`^(localhost|127\.\d+\.\d+\.\d+|[a-z0-9.-]+\.[a-z]{2,})(:\d+)?(/|$)`)
	curlShortRx  = regexp.MustCompile(`^-[a-zA-Z]*[dFT]`)
	curlXRx      = regexp.MustCompile(`(?i)^-X(POST|PUT|PATCH|DELETE)$`)
	curlReqRx    = regexp.MustCompile(`(?i)^--request=(POST|PUT|PATCH|DELETE)$`)
	wgetMethodRx = regexp.MustCompile(`(?i)^--method=(POST|PUT|PATCH|DELETE)`)
	rsyncHostRx  = regexp.MustCompile(`^([\p{L}\p{N}_.-]+@)?[\p{L}\p{N}_.-]+:`)
	dbusMethRx   = regexp.MustCompile(`\.[A-Z][A-Za-z]+$`)
	npxVerRx     = regexp.MustCompile(`.@[^/]*$`)
	npxStripRx   = regexp.MustCompile(`@[^@/]*$`)
	adbRedirRx   = regexp.MustCompile(`\d?>&\d|&>|\d?>>?\s*/dev/null|\d?>>?`)
	envAssignRx  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	rmRecRx      = regexp.MustCompile(`^-[a-zA-Z]*[rR]`)
	cleanFRx     = regexp.MustCompile(`^-[a-zA-Z]*f`)
	cleanNRx     = regexp.MustCompile(`^-[a-zA-Z]*n`)
	rsyncNRx     = regexp.MustCompile(`^-[a-zA-Z]*n[a-zA-Z]*$`)
	pkgNameRx    = regexp.MustCompile(`^@?[a-z0-9][a-z0-9._-]{0,50}(/[a-z0-9][a-z0-9._-]{0,50})?$`)
)

// init fills ghWrite: gh (command, subcommand) pairs that publish or change something.
func init() {
	for _, p := range [][2]string{{"pr", "create"}, {"pr", "merge"}, {"pr", "close"}, {"pr", "edit"}, {"pr", "comment"}, {"pr", "review"},
		{"issue", "create"}, {"issue", "close"}, {"issue", "comment"}, {"issue", "edit"}, {"release", "create"}, {"release", "upload"},
		{"release", "delete"}, {"release", "edit"}, {"repo", "create"}, {"repo", "delete"}, {"repo", "edit"}, {"repo", "fork"},
		{"repo", "rename"}, {"repo", "archive"}, {"secret", "set"}, {"secret", "delete"}, {"variable", "set"}, {"workflow", "run"},
		{"run", "rerun"}, {"run", "cancel"}, {"gist", "create"}, {"gist", "edit"}, {"gist", "delete"}} {
		ghWrite[p] = true
	}
}

// set returns a lookup map of xs.
func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// vocab returns the word if it is in the dictionary, otherwise "other"
// (raw agent text must not appear in Detail).
func vocab(m map[string]bool, w string) string {
	if m[w] {
		return w
	}
	if w == "" {
		return ""
	}
	return "other"
}

// firstNonopt returns the first non-option argument (takes lists options that take a value)
// and the tail after it.
func firstNonopt(args []string, takes ...string) (string, []string) {
	for i := 0; i < len(args); i++ {
		x := args[i]
		if in(x, takes...) {
			i++
			continue
		}
		if strings.HasPrefix(x, "-") && x != "-" {
			continue
		}
		return x, args[i+1:]
	}
	return "", nil
}

// afterLastDot returns the part of s after the last "." (all of s if there is none): the
// method name of a D-Bus "interface.Method".
func afterLastDot(s string) string { return s[strings.LastIndexByte(s, '.')+1:] }

// anyRemoteHost reports whether any argument contains a non-loopback address (scheme-URL or
// bare-host). Unlike "first host", a leading loopback URL does not mask a subsequent external
// address: curl/wget iterate all supplied URLs and send the body to each, so one external
// address is enough to trigger the rule.
func anyRemoteHost(args []string) bool {
	for _, x := range args {
		if strings.HasPrefix(x, "-") {
			continue
		}
		if m := urlHostRx.FindStringSubmatch(x); m != nil {
			if !loopbackRx.MatchString(strings.ToLower(m[1])) {
				return true
			}
			continue
		}
		if m := bareHostRx.FindStringSubmatch(x); m != nil {
			if !loopbackRx.MatchString(strings.ToLower(m[1])) {
				return true
			}
		}
	}
	return false
}

// curlWrite reports whether a curl or wget invocation sends a body or uses a write method.
func curlWrite(exe string, args []string) bool {
	switch exe {
	case "curl":
		// `-G/--get` is not safe: with `-d/--data*` data still goes to the host in the query.
		// net-write checks for an outgoing body/fields, not for the method.
		for i, x := range args {
			if in(x, "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json", "-F", "--form", "--form-string", "-T", "--upload-file") {
				return true
			}
			if !strings.HasPrefix(x, "--") && curlShortRx.MatchString(x) {
				return true
			}
			if in(x, "-X", "--request") && i+1 < len(args) && in(strings.ToUpper(args[i+1]), "POST", "PUT", "PATCH", "DELETE") {
				return true
			}
			if curlXRx.MatchString(x) || curlReqRx.MatchString(x) {
				return true
			}
		}
	case "wget":
		for _, x := range args {
			for _, p := range []string{"--post-data", "--post-file", "--body-data", "--body-file"} {
				if strings.HasPrefix(x, p) {
					return true
				}
			}
			if wgetMethodRx.MatchString(x) {
				return true
			}
		}
	}
	return false
}

// adbSplit returns the adb subcommand and (for shell) the remote command segments split on ; && | ( ).
func adbSplit(args []string) (string, [][]string) {
	i := 0
	for i < len(args) && in(args[i], "-s", "-t", "-H", "-P", "-d", "-e", "-a") {
		if in(args[i], "-s", "-t", "-H", "-P") {
			i += 2
		} else {
			i++
		}
	}
	sub := ""
	if i < len(args) {
		sub = args[i]
	}
	var rest []string
	if i+1 < len(args) {
		rest = args[i+1:]
	}
	if sub != "shell" {
		return sub, nil
	}
	txt := adbRedirRx.ReplaceAllString(strings.Join(rest, " "), " ")
	toks, ok := shlexSplit(txt)
	if !ok {
		toks = strings.Fields(txt)
	}
	var segs [][]string
	var cur []string
	for _, tk := range toks {
		if tk != "" && strings.Trim(tk, shPunct) == "" {
			if len(cur) > 0 {
				segs = append(segs, cur)
			}
			cur = nil
			continue
		}
		if strings.HasPrefix(tk, "$(") || strings.HasPrefix(tk, "`") {
			if len(cur) > 0 {
				segs = append(segs, cur)
			}
			cur = []string{strings.TrimLeft(tk, "$(`")}
			continue
		}
		cur = append(cur, tk)
	}
	if len(cur) > 0 {
		segs = append(segs, cur)
	}
	var out [][]string
	for _, s := range segs {
		var w []string
		for _, x := range s {
			if x != "" {
				w = append(w, x)
			}
		}
		for len(w) > 0 && envAssignRx.MatchString(w[0]) {
			w = w[1:]
		}
		if len(w) > 0 {
			out = append(out, w)
		}
	}
	return sub, out
}

// adbMutating returns ("", "") for read-only invocations; otherwise rule and detail.
func adbMutating(args []string) (string, string) {
	sub, segs := adbSplit(args)
	if adbRO[sub] {
		return "", ""
	}
	if sub == "exec-out" {
		for i, x := range args {
			if x == "exec-out" {
				if i+1 < len(args) && args[i+1] == "screencap" {
					return "", ""
				}
				break
			}
		}
		return "adb-exec-out", ""
	}
	if sub == "shell" {
		for _, w := range segs {
			c := bname(w[0])
			if adbShellRO[c] {
				continue
			}
			w1 := ""
			if len(w) > 1 {
				w1 = w[1]
			}
			switch {
			case c == "pm" && in(w1, "list", "path", "dump", "has-feature"),
				c == "settings" && in(w1, "get", "list"),
				c == "cmd" && len(w) > 2 && w1 == "package" && in(w[2], "resolve-activity", "list"),
				c == "uiautomator" && w1 == "dump",
				c == "screencap":
				continue
			}
			if adbShellMut[c] {
				d := c
				if w1 != "" && !strings.HasPrefix(w1, "-") && in(c, "input", "am", "cmd", "settings", "pm", "svc", "wm", "content", "appops", "service", "uiautomator") {
					d += " " + vocab(adbSubVerbs, w1)
				}
				return "adb-shell", d
			}
			return "adb-shell", "other"
		}
		return "", ""
	}
	if sub == "" {
		return "adb", "other"
	}
	return "adb", vocab(adbTopVerbs, sub)
}

// cliWords returns the non-option CLI words after the entry point; nil if not OpenClaw CLI;
// empty slice means help.
func cliWords(argv []string, entry *regexp.Regexp) []string {
	if len(argv) == 0 || entry == nil {
		return nil
	}
	i := -1
	if entry.MatchString(argv[0]) {
		i = 0
	} else if in(bname(argv[0]), "node", "nodejs") && len(argv) > 1 && entry.MatchString(argv[1]) {
		i = 1
	}
	if i < 0 {
		return nil
	}
	if in("--help", argv...) || in("-h", argv...) {
		return []string{}
	}
	out := []string{}
	for _, w := range argv[i+1:] {
		if !strings.HasPrefix(w, "-") {
			out = append(out, w)
		}
	}
	return out
}

// gitSub returns the git subcommand after the global options and the arguments that follow it.
func gitSub(args []string) (string, []string) {
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		if in(args[i], gitValOpts...) {
			i += 2
		} else {
			i++
		}
	}
	if i < len(args) {
		return args[i], args[i+1:]
	}
	return "", nil
}

// gitRepoDir returns the directory git works in: the first -C argument (resolved against cwd),
// otherwise cwd.
func gitRepoDir(e *Exec, home string) string {
	a := e.Argv
	for i := 0; i+1 < len(a); i++ {
		if a[i] == "-C" {
			return normPath(a[i+1], e.Cwd, home)
		}
	}
	return e.Cwd
}

// tripwireCheck is a port of rules.py: tripwire(). Returns nil if no rule triggered.
func (c *Config) tripwireCheck(e *Exec) *Hit {
	exe := bname(e.Path)
	a := e.Argv
	var args []string
	if len(a) > 1 {
		args = a[1:]
	}
	a0 := ""
	if len(a) > 0 {
		a0 = bname(a[0])
	}
	hit := func(cat, rule, detail, fam string) *Hit {
		if fam == "" {
			fam = rule
		}
		return &Hit{Category: cat, Rule: rule, Detail: detail, Family: fam}
	}
	home := c.home

	// --- delegation out of the gate ---
	switch exe {
	case "systemd-run":
		return hit("delegate", "systemd-run", "", "systemd")
	case "systemctl":
		v, _ := firstNonopt(args, systemctlVal...)
		if systemctlRO[v] {
			return nil
		}
		return hit("delegate", "systemctl", vocab(systemctlVerbs, v), "systemd")
	case "service":
		if len(args) >= 2 && args[1] != "status" {
			return hit("delegate", "service", vocab(systemctlVerbs, args[1]), "service")
		}
	case "loginctl":
		v, _ := firstNonopt(args)
		if loginctlRO[v] {
			return nil
		}
		return hit("delegate", "loginctl", vocab(loginctlVerbs, v), "systemd")
	case "machinectl":
		return hit("delegate", "machinectl", "", "machinectl")
	case "busctl":
		v, _ := firstNonopt(args, "--destination", "-M", "--machine", "-H", "--host")
		if busctlRO[v] {
			return nil
		}
		return hit("delegate", "busctl", vocab(set("call", "set-property", "emit", "wait"), v), "systemd")
	case "dbus-send", "gdbus":
		meth := ""
		if exe == "dbus-send" {
			// dbus-send [options] <object path> <interface.method> [arguments...]
			if pos := nonopts(args); len(pos) >= 2 {
				meth = afterLastDot(pos[1])
			}
		} else {
			var ms []string
			for _, x := range args {
				if dbusMethRx.MatchString(x) && !strings.HasPrefix(x, "-") {
					ms = append(ms, x)
				}
			}
			if len(ms) > 0 {
				meth = afterLastDot(ms[len(ms)-1])
			}
		}
		if exe == "gdbus" {
			for i, x := range args {
				if x == "--method" {
					meth = afterLastDot(wordAt(args, i+1))
					break
				}
			}
			if len(args) > 0 && args[0] == "introspect" {
				meth = "Introspect"
			}
		}
		if dbusRO[meth] {
			return nil
		}
		return hit("delegate", exe, "", "systemd")
	case "docker", "podman", "nerdctl":
		v, rest := firstNonopt(args, "-H", "--host", "--context", "-c", "--config", "-l", "--log-level")
		if v == "compose" {
			v2, _ := firstNonopt(rest, "-f", "--file", "-p", "--project-name", "--project-directory", "--profile", "--env-file")
			if dockerSubRO[[2]string{"compose", v2}] {
				return nil
			}
			return hit("container", "compose", vocab(composeVerbs, v2), "docker")
		}
		if dockerRO[v] {
			return nil
		}
		v2, _ := firstNonopt(rest)
		if dockerSubRO[[2]string{v, v2}] {
			return nil
		}
		return hit("container", exe, vocab(dockerVerbs, v), "docker")
	case "docker-compose":
		if len(args) > 0 && args[0] == "docker-cli-plugin-metadata" {
			return nil
		}
		rest := args
		if len(args) > 0 && args[0] == "compose" {
			rest = args[1:]
		}
		v2, _ := firstNonopt(rest, "-f", "--file", "-p", "--project-name", "--project-directory", "--profile", "--env-file")
		if dockerSubRO[[2]string{"compose", v2}] {
			return nil
		}
		return hit("container", "compose", vocab(composeVerbs, v2), "docker")
	case "kubectl", "ctr", "lxc", "lxc-attach", "incus", "distrobox", "toolbox", "flatpak-spawn", "systemd-nspawn":
		if exe == "kubectl" {
			v, _ := firstNonopt(args)
			if in(v, "get", "describe", "logs", "top", "version", "api-resources", "explain", "config") {
				return nil
			}
		}
		return hit("container", exe, "", "")
	case "at", "batch":
		return hit("delegate", exe, "", "")
	case "crontab":
		if len(args) > 0 && args[0] == "-l" {
			return nil
		}
		d := ""
		if len(args) > 0 {
			d = vocab(set("-e", "-r", "-i", "-u"), args[0])
			if d == "other" {
				d = "install"
			}
		}
		return hit("delegate", "crontab", d, "crontab")
	}
	if muxTools[exe] {
		return hit("delegate", exe, "", "")
	}

	// --- privilege escalation ---
	if privTools[exe] || privTools[a0] {
		t := exe
		if !privTools[exe] {
			t = a0
		}
		h := hit("privilege", t, "", "")
		h.Refuse = refuseTools[t]
		return h
	}

	// --- remote execution and raw network ---
	if remoteTools[exe] {
		fam := exe
		if in(exe, "ssh", "scp", "sftp", "sshpass", "mosh") {
			fam = "ssh"
		}
		return hit("remote", exe, "", fam)
	}
	if exe == "rsync" {
		for _, x := range args {
			if !strings.HasPrefix(x, "-") && rsyncHostRx.MatchString(x) && !strings.HasPrefix(x, "/") {
				return hit("remote", "rsync", "", "ssh")
			}
		}
	}

	// --- network write ---
	if (exe == "curl" || exe == "wget") && curlWrite(exe, args) && anyRemoteHost(args) {
		return hit("net-write", exe, "", "")
	}

	// --- the gate itself ---
	if (in(a0, "wardend", "wardenctl") || in(exe, "wardend", "wardenctl")) && c.guardExe != nil && c.guardExe.MatchString(e.Path) && !in("--help", args...) {
		v, _ := firstNonopt(args)
		if guardVerbs[v] {
			t := exe
			if !in(exe, "wardend", "wardenctl") {
				t = a0
			}
			return hit("guard", t, v, "")
		}
	}

	// --- packages: download-and-run, publish ---
	if a0 == "npm" || exe == "npm-cli.js" {
		v, _ := firstNonopt(args, "--prefix", "-C", "--registry", "-w", "--workspace", "--cache", "--userconfig")
		if npmPkgRun[v] {
			return hit("pkg-run", "npm", v, "npm")
		}
		if npmPublish[v] {
			return hit("publish", "npm", v, "npm")
		}
		return nil
	}
	if a0 == "npx" || exe == "npx-cli.js" {
		v, _ := firstNonopt(args, "-p", "--package", "-c", "--call")
		pre := args
		for i, x := range args {
			if x == v {
				pre = args[:i]
				break
			}
		}
		flag := false
		for _, x := range pre {
			if in(x, "-y", "--yes", "-p") || strings.HasPrefix(x, "--package") {
				flag = true
			}
		}
		if flag || npxVerRx.MatchString(v) {
			pkg := npxStripRx.ReplaceAllString(v, "")
			fam := "npm"
			if pkg == "eas-cli" {
				fam = "eas"
			}
			if !pkgNameRx.MatchString(pkg) {
				pkg = "other"
			}
			return hit("pkg-run", "npx", pkg, fam)
		}
		return nil
	}
	if in(a0, "pnpm", "yarn", "bun") && len(args) >= 1 {
		v, _ := firstNonopt(args)
		if in(v, "add", "install", "i", "dlx", "create", "x") {
			return hit("pkg-run", a0, v, "npm")
		}
	}
	if in(a0, "pip", "pip3", "pipx", "uv", "uvx") || (strings.HasPrefix(exe, "python") && len(args) >= 2 && args[0] == "-m" && args[1] == "pip") {
		words := nonDashWords(args)
		w0, w1 := wordAt(words, 0), wordAt(words, 1)
		if a0 == "uvx" || in(w0, "install", "download", "run") || (len(words) >= 2 && ((w0 == "pip" && w1 == "install") || (w0 == "tool" && w1 == "install"))) ||
			(len(args) >= 2 && args[0] == "-m" && args[1] == "pip" && in("install", args...)) {
			t := a0
			if !in(a0, "pip", "pip3", "pipx", "uv", "uvx") {
				t = "pip"
			}
			return hit("pkg-run", t, "install", "pip")
		}
	}
	if in(a0, "apt", "apt-get", "dpkg", "snap", "flatpak") && anyIn(args, "install", "remove", "purge", "-i", "-r", "-P", "upgrade", "dist-upgrade") {
		return hit("privilege", a0, "install", "")
	}
	if a0 == "go" && len(args) > 0 && in(args[0], "install", "get") {
		return hit("pkg-run", "go", args[0], "go")
	}
	if in(a0, "cargo", "gem", "brew") && len(args) > 0 && args[0] == "install" {
		return hit("pkg-run", a0, "install", "")
	}
	if a0 == "eas" || (exe == "run" && strings.Contains(e.Path, "eas-cli")) {
		v, _ := firstNonopt(args)
		if easPublish[strings.SplitN(v, ":", 2)[0]] && !easReadOnly[v] {
			return hit("publish", "eas", strings.SplitN(v, ":", 2)[0], "eas")
		}
		return nil
	}
	if exe == "gh" || a0 == "gh" {
		words := nonDashWords(args)
		v, v2 := wordAt(words, 0), wordAt(words, 1)
		switch {
		case v == "auth" && v2 == "token":
			return hit("secret-read", "gh-auth-token", "", "gh")
		case v == "auth" && in(v2, "login", "logout", "refresh", "setup-git"):
			return hit("agent-config", "gh-auth", v2, "gh")
		case v == "api":
			meth := ""
			for i, x := range args {
				if in(x, "-X", "--method") && i+1 < len(args) {
					meth = strings.ToUpper(args[i+1])
				}
			}
			if (meth != "" && meth != "GET") || anyIn(args, "-f", "-F", "--field", "--raw-field", "--input") {
				return hit("publish", "gh-api", "", "gh")
			}
			return nil
		case ghWrite[[2]string{v, v2}]:
			return hit("publish", "gh", v+" "+v2, "gh")
		}
		return nil
	}
	if cloudTools[exe] || cloudTools[a0] {
		t := exe
		if cloudTools[a0] {
			t = a0
		}
		return hit("cloud", t, "", "")
	}
	if exe == "fastboot" {
		return hit("device", "fastboot", "", "adb")
	}
	if exe == "adb" {
		if r, d := adbMutating(args); r != "" {
			return hit("device", r, d, "adb")
		}
		return nil
	}

	// --- git: publish and destructive operations ---
	if exe == "git" {
		sub, rest := gitSub(args)
		repoZone := c.zones.Zone(gitRepoDir(e, home))
		if sub == "push" {
			d := ""
			for _, x := range rest {
				if in(x, "-f", "--force", "--force-with-lease", "--mirror") || strings.HasPrefix(x, "+") {
					d = "force"
				}
			}
			return hit("publish", "git-push", d, "git")
		}
		first := ""
		if len(rest) > 0 {
			first = rest[0]
		}
		destructive := (sub == "reset" && in("--hard", rest...)) ||
			(sub == "clean" && anyMatch(cleanFRx, rest) && !anyMatch(cleanNRx, rest) && !in("--dry-run", rest...)) ||
			(sub == "checkout" && anyIn(rest, "--", ".", "-f", "--force")) ||
			(sub == "restore" && !in("--staged", rest...) && len(rest) > 0) ||
			(sub == "stash" && in(first, "drop", "clear")) ||
			(sub == "branch" && in("-D", rest...)) || in(sub, "filter-branch", "filter-repo") ||
			(sub == "reflog" && in(first, "expire", "delete")) || (sub == "update-ref" && in("-d", rest...))
		if anyIn(rest, "--version", "--help", "-h") {
			destructive = false
		}
		if destructive && repoZone != ZoneScratch {
			return hit("destructive", "git", vocab(gitSubs, sub), "git")
		}
		return nil
	}

	// --- agent settings via CLI: harness packs, checked earlier in ClassifyTripwire ---

	// --- files: destruction, protected zones, leaving working dirs, secret reads ---
	w, d, r := fileTargets(exe, a, e.Cwd, home)
	if len(w) == 0 && len(d) == 0 && len(r) == 0 {
		return nil
	}
	if exe == "rsync" && (anyIn(args, "-n", "--dry-run") || anyMatch(rsyncNRx, args)) {
		w, d = nil, nil
	}
	recursive := (exe == "rm" && (anyMatch(rmRecRx, args) || in("--recursive", args...))) || exe == "find" || (exe == "rsync" && len(d) > 0)
	for _, p := range d {
		switch z := c.zones.Zone(p); {
		case z == ZoneSecret || z == ZoneConfig:
			return hit("protected-write", exe, "delete "+z, "")
		case recursive && (z == ZoneWork || z == ZoneOther || z == ZoneTop):
			return hit("destructive", exe, "-r "+z, "")
		case z == ZoneOther || z == ZoneTop:
			return hit("outside-work", exe, "delete "+z, "")
		}
	}
	for _, p := range w {
		switch z := c.zones.Zone(p); z {
		case ZoneSecret, ZoneConfig:
			return hit("protected-write", exe, "write "+z, "")
		case ZoneOther, ZoneTop:
			return hit("outside-work", exe, "write "+z, "")
		}
	}
	if secretTools[exe] || pythonRx.MatchString(exe) {
		for _, p := range r {
			if c.zones.Zone(p) == ZoneSecret && !strings.HasSuffix(p, ".pub") {
				return hit("secret-read", exe, "", "")
			}
		}
	}
	return nil
}

// noImply lists the package-manager families: an approved install never covers the installs it
// starts (an approved `npm ci` used to cover `npm install -g x` and `npx -y x` from a postinstall
// for ImpliedTTL without a card), and an install never inherits from anything either. Nested
// installs are the largest card category, so the judge has to see each one.
var noImply = set("npm", "pip", "go", "cargo", "gem", "brew")

// ImpliedBy reports whether a child-family exec inherits the approval of a root-family exec:
// ssh transport under scp/sftp/rsync/git, eas under npx eas-cli, docker-compose plugin under
// docker compose, a CLI restarting itself. Package-manager families (noImply) never do.
func ImpliedBy(child, root string) bool {
	if child == "" || root == "" || noImply[child] || noImply[root] {
		return false
	}
	return child == root || (child == "ssh" && root == "git")
}
