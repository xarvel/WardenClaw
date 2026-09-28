// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardend: exec supervisor on seccomp user notification: an "approved root" by a ticket signed
// by a WardenClaw device.
//
// The command list with flags is usage() below; commands with their own file: wrap (wrap.go), config-check
// (configcheck.go), pair (paircmd.go), hw-register and hw-keys (hwcmd.go, only
// with the hwkey tag). Internal mode: wardend __child --fd N -- <cmd...> (childMain).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/feature"
	"github.com/xarvel/WardenClaw/daemon/journal"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

// version is set by the release build: -ldflags "-X main.version=vX.Y.Z" (scripts/release.sh).
var version = "dev"

func main() {
	// The shims: a symlink named sudo or docker to this binary on the agent's PATH (rootexec_client.go).
	if name := filepath.Base(os.Args[0]); policy.RootExecShim(name) {
		os.Exit(cmdShim(name, os.Args[1:], os.Stdout, os.Stderr))
	}
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if isHelpArg(cmd) { // wardend --help | -h | help [<command> [<subcommand>]]
		if len(args) == 0 || isHelpArg(args[0]) {
			usage(os.Stdout)
			return
		}
		// help only: the tail after the command name is not passed on (help run sh -c … starts
		// nothing); for pair the next word is the subcommand
		rest := args[1:]
		cmd, args = args[0], []string{"--help"}
		if cmd == "pair" && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			args = []string{rest[0], "--help"}
		}
	}
	switch cmd {
	case "wrap":
		os.Exit(cmdWrap(args))
	case "run":
		os.Exit(cmdRun(args))
	case "config-check":
		os.Exit(cmdConfigCheck(args, os.Stdout, os.Stderr))
	case "__child":
		childMain(args)
	case "version", "--version", "-version":
		os.Exit(cmdVersion(args, os.Stdout, os.Stderr))
	case "keygen":
		os.Exit(cmdKeygen(args, os.Stdout, os.Stderr))
	case "approve":
		os.Exit(cmdApprove(args))
	case "status":
		os.Exit(cmdStatus(args))
	case "journal":
		os.Exit(cmdJournal(args))
	case "verify-journal":
		os.Exit(cmdVerifyJournal(args))
	case "policy-defaults":
		os.Exit(cmdPolicyDefaults(args, os.Stdout, os.Stderr))
	case "replay":
		os.Exit(cmdReplay(args, os.Stdout, os.Stderr))
	case "hw-register":
		os.Exit(cmdHWRegister(args, os.Stdout, os.Stderr, time.Now()))
	case "hw-keys":
		os.Exit(cmdHWKeys(args, os.Stdout, os.Stderr))
	case "pair":
		os.Exit(cmdPair(args, os.Stdout, os.Stderr))
	case "rootexec":
		os.Exit(cmdRootExec(args, os.Stdout, os.Stderr))
	default:
		fmt.Fprintf(os.Stderr, "wardend: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func isHelpArg(s string) bool { return s == "help" || s == "-h" || s == "-help" || s == "--help" }

// ---------------- subcommand flags ----------------

// cmdFlags: a subcommand FlagSet with uniform help behavior: --help, -h, -help (and help instead
// of arguments) print usage and flags to stdout with code 0, and the command does nothing else:
// no key, no files, no socket connection. A command-line error: message and usage to stderr,
// code 2, also before any action.
type cmdFlags struct {
	*flag.FlagSet
	use            string // usage line after "wardend "
	about          string // what the command does
	stdout, stderr io.Writer
}

func newCmdFlags(name, use, about string, stdout, stderr io.Writer) *cmdFlags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // parse prints help and errors, each to its own stream
	fs.Usage = func() {}
	return &cmdFlags{FlagSet: fs, use: use, about: about, stdout: stdout, stderr: stderr}
}

func (c *cmdFlags) printUsage(w io.Writer) {
	fmt.Fprintf(w, "usage: wardend %s\n", c.use)
	if c.about != "" {
		fmt.Fprintf(w, "\n%s\n", c.about)
	}
	n := 0
	c.VisitAll(func(*flag.Flag) { n++ })
	if n > 0 {
		fmt.Fprintln(w, "\nflags:")
		c.SetOutput(w)
		c.PrintDefaults()
		c.SetOutput(io.Discard)
	}
}

// fail: a command-line error: message and usage to stderr, code 2.
func (c *cmdFlags) fail(format string, v ...any) int {
	fmt.Fprintf(c.stderr, "wardend %s: %s\n\n", c.Name(), fmt.Sprintf(format, v...))
	c.printUsage(c.stderr)
	return 2
}

// parse: flags up to the first positional argument or "--", the rest goes to Args() (run: that
// is the command). ok=false: exit with code (0 after help, 2 after an error).
func (c *cmdFlags) parse(args []string) (code int, ok bool) {
	err := c.Parse(args)
	switch {
	case err == nil:
		return 0, true
	case errors.Is(err, flag.ErrHelp):
		c.printUsage(c.stdout)
		return 0, false
	}
	return c.fail("%v", err), false
}

// parseArgs: flags anywhere among positional arguments (pair approve <id> --socket s), help as
// the first argument means --help, from min to max positional arguments.
func (c *cmdFlags) parseArgs(args []string, min, max int) (pos []string, code int, ok bool) {
	for {
		if code, ok := c.parse(args); !ok {
			return nil, code, false
		}
		if c.NArg() == 0 {
			break
		}
		pos = append(pos, c.Arg(0))
		args = c.Args()[1:]
	}
	switch {
	case len(pos) > 0 && pos[0] == "help":
		c.printUsage(c.stdout)
		return nil, 0, false
	case len(pos) > max:
		return nil, c.fail("unexpected argument %q", pos[max]), false
	case len(pos) < min:
		return nil, c.fail("missing argument"), false
	}
	return pos, 0, true
}

// afterDoubleDash: the last n arguments follow an explicit "--": that is the command, even "help".
func afterDoubleDash(args []string, n int) bool {
	i := len(args) - n - 1
	return i >= 0 && args[i] == "--"
}

func cmdVersion(args []string, stdout, stderr io.Writer) int {
	fs := newCmdFlags("version", "version", "Prints the version of this binary.", stdout, stderr)
	if _, code, ok := fs.parseArgs(args, 0, 0); !ok {
		return code
	}
	fmt.Fprintln(stdout, "wardend", version)
	return 0
}

// cmdKeygen: a test device key. The seed is secret, so the key is printed only by the command
// without extra arguments: keygen --help and keygen help print help, not a key.
func cmdKeygen(args []string, stdout, stderr io.Writer) int {
	fs := newCmdFlags("keygen", "keygen",
		"Prints a new test device key pair: seed (secret, hex), pubkey (base64url) and deviceId.\n"+
			"For demos and tests with wardend approve; in production the key stays in the phone app.", stdout, stderr)
	if _, code, ok := fs.parseArgs(args, 0, 0); !ok {
		return code
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "wardend keygen:", err)
		return 1
	}
	fmt.Fprintf(stdout, "seed=%s\npubkey=%s\ndeviceId=%s\n", hex.EncodeToString(priv.Seed()), envelope.B64URL(pub), envelope.DeviceID(pub))
	return 0
}

func cmdPolicyDefaults(args []string, stdout, stderr io.Writer) int {
	fs := newCmdFlags("policy-defaults", "policy-defaults [--pack <name>]",
		"Prints the built-in policy rules as JSON: the starting point for your own --policy file.\n"+
			"With --pack, prints a built-in harness pack ("+strings.Join(policy.BuiltinPacks(), ", ")+").", stdout, stderr)
	pack := fs.String("pack", "", "built-in harness pack instead of the general rules")
	if _, code, ok := fs.parseArgs(args, 0, 0); !ok {
		return code
	}
	if *pack != "" {
		b, err := policy.BuiltinPackJSON(*pack)
		if err != nil {
			return fs.fail("no built-in pack %q (%s)", *pack, strings.Join(policy.BuiltinPacks(), ", "))
		}
		stdout.Write(b)
		return 0
	}
	stdout.Write(policy.DefaultsJSON())
	return 0
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `usage:
  wardend wrap [--mode ticket|deny-list|observe] [--policy rules.json] [--ttl 120s] [--state-dir d]
               [--relay-url wss://…] [--qr ansi|utf8|invert|none] [--quiet] -- <cmd...>
                                          try it: gate <cmd...> with the defaults, pair the phone on the first run
  wardend run [--config f] [--mode observe|deny-list|ticket] [--policy-mode tripwire|root] [--state-dir d]
              [--socket s] [--journal j] [--policy rules.json] [--ttl 120s] [--max-pending 64]
              [--trust <deviceId>[:<pubkey>]]...
              [--gateway-db off|auto|path] [--toctou-roots stop|poll|off] [--toctou-service off|poll|stop]
              [--relay-url wss://relay.wardenclaw.dev|off]
              [--linger 2s] [--require-hardened] [--child-user name|uid[:gid]] [--quiet] -- <cmd...>
  wardend config-check [--config f] [--state-dir d] [--policy rules.json] [-- <cmd...>]
                                          check the config and policy as run reads them, without starting anything
  wardend version
  wardend keygen
  wardend approve --key-file <file|-> [--socket s] [--match regex] [--deny] [--count N] [--timeout 30s]
  wardend status [--socket s]
  wardend journal [--socket s] [-n 20]
  wardend verify-journal [--pubkey b64url] <journal.jsonl>
  wardend policy-defaults [--pack name]   built-in rules (a base for your own --policy) or a harness pack
  wardend replay --journal <file> [--config f] [--policy-mode tripwire|root] [--from t] [--until t] [--json]
                                          run the journal through the classifier: cards per day, peaks, categories
%s  wardend pair start [--socket s] [--ttl 5m] [--qr ansi|utf8|invert|none] [--no-wait]
  wardend pair list [--socket s]           pending requests (key fingerprint) and trusted devices
  wardend pair approve <id> | reject <id>  approve/reject a request (writes trusted_devices to the config)
  wardend pair revoke <deviceId|prefix>    stop trusting a device
  wardend rootexec [--socket s] [--cwd d] -- <cmd...>
                                          from under the gate: ask wardend to run <cmd...> as its own user
                                          (root in the hardened install) after a card on the phone

wardend <command> --help (or wardend help <command>) prints the flags of a command and does nothing else.
`, hwUsage())
}

// hwUsage: second-factor help lines: only in a build with the hwkey tag (docs/hwkey.md).
func hwUsage() string {
	if !feature.HWKey {
		return ""
	}
	return `  wardend hw-register [--config f] [--name n] [--rp-id wardenclaw] [--require-uv] [--dry-run]
              (<wchw1:…> | --attestation <b64url|@file> [--client-data <b64url|@file>]
               | --cose-key <b64url> --credential-id <b64url>)
  wardend hw-keys [--config f]            registered hardware keys and their signCount
`
}

type trustFlag []envelope.TrustedDevice

func (t *trustFlag) String() string { return fmt.Sprint(*t) }
func (t *trustFlag) Set(v string) error {
	id, pk, _ := strings.Cut(v, ":")
	*t = append(*t, envelope.TrustedDevice{ID: id, Pubkey: pk})
	return nil
}

func cmdRun(args []string) int {
	fs := newCmdFlags("run", "run [flags] -- <cmd...>",
		"Starts <cmd...> under the supervisor: every execve/execveat in its process tree is gated.\n"+
			"Everything after -- is the command; flags override the config.", os.Stdout, os.Stderr)
	cfgPath := fs.String("config", "", "JSON config (default: <state-dir>/config.json, if present)")
	mode := fs.String("mode", "", "observe|deny-list|ticket")
	policyMode := fs.String("policy-mode", "", "tripwire (default: a signature only when a rule fires) | root (approved root)")
	stateDir := fs.String("state-dir", "", "state directory (~/.wardend)")
	sock := fs.String("socket", "", "unix-socket JSON-RPC")
	jpath := fs.String("journal", "", "JSONL journal")
	pol := fs.String("policy", "", "rules JSON (default: built-in)")
	ttl := fs.Duration("ttl", 0, "ticket wait TTL")
	maxp := fs.Int("max-pending", 0, "limit of the queue waiting for a ticket")
	gdb := fs.String("gateway-db", "", "off|auto|path to openclaw.sqlite (device keys from the gateway, read-only; default off)")
	relayURL := fs.String("relay-url", "", "relay the app reaches wardend through (wss://relay.wardenclaw.dev) or off")
	tr := fs.String("toctou-roots", "", "stop|poll|off")
	ts := fs.String("toctou-service", "", "off|poll|stop")
	linger := fs.Duration("linger", 0, "serve the rest of the tree after the child exits")
	quiet := fs.Bool("quiet", false, "no summary to stderr")
	reqHard := fs.Bool("require-hardened", false, "refuse to start if the binary/config/key is not root-owned")
	childUser := fs.String("child-user", "", "hardened install: drop the harness uid/gid to this user (name or uid[:gid])")
	var trust trustFlag
	fs.Var(&trust, "trust", "trusted device deviceId[:pubkey] (repeatable)")
	if code, ok := fs.parse(args); !ok {
		return code
	}
	switch {
	case fs.NArg() == 0:
		return fs.fail("missing command after --")
	case fs.NArg() == 1 && fs.Arg(0) == "help" && !afterDoubleDash(args, 1):
		fs.printUsage(os.Stdout)
		return 0
	}
	// without a config file, pair approve creates <state_dir>/config.json
	cfg, err := loadConfig(configPath(*cfgPath, *stateDir))
	if err != nil {
		fmt.Fprintln(os.Stderr, "wardend:", err)
		return 2
	}
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&cfg.Mode, *mode)
	set(&cfg.PolicyMode, *policyMode)
	set(&cfg.StateDir, *stateDir)
	set(&cfg.Socket, *sock)
	set(&cfg.Journal, *jpath)
	set(&cfg.Policy, *pol)
	set(&cfg.GatewayDB, *gdb)
	set(&cfg.RelayURL, *relayURL)
	set(&cfg.ToctouRoots, *tr)
	set(&cfg.ToctouService, *ts)
	if *ttl > 0 {
		cfg.TicketTTL.Duration = *ttl
	}
	if *maxp > 0 {
		cfg.MaxPending = *maxp
	}
	if *linger > 0 {
		cfg.Linger.Duration = *linger
	}
	if *reqHard {
		cfg.RequireHardened = true
	}
	set(&cfg.ChildUser, *childUser)
	cfg.TrustedDevices = append(cfg.TrustedDevices, trust...)
	return runCommand(cfg, &runOpts{cmd: fs.Args(), quiet: *quiet})
}

// runCommand is the common end of run and wrap: the policy file is checked, the supervisor runs
// the command; the result is the exit code of wardend.
func runCommand(cfg *Config, o *runOpts) int {
	pw, err := checkPolicyFile(cfg.Policy)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wardend:", err)
		return 2
	}
	for _, w := range pw {
		fmt.Fprintln(os.Stderr, "wardend: warning:", w)
	}
	code, err := runSupervisor(cfg, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wardend:", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

// configPath: the config file of run and config-check: --config, else <state-dir>/config.json if
// it exists; "": no config, defaults.
func configPath(flagPath, stateDir string) string {
	if flagPath != "" {
		return flagPath
	}
	if stateDir == "" {
		stateDir = defaultStateDir()
	}
	if p := filepath.Join(stateDir, "config.json"); fileExists(p) {
		return p
	}
	return ""
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// ---------------- helper child ----------------

func childMain(args []string) {
	runtime.LockOSThread() // the filter is installed on this thread, execve is done from it too
	fs := newCmdFlags("__child", "__child [--fd N] [--user u] -- <cmd...>",
		"Internal: the helper that wardend run starts to install the seccomp filter and exec <cmd...>.", os.Stdout, os.Stderr)
	sockFd := fs.Int("fd", 3, "unix socket for passing the listener fd")
	childUser := fs.String("user", "", "hardened install: drop the descendant's uid/gid to this user (name or uid[:gid])")
	if code, ok := fs.parse(args); !ok {
		os.Exit(code)
	}
	cmd := fs.Args()
	if len(cmd) == 1 && cmd[0] == "help" && !afterDoubleDash(args, 1) {
		fs.printUsage(os.Stdout)
		os.Exit(0)
	}
	if len(cmd) == 0 {
		fmt.Fprintln(os.Stderr, "__child: no cmd")
		os.Exit(2)
	}
	path, err := exec.LookPath(cmd[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "__child:", err)
		os.Exit(127)
	}
	// WAIT_KILLABLE_RECV is required: otherwise any signal to the target (SIGURG of the Go runtime)
	// cancels the notification and restarts execve, a stream of duplicates (README, "Pitfalls").
	lfd, err := installFilter(true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "__child:", err)
		os.Exit(3)
	}
	if err := unix.Sendmsg(*sockFd, []byte{'L'}, unix.UnixRights(lfd), nil, 0); err != nil {
		fmt.Fprintln(os.Stderr, "__child: sendmsg:", err)
		os.Exit(3)
	}
	ack := make([]byte, 1)
	if _, err := unix.Read(*sockFd, ack); err != nil || ack[0] != 'A' {
		fmt.Fprintln(os.Stderr, "__child: no ack from supervisor")
		os.Exit(3)
	}
	unix.Close(*sockFd)
	unix.Close(lfd)
	// hardened install: drop privileges BEFORE exec. The filter is already installed (it carries
	// over to the new image), the listener is held by the supervisor under root, which keeps reading
	// the descendant's /proc/<pid>/mem. The order is required: supplementary groups and gid first,
	// uid last (after setuid there is no permission to change gid).
	if *childUser != "" {
		// before dropping uid: while we are root, any value can be set
		if err := resetOOMScoreAdj(); err != nil {
			fmt.Fprintln(os.Stderr, "__child: oom_score_adj:", err)
		}
		if err := dropPrivileges(*childUser); err != nil {
			fmt.Fprintln(os.Stderr, "__child: drop privileges:", err)
			os.Exit(3)
		}
	}
	err = syscall.Exec(path, cmd, os.Environ())
	fmt.Fprintf(os.Stderr, "__child: exec %s: %v\n", path, err)
	os.Exit(126)
}

// ---------------- client commands ----------------

// socketFlag: --socket of a client command; empty means clientSocket picks the socket.
func socketFlag(fs *flag.FlagSet) *string {
	return fs.String("socket", "", "wardend unix socket (default: $"+socketEnv+", else ~/.wardend/"+socketName+" if it exists, else the system install's)")
}

// dialSupervisor connects pair to the socket; on failure it tells the owner why on stderr.
func dialSupervisor(sock string, stderr io.Writer) (*rpcClient, bool) {
	c, err := dialClient(sock)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, false
	}
	return c, true
}

// callOnce makes a single RPC call over a new socket connection.
func callOnce(sock, method string, params, out any) error {
	c, err := dialClient(sock)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.call(method, params, out)
}

// printIndentedJSON prints an RPC result as indented JSON with sorted keys.
func printIndentedJSON(w io.Writer, raw json.RawMessage) {
	var v any
	json.Unmarshal(raw, &v)
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(w, string(b))
}

func cmdStatus(args []string) int {
	fs := newCmdFlags("status", "status [--socket s]",
		"Supervisor state over the socket (JSON): mode, queue, tracker, trusted devices, journal key, metrics.", os.Stdout, os.Stderr)
	sock := socketFlag(fs.FlagSet)
	if _, code, ok := fs.parseArgs(args, 0, 0); !ok {
		return code
	}
	var out json.RawMessage
	if err := callOnce(clientSocket(*sock), "status", map[string]any{}, &out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	printIndentedJSON(os.Stdout, out)
	printStatusWarnings(os.Stderr, out)
	return 0
}

func cmdJournal(args []string) int {
	fs := newCmdFlags("journal", "journal [--socket s] [-n 20]", "The last N journal records over the socket (JSON lines).", os.Stdout, os.Stderr)
	sock := socketFlag(fs.FlagSet)
	n := fs.Int("n", 20, "journal lines")
	if _, code, ok := fs.parseArgs(args, 0, 0); !ok {
		return code
	}
	var out json.RawMessage
	if err := callOnce(clientSocket(*sock), "journal.tail", map[string]any{"n": *n}, &out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var r struct{ Lines []json.RawMessage }
	json.Unmarshal(out, &r)
	for _, l := range r.Lines {
		fmt.Println(string(l))
	}
	return 0
}

// approve: a "device in the terminal": long-poll pending, sign with a test key.
// In production the WardenClaw app signs (same format, gate.ts signDecision).
// The seed is read from a file, never from argv: the process list is readable by every
// process of the same user, including the one wardend is supervising.
func cmdApprove(args []string) int {
	fs := newCmdFlags("approve", "approve --key-file <file|-> [flags]",
		"A test device in a terminal: waits for pending execs on the socket and signs decisions with the seed\n"+
			"from wardend keygen. For demos and tests; in production the phone app signs.\n"+
			"The seed is not accepted on the command line. Do not run this inside the supervised command:\n"+
			"that command runs as you and can read the seed file.", os.Stdout, os.Stderr)
	sock := socketFlag(fs.FlagSet)
	key := fs.String("key", "", "rejected: a seed on the command line is visible in the process list")
	keyFile := fs.String("key-file", "", "file from wardend keygen, or - to read that output from stdin")
	match := fs.String("match", "", "sign only execs whose argv (space-joined) matches the regex")
	deny := fs.Bool("deny", false, "sign a denial instead of an allow")
	count := fs.Int("count", 1, "how many decisions to send (0: no limit until --timeout)")
	timeout := fs.Duration("timeout", 30*time.Second, "how long to wait")
	if _, code, ok := fs.parseArgs(args, 0, 0); !ok {
		return code
	}
	if *key != "" {
		fmt.Fprintln(os.Stderr, "wardend approve: --key puts the seed in the process list, where the supervised command can read it. Use --key-file.")
		return 2
	}
	if *keyFile == "" {
		fmt.Fprintln(os.Stderr, "wardend approve: pass --key-file with the file from wardend keygen (or - for stdin)")
		return 2
	}
	if selfUnderSeccompFilter() {
		fmt.Fprintln(os.Stderr, "wardend approve: refusing to run under a seccomp filter. This process is inside a supervised tree; run it from another terminal, outside wardend.")
		return 2
	}
	seed, err := readApproveSeed(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wardend approve:", err)
		return 2
	}
	var re *regexp.Regexp
	if *match != "" {
		if re, err = regexp.Compile(*match); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	priv := ed25519.NewKeyFromSeed(seed)
	decision := "allow"
	if *deny {
		decision = "deny"
	}
	n, err := approveLoop(clientSocket(*sock), priv, re, decision, *count, *timeout, func(line string) { fmt.Println(line) })
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if n == 0 {
		fmt.Println("nothing approved")
		return 1
	}
	return 0
}

// selfUnderSeccompFilter reports whether this process already has a seccomp filter.
// A missing /proc (not Linux) is not a filter. An old kernel without Seccomp_filters is not one either.
func selfUnderSeccompFilter() bool {
	n, ok := seccompFilters(os.Getpid())
	return ok && n > 0
}

// readApproveSeed reads a wardend keygen file (seed=…, pubkey=…, deviceId=…) or a bare 32-byte hex seed.
// "-" reads stdin. The file must not be group- or world-readable.
func readApproveSeed(path string) ([]byte, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(os.Stdin, 4096))
	} else {
		var fi os.FileInfo
		fi, err = os.Stat(path)
		if err != nil {
			return nil, err
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s is readable by group or others (mode %o); a seed file must be 0600", path, fi.Mode().Perm())
		}
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	hexSeed := strings.TrimSpace(string(b))
	for _, line := range strings.Split(hexSeed, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "seed="); ok {
			hexSeed = v
			break
		}
	}
	seed, err := hex.DecodeString(strings.TrimSpace(hexSeed))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("seed file: expected a 32-byte hex seed, or wardend keygen output")
	}
	return seed, nil
}

// approvePollWait caps a single long-poll of pending.
const approvePollWait = 5 * time.Second

// approveLoop signs up to count pending execs (0: no limit) until timeout and returns how many
// decisions it sent.
func approveLoop(sock string, priv ed25519.PrivateKey, re *regexp.Regexp, decision string, count int, timeout time.Duration, logf func(string)) (int, error) {
	c, err := dialClient(sock)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	done := map[string]bool{}
	var since int64
	sent := 0
	for time.Now().Before(deadline) && (count == 0 || sent < count) {
		var p struct {
			Seq     int64 `json:"seq"`
			Pending []struct {
				ID       string         `json:"id"`
				Digest   string         `json:"digest"`
				Envelope map[string]any `json:"envelope"`
			} `json:"pending"`
		}
		wait := min(time.Until(deadline), approvePollWait)
		if err := c.call("pending", map[string]any{"since": since, "wait": wait.Milliseconds()}, &p); err != nil {
			return sent, err
		}
		since = p.Seq
		for _, it := range p.Pending {
			if done[it.ID] || (count != 0 && sent >= count) {
				continue
			}
			// compute the digest ourselves from the envelope, as the app does
			d, err := envelopeDigest(it.Envelope)
			if err != nil || d != it.Digest {
				logf(fmt.Sprintf("skip %s: digest mismatch (%v)", it.ID, err))
				done[it.ID] = true
				continue
			}
			argv := fmt.Sprint(it.Envelope["argv"])
			if re != nil && !re.MatchString(strings.Trim(argv, "[]")) {
				continue
			}
			// exec ticket for this supervisor: supervisorId from the envelope (covered by the digest above)
			req, _ := it.Envelope["requester"].(map[string]any)
			sup, _ := req["supervisorId"].(string)
			b := envelope.Sign(priv, sup, it.ID, it.Digest, decision, envelope.NowMs(), envelope.NewNonce())
			var r map[string]any
			if err := c.call("decide", b, &r); err != nil {
				return sent, err
			}
			done[it.ID] = true
			sent++
			logf(fmt.Sprintf("%s %s argv=%s -> %v", decision, it.ID, argv, r))
		}
	}
	return sent, nil
}

func envelopeDigest(env map[string]any) (string, error) {
	raw, _ := json.Marshal(env)
	v, err := envelope.ParseJSON(raw)
	if err != nil {
		return "", err
	}
	_, d, err := envelope.Digest(v)
	return d, err
}

func cmdVerifyJournal(args []string) int {
	fs := newCmdFlags("verify-journal", "verify-journal [--pubkey b64url] [--expect-head seq:hash] <journal.jsonl>",
		"Checks the hash chain and the signature of every journal record. Pass the supervisor's public key\n"+
			"(status.journalKey) to check authorship, not only integrity. A journal whose last lines were\n"+
			"deleted still verifies on its own: pass status.journalHead as --expect-head to require that the\n"+
			"file ends exactly there.", os.Stdout, os.Stderr)
	pk := fs.String("pubkey", "", "supervisor public key (base64url); without it, the key from the start record (integrity only)")
	eh := fs.String("expect-head", "", "seq:hash of the last entry as status.journalHead reports it; head_mismatch when the file ends elsewhere")
	pos, code, ok := fs.parseArgs(args, 1, 1)
	if !ok {
		return code
	}
	var head *journal.Head
	if *eh != "" {
		h, err := journal.ParseHead(*eh)
		if err != nil {
			fmt.Fprintln(os.Stderr, "--expect-head:", err)
			return 2
		}
		head = &h
	}
	f, err := os.Open(pos[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer f.Close()
	var pub ed25519.PublicKey
	if *pk != "" {
		if pub, err = envelope.DecodeKey(*pk); err != nil {
			fmt.Fprintln(os.Stderr, "--pubkey:", err)
			return 2
		}
	}
	r := journal.Verify(f, pub)
	if head != nil {
		r = r.ExpectHead(*head)
	}
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
	if !r.OK {
		return 1
	}
	if *pk == "" {
		fmt.Fprintln(os.Stderr, "warning: the key was taken from the journal itself: chain integrity is verified, not authorship; pass --pubkey")
	}
	return 0
}
