// SPDX-License-Identifier: AGPL-3.0-or-later

// wardenctl is the WardenClaw approver in a terminal: the same as the phone app, for the owner's
// laptop (macOS, Linux). Pairing via the `wardend pair start` link, exec cards over HTTP
// long-poll, signed tickets, a second YubiKey signature over USB (libfido2).
//
// The protocol is the wardend/envelope and wardend/hwkey packages (the same signing strings and
// fixtures as the app's app/src/core/wardendProto.ts). Builds without cgo and Linux specifics:
//
//	GOOS=darwin GOARCH=arm64 go build -o wardenctl ./cmd/wardenctl
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xarvel/WardenClaw/daemon/feature"
)

var version = "0.1.0" // release build: -ldflags "-X main.version=vX.Y.Z"

// Exit codes besides 0 (done) and 1 (failed); the README documents them for scripts.
const (
	exitUsage    = 2 // command line error
	exitGuard    = 3 // refused next to the agent (guard)
	exitProtocol = 4 // incompatible wardenctl and wardend protocol versions (ProtocolError)
)

type app struct {
	dir    string
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	now    func() time.Time
	guard  func() guardVerdict // nil: the real check
	tty    func() bool         // nil: stdin is a terminal (tests substitute the answer)
	json   bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := &app{dir: defaultDir(), stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, now: time.Now}
	os.Exit(a.run(ctx, os.Args[1:]))
}

func (a *app) usage(w io.Writer) {
	approve := hwText(`  wardenctl approve <id> [--no-hw] [--uv] [--device d] [--yes]
                                       shows the card and asks; allows with a YubiKey touch
                                       (--no-hw: without one, if wardend does not require it)
`, `  wardenctl approve <id> [--yes]       shows the card and asks; allows by signing with the
                                       device key
`)
	watchFlags := hwText(" [--no-hw]           ", "                     ")
	statusYubiKey := hwText("YubiKey, ", "")
	hwCommands := hwText(`  wardenctl hw-register [--device d] [--name n] [--alg auto|eddsa|es256] [--uv] [--require-uv]
                                       bind a YubiKey (USB): prints the command for wardend hw-register
  wardenctl hw-check [--device d] [--uv]  check the bound YubiKey
`, "")
	fmt.Fprintf(w, `wardenctl: approve wardend commands from a separate machine (like the WardenClaw app)

  wardenctl pair '<wardenclaw://pair?…>' [--name n] [--keystore auto|keychain|file] [--no-wait] [--timeout 10m]
  wardenctl pending                    the card queue
  wardenctl show <id>                  the full card: argv, cwd, exe, uid, process chain, rule, risk
%s  wardenctl deny <id>
  wardenctl watch%s new cards in the terminal: y allows, n denies,
                                       d shows details, Enter does nothing;
                                       a dangerous card is allowed only by typing allow in full
  wardenctl status                     server, device, %sconnection, clock
%s  wardenctl forget [--yes]             delete the server and the device key
  wardenctl version

Global flags: --dir state directory (default: $WARDENCTL_DIR or ~/.config/wardenctl),
              --json for pending, show, approve, and deny.
A card id can be shortened to a unique prefix (6+ characters, "wd-" is optional).

wardenctl <command> --help (or wardenctl help <command>) prints the flags of a command and does nothing else.
`, approve, watchFlags, statusYubiKey, hwCommands)
}

// hwText: the text for a build with YubiKey (hwkey tag) or without it (release, docs/hwkey.md).
func hwText(on, off string) string {
	if feature.HWKey {
		return on
	}
	return off
}

// hwOnlyFlags: the YubiKey flags of approve and watch. Without the hwkey tag they do not exist,
// and instead of "flag provided but not defined" the user learns that this release has no second
// factor.
var hwOnlyFlags = map[string]bool{"hw": true, "no-hw": true, "uv": true, "device": true}

// cmdHelp: usage and purpose of each command for wardenctl <command> --help.
var cmdHelp = map[string][2]string{
	"pair":        {"pair '<wardenclaw://pair?…>' [flags]", "Pairs this terminal with wardend using the link printed by wardend pair start (in quotes)."},
	"pending":     {"pending [--json]", "Lists the cards waiting for a decision."},
	"show":        {"show <id> [--json]", "Prints one card in full: argv, cwd, exe, uid, process chain, rule, risk."},
	"approve":     {hwText("approve <id> [--no-hw] [--uv] [--device d] [--yes] [--json]", "approve <id> [--yes] [--json]"), "Shows the card and asks, then signs an allow decision " + hwText("with a YubiKey touch (--no-hw: without one, if wardend does not require it)", "with the device key") + ". A dangerous card is allowed only by typing allow in full. Without a terminal, or with --yes, nothing is asked and the id needs at least 12 characters."},
	"deny":        {"deny <id> [--json]", "Signs a deny decision for a card."},
	"watch":       {hwText("watch [--no-hw] [--uv] [--device d]", "watch"), "Shows new cards one at a time: y allows (" + hwText("with a YubiKey touch unless --no-hw", "signed with the device key") + "), n denies, d shows details, Enter does nothing. A dangerous card is allowed only by typing allow in full."},
	"status":      {"status", "Server, device, " + hwText("YubiKey, ", "") + "connection and clock skew."},
	"hw-register": {"hw-register [flags]", "Binds a YubiKey over USB and prints the wardend hw-register command to run on the server."},
	"hw-check":    {"hw-check [--device d] [--uv]", "Checks the bound YubiKey."},
	"forget":      {"forget [--yes]", "Deletes the server and the device key from the state directory."},
	"version":     {"version", "Prints the version of this binary."},
}

func isHelpArg(s string) bool { return s == "help" || s == "-h" || s == "-help" || s == "--help" }

// cmdSpec: what the common parsing checks before a command.
type cmdSpec struct {
	guarded bool // guard: refuse next to the agent, code 3
	json    bool // the command supports --json
	maxArgs int  // at most this many positional arguments
}

// parseCmd: flags and positional arguments of a command (flags also after them: approve <id> --hw).
// --help, -h, -help or help instead of arguments print the command help to stdout with code 0
// before anything else: no guard, no state, no network. The "this is help" decision is made by the
// same parsing as the command itself, so guard cannot be bypassed with -h as a flag value (in
// --device -h it is a value, not help). Then: a command line error (code 2), --json for a command
// without it (code 2), guard (code 3). ok=false: exit with code.
func (a *app) parseCmd(fs *flag.FlagSet, args []string, spec cmdSpec) (pos []string, code int, ok bool) {
	fs.SetOutput(io.Discard) // we print help and errors ourselves, each to its own stream
	fs.Usage = func() {}
	pos, err := parseArgs(fs, args)
	switch {
	case errors.Is(err, flag.ErrHelp), err == nil && len(pos) > 0 && pos[0] == "help":
		a.cmdUsage(a.stdout, fs)
		return nil, 0, false
	case err == nil && len(pos) > spec.maxArgs:
		err = fmt.Errorf("unexpected argument %q", pos[spec.maxArgs])
	case err != nil && !feature.HWKey:
		if f, ok := strings.CutPrefix(err.Error(), "flag provided but not defined: -"); ok && hwOnlyFlags[f] {
			fmt.Fprintf(a.stderr, "wardenctl %s: --%s: %s; the decision is signed with the device key, remove the flag\n", fs.Name(), f, feature.HWKeyOff)
			return nil, exitUsage, false
		}
	}
	if err != nil {
		fmt.Fprintf(a.stderr, "wardenctl %s: %v\n\n", fs.Name(), err)
		a.cmdUsage(a.stderr, fs)
		return nil, exitUsage, false
	}
	if a.json && !spec.json {
		fmt.Fprintf(a.stderr, "wardenctl: --json is only supported by pending, show, approve, and deny\n")
		return nil, exitUsage, false
	}
	if spec.guarded && !a.checkGuard() {
		return nil, exitGuard, false
	}
	return pos, 0, true
}

func (a *app) cmdUsage(w io.Writer, fs *flag.FlagSet) {
	h := cmdHelp[fs.Name()]
	fmt.Fprintf(w, "usage: wardenctl %s\n\n%s\n\nflags:\n", h[0], h[1])
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(io.Discard)
}

// extractJSONFlag makes --json a true global flag: it can appear before or after the command.
func extractJSONFlag(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	jsonMode := false
	for _, arg := range args {
		if arg == "--json" {
			jsonMode = true
			continue
		}
		out = append(out, arg)
	}
	return out, jsonMode
}

func (a *app) writeJSON(v any) int {
	enc := json.NewEncoder(a.stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return a.errf("write JSON: %v", err)
	}
	return 0
}

// parseArgs: flags before and after positional arguments (approve <id> --hw).
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// flags: the flag set of a command with the common --dir; parseCmd decides where it prints.
func (a *app) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&a.dir, "dir", a.dir, "wardenctl state directory")
	return fs
}

func (a *app) errf(format string, v ...any) int {
	fmt.Fprintf(a.stderr, "wardenctl: "+format+"\n", v...)
	return 1
}

// codeFor: the exit code for an error: exitProtocol for ProtocolError, otherwise 1.
func codeFor(err error) int {
	var pe *ProtocolError
	if errors.As(err, &pe) {
		return exitProtocol
	}
	return 1
}

func (a *app) checkGuard() bool {
	var v guardVerdict
	if a.guard != nil {
		v = a.guard()
	} else {
		v = evalGuard(defaultGuardProbe())
	}
	if v.Refuse {
		fmt.Fprint(a.stderr, guardMessage(v))
		return false
	}
	if v.Override {
		fmt.Fprintf(a.stderr, "wardenctl: WARNING: wardend is running nearby (%s); WARDENCTL_ALLOW_SAME_HOST=1: the device key is readable by the agent.\n", strings.Join(v.Reasons, "; "))
	}
	return true
}

func (a *app) run(ctx context.Context, args []string) int {
	args, a.json = extractJSONFlag(args)
	// global --dir before the command
	for len(args) >= 2 && (args[0] == "--dir" || args[0] == "-dir") {
		a.dir, args = args[1], args[2:]
	}
	if len(args) == 0 {
		a.usage(a.stderr)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	if isHelpArg(cmd) { // wardenctl help [<command>]
		if len(rest) == 0 || isHelpArg(rest[0]) {
			a.usage(a.stdout)
			return 0
		}
		cmd, rest = rest[0], []string{"--help"}
	}
	// Each command parses its arguments first (parseCmd): help, command line errors and --json
	// answer before guard; guard (refuse next to the agent, code 3) is checked before any action.
	switch cmd {
	case "version", "--version":
		return a.cmdVersion(rest)
	case "forget":
		return a.cmdForget(rest)
	case "pair":
		return a.cmdPair(ctx, rest)
	case "pending":
		return a.cmdPending(ctx, rest)
	case "show":
		return a.cmdShow(ctx, rest)
	case "approve":
		return a.cmdDecide(ctx, "allow", rest)
	case "deny":
		return a.cmdDecide(ctx, "deny", rest)
	case "watch":
		return a.cmdWatch(ctx, rest)
	case "status":
		return a.cmdStatus(ctx, rest)
	case "hw-register":
		return a.cmdHWRegister(rest)
	case "hw-check":
		return a.cmdHWCheck(rest)
	}
	fmt.Fprintf(a.stderr, "wardenctl: unknown command %q\n\n", cmd)
	a.usage(a.stderr)
	return exitUsage
}

func (a *app) cmdVersion(args []string) int {
	if _, code, ok := a.parseCmd(a.flags("version"), args, cmdSpec{}); !ok {
		return code
	}
	fmt.Fprintf(a.stdout, "wardenctl %s\n", version)
	return 0
}
