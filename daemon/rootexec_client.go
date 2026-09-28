// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// `wardend rootexec -- <cmd...>`: the client side of rootexec.go, run by the agent from under the
// gate. It hands wardend the command, its working directory and its own stdin/stdout/stderr, then
// waits: for the card to be decided on the phone and for the command to finish. The command's
// output goes to those descriptors directly; this process only relays signals and the exit code.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// rootExecSocketEnv names the socket for the client; the agent cannot read /etc/wardend/config.json.
const rootExecSocketEnv = "WARDEND_ROOTEXEC_SOCKET"

func cmdRootExec(args []string, stdout, stderr io.Writer) int {
	fs := newCmdFlags("rootexec", "rootexec [--socket s] [--cwd d] [--quiet] -- <cmd...>",
		"From under the gate: asks wardend to run <cmd...> as its own user (root in the hardened install).\n"+
			"The policy (root_exec) decides whether the command may be asked for, the phone decides whether it runs;\n"+
			"it runs with this process's stdin/stdout/stderr and cwd. Exit code: the command's own, or\n"+
			"124 (card expired / timeout), 125 (refused: policy, mode, guard, socket), 126 (denied on the phone).", stdout, stderr)
	sock := fs.String("socket", "", "rootexec socket (default $"+rootExecSocketEnv+", else "+rootExecSocketRoot+")")
	cwd := fs.String("cwd", "", "working directory of the command (default: the current one)")
	quiet := fs.Bool("quiet", false, "no progress lines on stderr")
	if code, ok := fs.parse(args); !ok {
		return code
	}
	switch {
	case fs.NArg() == 0:
		return fs.fail("missing command after --")
	case fs.NArg() == 1 && fs.Arg(0) == "help" && !afterDoubleDash(args, 1):
		fs.printUsage(stdout)
		return 0
	}
	path := *sock
	if path == "" {
		path = os.Getenv(rootExecSocketEnv)
	}
	if path == "" {
		path = rootExecSocketRoot
	}
	dir := *cwd
	if dir == "" {
		var err error
		if dir, err = os.Getwd(); err != nil {
			fmt.Fprintln(stderr, "wardend rootexec: getwd:", err)
			return rootExecExitRefused
		}
	}
	code, err := rootExecClient(path, fs.Args(), dir, os.Getenv("TERM"), *quiet, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "wardend rootexec:", err)
	}
	return code
}

// The shims: this binary invoked as `sudo` or `docker` (symlinks on the agent's PATH, installed
// with --root-exec). Under the gate they are `wardend rootexec` with the familiar spelling: `sudo
// docker restart x`, `docker ps`. Outside the gate (a human whose PATH also has them) they exec the
// real program unchanged; WARDEND_<NAME>_REAL overrides its path.
const shimRealEnvPrefix = "WARDEND_"

var shimRealDefault = map[string]string{"sudo": "/usr/bin/sudo", "docker": "/usr/bin/docker"}

func cmdShim(name string, args []string, stdout, stderr io.Writer) int {
	if !selfUnderSeccompFilter() {
		real := os.Getenv(shimRealEnvPrefix + strings.ToUpper(name) + "_REAL")
		if real == "" {
			real = shimRealDefault[name]
		}
		if st, err := os.Stat(real); err != nil || st.Mode()&0o111 == 0 {
			fmt.Fprintf(stderr, "%s: this is wardend's %s shim for the agent; outside the gate it hands over to %s, which is not there\n", name, name, real)
			return 1
		}
		err := syscall.Exec(real, append([]string{name}, args...), os.Environ())
		fmt.Fprintf(stderr, "%s: exec %s: %v\n", name, real, err)
		return 1
	}
	var cmd []string
	if name == "sudo" {
		var code int
		var done bool
		if cmd, code, done = sudoShimArgs(args, stdout, stderr); done {
			return code
		}
	} else {
		cmd = append([]string{name}, args...)
	}
	sock := os.Getenv(rootExecSocketEnv)
	if sock == "" {
		sock = rootExecSocketRoot
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, "sudo: getwd:", err)
		return rootExecExitRefused
	}
	code, err := rootExecClient(sock, cmd, cwd, os.Getenv("TERM"), false, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%s (wardend rootexec): %v\n", name, err)
	}
	return code
}

// sudoShimArgs: sudo's options up to the command. done=true: answered already (help, version,
// -l, or a refusal), code is the exit code. What sudo can do and rootexec does not: shells (-i,
// -s), other users (-u), the caller's environment (-E, VAR=value), a password prompt; those are
// refused with a message (exit 125), never silently changed into something else.
func sudoShimArgs(args []string, stdout, stderr io.Writer) (cmd []string, code int, done bool) {
	refuse := func(what string) ([]string, int, bool) {
		fmt.Fprintf(stderr, "sudo (wardend rootexec): %s. Name the command: sudo <program> <args>; it runs as root after a card on the phone, with a clean environment and no shell.\n", what)
		return nil, rootExecExitRefused, true
	}
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !strings.HasPrefix(a, "-") {
			if strings.Contains(a, "=") && !strings.ContainsAny(a[:strings.Index(a, "=")], "/ ") {
				return refuse("VAR=value is not passed to the command (" + a + ")")
			}
			break
		}
		switch {
		case a == "-h" || a == "--help":
			fmt.Fprintln(stdout, "sudo: wardend's sudo shim for the agent. `sudo <command...>` asks wardend to run the command as root after a card on the phone (wardend rootexec). Options accepted: -n -H -k -K -S -A -p PROMPT -u root -- ; refused: -i -s -E -g -u <other>, VAR=value. Exit 124 expired/timeout, 125 refused, 126 denied.")
			return nil, 0, true
		case a == "-V" || a == "--version":
			fmt.Fprintf(stdout, "sudo shim of wardend %s (wardend rootexec)\n", version)
			return nil, 0, true
		case a == "-l" || a == "--list" || a == "-ll":
			fmt.Fprintln(stdout, "sudo shim of wardend: no sudoers rights. A command runs as root only after a card on the phone and only if the policy's root_exec list names it (wardend rootexec).")
			return nil, 0, true
		case a == "-v" || a == "--validate":
			return nil, 0, true
		case a == "-n" || a == "--non-interactive" || a == "-H" || a == "--set-home" || a == "-k" || a == "--reset-timestamp" ||
			a == "-K" || a == "--remove-timestamp" || a == "-S" || a == "--stdin" || a == "-A" || a == "--askpass" || a == "-b" || a == "--background":
			i++
		case a == "-p" || a == "--prompt" || a == "-C" || a == "--close-from":
			i += 2
		case strings.HasPrefix(a, "--prompt=") || strings.HasPrefix(a, "--close-from="):
			i++
		case a == "-D" || a == "--chdir" || strings.HasPrefix(a, "--chdir="):
			return refuse(a + ": the command runs in the current directory, cd first")
		case a == "-u" || a == "--user":
			if i+1 >= len(args) {
				return refuse("-u needs a user")
			}
			if u := args[i+1]; u != "root" && u != "0" && u != "#0" {
				return refuse("-u " + u + ": only root; the command always runs as wardend's user")
			}
			i += 2
		case strings.HasPrefix(a, "--user="):
			if u := strings.TrimPrefix(a, "--user="); u != "root" && u != "0" && u != "#0" {
				return refuse("--user=" + u + ": only root")
			}
			i++
		case a == "-i" || a == "--login" || a == "-s" || a == "--shell":
			return refuse(a + ": no shell as root")
		case a == "-E" || a == "--preserve-env" || strings.HasPrefix(a, "--preserve-env="):
			return refuse(a + ": the environment is not passed to the command")
		case a == "-g" || a == "--group" || strings.HasPrefix(a, "--group="):
			return refuse(a + ": no other group")
		case a == "-e" || a == "--edit":
			return refuse(a + ": no sudoedit")
		default:
			return refuse("option " + a + " is not supported")
		}
	}
	cmd = args[i:]
	if len(cmd) == 0 {
		return refuse("no command")
	}
	return cmd, 0, false
}

// rootExecClient sends the request with this process's descriptors 0, 1, 2 and follows the events.
func rootExecClient(sockPath string, argv []string, cwd, term string, quiet bool, stderr io.Writer) (int, error) {
	addr := &net.UnixAddr{Name: sockPath, Net: "unix"}
	c, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return rootExecExitRefused, fmt.Errorf("%s: %v (rootexec is off, or this wardend has no root_exec socket for your user)", sockPath, err)
	}
	defer c.Close()
	line, _ := json.Marshal(rootExecRequest{V: 1, Argv: argv, Cwd: cwd, Term: term})
	line = append(line, '\n')
	if _, _, err := c.WriteMsgUnix(line, unix.UnixRights(0, 1, 2), nil); err != nil {
		return rootExecExitRefused, fmt.Errorf("send: %v", err)
	}
	// Signals to this process go to the command (its process group) through wardend.
	sigc := make(chan os.Signal, 8)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH)
	defer signal.Stop(sigc)
	go func() {
		for sig := range sigc {
			if n, ok := sig.(syscall.Signal); ok {
				b, _ := json.Marshal(map[string]any{"event": "signal", "signal": int(n)})
				_, _ = c.Write(append(b, '\n'))
			}
		}
	}()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		var ev rootExecEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		switch ev.Event {
		case "card":
			if !quiet {
				left := time.Until(time.UnixMilli(ev.ExpiresAt)).Round(time.Second)
				fmt.Fprintf(stderr, "wardend rootexec: card %s is on the phone, waiting for the decision (expires in %s)\n", ev.ID, left)
			}
		case "refused":
			return rootExecExitRefused, fmt.Errorf("refused: %s", ev.Reason)
		case "denied":
			if strings.HasPrefix(ev.Reason, "ttl expired") {
				return rootExecExitTTL, fmt.Errorf("card %s expired without a decision", ev.ID)
			}
			return rootExecExitDenied, fmt.Errorf("denied: %s", ev.Reason)
		case "started":
			if !quiet {
				fmt.Fprintf(stderr, "wardend rootexec: approved, running (pid %d)\n", ev.Pid)
			}
		case "done":
			if ev.TimedOut {
				if !quiet {
					fmt.Fprintf(stderr, "wardend rootexec: the command hit wardend's timeout and was killed\n")
				}
				return rootExecExitTTL, nil
			}
			return ev.Exit, nil
		}
	}
	if err := sc.Err(); err != nil {
		return rootExecExitRefused, fmt.Errorf("connection: %v", err)
	}
	return rootExecExitRefused, fmt.Errorf("wardend closed the connection without a result")
}
