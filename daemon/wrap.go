// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardend wrap -- <cmd...>: the one-command way to try wardend. It is wardend run with defaults
// (ticket mode, the built-in policy, state in ~/.wardend, the default relay) plus what a person at
// a terminal needs: when no device is trusted yet, the phone is paired before the command starts;
// while the command runs wardend only speaks about cards that wait, are denied or expire; at the
// exit it prints a summary.
//
// The command runs as the same user as wardend: it cannot get past the exec gate, but it can read
// wardend's files and edit its config between runs. The system install is the one with a boundary.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	wrapRelayWait  = 10 * time.Second // how long wrap waits for the relay before it gives up
	wrapWaitNotice = 5 * time.Second  // a card unanswered this long is mentioned on the terminal
	wrapArgvMax    = 80               // characters of a command line in a notice
)

// wrapOpts: what wardend wrap adds to a run.
type wrapOpts struct {
	qr        string           // QR style of the pairing step (wardend pair start --qr)
	openTerm  func() *pairTerm // the terminal of the pairing question; nil result: none
	relayWait time.Duration
	cfgMode   string // the config file that chose a mode other than ticket; "": the flag or the default did
}

func cmdWrap(args []string) int {
	cfg, o, code, ok := wrapSetup(args, os.Stdout, os.Stderr)
	if !ok {
		return code
	}
	return runCommand(cfg, o)
}

// wrapSetup: the config and options of wardend wrap from its command line: the config file of the
// state directory if there is one, the defaults of wrap where it is silent, the flags on top.
func wrapSetup(args []string, stdout, stderr io.Writer) (cfg *Config, o *runOpts, code int, ok bool) {
	fs := newCmdFlags("wrap", "wrap [flags] -- <cmd...>",
		"Runs <cmd...> with every exec in its process tree gated, and asks your phone before the risky ones.\n"+
			"No flags are needed: ticket mode, the built-in policy, state in ~/.wardend. The first run pairs\n"+
			"the phone (QR, then a y/N question) before the command starts. The exit code is the command's.\n"+
			"The command runs as you, like wardend itself: it cannot bypass the gate, but it can read wardend's\n"+
			"files and edit its config between runs. The system install separates the two.", stdout, stderr)
	mode := fs.String("mode", "", "ticket (default) | deny-list | observe")
	pol := fs.String("policy", "", "rules JSON (default: built-in)")
	ttl := fs.Duration("ttl", 0, "how long a command waits for the decision (default 120s)")
	stateDir := fs.String("state-dir", "", "state directory (~/.wardend)")
	relayURL := fs.String("relay-url", "", "relay the app reaches wardend through (wss://relay.wardenclaw.dev)")
	qrMode := fs.String("qr", "ansi", "QR of the pairing step: ansi | utf8 | invert | none")
	quiet := fs.Bool("quiet", false, "no summary at the exit")
	if code, ok := fs.parse(args); !ok {
		return nil, nil, code, false
	}
	switch {
	case fs.NArg() == 0:
		return nil, nil, fs.fail("missing command after --"), false
	case fs.NArg() == 1 && fs.Arg(0) == "help" && !afterDoubleDash(args, 1):
		fs.printUsage(stdout)
		return nil, nil, 0, false
	}
	cfg, err := loadConfig(configPath("", *stateDir))
	if err != nil {
		fmt.Fprintln(stderr, "wardend:", err)
		return nil, nil, 2, false
	}
	cfgMode := ""
	if cfg.Mode == "" {
		cfg.Mode = "ticket"
	} else if cfg.Mode != "ticket" && *mode == "" {
		cfgMode = cfg.path
	}
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&cfg.Mode, *mode)
	set(&cfg.Policy, *pol)
	set(&cfg.StateDir, *stateDir)
	set(&cfg.RelayURL, *relayURL)
	if *ttl > 0 {
		cfg.TicketTTL.Duration = *ttl
	}
	return cfg, &runOpts{cmd: fs.Args(), quiet: *quiet, wrap: &wrapOpts{qr: *qrMode, openTerm: openPairTerm, relayWait: wrapRelayWait, cfgMode: cfgMode}}, 0, true
}

// wrapPrepare makes sure a decision can arrive before the command starts: the relay is reachable
// and a device is trusted. Without a device it pairs one on the terminal. An error means the
// command is not started.
func (s *supervisor) wrapPrepare(w *wrapOpts, cmd []string) error {
	if s.cfg.Mode != "ticket" { // nothing is asked in observe and deny-list
		if w.cfgMode != "" {
			// not what wrap does by default: the owner must not take a silent run for an approved one
			s.logf("wardend: mode %s (from %s): nothing is asked on the phone. To be asked: wardend wrap --mode ticket\n", s.cfg.Mode, w.cfgMode)
		}
		return nil
	}
	paired := len(s.devices.List()) > 0
	if s.relay == nil {
		switch {
		case s.relayErr != "":
			return fmt.Errorf("the relay link did not start (%s): no card would reach a device, %s was not started", s.relayErr, cmd[0])
		case paired:
			return nil // relay_url off by choice: decisions come over the socket (wardend approve)
		}
		return fmt.Errorf("relay_url is off and no device is trusted: nothing could approve a command, %s was not started. "+
			"--relay-url off is not a way to get approvals; drop it to pair a phone, or use --mode observe to only watch", cmd[0])
	}
	for end := time.Now().Add(w.relayWait); !s.relay.connected(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(end) {
			return fmt.Errorf("cannot reach the relay %s: no card would reach a device, %s was not started. "+
				"Check the network; --relay-url off is not a way to get approvals", s.cfg.RelayURL, cmd[0])
		}
	}
	if paired {
		return nil
	}
	term := w.openTerm()
	if term == nil {
		return errors.New("no device is paired, and there is no terminal to pair one on. Pair first: run wardend wrap once " +
			"from a terminal, or wardend pair start against a running wardend")
	}
	if term.close != nil {
		defer term.close()
	}
	c, err := dialClient(s.cfg.Socket)
	if err != nil {
		return err
	}
	defer c.Close()
	fmt.Fprintf(term.out, "wardend: no device is paired yet. Pair your phone; %s starts after that.\n\n", cmd[0])
	if pairStartCmd(c, 0, w.qr, true, term, term.out, term.out) != 0 {
		return fmt.Errorf("no device was paired: %s was not started", cmd[0])
	}
	fmt.Fprintln(term.out)
	return nil
}

// noteWaiting tells the terminal of wardend wrap that a card for argv has no answer yet; the
// returned func is called when the wait is over.
func (s *supervisor) noteWaiting(argv []string) (done func()) {
	if !s.wrap {
		return func() {}
	}
	t := time.AfterFunc(wrapWaitNotice, func() {
		s.logf("wardend: waiting for your decision on the phone: %s\n", shortArgv(argv))
	})
	return func() { t.Stop() }
}

// noteDecision tells the terminal of wardend wrap about a command that was not allowed.
func (s *supervisor) noteDecision(argv []string, res ticketResult, expired bool) {
	switch {
	case !s.wrap || res.Allow:
	case expired:
		s.logf("wardend: expired, no decision in %s: %s\n", s.cfg.TicketTTL.Duration, shortArgv(argv))
	case res.Body != nil:
		s.logf("wardend: denied on the phone: %s\n", shortArgv(argv))
	default:
		s.logf("wardend: denied (%s): %s\n", res.Reason, shortArgv(argv))
	}
}

// shortArgv is a command line for one line of a terminal.
func shortArgv(argv []string) string {
	s := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.Join(argv, " "))
	if r := []rune(s); len(r) > wrapArgvMax {
		s = string(r[:wrapArgvMax]) + "…"
	}
	return s
}

// wrapSummary is the last line of wardend wrap: what was seen and asked, and where the record is.
func (s *supervisor) wrapSummary(w io.Writer) {
	ok, no, ttl := s.m.ticketsOK.Load(), s.m.ticketsDenied.Load(), s.m.ticketsTTL.Load()
	// not commands of their own: the PATH search of a shell (a file that is not there) and its
	// retries of a denied command along PATH
	noise := s.m.denyRepeats.Load()
	if n, found := s.m.byClass.Load("missing"); found {
		noise += n.(*atomic.Int64).Load()
	}
	line := fmt.Sprintf("wardend: %d commands seen, %d asked: %d allowed, %d denied, %d expired", s.m.execs.Load()-noise, ok+no+ttl, ok, no, ttl)
	if other := s.m.denied.Load() - no - ttl - noise; other > 0 {
		line += fmt.Sprintf("; %d blocked without a card", other)
	}
	fmt.Fprintf(w, "%s. Journal: %s\n", line, s.cfg.Journal)
}
