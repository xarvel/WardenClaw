// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardend pair: pairs the WardenClaw app with the running supervisor (over the unix socket).
//
//	wardend pair start [--ttl 5m] [--qr ansi|utf8|invert|none] [--no-wait]
//	wardend pair list
//	wardend pair approve <id> | reject <id>
//	wardend pair revoke <deviceId|prefix>

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/qr"
)

const pairUsage = `usage: wardend pair start [--socket s] [--ttl 5m] [--qr ansi|utf8|invert|none] [--no-wait]
       wardend pair list [--socket s]
       wardend pair approve <id> [--socket s]
       wardend pair reject <id> [--socket s]
       wardend pair revoke <deviceId|prefix> [--socket s]
`

// pairSubs: pair subcommands: usage, purpose, number of positional arguments.
var pairSubs = map[string]struct {
	use, about string
	nargs      int
}{
	"start":   {"pair start [flags]", "Prints a one-time pairing code and QR for the WardenClaw app (or wardenctl pair), waits for the request,\nshows the device's name and key fingerprint and asks whether to approve it. Without a terminal it\nprints the request id for wardend pair approve instead of asking.", 0},
	"list":    {"pair list [--socket s]", "Pending pairing requests (key fingerprints) and trusted devices.", 0},
	"approve": {"pair approve <id> [--socket s]", "Trusts the device of a pairing request: compare its fingerprint with the phone first.\nWrites trusted_devices into the config; the supervisor trusts the device at once.", 1},
	"reject":  {"pair reject <id> [--socket s]", "Rejects a pairing request.", 1},
	"revoke":  {"pair revoke <deviceId|prefix> [--socket s]", "Stops trusting a device and removes it from trusted_devices.", 1},
}

func cmdPair(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, pairUsage)
		return 2
	}
	sub, rest := args[0], args[1:]
	if isHelpArg(sub) {
		fmt.Fprint(stdout, pairUsage+"\nPairs the WardenClaw app with the running wardend over its socket. Run it from your own\n"+
			"terminal on the server, not from the agent's shell. wardend pair <subcommand> --help lists its flags.\n")
		return 0
	}
	spec, known := pairSubs[sub]
	if !known {
		fmt.Fprintf(stderr, "wardend pair: unknown subcommand %q\n\n%s", sub, pairUsage)
		return 2
	}
	fs := newCmdFlags("pair "+sub, spec.use, spec.about, stdout, stderr)
	sock := socketFlag(fs.FlagSet)
	var qrMode *string
	var ttl *time.Duration
	var noWait *bool
	if sub == "start" {
		ttl = fs.Duration("ttl", 0, "code lifetime (default: pair_code_ttl, 5m)")
		qrMode = fs.String("qr", "ansi", "ansi (black on white via terminal colors) | utf8 (no color, light background) | invert (no color, dark background) | none")
		noWait = fs.Bool("no-wait", false, "print the code and return: do not wait for the request or ask to approve it")
	}
	// flags may also follow the id: wardend pair approve p-xxxx --socket …; help, an unknown
	// subcommand and a wrong argument count are answered before connecting to the socket
	pos, code, ok := fs.parseArgs(rest, spec.nargs, spec.nargs)
	if !ok {
		return code
	}
	c, ok := dialSupervisor(clientSocket(*sock), stderr)
	if !ok {
		return 1
	}
	defer c.Close()
	switch sub {
	case "start":
		var term *pairTerm
		if !*noWait {
			if term = openPairTerm(); term != nil {
				defer term.close()
			}
		}
		return pairStartCmd(c, *ttl, *qrMode, !*noWait, term, stdout, stderr)
	case "list":
		var r pairListResult
		if err := c.call("pair.list", map[string]any{}, &r); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		printPairList(stdout, &r)
		return 0
	case "approve", "reject":
		var r struct {
			Request pairReq `json:"request"`
			Config  string  `json:"config"`
		}
		if err := c.call("pair."+sub, map[string]any{"id": pos[0]}, &r); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		printPairDecision(stdout, sub, r.Request, r.Config)
		return 0
	case "revoke":
		var r struct {
			DeviceID string `json:"deviceId"`
			Name     string `json:"name"`
			Config   string `json:"config"`
		}
		if err := c.call("pair.revoke", map[string]any{"device": pos[0]}, &r); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "Device %s (\"%s\") is no longer trusted; removed from %s.\n", r.DeviceID, r.Name, r.Config)
		return 0
	}
	return 2 // unreachable: the subcommand was checked against pairSubs
}

type pairListResult struct {
	Requests []pairReq `json:"requests"`
	Devices  []struct {
		ID          string `json:"id"`
		Alg         string `json:"alg"`
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint"`
		AddedAt     string `json:"addedAt"`
		HasPubkey   bool   `json:"hasPubkey"`
		Valid       bool   `json:"valid"`
	} `json:"devices"`
	ActiveCodes int            `json:"activeCodes"`
	Relay       map[string]any `json:"relay"`
	Config      string         `json:"config"`
}

func printPairList(w io.Writer, r *pairListResult) {
	pending := 0
	for _, q := range r.Requests {
		if q.Status == "pending" {
			pending++
		}
	}
	fmt.Fprintf(w, "Pairing requests: %d pending, active codes: %d\n", pending, r.ActiveCodes)
	for _, q := range r.Requests {
		left := time.Until(time.UnixMilli(q.ExpiresAt)).Round(time.Second)
		extra := ""
		if q.Status == "pending" {
			extra = fmt.Sprintf(", expires in %s", left)
		}
		fmt.Fprintf(w, "  %-9s %-8s \"%s\"  fingerprint %s  key %s  from %s%s\n", q.ID, q.Status, q.Name, q.Fingerprint, orDash(q.Alg), q.Remote, extra)
	}
	if pending > 0 {
		fmt.Fprintln(w, "  Compare the fingerprint with the phone screen: wardend pair approve <id> (or reject <id>)")
	}
	fmt.Fprintf(w, "Trusted devices (%s): %d\n", r.Config, len(r.Devices))
	for _, d := range r.Devices {
		note := ""
		switch {
		case !d.Valid:
			note = "  [not a deviceId: entry ignored]"
		case !d.HasPubkey:
			note = "  [no pubkey: key only from the gateway DB, gateway_db]"
		}
		fmt.Fprintf(w, "  %s  \"%s\"  %s  key %s  added %s%s\n", d.Fingerprint, d.Name, d.ID, orDash(d.Alg), orDash(d.AddedAt), note)
	}
	if up, _ := r.Relay["connected"].(bool); !up {
		fmt.Fprintf(w, "Not connected to the relay %v: devices cannot reach this wardend (wardend status)\n", r.Relay["url"])
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// printPairDecision tells the owner what pair approve or pair reject did.
func printPairDecision(w io.Writer, sub string, q pairReq, config string) {
	if sub == "approve" {
		fmt.Fprintf(w, "Approved: \"%s\", fingerprint %s, deviceId %s\nWritten to %s (trusted_devices); the supervisor trusts the device right away.\n", q.Name, q.Fingerprint, q.DeviceID, config)
	} else {
		fmt.Fprintf(w, "Rejected: %s (\"%s\", %s)\n", q.ID, q.Name, q.Fingerprint)
	}
}

// pairTerm is the terminal the owner answers "Approve this device?" on: the controlling terminal
// (openPairTerm), not stdin, which under wardend wrap belongs to the wrapped command.
type pairTerm struct {
	in      io.Reader
	out     io.Writer
	timeout time.Duration // how long to wait for the answer; 0: until the request expires
	close   func()
}

// openPairTerm opens the controlling terminal; nil when stdin is not a terminal (a script, a
// pipe, a service) or there is no terminal to open.
func openPairTerm() *pairTerm {
	if _, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS); err != nil {
		return nil
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil
	}
	return &pairTerm{in: f, out: f, close: func() { f.Close() }}
}

// answer reads one line from the terminal, byte by byte: nothing typed after it is taken away
// from whoever reads the terminal next. ok=false: no answer within d, or the terminal closed.
func (t *pairTerm) answer(d time.Duration) (line string, ok bool) {
	got := make(chan string, 1)
	go func() {
		var b []byte
		one := make([]byte, 1)
		for {
			n, err := t.in.Read(one)
			if n == 1 && one[0] == '\n' {
				got <- string(b)
				return
			}
			if n == 1 {
				b = append(b, one[0])
			}
			if err != nil {
				close(got)
				return
			}
		}
	}()
	select {
	case line, ok = <-got:
		return strings.TrimSpace(line), ok
	case <-time.After(d):
		return "", false
	}
}

// pairStartCmd is wardend pair start, and the pairing step of wardend wrap: the code and the QR,
// then (wait) the request, then (term) the question. 0: the device is trusted, or without a
// terminal the request arrived and the owner was told how to approve it.
func pairStartCmd(c *rpcClient, ttl time.Duration, qrMode string, wait bool, term *pairTerm, stdout, stderr io.Writer) int {
	var r struct {
		Code                  string `json:"codeDisplay"`
		ExpiresAt             int64  `json:"expiresAt"`
		Relay                 string `json:"relay"`
		Link                  string `json:"link"`
		SupervisorKey         string `json:"supervisorKey"`
		SupervisorFingerprint string `json:"supervisorFingerprint"`
		Host                  string `json:"host"`
	}
	if err := c.call("pair.start", map[string]any{"ttl": ttl.Milliseconds()}, &r); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	printQR(stdout, stderr, r.Link, qrMode)
	exp := time.UnixMilli(r.ExpiresAt)
	fmt.Fprintf(stdout, "\nScan the QR in the WardenClaw app (Connect tab) or paste the link:\n  %s\n\n", r.Link)
	fmt.Fprintf(stdout, "Code:       %s (one-time, until %s)\n", r.Code, exp.Format("15:04:05"))
	fmt.Fprintf(stdout, "Relay:      %s\n", r.Relay)
	fmt.Fprintf(stdout, "Supervisor: %s, key fingerprint %s\n", r.Host, r.SupervisorFingerprint)
	if !wait {
		fmt.Fprintln(stdout, "Then: wardend pair list → wardend pair approve <id>")
		return 0
	}
	return waitPairRequest(c, exp, term, stdout, stderr)
}

// printQR prints the pairing link as a QR code in the --qr style; "none" prints nothing.
func printQR(stdout, stderr io.Writer, link, mode string) {
	if mode == "none" {
		return
	}
	code, err := qr.Encode([]byte(link))
	if err != nil {
		fmt.Fprintln(stderr, "QR:", err)
		return
	}
	switch mode {
	case "utf8":
		fmt.Fprint(stdout, code.UTF8())
	case "invert":
		fmt.Fprint(stdout, code.UTF8Inverted())
	default:
		fmt.Fprint(stdout, code.ANSI())
	}
}

const (
	pairPollInterval = time.Second
	pairWaitGrace    = 2 * time.Second // a request may land just as the code expires
)

// waitPairRequest polls pair.list until a request newer than the ones already listed arrives or
// the code expires, then asks the owner on term, or without one tells them the next step.
func waitPairRequest(c *rpcClient, exp time.Time, term *pairTerm, stdout, stderr io.Writer) int {
	fmt.Fprintln(stdout, "\nWaiting for the request from the phone (Ctrl+C to stop waiting; then wardend pair list)…")
	seen := map[string]bool{}
	var first pairListResult
	if err := c.call("pair.list", map[string]any{}, &first); err == nil {
		for _, q := range first.Requests {
			seen[q.ID] = true
		}
	}
	for time.Now().Before(exp.Add(pairWaitGrace)) {
		time.Sleep(pairPollInterval)
		var l pairListResult
		if err := c.call("pair.list", map[string]any{}, &l); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		for _, q := range l.Requests {
			if seen[q.ID] {
				continue
			}
			fmt.Fprintf(stdout, "\nRequest %s: \"%s\", fingerprint %s, from %s\n", q.ID, q.Name, q.Fingerprint, q.Remote)
			switch {
			case q.Status == "approved":
				fmt.Fprintln(stdout, "This device is already trusted: no approval needed.")
			case term == nil:
				fmt.Fprintf(stdout, "Compare the fingerprint with the phone screen and approve:\n  wardend pair approve %s\n", q.ID)
			default:
				return askPairApprove(c, q, term, stdout, stderr)
			}
			return 0
		}
	}
	fmt.Fprintln(stdout, "The code expired with no requests. New one: wardend pair start")
	return 1
}

// askPairApprove asks the owner about request q on the terminal and approves or rejects it.
// Anything but y or yes rejects; no answer leaves the request pending. 0: approved.
func askPairApprove(c *rpcClient, q pairReq, term *pairTerm, stdout, stderr io.Writer) int {
	wait := term.timeout
	if wait <= 0 {
		wait = time.Until(time.UnixMilli(q.ExpiresAt))
	}
	fmt.Fprint(term.out, "Compare the fingerprint with the phone screen.\nApprove this device? [y/N] ")
	ans, ok := term.answer(wait)
	if !ok {
		fmt.Fprintf(stdout, "\nNo answer: request %s is not approved (while it is pending: wardend pair approve %s)\n", q.ID, q.ID)
		return 1
	}
	sub := "reject"
	if a := strings.ToLower(ans); a == "y" || a == "yes" {
		sub = "approve"
	}
	var r struct {
		Request pairReq `json:"request"`
		Config  string  `json:"config"`
	}
	if err := c.call("pair."+sub, map[string]any{"id": q.ID}, &r); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	printPairDecision(stdout, sub, r.Request, r.Config)
	if sub == "reject" {
		return 1
	}
	return 0
}
