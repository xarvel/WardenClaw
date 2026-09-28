// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardend pair: pairs the WardenClaw app with the running supervisor (over the unix socket).
//
//	wardend pair start [--url https://…] [--ttl 5m] [--qr ansi|utf8|invert|none] [--no-wait]
//	wardend pair list
//	wardend pair approve <id> | reject <id>
//	wardend pair revoke <deviceId|prefix>

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/qr"
)

const pairUsage = `usage: wardend pair start [--socket s] [--url https://…] [--ttl 5m] [--qr ansi|utf8|invert|none] [--no-wait]
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
	"start":   {"pair start [flags]", "Prints a one-time pairing code and QR for the WardenClaw app (or wardenctl pair) and waits for the request.", 0},
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
	var url, qrMode *string
	var ttl *time.Duration
	var noWait *bool
	if sub == "start" {
		url = fs.String("url", "", "public endpoint address in the QR (default: public_url from the config)")
		ttl = fs.Duration("ttl", 0, "code lifetime (default: pair_code_ttl, 5m)")
		qrMode = fs.String("qr", "ansi", "ansi (black on white via terminal colors) | utf8 (no color, light background) | invert (no color, dark background) | none")
		noWait = fs.Bool("no-wait", false, "do not wait for the request from the phone")
	}
	// flags may also follow the id: wardend pair approve p-xxxx --socket …; help, an unknown
	// subcommand and a wrong argument count are answered before connecting to the socket
	pos, code, ok := fs.parseArgs(rest, spec.nargs, spec.nargs)
	if !ok {
		return code
	}
	c, ok := dialSupervisor(*sock, stderr)
	if !ok {
		return 1
	}
	defer c.Close()
	switch sub {
	case "start":
		return pairStartCmd(c, *url, *ttl, *qrMode, !*noWait, stdout, stderr)
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
		if sub == "approve" {
			fmt.Fprintf(stdout, "Approved: \"%s\", fingerprint %s, deviceId %s\nWritten to %s (trusted_devices); the supervisor trusts the device right away.\n", r.Request.Name, r.Request.Fingerprint, r.Request.DeviceID, r.Config)
		} else {
			fmt.Fprintf(stdout, "Rejected: %s (\"%s\", %s)\n", r.Request.ID, r.Request.Name, r.Request.Fingerprint)
		}
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
	HTTP        map[string]any `json:"http"`
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
	if up, _ := r.HTTP["up"].(bool); !up {
		fmt.Fprintf(w, "HTTP endpoint is down: %v\n", r.HTTP["error"])
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func pairStartCmd(c *rpcClient, url string, ttl time.Duration, qrMode string, wait bool, stdout, stderr io.Writer) int {
	var r struct {
		Code                  string `json:"codeDisplay"`
		ExpiresAt             int64  `json:"expiresAt"`
		URL                   string `json:"url"`
		Link                  string `json:"link"`
		SupervisorKey         string `json:"supervisorKey"`
		SupervisorFingerprint string `json:"supervisorFingerprint"`
		Host                  string `json:"host"`
	}
	if err := c.call("pair.start", map[string]any{"url": url, "ttl": ttl.Milliseconds()}, &r); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	printQR(stdout, stderr, r.Link, qrMode)
	exp := time.UnixMilli(r.ExpiresAt)
	fmt.Fprintf(stdout, "\nScan the QR in the WardenClaw app (Connect tab) or paste the link:\n  %s\n\n", r.Link)
	fmt.Fprintf(stdout, "Code:       %s (one-time, until %s)\n", r.Code, exp.Format("15:04:05"))
	fmt.Fprintf(stdout, "Endpoint:   %s\n", r.URL)
	fmt.Fprintf(stdout, "Supervisor: %s, key fingerprint %s\n", r.Host, r.SupervisorFingerprint)
	if strings.HasPrefix(r.URL, "http://127.") || strings.HasPrefix(r.URL, "http://localhost") {
		fmt.Fprintln(stdout, "Warning: the address is local, the phone cannot reach it. Set public_url (deploy/CLOUDFLARE.md) or --url.")
	}
	if !wait {
		fmt.Fprintln(stdout, "Then: wardend pair list → wardend pair approve <id>")
		return 0
	}
	return waitPairRequest(c, exp, stdout, stderr)
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
// the code expires, then tells the owner the next step.
func waitPairRequest(c *rpcClient, exp time.Time, stdout, stderr io.Writer) int {
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
			if q.Status == "approved" {
				fmt.Fprintln(stdout, "This device is already trusted: no approval needed.")
			} else {
				fmt.Fprintf(stdout, "Compare the fingerprint with the phone screen and approve:\n  wardend pair approve %s\n", q.ID)
			}
			return 0
		}
	}
	fmt.Fprintln(stdout, "The code expired with no requests. New one: wardend pair start")
	return 1
}
