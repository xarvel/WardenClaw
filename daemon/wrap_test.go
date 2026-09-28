// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardend wrap: the defaults of its command line, the pairing step before the command (approve,
// reject, no answer, no terminal), and whole runs against the in-process relay with a
// relaylink.Device as the phone.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
	"github.com/xarvel/WardenClaw/daemon/relaylink/relaytest"
)

func TestWrapDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	old := defaultRelayURL
	defaultRelayURL = "wss://relay.test.invalid" // nothing here dials it
	defer func() { defaultRelayURL = old }()
	withCfg := filepath.Join(home, "configured")
	os.MkdirAll(withCfg, 0o700)
	os.WriteFile(filepath.Join(withCfg, "config.json"), []byte(`{"mode":"deny-list","policy_mode":"root","ticket_ttl":"45s"}`), 0o600)

	for _, c := range []struct {
		name                    string
		args                    []string
		mode, policyMode, state string
		relay, policy           string
		ttl                     time.Duration
		quiet                   bool
		cmd                     string
	}{
		{"no flags", []string{"--", "claude", "code"}, "ticket", "tripwire", filepath.Join(home, ".wardend"), "wss://relay.test.invalid", "", 120 * time.Second, false, "claude code"},
		{"no double dash", []string{"make", "test"}, "ticket", "tripwire", filepath.Join(home, ".wardend"), "wss://relay.test.invalid", "", 120 * time.Second, false, "make test"},
		{"flags", []string{"--mode", "observe", "--ttl", "30s", "--state-dir", filepath.Join(home, "s"), "--relay-url", "off", "--policy", "/p.json", "--quiet", "--", "ls"},
			"observe", "tripwire", filepath.Join(home, "s"), "off", "/p.json", 30 * time.Second, true, "ls"},
		{"config of the state dir", []string{"--state-dir", withCfg, "--", "ls"}, "deny-list", "root", withCfg, "wss://relay.test.invalid", "", 45 * time.Second, false, "ls"},
		{"a flag over the config", []string{"--state-dir", withCfg, "--mode", "ticket", "--ttl", "10s", "--", "ls"}, "ticket", "root", withCfg, "wss://relay.test.invalid", "", 10 * time.Second, false, "ls"},
	} {
		var so, se bytes.Buffer
		cfg, o, code, ok := wrapSetup(c.args, &so, &se)
		if !ok {
			t.Fatalf("%s: code %d, stderr %s", c.name, code, se.String())
		}
		if err := cfg.setDefaults(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if cfg.Mode != c.mode || cfg.PolicyMode != c.policyMode || cfg.StateDir != c.state || cfg.RelayURL != c.relay || cfg.Policy != c.policy ||
			cfg.TicketTTL.Duration != c.ttl || cfg.GatewayDB != "" || o.quiet != c.quiet || strings.Join(o.cmd, " ") != c.cmd || o.wrap == nil ||
			(o.wrap.cfgMode != "") != (c.name == "config of the state dir") {
			t.Errorf("%s: mode=%s policy_mode=%s state=%s relay=%s policy=%q ttl=%s gateway_db=%q quiet=%v cmd=%q wrap=%v", c.name,
				cfg.Mode, cfg.PolicyMode, cfg.StateDir, cfg.RelayURL, cfg.Policy, cfg.TicketTTL.Duration, cfg.GatewayDB, o.quiet, o.cmd, o.wrap != nil)
		}
	}

	var so, se bytes.Buffer
	if _, _, code, ok := wrapSetup(nil, &so, &se); ok || code != 2 || !strings.Contains(se.String(), "missing command") {
		t.Fatalf("no command: ok=%v code=%d stderr=%s", ok, code, se.String())
	}
	so.Reset()
	if _, _, code, ok := wrapSetup([]string{"--help"}, &so, &se); ok || code != 0 || !strings.Contains(so.String(), "usage: wardend wrap") {
		t.Fatalf("--help: ok=%v code=%d stdout=%s", ok, code, so.String())
	}
}

// lockedBuf is what a test terminal shows: written by wardend, read by the test's phone.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// waitText waits until the terminal shows text.
func (l *lockedBuf) waitText(t *testing.T, text string) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		if strings.Contains(l.String(), text) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("the terminal never showed %q:\n%s", text, l.String())
}

var pairLinkRe = regexp.MustCompile(`wardenclaw://pair\?\S+`)

// wrapPhone is the phone of a pairing on a test terminal: it reads the link the terminal shows,
// as the app reads the QR, and connects to the relay as that device.
type wrapPhone struct {
	dev  *relaylink.Device
	link envelope.PairLink
	sess *relaylink.Session
}

func newWrapPhone(t *testing.T, screen *lockedBuf, relayURL string) *wrapPhone {
	t.Helper()
	screen.waitText(t, "Waiting for the request")
	raw := pairLinkRe.FindString(screen.String())
	// the in-process relay is ws://, a link names wss:// only (runOpts.pairWS)
	link, err := envelope.ParsePairLink(strings.Replace(raw, "relay=ws%3A", "relay=wss%3A", 1))
	if err != nil {
		t.Errorf("pair link %q: %v", raw, err)
		return nil
	}
	enc, err := relaylink.ParseEncKey(link.Enc)
	if err != nil {
		t.Errorf("link enc: %v", err)
		return nil
	}
	d := newRelayDev()
	p := &wrapPhone{link: link, dev: &relaylink.Device{Key: d.priv, Enc: d.enc, SupervisorID: link.SID, SupervisorEnc: enc, Client: "wardenclaw-test", Version: version}}
	if p.sess, err = p.dev.Connect(context.Background(), relayURL); err != nil {
		t.Errorf("phone: %v", err)
		return nil
	}
	t.Cleanup(p.sess.Close)
	return p
}

// pair sends the pairing request with the code of the link.
func (p *wrapPhone) pair(t *testing.T, name string) {
	t.Helper()
	pt, _ := p.dev.PairRequest(p.link.Code, name)
	e, _ := p.dev.SealPair(pt)
	if err := p.sess.Send(context.Background(), e); err != nil {
		t.Errorf("phone: pair frame: %v", err)
	}
}

// decide answers the next card with a signed ticket.
func (p *wrapPhone) decide(t *testing.T, decision string) {
	t.Helper()
	timeout := time.After(20 * time.Second)
	for {
		select {
		case m, ok := <-p.sess.Messages():
			if !ok {
				t.Errorf("phone: the session ended before a card: %v", p.sess.Err())
				return
			}
			if m.Kind != "card" {
				continue
			}
			var card struct{ ID, Digest string }
			json.Unmarshal(m.Body, &card)
			pt, _ := json.Marshal(envelope.SignPayload(p.dev.Key, envelope.ExecPayload(p.link.SID, card.ID, card.Digest, decision, envelope.NowMs(), envelope.NewNonce())))
			var err error
			for i := 0; i < 20; i++ { // the device list reaches the relay a moment after the approval
				e, _ := p.dev.Seal("ticket", pt)
				if err = p.sess.Send(context.Background(), e); err == nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Errorf("phone: ticket: %v", err)
			return
		case <-timeout:
			t.Error("phone: no card")
			return
		}
	}
}

type wrapRun struct {
	code           int
	err            error
	stdout, stderr string
	screen         string // the terminal of the pairing step
	cfg            *Config
}

// runWrap runs cmd as wardend wrap does, with relay_url at relayURL and a test terminal. phone
// (if not nil) runs beside it: it gets the terminal's screen and its keyboard.
func runWrap(t *testing.T, relayURL string, cmd []string, tune func(*Config, *runOpts, *pairTerm), phone func(screen *lockedBuf, keys io.Writer)) *wrapRun {
	t.Helper()
	cfg := &Config{Mode: "ticket", PolicyMode: "root", StateDir: t.TempDir(), RelayURL: relayURL, Linger: duration{300 * time.Millisecond}}
	var so bytes.Buffer
	se, screen := &lockedBuf{}, &lockedBuf{}
	keysR, keysW := io.Pipe()
	defer keysW.Close()
	idle, idleW, _ := os.Pipe()
	defer idle.Close()
	defer idleW.Close()
	term := &pairTerm{in: keysR, out: screen, timeout: 20 * time.Second}
	o := &runOpts{cmd: cmd, helperExe: os.Args[0], helperEnv: []string{"WARDEND_TEST_HELPER=1"}, stdout: &so, stderr: se, stdin: idle,
		noSignals: true, noSelfCheck: true, pairWS: true,
		wrap: &wrapOpts{qr: "none", openTerm: func() *pairTerm { return term }, relayWait: 5 * time.Second}}
	if tune != nil {
		tune(cfg, o, term)
	}
	var wg sync.WaitGroup
	if phone != nil {
		wg.Add(1)
		go func() { defer wg.Done(); phone(screen, keysW) }()
	}
	r := &wrapRun{cfg: cfg}
	r.code, r.err = runSupervisor(cfg, o)
	wg.Wait()
	r.stdout, r.stderr, r.screen = so.String(), se.String(), screen.String()
	return r
}

// gated needs a ticket in the "approved root" policy mode: the shell is the command, ls is a root.
var gated = []string{"sh", "-c", "ls -d / && echo ran"}

// The first run: no device, the phone pairs on the terminal, the owner says y, the command
// starts, its root gets a card, the phone allows; the summary counts it.
func TestWrapPairsThenRuns(t *testing.T) {
	relay := relaytest.NewRelay(t)
	r := runWrap(t, relay.URL(), gated, nil, func(screen *lockedBuf, keys io.Writer) {
		p := newWrapPhone(t, screen, relay.URL())
		if p == nil {
			return
		}
		p.pair(t, "Pixel 9")
		screen.waitText(t, "Approve this device? [y/N]")
		io.WriteString(keys, "y\n")
		p.decide(t, "allow")
	})
	t.Logf("terminal:\n%s\nstdout:\n%sstderr:\n%s", r.screen, r.stdout, r.stderr)
	if r.err != nil || r.code != 0 || !strings.Contains(r.stdout, "ran") {
		t.Fatalf("code=%d err=%v stdout=%q stderr=%q", r.code, r.err, r.stdout, r.stderr)
	}
	for _, want := range []string{"no device is paired yet", "wardenclaw://pair?", `"Pixel 9", fingerprint `, "Approve this device? [y/N]", "Approved: \"Pixel 9\""} {
		if !strings.Contains(r.screen, want) {
			t.Errorf("the terminal lacks %q", want)
		}
	}
	if !strings.Contains(r.stderr, "asked: 1 allowed, 0 denied, 0 expired. Journal: "+r.cfg.Journal) || strings.Contains(r.stderr, "mode=") {
		t.Errorf("summary: %q", r.stderr)
	}
	// the device is in the config: the next run does not pair
	c, err := loadConfig(filepath.Join(r.cfg.StateDir, "config.json"))
	if err != nil || len(c.TrustedDevices) != 1 || c.TrustedDevices[0].Name != "Pixel 9" {
		t.Fatalf("config after the pairing: %+v, %v", c, err)
	}
}

// The phone denies: the command goes on without its root, the terminal and the summary say so.
func TestWrapDenied(t *testing.T) {
	relay := relaytest.NewRelay(t)
	r := runWrap(t, relay.URL(), gated, nil, func(screen *lockedBuf, keys io.Writer) {
		p := newWrapPhone(t, screen, relay.URL())
		if p == nil {
			return
		}
		p.pair(t, "phone")
		screen.waitText(t, "Approve this device? [y/N]")
		io.WriteString(keys, "yes\n")
		p.decide(t, "deny")
	})
	t.Logf("stderr:\n%s", r.stderr)
	if r.err != nil || r.code == 0 || strings.Contains(r.stdout, "ran") {
		t.Fatalf("code=%d err=%v stdout=%q", r.code, r.err, r.stdout)
	}
	if !strings.Contains(r.stderr, "wardend: denied on the phone: ls -d /") || !strings.Contains(r.stderr, "wardend: 2 commands seen, 1 asked: 0 allowed, 1 denied, 0 expired. Journal:") {
		t.Errorf("stderr: %q", r.stderr)
	}
}

// --quiet: no summary; a card nobody answers is mentioned while it waits and when it expires.
func TestWrapQuietAndExpired(t *testing.T) {
	relay := relaytest.NewRelay(t)
	r := runWrap(t, relay.URL(), gated, func(c *Config, o *runOpts, _ *pairTerm) {
		c.TicketTTL.Duration = time.Second
		o.quiet = true
	}, func(screen *lockedBuf, keys io.Writer) {
		if p := newWrapPhone(t, screen, relay.URL()); p != nil {
			p.pair(t, "phone")
			screen.waitText(t, "Approve this device? [y/N]")
			io.WriteString(keys, "Y\n")
		}
	})
	if r.err != nil || strings.Contains(r.stdout, "ran") || !strings.Contains(r.stderr, "wardend: expired, no decision in 1s: ls -d /") || strings.Contains(r.stderr, "commands seen") {
		t.Fatalf("code=%d err=%v stdout=%q stderr=%q", r.code, r.err, r.stdout, r.stderr)
	}
}

// The command is never started without a device: the owner says no, does not answer, or there
// is no terminal to ask on.
func TestWrapNotPaired(t *testing.T) {
	relay := relaytest.NewRelay(t)
	pairAnd := func(answer string) func(*lockedBuf, io.Writer) {
		return func(screen *lockedBuf, keys io.Writer) {
			if p := newWrapPhone(t, screen, relay.URL()); p != nil {
				p.pair(t, "phone")
				screen.waitText(t, "Approve this device? [y/N]")
				io.WriteString(keys, answer)
			}
		}
	}
	for _, c := range []struct {
		name   string
		tune   func(*Config, *runOpts, *pairTerm)
		phone  func(*lockedBuf, io.Writer)
		errHas string
		screen string
	}{
		{"rejected", nil, pairAnd("n\n"), "no device was paired: sh was not started", "Rejected: p-"},
		{"empty answer", nil, pairAnd("\n"), "no device was paired", "Rejected: p-"},
		{"no answer", func(_ *Config, _ *runOpts, term *pairTerm) { term.timeout = 300 * time.Millisecond }, pairAnd(""), "no device was paired", "No answer: request p-"},
		{"no terminal", func(_ *Config, o *runOpts, _ *pairTerm) { o.wrap.openTerm = func() *pairTerm { return nil } }, nil, "Pair first", ""},
	} {
		r := runWrap(t, relay.URL(), []string{"sh", "-c", "echo ran"}, c.tune, c.phone)
		if r.err == nil || r.code == 0 || !strings.Contains(r.err.Error(), c.errHas) || strings.Contains(r.stdout, "ran") || !strings.Contains(r.screen, c.screen) {
			t.Errorf("%s: code=%d err=%v stdout=%q terminal:\n%s", c.name, r.code, r.err, r.stdout, r.screen)
		}
		if b, _ := os.ReadFile(r.cfg.Journal); strings.Contains(string(b), `"kind":"start"`) {
			t.Errorf("%s: the command was started", c.name)
		}
	}
}

// No way for a decision to arrive: wrap says so and starts nothing.
func TestWrapFailsClosedWithoutRelay(t *testing.T) {
	for _, c := range []struct{ name, url, errHas string }{
		{"unreachable", "ws://127.0.0.1:1", "cannot reach the relay ws://127.0.0.1:1"},
		{"off, no device", "off", "relay_url is off and no device is trusted"},
	} {
		r := runWrap(t, c.url, []string{"sh", "-c", "echo ran"}, func(_ *Config, o *runOpts, _ *pairTerm) { o.wrap.relayWait = 300 * time.Millisecond }, nil)
		if r.err == nil || r.code == 0 || !strings.Contains(r.err.Error(), c.errHas) || !strings.Contains(r.err.Error(), "--relay-url off is not a way to get approvals") || strings.Contains(r.stdout, "ran") {
			t.Errorf("%s: code=%d err=%v stdout=%q", c.name, r.code, r.err, r.stdout)
		}
	}
	// observe asks nobody: it runs without a relay and without a device
	// a mode the config chose is said aloud: a silent run must not pass for an approved one
	r := runWrap(t, "off", []string{"sh", "-c", "echo ran"}, func(c *Config, o *runOpts, _ *pairTerm) { c.Mode, o.wrap.cfgMode = "observe", "/c.json" }, nil)
	if r.err != nil || r.code != 0 || !strings.Contains(r.stdout, "ran") || !strings.Contains(r.stderr, "0 asked") ||
		!strings.Contains(r.stderr, "wardend: mode observe (from /c.json): nothing is asked on the phone") {
		t.Fatalf("observe: code=%d err=%v stdout=%q stderr=%q", r.code, r.err, r.stdout, r.stderr)
	}
}

// wardend pair start in one step: with a terminal it asks and approves; without one it prints
// the id for pair approve, as a script expects.
func TestPairStartAsks(t *testing.T) {
	s, relay := newRelaySupervisor(t)
	s.pairWS = true
	rpc, err := startRPC(s.cfg.Socket, s)
	if err != nil {
		t.Fatal(err)
	}
	defer rpc.close()
	start := func(term *pairTerm, name string) (int, string) {
		c, err := dialClient(s.cfg.Socket)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		out := &lockedBuf{}
		done := make(chan struct{})
		go func() {
			defer close(done)
			out.waitText(t, "Waiting for the request")
			link, _ := envelope.ParsePairLink(strings.Replace(pairLinkRe.FindString(out.String()), "relay=ws%3A", "relay=wss%3A", 1))
			relay.Send(newRelayDev().pairFrame(s, link.Code, name))
		}()
		code := pairStartCmd(c, 0, "none", true, term, out, out)
		<-done
		return code, out.String()
	}

	code, out := start(nil, "scripted")
	if code != 0 || !strings.Contains(out, "wardend pair approve p-") || len(s.devices.List()) != 1 {
		t.Fatalf("no terminal: code=%d devices=%d\n%s", code, len(s.devices.List()), out)
	}
	screen := &lockedBuf{}
	code, out = start(&pairTerm{in: strings.NewReader("y\n"), out: screen, timeout: 5 * time.Second}, "asked")
	if code != 0 || !strings.Contains(screen.String(), "Approve this device? [y/N]") || !strings.Contains(out, `Approved: "asked"`) || len(s.devices.List()) != 2 {
		t.Fatalf("terminal: code=%d devices=%d\n%s", code, len(s.devices.List()), out)
	}
}
