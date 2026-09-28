// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardenctl pair: the link from `wardend pair start`, a new device key, then a wait until the
// server approves the request.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

func hostname() string {
	h, _ := os.Hostname()
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	if h == "" {
		h = "terminal"
	}
	return h
}

func isLoopbackURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	h := p.Hostname()
	return h == "localhost" || strings.HasPrefix(h, "127.") || h == "::1"
}

func (a *app) cmdPair(ctx context.Context, args []string) int {
	fs := a.flags("pair")
	name := fs.String("name", "wardenctl@"+hostname(), "device name (shown in wardend pair list)")
	ks := fs.String("keystore", "auto", "where to keep the key: auto|keychain|file")
	noWait := fs.Bool("no-wait", false, "do not wait for approval (later: wardenctl status)")
	timeout := fs.Duration("timeout", 10*time.Minute, "how long to wait for wardend pair approve")
	pos, code, ok := a.parseCmd(fs, args, cmdSpec{guarded: true, maxArgs: 1})
	if !ok {
		return code
	}
	if len(pos) != 1 {
		return a.errf("a link is required: wardenctl pair 'wardenclaw://pair?code=…&key=…&url=…&v=1' (from the output of wardend pair start; in quotes)")
	}
	link, pinned, err := parsePairLink(pos[0])
	if err != nil {
		return a.errf("%v", err)
	}
	supID := envelope.DeviceID(pinned)

	if old, err := loadState(a.dir); err == nil {
		if old.PairStatus == "approved" {
			return a.errf("already paired with %s (%s). First wardenctl forget (and wardend pair revoke %s on the server).", old.Host, old.URL, revokeRef(old.DeviceID))
		}
		a.dropKey(old) // unfinished pairing: the old key and state are not needed
		os.Remove(statePath(a.dir))
	} else if !errors.Is(err, errNotPaired) {
		return a.errf("%v", err)
	}
	store, err := keyStoreByName(*ks, a.dir)
	if err != nil {
		return a.errf("%v", err)
	}
	if strings.HasPrefix(link.URL, "http://") && !isLoopbackURL(link.URL) {
		fmt.Fprintf(a.stderr, "Warning: %s is not HTTPS. Signatures protect against tampering, but the commands on the cards are visible on the network.\n", link.URL)
	}

	cl := newClient(link.URL, pinned, nil)
	ping, err := cl.Ping(ctx)
	if err != nil {
		a.errf("server check %s: %v", link.URL, err)
		return codeFor(err)
	}
	if ping.SupervisorID != supID {
		return a.errf("the server answered with the key from the link but with a different supervisorId: not wardend?")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return a.errf("key: %v", err)
	}
	devID := envelope.DeviceID(pub)
	if err := ensureDir(a.dir); err != nil {
		return a.errf("%v", err)
	}
	if err := store.Save(devID, priv.Seed()); err != nil {
		return a.errf("save key (%s): %v", store.Name(), err)
	}
	st := &State{URL: link.URL, SupervisorKey: envelope.B64URL(pinned), SupervisorID: supID, Host: link.Host, DeviceID: devID,
		Pubkey: envelope.B64URL(pub), Name: *name, KeyStore: store.Kind(),
		PairStatus: "pending"}
	if store.Kind() == "keychain" {
		st.KeychainACL = "prompt"
	}
	cl.Priv = priv
	pr, err := cl.Pair(ctx, link.Code, supID, *name)
	if err != nil {
		store.Delete(devID)
		return a.errf("pairing request: %v", err)
	}
	if pr.Host != "" {
		st.Host = pr.Host
	}
	st.PairID = pr.ID
	if err := saveState(a.dir, st); err != nil {
		return a.errf("%v", err)
	}
	fp := envelope.Fingerprint(devID)
	if pr.Fingerprint != "" && pr.Fingerprint != fp {
		return a.errf("the server shows a different fingerprint (%s, ours is %s): do not approve the request", pr.Fingerprint, fp)
	}
	fmt.Fprintf(a.stdout, "Server:      %s (%s), supervisor key pinned, fingerprint %s\n", st.Host, st.URL, envelope.Fingerprint(supID))
	fmt.Fprintf(a.stdout, "Device:      \"%s\", key: %s\n", *name, store.Name())
	fmt.Fprintf(a.stdout, "Request:     %s\n\n", pr.ID)
	fmt.Fprintf(a.stdout, "  This device's fingerprint:  %s\n\n", fp)
	fmt.Fprintf(a.stdout, "On the server: wardend pair list, compare the fingerprint, then wardend pair approve %s\n", pr.ID)
	if pr.Status == "approved" {
		return a.pairDone(st)
	}
	if *noWait {
		fmt.Fprintln(a.stdout, "Not waiting for approval; to check: wardenctl status")
		return 0
	}
	fmt.Fprintln(a.stdout, "Waiting for approval… (Ctrl-C stops waiting; pairing can be finished with wardenctl status)")
	return a.waitForPairing(ctx, cl, st, pr.ID, *timeout)
}

// minPairCode: the shortest pairing code a link may carry.
const minPairCode = 6

// parsePairLink: the link from wardend pair start with the server address and the code
// normalized, and the supervisor key that it pins.
func parsePairLink(raw string) (envelope.PairLink, ed25519.PublicKey, error) {
	link, err := envelope.ParsePairLink(raw)
	if err != nil {
		return link, nil, fmt.Errorf("link: %v", err)
	}
	link.URL = strings.TrimRight(strings.TrimSpace(link.URL), "/")
	if pu, err := url.Parse(link.URL); err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" {
		return link, nil, errors.New("the link has no server address (url)")
	}
	link.Code = envelope.NormalizeCode(link.Code)
	if len(link.Code) < minPairCode {
		return link, nil, errors.New("the link has no pairing code")
	}
	pinned, err := envelope.DecodeKey(link.Key)
	if err != nil {
		return link, nil, fmt.Errorf("the server key in the link is damaged: %v", err)
	}
	return link, pinned, nil
}

// pairPollInterval: how often pair asks wardend whether the request is approved.
const pairPollInterval = 1500 * time.Millisecond

// waitForPairing: polls pairing request id until the server decides it, the timeout runs out or
// the user presses Ctrl-C.
func (a *app) waitForPairing(ctx context.Context, cl *Client, st *State, id string, timeout time.Duration) int {
	deadline := a.now().Add(timeout)
	for a.now().Before(deadline) {
		select {
		case <-ctx.Done():
			fmt.Fprintln(a.stdout, "\nStopped waiting. Once approved on the server: wardenctl status")
			return 1
		case <-time.After(pairPollInterval):
		}
		ps, err := cl.PairStatus(ctx, id)
		if err != nil {
			if ctx.Err() == nil { // after Ctrl-C the select above reports it
				fmt.Fprintf(a.stderr, "  status: %v (will retry)\n", err)
			}
			continue
		}
		if done, code := a.applyPairStatus(st, ps.Status); done {
			return code
		}
	}
	return a.errf("no approval within %s; later: wardenctl status", timeout)
}

// applyPairStatus: update the state from /v1/pair/status. done=false: still waiting.
func (a *app) applyPairStatus(st *State, status string) (bool, int) {
	switch status {
	case "approved":
		return true, a.pairDone(st)
	case "rejected":
		st.PairStatus = "rejected"
		saveState(a.dir, st)
		return true, a.errf("pairing rejected on the server (wardend pair reject). New code: wardend pair start")
	case "revoked":
		return true, a.errf("device revoked on the server (wardend pair revoke): wardenctl forget and pair again")
	case "unknown":
		return true, a.errf("the server does not know this request: it expired (10 min) or wardend restarted. Start over: wardend pair start, wardenctl forget, wardenctl pair")
	}
	return false, 0
}

func (a *app) pairDone(st *State) int {
	st.PairStatus = "approved"
	st.PairedAt = a.now().UTC().Format(time.RFC3339)
	if err := saveState(a.dir, st); err != nil {
		return a.errf("%v", err)
	}
	fmt.Fprintf(a.stdout, "Approved: server %s trusts this device. Next: wardenctl watch\n", st.Host)
	return 0
}

// reprotectKeychain: a key written to the Keychain by an old version was readable by any process
// of this user without a prompt. The item is recreated once; after that every read goes through a
// system prompt (keychainStore.Reprotect).
func (a *app) reprotectKeychain(st *State) error {
	ks, err := keyStoreByName(st.KeyStore, a.dir)
	if err != nil {
		return err
	}
	kc, ok := ks.(keychainStore)
	if !ok {
		return nil
	}
	fmt.Fprintln(a.stderr, "wardenctl: the device key in the Keychain was readable by any process of this user without a prompt.")
	fmt.Fprintln(a.stderr, "  Recreating the item: from now on macOS asks on every read. Answer \"Allow\",")
	fmt.Fprintln(a.stderr, "  not \"Always Allow\": that would open the key to any process again, including the agent.")
	if err := kc.Reprotect(st.DeviceID); err != nil {
		return fmt.Errorf("keychain: %v", err)
	}
	st.KeychainACL = "prompt"
	return saveState(a.dir, st)
}

// interactive: stdin is a terminal, so approve shows the card and asks.
func (a *app) interactive() bool {
	if a.tty != nil {
		return a.tty()
	}
	f, ok := a.stdin.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func (a *app) dropKey(st *State) {
	if ks, err := keyStoreByName(st.KeyStore, a.dir); err == nil {
		if err := ks.Delete(st.DeviceID); err != nil {
			fmt.Fprintf(a.stderr, "wardenctl: delete key (%s): %v\n", ks.Name(), err)
		}
	}
}
