// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/feature"
)

// Review 2026-09-28 (M6, W3): the Keychain key without trusted applications, approve shows the
// card and asks, allowing from the CLI with a YubiKey touch by default.

func fakeKeychain(t *testing.T) string {
	t.Helper()
	fk := installFakes(t, "security")
	store := filepath.Join(t.TempDir(), "kc.json")
	t.Setenv("FAKE_SECURITY_STORE", store)
	t.Setenv("WARDENCTL_SECURITY_BIN", filepath.Join(fk, "security"))
	return store
}

func keychainACL(t *testing.T, store, account string) string {
	t.Helper()
	m := map[string]string{}
	b, _ := os.ReadFile(store)
	json.Unmarshal(b, &m)
	return m["acl:"+keychainService+"/"+account]
}

// A new entry without trusted applications (-T ""): reading it shows a system prompt, including
// to wardenctl itself. The entry is verified by its attributes, without reading the seed.
func TestKeychainSaveTrustsNoApp(t *testing.T) {
	store := fakeKeychain(t)
	ks, _ := keyStoreByName("keychain", t.TempDir())
	priv := seedKey(t, strings.Repeat("5c", 32))
	id := deviceIDOf(priv)
	if err := ks.Save(id, priv.Seed()); err != nil {
		t.Fatal(err)
	}
	if acl := keychainACL(t, store, id); acl != "prompt" {
		t.Fatalf("entry ACL %q, want prompt (-T \"\")", acl)
	}
	argv, _ := os.ReadFile(store + ".argv")
	if strings.Contains(string(argv), " -w") {
		t.Fatalf("Save read the seed (find -w) while verifying the entry:\n%s", argv)
	}
	if got, err := ks.Load(id); err != nil || !bytes.Equal(got, priv.Seed()) {
		t.Fatalf("%x %v", got, err)
	}
}

// An old-version entry (trusted security) is recreated; if the new one fails, the previous one
// is restored and the key is not lost.
func TestKeychainReprotect(t *testing.T) {
	store := fakeKeychain(t)
	kc := keychainStore{bin: securityBin()}
	priv := seedKey(t, strings.Repeat("6d", 32))
	id := deviceIDOf(priv)
	if err := kc.add(id, priv.Seed(), false); err != nil {
		t.Fatal(err)
	}
	if acl := keychainACL(t, store, id); acl != "security" {
		t.Fatalf("old entry: ACL %q", acl)
	}
	t.Setenv("FAKE_SECURITY_FAIL_PROMPT", "1")
	if err := kc.Reprotect(id); err == nil || !strings.Contains(err.Error(), "previous entry restored") {
		t.Fatalf("new entry failure: %v", err)
	}
	if got, err := kc.Load(id); err != nil || !bytes.Equal(got, priv.Seed()) || keychainACL(t, store, id) != "security" {
		t.Fatalf("key lost after the failure: %x %v", got, err)
	}
	t.Setenv("FAKE_SECURITY_FAIL_PROMPT", "")
	if err := kc.Reprotect(id); err != nil {
		t.Fatal(err)
	}
	if got, err := kc.Load(id); err != nil || !bytes.Equal(got, priv.Seed()) || keychainACL(t, store, id) != "prompt" {
		t.Fatalf("after Reprotect: %x %v, ACL %q", got, err, keychainACL(t, store, id))
	}
}

// open recreates an old-version entry once and records this in server.json.
func TestOpenReprotectsOldKeychainEntry(t *testing.T) {
	store := fakeKeychain(t)
	dir := t.TempDir()
	st := writeTestState(t, dir)
	priv := seedKey(t, strings.Repeat("11", 32))
	os.Remove(filepath.Join(dir, "device.key"))
	if err := (keychainStore{bin: securityBin()}).add(st.DeviceID, testSecret(priv), false); err != nil {
		t.Fatal(err)
	}
	st.KeyStore = "keychain"
	// writeTestState pins 32 zero bytes. DecodeKey rejects that point, so open never reaches the Keychain.
	sup := seedKey(t, strings.Repeat("ab", 32)).Public().(ed25519.PublicKey)
	st.SupervisorKey = envelope.B64URL(sup)
	st.SupervisorID = envelope.DeviceID(sup)
	if err := saveState(dir, st); err != nil {
		t.Fatal(err)
	}
	a, _, errb := testApp(dir, "")
	if _, err := a.open(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errb.String(), "Recreating the item") || keychainACL(t, store, st.DeviceID) != "prompt" {
		t.Fatalf("entry not recreated: ACL %q\n%s", keychainACL(t, store, st.DeviceID), errb)
	}
	if st2, _ := loadState(dir); st2.KeychainACL != "prompt" {
		t.Fatalf("keychainAcl in server.json: %q", st2.KeychainACL)
	}
	a, _, errb = testApp(dir, "")
	if _, err := a.open(context.Background()); err != nil || errb.Len() != 0 {
		t.Fatalf("second open: %v %s", err, errb)
	}
}

// On a terminal approve shows the card and waits for an answer: a normal one is allowed by y, a
// dangerous one only by the whole word allow; an empty line and anything else cancel.
func TestConfirmAllow(t *testing.T) {
	safe := checkItem(testItem(t, "bash", "-c", "git status"), testSup)
	danger := checkItem(testItem(t, "bash", "-c", "/usr/bin/pуthon -m http.server"), testSup)
	for _, c := range []struct {
		card Card
		in   string
		want bool
		out  string
	}{
		{safe, "y\n", true, "Allow wd-"},
		{safe, "yes\n", true, "[y/N]"},
		{safe, "\n", false, "Cancelled"},
		{safe, "n\n", false, "Cancelled"},
		{safe, "", false, "Cancelled"},
		{danger, "y\n", false, "only the word allow in full allows it"},
		{danger, "allow\n", true, "Dangerous card wd-"},
		{danger, "allo\n", false, "Cancelled"},
	} {
		a, out, _ := testApp(t.TempDir(), c.in)
		if got := a.confirmAllow(c.card, 0); got != c.want || !strings.Contains(out.String(), c.out) || !strings.Contains(out.String(), "Card "+c.card.ID) {
			t.Errorf("%q on %s: %v, want %v\n%s", c.in, c.card.ID, got, c.want, out)
		}
	}
	// --json: the card and the question go to stderr, stdout is left for JSON
	a, out, errb := testApp(t.TempDir(), "y\n")
	a.json = true
	if !a.confirmAllow(safe, 0) || out.Len() != 0 || !strings.Contains(errb.String(), "Allow wd-") {
		t.Fatalf("--json: stdout %q, stderr %q", out, errb)
	}
}

// Without a question (not a terminal or --yes) approve takes an id of at least 12 characters,
// before the key and the network.
func TestApproveWithoutQuestionNeedsLongID(t *testing.T) {
	for _, args := range [][]string{{"approve", "wd-0123456789"}, {"approve", "0123456789a", "--yes"}} {
		a, out, errb := testApp(filepath.Join(t.TempDir(), "state"), "")
		if code := a.run(context.Background(), args); code != 1 || out.Len() != 0 || !strings.Contains(errb.String(), "at least 12") {
			t.Errorf("%q: code %d, stderr %q", args, code, errb)
		}
	}
	// on a terminal a short prefix is fine: the card will be shown with a question (there is no
	// server past that point here)
	a, _, errb := testApp(filepath.Join(t.TempDir(), "state"), "")
	a.tty = func() bool { return true }
	if code := a.run(context.Background(), []string{"approve", "wd-0123456789"}); code != 1 || strings.Contains(errb.String(), "at least") {
		t.Fatalf("terminal: code %d, stderr %q", code, errb)
	}
	// deny has no question and accepts a short prefix as before
	a, _, errb = testApp(filepath.Join(t.TempDir(), "state"), "")
	if code := a.run(context.Background(), []string{"deny", "wd-0123456789"}); code != 1 || strings.Contains(errb.String(), "at least") {
		t.Fatalf("deny: code %d, stderr %q", code, errb)
	}
}

// Allow uses a YubiKey touch by default: without a bound key, an error before signing, --no-hw
// lifts the requirement; if wardend itself requires the YubiKey, --no-hw does not help.
func TestAllowNeedsYubiKeyByDefault(t *testing.T) {
	if !feature.HWKey {
		t.Skip("YubiKey only in a build with the hwkey tag")
	}
	priv := seedKey(t, strings.Repeat("22", 32))
	s := &session{st: &State{DeviceID: deviceIDOf(priv)}, priv: priv}
	c := checkItem(testItem(t, "bash", "-c", "git status"), testSup)
	c.Meta.Hardware = nil // testItem marks the card with the hw-bash rule
	a, _, _ := testApp(t.TempDir(), "")
	if _, err := a.decide(context.Background(), s, c, "allow", decideOpts{forceHW: true}); err == nil || err.Error() != noHWBound {
		t.Fatalf("default without YubiKey: %v", err)
	}
	c.Meta.Hardware = &HWMeta{Required: true, Rule: "hw-bash"}
	if _, err := a.decide(context.Background(), s, c, "allow", decideOpts{forceHW: true, noHW: true}); err == nil || !strings.Contains(err.Error(), "rule hw-bash") {
		t.Fatalf("wardend requires the key, --no-hw: %v", err)
	}
	// watch without a bound key responds before the first card
	dir := t.TempDir()
	writeTestState(t, dir)
	a, _, errb := testApp(dir, "")
	if code := a.run(context.Background(), []string{"watch"}); code != 1 || !strings.Contains(errb.String(), "watch --no-hw") {
		t.Fatalf("watch: code %d, stderr %q", code, errb)
	}
}
