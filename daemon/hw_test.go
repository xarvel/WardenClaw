// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Second factor without seccomp: decide1 (classification, queue, waiting for a ticket) runs in a
// goroutine on a synthetic execEvent, the "app" signs via decide() the same way as over the
// socket. Software FIDO2 authenticator: hwkey/hwkeytest.

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/feature"
	"github.com/xarvel/WardenClaw/daemon/hwkey"
	"github.com/xarvel/WardenClaw/daemon/hwkey/hwkeytest"
	"github.com/xarvel/WardenClaw/daemon/journal"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

type procMap map[int][2]uint64 // pid → {ppid, start}

func (f procMap) Stat(pid int) (int, uint64, bool) {
	v, ok := f[pid]
	return int(v[0]), v[1], ok
}

func newHWSupervisor(t *testing.T, pol string, d device, keys ...hwkey.Key) *supervisor {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{Mode: "ticket", PolicyMode: "root", StateDir: dir, GatewayDB: "off", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, HardwareKeys: keys}
	if err := cfg.fill(); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	hw, err := hwkey.NewStore(cfg.HardwareKeys, cfg.HardwareCounters)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := journal.LoadOrCreateKey(cfg.KeyFile)
	jr, err := journal.Open(cfg.Journal, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { jr.Close() })
	s := &supervisor{cfg: cfg, pol: p, jr: jr, key: key, supervisorID: strings.Repeat("5a", 32), host: "h", devices: envelope.NewDevices(cfg.TrustedDevices, ""),
		hw: hw, nonces: envelope.NewNonceCache(time.Minute), q: newQueue(16), m: newMetrics(), supPid: 999, childPid: -1,
		stderr: io.Discard, quiet: true, denyCache: map[string]deniedReq{}, pair: newPairing()}
	s.tracker = policy.NewTracker(procMap{100: {1, 100}, 101: {100, 101}, 200: {1, 200}, 201: {200, 201}, 300: {1, 300}, 301: {1, 301}, 302: {1, 302}}, 999)
	return s
}

type execOutcome struct {
	allow bool
	errno unix.Errno
	rec   *execRecord
}

// startExec: decide1 in a goroutine; returns the result channel and the pending item (nil: decided
// right away).
func startExec(t *testing.T, s *supervisor, tgid int, argv ...string) (chan execOutcome, *pendingItem) {
	t.Helper()
	ev := &execEvent{Pid: tgid, Tgid: tgid, Start: uint64(tgid), Target: "/usr/bin/" + argv[0], Argv: argv, ArgvOK: true, Cwd: "/tmp", CallerExe: "/usr/bin/bash",
		Chain: []envelope.Link{{Pid: tgid, Exe: "/usr/bin/bash"}}}
	ch := make(chan execOutcome, 1)
	before := s.q.len()
	go func() {
		rec := &execRecord{}
		allow, errno, _, fd := s.decide1(ev, rec)
		closeFd(fd)
		ch <- execOutcome{allow, errno, rec}
	}()
	for i := 0; i < 200; i++ {
		select {
		case o := <-ch:
			ch <- o
			return ch, nil
		default:
		}
		if s.q.len() > before {
			_, items := s.q.snapshot()
			return ch, items[len(items)-1]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("exec neither pending nor decided")
	return nil, nil
}

// supOf: supervisorId from the item's envelope: the exec ticket is signed for this supervisor.
func supOf(it *pendingItem) string {
	r, _ := it.Envelope["requester"].(map[string]any)
	s, _ := r["supervisorId"].(string)
	return s
}

func ticket(d device, it *pendingItem, decision string, risk int) envelope.DecisionBody {
	p := envelope.ExecPayload(supOf(it), it.ID, it.Digest, decision, envelope.NowMs(), envelope.NewNonce())
	if risk >= 0 {
		r := json.Number(itoa64(int64(risk)))
		p.Risk = &r
	}
	return envelope.SignPayload(d.priv, p)
}

func itoa64(n int64) string { b, _ := json.Marshal(n); return string(b) }

func withHW(b envelope.DecisionBody, a *hwkeytest.Authenticator) envelope.DecisionBody {
	ch, _ := envelope.HWChallenge(b.DeviceID, b.Payload)
	b.HW = a.Assert(ch)
	return b
}

func decideRaw(s *supervisor, b envelope.DecisionBody) map[string]any {
	raw, _ := json.Marshal(b) // as over the socket: through JSON
	return s.decide(raw)
}

func wait(t *testing.T, ch chan execOutcome) execOutcome {
	t.Helper()
	select {
	case o := <-ch:
		return o
	case <-time.After(5 * time.Second):
		t.Fatal("exec not decided")
	}
	return execOutcome{}
}

const hwPolicy = `{
  "delegating": [{"id": "sudo", "argv0": "^sudo$"}],
  "require_hardware": [
    {"id": "hw-rm", "argv0": "^rm$"},
    {"id": "hw-delegating", "class": "delegating"},
    {"id": "hw-score", "class": "root", "min_score": 70}
  ]}`

func TestHardwareStaticRule(t *testing.T) {
	for _, a := range []*hwkeytest.Authenticator{hwkeytest.NewEd25519("wardenclaw"), hwkeytest.NewES256("wardenclaw")} {
		d := newDevice()
		stranger := hwkeytest.NewEd25519("wardenclaw")
		s := newHWSupervisor(t, hwPolicy, d, a.Key())
		ch, it := startExec(t, s, 100, "rm", "-rf", "/tmp/x")
		if it == nil {
			t.Fatal("rm must wait for a ticket")
		}
		hm, _ := it.Meta["hardware"].(map[string]any)
		if hm == nil || hm["required"] != true || hm["rule"] != "hw-rm" {
			t.Fatalf("meta.hardware: %#v", it.Meta)
		}
		if creds, _ := hm["credentials"].([]map[string]string); len(creds) != 1 || creds[0]["id"] != hwkey.B64(a.CredID) {
			t.Fatalf("credentials: %#v", hm["credentials"])
		}
		reasons := []string{}
		try := func(b envelope.DecisionBody) {
			r := decideRaw(s, b)
			reasons = append(reasons, asStr(r["reason"]))
		}
		// 1) without the second signature
		try(ticket(d, it, "allow", -1))
		// 2) a foreign key (not registered)
		try(withHW(ticket(d, it, "allow", -1), stranger))
		// 3) a foreign key under our credentialId
		b := withHW(ticket(d, it, "allow", -1), stranger)
		b.HW.CredentialID = hwkey.B64(a.CredID)
		try(b)
		// 4) assertion from another ticket (another nonce → another challenge), valid device signature
		other := ticket(d, it, "allow", -1)
		b = withHW(ticket(d, it, "allow", -1), a)
		oc, _ := envelope.HWChallenge(other.DeviceID, other.Payload)
		b.HW = a.Assert(oc)
		try(b)
		// 5) assertion for another digest
		fake := *it
		fake.Digest = strings.Repeat("ab", 32)
		fb := ticket(d, &fake, "allow", -1)
		b = ticket(d, it, "allow", -1)
		fc, _ := envelope.HWChallenge(fb.DeviceID, fb.Payload)
		b.HW = a.Assert(fc)
		try(b)
		// 6) forged key signature
		b = withHW(ticket(d, it, "allow", -1), a)
		sig, _ := hwkey.DecodeB64(b.HW.Signature)
		sig[len(sig)-2] ^= 0x40
		b.HW.Signature = hwkey.B64(sig)
		try(b)
		want := "hardware_required,hw_unknown_credential,hw_bad_signature,hw_challenge_mismatch,hw_challenge_mismatch,hw_bad_signature"
		if strings.Join(reasons, ",") != want {
			t.Fatalf("%s: reasons %v", hwkey.AlgName(a.Alg), reasons)
		}
		// 7) a correct ticket with the key: exec passes, the root is marked as hardware
		good := withHW(ticket(d, it, "allow", -1), a)
		if r := decideRaw(s, good); r["ok"] != true {
			t.Fatalf("valid: %v", r)
		}
		o := wait(t, ch)
		if !o.allow || o.rec.Hardware == nil || o.rec.Hardware.Verified == nil || o.rec.Hardware.Rule != "hw-rm" || !strings.Contains(o.rec.Reason, "hardware key") {
			t.Fatalf("outcome: %+v %+v", o, o.rec.Hardware)
		}
		if !s.tracker.RootHardware(100) {
			t.Fatal("root not marked hardware")
		}
		// 8) old signCount: the same assertion for a new exec (reissued ticket) is a replay
		ch2, it2 := startExec(t, s, 300, "rm", "/tmp/y")
		b = ticket(d, it2, "allow", -1)
		c2, _ := envelope.HWChallenge(b.DeviceID, b.Payload)
		a.Count-- // a clone of the key with an old counter
		b.HW = a.Assert(c2)
		if r := decideRaw(s, b); r["reason"] != "hw_counter_replay" {
			t.Fatalf("old counter: %v", r)
		}
		a.Count++
		// 9) deny does not require the key
		if r := decideRaw(s, ticket(d, it2, "deny", -1)); r["ok"] != true {
			t.Fatalf("deny: %v", r)
		}
		if o := wait(t, ch2); o.allow {
			t.Fatal("denied exec allowed")
		}
		// journal: decide_reject rejections with the rule
		jb, _ := os.ReadFile(filepath.Join(s.cfg.StateDir, "journal.jsonl"))
		if bytes.Count(jb, []byte(`"hardwareRule":"hw-rm"`)) < 6 {
			t.Fatalf("journal lacks hardware rejects:\n%s", jb)
		}
	}
}

func asStr(v any) string { s, _ := v.(string); return s }

func TestHardwareScoreRule(t *testing.T) {
	a := hwkeytest.NewES256("wardenclaw")
	d := newDevice()
	s := newHWSupervisor(t, hwPolicy, d, a.Key())
	// ls: no static rule, but there is a score rule (root, ≥70): a hint for the app
	ch, it := startExec(t, s, 300, "ls", "/tmp")
	hm, _ := it.Meta["hardware"].(map[string]any)
	if hm == nil || hm["required"] != false || hm["minScore"] != 70 {
		t.Fatalf("meta: %#v", it.Meta)
	}
	// risk 80 without the key: rejected; changing risk to 10 breaks the device signature
	if r := decideRaw(s, ticket(d, it, "allow", 80)); r["reason"] != "hardware_required" || r["hardwareRule"] != "hw-score" {
		t.Fatalf("risk 80: %v", r)
	}
	b := ticket(d, it, "allow", 80)
	ten := json.Number("10")
	b.Payload.Risk = &ten
	if r := decideRaw(s, b); r["reason"] != "bad_signature" {
		t.Fatalf("risk tamper: %v", r)
	}
	if r := decideRaw(s, withHW(ticket(d, it, "allow", 80), a)); r["ok"] != true {
		t.Fatalf("risk 80 + key: %v", r)
	}
	if o := wait(t, ch); !o.allow || o.rec.Hardware.Verified == nil || o.rec.Hardware.Rule != "hw-score" {
		t.Fatalf("outcome %+v", o.rec.Hardware)
	}
	// risk 50: no key needed; without risk: same
	for i, risk := range []int{50, -1} {
		ch, it := startExec(t, s, 301+i, "ls", "/")
		if r := decideRaw(s, ticket(d, it, "allow", risk)); r["ok"] != true {
			t.Fatalf("risk %d: %v", risk, r)
		}
		if o := wait(t, ch); !o.allow || o.rec.Hardware.Verified != nil {
			t.Fatalf("risk %d: %+v", risk, o.rec.Hardware)
		}
	}
}

func TestHardwareInheritEscalation(t *testing.T) {
	a := hwkeytest.NewEd25519("wardenclaw")
	d := newDevice()
	s := newHWSupervisor(t, hwPolicy, d, a.Key())
	// root 200 approved without the key (no risk)
	ch, it := startExec(t, s, 200, "bash", "-c", "x")
	if r := decideRaw(s, ticket(d, it, "allow", -1)); r["ok"] != true {
		t.Fatal(r)
	}
	wait(t, ch)
	// its descendant 201 runs rm → a new root that requires the key (does not inherit)
	ch, it = startExec(t, s, 201, "rm", "/tmp/z")
	if it == nil {
		t.Fatal("rm inside non-hardware root inherited")
	}
	if hm := it.Meta["hardware"].(map[string]any); hm["escalated"] != true || hm["required"] != true {
		t.Fatalf("meta %#v", it.Meta)
	}
	if r := decideRaw(s, withHW(ticket(d, it, "allow", -1), a)); r["ok"] != true {
		t.Fatal(r)
	}
	if o := wait(t, ch); !o.allow || o.rec.Class != "root" || !o.rec.Hardware.Escalated {
		t.Fatalf("%+v", o.rec)
	}
	// root 100 approved WITH the key (an assertion that was not required is also verified and counted)
	ch, it = startExec(t, s, 100, "bash", "-c", "y")
	if r := decideRaw(s, withHW(ticket(d, it, "allow", -1), a)); r["ok"] != true {
		t.Fatal(r)
	}
	wait(t, ch)
	// its descendant 101 runs rm → inherited, no new ticket
	ch, it = startExec(t, s, 101, "rm", "/tmp/w")
	if it != nil {
		t.Fatal("rm inside hardware root must inherit")
	}
	if o := wait(t, ch); !o.allow || o.rec.Class != "inherit" {
		t.Fatalf("%+v", o.rec)
	}
}

func TestHardwareNotConfigured(t *testing.T) {
	d := newDevice()
	s := newHWSupervisor(t, hwPolicy, d) // many rules, no keys
	a := hwkeytest.NewEd25519("wardenclaw")
	ch, it := startExec(t, s, 300, "sudo", "ls")
	if r := decideRaw(s, withHW(ticket(d, it, "allow", -1), a)); r["reason"] != "hardware_not_configured" {
		t.Fatal(r)
	}
	s.q.resolve(it.ID, ticketResult{Reason: "test done"})
	if o := wait(t, ch); o.allow {
		t.Fatal("allowed")
	}
	st := s.status()
	if !feature.HWKey { // without the hwkey tag status has no second-factor fields
		for _, k := range []string{"hardwareKeys", "requireHardwareRules", "requireHardware"} {
			if _, ok := st[k]; ok {
				t.Fatalf("status.%s without the hwkey tag: %v", k, st)
			}
		}
		return
	}
	if st["requireHardwareRules"] != 3 {
		t.Fatalf("status %v", st)
	}
	// rule names for the app ("The key is required for: …"), without the argv patterns
	b, err := json.Marshal(st["requireHardware"])
	if err != nil {
		t.Fatal(err)
	}
	if want := `[{"id":"hw-rm"},{"id":"hw-delegating","class":"delegating"},{"id":"hw-score","class":"root","minScore":70}]`; string(b) != want {
		t.Fatalf("requireHardware %s, want %s", b, want)
	}
}

func TestHWRegisterCommand(t *testing.T) {
	if !feature.HWKey {
		t.Skip("hw-register only in a build with the hwkey tag")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"mode":"ticket","ticket_ttl":"90s","trusted_devices":[{"id":"ab"}],"root_exec":{"enabled":false}}`), 0o640)
	a := hwkeytest.NewEd25519("wardenclaw")
	cdj := hwkey.ClientDataJSON("webauthn.create", []byte("0123456789abcdef0123456789abcdef"))
	att := a.MakeCredential(cdj, "packed-x5c")
	blob := (&hwkey.Blob{CredentialID: hwkey.B64(a.CredID), AttestationObject: hwkey.B64(att), ClientDataJSON: hwkey.B64(cdj), RPID: "wardenclaw", Name: "YubiKey 5 NFC"}).Encode()
	var out, errb bytes.Buffer
	if c := cmdHWRegister([]string{"--config", cfgPath, blob}, &out, &errb, time.Now()); c != 0 {
		t.Fatalf("exit %d: %s", c, errb.String())
	}
	// a repeat replaces, not duplicates; the second key via --cose-key
	b := hwkeytest.NewES256("wardenclaw")
	for _, args := range [][]string{{"--config", cfgPath, "--require-uv", blob}, {"--config", cfgPath, "--name", "spare", "--cose-key", hwkey.B64(b.COSE()), "--credential-id", hwkey.B64(b.CredID)}} {
		out.Reset()
		if c := cmdHWRegister(args, &out, &errb, time.Now()); c != 0 {
			t.Fatalf("exit %d: %s", c, errb.String())
		}
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.HardwareKeys) != 2 || cfg.HardwareKeys[0].Name != "YubiKey 5 NFC" || !cfg.HardwareKeys[0].RequireUV || cfg.HardwareKeys[1].Alg != "ES256" || cfg.Mode != "ticket" || cfg.TicketTTL.Duration != 90*time.Second {
		t.Fatalf("config: %+v", cfg)
	}
	raw, _ := os.ReadFile(cfgPath)
	if !bytes.Contains(raw, []byte(`"root_exec"`)) {
		t.Fatal("unknown field dropped")
	}
	if st, _ := os.Stat(cfgPath); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode())
	}
	// the key from the config accepts an assertion
	st, err := hwkey.NewStore(cfg.HardwareKeys, "")
	if err != nil {
		t.Fatal(err)
	}
	c := []byte("challenge-challenge-challenge-32")
	a.Count++
	if _, r := st.VerifyAssertion(a.AssertRaw(hwkey.ClientDataJSON("webauthn.get", c), hwkey.FlagUP|hwkey.FlagUV, a.Count), c); r != "" {
		t.Fatal(r)
	}
	// hw-keys prints both
	out.Reset()
	if cmdHWKeys([]string{"--config", cfgPath}, &out, &errb) != 0 || !strings.Contains(out.String(), "2 hardware key(s)") {
		t.Fatalf("hw-keys: %s %s", out.String(), errb.String())
	}
	// garbage and dry-run
	if cmdHWRegister([]string{"--config", cfgPath, "wchw1:AAAA"}, &out, &errb, time.Now()) == 0 {
		t.Fatal("garbage blob accepted")
	}
	before, _ := os.ReadFile(cfgPath)
	if cmdHWRegister([]string{"--config", cfgPath, "--dry-run", blob}, &out, &errb, time.Now()) != 0 {
		t.Fatal("dry-run")
	}
	if after, _ := os.ReadFile(cfgPath); !bytes.Equal(before, after) {
		t.Fatal("dry-run changed config")
	}
}
