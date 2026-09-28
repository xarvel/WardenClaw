// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build hwkey

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/hwkey"
)

func TestUnwrapAuthData(t *testing.T) {
	raw := hwkey.BuildAuthData("wardenclaw", hwkey.FlagUP, 7, nil, nil, nil)
	if !bytes.Equal(unwrapAuthData(raw, "wardenclaw"), raw) {
		t.Fatal("raw data must not be touched")
	}
	if !bytes.Equal(unwrapAuthData(hwkey.EncodeCBOR(raw), "wardenclaw"), raw) {
		t.Fatal("CBOR byte string was not unwrapped")
	}
	long := hwkey.BuildAuthData("wardenclaw", hwkey.FlagUP|hwkey.FlagAT, 1, make([]byte, 16), make([]byte, 300), hwkey.EncodeCOSEEd25519(make([]byte, 32)))
	if !bytes.Equal(unwrapAuthData(hwkey.EncodeCBOR(long), "wardenclaw"), long) {
		t.Fatal("long one (2-byte length) was not unwrapped")
	}
	junk := []byte{0x58, 0x05, 1, 2}
	if !bytes.Equal(unwrapAuthData(junk, "wardenclaw"), junk) {
		t.Fatal("wrong length: must not unwrap")
	}
}

func TestParseTokenList(t *testing.T) {
	ds := parseTokenList("/dev/hidraw4: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)\n" +
		"ioreg://4294971234: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)\n\n")
	if len(ds) != 2 || ds[0].Path != "/dev/hidraw4" || ds[1].Path != "ioreg://4294971234" || !strings.Contains(ds[1].Desc, "Yubico") {
		t.Fatalf("%+v", ds)
	}
}

// hw-register → the blob passes wardend parsing → an assertion over the ticket challenge passes the
// wardend check (hwkey.Store: the same code as in supervisor.checkHardware).
func TestHWRegisterBlobAndAssertion(t *testing.T) {
	for _, tc := range []struct{ name, att, noEd string }{{"x5c-eddsa", "", ""}, {"self-es256-fallback", "self", "1"}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("WARDENCTL_FIDO2_DIR", installFakes(t, "fido2-token", "fido2-cred", "fido2-assert"))
			t.Setenv("FAKE_FIDO_ATT", tc.att)
			t.Setenv("FAKE_FIDO_NO_EDDSA", tc.noEd)
			dir := t.TempDir()
			writeTestState(t, dir)
			a, out, errb := testApp(dir, "")
			if code := a.run(context.Background(), []string{"hw-register", "--name", "YK test"}); code != 0 {
				t.Fatalf("code %d\n%s\n%s", code, out, errb)
			}
			m := blobRe.FindStringSubmatch(out.String())
			if m == nil {
				t.Fatalf("no wardend hw-register command:\n%s", out)
			}
			b, err := hwkey.ParseBlob(m[1])
			if err != nil {
				t.Fatal(err)
			}
			att, _ := hwkey.DecodeB64(b.AttestationObject)
			cdj, _ := hwkey.DecodeB64(b.ClientDataJSON)
			reg, err := hwkey.ParseRegistration(att, cdj, b.RPID, time.Now())
			if err != nil {
				t.Fatalf("wardend would not accept the blob: %v", err)
			}
			wantAlg := "EdDSA"
			if tc.noEd == "1" {
				wantAlg = "ES256"
			}
			if reg.Key.Alg != wantAlg || b.Name != "YK test" {
				t.Fatalf("alg %s name %s", reg.Key.Alg, b.Name)
			}
			st, _ := loadState(dir)
			if st.HW == nil || st.HW.CredentialID != reg.Key.ID || st.HW.PublicKey != reg.Key.PublicKey {
				t.Fatalf("state.hw %+v", st.HW)
			}
			// assertion for the ticket
			store, err := hwkey.NewStore([]hwkey.Key{reg.Key}, filepath.Join(t.TempDir(), "hw_counters.json"))
			if err != nil {
				t.Fatal(err)
			}
			priv, _ := deviceKey(dir, st)
			digest := strings.Repeat("ab", 32)
			for i := 0; i < 2; i++ {
				body, cdj, err := signTicket(priv, st.SupervisorID, envelope.PendingID(digest), digest, "allow", time.Now().UnixMilli(), envelope.NewNonce())
				if err != nil {
					t.Fatal(err)
				}
				asr, err := hwAssert(st.HW, "", false, cdj, &bytes.Buffer{})
				if err != nil {
					t.Fatal(err)
				}
				ch, _ := envelope.HWChallenge(body.DeviceID, body.Payload)
				if res, reason := store.VerifyAssertion(asr, ch); reason != "" || res == nil {
					t.Fatalf("wardend rejected the assertion: %s", reason)
				}
				// another ticket with this assertion does not pass
				other, _, _ := signTicket(priv, st.SupervisorID, envelope.PendingID(digest), digest, "allow", time.Now().UnixMilli(), envelope.NewNonce())
				ch2, _ := envelope.HWChallenge(other.DeviceID, other.Payload)
				if _, reason := store.VerifyAssertion(asr, ch2); reason != "hw_challenge_mismatch" {
					t.Fatalf("assertion fit another ticket: %q", reason)
				}
			}
			// hw-check
			a, out, errb = testApp(dir, "")
			if code := a.run(context.Background(), []string{"hw-check"}); code != 0 || !strings.Contains(out.String(), "YubiKey OK") {
				t.Fatalf("hw-check %d\n%s\n%s", code, out, errb)
			}
		})
	}
}

func TestHWRegisterU2FGivesCoseCommand(t *testing.T) {
	t.Setenv("WARDENCTL_FIDO2_DIR", installFakes(t, "fido2-token", "fido2-cred", "fido2-assert"))
	t.Setenv("FAKE_FIDO_ATT", "u2f")
	dir := t.TempDir()
	writeTestState(t, dir)
	a, out, errb := testApp(dir, "")
	if code := a.run(context.Background(), []string{"hw-register", "--alg", "es256", "--require-uv"}); code != 0 {
		t.Fatalf("%d %s", code, errb)
	}
	m := regexp.MustCompile(`--require-uv --name .* --cose-key (\S+) --credential-id (\S+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("%s", out)
	}
	if _, err := hwkey.KeyFromCOSE(m[1], m[2], "", time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestFidoToolMissing(t *testing.T) {
	t.Setenv("WARDENCTL_FIDO2_DIR", t.TempDir())
	dir := t.TempDir()
	st := writeTestState(t, dir)
	st.HW = &HWCred{CredentialID: "AAAA", RPID: "wardenclaw", PublicKey: "AA"}
	saveState(dir, st)
	a, _, errb := testApp(dir, "")
	if code := a.run(context.Background(), []string{"hw-check"}); code != 1 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(errb.String(), "utility fido2-assert not found") || !strings.Contains(errb.String(), "brew install libfido2") {
		t.Fatalf("%s", errb)
	}
	// and via PATH
	t.Setenv("WARDENCTL_FIDO2_DIR", "")
	t.Setenv("PATH", t.TempDir())
	if _, err := fidoTool("fido2-assert"); err == nil || !strings.Contains(err.Error(), "apt install fido2-tools") {
		t.Fatalf("%v", err)
	}
}

func TestAssertWrongKeyCaughtLocally(t *testing.T) {
	t.Setenv("WARDENCTL_FIDO2_DIR", installFakes(t, "fido2-token", "fido2-cred", "fido2-assert"))
	dir := t.TempDir()
	writeTestState(t, dir)
	a, _, errb := testApp(dir, "")
	if a.run(context.Background(), []string{"hw-register"}) != 0 {
		t.Fatal(errb)
	}
	st, _ := loadState(dir)
	// substitute the public key: an assertion of the real key must not "pass" locally
	st.HW.PublicKey = hwkey.B64(hwkey.EncodeCOSEEd25519(make([]byte, 32)))
	cdj := hwkey.ClientDataJSON("webauthn.get", sha256.New().Sum(nil))
	if _, err := hwAssert(st.HW, "", false, cdj, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("%v", err)
	}
}

func TestKeychainStoreViaSecurity(t *testing.T) {
	fk := installFakes(t, "security")
	store := filepath.Join(t.TempDir(), "kc.json")
	t.Setenv("FAKE_SECURITY_STORE", store)
	t.Setenv("WARDENCTL_SECURITY_BIN", filepath.Join(fk, "security"))
	ks, err := keyStoreByName("keychain", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	priv := seedKey(t, strings.Repeat("7a", 32))
	id := deviceIDOf(priv)
	if err := ks.Save(id, priv.Seed()); err != nil {
		t.Fatal(err)
	}
	got, err := ks.Load(id)
	if err != nil || !bytes.Equal(got, priv.Seed()) {
		t.Fatalf("%x %v", got, err)
	}
	argv, _ := os.ReadFile(store + ".argv")
	if strings.Contains(string(argv), strings.Repeat("7a", 32)) {
		t.Fatal("seed ended up in security argv")
	}
	if err := ks.Delete(id); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Load(id); err == nil {
		t.Fatal("key not deleted")
	}
	if err := ks.Delete(id); err != nil {
		t.Fatalf("repeated delete: %v", err)
	}
	if err := ks.Save("../x", priv.Seed()); err == nil {
		t.Fatal("account is not hex")
	}
}

func TestFileStorePerms(t *testing.T) {
	dir := t.TempDir()
	st := writeTestState(t, dir)
	fi, _ := os.Stat(filepath.Join(dir, "device.key"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", fi.Mode().Perm())
	}
	os.Chmod(filepath.Join(dir, "device.key"), 0o644)
	if _, err := deviceKey(dir, st); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("%v", err)
	}
}
