// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Fake external utilities for tests: the test binary, run via a symlink named
// fido2-token / fido2-cred / fido2-assert / security, behaves like that utility.
// FIDO: a software authenticator (like hwkey/hwkeytest), state in $FAKE_FIDO_STATE;
// authenticatorData is output as a CBOR byte string, like the real libfido2 utilities.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/hwkey"
)

func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case "fido2-token":
		fmt.Println("/dev/fakehid0: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)")
		os.Exit(0)
	case "fido2-cred":
		os.Exit(fakeCred(os.Args[1:]))
	case "fido2-assert":
		os.Exit(fakeAssert(os.Args[1:]))
	case "security":
		os.Exit(fakeSecurity(os.Args[1:]))
	}
	code := m.Run()
	for _, f := range afterAll {
		f()
	}
	os.Exit(code)
}

// afterAll: cleanup after all tests (built e2e binaries).
var afterAll []func()

// installFakes: a directory with symlinks to the test binary; WARDENCTL_FIDO2_DIR and state.
func installFakes(t *testing.T, names ...string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, n := range names {
		if err := os.Symlink(exe, filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("FAKE_FIDO_STATE", filepath.Join(t.TempDir(), "fido.json"))
	return dir
}

type fakeFido struct {
	Alg    int64  `json:"alg"`
	Seed   string `json:"seed,omitempty"`
	EC     string `json:"ec,omitempty"`
	CredID string `json:"credId"`
	Count  uint32 `json:"count"`
}

func (f *fakeFido) cose() []byte {
	if f.Alg == hwkey.AlgEdDSA {
		s, _ := hex.DecodeString(f.Seed)
		return hwkey.EncodeCOSEEd25519(ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey))
	}
	return hwkey.EncodeCOSEES256(&f.ec().PublicKey)
}

func (f *fakeFido) ec() *ecdsa.PrivateKey {
	d, _ := hex.DecodeString(f.EC)
	k, _ := x509.ParseECPrivateKey(d)
	return k
}

func (f *fakeFido) sign(msg []byte) []byte {
	if f.Alg == hwkey.AlgEdDSA {
		s, _ := hex.DecodeString(f.Seed)
		return ed25519.Sign(ed25519.NewKeyFromSeed(s), msg)
	}
	h := sha256.Sum256(msg)
	sig, _ := ecdsa.SignASN1(rand.Reader, f.ec(), h[:])
	return sig
}

func loadFake() (*fakeFido, error) {
	b, err := os.ReadFile(os.Getenv("FAKE_FIDO_STATE"))
	if err != nil {
		return nil, err
	}
	var f fakeFido
	return &f, json.Unmarshal(b, &f)
}

func (f *fakeFido) save() {
	b, _ := json.Marshal(f)
	os.WriteFile(os.Getenv("FAKE_FIDO_STATE"), b, 0o600)
}

// fakeArgs: flags, -i/-o, the rest positional.
func fakeArgs(args []string) (flags map[string]bool, in, out string, pos []string) {
	flags = map[string]bool{}
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-i" && i+1 < len(args):
			in, i = args[i+1], i+1
		case a == "-o" && i+1 < len(args):
			out, i = args[i+1], i+1
		case strings.HasPrefix(a, "-"):
			for _, c := range a[1:] {
				flags[string(c)] = true
			}
		default:
			pos = append(pos, a)
		}
	}
	return
}

func readInput(path string) []string {
	b, _ := os.ReadFile(path)
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func cborBytes(b []byte) []byte { return hwkey.EncodeCBOR(b) }

var yubiAAGUID = []byte{0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13, 0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97, 0x07, 0x2a}

func fakeCred(args []string) int {
	flags, in, out, pos := fakeArgs(args)
	if !flags["M"] || in == "" || out == "" || len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "usage: fido2-cred -M -i in -o out dev [type]")
		return 1
	}
	typ := "es256"
	if len(pos) > 1 {
		typ = pos[1]
	}
	if typ == "eddsa" && os.Getenv("FAKE_FIDO_NO_EDDSA") == "1" {
		fmt.Fprintln(os.Stderr, "fido2-cred: fido_dev_make_cred: FIDO_ERR_UNSUPPORTED_ALGORITHM")
		return 1
	}
	lines := readInput(in)
	cdh, _ := base64.StdEncoding.DecodeString(lines[0])
	rp := lines[1]
	f := &fakeFido{CredID: hex.EncodeToString(randBytes(48))}
	if typ == "eddsa" {
		f.Alg = hwkey.AlgEdDSA
		f.Seed = hex.EncodeToString(randBytes(32))
	} else {
		f.Alg = hwkey.AlgES256
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		d, _ := x509.MarshalECPrivateKey(k)
		f.EC = hex.EncodeToString(d)
	}
	f.Count = 1
	credID, _ := hex.DecodeString(f.CredID)
	fl := hwkey.FlagUP | hwkey.FlagAT
	if flags["v"] {
		fl |= hwkey.FlagUV
	}
	auth := hwkey.BuildAuthData(rp, fl, f.Count, yubiAAGUID, credID, f.cose())
	signed := append(append([]byte{}, auth...), cdh...)
	format, sig, cert := "packed", []byte(nil), []byte(nil)
	switch os.Getenv("FAKE_FIDO_ATT") {
	case "self":
		sig = f.sign(signed)
	case "u2f":
		format = "fido-u2f"
		sig = f.sign(signed) // wardend does not parse fido-u2f; wardenctl gives --cose-key
	default: // x5c, like a YubiKey: P-256 attestation certificate
		ak, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ext, _ := asn1.Marshal(yubiAAGUID)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake Yubico U2F EE Serial 1"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}, Value: ext}}}
		cert, _ = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ak.PublicKey, ak)
		h := sha256.Sum256(signed)
		sig, _ = ecdsa.SignASN1(rand.Reader, ak, h[:])
	}
	f.save()
	o := []string{lines[0], rp, format, b64s(cborBytes(auth)), b64s(credID), b64s(sig)}
	if cert != nil {
		o = append(o, b64s(cert))
	}
	os.WriteFile(out, []byte(strings.Join(o, "\n")+"\n"), 0o600)
	return 0
}

func fakeAssert(args []string) int {
	flags, in, out, pos := fakeArgs(args)
	if !flags["G"] || in == "" || out == "" || len(pos) != 1 {
		fmt.Fprintln(os.Stderr, "usage: fido2-assert -G -i in -o out dev")
		return 1
	}
	f, err := loadFake()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fido2-assert: fido_dev_get_assert: FIDO_ERR_NO_CREDENTIALS")
		return 1
	}
	lines := readInput(in)
	cdh, _ := base64.StdEncoding.DecodeString(lines[0])
	rp := lines[1]
	cid, _ := base64.StdEncoding.DecodeString(lines[2])
	if hex.EncodeToString(cid) != f.CredID {
		fmt.Fprintln(os.Stderr, "fido2-assert: fido_dev_get_assert: FIDO_ERR_NO_CREDENTIALS")
		return 1
	}
	f.Count++
	f.save()
	var fl byte
	if flags["p"] {
		fl |= hwkey.FlagUP
	}
	if flags["v"] {
		fl |= hwkey.FlagUV
	}
	auth := hwkey.BuildAuthData(rp, fl, f.Count, nil, nil, nil)
	sig := f.sign(append(append([]byte{}, auth...), cdh...))
	os.WriteFile(out, []byte(strings.Join([]string{lines[0], rp, b64s(cborBytes(auth)), b64s(sig)}, "\n")+"\n"), 0o600)
	return 0
}

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
func b64s(b []byte) string   { return base64.StdEncoding.EncodeToString(b) }

// fakeSecurity: /usr/bin/security: add (via -i), find -w, delete. The store is a JSON file, the
// argv of every call is appended to $FAKE_SECURITY_STORE.argv (test: the seed did not end up in argv).
func fakeSecurity(args []string) int {
	store := os.Getenv("FAKE_SECURITY_STORE")
	af, _ := os.OpenFile(store+".argv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	fmt.Fprintln(af, strings.Join(args, " "))
	af.Close()
	m := map[string]string{}
	if b, err := os.ReadFile(store); err == nil {
		json.Unmarshal(b, &m)
	}
	opt := func(a []string, k string) string {
		for i := 0; i+1 < len(a); i++ {
			if a[i] == k {
				return a[i+1]
			}
		}
		return ""
	}
	notFound := func() int {
		fmt.Fprintln(os.Stderr, "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.")
		return 44
	}
	if len(args) == 0 {
		return 1
	}
	switch args[0] {
	case "-i":
		// Like the real one: a command error inside -i does not change the exit code. Entry ACL in
		// "acl:<key>": security (without -T security itself becomes trusted) or prompt (-T "", parsing
		// -i gives an empty argument). FAKE_SECURITY_FAIL_PROMPT=1: an entry with -T "" is not created.
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			a := strings.Fields(sc.Text())
			if len(a) == 0 || a[0] != "add-generic-password" {
				continue
			}
			k := opt(a, "-s") + "/" + opt(a, "-a")
			acl := "security"
			if opt(a, "-T") == `""` {
				acl = "prompt"
				if os.Getenv("FAKE_SECURITY_FAIL_PROMPT") != "" {
					fmt.Fprintln(os.Stderr, "security: SecKeychainItemCreateFromContent: test failure")
					continue
				}
			}
			if _, exists := m[k]; exists && !slices.Contains(a, "-U") {
				fmt.Fprintln(os.Stderr, "security: SecKeychainItemCreateFromContent: The specified item already exists in the keychain.")
				continue
			}
			m[k] = opt(a, "-w")
			m["acl:"+k] = acl
		}
	case "find-generic-password":
		v, ok := m[opt(args, "-s")+"/"+opt(args, "-a")]
		if !ok {
			return notFound()
		}
		fmt.Println(v)
		return 0
	case "delete-generic-password":
		k := opt(args, "-s") + "/" + opt(args, "-a")
		if _, ok := m[k]; !ok {
			return notFound()
		}
		delete(m, k)
		delete(m, "acl:"+k)
	default:
		return 1
	}
	b, _ := json.Marshal(m)
	os.WriteFile(store, b, 0o600)
	return 0
}
