// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build hwkey

package main

// Only in a build with the hwkey tag (daemon/docs/hwkey.md), without the tag hw_off.go.
// Second YubiKey signature over USB through the libfido2 utilities (fido2-token, fido2-cred,
// fido2-assert) as external programs: no cgo, the binary is cross-compiled.
// Format of challenge and clientDataJSON: protocol/HARDWARE.md (same as the app over NFC):
//
//	challenge      = envelope.HWChallenge(deviceId, payload)
//	clientDataJSON = {"type":"webauthn.get","challenge":"<b64url>","origin":"wardenclaw:app"}
//	fido2-assert gets sha256(clientDataJSON), rpId "wardenclaw" and credentialId;
//	the key signs authenticatorData || sha256(clientDataJSON).
//
// The utilities output authenticatorData as a CBOR byte string (fido_*_authdata_ptr): we unwrap it.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/hwkey"
)

const fidoInstallHint = "install libfido2 (macOS: brew install libfido2; Debian/Ubuntu: sudo apt install fido2-tools; Fedora: sudo dnf install libfido2)"

// Timeouts of the libfido2 utilities: listing devices is quick, a touch or a PIN waits for a human.
const (
	fidoListTimeout = 15 * time.Second
	fidoTimeout     = 2 * time.Minute
)

// fidoTool: path to the utility: $WARDENCTL_FIDO2_DIR/<name> or PATH.
func fidoTool(name string) (string, error) {
	if d := os.Getenv("WARDENCTL_FIDO2_DIR"); d != "" {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
		return "", fmt.Errorf("utility %s not found in WARDENCTL_FIDO2_DIR=%s: %s", name, d, fidoInstallHint)
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("utility %s (libfido2) not found, cannot sign with a YubiKey over USB without it: %s", name, fidoInstallHint)
	}
	return p, nil
}

type fidoDevice struct {
	Path string
	Desc string
}

// parseTokenList: output of `fido2-token -L`:
//
//	/dev/hidraw4: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)
//	ioreg://4294971234: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)
func parseTokenList(out string) []fidoDevice {
	var ds []fidoDevice
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		i := strings.Index(l, ": vendor=")
		if i < 0 {
			i = strings.LastIndex(l, ": ")
		}
		if i <= 0 {
			continue
		}
		ds = append(ds, fidoDevice{Path: l[:i], Desc: strings.TrimSpace(l[i+2:])})
	}
	return ds
}

// pickDevice: --device / $WARDENCTL_FIDO_DEVICE, otherwise the only key found.
func pickDevice(flagDev string) (string, error) {
	if flagDev == "" {
		flagDev = os.Getenv("WARDENCTL_FIDO_DEVICE")
	}
	if flagDev != "" {
		return flagDev, nil
	}
	bin, err := fidoTool("fido2-token")
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), fidoListTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-L").Output()
	if err != nil {
		return "", fmt.Errorf("fido2-token -L: %v", err)
	}
	ds := parseTokenList(string(out))
	switch len(ds) {
	case 0:
		return "", errors.New("YubiKey not found over USB (fido2-token -L is empty): insert the key; on Linux you need access to /dev/hidraw* (libfido2 udev rules)")
	case 1:
		return ds[0].Path, nil
	}
	var b strings.Builder
	for _, d := range ds {
		fmt.Fprintf(&b, "\n  %s  %s", d.Path, d.Desc)
	}
	return "", fmt.Errorf("several FIDO keys found, choose --device (or WARDENCTL_FIDO_DEVICE):%s", b.String())
}

// runFido: runs the utility with input in a temporary file (-i) and output to a file (-o): stdin/tty
// stay free for the PIN prompt (libfido2 asks for it on /dev/tty).
func runFido(bin string, args []string, input string, stderr io.Writer) ([]string, error) {
	dir, err := os.MkdirTemp("", "wardenctl-fido-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	if err := os.WriteFile(in, []byte(input), 0o600); err != nil {
		return nil, err
	}
	full := append([]string{}, args[:len(args)-1]...)
	full = append(full, "-i", in, "-o", out, args[len(args)-1])
	ctx, cancel := context.WithTimeout(context.Background(), fidoTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, full...)
	var eb bytes.Buffer
	cmd.Stderr = io.MultiWriter(&eb, stderr)
	cmd.Stdout = stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(eb.String())
		hint := ""
		switch {
		case strings.Contains(msg, "FIDO_ERR_PIN_REQUIRED") || strings.Contains(msg, "FIDO_ERR_UV_"):
			hint = ": the key requires a PIN: add --uv"
		case strings.Contains(msg, "FIDO_ERR_NO_CREDENTIALS"):
			hint = ": this key has no bound credential (another YubiKey? wardenctl hw-register)"
		case strings.Contains(msg, "FIDO_ERR_ACTION_TIMEOUT") || strings.Contains(msg, "FIDO_ERR_USER_ACTION_TIMEOUT"):
			hint = ": no touch received in time"
		case strings.Contains(msg, "FIDO_ERR_UNSUPPORTED_ALGORITHM"):
			hint = ": the key does not support this algorithm"
		}
		if ctx.Err() != nil {
			hint = ": timeout 2 min"
		}
		return nil, fmt.Errorf("%s: %v%s", filepath.Base(bin), err, hint)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		lines = append(lines, strings.TrimRight(sc.Text(), "\r"))
	}
	return lines, nil
}

func b64std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// decodeB64Any: standard base64 of the utilities (or base64url).
func decodeB64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return hwkey.DecodeB64(s)
}

// unwrapAuthData: authenticatorData from the libfido2 utilities comes as a CBOR byte string; raw
// data starts with rpIdHash. We unwrap only if the CBOR header exactly describes the whole length
// and the content is the rpIdHash of the expected rpId.
func unwrapAuthData(b []byte, rpID string) []byte {
	want := sha256.Sum256([]byte(rpID))
	if len(b) >= 32 && bytes.Equal(b[:32], want[:]) {
		return b
	}
	if len(b) < 2 || b[0]>>5 != 2 {
		return b
	}
	ai := b[0] & 0x1f
	var n uint64
	hdr := 1
	switch {
	case ai < 24:
		n = uint64(ai)
	case ai == 24:
		n, hdr = uint64(b[1]), 2
	case ai == 25 && len(b) >= 3:
		n, hdr = uint64(binary.BigEndian.Uint16(b[1:3])), 3
	case ai == 26 && len(b) >= 5:
		n, hdr = uint64(binary.BigEndian.Uint32(b[1:5])), 5
	default:
		return b
	}
	if uint64(len(b)-hdr) != n {
		return b
	}
	return b[hdr:]
}

// hwAssert: YubiKey assertion over clientDataJSON for the bound credential.
func hwAssert(cred *HWCred, device string, uv bool, clientDataJSON []byte, stderr io.Writer) (*hwkey.Assertion, error) {
	bin, err := fidoTool("fido2-assert")
	if err != nil {
		return nil, err
	}
	dev, err := pickDevice(device)
	if err != nil {
		return nil, err
	}
	credID, err := hwkey.DecodeB64(cred.CredentialID)
	if err != nil {
		return nil, errors.New("corrupted credentialId in server.json")
	}
	cdh := sha256.Sum256(clientDataJSON)
	input := b64std(cdh[:]) + "\n" + cred.RPID + "\n" + b64std(credID) + "\n"
	args := []string{"-G", "-p"}
	if uv || cred.RequireUV {
		args = append(args, "-v")
	}
	args = append(args, dev)
	fmt.Fprintf(stderr, "Touch the YubiKey (%s)…\n", dev)
	lines, err := runFido(bin, args, input, stderr)
	if err != nil {
		return nil, err
	}
	if len(lines) < 4 {
		return nil, fmt.Errorf("fido2-assert: unexpected output (%d lines)", len(lines))
	}
	gotCDH, err := decodeB64Any(lines[0])
	if err != nil || !bytes.Equal(gotCDH, cdh[:]) || lines[1] != cred.RPID {
		return nil, errors.New("fido2-assert: response is not for this request (clientDataHash/rpId)")
	}
	ad, err := decodeB64Any(lines[2])
	if err != nil {
		return nil, fmt.Errorf("fido2-assert: authenticatorData: %v", err)
	}
	sig, err := decodeB64Any(lines[3])
	if err != nil {
		return nil, fmt.Errorf("fido2-assert: signature: %v", err)
	}
	ad = unwrapAuthData(ad, cred.RPID)
	a := &hwkey.Assertion{CredentialID: hwkey.B64(credID), ClientDataJSON: hwkey.B64(clientDataJSON),
		AuthenticatorData: hwkey.B64(ad), Signature: hwkey.B64(sig)}
	if err := verifyLocal(cred, ad, clientDataJSON, sig); err != nil {
		return nil, err
	}
	return a, nil
}

// verifyLocal: the same signature and flag check that wardend will do (except the counter): the
// error is visible right away, not as a server rejection.
func verifyLocal(cred *HWCred, authData, clientDataJSON, sig []byte) error {
	raw, err := hwkey.DecodeB64(cred.PublicKey)
	if err != nil {
		return errors.New("corrupted YubiKey publicKey in server.json")
	}
	k, err := hwkey.ParseCOSEKey(raw)
	if err != nil {
		return err
	}
	a, err := hwkey.ParseAuthData(authData)
	if err != nil {
		return fmt.Errorf("YubiKey: %v", err)
	}
	if a.RPIDHash != sha256.Sum256([]byte(cred.RPID)) {
		return errors.New("YubiKey: rpIdHash does not match")
	}
	if a.Flags&hwkey.FlagUP == 0 {
		return errors.New("YubiKey did not confirm a touch (UP)")
	}
	cdh := sha256.Sum256(clientDataJSON)
	if !k.Verify(append(append([]byte{}, authData...), cdh[:]...), sig) {
		return errors.New("YubiKey signature does not match the key bound in wardenctl (another key?)")
	}
	return nil
}

// hwRegistration: result of `fido2-cred -M`: the record for wardend and a local copy.
type hwRegistration struct {
	Cred    HWCred
	Blob    string // wchw1:… for `wardend hw-register`
	Command string // ready-made line for the server
	Format  string
}

// credOutput: what `fido2-cred -M` printed about the new credential.
type credOutput struct {
	format   string // attestation format: packed, none, fido-u2f…
	authData []byte // unwrapped from the CBOR byte string
	credID   []byte
	sig      []byte // attestation signature, may be empty
	x5c      []byte // attestation certificate, if there is one
}

// parseCredOutput: the output of `fido2-cred -M` for this request. The first two lines echo the
// clientDataHash and the rpId; then come the format, authenticatorData, credentialId, the
// signature and an optional seventh line.
func parseCredOutput(lines []string, cdh []byte, rpID string) (credOutput, error) {
	var out credOutput
	if len(lines) < 6 {
		return out, fmt.Errorf("fido2-cred: unexpected output (%d lines)", len(lines))
	}
	gotCDH, err := decodeB64Any(lines[0])
	if err != nil || !bytes.Equal(gotCDH, cdh) || lines[1] != rpID {
		return out, errors.New("fido2-cred: response is not for this request")
	}
	out.format = lines[2]
	ad, err := decodeB64Any(lines[3])
	if err != nil {
		return out, fmt.Errorf("fido2-cred: authenticatorData: %v", err)
	}
	out.authData = unwrapAuthData(ad, rpID)
	out.credID, err = decodeB64Any(lines[4])
	if err != nil || len(out.credID) == 0 {
		return out, errors.New("fido2-cred: credentialId")
	}
	if strings.TrimSpace(lines[5]) != "" {
		if out.sig, err = decodeB64Any(lines[5]); err != nil {
			return out, fmt.Errorf("fido2-cred: signature: %v", err)
		}
	}
	if len(lines) >= 7 && strings.TrimSpace(lines[6]) != "" {
		if c, err := decodeB64Any(lines[6]); err == nil {
			if _, perr := x509.ParseCertificate(c); perr == nil {
				out.x5c = c // line 7 is a certificate; otherwise it is largeBlobKey (not requested)
			}
		}
	}
	return out, nil
}

// hwMakeCredential: create a credential (rpId wardenclaw) and build the wchw1 blob in the app's format.
func hwMakeCredential(device, alg, name, userName string, userID []byte, uv, requireUV bool, stderr io.Writer, now time.Time) (*hwRegistration, error) {
	bin, err := fidoTool("fido2-cred")
	if err != nil {
		return nil, err
	}
	dev, err := pickDevice(device)
	if err != nil {
		return nil, err
	}
	rpID := hwkey.DefaultRPID
	challenge := make([]byte, 32)
	rand.Read(challenge)
	cdj := hwkey.ClientDataJSON("webauthn.create", challenge)
	cdh := sha256.Sum256(cdj)
	input := b64std(cdh[:]) + "\n" + rpID + "\n" + strings.ReplaceAll(userName, "\n", " ") + "\n" + b64std(userID) + "\n"
	algs := []string{alg}
	if alg == "" || alg == "auto" {
		algs = []string{"eddsa", "es256"}
	}
	var lines []string
	for i, a := range algs {
		args := []string{"-M"}
		if uv {
			args = append(args, "-v")
		}
		args = append(args, dev, a)
		fmt.Fprintf(stderr, "Creating a %s key for rpId %q on %s: touch the YubiKey…\n", strings.ToUpper(a), rpID, dev)
		lines, err = runFido(bin, args, input, stderr)
		if err == nil {
			break
		}
		if i == len(algs)-1 || !strings.Contains(err.Error(), "algorithm") {
			return nil, err
		}
		fmt.Fprintf(stderr, "%v; trying %s\n", err, strings.ToUpper(algs[i+1]))
	}
	out, err := parseCredOutput(lines, cdh[:], rpID)
	if err != nil {
		return nil, err
	}
	format, ad, credID, sig, x5c := out.format, out.authData, out.credID, out.sig, out.x5c
	a, err := hwkey.ParseAuthData(ad)
	if err != nil {
		return nil, fmt.Errorf("fido2-cred: %v", err)
	}
	if a.CredKey == nil || !bytes.Equal(a.CredentialID, credID) {
		return nil, errors.New("fido2-cred: authenticatorData without a key or with another credentialId")
	}
	if name == "" {
		name = "YubiKey (wardenctl)"
	}
	reg := &hwRegistration{Format: format}
	reg.Cred = HWCred{CredentialID: hwkey.B64(credID), RPID: rpID, Alg: hwkey.AlgName(a.CredKey.Alg), PublicKey: hwkey.B64(a.CredKey.Raw),
		Name: name, RequireUV: requireUV, AddedAt: now.UTC().Format(time.RFC3339)}
	uvFlag := ""
	if requireUV {
		uvFlag = " --require-uv"
	}
	switch format {
	case "packed", "none":
		stmt := map[any]any{}
		if format == "packed" {
			alg := a.CredKey.Alg // self attestation
			if x5c != nil {
				cert, _ := x509.ParseCertificate(x5c)
				switch cert.PublicKey.(type) {
				case *ecdsa.PublicKey:
					alg = hwkey.AlgES256
				case ed25519.PublicKey:
					alg = hwkey.AlgEdDSA
				}
				stmt["x5c"] = []any{x5c}
			}
			stmt["alg"] = alg
			stmt["sig"] = sig
		}
		att := hwkey.EncodeCBOR(map[any]any{"fmt": format, "authData": ad, "attStmt": stmt})
		// the same check that `wardend hw-register` will do
		if _, err := hwkey.ParseRegistration(att, cdj, rpID, now); err != nil {
			return nil, fmt.Errorf("registration would not pass the wardend check: %v", err)
		}
		reg.Blob = (&hwkey.Blob{CredentialID: hwkey.B64(credID), AttestationObject: hwkey.B64(att), ClientDataJSON: hwkey.B64(cdj), RPID: rpID, Name: name}).Encode()
		reg.Command = "wardend hw-register" + uvFlag + " '" + reg.Blob + "'"
	default: // fido-u2f and others: wardend accepts a bare COSE key without attestation
		reg.Command = fmt.Sprintf("wardend hw-register%s --name %s --cose-key %s --credential-id %s", uvFlag, shellQuote([]string{name}), hwkey.B64(a.CredKey.Raw), hwkey.B64(credID))
	}
	return reg, nil
}
