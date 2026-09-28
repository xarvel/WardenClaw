// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build hwkey

package main

// YubiKey commands: only in a build with the hwkey tag (daemon/docs/hwkey.md), without the tag hw_off.go.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/hwkey"
)

func (a *app) cmdHWRegister(args []string) int {
	fs := a.flags("hw-register")
	device := fs.String("device", "", "FIDO device (otherwise the only one from fido2-token -L)")
	name := fs.String("name", "", "key name in wardend (default \"YubiKey (wardenctl)\")")
	alg := fs.String("alg", "auto", "auto (EdDSA, otherwise ES256) | eddsa | es256")
	uv := fs.Bool("uv", false, "ask for the key PIN on creation (if the key has a PIN set, it is required)")
	requireUV := fs.Bool("require-uv", false, "wardend will require the key PIN in every signature")
	if _, code, ok := a.parseCmd(fs, args, cmdSpec{guarded: true}); !ok {
		return code
	}
	switch *alg {
	case "auto", "eddsa", "es256":
	default:
		return a.errf("--alg: auto|eddsa|es256")
	}
	st, err := loadState(a.dir)
	if err != nil {
		return a.errf("%v", err)
	}
	userID, _ := hex.DecodeString(st.DeviceID)
	reg, err := hwMakeCredential(*device, *alg, *name, "wardenctl "+envelope.Fingerprint(st.DeviceID), userID, *uv || *requireUV, *requireUV, a.stderr, a.now())
	if err != nil {
		return a.errf("%v", err)
	}
	st.HW = &reg.Cred
	if err := saveState(a.dir, st); err != nil {
		return a.errf("%v", err)
	}
	fmt.Fprintf(a.stdout, "YubiKey bound: %s, credentialId %s… (attestation %s)\n\n", reg.Cred.Alg, clip(reg.Cred.CredentialID, 16), reg.Format)
	fmt.Fprintf(a.stdout, "On the server run this and restart wardend:\n\n%s\n\n", reg.Command)
	fmt.Fprintln(a.stdout, "Then: wardenctl status will show that wardend knows this key.")
	return 0
}

func (a *app) cmdHWCheck(args []string) int {
	fs := a.flags("hw-check")
	device := fs.String("device", "", "FIDO device")
	uv := fs.Bool("uv", false, "with PIN")
	if _, code, ok := a.parseCmd(fs, args, cmdSpec{guarded: true}); !ok {
		return code
	}
	st, err := loadState(a.dir)
	if err != nil {
		return a.errf("%v", err)
	}
	if st.HW == nil {
		return a.errf("YubiKey not bound: wardenctl hw-register")
	}
	ch := make([]byte, 32)
	rand.Read(ch)
	asr, err := hwAssert(st.HW, *device, *uv, hwkey.ClientDataJSON("webauthn.get", ch), a.stderr)
	if err != nil {
		return a.errf("%v", err)
	}
	ad, _ := hwkey.DecodeB64(asr.AuthenticatorData)
	pa, _ := hwkey.ParseAuthData(ad)
	fmt.Fprintf(a.stdout, "YubiKey OK: signature matches the bound key, touch present, UV=%v, signCount %d\n", pa.Flags&hwkey.FlagUV != 0, pa.SignCount)
	return 0
}
