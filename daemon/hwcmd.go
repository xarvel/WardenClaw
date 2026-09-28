// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build hwkey

package main

// Second-factor commands (hwkey build tag only, docs/hwkey.md; without the tag: hwcmd_off.go):
//
//	wardend hw-register [--config f] [--name n] [--rp-id wardenclaw] [--require-uv] [--dry-run]
//	                    (<wchw1:…> | --attestation <b64url|@file> [--client-data <b64url|@file>]
//	                     | --cose-key <b64url> --credential-id <b64url>)
//	wardend hw-keys [--config f]
//
// hw-register adds (or replaces by credentialId) an entry in hardware_keys of the config.
// Other config keys are kept as is (the JSON is rewritten with indentation, top-level keys in
// alphabetical order). The supervisor reads the config at startup: restart wardend after
// registration.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/hwkey"
)

// readArg returns the flag value v, or the trimmed contents of the file f when v is "@f".
func readArg(v string) (string, error) {
	if strings.HasPrefix(v, "@") {
		b, err := os.ReadFile(v[1:])
		return strings.TrimSpace(string(b)), err
	}
	return v, nil
}

func cmdHWRegister(args []string, stdout, stderr io.Writer, now time.Time) int {
	fs := newCmdFlags("hw-register",
		"hw-register [flags] (<wchw1:…> | --attestation <b64url|@file> [--client-data <b64url|@file>]\n"+
			"                           | --cose-key <b64url> --credential-id <b64url>)",
		"Adds a hardware key (FIDO2, YubiKey) to hardware_keys of the config, or replaces it by credentialId.\n"+
			"The blob comes from the app or from wardenctl hw-register. Restart wardend to apply.", stdout, stderr)
	cfgPath := fs.String("config", defaultConfigPath(), "wardend config to add the key to")
	name := fs.String("name", "", "key name (default: from the blob or \"YubiKey\")")
	rpID := fs.String("rp-id", "", "rpId (default: from the blob or "+hwkey.DefaultRPID+")")
	requireUV := fs.Bool("require-uv", false, "require the UV flag (PIN on the key) in every assertion")
	att := fs.String("attestation", "", "attestationObject base64url or @file")
	cd := fs.String("client-data", "", "registration clientDataJSON base64url or @file")
	cose := fs.String("cose-key", "", "COSE_Key base64url (registration without attestation)")
	credID := fs.String("credential-id", "", "credentialId base64url (with --cose-key)")
	dry := fs.Bool("dry-run", false, "only parse and print the entry, do not touch the config")
	pos, code, ok := fs.parseArgs(args, 0, 1)
	if !ok {
		return code
	}
	var key *hwkey.Key
	var err error
	switch {
	case len(pos) == 1:
		key, err = keyFromBlob(pos[0], rpID, name, now)
	case *att != "":
		key, err = keyFromAttestationArgs(*att, *cd, *rpID, now)
	case *cose != "":
		key, err = keyFromCOSEArgs(*cose, *credID, *rpID, now)
	default:
		fmt.Fprintln(stderr, "hw-register: need a wchw1:… blob, --attestation or --cose-key")
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "hw-register:", err)
		return 1
	}
	key.Name = *name
	if key.Name == "" {
		key.Name = "YubiKey"
	}
	key.RequireUV = *requireUV
	out, _ := json.MarshalIndent(key, "", "  ")
	if *dry {
		fmt.Fprintln(stdout, string(out))
		return 0
	}
	replaced, err := addHardwareKey(*cfgPath, *key)
	if err != nil {
		fmt.Fprintln(stderr, "hw-register:", err)
		return 1
	}
	verb := "added"
	if replaced {
		verb = "replaced"
	}
	fmt.Fprintf(stdout, "%s hardware key %s (%s, %s) in %s\n%s\nrestart wardend to apply\n", verb, key.ID, key.Alg, key.Name, *cfgPath, out)
	return 0
}

// keyFromBlob registers the key from a wchw1:… blob (or @file); the blob's rpId and name fill in
// the flags left empty.
func keyFromBlob(arg string, rpID, name *string, now time.Time) (*hwkey.Key, error) {
	s, err := readArg(arg)
	if err != nil {
		return nil, err
	}
	b, err := hwkey.ParseBlob(s)
	if err != nil {
		return nil, err
	}
	if *rpID == "" {
		*rpID = b.RPID
	}
	if *name == "" {
		*name = b.Name
	}
	key, err := registerFromAttestation(b.AttestationObject, b.ClientDataJSON, *rpID, now)
	if err != nil {
		return nil, err
	}
	if b.CredentialID != "" && b.CredentialID != key.ID {
		if raw, err := hwkey.DecodeB64(b.CredentialID); err != nil || hwkey.B64(raw) != key.ID {
			return nil, errors.New("blob credentialId does not match attestation")
		}
	}
	return key, nil
}

// keyFromAttestationArgs registers the key from --attestation and the optional --client-data.
func keyFromAttestationArgs(att, clientData, rpID string, now time.Time) (*hwkey.Key, error) {
	a, err := readArg(att)
	if err != nil {
		return nil, err
	}
	var c string
	if clientData != "" {
		if c, err = readArg(clientData); err != nil {
			return nil, err
		}
	}
	return registerFromAttestation(a, c, rpID, now)
}

// keyFromCOSEArgs registers the key from --cose-key and --credential-id, without attestation.
func keyFromCOSEArgs(cose, credID, rpID string, now time.Time) (*hwkey.Key, error) {
	if credID == "" {
		return nil, errors.New("--cose-key needs --credential-id")
	}
	ck, err := readArg(cose)
	if err != nil {
		return nil, err
	}
	ci, err := readArg(credID)
	if err != nil {
		return nil, err
	}
	return hwkey.KeyFromCOSE(ck, ci, rpID, now)
}

func registerFromAttestation(attB64, cdB64, rpID string, now time.Time) (*hwkey.Key, error) {
	a, err := hwkey.DecodeB64(attB64)
	if err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}
	var c []byte
	if cdB64 != "" {
		if c, err = hwkey.DecodeB64(cdB64); err != nil {
			return nil, fmt.Errorf("client data: %w", err)
		}
	}
	r, err := hwkey.ParseRegistration(a, c, rpID, now)
	if err != nil {
		return nil, err
	}
	return &r.Key, nil
}

// addHardwareKey: add the key to the config without touching other fields. Atomic write, 0600.
func addHardwareKey(path string, k hwkey.Key) (bool, error) {
	replaced := false
	err := updateConfig(path, func(top map[string]json.RawMessage) error {
		var keys []hwkey.Key
		if raw, ok := top["hardware_keys"]; ok {
			if err := json.Unmarshal(raw, &keys); err != nil {
				return fmt.Errorf("config %s: hardware_keys: %w", path, err)
			}
		}
		for i := range keys {
			if keys[i].ID == k.ID {
				keys[i], replaced = k, true
			}
		}
		if !replaced {
			keys = append(keys, k)
		}
		// check that the supervisor will accept the resulting list
		if _, err := hwkey.NewStore(keys, ""); err != nil {
			return err
		}
		kb, _ := json.Marshal(keys)
		top["hardware_keys"] = kb
		return nil
	})
	return replaced, err
}

func cmdHWKeys(args []string, stdout, stderr io.Writer) int {
	fs := newCmdFlags("hw-keys", "hw-keys [--config f]", "Lists the hardware keys registered in the config and their signCount.", stdout, stderr)
	cfgPath := fs.String("config", defaultConfigPath(), "wardend config")
	if _, code, ok := fs.parseArgs(args, 0, 0); !ok {
		return code
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "hw-keys:", err)
		return 1
	}
	st, err := hwkey.NewStore(cfg.HardwareKeys, "")
	if err != nil {
		fmt.Fprintln(stderr, "hw-keys:", err)
		return 1
	}
	counters := map[string]uint32{}
	if b, err := os.ReadFile(cfg.hwCountersPath()); err == nil {
		json.Unmarshal(b, &counters)
	}
	fmt.Fprintf(stdout, "%d hardware key(s) in %s\n", st.Len(), *cfgPath)
	for _, k := range cfg.HardwareKeys {
		fmt.Fprintf(stdout, "  %s  %-5s rp=%s name=%q uv=%v signCount=%d added=%s\n    attestation: %s\n", k.ID, k.Alg, k.RPID, k.Name, k.RequireUV, counters[k.ID], k.AddedAt, k.Attestation)
	}
	return 0
}
