// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Storage of the device secret (state.go: the Ed25519 seed and the X25519 private key).
//
//	keychain  macOS Keychain via /usr/bin/security (no cgo: the binary is cross-compiled).
//	          The entry is written with `security -i` and the command on stdin, so the seed does not
//	          end up in argv (on macOS any user sees other processes' argv via ps). The entry has an
//	          empty list of trusted applications (-T ""): every read shows a system prompt.
//	file      <dir>/device.key, 0600 in a 0700 directory.
//
// Default (auto): keychain on macOS if the security utility exists, otherwise file.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

const keychainService = "wardenctl"

// keychainTimeout: the Keychain may ask for the login password, so security gets a minute.
const keychainTimeout = 60 * time.Second

type keyStore interface {
	Kind() string // file | keychain
	Name() string
	Save(account string, seed []byte) error
	Load(account string) ([]byte, error)
	Delete(account string) error
}

func deviceIDOf(priv ed25519.PrivateKey) string {
	return envelope.DeviceID(priv.Public().(ed25519.PublicKey))
}

func securityBin() string {
	if p := os.Getenv("WARDENCTL_SECURITY_BIN"); p != "" { // tests: fake security
		return p
	}
	if p, err := exec.LookPath("security"); err == nil {
		return p
	}
	return ""
}

// keyStoreByName: auto | keychain | file.
func keyStoreByName(name, dir string) (keyStore, error) {
	switch name {
	case "", "auto":
		if runtime.GOOS == "darwin" {
			if bin := securityBin(); bin != "" {
				return keychainStore{bin: bin}, nil
			}
		}
		return fileStore{dir: dir}, nil
	case "file":
		return fileStore{dir: dir}, nil
	case "keychain":
		bin := securityBin()
		if bin == "" {
			return nil, errors.New("no security utility (macOS Keychain); use --keystore file")
		}
		return keychainStore{bin: bin}, nil
	}
	return nil, fmt.Errorf("--keystore %q: auto|keychain|file", name)
}

type fileStore struct{ dir string }

func (f fileStore) Kind() string { return "file" }
func (f fileStore) Name() string { return "file " + f.path() }
func (f fileStore) path() string { return filepath.Join(f.dir, "device.key") }

func (f fileStore) Save(_ string, seed []byte) error {
	return writeFileAtomic(f.path(), []byte(hex.EncodeToString(seed)+"\n"))
}

func (f fileStore) Load(_ string) ([]byte, error) {
	st, err := os.Stat(f.path())
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible not only to its owner (%v): chmod 600", f.path(), st.Mode().Perm())
	}
	b, err := os.ReadFile(f.path())
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(b)))
}

func (f fileStore) Delete(_ string) error {
	err := os.Remove(f.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type keychainStore struct{ bin string }

func (k keychainStore) Kind() string { return "keychain" }
func (k keychainStore) Name() string { return "macOS Keychain (service " + keychainService + ")" }

func (k keychainStore) run(stdin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), keychainTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, k.bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("security %s: %s", args[0], msg)
	}
	return out.Bytes(), nil
}

func safeAccount(a string) error {
	for _, c := range a {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return errors.New("keychain: account must be hex")
		}
	}
	return nil
}

// Save: a new entry without trusted applications (-T ""): every read of the seed, including by
// wardenctl itself via /usr/bin/security, shows a macOS system prompt. Without -T, security itself
// becomes trusted, and `security find-generic-password -w` hands out the seed without a prompt to
// any process of this user, including an AI agent on the same machine (review 2026-09-28, M6).
func (k keychainStore) Save(account string, seed []byte) error {
	return k.add(account, seed, true)
}

// add: `security -i add-generic-password`. prompt=false writes the entry the old way (security among
// the trusted): only to restore the previous entry if the new one failed (Reprotect).
func (k keychainStore) add(account string, seed []byte, prompt bool) error {
	if err := safeAccount(account); err != nil {
		return err
	}
	// hex and the service name have no spaces or quotes: the line command for `security -i` is safe;
	// `security -i` parses "" as an empty argument (split_line in security.c).
	acl := ` -T ""`
	if !prompt {
		acl = ""
	}
	line := fmt.Sprintf("add-generic-password -a %s -s %s -l wardenctl-device-key%s -w %s\n", account, keychainService, acl, hex.EncodeToString(seed))
	if _, err := k.run(line, "-i"); err != nil {
		return err
	}
	// `security -i` does not always return the command's error code: check that the entry appeared.
	// Without -w only the attributes are read, there is no system prompt.
	if _, err := k.run("", "find-generic-password", "-a", account, "-s", keychainService); err != nil {
		return fmt.Errorf("keychain: entry not confirmed: %v", err)
	}
	return nil
}

// Reprotect: an entry made without -T "" (any process of the user reads it without a prompt) is
// recreated with an empty list of trusted applications: `add -U` would only append the new list to
// the old one. The seed is still read the old way, without a prompt. If the new entry failed, the
// previous one is restored as it was: the device key is not lost.
func (k keychainStore) Reprotect(account string) error {
	seed, err := k.Load(account)
	if err != nil {
		return err
	}
	if err := k.Delete(account); err != nil {
		return err
	}
	if err := k.add(account, seed, true); err != nil {
		if rerr := k.add(account, seed, false); rerr != nil {
			return fmt.Errorf("%v; could not restore the previous entry: %v (device key lost: wardenctl forget and pair again)", err, rerr)
		}
		return fmt.Errorf("%v (previous entry restored)", err)
	}
	return nil
}

func (k keychainStore) Load(account string) ([]byte, error) {
	if err := safeAccount(account); err != nil {
		return nil, err
	}
	out, err := k.run("", "find-generic-password", "-a", account, "-s", keychainService, "-w")
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(out)))
}

func (k keychainStore) Delete(account string) error {
	if err := safeAccount(account); err != nil {
		return err
	}
	_, err := k.run("", "delete-generic-password", "-a", account, "-s", keychainService)
	if err != nil && strings.Contains(err.Error(), "could not be found") {
		return nil
	}
	return err
}
