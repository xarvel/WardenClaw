// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// An in-process supervisor without seccomp (newHWSupervisor) with its RPC on a real unix socket:
// pairing, status and the socket's peer check.

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

type rpcEnv struct {
	s    *supervisor
	sock string
}

// newRPCEnv: ticket mode; without an argument no device is trusted.
func newRPCEnv(t *testing.T, trusted ...device) *rpcEnv {
	t.Helper()
	d := newDevice()
	if len(trusted) > 0 {
		d = trusted[0]
	}
	s := newHWSupervisor(t, `{}`, d)
	if len(trusted) == 0 {
		s.devices.Remove(d.id)
	}
	s.pair = newPairing()
	s.supervisorID = envelope.DeviceID(s.key.Public().(ed25519.PublicKey))
	sock := filepath.Join(s.cfg.StateDir, "w.sock")
	r, err := startRPC(sock, s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	return &rpcEnv{s: s, sock: sock}
}

func rpcDo(t *testing.T, sock, method string, params any, out any) error {
	t.Helper()
	c, err := dialRPC(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.call(method, params, out)
}
