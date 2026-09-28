// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin && !cgo

package main

import "errors"

// startESGate: the Endpoint Security client is C (esgate_darwin.c); a build without cgo has no
// gate at all, so the command is not started: fail-closed.
func startESGate(s *supervisor, cfg *Config, childUID int) (execGate, error) {
	return nil, errors.New("this wardend was built without cgo: no Endpoint Security client, nothing can be gated (build with CGO_ENABLED=1 and the Command Line Tools)")
}
