// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux && !darwin

package main

// peerSupervised: no gate on this OS; every peer counts as supervised (fail-closed).
func (s *supervisor) peerSupervised(pid int) bool { return true }
