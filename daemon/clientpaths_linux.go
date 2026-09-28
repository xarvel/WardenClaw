// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

// The system install (install.sh, deploy/wardend.service): wardend runs as a root service with
// its state here. A variable, so that tests point it at a temp dir.
var systemStateDir = "/var/lib/wardend"
