// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package main

// The system install on macOS (deploy/macos-install.sh, a LaunchDaemon): wardend runs as root
// for Endpoint Security, its state lives where macOS keeps daemon state. A variable, so that
// tests point it at a temp dir.
var systemStateDir = "/var/db/wardend"
