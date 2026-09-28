// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux && !darwin

package main

// No system install exists for this OS; the client commands still look at the Linux location so
// that their error messages name a path.
var systemStateDir = "/var/lib/wardend"
