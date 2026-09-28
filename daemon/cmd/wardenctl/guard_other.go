// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package main

// Not Linux (macOS): wardend does not run here, only the ~/.wardend check remains.
func platformProbe() guardProbe { return guardProbe{} }
