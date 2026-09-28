// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardenctl status: the paired server, this device, the connection through the relay and the clock.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/feature"
)

func (a *app) cmdStatus(ctx context.Context, args []string) int {
	if _, code, ok := a.parseCmd(a.flags("status"), args, cmdSpec{guarded: true}); !ok {
		return code
	}
	st, err := loadState(a.dir)
	if err != nil {
		return a.errf("%v", err)
	}
	ksName := st.KeyStore
	if ks, err := keyStoreByName(st.KeyStore, a.dir); err == nil {
		ksName = ks.Name()
	}
	fmt.Fprintf(a.stdout, "Directory:   %s\n", a.dir)
	fmt.Fprintf(a.stdout, "Server:      %s  %s\n", st.Host, st.Relay)
	fmt.Fprintf(a.stdout, "Supervisor:  fingerprint %s (key pinned by the pairing link)\n", envelope.Fingerprint(st.SupervisorID))
	fmt.Fprintf(a.stdout, "Device:      \"%s\", fingerprint %s, key: %s (ed25519)\n", st.Name, envelope.Fingerprint(st.DeviceID), ksName)
	if feature.HWKey {
		if st.HW != nil {
			uv := ""
			if st.HW.RequireUV {
				uv = ", with PIN"
			}
			fmt.Fprintf(a.stdout, "YubiKey:     \"%s\" %s%s, credentialId %s…\n", st.HW.Name, st.HW.Alg, uv, clip(st.HW.CredentialID, 16))
		} else {
			fmt.Fprintf(a.stdout, "YubiKey:     not bound (wardenctl hw-register)\n")
		}
	}
	s, err := a.open(ctx)
	if err != nil {
		fmt.Fprintf(a.stdout, "Pairing:     %s\n", err)
		return 1
	}
	defer s.cl.Close()
	fmt.Fprintf(a.stdout, "Pairing:     approved %s\n", s.st.PairedAt)
	t0 := time.Now()
	sr, err := s.cl.Status(ctx)
	if err != nil {
		fmt.Fprintf(a.stdout, "Connection:  %v\n", err)
		return codeFor(err)
	}
	rs := sr.Raw
	rtt := time.Since(t0)
	skew := time.Duration(sr.Queue.Now-t0.Add(rtt/2).UnixMilli()) * time.Millisecond
	fmt.Fprintf(a.stdout, "Connection:  wardend answered through the relay in %s, server clock %+.1f s\n", rtt.Round(time.Millisecond), skew.Seconds())
	if skew > skewWarning || skew < -skewWarning {
		fmt.Fprintln(a.stdout, "             WARNING: the clocks differ, decisions will be rejected (stale_timestamp) when the skew exceeds ts_window")
	}
	trusted := statusTrusts(rs, s.st.DeviceID)
	hwCount, hwKnown := statusHWKeys(rs, s.st.HW)
	fmt.Fprintf(a.stdout, "wardend:     mode %v, pending %v, this device is trusted: %s\n", rs["mode"], rs["pendingCount"], yesno(trusted))
	if line := deviceAlgLine(rs["trustedDevices"]); line != "" {
		fmt.Fprintln(a.stdout, "             "+line)
	}
	if feature.HWKey && (hwCount > 0 || s.st.HW != nil) {
		line := fmt.Sprintf("             hardware keys: %d", hwCount)
		if s.st.HW != nil {
			line += ", the YubiKey bound here is registered: " + yesno(hwKnown)
		}
		fmt.Fprintln(a.stdout, line)
	}
	return 0
}

// skewWarning: status warns about the clock skew from here on; wardend rejects decisions past its
// ts_window (60 s by default).
const skewWarning = 30 * time.Second

// statusTrusts: whether the status lists deviceID among the trusted devices.
func statusTrusts(rs map[string]any, deviceID string) bool {
	ids, _ := rs["trustedDeviceIds"].([]any)
	for _, x := range ids {
		if x == deviceID {
			return true
		}
	}
	return false
}

// statusHWKeys: how many hardware keys the status lists and whether the YubiKey bound
// here (hw, may be nil) is one of them.
func statusHWKeys(rs map[string]any, hw *HWCred) (count int, known bool) {
	keys, _ := rs["hardwareKeys"].([]any)
	for _, k := range keys {
		if m, ok := k.(map[string]any); ok && hw != nil && m["id"] == hw.CredentialID {
			known = true
		}
	}
	return len(keys), known
}

// deviceAlgLine: the server's trusted devices by key type: ed25519 (phone, wardenctl), es256
// (Secure Enclave, Apple Watch).
func deviceAlgLine(v any) string {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return ""
	}
	count := map[string]int{}
	var names []string
	for _, x := range list {
		m, _ := x.(map[string]any)
		alg, _ := m["alg"].(string)
		if alg == "" {
			alg = "ed25519"
		}
		count[alg]++
		if name, _ := m["name"].(string); name != "" {
			names = append(names, fmt.Sprintf("\"%s\" %s", name, alg))
		}
	}
	line := fmt.Sprintf("trusted devices: %d (ed25519: %d, es256: %d)", len(list), count["ed25519"], count["es256"])
	if len(names) > 0 {
		line += ": " + strings.Join(names, ", ")
	}
	return line
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
