// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Guard against running the approver next to the agent.
//
// wardenctl is the second key held away from the agent. If it runs on the same machine and as the
// same user as the agent under wardend, the agent can read the device key
// (~/.config/wardenctl/device.key) or run `wardenctl approve` itself and approve any command for
// itself. Therefore:
//
//  1. the process is under a seccomp filter and wardend is nearby (a wardend ancestor, ~/.wardend
//     or a wardend process of this user): this is the agent's tree, always refuse;
//  2. not under a filter, but this user has ~/.wardend or a running wardend: refuse unless
//     WARDENCTL_ALLOW_SAME_HOST=1 is set (demo and tests; the key is then available to the agent).
//
// On macOS wardend does not run (seccomp is Linux-only), only ~/.wardend is checked.

import (
	"os"
	"path/filepath"
	"strings"
)

type guardProbe struct {
	Home string
	// SelfFiltered: this process is under a seccomp filter (description for the message).
	SelfFiltered func() (bool, string)
	// WardendAncestor: there is a wardend among the ancestors.
	WardendAncestor func() (string, bool)
	// WardendProcs: wardend processes of this user.
	WardendProcs func() []string
	AllowEnv     string
}

type guardVerdict struct {
	Refuse   bool
	Hard     bool // cannot be overridden
	Reasons  []string
	Override bool // refusal lifted by WARDENCTL_ALLOW_SAME_HOST=1
}

func localWardendDir(home string) (string, bool) {
	if home == "" {
		return "", false
	}
	d := filepath.Join(home, ".wardend")
	if st, err := os.Stat(d); err == nil && st.IsDir() {
		return d, true
	}
	return "", false
}

// evalGuard: the verdict on what the probe found, by the two rules at the top of this file.
func evalGuard(p guardProbe) guardVerdict {
	var v guardVerdict
	dir, hasDir := localWardendDir(p.Home)
	var procs []string
	if p.WardendProcs != nil {
		procs = p.WardendProcs()
	}
	anc, hasAnc := "", false
	if p.WardendAncestor != nil {
		anc, hasAnc = p.WardendAncestor()
	}
	filtered, fdesc := false, ""
	if p.SelfFiltered != nil {
		filtered, fdesc = p.SelfFiltered()
	}
	if hasAnc {
		v.Reasons = append(v.Reasons, "wardend is among the parents of this process ("+anc+")")
	}
	if hasDir {
		v.Reasons = append(v.Reasons, "this user has a wardend directory "+dir)
	}
	if len(procs) > 0 {
		v.Reasons = append(v.Reasons, "wardend is running as this user: "+strings.Join(procs, ", "))
	}
	near := hasAnc || hasDir || len(procs) > 0
	switch {
	case filtered && near:
		v.Refuse, v.Hard = true, true
		v.Reasons = append([]string{"the process runs under a seccomp filter (" + fdesc + ")"}, v.Reasons...)
	case near:
		v.Refuse = true
		if p.AllowEnv == "1" {
			v.Refuse, v.Override = false, true
		}
	}
	return v
}

// guardMessage: the refusal text for stderr.
func guardMessage(v guardVerdict) string {
	var b strings.Builder
	if v.Hard {
		b.WriteString("wardenctl: refused: this looks like an agent process under the wardend filter.\n")
	} else {
		b.WriteString("wardenctl: refused: wardend is running on this machine as the same user.\n")
	}
	for _, r := range v.Reasons {
		b.WriteString("  - " + r + "\n")
	}
	b.WriteString(`The approver is the second key held away from the agent. Next to the agent (same host, same user) the
agent can read the device key or call wardenctl approve itself and approve any command for itself.
Run wardenctl on a separate machine (for example, the owner's laptop): see README, "Where to run".
`)
	if v.Hard {
		b.WriteString("Nothing bypasses this from under the wardend filter.\n")
	} else {
		b.WriteString("For demos and tests on a single machine: WARDENCTL_ALLOW_SAME_HOST=1 (the key is then available to the agent).\n")
	}
	return b.String()
}

// defaultGuardProbe: the probe of this process and user on this platform.
func defaultGuardProbe() guardProbe {
	h, _ := os.UserHomeDir()
	p := platformProbe()
	p.Home = h
	p.AllowEnv = os.Getenv("WARDENCTL_ALLOW_SAME_HOST")
	return p
}
