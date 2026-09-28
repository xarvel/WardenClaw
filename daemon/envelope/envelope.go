// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Version is the envelope format version.
const Version = 1

// Protocol is the WardenClaw protocol version spoken by wardend: envelope, signing strings,
// wardend and plugin API share a single version number. Incremented on any change that breaks
// an existing client or server; adding a new optional field to a response does not increment it.
// wardend reports it in ping and status as the "protocol" field (protocol/README.md).
const Protocol = 1

// MinClient is the minimum client protocol version that wardend still supports
// ("minClient" field in ping and status).
const MinClient = 1

// Link is one entry in the process chain: pid and exe (realpath of /proc/<pid>/exe).
type Link struct {
	Pid int    `json:"pid"`
	Exe string `json:"exe"`
}

// Requester identifies the caller: host and supervisor ID (sha256 hex of the supervisor public key).
type Requester struct {
	Host         string `json:"host"`
	SupervisorID string `json:"supervisorId"`
}

// Exec is the v1 envelope for an execve/execveat request.
//
//	{v:1, type:"exec", argv, cwd, exe, uid, gid, ppidChain:[{pid,exe}], env, envHash,
//	 requester:{host, supervisorId}, pidfdCookie, ts, nonce}
//
// env contains variables that affect program behavior (SelectEnv): [{name, value[, cut]}]
// in envp order; envHash covers the full environment.
// exe is the realpath of the executable that will be launched (not the calling process).
// ppidChain[0] is the calling process itself (pid = tgid, exe = its current image before exec),
// followed by parents up to the supervisor (not including it).
// pidfdCookie is "pidfs:<inode>" of the calling process's pidfd (unique within a boot,
// binding the ticket to a process instance rather than a reusable pid);
// when pidfs is unavailable: "start:<pid>:<starttime>".
// ts is Unix milliseconds (like Date.now()), nonce is 16 hex bytes.
type Exec struct {
	Argv        []string
	Cwd         string
	Exe         string
	UID         int
	GID         int
	PpidChain   []Link
	Env         []EnvVar
	EnvHash     string
	Requester   Requester
	PidfdCookie string
	Ts          int64
	Nonce       string
}

// NewNonce returns 16 random bytes as a hex string.
func NewNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// NowMs returns the current time in milliseconds, like Date.now().
func NowMs() int64 { return time.Now().UnixMilli() }

// Map returns the canonical JSON representation (all fields required; arrays must not be nil).
func (e *Exec) Map() map[string]any {
	argv := e.Argv
	if argv == nil {
		argv = []string{}
	}
	chain := make([]any, 0, len(e.PpidChain))
	for _, l := range e.PpidChain {
		chain = append(chain, map[string]any{"pid": l.Pid, "exe": l.Exe})
	}
	env := make([]any, 0, len(e.Env))
	for _, v := range e.Env {
		m := map[string]any{"name": v.Name, "value": v.Value}
		if v.Cut > 0 {
			m["cut"] = v.Cut
		}
		env = append(env, m)
	}
	return map[string]any{
		"v":           Version,
		"type":        "exec",
		"argv":        argv,
		"cwd":         e.Cwd,
		"exe":         e.Exe,
		"uid":         e.UID,
		"gid":         e.GID,
		"ppidChain":   chain,
		"env":         env,
		"envHash":     e.EnvHash,
		"requester":   map[string]any{"host": e.Requester.Host, "supervisorId": e.Requester.SupervisorID},
		"pidfdCookie": e.PidfdCookie,
		"ts":          e.Ts,
		"nonce":       e.Nonce,
	}
}

// Canonical returns canonical JSON bytes and hex sha256 (the digest is the sole ticket identifier).
// Returns ErrInvalidUTF8 if argv/cwd/exe/env contain non-UTF-8: such an envelope cannot be built
// because the app would not be able to display and recompute it byte-for-byte.
func (e *Exec) Canonical() ([]byte, string, error) {
	c, d, err := Digest(e.Map())
	if err != nil {
		return nil, "", fmt.Errorf("envelope: %w", err)
	}
	return c, d, nil
}

// PendingID returns the pending-entry identifier for the app/plugin. The "wd-" prefix
// distinguishes wardend exec entries from plugin entries (UUIDs); relay uses it to route decide.
func PendingID(digest string) string { return "wd-" + digest[:32] }
