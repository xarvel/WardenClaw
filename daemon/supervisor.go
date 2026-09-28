// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/hwkey"
	"github.com/xarvel/WardenClaw/daemon/journal"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

const (
	sweepInterval = 2 * time.Second  // how often the roots of exited processes are swept
	notifPollMs   = 500              // listener poll timeout while the child runs
	lingerPollMs  = 100              // listener poll timeout after the child exited (cfg.Linger)
	denyCacheTTL  = 10 * time.Second // how long a denial answers repeats of the same request
)

type supervisor struct {
	cfg          *Config
	pol          *policy.Config
	tracker      *policy.Tracker
	jr           *journal.Journal
	devices      *envelope.Devices
	hw           *hwkey.Store
	nonces       *envelope.NonceCache
	q            *queue
	m            *metrics
	key          ed25519.PrivateKey
	supervisorID string
	host         string
	supPid       int
	supMntNs     string // supervisor's /proc/self/ns/mnt ("" if not read): baseline for mount ns comparison
	lfd          int
	childPid     int
	ownFilters   int // seccomp filters of wardend itself; the tree has one more (reaper.go)
	initialDone  sync.Once
	denyMu       sync.Mutex
	denyCache    map[string]deniedReq
	started      time.Time
	stderr       io.Writer
	quiet        bool
	pair         *pairing
	rootExec     *rootExecServer // nil: root_exec not enabled
	relay        *relayClient    // nil if relay_url is off or the relay key failed to load (relayErr)
	relayErr     string
	wrap         bool // wardend wrap: tell the terminal about cards that wait, are denied or expire
	pairWS       bool // tests: runOpts.pairWS
	// for tests: called after the socket is up
	onReady func(socket string)
}

// deniedReq: a recent denial of a root. Shells and execvp continue the PATH search after EPERM
// (/usr/bin/bash → /bin/bash is the same file), and without a cache the human would get a second
// request for the same thing. Key: process (tgid+starttime) + realpath + argv; lives denyCacheTTL.
type deniedReq struct {
	until  time.Time
	reason string
}

// runOpts: what is not part of the config (the process and test substitutions).
type runOpts struct {
	cmd         []string
	helperExe   string
	helperArgs  []string
	helperEnv   []string
	stdout      io.Writer
	stderr      io.Writer
	stdin       io.Reader
	quiet       bool
	onReady     func(socket string)
	noSignals   bool      // tests: do not intercept process signals
	noSelfCheck bool      // tests: do not check installation permissions (the test binary is group-writable)
	pairWS      bool      // tests: a pair link may name the ws:// loopback relay
	wrap        *wrapOpts // wardend wrap (wrap.go): pairing before the command, notices, the summary
}

// childExitCode: the child's exit status the way a shell reports it (128+N after signal N).
func childExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return 1
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ee.ExitCode()
}

func (s *supervisor) journal(kind string, data any) {
	if _, err := s.jr.Append(kind, data); err != nil {
		fmt.Fprintln(s.stderr, "wardend: journal:", err)
	}
}

// execRecord: a journal record for every exec.
type execRecord struct {
	Pid        int             `json:"pid"`
	Tgid       int             `json:"tgid"`
	PPid       int             `json:"ppid"`
	Syscall    string          `json:"syscall"`
	Path       string          `json:"path"`
	Exe        string          `json:"exe"`
	CallerExe  string          `json:"callerExe"`
	Argv       []string        `json:"argv"`
	Cwd        string          `json:"cwd"`
	EnvHash    string          `json:"envHash,omitempty"`
	LoaderEnv  []string        `json:"loaderEnv,omitempty"` // LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH in the environment
	UID        int             `json:"uid"`
	Chain      []envelope.Link `json:"chain"`
	Class      string          `json:"class"`
	Rule       string          `json:"rule,omitempty"`
	Category   string          `json:"category,omitempty"` // tripwire: hit category
	Detail     string          `json:"detail,omitempty"`   // tripwire: verb from the rule's vocabulary
	RootPid    int             `json:"rootPid,omitempty"`
	Decision   string          `json:"decision"` // allow | deny
	Errno      string          `json:"errno,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	Digest     string          `json:"digest,omitempty"`
	Envelope   map[string]any  `json:"envelope,omitempty"`
	Ticket     any             `json:"ticket,omitempty"`
	Hardware   *hwRecord       `json:"hardware,omitempty"`
	Provenance *provInfo       `json:"provenance,omitempty"` // self-built: provenance of the target file
	Toctou     *toctouResult   `json:"toctou,omitempty"`
	Deadline   *deadlineRecord `json:"deadline,omitempty"` // a gate with a deadline of its own (Endpoint Security): the budget and whether it ran out
	LatencyUs  int64           `json:"latencyUs"`
	WaitUs     int64           `json:"ticketWaitUs,omitempty"`
	ReadError  string          `json:"readError,omitempty"`
}

// deadlineRecord: a gate that must answer the kernel by a deadline of its own (esgate_darwin.go).
type deadlineRecord struct {
	LeftMs   int64 `json:"leftMs"`             // what was left of the kernel's deadline when the event arrived
	BudgetMs int64 `json:"budgetMs"`           // how long a ticket could be waited for (left minus the margin)
	Missed   bool  `json:"missed,omitempty"`   // the budget ran out before a decision: the kernel got DENY
	TooShort bool  `json:"tooShort,omitempty"` // no budget at all: DENY without a card
}

// hwRecord: the second factor in an exec record.
type hwRecord struct {
	Required  bool          `json:"required"`            // static rule (known in advance)
	Rule      string        `json:"rule,omitempty"`      // matched rule (static or score-based)
	Escalated bool          `json:"escalated,omitempty"` // inherit → new root because of the rule
	MinScore  *int          `json:"minScore,omitempty"`  // threshold of score rules for this exec
	Verified  *hwkey.Result `json:"verified,omitempty"`  // verified assertion
}

func (s *supervisor) logf(format string, a ...any) { fmt.Fprintf(s.stderr, format, a...) }
