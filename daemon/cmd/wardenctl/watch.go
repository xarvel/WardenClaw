// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardenctl watch: long-poll of the queue and cards in the terminal one at a time:
//
//	y: allow (with a YubiKey touch; with --no-hw only if wardend requires it), n: deny,
//	d: details, empty input (Enter): do nothing, the card stays in the queue
//	(the phone can decide it, otherwise it expires by TTL and the exec gets EPERM).
//
// A dangerous card (rule, flag, delegating launch: the same as "!!! DANGEROUS") is allowed only by
// the word allow in full, like the hold on the phone and the watch: y, yes and other short
// answers do not allow it, so that a habitual key does not approve something dangerous.
//
// There is no default answer. If the card leaves the queue while you are thinking (decided by
// another device, expired), the question is withdrawn. Input is read only when a question is
// asked: while fido2-assert asks for the PIN, nobody intercepts the terminal.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/feature"
)

type lineResult struct {
	line string
	err  error
}

// lineReader: a stdin line on request (ask), the result in C.
type lineReader struct {
	req     chan struct{}
	C       chan lineResult
	pending bool
	closed  bool
}

func newLineReader(r io.Reader) *lineReader {
	lr := &lineReader{req: make(chan struct{}), C: make(chan lineResult, 1)}
	br := bufio.NewReader(r)
	go func() {
		for range lr.req {
			s, err := br.ReadString('\n')
			lr.C <- lineResult{strings.TrimSpace(s), err}
			if err != nil {
				return
			}
		}
	}()
	return lr
}

func (lr *lineReader) ask() {
	if !lr.pending && !lr.closed {
		lr.req <- struct{}{}
		lr.pending = true
	}
}

// snapshot: one fetch of the queue by the poller.
type snapshot struct {
	resp *PendingResp
	err  error
}

// The poller waits on the queue for up to pollWait (wardend caps a long-poll at 25 s) and after
// a failed fetch tries again in pollRetry.
const (
	pollWait  = 25 * time.Second
	pollRetry = 5 * time.Second
)

// pollQueue: long-polls the queue until ctx ends. snaps holds only the latest fetch: an older
// snapshot nobody has read yet is dropped.
func pollQueue(ctx context.Context, cl *Client, snaps chan snapshot) {
	var since int64
	for ctx.Err() == nil {
		r, err := cl.Pending(ctx, since, pollWait)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			since = r.Seq
		}
		select {
		case <-snaps:
		default:
		}
		snaps <- snapshot{r, err}
		if err != nil {
			select {
			case <-ctx.Done():
			case <-time.After(pollRetry):
			}
		}
	}
}

// retryableRejection: a wardend rejection after which watch asks about the same card again:
// YubiKey problems (hw_*, hardware_required) and clock skew (stale_timestamp).
func retryableRejection(reason string) bool {
	return strings.HasPrefix(reason, "hw_") || reason == "hardware_required" || reason == "stale_timestamp"
}

// watchAction: what to do with the answer to a card question.
type watchAction int

const (
	watchUnknown watchAction = iota
	watchSkip
	watchDetails
	watchAllow
	watchDeny
	// y on a dangerous card: not allowed, the word allow in full is needed
	watchNeedAllowWord
)

// watchAnswer parses the answer. allow allows any card; y (yes) only a non-dangerous one.
func watchAnswer(line string, dangerous bool) watchAction {
	switch ans := strings.ToLower(strings.TrimSpace(line)); {
	case ans == "":
		return watchSkip
	case ans == "d" || ans == "?":
		return watchDetails
	case ans == "n" || ans == "no":
		return watchDeny
	case ans == "allow":
		return watchAllow
	case isYes(ans):
		if dangerous {
			return watchNeedAllowWord
		}
		return watchAllow
	}
	return watchUnknown
}

func (a *app) cmdWatch(ctx context.Context, args []string) int {
	fs := a.flags("watch")
	var o decideOpts
	if feature.HWKey {
		hwFlags(fs, &o)
		fs.BoolVar(&o.uv, "uv", false, "YubiKey PIN on touch")
		fs.StringVar(&o.device, "device", "", "FIDO device")
	}
	if _, code, ok := a.parseCmd(fs, args, cmdSpec{guarded: true}); !ok {
		return code
	}
	// Without a bound YubiKey every "y" would end in an error: say so before the first card.
	if st, err := loadState(a.dir); err == nil && st.HW == nil && o.forceHW && !o.noHW {
		return a.errf("%s (wardenctl watch --no-hw)", noHWBound)
	}
	s, err := a.open(ctx)
	if err != nil {
		return a.errf("%v", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	snaps := make(chan snapshot, 1)
	go pollQueue(ctx, s.cl, snaps)

	out := a.stdout
	fmt.Fprintf(out, "Watching %s (%s). y: allow, n: deny, d: details, Enter: do nothing. Ctrl-C: quit.\n", s.st.Host, s.st.URL)
	fmt.Fprintf(out, "A dangerous card is allowed only by the word allow in full.\n")
	lr := newLineReader(a.stdin)
	seen := map[string]bool{}
	var queue []Card
	var cur *Card
	curDanger := false
	var serverNow int64
	var lastErr string
	online := false

	prompt := func() {
		if lr.closed {
			return
		}
		if curDanger {
			fmt.Fprintf(out, "Dangerous card %s. Only the word allow in full allows it; n denies, d shows details, Enter skips: ", cur.ID)
		} else {
			fmt.Fprintf(out, "Allow %s? [y/n/d, Enter: skip] ", cur.ID)
		}
		lr.ask()
	}
	next := func() {
		cur = nil
		for len(queue) > 0 && cur == nil {
			c := queue[0]
			queue = queue[1:]
			fmt.Fprintln(out)
			printCard(out, c, serverNow, false)
			if c.Err != nil || lr.closed {
				continue // must not be signed or nobody can answer: only shown
			}
			cur = &c
			curDanger, _ = dangerOf(c)
			if len(queue) > 0 {
				fmt.Fprintf(out, "  (%d more in the queue)\n", len(queue))
			}
			prompt()
		}
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(out)
			return 0
		case sn := <-snaps:
			if sn.err != nil {
				if msg := sn.err.Error(); msg != lastErr || online {
					fmt.Fprintf(a.stderr, "\nno connection: %v (retrying every 5 s)\n", sn.err)
					lastErr = msg
				}
				online = false
				if isHTTPReason(sn.err, "untrusted_device") {
					return 1
				}
				continue
			}
			if !online && lastErr != "" {
				fmt.Fprintln(a.stderr, "connection restored")
			}
			online, lastErr = true, ""
			serverNow = sn.resp.Now
			present := map[string]bool{}
			for _, c := range s.check(sn.resp) {
				present[c.ID] = true
				if !seen[c.ID] {
					seen[c.ID] = true
					queue = append(queue, c)
				}
			}
			kept := queue[:0]
			for _, c := range queue {
				if present[c.ID] {
					kept = append(kept, c)
				}
			}
			queue = kept
			if cur != nil && !present[cur.ID] {
				fmt.Fprintf(out, "\nCard %s withdrawn: decided by another device or expired.\n", cur.ID)
				cur = nil
			}
			if cur == nil {
				next()
			}
		case in := <-lr.C:
			lr.pending = false
			if in.err != nil {
				lr.closed = true // the reader goroutine has finished
				if in.line == "" {
					fmt.Fprintln(out, "\ninput closed: from now on only showing cards, not sending decisions")
					next()
					continue
				}
			}
			if cur == nil {
				continue // the question is already withdrawn
			}
			switch act := watchAnswer(in.line, curDanger); act {
			case watchSkip:
				fmt.Fprintf(out, "Skipped: no decision sent, %s stays in the queue.\n", cur.ID)
				next()
			case watchDetails:
				printCard(out, *cur, serverNow, true)
				prompt()
			case watchNeedAllowWord:
				fmt.Fprintf(out, "Not allowed: the card is dangerous, only the word allow in full allows it. n denies.\n")
				prompt()
			case watchAllow, watchDeny:
				decision := "deny"
				if act == watchAllow {
					decision = "allow"
				}
				r, err := a.decide(ctx, s, *cur, decision, o)
				switch {
				case err != nil:
					fmt.Fprintf(out, "Not sent: %v\n", err)
					prompt()
					continue
				case !r.OK && retryableRejection(r.Reason):
					fmt.Fprintf(out, "wardend rejected: %s; you can try again.\n", reasonHuman(r.Reason))
					prompt()
					continue
				case !r.OK:
					fmt.Fprintf(out, "wardend rejected: %s\n", reasonHuman(r.Reason))
				default:
					fmt.Fprintf(out, "%s: %s\n", decisionWord(decision), clip(sanitize(displayCommand(cur.Env)), 120))
				}
				next()
			default:
				if curDanger {
					fmt.Fprintln(out, "Not understood. To allow: allow (the whole word); n denies, d shows details, Enter does nothing.")
				} else {
					fmt.Fprintln(out, "Not understood. y: allow, n: deny, d: details, Enter: do nothing.")
				}
				prompt()
			}
		}
	}
}
