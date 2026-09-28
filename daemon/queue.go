// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Queue of execs waiting for a ticket. Bounded (max_pending): on overflow an exec immediately
// gets EAGAIN, so the kernel does not pile up processes stuck in execve indefinitely.

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/hwkey"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

var errQueueFull = errors.New("pending queue full")

type ticketResult struct {
	Allow    bool
	Reason   string
	Body     *envelope.DecisionBody // signed decision (for the journal)
	Hardware *hwkey.Result          // verified second signature (nil: there was none)
	HWRule   string                 // require_hardware rule under which it was required
}

type pendingItem struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"` // "exec"
	Digest    string         `json:"digest"`
	Envelope  map[string]any `json:"envelope"`
	Meta      map[string]any `json:"meta"`
	CreatedAt int64          `json:"createdAt"`
	ExpiresAt int64          `json:"expiresAt"`

	done chan ticketResult
	// for checking the second factor on decide (not sent in JSON)
	pe       *policy.Exec
	class    policy.Class
	category string         // tripwire category ("": root mode)
	hwRule   *policy.HWRule // static require_hardware (nil: not required up front)
}

type queue struct {
	mu      sync.Mutex
	max     int
	items   map[string]*pendingItem
	seq     int64         // bumped on every add and remove; long-poll clients pass the last one seen
	changed chan struct{} // closed and replaced on every bump, wakes waitChange
}

func newQueue(maxPending int) *queue {
	return &queue{max: maxPending, items: map[string]*pendingItem{}, changed: make(chan struct{})}
}

// bumpLocked advances seq and wakes the long-polls; q.mu must be held.
func (q *queue) bumpLocked() {
	q.seq++
	close(q.changed)
	q.changed = make(chan struct{})
}

func (q *queue) add(it *pendingItem) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= q.max {
		return errQueueFull
	}
	it.done = make(chan ticketResult, 1)
	q.items[it.ID] = it
	q.bumpLocked()
	return nil
}

func (q *queue) remove(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.items[id]; ok {
		delete(q.items, id)
		q.bumpLocked()
	}
}

func (q *queue) get(id string) *pendingItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.items[id]
}

func (q *queue) digestOf(id string) string {
	q.mu.Lock()
	defer q.mu.Unlock()
	if it := q.items[id]; it != nil {
		return it.Digest
	}
	return ""
}

// resolve hands the decision to the waiting exec (the first decision wins).
func (q *queue) resolve(id string, r ticketResult) bool {
	q.mu.Lock()
	it := q.items[id]
	q.mu.Unlock()
	if it == nil {
		return false
	}
	select {
	case it.done <- r:
		return true
	default:
		return false
	}
}

func (q *queue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

func (q *queue) snapshot() (int64, []*pendingItem) {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]*pendingItem, 0, len(q.items))
	for _, it := range q.items {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return q.seq, out
}

// waitChange long-polls: returns when seq > since, on timeout or on cancellation.
func (q *queue) waitChange(ctx context.Context, since int64, wait time.Duration) {
	q.mu.Lock()
	if q.seq > since {
		q.mu.Unlock()
		return
	}
	ch := q.changed
	q.mu.Unlock()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ch:
	case <-t.C:
	case <-ctx.Done():
	}
}
