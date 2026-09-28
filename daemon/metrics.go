// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"sort"
	"sync"
	"sync/atomic"
)

// ring holds the last N values for percentiles.
type ring struct {
	mu   sync.Mutex
	buf  []int64
	next int
	full bool
	max  int64
	n    int64
}

func newRing(n int) *ring { return &ring{buf: make([]int64, n)} }

func (r *ring) add(v int64) {
	r.mu.Lock()
	r.buf[r.next] = v
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
	if v > r.max {
		r.max = v
	}
	r.n++
	r.mu.Unlock()
}

type pct struct {
	Count int64 `json:"count"`
	P50   int64 `json:"p50"`
	P95   int64 `json:"p95"`
	Max   int64 `json:"max"`
}

func (r *ring) pct() pct {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	if r.full {
		n = len(r.buf)
	}
	if n == 0 {
		return pct{}
	}
	s := append([]int64(nil), r.buf[:n]...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	at := func(p float64) int64 { return s[min(n-1, int(p*float64(n)))] }
	return pct{Count: r.n, P50: at(0.50), P95: at(0.95), Max: r.max}
}

type metrics struct {
	execs         atomic.Int64
	allowed       atomic.Int64
	denied        atomic.Int64
	byClass       sync.Map // class → *atomic.Int64
	ticketsOK     atomic.Int64
	ticketsDenied atomic.Int64
	ticketsTTL    atomic.Int64
	queueFull     atomic.Int64
	toctouKills   atomic.Int64
	decideRejects atomic.Int64

	latency    *ring // RECV→SEND excluding ticket wait, µs
	ticketWait *ring // ticket wait, µs
}

// Percentiles are taken over the last latencySamples execs and ticketWaitSamples tickets.
const (
	latencySamples    = 4096
	ticketWaitSamples = 1024
)

func newMetrics() *metrics {
	return &metrics{latency: newRing(latencySamples), ticketWait: newRing(ticketWaitSamples)}
}

func (m *metrics) class(c string) {
	v, _ := m.byClass.LoadOrStore(c, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
}

func (m *metrics) snapshot() map[string]any {
	classes := map[string]int64{}
	m.byClass.Range(func(k, v any) bool {
		classes[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return map[string]any{
		"execs": m.execs.Load(), "allowed": m.allowed.Load(), "denied": m.denied.Load(), "byClass": classes,
		"tickets":       map[string]int64{"allowed": m.ticketsOK.Load(), "denied": m.ticketsDenied.Load(), "expired": m.ticketsTTL.Load(), "queueFull": m.queueFull.Load()},
		"toctouKills":   m.toctouKills.Load(),
		"decideRejects": m.decideRejects.Load(),
		"latencyUs":     m.latency.pct(),
		"ticketWaitUs":  m.ticketWait.pct(),
	}
}
