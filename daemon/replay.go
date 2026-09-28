// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardend replay runs a wardend journal through the same classifier as the supervisor
// (classifyExec: root or tripwire mode, harness packs, install zones) to see, before the mode is
// turned on, how many cards it would give on real work. Every hit is "approved" (as in observe),
// so inheritance pairs count the same way as in production after a signature. Only aggregates are
// printed: classes, categories, rules from a closed vocabulary, card rate. Raw argv is never
// printed (the journal contains commands and secrets).

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

type replayRecord struct {
	Seq  int64           `json:"seq"`
	Ts   int64           `json:"ts"`
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

type replayExec struct {
	Tgid      int             `json:"tgid"`
	Path      string          `json:"path"`
	Exe       string          `json:"exe"`
	CallerExe string          `json:"callerExe"`
	Argv      []string        `json:"argv"`
	Cwd       string          `json:"cwd"`
	Chain     []envelope.Link `json:"chain"`
	Class     string          `json:"class"`
}

// chainProc is /proc built from the chain of the current record (replay sees no live processes):
// the parent is the next pid of the chain, one starttime for all (pid reuse within the journal
// window is not modeled).
type chainProc struct{ ppid map[int]int }

func (c *chainProc) set(ch []envelope.Link) {
	clear(c.ppid)
	for i, l := range ch {
		pp := 0
		if i+1 < len(ch) {
			pp = ch[i+1].Pid
		}
		if _, ok := c.ppid[l.Pid]; !ok {
			c.ppid[l.Pid] = pp
		}
	}
}

func (c *chainProc) Stat(pid int) (int, uint64, bool) {
	pp, ok := c.ppid[pid]
	return pp, 1, ok
}

type replayCard struct {
	ts   int64
	cat  string
	rule string
}

type replayStats struct {
	Journal     string           `json:"journal"`
	PolicyMode  string           `json:"policyMode"`
	Packs       []string         `json:"packs"`
	AgentHome   string           `json:"agentHome"`
	WorkDirs    int              `json:"workDirs"`
	Window      [2]string        `json:"window"`
	Hours       float64          `json:"hours"`
	Records     int              `json:"records"`
	Execs       int              `json:"execs"`
	Skipped     map[string]int   `json:"skipped"`
	Starts      int              `json:"starts"`
	SelfExe     int              `json:"procSelfExeFixed"`
	Classes     map[string]int   `json:"classes"`
	Cards       cardMetrics      `json:"cards"`
	Categories  map[string]int   `json:"byCategory"`
	Rules       map[string]int   `json:"byRule"`
	Implied     map[string]int   `json:"impliedByRule"`
	Refused     map[string]int   `json:"refusedByRule"`
	PackHits    map[string]int   `json:"packRules"`
	Recorded    map[string]int   `json:"recordedClasses"`
	Agreement   *replayAgreement `json:"agreement,omitempty"`
	NightByCat  map[string]int   `json:"nightByCategory"`
	HourOfDay3h map[string]int   `json:"byHourOfDay3h"`
}

type replayAgreement struct {
	Total      int            `json:"total"`
	Agree      int            `json:"agree"`
	Pct        float64        `json:"pct"`
	Mismatches map[string]int `json:"mismatches"`
}

type cardMetrics struct {
	Total      int     `json:"total"`
	PerHour    float64 `json:"perHour"`
	PerDay     int     `json:"perDay"`
	HourMedian float64 `json:"hourMedian"`
	HourP90    int     `json:"hourP90"`
	HourMax    int     `json:"hourMax"`
	ZeroHours  int     `json:"zeroHours"`
	ClockHours int     `json:"clockHours"`
	Peak2m     int     `json:"peak2min"`
	Peak10m    int     `json:"peak10min"`
	Peak60m    int     `json:"peak60min"`
	Night      int     `json:"night"`
	NightPct   float64 `json:"nightPct"`
}

const (
	minuteMs     = 60_000
	hourMs       = 60 * minuteMs
	nightEndHour = 7 // a card before 07:00 local time counts as a night card
)

func isNight(ts int64) bool { return time.UnixMilli(ts).Hour() < nightEndHour }

// cardStats computes the card rates over the window [tFirst, tLast]: per hour and per day, the
// distribution over clock hours, the peaks in sliding windows and the night share.
func cardStats(ts []int64, tFirst, tLast int64) cardMetrics {
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	n := len(ts)
	hours := float64(tLast-tFirst) / hourMs
	m := cardMetrics{Total: n}
	if hours > 0 {
		m.PerHour = math.Round(float64(n)/hours*10) / 10
		m.PerDay = int(math.Round(float64(n) / hours * 24))
	}
	maxwin := func(w int64) int {
		best, j := 0, 0
		for i, t := range ts {
			for ts[j] < t-w {
				j++
			}
			best = max(best, i-j+1)
		}
		return best
	}
	h0, h1 := tFirst/hourMs, tLast/hourMs
	per := map[int64]int{}
	for _, t := range ts {
		per[t/hourMs]++
	}
	var series []int
	for h := h0; h <= h1; h++ {
		series = append(series, per[h])
	}
	qs := append([]int(nil), series...)
	sort.Ints(qs)
	if k := len(qs); k > 0 {
		if k%2 == 1 {
			m.HourMedian = float64(qs[k/2])
		} else {
			m.HourMedian = float64(qs[k/2-1]+qs[k/2]) / 2
		}
		m.HourP90 = qs[min(k-1, int(0.9*float64(k)))]
		m.HourMax = qs[k-1]
	}
	for _, x := range series {
		if x == 0 {
			m.ZeroHours++
		}
	}
	m.ClockHours = len(series)
	if n > 0 {
		m.Peak2m, m.Peak10m, m.Peak60m = maxwin(2*minuteMs), maxwin(10*minuteMs), maxwin(hourMs)
	}
	for _, t := range ts {
		if isNight(t) {
			m.Night++
		}
	}
	if n > 0 {
		m.NightPct = math.Round(1000*float64(m.Night)/float64(n)) / 10
	}
	return m
}

func parseWhen(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t.UnixMilli(), nil
		}
	}
	return 0, fmt.Errorf("time %q: unix ms or RFC 3339 (2026-09-27T23:11:26+02:00)", s)
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func cmdReplay(args []string, stdout, stderr io.Writer) int {
	fs := newCmdFlags("replay", "replay --journal <journal.jsonl> [flags]",
		"Replays the exec records of a wardend journal through this build's classifier (the same code as the\n"+
			"supervisor: policy mode, harness packs, path zones) and prints aggregates only: classes, categories,\n"+
			"rules, how many cards a day and the peaks. Every card is treated as approved, as in observe.\n"+
			"Nothing from argv is printed. The install comes from --config (policy_mode, agent_home, work_dirs,\n"+
			"scratch_dirs, packs, pack_vars, policy); flags override it.", stdout, stderr)
	jpath := fs.String("journal", "", "wardend journal (JSONL); read only")
	cfgPath := fs.String("config", "", "install config (as for run); without it, the defaults")
	mode := fs.String("policy-mode", "", "tripwire|root (default from the config, else tripwire)")
	polPath := fs.String("policy", "", "rules JSON (default from the config, else built-in)")
	agentHome := fs.String("agent-home", "", "${AGENT_HOME} (default from the config, else $HOME)")
	packs := fs.String("packs", "", "comma-separated harness packs; none for no packs (default from the config, else all)")
	from := fs.String("from", "", "from this time (unix ms or RFC 3339)")
	until := fs.String("until", "", "up to this time, inclusive")
	top := fs.Int("top", 25, "how many rules to show")
	asJSON := fs.Bool("json", false, "summary as one JSON object")
	dump := fs.String("dump", "", "write one line per exec: seq, class, rule, detail (no argv; file 0600)")
	var work, scratch listFlag
	fs.Var(&work, "work-dir", "work directory (repeatable; added to the config's work_dirs)")
	fs.Var(&scratch, "scratch-dir", "scratch directory (repeatable)")
	if _, code, ok := fs.parseArgs(args, 0, 0); !ok {
		return code
	}
	if *jpath == "" {
		return fs.fail("--journal required")
	}
	failed := func(code int, err error) int {
		fmt.Fprintln(stderr, "wardend replay:", err)
		return code
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return failed(2, err)
	}
	if *mode != "" {
		cfg.PolicyMode = *mode
	}
	if cfg.PolicyMode == "" {
		cfg.PolicyMode = policy.ModeTripwire
	}
	if cfg.PolicyMode != policy.ModeTripwire && cfg.PolicyMode != policy.ModeRoot {
		return fs.fail("--policy-mode %q: tripwire|root", cfg.PolicyMode)
	}
	if *polPath != "" {
		cfg.Policy = *polPath
	}
	if *agentHome != "" {
		cfg.AgentHome = *agentHome
	}
	if *packs != "" {
		list := []string{}
		if *packs != "none" {
			list = strings.Split(*packs, ",")
		}
		cfg.Packs = &list
	}
	cfg.WorkDirs = append(cfg.WorkDirs, work...)
	cfg.ScratchDirs = append(cfg.ScratchDirs, scratch...)
	tFrom, err := parseWhen(*from)
	if err != nil {
		return fs.fail("%v", err)
	}
	tUntil, err := parseWhen(*until)
	if err != nil {
		return fs.fail("%v", err)
	}
	pol, err := policy.Load(cfg.Policy)
	if err != nil {
		return failed(2, err)
	}
	if err := pol.Setup(cfg.policyOptions(nil, "")); err != nil {
		return failed(2, err)
	}
	f, err := os.Open(*jpath)
	if err != nil {
		return failed(1, err)
	}
	defer f.Close()
	var dumpW *bufio.Writer
	if *dump != "" {
		df, err := os.OpenFile(*dump, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return failed(1, err)
		}
		defer df.Close()
		dumpW = bufio.NewWriterSize(df, 1<<20)
		defer dumpW.Flush()
	}
	st, err := runReplay(f, cfg, pol, tFrom, tUntil, dumpW)
	if err != nil {
		return failed(1, err)
	}
	st.Journal = *jpath
	if *asJSON {
		b, _ := json.MarshalIndent(st, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	printReplay(stdout, st, *top)
	return 0
}

// replayer is the state of one replay run, carried from one journal line to the next.
type replayer struct {
	st      *replayStats
	cfg     *Config
	pol     *policy.Config
	proc    *chainProc
	tracker *policy.Tracker
	cards   []replayCard
	tFirst  int64          // ts of the first exec record in the window (0: none yet)
	tLast   int64          // ts of the last exec record in the window
	lastCmd string         // command of the last start record (packs are set up again when it changes)
	agree   map[string]int // root mode: "recorded class->replayed class" → count
	tFrom   int64
	tUntil  int64
	dump    *bufio.Writer
}

// runReplay is the main loop (tests can call it without flags).
func runReplay(r io.Reader, cfg *Config, pol *policy.Config, tFrom, tUntil int64, dump *bufio.Writer) (*replayStats, error) {
	st := &replayStats{PolicyMode: cfg.PolicyMode, Packs: pol.PackNames(), AgentHome: pol.AgentHome(), WorkDirs: len(cfg.WorkDirs),
		Skipped: map[string]int{}, Classes: map[string]int{}, Categories: map[string]int{}, Rules: map[string]int{},
		Implied: map[string]int{}, Refused: map[string]int{}, PackHits: map[string]int{}, Recorded: map[string]int{},
		NightByCat: map[string]int{}, HourOfDay3h: map[string]int{}}
	proc := &chainProc{ppid: map[int]int{}}
	rp := &replayer{st: st, cfg: cfg, pol: pol, proc: proc, tracker: policy.NewTracker(proc, 0), agree: map[string]int{},
		tFrom: tFrom, tUntil: tUntil, dump: dump}
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			st.Records++
			if e := rp.line(line); e != nil {
				return nil, e
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if rp.tFirst == 0 {
		return nil, fmt.Errorf("no exec records in the window")
	}
	tFirst, tLast := rp.tFirst, rp.tLast
	st.Window = [2]string{time.UnixMilli(tFirst).Format("2006-01-02T15:04:05"), time.UnixMilli(tLast).Format("2006-01-02T15:04:05")}
	st.Hours = math.Round(float64(tLast-tFirst)/hourMs*100) / 100
	ts := make([]int64, len(rp.cards))
	for i, c := range rp.cards {
		ts[i] = c.ts
		st.Categories[c.cat]++
		st.Rules[c.rule]++
		if isNight(c.ts) {
			st.NightByCat[c.cat]++
		}
		h := time.UnixMilli(c.ts).Hour() / 3 * 3
		st.HourOfDay3h[fmt.Sprintf("%02d-%02d", h, h+3)]++
	}
	st.Cards = cardStats(ts, tFirst, tLast)
	if cfg.PolicyMode == policy.ModeRoot {
		st.Agreement = agreement(rp.agree)
	}
	return st, nil
}

// agreement compares the classes recorded in the journal with the replayed ones (root mode).
func agreement(counts map[string]int) *replayAgreement {
	a := &replayAgreement{Mismatches: map[string]int{}}
	for k, n := range counts {
		a.Total += n
		rec, got, _ := strings.Cut(k, "->")
		if rec == got {
			a.Agree += n
		} else {
			a.Mismatches[k] += n
		}
	}
	if a.Total > 0 {
		a.Pct = math.Round(100000*float64(a.Agree)/float64(a.Total)) / 1000
	}
	return a
}

// line handles one journal line; only start and exec records inside the window count.
func (rp *replayer) line(line []byte) error {
	var rec replayRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		rp.st.Skipped["unparsable"]++ // a cut last line of a copy of a live journal
		return nil
	}
	if (rp.tFrom > 0 && rec.Ts < rp.tFrom) || (rp.tUntil > 0 && rec.Ts > rp.tUntil) {
		return nil
	}
	switch rec.Kind {
	case "start":
		return rp.start(rec.Data)
	case "exec":
		rp.exec(rec)
	}
	return nil
}

// start handles a new wardend process: the old one's roots are gone; the command drives pack
// auto-detection.
func (rp *replayer) start(data json.RawMessage) error {
	var s struct {
		Cmd []string `json:"cmd"`
	}
	_ = json.Unmarshal(data, &s)
	rp.st.Starts++
	rp.tracker = policy.NewTracker(rp.proc, 0)
	if k := strings.Join(s.Cmd, "\x00"); k != rp.lastCmd {
		rp.lastCmd = k
		return rp.pol.Setup(rp.cfg.policyOptions(s.Cmd, ""))
	}
	return nil
}

// exec classifies one exec record and counts the result.
func (rp *replayer) exec(rec replayRecord) {
	st := rp.st
	var d replayExec
	if err := json.Unmarshal(rec.Data, &d); err != nil {
		st.Skipped["unparsable"]++
		return
	}
	if rp.tFirst == 0 {
		rp.tFirst = rec.Ts
	}
	rp.tLast = rec.Ts
	st.Recorded[d.Class]++
	if d.Class == "missing" || d.Class == "unreadable" || d.Class == "supervised_cmd" {
		st.Skipped[d.Class]++
		return
	}
	st.Execs++
	exe := d.Exe
	// /proc/self/exe in journals from before the procinfo fix was resolved in the wardend process:
	// the target is the caller itself
	if d.Path == "/proc/self/exe" || d.Path == "/proc/thread-self/exe" {
		if exe != d.CallerExe {
			st.SelfExe++
		}
		exe = d.CallerExe
	}
	rp.proc.set(d.Chain)
	pe := &policy.Exec{Path: exe, Argv: d.Argv, CallerExe: d.CallerExe, Cwd: d.Cwd, Chain: chainExes(d.Chain)}
	now := time.UnixMilli(rec.Ts)
	v := classifyExec(rp.cfg.PolicyMode, rp.pol, rp.tracker, pe, d.Tgid, now)
	cls := string(v.Class)
	st.Classes[cls]++
	if rp.cfg.PolicyMode == policy.ModeRoot {
		rp.agree[d.Class+"->"+cls]++
	}
	label := ""
	switch {
	case v.Hit != nil:
		label = maskLabel(v.Hit.Label())
	case v.Rule != nil:
		label = v.Rule.ID
	}
	switch {
	case v.NeedsTicket():
		cat := v.Category()
		if cat == "" {
			cat = cls
			if v.Rule != nil {
				cat += ":" + v.Rule.ID
			}
		}
		rp.cards = append(rp.cards, replayCard{ts: rec.Ts, cat: cat, rule: label})
		rp.tracker.AddRoot(&policy.Root{Pid: d.Tgid, Start: 1, ApprovedAt: now, Digest: "replay", Family: hitFamily(v)})
	case v.Class == policy.ClassImplied:
		st.Implied[label]++
	case v.Class == policy.ClassRefuse:
		st.Refused[label]++
	case v.Class == policy.ClassService:
		st.PackHits[label]++
		if v.Inherits() && rp.cfg.PolicyMode == policy.ModeRoot {
			rp.tracker.AddRoot(&policy.Root{Pid: d.Tgid, Start: 1, ApprovedAt: now, Digest: "service"})
		}
	}
	if rp.dump != nil {
		fmt.Fprintf(rp.dump, "%d\t%s\t%s\n", rec.Seq, cls, label)
	}
}

// maskLabel prepares a rule label for printing: the details (verbs, npx package names) come from
// the vocabulary anyway, but long hex- and base64-like chunks are hidden just in case.
func maskLabel(s string) string {
	f := strings.Fields(s)
	for i, w := range f {
		if len(w) >= 20 && strings.IndexFunc(w, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0 {
			f[i] = "<masked>"
		}
	}
	return strings.Join(f, " ")
}

func printReplay(w io.Writer, st *replayStats, top int) {
	fmt.Fprintf(w, "journal     %s\n", st.Journal)
	fmt.Fprintf(w, "window      %s .. %s (%.2f h), records %d, wardend starts %d\n", st.Window[0], st.Window[1], st.Hours, st.Records, st.Starts)
	fmt.Fprintf(w, "policy      %s, packs %s, agent_home %s, work_dirs %d\n", st.PolicyMode, strings.Join(st.Packs, ","), st.AgentHome, st.WorkDirs)
	fmt.Fprintf(w, "execs       %d classified, skipped %s", st.Execs, formatCounts(st.Skipped, 0))
	if st.SelfExe > 0 {
		fmt.Fprintf(w, ", /proc/self/exe re-resolved %d", st.SelfExe)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "classes     %s\n", formatCounts(st.Classes, 0))
	c := st.Cards
	if st.Hours < 1 {
		fmt.Fprintf(w, "cards       %d (window shorter than an hour: no rates)\n", c.Total)
	} else {
		fmt.Fprintf(w, "cards       %d: %.1f/h, %d/day; hour median %.1f, p90 %d, max %d; hours without cards %d of %d\n",
			c.Total, c.PerHour, c.PerDay, c.HourMedian, c.HourP90, c.HourMax, c.ZeroHours, c.ClockHours)
	}
	fmt.Fprintf(w, "peaks       2 min %d, 10 min %d, 60 min %d (2 min = ticket TTL: pending if nobody answers); night 00-07 %d (%.1f %%)\n",
		c.Peak2m, c.Peak10m, c.Peak60m, c.Night, c.NightPct)
	fmt.Fprintf(w, "categories  %s\n", formatCounts(st.Categories, 0))
	if len(st.Implied) > 0 {
		fmt.Fprintf(w, "implied     %d: %s\n", countTotal(st.Implied), formatCounts(st.Implied, 8))
	}
	if len(st.Refused) > 0 {
		fmt.Fprintf(w, "refused     %d: %s\n", countTotal(st.Refused), formatCounts(st.Refused, 8))
	}
	if st.Agreement != nil {
		fmt.Fprintf(w, "recorded    agreement with the journal's classes %.3f %% of %d (%s)\n", st.Agreement.Pct, st.Agreement.Total, formatCounts(st.Agreement.Mismatches, 6))
	}
	fmt.Fprintf(w, "night       %s\n", formatCounts(st.NightByCat, 0))
	fmt.Fprintf(w, "top rules (cards):\n")
	for _, p := range topCounts(st.Rules, top) {
		fmt.Fprintf(w, "  %6d  %s\n", p.n, p.k)
	}
	fmt.Fprintf(w, "service rules (packs, service_allow): %d, top: %s\n", countTotal(st.PackHits), formatCounts(st.PackHits, 8))
}

// countPair: one entry of a count map.
type countPair struct {
	k string
	n int
}

// topCounts: the entries by count, descending (ties by key); top > 0 keeps the first top.
func topCounts(m map[string]int, top int) []countPair {
	out := make([]countPair, 0, len(m))
	for k, n := range m {
		out = append(out, countPair{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].k < out[j].k
	})
	if top > 0 && len(out) > top {
		out = out[:top]
	}
	return out
}

// formatCounts: "key n, key n" for the report, "-" when there is nothing.
func formatCounts(m map[string]int, top int) string {
	var parts []string
	for _, p := range topCounts(m, top) {
		parts = append(parts, fmt.Sprintf("%s %d", p.k, p.n))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

// countTotal: the sum of all counts.
func countTotal(m map[string]int) (n int) {
	for _, x := range m {
		n += x
	}
	return
}
