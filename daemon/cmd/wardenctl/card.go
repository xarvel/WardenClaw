// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The exec card: strict check of the v1 envelope and digest recomputation (like checkExecPending
// in app/src/core/execEnvelope.ts), display in the terminal.
//
// The signed digest is the one recomputed here from the envelope, not the one the transport sent;
// the envelope must come from the supervisor whose key is pinned by the pairing link.
//
// Display (protocol/DISPLAY.md, implemented in display.go): the signed facts of the envelope (argv,
// exe, cwd, uid, process chain), then what is not signed: the assessment (the rules verdict and the
// model opinion, each under its own name) and the meta fields from the transport. meta is only
// shown and can only add caution (wardend checks the YubiKey itself), no decisions rest on it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// Item: a queue record as /v1/pending sends it; the envelope and meta stay raw until checkItem.
type Item struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Digest    string          `json:"digest"`
	Envelope  json.RawMessage `json:"envelope"`
	Meta      json.RawMessage `json:"meta"`
	CreatedAt int64           `json:"createdAt"`
	ExpiresAt int64           `json:"expiresAt"`
}

// Link: one process of the envelope ppidChain.
type Link struct {
	Pid int64  `json:"pid"`
	Exe string `json:"exe"`
}

// Env: the signed v1 exec envelope, decoded only after strictEnvelope accepted its shape.
type Env struct {
	V         int64             `json:"v"`
	Type      string            `json:"type"`
	Argv      []string          `json:"argv"`
	Cwd       string            `json:"cwd"`
	Exe       string            `json:"exe"`
	UID       int64             `json:"uid"`
	GID       int64             `json:"gid"`
	PpidChain []Link            `json:"ppidChain"`
	Vars      []envelope.EnvVar `json:"env"` // variables that change program behavior (signed)
	EnvHash   string            `json:"envHash"`
	Requester struct {
		Host         string `json:"host"`
		SupervisorID string `json:"supervisorId"`
	} `json:"requester"`
	PidfdCookie string `json:"pidfdCookie"`
	Ts          int64  `json:"ts"`
	Nonce       string `json:"nonce"`
}

// HWMeta: meta.hardware, the YubiKey requirement that wardend enforces itself.
type HWMeta struct {
	Required    bool   `json:"required"`
	Rule        string `json:"rule"`
	Escalated   bool   `json:"escalated"`
	MinScore    *int   `json:"minScore"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	Credentials []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Alg  string `json:"alg"`
		RPID string `json:"rpId"`
	} `json:"credentials"`
}

// Meta: the meta fields of a queue record. Not part of the digest: on the path through the adapter
// the transport sets them. Types are as wardend sends them (daemon/supervisor.go): delegating is
// the rule text, insideRoot is the pid of the approved root. Parsing is lenient: a field of an
// unexpected type is simply skipped.
type Meta struct {
	Class      string
	Rule       string
	Path       string
	Syscall    string
	CallerExe  string
	Delegating string // explanation of the delegation rule ("": none)
	InsideRoot int64  // pid of the approved root (0: none)
	Hardware   *HWMeta
	Judge      string // meta.judge / meta.opinion: someone else's opinion, display only
}

func parseMeta(raw json.RawMessage) Meta {
	var m map[string]json.RawMessage
	var out Meta
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return out
	}
	str := func(k string) string {
		var s string
		if json.Unmarshal(m[k], &s) == nil {
			return s
		}
		return ""
	}
	out.Class, out.Rule, out.Path, out.Syscall, out.CallerExe = str("class"), str("rule"), str("path"), str("syscall"), str("callerExe")
	var d any
	if json.Unmarshal(m["delegating"], &d) == nil {
		switch v := d.(type) {
		case string:
			out.Delegating = v
		case bool:
			if v {
				out.Delegating = "yes"
			}
		}
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(m["insideRoot"]))
	dec.UseNumber()
	if dec.Decode(&n) == nil {
		if v, err := n.Int64(); err == nil && v > 0 {
			out.InsideRoot = v
		}
	}
	if h, ok := m["hardware"]; ok {
		var hw HWMeta
		if json.Unmarshal(h, &hw) == nil {
			out.Hardware = &hw
		}
	}
	for _, k := range []string{"judge", "opinion"} {
		if j, ok := m[k]; ok && len(j) > 0 && string(j) != "null" {
			var b bytes.Buffer
			if json.Compact(&b, j) == nil {
				out.Judge = b.String()
			}
			break
		}
	}
	return out
}

// Card: a verified queue record.
type Card struct {
	Item
	Env  *Env
	Meta Meta
	Err  error // not nil: must not be signed
}

// envKeys: the exact key set of a v1 envelope, sorted.
var envKeys = []string{"argv", "cwd", "env", "envHash", "exe", "gid", "nonce", "pidfdCookie", "ppidChain", "requester", "ts", "type", "uid", "v"}

func safeInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	if err != nil || f != math.Trunc(f) || math.Abs(f) > (1<<53)-1 {
		return 0, false
	}
	return int64(f), true
}

// ErrNewerEnvelope: a request in an envelope of a version newer than envelope.Version. wardenctl
// cannot show or allow it (fail-closed), an update is needed.
var ErrNewerEnvelope = errors.New("request from a newer protocol version, update wardenctl")

// strictEnvelope: the v1 envelope shape exactly as execEnvelopeFromPending in the app.
func strictEnvelope(raw json.RawMessage) (*Env, error) {
	v, err := envelope.ParseJSON(raw)
	if err != nil {
		return nil, errors.New("envelope is not JSON")
	}
	o, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("envelope is not an object")
	}
	// an envelope newer than wardenctl: the shape is not checked (it may have changed), but it is
	// not dropped silently either: the card is visible and cannot be signed
	if n, ok := safeInt(o["v"]); ok && n > envelope.Version {
		return nil, fmt.Errorf("%w (envelope v%d, wardenctl understands v%d)", ErrNewerEnvelope, n, envelope.Version)
	}
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != strings.Join(envKeys, ",") {
		return nil, errors.New("envelope is not v1 or has extra fields")
	}
	if o["v"] != json.Number("1") || o["type"] != "exec" {
		return nil, errors.New("envelope is not v1/exec")
	}
	str := func(k string) bool { _, ok := o[k].(string); return ok }
	if !str("cwd") || !str("exe") || !str("envHash") || !str("pidfdCookie") || !str("nonce") {
		return nil, errors.New("envelope: string fields")
	}
	for _, k := range []string{"uid", "gid", "ts"} {
		if _, ok := safeInt(o[k]); !ok {
			return nil, errors.New("envelope: " + k + " is not an integer")
		}
	}
	fields := []struct {
		key   string
		check func(any) error
	}{{"argv", strictArgv}, {"ppidChain", strictPpidChain}, {"env", strictEnvVars}, {"requester", strictRequester}}
	for _, f := range fields {
		if err := f.check(o[f.key]); err != nil {
			return nil, err
		}
	}
	var e Env
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// strictArgv: the envelope argv: an array of strings.
func strictArgv(v any) error {
	argv, ok := v.([]any)
	if !ok {
		return errors.New("envelope: argv")
	}
	for _, a := range argv {
		if _, ok := a.(string); !ok {
			return errors.New("envelope: argv")
		}
	}
	return nil
}

// strictPpidChain: the envelope ppidChain: an array of records exactly {pid, exe}.
func strictPpidChain(v any) error {
	chain, ok := v.([]any)
	if !ok {
		return errors.New("envelope: ppidChain")
	}
	for _, l := range chain {
		lo, ok := l.(map[string]any)
		if !ok || len(lo) != 2 {
			return errors.New("envelope: ppidChain")
		}
		if _, ok := safeInt(lo["pid"]); !ok {
			return errors.New("envelope: ppidChain.pid")
		}
		if _, ok := lo["exe"].(string); !ok {
			return errors.New("envelope: ppidChain.exe")
		}
	}
	return nil
}

// strictEnvVars: the envelope env: an array of records exactly {name, value} or {name, value, cut};
// name non-empty without "=", value at most envelope.EnvValueMax code points, cut an integer > 0.
func strictEnvVars(v any) error {
	arr, ok := v.([]any)
	if !ok {
		return errors.New("envelope: env")
	}
	for _, x := range arr {
		o, ok := x.(map[string]any)
		if !ok || (len(o) != 2 && len(o) != 3) {
			return errors.New("envelope: env")
		}
		name, ok1 := o["name"].(string)
		value, ok2 := o["value"].(string)
		if !ok1 || !ok2 || name == "" || strings.Contains(name, "=") || utf8.RuneCountInString(value) > envelope.EnvValueMax {
			return errors.New("envelope: env.name/value")
		}
		if len(o) == 3 {
			if n, ok := safeInt(o["cut"]); !ok || n <= 0 {
				return errors.New("envelope: env.cut")
			}
		}
	}
	return nil
}

// strictRequester: the envelope requester: exactly {host, supervisorId}, both strings.
func strictRequester(v any) error {
	r, ok := v.(map[string]any)
	if !ok || len(r) != 2 {
		return errors.New("envelope: requester")
	}
	if _, ok := r["host"].(string); !ok {
		return errors.New("envelope: requester.host")
	}
	if _, ok := r["supervisorId"].(string); !ok {
		return errors.New("envelope: requester.supervisorId")
	}
	return nil
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// checkItem: whether this record may be signed: a v1 envelope from the pinned supervisor, the
// digest recomputed and matching, id = wd-<digest[:32]>.
func checkItem(it Item, supervisorID string) Card {
	c := Card{Item: it, Meta: parseMeta(it.Meta)}
	if it.Kind != "exec" {
		c.Err = fmt.Errorf("unknown record kind %q", it.Kind)
		return c
	}
	env, err := strictEnvelope(it.Envelope)
	if err != nil {
		c.Err = err
		return c
	}
	c.Env = env
	if env.Requester.SupervisorID != supervisorID {
		c.Err = errors.New("envelope from another supervisor")
		return c
	}
	v, _ := envelope.ParseJSON(it.Envelope)
	_, d, err := envelope.Digest(v)
	if err != nil {
		c.Err = fmt.Errorf("digest: %w", err)
		return c
	}
	if !hex64.MatchString(it.Digest) || d != it.Digest {
		c.Err = fmt.Errorf("digest mismatch: record %.12s, recomputed %.12s", it.Digest, d)
		return c
	}
	if it.ID != envelope.PendingID(d) {
		c.Err = errors.New("id does not match the digest")
	}
	return c
}

// viewOf: the display model of the envelope (display.go).
func viewOf(e *Env) commandViewT {
	chain := make([]string, len(e.PpidChain))
	for i, l := range e.PpidChain {
		chain[i] = l.Exe
	}
	return commandView(viewInput{Argv: e.Argv, Exe: e.Exe, Cwd: e.Cwd, Chain: chain})
}

// displayCommand: the command for one line (JSON interface, decision echo): the inner command of
// the claude-cli wrapper only on an exact template match, otherwise the `sh -c` script or the full
// argv.
func displayCommand(e *Env) string { return viewOf(e).Command }

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func (c Card) hwNeeded() bool { return c.Meta.Hardware != nil && c.Meta.Hardware.Required }

func leftText(expiresAt, serverNow int64) string {
	if expiresAt == 0 || serverNow == 0 {
		return ""
	}
	d := time.Duration(expiresAt-serverNow) * time.Millisecond
	if d <= 0 {
		return "expiring"
	}
	return "expires in " + d.Round(time.Second).String()
}

// Reasons in human words (by the ids of rules, flags and delegation groups from DISPLAY.md).
var ruleReasons = map[string]string{
	"rm-rf":            "deletes the root, a home or a system directory recursively",
	"mkfs":             "creates a file system or wipes a disk",
	"dd":               "dd writes straight to a block device",
	"curl-sh":          "downloads code from the network and runs it at once",
	"pipe-shell":       "pipes a stream into a shell: what runs is not visible",
	"exec-dynamic":     "runs code that is assembled only at run time",
	"decode":           "decodes hidden data (base64, hex)",
	"netcat":           "raw network connection (nc, socat, /dev/tcp): a data leak or remote access",
	"reverse-shell":    "looks like a reverse shell: remote control of this host",
	"chmod-root":       "changes permissions or the owner of system directories recursively",
	"shutdown":         "shutdown or reboot",
	"gateway-stop":     "stops or restarts the OpenClaw gateway",
	"openclaw-json":    "edits openclaw.json",
	"openclaw-cli":     "OpenClaw config, secrets, devices or update commands",
	"openclaw-secrets": "OpenClaw secrets, credentials or database",
	"secrets":          "mentions secrets, tokens or passwords",
	"ssh":              "SSH keys, /etc/shadow or sudoers",
	"sudo":             "raises privileges (sudo, doas, pkexec)",
	"fork-bomb":        "fork bomb",
	"firewall":         "resets or disables the firewall",
	"crontab":          "removes the crontab",
	"git-force":        "git push that rewrites history",
	"injection":        "text inside the command talks to the reviewer: looks like an injection",
}

var flagReasons = map[string]string{
	"control":      "control characters (shown as ⟨U+…⟩)",
	"bidi":         "text direction controls: the line reads differently from what runs",
	"invisible":    "invisible characters or unusual spaces (shown as ⟨U+…⟩)",
	"mixedScript":  "mixed alphabets in one word: letters may be look-alikes",
	"nonAsciiPath": "non-ASCII characters in the program path (exe, argv[0]): a letter may only look Latin",
}

var delegReasons = map[string]string{
	"session-detach":   "detaches from the session: its descendants leave supervision",
	"service-managers": "runs through systemd or D-Bus, outside the wardend tree",
	"containers":       "runs in a container, outside the wardend tree",
	"multiplexers":     "runs in a terminal multiplexer, outside the tree",
	"schedulers":       "delayed run outside the tree",
	"privilege-and-ns": "changes privileges or namespaces",
	"remote":           "runs on another host",
}

// dangerOf: whether the card is dangerous and why: rules, flags and a delegating launch from the
// signed envelope; meta from the transport can only add caution (as in the app and on the watch).
func dangerOf(c Card) (bool, []string) {
	if c.Env == nil {
		return false, nil
	}
	v := viewOf(c.Env)
	reasons := dangerReasons(v)
	reasons = append(reasons, envReasons(envView(c.Env.Vars))...)
	if v.Delegating == nil && (c.Meta.Class == "delegating" || c.Meta.Delegating != "") {
		reasons = append(reasons, "delegating launch (according to the server, not signed)")
	}
	return len(reasons) > 0, reasons
}

// Alphabets in words (DISPLAY.md groups, section 3): a Cyrillic "о" among Latin letters, label ⟨Cyr.⟩.
var (
	scriptAdjective = map[string]string{"latin": "a Latin", "greek": "a Greek", "cyrillic": "a Cyrillic", "armenian": "an Armenian", "cherokee": "a Cherokee", "fullwidth": "a fullwidth"}
	scriptLetters   = map[string]string{"latin": "Latin letters", "greek": "Greek letters", "cyrillic": "Cyrillic letters", "armenian": "Armenian letters", "cherokee": "Cherokee letters", "fullwidth": "fullwidth letters"}
	scriptLabel     = map[string]string{"latin": "Lat.", "greek": "Gr.", "cyrillic": "Cyr.", "armenian": "Arm.", "cherokee": "Cher.", "fullwidth": "FW"}
)

// mixedWordsShown: at most this many words with mixed alphabets in the reasons, the rest as a count.
const mixedWordsShown = 3

// A long word in a reason is cut to a window of wordWindow code points that starts wordLead code
// points before the first foreign letter.
const (
	wordWindow = 40
	wordLead   = 15
)

// clipWord: a long word for a reason: a window around the first foreign letter.
func clipWord(word string, firstOdd int) string {
	r := []rune(word)
	if len(r) <= wordWindow {
		return word
	}
	from := max(0, min(firstOdd-wordLead, len(r)-wordWindow))
	to := min(len(r), from+wordWindow)
	s := string(r[from:to])
	if from > 0 {
		s = "…" + s
	}
	if to < len(r) {
		s += "…"
	}
	return s
}

// mixedReasons: where exactly a letter is substituted: in the word "Sоns" a Cyrillic "о" among
// Latin letters (the same letters of a word only once).
func mixedReasons(words []mixedWord) []string {
	var out []string
	for i, w := range words {
		if i == mixedWordsShown {
			out = append(out, fmt.Sprintf("more words with mixed alphabets: %d", len(words)-mixedWordsShown))
			break
		}
		seen := map[string]bool{}
		var letters []string
		for _, o := range w.Odd {
			if !seen[o.Char] {
				seen[o.Char] = true
				letters = append(letters, scriptAdjective[o.Script]+" \""+o.Char+"\"")
			}
		}
		first := 0
		if len(w.Odd) > 0 {
			first = w.Odd[0].At
		}
		out = append(out, fmt.Sprintf("in the word \"%s\" %s among %s", clipWord(w.Word, first), strings.Join(letters, ", "), scriptLetters[w.Among]))
	}
	return out
}

// markOdd: sanitized text with an alphabet label after each foreign letter of a mixed run (and the
// combining marks after it): `Sо⟨Cyr.⟩ns`. Terminal highlighting is unreliable, hence text.
func markOdd(text string, runs []mixedRun) string {
	odd := map[int]string{}
	for _, r := range runs {
		for _, o := range r.Odd {
			odd[r.At+o.At] = o.Script
		}
	}
	if len(odd) == 0 {
		return text
	}
	rs := []rune(text)
	var b strings.Builder
	for i := 0; i < len(rs); i++ {
		b.WriteRune(rs[i])
		if sc, ok := odd[i]; ok {
			for i+1 < len(rs) && isMark(rs[i+1]) {
				i++
				b.WriteRune(rs[i])
			}
			b.WriteString("⟨" + scriptLabel[sc] + "⟩")
		}
	}
	return b.String()
}

// shownMarked: an envelope string for the terminal: sanitizer and labels of foreign letters.
func shownMarked(s string) string { return markOdd(sanitize(s), mixedRuns(s)) }

// dangerReasons: why the card is dangerous (from the signed envelope only).
func dangerReasons(v commandViewT) []string {
	var out []string
	for _, id := range v.Danger {
		out = append(out, ruleReasons[id])
	}
	for _, f := range v.Flags {
		if f == "mixedScript" && len(v.Mixed) > 0 {
			out = append(out, mixedReasons(v.Mixed)...)
			continue
		}
		out = append(out, flagReasons[f])
	}
	if v.Delegating != nil {
		out = append(out, "delegating launch: "+delegReasons[*v.Delegating])
	}
	return out
}

func formTitle(v commandViewT) string {
	switch v.Form {
	case "wrapper":
		return "Command inside the claude-cli wrapper (full argv below):"
	case "shell":
		return fmt.Sprintf("%s -c script, in parts:", *v.Shell)
	}
	return "Command (argv):"
}

func sepText(s string) string {
	if s == "\n" || s == "" {
		return ""
	}
	return "  " + s
}

// printParts: the parts of the command; the short view shows only the visible ones (a chain with a
// dangerous part is shown whole), and "N more" stands where parts are hidden, so that the visible
// ones do not read as one command in a row. A foreign letter of a mixed run is followed by an
// alphabet label: `Sо⟨Cyr.⟩ns`.
func printParts(w io.Writer, v commandViewT, id string, full bool) {
	vis := map[int]bool{}
	for _, i := range v.Visible {
		vis[i] = true
	}
	gap := 0
	flushGap := func() {
		if gap > 0 {
			fmt.Fprintf(w, "        … %d more (no rules, no flags)\n", gap)
			gap = 0
		}
	}
	for i, p := range v.Parts {
		if !full && !vis[i] {
			gap++
			continue
		}
		flushGap()
		mark := " "
		if len(p.Danger) > 0 || len(p.Flags) > 0 {
			mark = "!"
		}
		fmt.Fprintf(w, "    %s %2d. %s%s\n", mark, i+1, markOdd(p.Text, p.Mixed), sepText(p.Sep))
	}
	flushGap()
	if !full && v.Hidden > 0 {
		fmt.Fprintf(w, "        all parts: wardenctl show %s\n", id)
	}
	if len(v.Parts) == 0 {
		fmt.Fprintf(w, "      (empty argv)\n")
	}
}

// printShort: a list line.
func printShort(w io.Writer, c Card, serverNow int64) {
	if c.Err != nil {
		fmt.Fprintf(w, "  %s  NOT VERIFIED: %s. Must not be signed.\n", c.ID, c.Err)
		return
	}
	v := viewOf(c.Env)
	tags := ""
	if danger, _ := dangerOf(c); danger {
		tags += "  [DANGEROUS]"
	}
	if c.hwNeeded() {
		tags += "  [YubiKey]"
	}
	fmt.Fprintf(w, "  %s  %s%s\n      %s\n", c.ID, leftText(c.ExpiresAt, serverNow), tags, clip(v.headlineText(), 200))
}

// printCard: the full card (show, "details" in watch). First the signed facts, then what is not
// signed.
func printCard(w io.Writer, c Card, serverNow int64, full bool) {
	fmt.Fprintf(w, "Card %s\n", c.ID)
	if c.Err != nil {
		fmt.Fprintf(w, "  NOT VERIFIED: %s. Must not be signed.\n", c.Err)
		if full {
			fmt.Fprintf(w, "  raw envelope: %s\n", sanitize(string(c.Envelope)))
		}
		return
	}
	e := c.Env
	v := viewOf(e)
	if danger, reasons := dangerOf(c); danger {
		fmt.Fprintf(w, "  !!! DANGEROUS: %s\n", strings.Join(reasons, "; "))
	}
	fmt.Fprintf(w, "  Signed facts (digest recomputed, matches):\n")
	fmt.Fprintf(w, "    %s\n", formTitle(v))
	printParts(w, v, c.ID, full)
	if full || v.Form != "argv" {
		fmt.Fprintf(w, "    argv:     %s\n", sanitize(argvJSON(e.Argv)))
	}
	fmt.Fprintf(w, "    exe:      %s\n", shownMarked(e.Exe))
	fmt.Fprintf(w, "    cwd:      %s\n", sanitize(e.Cwd))
	uid := ""
	if e.UID == 0 {
		uid = " (root)"
	}
	fmt.Fprintf(w, "    uid/gid:  %d/%d%s\n", e.UID, e.GID, uid)
	fmt.Fprintf(w, "    host:     %s\n", sanitize(e.Requester.Host))
	printEnv(w, envView(e.Vars), full)
	if l := leftText(c.ExpiresAt, serverNow); l != "" {
		fmt.Fprintf(w, "    deadline: %s; no answer means deny\n", l)
	}
	if full {
		fmt.Fprintf(w, "    process chain (caller, then parents):\n")
		for _, l := range e.PpidChain {
			fmt.Fprintf(w, "      %7d  %s\n", l.Pid, shownMarked(l.Exe))
		}
		fmt.Fprintf(w, "    envHash:  %s (the whole environment; above, only variables that change program behavior)\n", e.EnvHash)
		fmt.Fprintf(w, "    process:  %s\n", sanitize(e.PidfdCookie))
		fmt.Fprintf(w, "    ts:       %s\n", time.UnixMilli(e.Ts).Format("2006-01-02 15:04:05.000"))
		fmt.Fprintf(w, "    digest:   %s (recomputed, matches)\n", c.Digest)
	}
	fmt.Fprintf(w, "  Allowing covers everything this command starts while it runs.\n")
	printAssessment(w, c, v, full)
	printUnconfirmed(w, c, full)
}

// envReasons: danger reasons from the "Environment" block.
func envReasons(ev envViewT) []string {
	var out []string
	for _, n := range ev.Loader {
		out = append(out, n+" in the environment: code of another library runs inside the program, however harmless the command looks")
	}
	for _, e := range ev.Entries {
		for _, f := range e.Flags {
			switch f {
			case "truncated":
				out = append(out, fmt.Sprintf("value of %s is cut (%d chars not shown)", e.Name, e.Cut))
			case "duplicate":
				out = append(out, e.Name+" is set in the environment more than once")
			default:
				out = append(out, "invisible or control characters in the environment ("+e.Name+")")
			}
		}
	}
	return dedup(out)
}

func dedup(l []string) []string {
	seen := map[string]bool{}
	out := l[:0]
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// printEnv: the "Environment" block (DISPLAY.md, section 7a): the short view has the records with
// loader or flags and the count of the rest, the full view has all of them.
func printEnv(w io.Writer, ev envViewT, full bool) {
	if len(ev.Entries) == 0 {
		fmt.Fprintf(w, "    environment: (no variables that change program behavior)\n")
		return
	}
	fmt.Fprintf(w, "    environment (%d):\n", len(ev.Entries))
	hidden := 0
	for _, e := range ev.Entries {
		if !full && !e.Loader && len(e.Flags) == 0 {
			hidden++
			continue
		}
		mark := "  "
		if e.Loader || len(e.Flags) > 0 {
			mark = "! "
		}
		val := e.Value
		if e.Cut > 0 {
			val += fmt.Sprintf("… (+%d chars)", e.Cut)
		}
		fmt.Fprintf(w, "      %s%s=%s\n", mark, e.Name, val)
	}
	if hidden > 0 {
		fmt.Fprintf(w, "      … %d more (wardenctl show <id>)\n", hidden)
	}
}

// printAssessment: "Assessment, not signed": the verdict of the common rules (deterministic, from
// the signed envelope) and the model opinion from meta.judge (sent by the transport), each under
// its own name: a matched rule is not passed off as the model opinion. In the short view the rule
// reasons are already in "!!! DANGEROUS", in the full view they are repeated here.
func printAssessment(w io.Writer, c Card, v commandViewT, full bool) {
	var lines, blocks []string
	injection := false
	for _, id := range v.Danger {
		if id == "injection" {
			injection = true
		} else {
			blocks = append(blocks, ruleReasons[id])
		}
	}
	if len(blocks) > 0 {
		l := "Rule: blocklist matched"
		if full {
			l += " (" + strings.Join(blocks, "; ") + ")"
		}
		lines = append(lines, l)
	}
	if injection {
		lines = append(lines, "Rule: looks like an injection (text inside the command talks to the reviewer)")
	}
	if c.Meta.Judge != "" {
		lines = append(lines, "Model (sent by the transport, meta.judge): "+clip(sanitize(c.Meta.Judge), 300))
	}
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(w, "  Assessment, not signed:\n")
	for _, l := range lines {
		fmt.Fprintf(w, "    %s\n", l)
	}
}

// printUnconfirmed: meta from the transport: not part of the digest, for information only.
func printUnconfirmed(w io.Writer, c Card, full bool) {
	m := c.Meta
	var lines []string
	if m.Class != "" || m.Rule != "" {
		cl := m.Class
		if m.Rule != "" {
			cl += " (rule " + m.Rule + ")"
		}
		lines = append(lines, "class:    "+sanitize(cl))
	}
	if m.Delegating != "" {
		lines = append(lines, "delegating: "+sanitize(m.Delegating))
	}
	if m.InsideRoot > 0 {
		lines = append(lines, fmt.Sprintf("inside an approved tree (root pid %d)", m.InsideRoot))
	}
	if h := m.Hardware; h != nil {
		switch {
		case h.Required && h.Escalated:
			lines = append(lines, "YubiKey required (rule "+sanitize(h.Rule)+"): inside a tree approved without the key; wardend checks it itself")
		case h.Required:
			lines = append(lines, "YubiKey required (rule "+sanitize(h.Rule)+"); wardend checks it itself")
		case h.MinScore != nil:
			lines = append(lines, fmt.Sprintf("YubiKey required at risk score %d and above (the CLI does not sign the score)", *h.MinScore))
		}
		if full {
			lines = append(lines, fmt.Sprintf("YubiKeys in wardend: %d", len(h.Credentials)))
		}
	}
	if full && m.CallerExe != "" {
		lines = append(lines, "callerExe: "+sanitize(m.CallerExe))
	}
	if full && m.Syscall != "" {
		lines = append(lines, "syscall:  "+sanitize(m.Syscall))
	}
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(w, "  Not confirmed (meta from the transport, not part of the digest):\n")
	for _, l := range lines {
		fmt.Fprintf(w, "    %s\n", l)
	}
}

func argvJSON(a []string) string {
	var b bytes.Buffer
	b.WriteByte('[')
	for i, x := range a {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Quote(x))
	}
	b.WriteByte(']')
	return b.String()
}

// minIDPrefix: the shortest unique prefix that stands for a card id.
const minIDPrefix = 6

// cardHex: the hex part of a card id as the user typed it: lower case, without "wd-".
func cardHex(ref string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(ref)), "wd-")
}

// findCard: by the full id, by the id without "wd-" or by a unique prefix (6+ characters).
func findCard(cards []Card, ref string) (Card, error) {
	ref = strings.ToLower(strings.TrimSpace(ref))
	hexID := cardHex(ref)
	full := "wd-" + hexID
	var m []Card
	for _, c := range cards {
		if c.ID == full {
			return c, nil
		}
		if len(hexID) >= minIDPrefix && strings.HasPrefix(c.ID, full) {
			m = append(m, c)
		}
	}
	switch len(m) {
	case 1:
		return m[0], nil
	case 0:
		return Card{}, fmt.Errorf("card %s is not in the queue (expired, decided or a wrong link)", ref)
	}
	return Card{}, fmt.Errorf("prefix %s is ambiguous: %d cards", ref, len(m))
}
