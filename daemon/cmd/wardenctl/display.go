// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// "Card truth" (protocol/DISPLAY.md): how to show an exec to a human. The same specification as
// app/src/core/display.ts (reference) and app/targets/watch/Protocol/Display.swift; all three are
// checked by the shared vectors protocol/vectors/display_vectors.json (display_test.go). Only the
// display changes: the envelope digest is signed as is.

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// ---- code point classes (DISPLAY.md, section 2) ----

type cpClassT string

const (
	clsLF        cpClassT = "lf"
	clsTab       cpClassT = "tab"
	clsCtrlSpace cpClassT = "ctrlSpace"
	clsCtrl      cpClassT = "ctrl"
	clsBidi      cpClassT = "bidi"
	clsOddSpace  cpClassT = "oddSpace"
	clsInvisible cpClassT = "invisible"
)

type cpRange struct {
	Lo, Hi rune
	Class  cpClassT
}

var cpClasses = []cpRange{
	{0x0000, 0x0008, clsCtrl},
	{0x0009, 0x0009, clsTab},
	{0x000a, 0x000a, clsLF},
	{0x000b, 0x000d, clsCtrlSpace},
	{0x000e, 0x001f, clsCtrl},
	{0x007f, 0x0084, clsCtrl},
	{0x0085, 0x0085, clsCtrlSpace},
	{0x0086, 0x009f, clsCtrl},
	{0x00a0, 0x00a0, clsOddSpace},
	{0x00ad, 0x00ad, clsInvisible},
	{0x034f, 0x034f, clsInvisible},
	{0x0600, 0x0605, clsInvisible},
	{0x061c, 0x061c, clsBidi},
	{0x06dd, 0x06dd, clsInvisible},
	{0x070f, 0x070f, clsInvisible},
	{0x0890, 0x0891, clsInvisible},
	{0x08e2, 0x08e2, clsInvisible},
	{0x115f, 0x1160, clsInvisible},
	{0x1680, 0x1680, clsOddSpace},
	{0x17b4, 0x17b5, clsInvisible},
	{0x180b, 0x180f, clsInvisible},
	{0x2000, 0x200a, clsOddSpace},
	{0x200b, 0x200d, clsInvisible},
	{0x200e, 0x200f, clsBidi},
	{0x2028, 0x2029, clsCtrlSpace},
	{0x202a, 0x202e, clsBidi},
	{0x202f, 0x202f, clsOddSpace},
	{0x205f, 0x205f, clsOddSpace},
	{0x2060, 0x2064, clsInvisible},
	{0x2066, 0x2069, clsBidi},
	{0x206a, 0x206f, clsInvisible},
	{0x2800, 0x2800, clsInvisible},
	{0x3000, 0x3000, clsOddSpace},
	{0x3164, 0x3164, clsInvisible},
	{0xd800, 0xdfff, clsCtrl},
	{0xfeff, 0xfeff, clsInvisible},
	{0xffa0, 0xffa0, clsInvisible},
	{0xfff9, 0xfffb, clsInvisible},
	{0x110bd, 0x110bd, clsInvisible},
	{0x110cd, 0x110cd, clsInvisible},
	{0x13430, 0x1343f, clsInvisible},
	{0x1bca0, 0x1bca3, clsInvisible},
	{0x1d173, 0x1d17a, clsInvisible},
	{0xe0001, 0xe0001, clsInvisible},
	{0xe0020, 0xe007f, clsInvisible},
}

// cpClass: the class of code point c, "" for a plain one (cpClasses is sorted by range).
func cpClass(c rune) cpClassT {
	i := sort.Search(len(cpClasses), func(i int) bool { return cpClasses[i].Hi >= c })
	if i < len(cpClasses) && cpClasses[i].Lo <= c {
		return cpClasses[i].Class
	}
	return ""
}

// flags in specification order
var flagOrder = []string{"control", "bidi", "invisible", "mixedScript", "nonAsciiPath"}

var flagOfClass = map[cpClassT]string{clsCtrlSpace: "control", clsCtrl: "control", clsBidi: "bidi", clsOddSpace: "invisible", clsInvisible: "invisible"}

type flagSet map[string]bool

func (f flagSet) list() []string {
	out := []string{}
	for _, k := range flagOrder {
		if f[k] {
			out = append(out, k)
		}
	}
	return out
}

func (f flagSet) add(l []string) {
	for _, k := range l {
		f[k] = true
	}
}

func cpMarker(c rune) string { return fmt.Sprintf("⟨U+%04X⟩", c) }

// sanitizeFlags: the display sanitizer: invisible and control characters become ⟨U+XXXX⟩ and a flag.
func sanitizeFlags(s string) (string, []string) {
	var b strings.Builder
	fl := flagSet{}
	for _, c := range s {
		switch k := cpClass(c); k {
		case "":
			b.WriteRune(c)
		case clsLF:
			b.WriteString("⏎")
		case clsTab:
			b.WriteString("⇥")
		default:
			b.WriteString(cpMarker(c))
			fl[flagOfClass[k]] = true
		}
	}
	return b.String(), fl.list()
}

// sanitize: an untrusted string for the terminal (text only, no flags).
func sanitize(s string) string {
	t, _ := sanitizeFlags(s)
	return t
}

// normalizeForRules: the text for the rules (DISPLAY.md, section 5.1).
func normalizeForRules(s string) string {
	var b strings.Builder
	prevSpace := false
	for _, c := range s {
		k := cpClass(c)
		var ch rune
		switch {
		case k == clsLF:
			ch = '\n'
		case k == clsTab || k == clsCtrlSpace || k == clsOddSpace || c == ' ':
			ch = ' '
		case k != "":
			continue
		case c == '\'' || c == '"' || c == '\\':
			continue
		case c >= 'A' && c <= 'Z':
			ch = c + 0x20
		case c >= 0x410 && c <= 0x42f: // Cyrillic А-Я to а-я
			ch = c + 0x20
		case c == 0x401: // Ё to ё
			ch = 0x451
		default:
			ch = c
		}
		if ch == ' ' {
			if prevSpace {
				continue
			}
			prevSpace = true
		} else {
			prevSpace = false
		}
		b.WriteRune(ch)
	}
	return b.String()
}

// ---- rules (DISPLAY.md, section 5) ----

type displayRule struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Re   string `json:"re"`
	re   *regexp.Regexp
}

var displayRules = []*displayRule{
	{ID: "rm-rf", Kind: "block", Re: `\brm\s+(-[a-z]*\s+)*(-[a-z]*r[a-z]*|--recursive)(\s+-[a-z-]*)*(\s+[^\s;&|]+)*?\s+(\/|~|\$\{?home\}?|\/home(\/[^\/\s]+)?|\/root|\/etc|\/usr|\/var|\/boot|\/bin|\/sbin|\/lib|\/lib64|\/opt|\/srv|\/mnt(\/[^\/\s]+)?|\/media)\/?\*?(\s|$)`},
	{ID: "mkfs", Kind: "block", Re: `\b(mkfs(\.[a-z0-9]+)?|mke2fs|mkswap|wipefs|sfdisk|cfdisk|sgdisk|blkdiscard)\b`},
	{ID: "dd", Kind: "block", Re: `\bdd\b[^|;&]*\bof=\/dev\/(sd|nvme|mmcblk|disk|vd|hd|xvd)`},
	{ID: "curl-sh", Kind: "block", Re: `\b(curl|wget)\b[^|]*\|&?\s*(sudo\s+)?(ba|z|da|k)?sh\b`},
	{ID: "pipe-shell", Kind: "block", Re: `\|&?\s*(sudo\s+)?(env\s+)?(\/[a-z\/]*\/)?(ba|z|da|k|fi|c|tc)?sh\b`},
	{ID: "exec-dynamic", Kind: "block", Re: "\\beval\\s+(\\$|`)|\\b(ba|z|da|k)?sh\\s+-[a-z]*c\\s+(\\$|`)|(^|[\\s;&|])(source|\\.)\\s+<\\("},
	{ID: "decode", Kind: "block", Re: `\bbase64\s+([^\s;&|]+\s+)*?(-[a-z]*d[a-z]*|--decode)\b|\bxxd\s+([^\s;&|]+\s+)*?-[a-z]*r`},
	{ID: "netcat", Kind: "block", Re: `(^|[\s|;&(\/])(nc|ncat|netcat|socat|telnet)(\s|$)|\/dev\/(tcp|udp)\/`},
	{ID: "reverse-shell", Kind: "block", Re: `\bsocket\b.*\.connect\(|(\/|\b)(ba|z|da|k)?sh\W{1,3}-i\b|\bpty\.spawn\b`},
	{ID: "chmod-root", Kind: "block", Re: `\bch(mod|own|grp)\s+(-[a-z]*r[a-z]*|--recursive)[^;&|]*\s\/(bin|boot|etc|home|lib|usr|var)?\/?(\s|$)`},
	{ID: "shutdown", Kind: "block", Re: `\b(shutdown|reboot|poweroff|halt|init\s+[06])\b`},
	{ID: "gateway-stop", Kind: "block", Re: `\bsystemctl\s+(--user\s+)?(stop|restart|disable|mask|kill)\s+\S*openclaw`},
	{ID: "openclaw-json", Kind: "block", Re: `openclaw\.json\b`},
	{ID: "openclaw-cli", Kind: "block", Re: `\bopenclaw\s+(config\s+(set|unset|patch)|secrets|devices\s+(approve|clear|remove)|update)\b`},
	{ID: "openclaw-secrets", Kind: "block", Re: `\.openclaw\/(secrets|credentials|agents\/[^\/\s]+\/agent\/[^\s]*sqlite)`},
	{ID: "secrets", Kind: "block", Re: `\b(secret|token|password|passwd|api[_-]?key|private[_-]?key)s?\b`},
	{ID: "ssh", Kind: "block", Re: `\/etc\/(shadow|sudoers)\b|(~|\$\{?home\}?)\/\.ssh\b|\.ssh\/(id_|authorized_keys)`},
	{ID: "sudo", Kind: "block", Re: `\b(sudo|doas|pkexec)\b`},
	{ID: "fork-bomb", Kind: "block", Re: `:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`},
	{ID: "firewall", Kind: "block", Re: `\b(iptables|ip6tables|nft|ufw)\b.*(\s(-f|--flush)\b|\b(flush|reset|disable)\b)`},
	{ID: "crontab", Kind: "block", Re: `\bcrontab\s+([^\s;&|]+\s+)*?-[a-z]*r[a-z]*\b`},
	{ID: "git-force", Kind: "block", Re: `\bgit\s+push\b[^;&|]*(--force|\s-[a-z]*f[a-z]*\b|\s\+\S)`},
	{ID: "injection", Kind: "injection", Re: `ignore\s+(all\s+|the\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)|you\s+are\s+(now\s+)?(an?\s+)?(ai|assistant|model|reviewer|approver|judge)\b|\bas\s+(the\s+|an?\s+)?(ai\s+)?(reviewer|approver|judge)\b|\bapprove\s+(this|it|the\s+command|immediately)\b|\ballow[- ](once|always)\b|\bdecision\s*[:=]\s*(allow|deny|ask)\b|\bthis\s+(command|request|action)\s+is\s+(safe|harmless|pre-?approved)|\bdo\s+not\s+(deny|block|flag)\b|\bplease\s+(approve|allow)\b|\bsystem\s+prompt\b|\bpre-?approved\b|\bnote\s+(to|for)\s+(the\s+)?(ai|reviewer|approver|judge|model)\b|\b(reviewer|approver)\s*(note\b|:)|одобри|разреши\s+(эту|команду|это)|ты\s+(ии|модель|ревьюер|судья)|игнорируй\s+(предыдущие|все|инструкции)`},
}

func init() {
	for _, r := range displayRules {
		r.re = regexp.MustCompile(r.Re)
	}
}

func ruleByID(id string) *displayRule {
	for _, r := range displayRules {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// matchRules: the ids of the rules that matched the normalized text, in table order.
func matchRules(norm string) []string {
	out := []string{}
	for _, r := range displayRules {
		if r.re.MatchString(norm) {
			out = append(out, r.ID)
		}
	}
	return out
}

func orderRules(ids map[string]bool) []string {
	out := []string{}
	for _, r := range displayRules {
		if ids[r.ID] {
			out = append(out, r.ID)
		}
	}
	return out
}

// ---- delegating launches (the same groups as delegating in daemon/policy/defaults.json) ----

type delegGroup struct {
	ID    string   `json:"id"`
	Names []string `json:"names"`
}

var delegatingGroups = []delegGroup{
	{"session-detach", []string{"setsid", "daemon", "start-stop-daemon", "disown"}},
	{"service-managers", []string{"systemd-run", "systemctl", "service", "busctl", "dbus-send", "gdbus", "loginctl", "machinectl"}},
	{"containers", []string{"docker", "podman", "nerdctl", "ctr", "kubectl", "lxc", "lxc-attach", "incus", "firejail", "bwrap", "flatpak-spawn", "distrobox", "toolbox"}},
	{"multiplexers", []string{"tmux", "screen", "zellij", "abduco", "dtach"}},
	{"schedulers", []string{"at", "batch", "crontab", "anacron"}},
	{"privilege-and-ns", []string{"sudo", "su", "doas", "pkexec", "runuser", "nsenter", "unshare", "chroot", "setpriv", "capsh"}},
	{"remote", []string{"ssh", "mosh", "rsh", "scp", "sftp"}},
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func delegatingOf(argv []string, exe string) string {
	names := []string{baseName(exe), ""}
	if len(argv) > 0 {
		names[1] = baseName(argv[0])
	}
	for _, g := range delegatingGroups {
		for _, n := range g.Names {
			if n == names[0] || n == names[1] {
				return g.ID
			}
		}
	}
	return ""
}

// ---- homoglyphs (DISPLAY.md, section 3) ----
// Mixed alphabets inside one run of letters and non-ASCII in the program path. A word entirely in
// one alphabet (Russian file and folder names) gives no flags.

// scriptRanges: alphabet groups: 1 Latin, 2 Greek, 3 Cyrillic, 4 Armenian, 5 Cherokee,
// 6 fullwidth Latin.
var scriptRanges = []struct {
	Lo, Hi rune
	S      int
}{
	{0x0041, 0x005a, 1}, {0x0061, 0x007a, 1}, {0x00c0, 0x00d6, 1}, {0x00d8, 0x00f6, 1}, {0x00f8, 0x024f, 1},
	{0x0370, 0x03ff, 2},
	{0x0400, 0x052f, 3},
	{0x0531, 0x058f, 4},
	{0x13a0, 0x13ff, 5},
	{0x1c80, 0x1c8f, 3},
	{0x1e00, 0x1eff, 1},
	{0x1f00, 0x1fff, 2},
	{0x2de0, 0x2dff, 3},
	{0xa640, 0xa69f, 3},
	{0xab70, 0xabbf, 5},
	{0xff21, 0xff3a, 6}, {0xff41, 0xff5a, 6},
}

func scriptOf(c rune) int {
	for _, r := range scriptRanges {
		if c >= r.Lo && c <= r.Hi {
			return r.S
		}
	}
	return 0
}

// markRanges: combining marks: they have no alphabet of their own and do not break a run of letters.
var markRanges = [][2]rune{{0x0300, 0x036f}, {0x1ab0, 0x1aff}, {0x1dc0, 0x1dff}, {0x20d0, 0x20ff}, {0xfe20, 0xfe2f}}

func isMark(c rune) bool {
	for _, r := range markRanges {
		if c >= r[0] && c <= r[1] {
			return true
		}
	}
	return false
}

// scriptNames: the names of groups 1..6 (vectors.scriptNames) for among and odd[].script.
var scriptNames = []string{"latin", "greek", "cyrillic", "armenian", "cherokee", "fullwidth"}

// oddLetter: a letter not of the main alphabet of the run; At is the index in Word (code points of
// the shown text).
type oddLetter struct {
	At     int    `json:"at"`
	Char   string `json:"char"`
	Script string `json:"script"`
}

// mixedRun: a mixed run of letters as a human sees it: At is the index of the first code point of
// the run in the sanitized text, Word is the run in that text, Among is the main alphabet (the most
// letters; on a tie, the one whose letter comes first), Odd are the letters of other alphabets.
type mixedRun struct {
	At    int         `json:"at"`
	Word  string      `json:"word"`
	Among string      `json:"among"`
	Odd   []oddLetter `json:"odd"`
}

// mixedWord: a mixed word of the card (no position: from argv, exe or the chain).
type mixedWord struct {
	Word  string      `json:"word"`
	Among string      `json:"among"`
	Odd   []oddLetter `json:"odd"`
}

// shownLen: how many code points c takes after the sanitizer.
func shownLen(c rune) int {
	switch cpClass(c) {
	case "", clsLF, clsTab:
		return 1
	}
	return len([]rune(cpMarker(c)))
}

// mixedRuns: the mixed runs of s (DISPLAY.md, section 3) with positions in the sanitized text of
// s: it shows not only that alphabets are mixed, but also which letter is foreign.
func mixedRuns(s string) []mixedRun {
	type letter struct {
		at, g int
		c     rune
	}
	out := []mixedRun{}
	pos, runAt := 0, -1
	var raw []rune
	var letters []letter
	flush := func() {
		if runAt >= 0 {
			count := map[int]int{}
			var order []int // groups in the order of their first letter
			for _, l := range letters {
				if count[l.g] == 0 {
					order = append(order, l.g)
				}
				count[l.g]++
			}
			if len(order) > 1 {
				main := order[0]
				for _, g := range order[1:] {
					if count[g] > count[main] {
						main = g
					}
				}
				odd := []oddLetter{}
				for _, l := range letters {
					if l.g != main {
						odd = append(odd, oddLetter{At: l.at, Char: string(l.c), Script: scriptNames[l.g-1]})
					}
				}
				out = append(out, mixedRun{At: runAt, Word: sanitize(string(raw)), Among: scriptNames[main-1], Odd: odd})
			}
		}
		runAt, raw, letters = -1, nil, nil
	}
	for _, c := range s {
		g := scriptOf(c)
		if g == 0 && !isMark(c) {
			flush()
		} else {
			if runAt < 0 {
				runAt = pos
			}
			if g != 0 {
				letters = append(letters, letter{pos - runAt, g, c})
			}
			raw = append(raw, c)
		}
		pos += shownLen(c)
	}
	flush()
	return out
}

// mixedWordsOf: the mixed words of the strings in order, without repeats (the same word in argv[0]
// and exe counts once).
func mixedWordsOf(strs []string) []mixedWord {
	out := []mixedWord{}
	seen := map[string]bool{}
	for _, s := range strs {
		for _, r := range mixedRuns(s) {
			w := mixedWord{Word: r.Word, Among: r.Among, Odd: r.Odd}
			k := fmt.Sprintf("%q %s %v", w.Word, w.Among, w.Odd)
			if !seen[k] {
				seen[k] = true
				out = append(out, w)
			}
		}
	}
	return out
}

// tokenFlags: mixedScript if a run of letters (group letters and combining marks in a row) mixes
// alphabets. Digits, punctuation, "/", ".", "-", "_" and spaces end a run: `media/Сериалы` is not
// mixed, `pаypal` with a Cyrillic "а" is mixed.
func tokenFlags(s string) []string {
	first := 0
	for _, c := range s {
		sc := scriptOf(c)
		if sc == 0 {
			if !isMark(c) {
				first = 0
			}
			continue
		}
		if first == 0 {
			first = sc
		} else if sc != first {
			return []string{"mixedScript"}
		}
	}
	return []string{}
}

// programFlags: the program path (exe, argv[0], chain exe): sanitizer, any non-ASCII character,
// mixed alphabets.
func programFlags(p string) []string {
	fl := flagSet{}
	_, f := sanitizeFlags(p)
	fl.add(f)
	for _, c := range p {
		if c > 0x7f {
			fl["nonAsciiPath"] = true
		}
	}
	fl.add(tokenFlags(p))
	return fl.list()
}

// ---- lexer (DISPLAY.md, section 4) ----

type rawPart struct {
	Raw string
	Sep string
}

func isWS(c rune) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func trimWS(a []rune) []rune {
	i, j := 0, len(a)
	for i < j && isWS(a[i]) {
		i++
	}
	for j > i && isWS(a[j-1]) {
		j--
	}
	return a[i:j]
}

func endSingle(s []rune, i int) int {
	for j := i + 1; j < len(s); j++ {
		if s[j] == '\'' {
			return j
		}
	}
	return len(s) - 1
}

func endEscaped(s []rune, i int, q rune) int {
	j := i + 1
	for j < len(s) {
		if s[j] == '\\' {
			j += 2
			continue
		}
		if s[j] == q {
			return j
		}
		j++
	}
	return len(s) - 1
}

func endParens(s []rune, i int) int {
	depth := 0
	j := i
	for j < len(s) {
		c := s[j]
		if c == '\\' {
			j += 2
			continue
		}
		switch c {
		case '\'':
			j = endSingle(s, j)
		case '"', '`':
			j = endEscaped(s, j, c)
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j
			}
		}
		j++
	}
	return len(s) - 1
}

func isWordStop(c rune) bool { return isWS(c) || strings.ContainsRune(";&|<>()", c) }

func heredocWord(s []rune, k int) ([]rune, int) {
	var word []rune
	j := k
	for j < len(s) && !isWordStop(s[j]) {
		c := s[j]
		switch {
		case c == '\'' || c == '"':
			var e int
			if c == '\'' {
				e = endSingle(s, j)
			} else {
				e = endEscaped(s, j, '"')
			}
			end := e + 1
			if s[e] == c && e > j {
				end = e
			}
			word = append(word, s[j+1:end]...)
			j = e + 1
		case c == '\\' && j+1 < len(s):
			word = append(word, s[j+1])
			j += 2
		default:
			word = append(word, c)
			j++
		}
	}
	if j > len(s) {
		j = len(s)
	}
	return word, j
}

func splitShell(script string) []rawPart {
	s := []rune(script)
	n := len(s)
	var parts []rawPart
	var cur []rune
	type heredoc struct {
		delim []rune
		strip bool
	}
	var hds []heredoc
	emit := func(sep string) {
		if t := trimWS(cur); len(t) > 0 {
			parts = append(parts, rawPart{string(t), sep})
		}
		cur = nil
	}
	take := func(from, to int) {
		for k := from; k <= to && k < n; k++ {
			cur = append(cur, s[k])
		}
	}
	at := func(k int) rune {
		if k >= 0 && k < n {
			return s[k]
		}
		return -1
	}
	last := func() rune {
		if len(cur) == 0 {
			return -1
		}
		return cur[len(cur)-1]
	}
	i := 0
	for i < n {
		c := s[i]
		next := at(i + 1)
		switch {
		case c == '\\':
			take(i, i+1)
			i += 2
		case c == '\'':
			e := endSingle(s, i)
			take(i, e)
			i = e + 1
		case c == '"' || c == '`':
			e := endEscaped(s, i, c)
			take(i, e)
			i = e + 1
		case (c == '$' || c == '<' || c == '>') && next == '(':
			e := endParens(s, i+1)
			take(i, e)
			i = e + 1
		case c == '#' && (len(cur) == 0 || isWS(last())):
			e := i
			for e < n && s[e] != '\n' {
				e++
			}
			take(i, e-1)
			i = e
		case c == '<' && next == '<' && at(i+2) != '<':
			j := i + 2
			strip := false
			if at(j) == '-' {
				strip = true
				j++
			}
			k := j
			for k < n && (s[k] == ' ' || s[k] == '\t') {
				k++
			}
			word, end := heredocWord(s, k)
			if len(word) == 0 {
				take(i, j-1)
				i = j
				continue
			}
			hds = append(hds, heredoc{append([]rune(nil), word...), strip})
			take(i, end-1)
			i = end
		case c == '\n':
			if len(hds) > 0 {
				cur = append(cur, '\n')
				i++
				for _, h := range hds {
					for i < n {
						e := i
						for e < n && s[e] != '\n' {
							e++
						}
						line := s[i:e]
						if h.strip {
							t := 0
							for t < len(line) && line[t] == '\t' {
								t++
							}
							line = line[t:]
						}
						take(i, e)
						i = e + 1
						if string(line) == string(h.delim) {
							break
						}
					}
				}
				hds = nil
				emit("\n")
				continue
			}
			emit("\n")
			i++
		case c == ';':
			emit(";")
			i++
		case c == '&':
			switch p := last(); {
			case p == '<' || p == '>':
				cur = append(cur, c)
				i++
			case next == '&':
				emit("&&")
				i += 2
			case next == '>':
				cur = append(cur, '&', '>')
				i += 2
			default:
				emit("&")
				i++
			}
		case c == '|':
			switch {
			case last() == '>':
				cur = append(cur, c)
				i++
			case next == '|':
				emit("||")
				i += 2
			default:
				emit("|")
				if next == '&' {
					i += 2
				} else {
					i++
				}
			}
		default:
			cur = append(cur, c)
			i++
		}
	}
	emit("")
	return parts
}

// ---- claude-cli wrapper (DISPLAY.md, section 6) ----

const (
	wrapMid   = " 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval "
	wrapTail  = " && pwd -P >| "
	wrapStdin = " < /dev/null"
)

var (
	safePathRe     = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	snapshotFileRe = regexp.MustCompile(`^snapshot-bash-[0-9]+-[a-z0-9]+\.sh$`)
	cwdFileRe      = regexp.MustCompile(`^claude-[0-9a-f]+-cwd$`)
)

func safePath(p string) bool { return len(p) > 1 && p[0] == '/' && safePathRe.MatchString(p) }

type claudeWrap struct {
	Command, Snapshot, CwdFile string
}

// claudeWrapper: the inner command of the claude-cli wrapper exactly by the template; otherwise nil.
func claudeWrapper(argv []string) *claudeWrap {
	if len(argv) != 3 || baseName(argv[0]) != "bash" || argv[1] != "-c" {
		return nil
	}
	s := argv[2]
	if !strings.HasPrefix(s, "source ") {
		return nil
	}
	sp := strings.Index(s[7:], " ")
	if sp < 0 {
		return nil
	}
	sp += 7
	snap := s[7:sp]
	i := strings.LastIndex(snap, "/")
	if !safePath(snap) || i < 0 || baseName(snap[:i]) != "shell-snapshots" || !snapshotFileRe.MatchString(snap[i+1:]) {
		return nil
	}
	if !strings.HasPrefix(s[sp:], wrapMid) {
		return nil
	}
	i = sp + len(wrapMid)
	var cmd strings.Builder
	segs := 0
	for {
		if i < len(s) && s[i] == '\'' {
			e := strings.IndexByte(s[i+1:], '\'')
			if e < 0 {
				return nil
			}
			cmd.WriteString(s[i+1 : i+1+e])
			i += e + 2
			segs++
		} else if segs > 0 && strings.HasPrefix(s[i:], `"'"`) {
			cmd.WriteByte('\'')
			i += 3
		} else {
			break
		}
	}
	if segs == 0 {
		return nil
	}
	if strings.HasPrefix(s[i:], wrapStdin) {
		i += len(wrapStdin)
	}
	if !strings.HasPrefix(s[i:], wrapTail) {
		return nil
	}
	cwdFile := s[i+len(wrapTail):]
	if !safePath(cwdFile) || !cwdFileRe.MatchString(baseName(cwdFile)) {
		return nil
	}
	return &claudeWrap{Command: cmd.String(), Snapshot: snap, CwdFile: cwdFile}
}

// ---- display model ----

type viewPart struct {
	Text   string     `json:"text"`
	Sep    string     `json:"sep"`
	Danger []string   `json:"danger"`
	Flags  []string   `json:"flags"`
	Mixed  []mixedRun `json:"mixed"` // where in Text a letter is substituted
}

type commandViewT struct {
	Form       string      `json:"form"`
	Wrapper    *string     `json:"wrapper"`
	Shell      *string     `json:"shell"`
	Command    string      `json:"command"`
	Parts      []viewPart  `json:"parts"`
	Visible    []int       `json:"visible"`
	Hidden     int         `json:"hidden"`
	Headline   *int        `json:"headline"`
	Danger     []string    `json:"danger"`
	Flags      []string    `json:"flags"`
	Mixed      []mixedWord `json:"mixed"` // the mixed words behind the card's mixedScript flag
	Delegating *string     `json:"delegating"`
	Dangerous  bool        `json:"dangerous"`
}

var (
	shells     = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true}
	shellCFlag = regexp.MustCompile(`^-[eilux]*c[eilux]*$`)
	evalPartRe = regexp.MustCompile(`(^|[\s;&|(])eval(\s|$)`)
)

func shellQuote(a []string) string {
	out := make([]string, len(a))
	for i, x := range a {
		if plainArg.MatchString(x) {
			out[i] = x
		} else {
			out[i] = "'" + strings.ReplaceAll(x, "'", `'\''`) + "'"
		}
	}
	return strings.Join(out, " ")
}

var plainArg = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

type normPart struct {
	raw, sep, norm string
}

// partsOf: the view parts of a command and whether the short view must show all of them. A card
// rule that no single part matches goes to every pipeline whose joined text matches it; when no
// pipeline does, the whole command is shown.
func partsOf(raws []normPart, cardDanger []string) ([]viewPart, bool) {
	parts := make([]viewPart, len(raws))
	for i, r := range raws {
		t, f := sanitizeFlags(r.raw)
		fl := flagSet{}
		fl.add(f)
		fl.add(tokenFlags(r.raw))
		parts[i] = viewPart{Text: t, Sep: r.sep, Danger: matchRules(r.norm), Flags: fl.list(), Mixed: mixedRuns(r.raw)}
	}
	var pipes [][]int
	var cur []int
	for i, r := range raws {
		cur = append(cur, i)
		if r.sep != "|" {
			pipes = append(pipes, cur)
			cur = nil
		}
	}
	if len(cur) > 0 {
		pipes = append(pipes, cur)
	}
	showAll := false
	for _, id := range cardDanger {
		attributed := false
		for _, p := range parts {
			attributed = attributed || slices.Contains(p.Danger, id)
		}
		if attributed {
			continue
		}
		rule := ruleByID(id)
		found := false
		for _, pipe := range pipes {
			if len(pipe) < 2 {
				continue
			}
			texts := make([]string, len(pipe))
			for k, i := range pipe {
				texts[k] = raws[i].norm
			}
			if rule.re.MatchString(strings.Join(texts, " | ")) {
				found = true
				for _, i := range pipe {
					ids := map[string]bool{id: true}
					for _, x := range parts[i].Danger {
						ids[x] = true
					}
					parts[i].Danger = orderRules(ids)
				}
			}
		}
		if !found {
			showAll = true
		}
	}
	return parts, showAll
}

// riskyChains: the parts of chains (joined by "|", "|&", "&&", "||"; ";", "&" and a newline end a
// chain) that contain a part with a rule or a flag: such chains are shown whole, otherwise
// `tar cz ~/.ssh | 1 more | nc …` hides what stands between the dangerous parts.
func riskyChains(parts []viewPart, risky func(int) bool) []bool {
	out := make([]bool, len(parts))
	start := 0
	for i, p := range parts {
		if (p.Sep == "|" || p.Sep == "&&" || p.Sep == "||") && i < len(parts)-1 {
			continue
		}
		hit := false
		for k := start; k <= i; k++ {
			hit = hit || risky(k)
		}
		for k := start; k <= i; k++ {
			out[k] = hit
		}
		start = i + 1
	}
	return out
}

// visibility: the parts the short view shows (all of a short command; otherwise the first two, the
// last, risky chains and eval), how many it hides, and the headline part: the first visible risky
// part, else the first visible eval, else the first part (nil when there are no parts).
func visibility(parts []viewPart, norms []string, showAll bool) ([]int, int, *int) {
	n := len(parts)
	risky := func(i int) bool { return len(parts[i].Danger) > 0 || len(parts[i].Flags) > 0 }
	hasEval := func(i int) bool { return evalPartRe.MatchString(norms[i]) }
	inRiskyChain := riskyChains(parts, risky)
	visible := []int{}
	for i := 0; i < n; i++ {
		if showAll || n <= 4 || i < 2 || i == n-1 || inRiskyChain[i] || hasEval(i) {
			visible = append(visible, i)
		}
	}
	if n == 0 {
		return visible, 0, nil
	}
	head := 0
	found := false
	for _, i := range visible {
		if risky(i) {
			head, found = i, true
			break
		}
	}
	if !found {
		for _, i := range visible {
			if hasEval(i) {
				head = i
				break
			}
		}
	}
	return visible, n - len(visible), &head
}

type viewInput struct {
	Argv  []string `json:"argv"`
	Exe   string   `json:"exe"`
	Cwd   string   `json:"cwd"`
	Chain []string `json:"chain"`
}

func strp(s string) *string { return &s }

// commandView: the display of an exec envelope (all inputs are signed envelope fields).
func commandView(in viewInput) commandViewT {
	argv := in.Argv
	wrap := claudeWrapper(argv)
	v := commandViewT{}
	var raws []normPart
	var cardDanger []string
	if wrap != nil || (len(argv) == 3 && shells[baseName(argv[0])] && shellCFlag.MatchString(argv[1])) {
		if wrap != nil {
			v.Form, v.Wrapper, v.Command = "wrapper", strp("claude-cli"), wrap.Command
		} else {
			v.Form, v.Command = "shell", argv[2]
		}
		v.Shell = strp(baseName(argv[0]))
		for _, p := range splitShell(v.Command) {
			raws = append(raws, normPart{p.Raw, p.Sep, normalizeForRules(p.Raw)})
		}
		cardDanger = matchRules(normalizeForRules(v.Command))
	} else {
		v.Form = "argv"
		v.Command = shellQuote(argv)
		texts := []string{strings.Join(argv, " ")}
		if len(argv) > 0 && in.Exe != "" {
			texts = append(texts, strings.Join(append([]string{baseName(in.Exe)}, argv[1:]...), " "))
		}
		ids := map[string]bool{}
		for _, t := range texts {
			for _, id := range matchRules(normalizeForRules(t)) {
				ids[id] = true
			}
		}
		cardDanger = orderRules(ids)
		if len(argv) > 0 {
			raws = []normPart{{v.Command, "", normalizeForRules(texts[0])}}
		}
	}
	parts, showAll := partsOf(raws, cardDanger)
	if v.Form == "argv" && len(parts) > 0 {
		parts[0].Danger = cardDanger
		fl := flagSet{}
		fl.add(parts[0].Flags)
		for _, a := range argv {
			fl.add(tokenFlags(a))
		}
		fl.add(programFlags(argv[0]))
		parts[0].Flags = fl.list()
		showAll = false
	}
	norms := make([]string, len(raws))
	for i, r := range raws {
		norms[i] = r.norm
	}
	v.Parts = parts
	if v.Parts == nil {
		v.Parts = []viewPart{}
	}
	v.Visible, v.Hidden, v.Headline = visibility(parts, norms, showAll)
	fl := flagSet{}
	for _, a := range argv {
		_, f := sanitizeFlags(a)
		fl.add(f)
		fl.add(tokenFlags(a))
	}
	if len(argv) > 0 {
		fl.add(programFlags(argv[0]))
	}
	if in.Exe != "" {
		fl.add(programFlags(in.Exe))
	}
	_, f := sanitizeFlags(in.Cwd)
	fl.add(f)
	for _, c := range in.Chain {
		fl.add(programFlags(c))
	}
	v.Flags = fl.list()
	v.Mixed = mixedWordsOf(append(append(append([]string{}, argv...), in.Exe), in.Chain...))
	v.Danger = cardDanger
	if d := delegatingOf(argv, in.Exe); d != "" {
		v.Delegating = strp(d)
	}
	v.Dangerous = len(cardDanger) > 0 || len(v.Flags) > 0 || v.Delegating != nil
	return v
}

// headlineText: a one-line summary: the headline part and "(+N)".
func (v commandViewT) headlineText() string {
	if v.Headline == nil {
		return ""
	}
	t := v.Parts[*v.Headline].Text
	if len(v.Parts) > 1 {
		return fmt.Sprintf("%s  (+%d)", t, len(v.Parts)-1)
	}
	return t
}

// ---------- environment (DISPLAY.md, section 7a) ----------

type envEntryT struct {
	Name   string   `json:"name"`
	Value  string   `json:"value"`
	Cut    int      `json:"cut"`
	Flags  []string `json:"flags"`
	Loader bool     `json:"loader"`
}

type envViewT struct {
	Entries   []envEntryT `json:"entries"`
	Loader    []string    `json:"loader"`
	Dangerous bool        `json:"dangerous"`
}

var envFlagOrder = []string{"control", "bidi", "invisible", "truncated", "duplicate"}

// envView: the "Environment" block: name and value through the sanitizer, sanitizer flags,
// truncated (cut > 0), duplicate (the name occurs more than once); loader: LD_PRELOAD, LD_AUDIT,
// LD_LIBRARY_PATH with a non-empty value.
func envView(env []envelope.EnvVar) envViewT {
	count := map[string]int{}
	for _, e := range env {
		count[e.Name]++
	}
	out := envViewT{Entries: []envEntryT{}, Loader: []string{}}
	seen := map[string]bool{}
	for _, e := range env {
		name, nf := sanitizeFlags(e.Name)
		value, vf := sanitizeFlags(e.Value)
		fl := map[string]bool{}
		for _, f := range append(nf, vf...) {
			fl[f] = true
		}
		if e.Cut > 0 {
			fl["truncated"] = true
		}
		if count[e.Name] > 1 {
			fl["duplicate"] = true
		}
		flags := []string{}
		for _, f := range envFlagOrder {
			if fl[f] {
				flags = append(flags, f)
			}
		}
		loader := false
		if e.Value != "" {
			for _, n := range envelope.LoaderNames {
				if e.Name == n {
					loader = true
				}
			}
		}
		if loader && !seen[e.Name] {
			seen[e.Name] = true
			out.Loader = append(out.Loader, e.Name)
		}
		if loader || len(flags) > 0 {
			out.Dangerous = true
		}
		out.Entries = append(out.Entries, envEntryT{Name: name, Value: value, Cut: e.Cut, Flags: flags, Loader: loader})
	}
	return out
}
