// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

// Path zones for tripwire: which paths from argv (accounting for cwd) an exec writes, deletes,
// or reads, and which zone they fall in. Zones are installation configuration: built-in patterns
// (defaults.json "zones"), harness pack zones (their settings and secrets), and work directories
// from config.
//
//	secret   keys and tokens (~/.ssh/id_*, ~/.config/*token*, .env, supervisor.key ...)
//	config   files executed by the owner or that configure the agent (dotfiles, ~/.local/bin,
//	         ~/.config/systemd, /etc, /usr ...)
//	scratch  temporary (/tmp, caches, node_modules, dist ...)
//	work     working directories (work_dirs); when not set, everything else is treated as work
//	top      roots (/, /home, /mnt/<disk>, the home directory itself)
//	other    everything else when work_dirs is set
//
// Check order: secret -> config -> scratch -> work -> top -> other.
// Paths are taken from argv only: shell redirections (`> ~/.bashrc`, `< secret`) are not
// visible in argv; this is an acknowledged blind spot (docs/tripwire.md).

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Zone names returned by Zones.Zone; ZoneNone is for an empty path.
const (
	ZoneSecret  = "secret"
	ZoneConfig  = "config"
	ZoneScratch = "scratch"
	ZoneWork    = "work"
	ZoneTop     = "top"
	ZoneOther   = "other"
	ZoneNone    = "none"
)

// PathPattern is a zone element in JSON: "^regexp" | "/literal/prefix" (also ~/... and ${VAR}/...)
// or {"re": "^...", "not": "^..."} (regexp with exclusion: RE2 has no (?!...)).
type PathPattern struct {
	Re     string `json:"re,omitempty"`
	Not    string `json:"not,omitempty"`
	Prefix string `json:"-"`
}

// UnmarshalJSON accepts the string and the object forms described on PathPattern.
func (p *PathPattern) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		if strings.HasPrefix(s, "^") || strings.HasPrefix(s, "(?i)") {
			p.Re = s
		} else {
			p.Prefix = s
		}
		return nil
	}
	type raw PathPattern
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	if r.Re == "" {
		return errors.New("zone pattern: re required")
	}
	*p = PathPattern(r)
	return nil
}

// MarshalJSON writes the shortest form: a string unless the pattern has an exclusion.
func (p PathPattern) MarshalJSON() ([]byte, error) {
	if p.Prefix != "" {
		return json.Marshal(p.Prefix)
	}
	if p.Not == "" {
		return json.Marshal(p.Re)
	}
	type raw PathPattern
	return json.Marshal(raw(p))
}

// ZoneSpec holds zones in JSON (defaults.json "zones", harness packs).
type ZoneSpec struct {
	Secret  []PathPattern `json:"secret,omitempty"`
	Config  []PathPattern `json:"config,omitempty"`
	Scratch []PathPattern `json:"scratch,omitempty"`
	Work    []PathPattern `json:"work,omitempty"`
	Top     []PathPattern `json:"top,omitempty"`
}

type pathMatcher struct {
	re, not  *regexp.Regexp
	prefixes []string
}

func (m *pathMatcher) match(p string) bool {
	for _, pre := range m.prefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") || pre == "/" {
			return true
		}
	}
	if m.re != nil && m.re.MatchString(p) {
		return m.not == nil || !m.not.MatchString(p)
	}
	return false
}

func compilePatterns(ps []PathPattern, v Vars) ([]pathMatcher, error) {
	var out []pathMatcher
	for _, p := range ps {
		var m pathMatcher
		if p.Prefix != "" {
			paths, err := v.Paths(p.Prefix)
			if err != nil {
				return nil, err
			}
			m.prefixes = paths
		} else {
			var err error
			if m.re, err = compileZoneRx(p.Re, v); err != nil {
				return nil, err
			}
			if p.Not != "" {
				if m.not, err = compileZoneRx(p.Not, v); err != nil {
					return nil, err
				}
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// compileZoneRx compiles a zone regexp after expanding ${VAR}; errors name the pattern.
func compileZoneRx(expr string, v Vars) (*regexp.Regexp, error) {
	re, err := compileVar(expr, v)
	if err != nil {
		return nil, fmt.Errorf("zone %q: %w", expr, err)
	}
	return re, nil
}

// Zones holds the compiled zones.
type Zones struct {
	secret, config, scratch, work, top []pathMatcher
}

func matchAny(ms []pathMatcher, p string) bool {
	for i := range ms {
		if ms[i].match(p) {
			return true
		}
	}
	return false
}

// Zone returns the zone of an absolute normalized path.
func (z *Zones) Zone(p string) string {
	switch {
	case p == "":
		return ZoneNone
	case matchAny(z.secret, p):
		return ZoneSecret
	case matchAny(z.config, p):
		return ZoneConfig
	case matchAny(z.scratch, p):
		return ZoneScratch
	case len(z.work) == 0 && !matchAny(z.top, p):
		return ZoneWork
	case matchAny(z.work, p):
		return ZoneWork
	case matchAny(z.top, p):
		return ZoneTop
	}
	return ZoneOther
}

func buildZones(specs []ZoneSpec, v Vars) (*Zones, error) {
	z := &Zones{}
	for _, s := range specs {
		for _, part := range []struct {
			dst *[]pathMatcher
			src []PathPattern
		}{{&z.secret, s.Secret}, {&z.config, s.Config}, {&z.scratch, s.Scratch}, {&z.work, s.Work}, {&z.top, s.Top}} {
			ms, err := compilePatterns(part.src, v)
			if err != nil {
				return nil, err
			}
			*part.dst = append(*part.dst, ms...)
		}
	}
	return z, nil
}

// ---------- paths from argv ----------

var homeVarRx = regexp.MustCompile(`^\$\{?HOME\}?`)

// normPath makes an argv path absolute: ~ and $HOME -> home, a relative path is taken from
// cwd, then it is cleaned (like os.path.normpath).
func normPath(p, cwd, home string) string {
	if p == "" {
		return ""
	}
	p = strings.TrimSpace(p)
	if p == "~" || strings.HasPrefix(p, "~/") {
		p = home + p[1:]
	}
	p = homeVarRx.ReplaceAllLiteralString(p, home)
	if !strings.HasPrefix(p, "/") {
		if cwd == "" {
			cwd = "/"
		}
		p = cwd + "/" + p
	}
	return filepath.Clean(p)
}

// nonopts returns positional arguments: options are skipped, takes lists options that take a
// value, after "--" everything is positional.
func nonopts(args []string, takes ...string) []string {
	var out []string
	dd := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case dd:
			out = append(out, a)
		case a == "--":
			dd = true
		case in(a, takes...):
			i++
		case strings.HasPrefix(a, "-") && a != "-":
		default:
			out = append(out, a)
		}
	}
	return out
}

// optValue returns the value of the first matching option name (next argument); "" if absent.
func optValue(args []string, names ...string) string {
	for i := 0; i+1 < len(args); i++ {
		if in(args[i], names...) {
			return args[i+1]
		}
	}
	return ""
}

var (
	remoteSpecRx = regexp.MustCompile(`^[\p{L}\p{N}_.@-]+:`)
	tarXRx       = regexp.MustCompile(`^-?[a-zA-Z]*x`)
	tarCRx       = regexp.MustCompile(`^-?[a-zA-Z]*c`)
	tarFRx       = regexp.MustCompile(`^-[a-zA-Z]*f$`)
	perlIRx      = regexp.MustCompile(`^-[a-zA-Z0-9]*i`)
	pythonRx     = regexp.MustCompile(`^python3(\.[0-9]+)?$`)
)

// fileTargets returns paths explicitly named in argv: writes, deletes, content reads.
// Heuristic only for known tools (by real binary exe); unknown tools return empty.
func fileTargets(exe string, argv []string, cwd, home string) (w, d, r []string) {
	var a []string
	if len(argv) > 1 {
		a = argv[1:]
	}
	n := func(p string) string { return normPath(p, cwd, home) }
	all := func(xs []string) []string {
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			out = append(out, n(x))
		}
		return out
	}
	switch {
	case in(exe, "rm", "unlink", "rmdir", "shred"):
		d = append(d, all(nonopts(a))...)
	case exe == "trash-put":
	case exe == "mv":
		xs := nonopts(a, "-t", "--target-directory", "-S", "--suffix")
		if t := optValue(a, "-t", "--target-directory"); t != "" {
			w = append(w, n(t))
			d = append(d, all(xs)...)
		} else if len(xs) >= 2 {
			w = append(w, n(xs[len(xs)-1]))
			d = append(d, all(xs[:len(xs)-1])...)
		}
	case in(exe, "cp", "ln", "install", "rsync"):
		xs := nonopts(a, "-t", "--target-directory", "-S", "--suffix", "-m", "--mode", "-o", "--owner", "-g", "--group",
			"-e", "--rsh", "--exclude", "--include", "--filter", "-f", "--chmod", "--rsync-path")
		remote := false
		for _, x := range xs {
			if remoteSpecRx.MatchString(x) && !strings.HasPrefix(x, "/") {
				remote = true
			}
		}
		t := optValue(a, "-t", "--target-directory")
		switch {
		case exe == "rsync" && remote:
		case t != "":
			w = append(w, n(t))
			r = append(r, all(xs)...)
		case len(xs) >= 2:
			w = append(w, n(xs[len(xs)-1]))
			r = append(r, all(xs[:len(xs)-1])...)
			if exe == "rsync" {
				for _, x := range a {
					if strings.HasPrefix(x, "--delete") {
						d = append(d, n(xs[len(xs)-1]))
						break
					}
				}
			}
		case exe == "install" && len(xs) == 1 && in("-d", a...):
			w = append(w, n(xs[0]))
		}
	case in(exe, "chmod", "chown", "chgrp"):
		if xs := nonopts(a, "--reference"); len(xs) > 1 {
			w = append(w, all(xs[1:])...)
		}
	case in(exe, "touch", "mkdir", "truncate", "tee", "mkfifo"):
		w = append(w, all(nonopts(a, "-s", "--size", "-m", "--mode", "-r", "--reference", "-d", "--date", "-t"))...)
	case exe == "dd":
		for _, x := range a {
			if v, ok := strings.CutPrefix(x, "of="); ok {
				w = append(w, n(v))
			} else if v, ok := strings.CutPrefix(x, "if="); ok {
				r = append(r, n(v))
			}
		}
	case exe == "sed":
		inPlace := false
		for _, x := range a {
			if strings.HasPrefix(x, "-i") || strings.HasPrefix(x, "--in-place") {
				inPlace = true
			}
		}
		if inPlace {
			xs := nonopts(a, "-e", "--expression", "-f", "--file", "-l", "--line-length")
			hasE := false
			for _, x := range a {
				if in(x, "-e", "--expression", "-f", "--file") || strings.HasPrefix(x, "--expression=") {
					hasE = true
				}
			}
			if !hasE && len(xs) > 0 {
				xs = xs[1:]
			}
			w = append(w, all(xs)...)
		} else if xs := nonopts(a, "-e", "--expression", "-f", "--file"); len(xs) > 1 {
			r = append(r, all(xs[1:])...)
		}
	case exe == "perl" && anyMatch(perlIRx, a):
		for _, x := range nonopts(a, "-e", "-E", "-M", "-I") {
			if !strings.HasPrefix(x, "-") {
				w = append(w, n(x))
			}
		}
	case exe == "tar":
		first := a[:min(1, len(a))]
		modeX := anyMatch(tarXRx, first) || in("-x", a...) || in("--extract", a...)
		modeC := anyMatch(tarCRx, first) || in("-c", a...) || in("--create", a...)
		cdir := optValue(a, "-C", "--directory")
		f := ""
		for i := 0; i+1 < len(a); i++ {
			if in(a[i], "-f", "--file") || tarFRx.MatchString(a[i]) {
				f = a[i+1]
				break
			}
		}
		if modeX {
			if cdir != "" {
				w = append(w, n(cdir))
			} else {
				w = append(w, n("."))
			}
			if f != "" {
				r = append(r, n(f))
			}
		} else if modeC && f != "" && f != "-" {
			w = append(w, n(f))
		}
	case exe == "unzip":
		if dd := optValue(a, "-d"); dd != "" {
			w = append(w, n(dd))
		} else {
			w = append(w, n("."))
		}
	case exe == "find":
		var roots []string
		for _, x := range a {
			if strings.HasPrefix(x, "-") || in(x, "(", "!", ")") {
				break
			}
			roots = append(roots, n(x))
		}
		if len(roots) == 0 {
			roots = []string{n(".")}
		}
		del := in("-delete", a...)
		for i, x := range a {
			if in(x, "-exec", "-execdir") && i+1 < len(a) && in(pyBase(a[i+1]), "rm", "shred") {
				del = true
			}
		}
		if del {
			d = append(d, roots...)
		} else {
			r = append(r, roots...)
		}
	case in(exe, "cat", "head", "tail", "less", "more", "grep", "rg", "ugrep", "xxd", "od", "base64", "strings", "jq", "awk",
		"mawk", "gawk", "node", "openssl", "age", "gpg", "zip", "diff") || pythonRx.MatchString(exe):
		// readers (ls/stat/wc/file do not reveal content)
		xs := nonopts(a, "-e", "-f", "-n", "-c", "-m", "-A", "-B", "-C", "--max-count", "-t", "-k", "-F", "-v", "--regexp",
			"--file", "-in", "-out", "-key", "-inkey", "-config", "-passin")
		if in(exe, "grep", "rg", "ugrep") && !anyIn(a, "-e", "--regexp", "-f", "--file") && len(xs) > 0 {
			xs = xs[1:]
		}
		if in(exe, "awk", "mawk", "gawk") && !in("-f", a...) && len(xs) > 0 {
			xs = xs[1:]
		}
		if exe == "jq" && len(xs) > 0 {
			xs = xs[1:]
		}
		if exe == "openssl" {
			xs = nil
			for i := 0; i+1 < len(a); i++ {
				if in(a[i], "-in", "-key", "-inkey", "-config") {
					xs = append(xs, a[i+1])
				}
			}
		}
		// for readers the positional args are files (`cat id_rsa` in ~/.ssh reads a secret via cwd);
		// for interpreters, openssl, awk, jq: only path-like args
		bare := in(exe, "cat", "head", "tail", "less", "more", "xxd", "od", "base64", "strings", "grep", "rg", "ugrep", "diff")
		for _, x := range xs {
			if bare || strings.Contains(x, "/") || strings.HasPrefix(x, ".") || strings.HasPrefix(x, "~") {
				r = append(r, n(x))
			}
		}
	}
	return w, d, r
}

// ---------- helpers ----------

// nonDashWords returns the arguments that do not start with "-" (unlike nonopts, option
// values are not skipped); nil if there are none.
func nonDashWords(args []string) []string {
	var out []string
	for _, x := range args {
		if !strings.HasPrefix(x, "-") {
			out = append(out, x)
		}
	}
	return out
}

// wordAt returns words[i], or "" if there is no such word.
func wordAt(words []string, i int) string {
	if i < len(words) {
		return words[i]
	}
	return ""
}

func in(s string, set ...string) bool {
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}

func anyIn(xs []string, set ...string) bool {
	for _, x := range xs {
		if in(x, set...) {
			return true
		}
	}
	return false
}

func anyMatch(rx *regexp.Regexp, xs []string) bool {
	for _, x := range xs {
		if rx.MatchString(x) {
			return true
		}
	}
	return false
}

// pyBase is basename like os.path.basename: "" for a path with a trailing "/".
func pyBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// bname returns the file name; "?" for empty.
func bname(p string) string {
	if b := pyBase(p); b != "" {
		return b
	}
	return "?"
}
