// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

// Installation path variables for rules, zones, and harness packs.
//
// In rule regexps `${NAME}` is replaced with `(?:v1|v2|...)` of escaped literal values
// (regexp.QuoteMeta): a path from config cannot "break" the regexp. The special variable
// `${ANY_HOME}` is a regexp matching any home directory: `(?:<AGENT_HOME>|/home/[^/]+|/root)`.
// In literal paths (work_dirs zones etc.) `~` and `${NAME}` expand to a list of paths.
//
// Built-in variables:
//
//	AGENT_HOME   harness user home: agent_home from config -> child_user home -> wardend $HOME
//	ANY_HOME     (regexps only) any home: AGENT_HOME, /home/*, /root
//
// A harness pack declares its own variables (CLAUDE_ROOT, OPENCLAW_ROOT ...) with default
// values; config (pack_vars) overrides them.

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Vars holds variable values: name -> literal paths (multiple values = alternative).
type Vars map[string][]string

var varRef = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)\}`)

// maxVarNesting bounds how deep variable values may reference other variables; deeper
// nesting is reported as a reference loop.
const maxVarNesting = 8

// isReservedVar reports whether name is a built-in variable that packs and pack_vars cannot set.
func isReservedVar(name string) bool { return name == "AGENT_HOME" || name == "ANY_HOME" }

// Clone returns a copy (values are copied too).
func (v Vars) Clone() Vars {
	out := Vars{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// Regex expands ${NAME} in a regexp. Unknown variable or a variable with no values is
// an error: a rule with a silently empty variable must not match anything.
func (v Vars) Regex(s string) (string, error) {
	var err error
	out := varRef.ReplaceAllStringFunc(s, func(m string) string {
		name := m[2 : len(m)-1]
		if name == "ANY_HOME" {
			alts := []string{`/home/[^/]+`, `/root`}
			for _, h := range v["AGENT_HOME"] {
				alts = append([]string{regexp.QuoteMeta(cleanDir(h))}, alts...)
			}
			return "(?:" + strings.Join(alts, "|") + ")"
		}
		vals, ok := v[name]
		if !ok || len(vals) == 0 {
			if err == nil {
				err = fmt.Errorf("unknown variable ${%s}", name)
			}
			return m
		}
		q := make([]string, 0, len(vals))
		seen := map[string]bool{}
		for _, x := range vals {
			x = regexp.QuoteMeta(cleanDir(x))
			if !seen[x] {
				seen[x] = true
				q = append(q, x)
			}
		}
		return "(?:" + strings.Join(q, "|") + ")"
	})
	return out, err
}

// Paths expands a literal path: ~ -> AGENT_HOME, ${NAME} -> each value.
func (v Vars) Paths(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "~" || strings.HasPrefix(s, "~/") {
		s = "${AGENT_HOME}" + s[1:]
	}
	outs := []string{s}
	for depth := 0; ; depth++ {
		if depth > maxVarNesting {
			return nil, fmt.Errorf("path %q: variable reference loop", s)
		}
		var next []string
		changed := false
		for _, p := range outs {
			m := varRef.FindStringSubmatchIndex(p)
			if m == nil {
				next = append(next, p)
				continue
			}
			changed = true
			name := p[m[2]:m[3]]
			vals := v[name]
			if name == "ANY_HOME" || len(vals) == 0 {
				return nil, fmt.Errorf("variable ${%s} cannot be used in a path", name)
			}
			for _, x := range vals {
				next = append(next, p[:m[0]]+cleanDir(x)+p[m[1]:])
			}
		}
		outs = next
		if !changed {
			break
		}
	}
	for i, p := range outs {
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("path %q is not absolute", p)
		}
		outs[i] = filepath.Clean(p)
	}
	return outs, nil
}

// resolveDefaults expands value references (a variable value may reference others,
// e.g. CLAUDE_ROOT = ${AGENT_HOME}/.local/share/claude). Depth is limited.
func (v Vars) resolveDefaults() error {
	names := make([]string, 0, len(v))
	for k := range v {
		names = append(names, k)
	}
	sort.Strings(names)
	for i := 0; i < maxVarNesting; i++ {
		changed := false
		for _, k := range names {
			var out []string
			for _, x := range v[k] {
				if !varRef.MatchString(x) {
					out = append(out, x)
					continue
				}
				ps, err := v.Paths(x)
				if err != nil {
					return fmt.Errorf("${%s}: %w", k, err)
				}
				out = append(out, ps...)
				changed = true
			}
			v[k] = out
		}
		if !changed {
			return nil
		}
	}
	return errors.New("variables: reference loop")
}

// cleanDir is filepath.Clean, except that "" and paths that clean to "." are returned as given.
func cleanDir(p string) string {
	if p == "" {
		return p
	}
	c := filepath.Clean(p)
	if c == "." {
		return p
	}
	return c
}
