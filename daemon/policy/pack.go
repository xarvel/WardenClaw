// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

// Harness packs: knowledge about a specific harness (claude-cli, OpenClaw gateway) separated
// from general rules. A pack describes the harness process model (its runtime and service execs),
// zones of its settings and secrets, and the CLI verbs that change agent settings. Paths are not
// hardcoded: rules use variables (${AGENT_HOME}, ${CLAUDE_ROOT}, ${OPENCLAW_ROOT} ...) that
// wardend substitutes from the installation (vars.go). Built-in packs live in policy/packs/*.json
// and are compiled into the binary.
//
// How a pack is selected:
//
//   - which packs are loaded: config key `packs` (names of built-ins or file paths);
//     default is all built-ins;
//   - which exec a pack applies to: by process chain: a pack rule matches only inside its
//     harness (field under: harness runtime among caller and ancestors; field chain_all: all
//     ancestors up to the wardend command, i.e. gateway processes; caller/path by harness
//     binary path);
//   - where the harness lives: pack variables, default values, override in config (pack_vars)
//     and auto-detection from the command wardend was started with (detect: for the OpenClaw
//     gateway the pack root is taken from the path of its index.js).
//
// Format (JSON):
//
//	{"pack": "name", "description": "...", "tested": ["versions"], "family": "CLI family",
//	 "vars": {"NAME": ["default value", ...]},
//	 "detect": [{"var": "NAME", "command": "regexp with group 1 on a command element"}],
//	 "runtime": "regexp matching harness runtime exe (for under)",
//	 "service": [rules like service_allow + under/chain_all/chain_max/inherit],
//	 "zones": {"secret": [...], "config": [...], "scratch": [...]},
//	 "agent_config": [{"id", "path"?, "entry"?, "words": "nonopt|raw",
//	     "verbs": {"command": ["subcommand"|"*"|"**"|"!exclusion"]}}]}
//
// service: exec passes without a ticket and without inheritance (its children are checked
// independently); with "inherit": true in root mode, the probe's own helpers inherit (probe
// with children like `lsb_release`). In tripwire mode the pack only exempts service execs from
// tripwire rules.
// verbs: "*" any subcommand, "**" any or none, "!x" except x.

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

//go:embed packs/*.json
var packFS embed.FS

// Pack is a harness pack (as in JSON).
type Pack struct {
	Name        string              `json:"pack"`
	Description string              `json:"description,omitempty"`
	Tested      []string            `json:"tested,omitempty"`
	Family      string              `json:"family,omitempty"`
	Vars        map[string][]string `json:"vars,omitempty"`
	Detect      []PackDetect        `json:"detect,omitempty"`
	Runtime     string              `json:"runtime,omitempty"`
	Service     []*Rule             `json:"service,omitempty"`
	Zones       ZoneSpec            `json:"zones,omitempty"`
	AgentConfig []*AgentConfigRule  `json:"agent_config,omitempty"`
}

// PackDetect holds auto-detection config for a pack variable based on the wardend command.
type PackDetect struct {
	Var     string `json:"var"`
	Command string `json:"command"`
}

// AgentConfigRule holds CLI verbs of a harness that change agent settings (category agent-config).
type AgentConfigRule struct {
	ID    string              `json:"id"`
	Path  string              `json:"path,omitempty"`  // realpath of the CLI binary
	Entry string              `json:"entry,omitempty"` // argv[0] or script after node (argv[1])
	Words string              `json:"words,omitempty"` // nonopt (default) | raw
	Verbs map[string][]string `json:"verbs"`

	pack        string
	family      string
	path, entry *regexp.Regexp
}

// BuiltinPacks returns the names of built-in packs.
func BuiltinPacks() []string {
	ents, _ := packFS.ReadDir("packs")
	var out []string
	for _, e := range ents {
		out = append(out, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(out)
	return out
}

// BuiltinPackJSON returns the raw JSON of a built-in pack.
func BuiltinPackJSON(name string) ([]byte, error) {
	return packFS.ReadFile("packs/" + name + ".json")
}

// LoadPack loads a built-in pack by name or a file (ref contains "/" or ends in ".json").
func LoadPack(ref string) (*Pack, error) {
	var b []byte
	var err error
	if strings.ContainsRune(ref, '/') || strings.HasSuffix(ref, ".json") {
		b, err = os.ReadFile(ref)
	} else {
		b, err = BuiltinPackJSON(ref)
		if err != nil {
			return nil, fmt.Errorf("pack %q: no such built-in pack (built-in: %s)", ref, strings.Join(BuiltinPacks(), ", "))
		}
	}
	if err != nil {
		return nil, fmt.Errorf("pack %q: %w", ref, err)
	}
	var p Pack
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("pack %q: %w", ref, err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("pack %q: \"pack\" (name) required", ref)
	}
	return &p, nil
}

// detectVars returns pack variable values detected from the wardend command (elements and their realpath).
func (p *Pack) detectVars(cmd []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, d := range p.Detect {
		rx, err := regexp.Compile(d.Command)
		if err != nil {
			return nil, fmt.Errorf("pack %s: detect %s: %w", p.Name, d.Var, err)
		}
		for _, c := range commandCandidates(cmd) {
			if m := rx.FindStringSubmatch(c); len(m) > 1 && m[1] != "" && filepath.IsAbs(m[1]) {
				if !in(m[1], out[d.Var]...) {
					out[d.Var] = append(out[d.Var], m[1])
				}
			}
		}
	}
	return out, nil
}

// commandCandidates returns command elements and their realpath (argv[0] is searched in PATH).
func commandCandidates(cmd []string) []string {
	var out []string
	for i, c := range cmd {
		out = append(out, c)
		p := c
		if i == 0 && !strings.ContainsRune(c, '/') {
			if lp, err := lookPath(c); err == nil {
				p = lp
			}
		}
		if strings.ContainsRune(p, '/') {
			if rp, err := filepath.EvalSymlinks(p); err == nil && rp != c {
				out = append(out, rp)
			}
		}
	}
	return out
}

// lookPath finds an executable regular file name in $PATH, skipping empty PATH entries.
func lookPath(name string) (string, error) {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", os.ErrNotExist
}

// compile compiles the agent-config rule regexps after variable substitution.
func (r *AgentConfigRule) compile(v Vars) error {
	var err error
	if r.Path != "" {
		if r.path, err = compileVar(r.Path, v); err != nil {
			return fmt.Errorf("agent_config %s: path: %w", r.ID, err)
		}
	}
	if r.Entry != "" {
		if r.entry, err = compileVar(r.Entry, v); err != nil {
			return fmt.Errorf("agent_config %s: entry: %w", r.ID, err)
		}
	}
	if r.path == nil && r.entry == nil {
		return fmt.Errorf("agent_config %s: path or entry required", r.ID)
	}
	if len(r.Verbs) == 0 {
		return fmt.Errorf("agent_config %s: verbs required", r.ID)
	}
	return nil
}

// compileVar compiles a regexp after expanding ${VAR} references.
func compileVar(s string, v Vars) (*regexp.Regexp, error) {
	rx, err := v.Regex(s)
	if err != nil {
		return nil, err
	}
	return regexp.Compile(rx)
}

// match reports whether the exec runs a CLI subcommand that changes agent settings; detail
// is "verb" or "verb sub".
func (r *AgentConfigRule) match(e *Exec) (detail string, ok bool) {
	var words []string
	switch {
	case r.path != nil:
		if !r.path.MatchString(e.Path) {
			return "", false
		}
		if r.Words == "raw" {
			if len(e.Argv) > 1 {
				words = e.Argv[1:]
			}
		} else {
			words = nonDashWords(e.Argv[min(1, len(e.Argv)):])
			if in("--help", e.Argv...) || in("-h", e.Argv...) {
				return "", false
			}
		}
	default:
		words = cliWords(e.Argv, r.entry)
		if words == nil {
			return "", false
		}
	}
	if len(words) == 0 {
		return "", false
	}
	verb, sub := words[0], wordAt(words, 1)
	subs, ok := r.Verbs[verb]
	if !ok {
		return "", false
	}
	anySub, anyOrNone, listed := false, false, false
	for _, s := range subs {
		switch {
		case s == "*":
			anySub = true
		case s == "**":
			anyOrNone = true
		case strings.HasPrefix(s, "!"):
			if sub == s[1:] {
				return "", false
			}
		case s == sub && sub != "":
			listed = true
		}
	}
	switch {
	case listed:
		return verb + " " + sub, true
	case anyOrNone || (anySub && sub != ""):
		return verb, true
	}
	return "", false
}

// agentConfigHit returns the matching agent-config rule from packs (pack load order).
func (c *Config) agentConfigHit(e *Exec) *Hit {
	for _, r := range c.agentConfig {
		if d, ok := r.match(e); ok {
			return &Hit{Category: "agent-config", Rule: r.pack + "-cli", Detail: d, Family: r.family}
		}
	}
	return nil
}
