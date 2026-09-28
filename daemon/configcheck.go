// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Config and policy check before a restart (wardend config-check) and what it shares with the
// start: a JSON parse error with line and column, the config version, unknown keys.
// json.Unmarshal silently skips unknown keys: a typo in "mode" would leave observe. In the config
// an unknown key is an error (config.go: config-check fails, wardend does not start); in the
// policy file it is a warning.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/xarvel/WardenClaw/daemon/feature"
	"github.com/xarvel/WardenClaw/daemon/hwkey"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

// configVersion: the highest config schema version this build understands. A missing version
// field means 1. It is bumped only if an old wardend would misread the new config (a field was
// renamed or changed meaning); a new optional field does not bump the version.
const configVersion = 1

func checkConfigVersion(path string, v int) error {
	switch {
	case v > configVersion:
		return fmt.Errorf("config %s: version %d is newer than this wardend understands (up to %d): update wardend (this is %s), or write the config for this version", path, v, configVersion, version)
	case v < 0:
		return fmt.Errorf("config %s: version %d: expected %d (or no version key)", path, v, configVersion)
	}
	return nil
}

// jsonErrorPos: "line L, column C: " for a json.Unmarshal error with a position (syntax, value
// type); other errors have no position.
func jsonErrorPos(b []byte, err error) string {
	var off int64
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se):
		off = se.Offset
	case errors.As(err, &te):
		off = te.Offset
	default:
		return ""
	}
	// Offset: bytes read before the error, including the bad character
	off = min(max(off-1, 0), int64(len(b)))
	line, col := 1, 1
	for _, c := range b[:off] {
		if c == '\n' {
			line, col = line+1, 1
		} else {
			col++
		}
	}
	return fmt.Sprintf("line %d, column %d: ", line, col)
}

var jsonUnmarshaler = reflect.TypeFor[json.Unmarshaler]()

// unknownKeys: object keys in JSON b that are not among the fields of t (with nested objects and
// arrays): root_exec.sockte, trusted_devices[1].pubkye. Names match case-insensitively, as in
// encoding/json. Values with their own UnmarshalJSON are not parsed. A key one or two edits away
// from a known one gets a hint: "moed" (did you mean "mode"?).
func unknownKeys(b []byte, t reflect.Type) []unknownKey {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return nil
	}
	var out []unknownKey
	walkUnknown(v, t, "", &out)
	return out
}

// unknownKey: the path of an unknown key and a hint (may be empty).
type unknownKey struct{ path, hint string }

func (k unknownKey) String() string {
	return fmt.Sprintf("unknown key %q is ignored%s", k.path, k.hint)
}

func walkUnknown(v any, t reflect.Type, path string, out *[]unknownKey) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Implements(jsonUnmarshaler) || reflect.PointerTo(t).Implements(jsonUnmarshaler) {
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		obj, _ := v.(map[string]any)
		fields := jsonFields(t)
		for _, k := range slices.Sorted(maps.Keys(obj)) {
			p := k
			if path != "" {
				p = path + "." + k
			}
			ft, ok := fieldType(fields, k)
			if !ok {
				*out = append(*out, unknownKey{p, suggestKey(k, fields)})
				continue
			}
			walkUnknown(obj[k], ft, p, out)
		}
	case reflect.Slice, reflect.Array:
		arr, _ := v.([]any)
		for i, e := range arr {
			walkUnknown(e, t.Elem(), fmt.Sprintf("%s[%d]", path, i), out)
		}
	case reflect.Map:
		obj, _ := v.(map[string]any)
		for _, k := range slices.Sorted(maps.Keys(obj)) {
			walkUnknown(obj[k], t.Elem(), path+"."+k, out)
		}
	}
}

// fieldType returns the type of the field for JSON key k: an exact name first, then a
// case-insensitive match, as in encoding/json.
func fieldType(fields map[string]reflect.Type, k string) (reflect.Type, bool) {
	if ft, ok := fields[k]; ok {
		return ft, true
	}
	for name, ft := range fields {
		if strings.EqualFold(name, k) {
			return ft, true
		}
	}
	return nil, false
}

// jsonFields: struct field names as encoding/json sees them (including embedded ones).
func jsonFields(t reflect.Type) map[string]reflect.Type {
	m := map[string]reflect.Type{}
	var embedded []reflect.Type
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		ft := f.Type
		if f.Anonymous && name == "" {
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				embedded = append(embedded, ft)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		m[name] = ft
	}
	for _, et := range embedded { // a top-level field wins over an embedded one
		for k, ft := range jsonFields(et) {
			if _, ok := m[k]; !ok {
				m[k] = ft
			}
		}
	}
	return m
}

// maxSuggestEdits is how far a typo may be from a known key to get a "did you mean" hint.
const maxSuggestEdits = 2

// suggestKey returns the " (did you mean …?)" hint for an unknown key: the closest known key,
// the alphabetically first on a tie; "" if none is within maxSuggestEdits.
func suggestKey(k string, fields map[string]reflect.Type) string {
	best, bestD := "", maxSuggestEdits+1
	for name := range fields {
		if d := editDistance(strings.ToLower(k), name); d < bestD || d == bestD && name < best {
			best, bestD = name, d
		}
	}
	if best == "" {
		return ""
	}
	return fmt.Sprintf(" (did you mean %q?)", best)
}

// editDistance: Levenshtein distance (short config keys, no optimizations).
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// checkPolicyFile: the policy file before policy.Load: a parse error with line and column
// (policy.Load would say the same without a position) and unknown keys (warnings). If the file
// cannot be read, it stays silent: policy.Load reports the error.
func checkPolicyFile(path string) (warns []string, err error) {
	if path == "" {
		return nil, nil
	}
	b, rerr := os.ReadFile(path)
	if rerr != nil {
		return nil, nil
	}
	var c policy.Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("policy %s: %s%w", path, jsonErrorPos(b, err), err)
	}
	for _, k := range unknownKeys(b, reflect.TypeFor[policy.Config]()) {
		warns = append(warns, fmt.Sprintf("policy %s: %s", path, k))
	}
	return warns, nil
}

// hwKeyOffHelp: the start error of a build without the hwkey tag when hardware_keys or
// require_hardware is set, explained in words.
const hwKeyOffHelp = `this wardend is built without the hwkey tag (release builds are), so it has no second factor
  and refuses to start while hardware_keys or require_hardware are set: otherwise roots you meant
  to need a key touch would pass with the phone signature alone. Remove hardware_keys from the
  config and require_hardware from the policy, or build wardend with -tags hwkey
  (daemon/docs/hwkey.md).`

func cmdConfigCheck(args []string, stdout, stderr io.Writer) int {
	fs := newCmdFlags("config-check", "config-check [--config f] [--state-dir d] [--policy rules.json] [-- <cmd...>]",
		"Checks the config and the policy the way wardend run reads them at start, and starts nothing:\n"+
			"JSON errors with line and column, unknown keys, values run would reject, the second factor\n"+
			"in a build without it. Prints every error and warning; exit code 0 if wardend run would start\n"+
			"with these files, 1 if not. Run it before systemctl restart wardend. The command after --\n"+
			"(optional, as in run) is used for harness pack detection.", stdout, stderr)
	cfgPath := fs.String("config", "", "JSON config (default: <state-dir>/config.json, if present), as in run")
	stateDir := fs.String("state-dir", "", "state directory (~/.wardend), as in run")
	pol := fs.String("policy", "", "rules JSON instead of the policy from the config, as in run")
	if code, ok := fs.parse(args); !ok {
		return code
	}
	if fs.NArg() == 1 && fs.Arg(0) == "help" && !afterDoubleDash(args, 1) {
		fs.printUsage(stdout)
		return 0
	}
	nerr := 0
	fail := func(err error) {
		nerr++
		fmt.Fprintln(stdout, "error:", err)
	}
	warn := func(w string) { fmt.Fprintln(stdout, "warning:", w) }

	path := configPath(*cfgPath, *stateDir)
	if path == "" {
		fmt.Fprintln(stdout, "no config file: wardend run starts with the defaults")
	}
	cfg, err := loadConfig(path)
	if err != nil {
		fail(err)
		return verdict(stdout, nerr)
	}
	if *stateDir != "" {
		cfg.StateDir = *stateDir
	}
	if *pol != "" {
		cfg.Policy = *pol
	}
	pw, err := checkPolicyFile(cfg.Policy)
	if err != nil {
		fail(err)
		return verdict(stdout, nerr)
	}
	for _, w := range pw {
		warn(w)
	}
	// from here on, the runSupervisor order up to the first side effect (journal key, socket)
	if err := cfg.setDefaults(); err != nil {
		fail(err)
		return verdict(stdout, nerr)
	}
	exePath, _ := os.Executable()
	if err := runSelfCheck(cfg, exePath, stdout, false); err != nil {
		fail(err)
	}
	p, err := policy.Load(cfg.Policy)
	if err == nil {
		err = p.Setup(cfg.policyOptions(fs.Args(), exePath))
	}
	if err != nil {
		fail(err)
		return verdict(stdout, nerr)
	}
	if err := hwFeatureCheck(len(cfg.HardwareKeys), len(p.RequireHardware)); err != nil {
		fail(fmt.Errorf("%v\n  %s", err, hwKeyOffHelp))
	} else if _, err := hwkey.NewStore(cfg.HardwareKeys, cfg.HardwareCounters); err != nil {
		fail(err)
	}
	if cfg.Mode == "ticket" && len(cfg.TrustedDevices) == 0 {
		warn("mode ticket without trusted_devices: every root is denied after ticket_ttl until a phone is paired (wardend pair start)")
	}
	if feature.HWKey && cfg.Mode == "ticket" && len(p.RequireHardware) > 0 && len(cfg.HardwareKeys) == 0 {
		warn("require_hardware without hardware_keys: roots these rules match are denied (wardend hw-register)")
	}
	if nerr == 0 {
		policyName := cfg.Policy
		if policyName == "" {
			policyName = "built-in"
		}
		fmt.Fprintf(stdout, "mode %s, policy_mode %s, policy %s, trusted devices %d\n", cfg.Mode, cfg.PolicyMode, policyName, len(cfg.TrustedDevices))
	}
	return verdict(stdout, nerr)
}

func verdict(w io.Writer, nerr int) int {
	if nerr > 0 {
		fmt.Fprintf(w, "config-check: %d error(s): wardend run would not start with these files\n", nerr)
		return 1
	}
	fmt.Fprintln(w, "config-check: ok")
	return 0
}
