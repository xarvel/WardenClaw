// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/hwkey"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

type duration struct{ time.Duration }

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	d.Duration = v
	return err
}

func (d duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// Config is ~/.wardend/config.json. All fields are optional; run flags override them.
type Config struct {
	// Version is the config schema version: a missing field means 1; a version newer than
	// configVersion is refused at start (a config from a newer wardend build, configcheck.go).
	Version int    `json:"version,omitempty"`
	Mode    string `json:"mode"` // observe | deny-list | ticket
	// PolicyMode decides what needs a signature: tripwire (default: every launch goes through
	// the rules, a signature only when one fires) | root (approved root with its subtree).
	PolicyMode string `json:"policy_mode"`
	// Setup for tripwire and harness packs (policy/): home of the harness user (${AGENT_HOME};
	// default: the child_user home, else $HOME), work and scratch directories, harness packs
	// (nil: all built-in, []: none) and their variables.
	AgentHome      string                   `json:"agent_home,omitempty"`
	WorkDirs       []string                 `json:"work_dirs,omitempty"`
	ScratchDirs    []string                 `json:"scratch_dirs,omitempty"`
	Packs          *[]string                `json:"packs,omitempty"`
	PackVars       map[string][]string      `json:"pack_vars,omitempty"`
	StateDir       string                   `json:"state_dir"`  // ~/.wardend
	Socket         string                   `json:"socket"`     // <state_dir>/wardend.sock
	Journal        string                   `json:"journal"`    // <state_dir>/journal.jsonl
	KeyFile        string                   `json:"key_file"`   // <state_dir>/supervisor.key
	Policy         string                   `json:"policy"`     // rules JSON; "": built-in (policy/defaults.json)
	TicketTTL      duration                 `json:"ticket_ttl"` // 120s
	TsWindow       duration                 `json:"ts_window"`  // 60s
	MaxPending     int                      `json:"max_pending"`
	Linger         duration                 `json:"linger"` // after the child exits, serve the rest of the tree
	TrustedDevices []envelope.TrustedDevice `json:"trusted_devices"`
	GatewayDB      string                   `json:"gateway_db"` // "off" (default) | "auto" | path
	ToctouRoots    string                   `json:"toctou_roots"`
	ToctouService  string                   `json:"toctou_service"`
	Host           string                   `json:"host"`
	// Second factor: trusted hardware keys (FIDO2, `wardend hw-register`) and the file of
	// monotonic signCount counters (<state_dir>/hw_counters.json).
	HardwareKeys     []hwkey.Key `json:"hardware_keys"`
	HardwareCounters string      `json:"hardware_counters"`
	PairCodeTTL      duration    `json:"pair_code_ttl"` // lifetime of the one-time pairing code, 5m
	// The relay (relay.go, protocol/README.md): wardend keeps an outbound WebSocket to it, and that
	// is the only way a device reaches wardend; nothing listens on the network. "" is the default
	// relay; "off": no relay, for a wardend that no device approves for (observe mode, a local
	// test key).
	RelayURL     string `json:"relay_url"`      // wss://relay.wardenclaw.dev | off
	RelayKeyFile string `json:"relay_key_file"` // X25519 encryption key, <state_dir>/relay_enc.key
	// RequireHardened refuses to start if the binary, config or key is not root-owned
	// (for an install under a separate user, see deploy/hardened-install.sh).
	RequireHardened bool `json:"require_hardened"`
	// ChildUser (hardened install) is the user, name or uid[:gid], the harness descendant runs
	// as. wardend stays under its own (root) uid, out of the agent's reach.
	ChildUser string `json:"child_user"`
	// RootExec (rootexec.go): the socket on which a process under the gate may ask wardend to run
	// a command as wardend's own user after a ticket (`wardend rootexec -- cmd`). nil or
	// enabled=false: no socket, every request refused.
	RootExec *RootExecConfig `json:"root_exec,omitempty"`

	path string // config file: `wardend pair approve` appends trusted_devices here
}

const (
	defaultMaxPending = 64
)

// RootExecConfig is the "root_exec" config object.
type RootExecConfig struct {
	Enabled bool `json:"enabled"`
	// Socket: unix socket of the requests. Default /run/wardend/rootexec.sock when wardend runs
	// as root (RuntimeDirectory=wardend in the unit), else <state_dir>/rootexec.sock. The socket
	// is root:<group> 0660; the state directory (0700) is not reachable by the agent, so a
	// hardened install needs the /run path.
	Socket string `json:"socket,omitempty"`
	// Group that may connect (name or gid). Default: the primary group of child_user, else the
	// group of wardend itself.
	Group string `json:"group,omitempty"`
	// Timeout: the approved command is killed (SIGTERM, then SIGKILL) after this long. Default 10m.
	Timeout duration `json:"timeout,omitempty"`
}

// agentHome is ${AGENT_HOME}: agent_home from the config, else the child_user home, else
// wardend's $HOME.
func (c *Config) agentHome() string {
	if c.AgentHome != "" {
		return c.AgentHome
	}
	if h := childUserHome(c.ChildUser); h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}

// childUserHome returns the home directory of a child_user (name or uid[:gid]); "" if the user is
// unset or unknown.
func childUserHome(spec string) string {
	id, _, _ := strings.Cut(strings.TrimSpace(spec), ":")
	if id == "" {
		return ""
	}
	lookup := user.Lookup
	if _, err := strconv.Atoi(id); err == nil {
		lookup = user.LookupId
	}
	u, err := lookup(id)
	if err != nil {
		return ""
	}
	return u.HomeDir
}

// policyOptions: setup for building the rules (variables, packs, zones).
func (c *Config) policyOptions(cmd []string, selfExe string) policy.Options {
	o := policy.Options{AgentHome: c.agentHome(), PackVars: c.PackVars, WorkDirs: c.WorkDirs, ScratchDirs: c.ScratchDirs, Command: cmd}
	if c.Packs != nil {
		o.Packs = append([]string{}, (*c.Packs)...)
	}
	if selfExe != "" {
		if rp, err := filepath.EvalSymlinks(selfExe); err == nil {
			selfExe = rp
		}
		o.GuardExe = []string{selfExe, filepath.Join(filepath.Dir(selfExe), "wardenctl")}
	}
	return o
}

func defaultStateDir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".wardend")
}

// loadConfig: parses the config file: a JSON error with line and column, a version newer than
// supported = an error, and so is a key Config does not have: a typo in "mode" would leave
// observe, a key of a removed feature would be believed to still do something.
func loadConfig(path string) (*Config, error) {
	c := &Config{path: path}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("config %s: %s%w", path, jsonErrorPos(b, err), err)
		}
		if err := checkConfigVersion(path, c.Version); err != nil {
			return nil, err
		}
		if unknown := unknownKeys(b, reflect.TypeFor[Config]()); len(unknown) > 0 {
			names := make([]string, len(unknown))
			for i, k := range unknown {
				names[i] = fmt.Sprintf("unknown key %q%s", k.path, k.hint)
			}
			return nil, fmt.Errorf("config %s: %s", path, strings.Join(names, "; "))
		}
	}
	return c, nil
}

// fill: defaults and validation (setDefaults), then the state directory.
func (c *Config) fill() error {
	if err := c.setDefaults(); err != nil {
		return err
	}
	return os.MkdirAll(c.StateDir, 0o700)
}

// setDefaults: the part of fill without side effects (wardend config-check calls it too).
func (c *Config) setDefaults() error {
	if c.Mode == "" {
		c.Mode = "observe"
	}
	switch c.Mode {
	case "observe", "deny-list", "ticket":
	default:
		return fmt.Errorf("mode %q: observe|deny-list|ticket", c.Mode)
	}
	if c.PolicyMode == "" {
		c.PolicyMode = policy.ModeTripwire
	}
	switch c.PolicyMode {
	case policy.ModeTripwire, policy.ModeRoot:
	default:
		return fmt.Errorf("policy_mode %q: tripwire|root", c.PolicyMode)
	}
	if c.StateDir == "" {
		c.StateDir = defaultStateDir()
	}
	if c.Socket == "" {
		c.Socket = filepath.Join(c.StateDir, "wardend.sock")
	}
	if c.Journal == "" {
		c.Journal = filepath.Join(c.StateDir, "journal.jsonl")
	}
	if c.KeyFile == "" {
		c.KeyFile = filepath.Join(c.StateDir, "supervisor.key")
	}
	c.HardwareCounters = c.hwCountersPath()
	if c.TicketTTL.Duration == 0 {
		c.TicketTTL.Duration = 120 * time.Second
	}
	if c.TsWindow.Duration == 0 {
		c.TsWindow.Duration = 60 * time.Second
	}
	if c.MaxPending == 0 {
		// Peak of the journal replay in tripwire: 34 cards in 2 minutes (= TTL): 64 is a 2x margin.
		// The queue is bounded anyway: over the limit an exec gets EAGAIN at once.
		c.MaxPending = defaultMaxPending
	}
	if c.Linger.Duration == 0 {
		c.Linger.Duration = 2 * time.Second
	}
	// The OpenClaw gateway DB as a source of device keys: only with an explicit "auto"/path:
	// wardend has its own pairing (`wardend pair`), the keys live in trusted_devices.
	switch c.GatewayDB {
	case "auto":
		h, _ := os.UserHomeDir()
		c.GatewayDB = filepath.Join(h, ".openclaw", "state", "openclaw.sqlite")
	case "", "off":
		c.GatewayDB = ""
	}
	u, err := normalizeRelayURL(c.RelayURL)
	if err != nil {
		return err
	}
	c.RelayURL = u
	if c.RelayKeyFile == "" {
		c.RelayKeyFile = filepath.Join(c.StateDir, "relay_enc.key")
	}
	if c.PairCodeTTL.Duration == 0 {
		c.PairCodeTTL.Duration = 5 * time.Minute
	}
	if c.path == "" {
		c.path = filepath.Join(c.StateDir, "config.json")
	}
	if c.ToctouRoots == "" {
		c.ToctouRoots = string(toctouStop)
	}
	if c.ToctouService == "" {
		c.ToctouService = string(toctouOff)
	}
	for _, m := range []string{c.ToctouRoots, c.ToctouService} {
		switch toctouMode(m) {
		case toctouStop, toctouPoll, toctouOff:
		default:
			return fmt.Errorf("toctou mode %q: stop|poll|off", m)
		}
	}
	if c.Host == "" {
		c.Host, _ = os.Hostname()
	}
	for i, d := range c.TrustedDevices {
		c.TrustedDevices[i].ID = strings.ToLower(strings.TrimSpace(d.ID))
		// A key whose sha256 does not equal the id is not this device's key: refuse to start
		// rather than silently trust it (or reject every phone ticket without explanation).
		if err := envelope.CheckTrusted(c.TrustedDevices[i]); err != nil {
			return fmt.Errorf("config %s: trusted_devices[%d] (id %q): %v; re-pair the device (wardend pair start) or remove the entry", c.path, i, c.TrustedDevices[i].ID, err)
		}
	}
	return nil
}

// defaultRelayURL is relay_url when the config does not name one: the relay is the transport of
// the app, so it is on out of the box. A variable only so the tests of this package never dial
// it (TestMain).
var defaultRelayURL = "wss://relay.wardenclaw.dev"

// relayOff is the relay_url of a wardend without the relay.
const relayOff = "off"

// relayOn: the relay transport is configured.
func (c *Config) relayOn() bool { return c.RelayURL != "" && c.RelayURL != relayOff }

// normalizeRelayURL checks relay_url: "" (the default relay) or "off" (no relay), else wss://host[:port][/prefix]
// without the /v1/ws/<id> tail, query or credentials. https:// is read as wss://. Plain ws:// is
// accepted for a loopback relay only (tests, a relay behind a local proxy): the hello and the
// traffic pattern are not for an open network even though the payload is end-to-end encrypted.
// With a ws:// relay `pair start` prints no link (pairStart): a pair link is wss:// only.
func normalizeRelayURL(s string) (string, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	if s == "" {
		s = defaultRelayURL
	}
	if s == "" || s == relayOff {
		return relayOff, nil
	}
	if rest, ok := strings.CutPrefix(s, "https://"); ok {
		s = "wss://" + rest
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("relay_url %q: must be wss://host[:port]", s)
	}
	switch u.Scheme {
	case "wss":
	case "ws":
		if h := u.Hostname(); h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return "", fmt.Errorf("relay_url %q: ws:// is for a loopback relay only, use wss://", s)
		}
	default:
		return "", fmt.Errorf("relay_url %q: must be wss://host[:port]", s)
	}
	if strings.HasSuffix(u.Path, "/v1/ws") {
		return "", fmt.Errorf("relay_url %q: give the relay's base address, without /v1/ws", s)
	}
	return s, nil
}

// hwCountersPath is hardware_counters, by default <state_dir>/hw_counters.json; wardend hw-keys
// reads it without the rest of setDefaults.
func (c *Config) hwCountersPath() string {
	if c.HardwareCounters != "" {
		return c.HardwareCounters
	}
	stateDir := c.StateDir
	if stateDir == "" {
		stateDir = defaultStateDir()
	}
	return filepath.Join(stateDir, "hw_counters.json")
}

// updateConfig: rewrites the config, changing only the needed top-level keys (fn edits top).
// Other fields are kept as is; indented JSON, keys in alphabetical order.
// The write is atomic (tmp + rename), permissions kept or 0600.
func updateConfig(path string, fn func(top map[string]json.RawMessage) error) error {
	top := map[string]json.RawMessage{}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	default:
		if len(bytes.TrimSpace(b)) > 0 {
			if err := json.Unmarshal(b, &top); err != nil {
				return fmt.Errorf("config %s: %w", path, err)
			}
		}
	}
	if err := fn(top); err != nil {
		return err
	}
	out, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// editTrustedDevices: reads the config's trusted_devices, modifies them, writes them back.
func editTrustedDevices(path string, fn func([]envelope.TrustedDevice) ([]envelope.TrustedDevice, error)) error {
	return updateConfig(path, func(top map[string]json.RawMessage) error {
		var list []envelope.TrustedDevice
		if raw, ok := top["trusted_devices"]; ok {
			if err := json.Unmarshal(raw, &list); err != nil {
				return fmt.Errorf("config %s: trusted_devices: %w", path, err)
			}
		}
		list, err := fn(list)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(list)
		top["trusted_devices"] = b
		return nil
	})
}
