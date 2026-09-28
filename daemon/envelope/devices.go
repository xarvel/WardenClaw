// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

// Trusted devices. The trust decision is made solely by wardend config
// (trusted_devices: [{id, pubkey}]); native pairing (`wardend pair approve`) appends a
// device with its key and immediately adds it here (Add), without a restart. Public key:
//   1) pubkey from config, if set (pinned; on conflict with the gateway DB: "pubkey_conflict",
//      not a silent choice between the two);
//   2) otherwise, if gateway_db is enabled (off by default): from device_pairing_paired in
//      ~/.openclaw/state/openclaw.sqlite (as the plugin does), read-only:
//      `sqlite3 -readonly -json`, 30 s cache;
//   3) neither present: "unknown_device".
// If the DB is unavailable or sqlite3 is missing, only config is used (fallback).
// Any key (config and DB, both algorithms) is accepted only when deviceId = sha256(key),
// as at pairing time (DeviceKey.ID): the gateway DB may store the agent uid, and a foreign
// key under a trusted id would otherwise allow the agent to sign tickets on behalf of the
// phone. Such a key from DB is rejected ("gateway_pubkey_mismatch" if no other key exists),
// from config: "config_pubkey_invalid" (and CheckTrusted prevents wardend from starting
// when the config is loaded).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	gatewayCacheTTL = 30 * time.Second // how long a gateway DB lookup is reused
	sqliteTimeout   = 3 * time.Second  // limit for one sqlite3 run
)

// TrustedDevice is a trusted_devices entry of the wardend config.
type TrustedDevice struct {
	ID      string `json:"id"`
	Pubkey  string `json:"pubkey,omitempty"` // ed25519: base64url raw 32 bytes or hex; es256: base64url SEC1 65 bytes
	Alg     string `json:"alg,omitempty"`    // "" = ed25519 | "es256" (Secure Enclave, Apple Watch)
	Enc     string `json:"enc,omitempty"`    // X25519 key for the relay transport, base64url 32 bytes
	Name    string `json:"name,omitempty"`
	AddedAt string `json:"added_at,omitempty"` // RFC 3339, written by `wardend pair approve`
}

// Devices is the trusted-device registry: config entries plus the optional gateway DB lookup.
type Devices struct {
	tmu      sync.RWMutex
	trusted  map[string]TrustedDevice
	dbPath   string
	cacheTTL time.Duration

	mu    sync.Mutex
	cache map[string]dbEntry
	// Lookup reads a device public key from the gateway DB (sqliteLookup; tests replace it).
	Lookup func(id string) (string, error)
}

type dbEntry struct {
	at  time.Time
	key string
	err error
}

// NewDevices builds the registry from config entries; gatewayDB is the gateway state DB path
// ("" disables the lookup).
func NewDevices(list []TrustedDevice, gatewayDB string) *Devices {
	d := &Devices{trusted: map[string]TrustedDevice{}, dbPath: gatewayDB, cacheTTL: gatewayCacheTTL, cache: map[string]dbEntry{}}
	for _, t := range list {
		d.trusted[normalizeID(t.ID)] = t
	}
	d.Lookup = d.sqliteLookup
	return d
}

// normalizeID brings a device id from config to the form used as the registry key.
func normalizeID(id string) string { return strings.ToLower(strings.TrimSpace(id)) }

// IDs returns the trusted device ids, sorted.
func (d *Devices) IDs() []string {
	d.tmu.RLock()
	defer d.tmu.RUnlock()
	out := make([]string, 0, len(d.trusted))
	for id := range d.trusted {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// List returns a copy of the trusted device list (sorted by id).
func (d *Devices) List() []TrustedDevice {
	d.tmu.RLock()
	defer d.tmu.RUnlock()
	out := make([]TrustedDevice, 0, len(d.trusted))
	for _, t := range d.trusted {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Add trusts a device (or replaces an existing entry with the same id).
func (d *Devices) Add(t TrustedDevice) {
	t.ID = normalizeID(t.ID)
	d.tmu.Lock()
	d.trusted[t.ID] = t
	d.tmu.Unlock()
}

// Remove untrusts a device; returns false if the device was not present.
func (d *Devices) Remove(id string) bool {
	d.tmu.Lock()
	defer d.tmu.Unlock()
	_, ok := d.trusted[id]
	delete(d.trusted, id)
	return ok
}

// Key returns the public key of a trusted device, or a rejection reason. Algorithm is taken
// only from config (recorded at pairing time); the gateway DB knows only Ed25519.
func (d *Devices) Key(id string) (DeviceKey, string) {
	d.tmu.RLock()
	t, ok := d.trusted[id]
	d.tmu.RUnlock()
	if !ok {
		return DeviceKey{}, "untrusted_device"
	}
	alg, err := NormalizeAlg(t.Alg)
	if err != nil {
		return DeviceKey{}, "config_alg_invalid"
	}
	var cfgKey, dbKey DeviceKey
	if t.Pubkey != "" {
		k, err := ParseDeviceKey(alg, t.Pubkey)
		if err != nil || k.ID() != id {
			return DeviceKey{}, "config_pubkey_invalid"
		}
		cfgKey = k
	}
	dbMismatch := false
	if d.dbPath != "" && alg == AlgEd25519 {
		dbKey, dbMismatch = d.gatewayKey(id)
	}
	switch {
	case cfgKey.Valid() && dbKey.Valid() && !cfgKey.Equal(dbKey):
		return DeviceKey{}, "pubkey_conflict"
	case cfgKey.Valid():
		return cfgKey, ""
	case dbKey.Valid():
		return dbKey, ""
	case dbMismatch:
		return DeviceKey{}, "gateway_pubkey_mismatch"
	}
	return DeviceKey{}, "unknown_device"
}

// gatewayKey returns the Ed25519 key of id from the gateway DB, if there is one. mismatch
// reports a key that parses but does not belong to this device (sha256(key) != id).
func (d *Devices) gatewayKey(id string) (k DeviceKey, mismatch bool) {
	s, err := d.cachedLookup(id)
	if err != nil || s == "" {
		return DeviceKey{}, false
	}
	k, err = ParseDeviceKey(AlgEd25519, s)
	if err != nil {
		return DeviceKey{}, false
	}
	if k.ID() != id {
		return DeviceKey{}, true
	}
	return k, false
}

// CheckTrusted validates a trusted_devices entry: pubkey must parse for alg and
// deviceId must equal sha256(pubkey), as at pairing time. Entries without pubkey (key from
// the gateway DB) are validated the same way on each Key call.
func CheckTrusted(t TrustedDevice) error {
	id := normalizeID(t.ID)
	alg, err := NormalizeAlg(t.Alg)
	if err != nil {
		return err
	}
	if t.Pubkey == "" {
		return nil
	}
	k, err := ParseDeviceKey(alg, t.Pubkey)
	if err != nil {
		return fmt.Errorf("%s pubkey: %w", alg, err)
	}
	if k.ID() != id {
		return fmt.Errorf("pubkey is not this device's key: sha256(pubkey) = %s, not the id", k.ID())
	}
	return nil
}

// Alg returns the key algorithm for a trusted device ("" if not trusted).
func (d *Devices) Alg(id string) string {
	d.tmu.RLock()
	t, ok := d.trusted[id]
	d.tmu.RUnlock()
	if !ok {
		return ""
	}
	a, _ := NormalizeAlg(t.Alg)
	return a
}

func (d *Devices) cachedLookup(id string) (string, error) {
	d.mu.Lock()
	c, ok := d.cache[id]
	d.mu.Unlock()
	if ok && time.Since(c.at) < d.cacheTTL {
		return c.key, c.err
	}
	k, err := d.Lookup(id)
	d.mu.Lock()
	d.cache[id] = dbEntry{at: time.Now(), key: k, err: err}
	d.mu.Unlock()
	return k, err
}

// sqliteLookup reads public_key from the gateway DB via the sqlite3 CLI (no cgo), read-only.
func (d *Devices) sqliteLookup(id string) (string, error) {
	if _, err := os.Stat(d.dbPath); err != nil {
		return "", err
	}
	if !hex64.MatchString(id) {
		return "", errors.New("bad id")
	}
	ctx, cancel := context.WithTimeout(context.Background(), sqliteTimeout)
	defer cancel()
	// id was validated by regexp [0-9a-f]{64}, so substitution into SQL is safe.
	q := "SELECT public_key FROM device_pairing_paired WHERE device_id = '" + id + "'"
	out, err := exec.CommandContext(ctx, "sqlite3", "-readonly", "-json", d.dbPath, q).Output()
	if err != nil {
		return "", err
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return "", nil
	}
	var rows []struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(out, &rows); err != nil || len(rows) == 0 {
		return "", err
	}
	return rows[0].PublicKey, nil
}
