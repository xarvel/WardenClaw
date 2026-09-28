// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

// Trusted devices. The trust decision is made solely by wardend config
// (trusted_devices: [{id, pubkey}]); native pairing (`wardend pair approve`) appends a
// device with its key and immediately adds it here (Add), without a restart. The public key
// is the pubkey of the config entry, there is no other source: an entry without one is
// "unknown_device" and cannot approve anything until the device is paired again.
// A key is accepted only when deviceId = sha256(key), as at pairing time
// (DeviceKey.ID): a foreign key under a trusted id would otherwise sign tickets on behalf of
// the phone. Such an entry is "config_pubkey_invalid" (and CheckTrusted prevents wardend
// from starting when the config is loaded).

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// TrustedDevice is a trusted_devices entry of the wardend config.
type TrustedDevice struct {
	ID      string `json:"id"`
	Pubkey  string `json:"pubkey,omitempty"` // ed25519: base64url raw 32 bytes or hex
	Alg     string `json:"alg,omitempty"`    // "" or "ed25519"; anything else is refused
	Enc     string `json:"enc,omitempty"`    // X25519 key for the relay transport, base64url 32 bytes
	Name    string `json:"name,omitempty"`
	AddedAt string `json:"added_at,omitempty"` // RFC 3339, written by `wardend pair approve`
}

// Devices is the trusted-device registry built from the config entries.
type Devices struct {
	tmu     sync.RWMutex
	trusted map[string]TrustedDevice
}

// NewDevices builds the registry from config entries.
func NewDevices(list []TrustedDevice) *Devices {
	d := &Devices{trusted: map[string]TrustedDevice{}}
	for _, t := range list {
		d.trusted[normalizeID(t.ID)] = t
	}
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

// Key returns the public key of a trusted device, or a rejection reason. Key and algorithm
// are taken only from config (recorded at pairing time).
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
	if t.Pubkey == "" {
		return DeviceKey{}, "unknown_device"
	}
	k, err := ParseDeviceKey(alg, t.Pubkey)
	if err != nil || k.ID() != id {
		return DeviceKey{}, "config_pubkey_invalid"
	}
	return k, ""
}

// CheckTrusted validates a trusted_devices entry: pubkey must parse for alg and
// deviceId must equal sha256(pubkey), as at pairing time. An entry without pubkey loads, but
// Key refuses it as "unknown_device".
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
