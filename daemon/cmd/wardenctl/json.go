// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "encoding/json"

// These types are the stable, minimal interface for external approvers. Keep field names
// backwards-compatible: callers may persist the objects or use strict decoders.
type cardJSON struct {
	ID                string          `json:"id"`
	Kind              string          `json:"kind"`
	Digest            string          `json:"digest"`
	CreatedAt         int64           `json:"createdAt"`
	ExpiresAt         int64           `json:"expiresAt"`
	Command           string          `json:"command,omitempty"`
	Envelope          json.RawMessage `json:"envelope"`
	Meta              json.RawMessage `json:"meta,omitempty"`
	Verified          bool            `json:"verified"`
	VerificationError string          `json:"verificationError,omitempty"`
}

type pendingJSON struct {
	OK      bool       `json:"ok"`
	Host    string     `json:"host"`
	Mode    string     `json:"mode"`
	Seq     int64      `json:"seq"`
	Now     int64      `json:"now"`
	Pending []cardJSON `json:"pending"`
}

type showJSON struct {
	OK   bool     `json:"ok"`
	Host string   `json:"host"`
	Mode string   `json:"mode"`
	Now  int64    `json:"now"`
	Card cardJSON `json:"card"`
}

type decisionJSON struct {
	OK           bool   `json:"ok"`
	ID           string `json:"id"`
	Digest       string `json:"digest"`
	Decision     string `json:"decision"`
	HardwareRule string `json:"hardwareRule,omitempty"`
}

func newCardJSON(c Card) cardJSON {
	out := cardJSON{
		ID:        c.ID,
		Kind:      c.Kind,
		Digest:    c.Digest,
		CreatedAt: c.CreatedAt,
		ExpiresAt: c.ExpiresAt,
		Envelope:  c.Envelope,
		Meta:      c.Item.Meta,
		Verified:  c.Err == nil,
	}
	if c.Env != nil {
		out.Command = displayCommand(c.Env)
	}
	if c.Err != nil {
		out.VerificationError = c.Err.Error()
	}
	return out
}
