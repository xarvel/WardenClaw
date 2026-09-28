// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Card display against the shared vectors protocol/vectors/display_vectors.json (reference:
// app/src/core/display.ts; the same vectors check the app and the watch).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type displayVectors struct {
	Version     int           `json:"version"`
	Flags       []string      `json:"flags"`
	Classes     [][3]any      `json:"classes"`
	Rules       []displayRule `json:"rules"`
	Delegating  []delegGroup  `json:"delegating"`
	Scripts     [][3]rune     `json:"scripts"`
	ScriptNames []string      `json:"scriptNames"`
	Marks       [][2]rune     `json:"marks"`
	Sanitize    []struct {
		In    string   `json:"in"`
		Text  string   `json:"text"`
		Flags []string `json:"flags"`
	} `json:"sanitize"`
	Normalize []struct {
		In  string `json:"in"`
		Out string `json:"out"`
	} `json:"normalize"`
	TokenFlags []struct {
		In    string          `json:"in"`
		Flags []string        `json:"flags"`
		Mixed json.RawMessage `json:"mixed"`
	} `json:"tokenFlags"`
	Lex []struct {
		In    string      `json:"in"`
		Parts [][2]string `json:"parts"`
	} `json:"lex"`
	Cases []struct {
		Name   string          `json:"name"`
		Input  viewInput       `json:"input"`
		Expect json.RawMessage `json:"expect"`
	} `json:"cases"`
}

func loadDisplayVectors(t *testing.T) displayVectors {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "vectors", "display_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v displayVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDisplayVectorTables(t *testing.T) {
	v := loadDisplayVectors(t)
	if v.Version != 1 || !reflect.DeepEqual(v.Flags, flagOrder) {
		t.Fatalf("flags: %v", v.Flags)
	}
	if len(v.Classes) != len(cpClasses) {
		t.Fatalf("classes: %d vs %d", len(v.Classes), len(cpClasses))
	}
	for i, c := range v.Classes {
		lo, hi, k := rune(c[0].(float64)), rune(c[1].(float64)), cpClassT(c[2].(string))
		if cpClasses[i].Lo != lo || cpClasses[i].Hi != hi || cpClasses[i].Class != k {
			t.Errorf("class %d: %v vs %+v", i, c, cpClasses[i])
		}
	}
	if len(v.Rules) != len(displayRules) {
		t.Fatalf("rules: %d vs %d", len(v.Rules), len(displayRules))
	}
	for i, r := range v.Rules {
		g := displayRules[i]
		if r.ID != g.ID || r.Kind != g.Kind || r.Re != g.Re {
			t.Errorf("rule %d: vectors %s/%s %q, wardenctl %s/%s %q", i, r.ID, r.Kind, r.Re, g.ID, g.Kind, g.Re)
		}
	}
	if !reflect.DeepEqual(v.Delegating, delegatingGroups) {
		t.Errorf("delegating: %v", v.Delegating)
	}
	if len(v.Scripts) != len(scriptRanges) {
		t.Fatalf("scripts: %d vs %d", len(v.Scripts), len(scriptRanges))
	}
	for i, r := range v.Scripts {
		if g := scriptRanges[i]; g.Lo != r[0] || g.Hi != r[1] || rune(g.S) != r[2] {
			t.Errorf("script %d: vectors %v, wardenctl %+v", i, r, g)
		}
	}
	if !reflect.DeepEqual(v.Marks, markRanges) {
		t.Errorf("marks: vectors %v, wardenctl %v", v.Marks, markRanges)
	}
	if !reflect.DeepEqual(v.ScriptNames, scriptNames) {
		t.Errorf("scriptNames: vectors %v, wardenctl %v", v.ScriptNames, scriptNames)
	}
}

// sameJSON: got (a Go value) and want (the raw vector JSON) are equal as JSON.
func sameJSON(t *testing.T, got any, want json.RawMessage) (bool, string) {
	t.Helper()
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var g, w any
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(g, w), string(b)
}

func TestDisplayVectorUnits(t *testing.T) {
	v := loadDisplayVectors(t)
	for _, c := range v.Sanitize {
		text, fl := sanitizeFlags(c.In)
		if text != c.Text || !reflect.DeepEqual(fl, c.Flags) {
			t.Errorf("sanitize %q: %q %v, want %q %v", c.In, text, fl, c.Text, c.Flags)
		}
	}
	for _, c := range v.Normalize {
		if got := normalizeForRules(c.In); got != c.Out {
			t.Errorf("normalize %q: %q, want %q", c.In, got, c.Out)
		}
	}
	for _, c := range v.TokenFlags {
		if got := tokenFlags(c.In); !reflect.DeepEqual(got, c.Flags) {
			t.Errorf("tokenFlags %q: %v, want %v", c.In, got, c.Flags)
		}
		if ok, got := sameJSON(t, mixedRuns(c.In), c.Mixed); !ok {
			t.Errorf("mixedRuns %q:\n got %s\nwant %s", c.In, got, c.Mixed)
		}
	}
	for _, c := range v.Lex {
		got := [][2]string{}
		for _, p := range splitShell(c.In) {
			got = append(got, [2]string{p.Raw, p.Sep})
		}
		want := c.Parts
		if want == nil {
			want = [][2]string{}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("lex %q:\n got %q\nwant %q", c.In, got, want)
		}
	}
}

func TestDisplayVectorCases(t *testing.T) {
	v := loadDisplayVectors(t)
	if len(v.Cases) < 40 {
		t.Fatalf("cases: %d", len(v.Cases))
	}
	for _, c := range v.Cases {
		in := c.Input
		if in.Chain == nil {
			in.Chain = []string{}
		}
		if ok, got := sameJSON(t, commandView(in), c.Expect); !ok {
			t.Errorf("%s:\n got %s\nwant %s", c.Name, got, c.Expect)
		}
	}
}
