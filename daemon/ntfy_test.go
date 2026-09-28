// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ntfy push text: body "New request to approve" in English, WardenClaw title, token in
// Authorization; nothing beyond that (daemon/docs/CLI.md, ntfy section).
func TestNtfyPushText(t *testing.T) {
	type got struct {
		body                                   string
		title, prio, tags, click, auth, method string
	}
	reqs := make(chan got, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		reqs <- got{string(b), r.Header.Get("Title"), r.Header.Get("Priority"), r.Header.Get("Tags"), r.Header.Get("Click"), r.Header.Get("Authorization"), r.Method}
	}))
	defer srv.Close()
	if err := newNotifier(srv.URL, "tok", nil).send(context.Background()); err != nil {
		t.Fatal(err)
	}
	g := <-reqs
	want := got{"New request to approve", "WardenClaw", "high", "lock", "wardenclaw://feed", "Bearer tok", http.MethodPost}
	if g != want {
		t.Fatalf("ntfy request %+v, want %+v", g, want)
	}
	if ntfyBody != want.body {
		t.Fatalf("ntfyBody %q", ntfyBody)
	}
	// without a token there is no Authorization header
	if err := newNotifier(srv.URL, "", nil).send(context.Background()); err != nil {
		t.Fatal(err)
	}
	if g := <-reqs; g.auth != "" || g.body != want.body {
		t.Fatalf("without token: %+v", g)
	}
}
