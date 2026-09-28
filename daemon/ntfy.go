// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Notifications via ntfy (optional): POST to the topic URL (ntfy_url) when a card appears.
// The notification only says "there is a new card" (ntfyBody), no command or host: an ntfy topic
// is not a secret channel (whoever knows the topic name sees when cards appear and can push to
// that topic themselves). Several cards in a row are collapsed: at most one notification per
// ntfyMinGap.

import (
	"context"
	"net/http"
	"strings"
	"time"
)

const (
	ntfyMinGap         = 10 * time.Second
	ntfyRequestTimeout = 10 * time.Second
)

// ntfyBody: the whole push text (the WardenClaw heading goes into Title). In English, like the
// other wardend messages.
const ntfyBody = "New request to approve"

type notifier struct {
	url, token string
	kick       chan struct{}
	client     *http.Client
	logf       func(format string, a ...any)
	sent       func() // for tests
}

func newNotifier(url, token string, logf func(string, ...any)) *notifier {
	if url == "" {
		return nil
	}
	return &notifier{url: url, token: token, kick: make(chan struct{}, 1), client: &http.Client{Timeout: ntfyRequestTimeout}, logf: logf}
}

// poke: there is a new card (non-blocking).
func (n *notifier) poke() {
	if n == nil {
		return
	}
	select {
	case n.kick <- struct{}{}:
	default:
	}
}

func (n *notifier) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.kick:
		}
		if err := n.send(ctx); err != nil && n.logf != nil {
			n.logf("wardend: ntfy: %v\n", err)
		}
		if n.sent != nil {
			n.sent()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(ntfyMinGap):
		}
	}
}

func (n *notifier) send(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, strings.NewReader(ntfyBody))
	if err != nil {
		return err
	}
	req.Header.Set("Title", "WardenClaw")
	req.Header.Set("Priority", "high")
	req.Header.Set("Tags", "lock")
	req.Header.Set("Click", "wardenclaw://feed")
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return &httpStatusErr{resp.StatusCode}
	}
	return nil
}

type httpStatusErr struct{ code int }

func (e *httpStatusErr) Error() string { return "HTTP " + http.StatusText(e.code) }
