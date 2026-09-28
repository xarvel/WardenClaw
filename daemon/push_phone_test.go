// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Pushes to the iPhone itself (topic_ios): the phone's token is registered by the same signed
// request as the watch token, and delivery uses the apns-topic of the target token (the phone and
// watch apps have different bundle ids, APNs rejects a foreign topic). The payload has only the card
// id, the time-sensitive level and the WARDEN_APPROVAL category: the phone registers it without
// "Allow".

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// phoneHeaders: signature of a request with a body by the phone's Ed25519 key (as the app does it).
func phoneHeaders(d device, sup, action, nonce string, body map[string]any) map[string]string {
	ts := envelope.NowMs()
	msg, _ := envelope.RequestBodySigningString(sup, action, d.id, ts, nonce, body)
	return map[string]string{"X-Wardenclaw-Device": d.id, "X-Wardenclaw-Ts": strconv.FormatInt(ts, 10), "X-Wardenclaw-Nonce": nonce,
		"X-Wardenclaw-Signature": envelope.B64URL(ed25519.Sign(d.priv, msg))}
}

// A new card: a push to both the iPhone (topic_ios) and the watch (topic_watch), each with its
// own apns-topic.
func TestPushPhoneAndWatchTopics(t *testing.T) {
	phone, w := newDevice(), newWatch()
	s := newHWSupervisor(t, `{}`, phone)
	s.devices.Add(w.trusted())
	kf, _ := writeP8(t, t.TempDir(), 0o600)
	s.cfg.APNS = testAPNSConfig(kf)
	s.push = newPushService(s.cfg, s)
	m := newAPNSMock(t)
	m.attach(s.push.apns)
	tokPhone, tokWatch := strings.Repeat("4a", 32), strings.Repeat("5b", 32)
	now := time.Now().UnixMilli()
	s.push.store.register(pushToken{DeviceID: phone.id, Platform: "apns", Token: tokPhone, Topic: "com.wardenclaw.app", Environment: "production", RegisteredAt: now})
	s.push.store.register(pushToken{DeviceID: w.id, Platform: "apns", Token: tokWatch, Topic: "com.wardenclaw.app.watchkitapp", Environment: "sandbox", RegisteredAt: now + 1})
	done := make(chan map[string]apnsResult, 1)
	s.push.sent = func(_ string, r map[string]apnsResult) { done <- r }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.push.run(ctx)

	ch, it := startExec(t, s, 100, "cat", "/home/secret-project/SECRET-ARG")
	select {
	case res := <-done:
		if len(res) != 2 || res[tokPhone].Status != 200 || res[tokWatch].Status != 200 {
			t.Fatalf("results: %+v", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no push")
	}
	m.mu.Lock()
	reqs := append([]apnsReq(nil), m.reqs...)
	m.mu.Unlock()
	want := map[string]string{tokPhone: "com.wardenclaw.app", tokWatch: "com.wardenclaw.app.watchkitapp"}
	for _, q := range reqs {
		tok := strings.TrimPrefix(q.path, "/3/device/")
		if q.hdr.Get("apns-topic") != want[tok] {
			t.Fatalf("token %s…: apns-topic %q, want %q", tok[:8], q.hdr.Get("apns-topic"), want[tok])
		}
		if q.hdr.Get("apns-push-type") != "alert" || q.hdr.Get("apns-priority") != "10" || q.hdr.Get("apns-collapse-id") != it.ID {
			t.Fatalf("headers: %v", q.hdr)
		}
		var p struct {
			APS struct {
				Category          string `json:"category"`
				InterruptionLevel string `json:"interruption-level"`
				Sound             string `json:"sound"`
			} `json:"aps"`
			CardID string `json:"cardId"`
		}
		if err := json.Unmarshal(q.body, &p); err != nil {
			t.Fatalf("payload %s: %v", q.body, err)
		}
		// iPhone lock screen: an urgent notification without the command, host and paths
		if p.APS.InterruptionLevel != "time-sensitive" || p.APS.Category != apnsCategory || p.APS.Sound != "default" || p.CardID != it.ID {
			t.Fatalf("payload: %s", q.body)
		}
		if strings.Contains(string(q.body), "SECRET") || strings.Contains(string(q.body), "secret-project") || strings.Contains(string(q.body), "/home") {
			t.Fatalf("payload leaks the command: %s", q.body)
		}
	}
	if len(reqs) != 2 {
		t.Fatalf("requests: %d", len(reqs))
	}
	decideRaw(s, w.ticket(it, "deny", true))
	wait(t, ch)
}

// iPhone-only server (topic_ios without topic_watch): the phone registers, a foreign topic is
// rejected.
func TestPushRegisterTopicIOSOnly(t *testing.T) {
	phone := newDevice()
	e, _ := pushEnv(t, phone)
	e.s.cfg.APNS.TopicWatch = ""
	tok := strings.Repeat("6c", 32)
	for i, c := range []struct {
		topic, want string
		status      int
	}{
		{"com.wardenclaw.app.watchkitapp", "topic_not_allowed", 400},
		{"com.wardenclaw.app", "", 200},
	} {
		nonce := "n-ios-only-" + strconv.Itoa(i)
		body := regBody(phone.id, tok, c.topic, "production")
		r := e.do(t, "POST", "/v1/push/register", phoneHeaders(phone, e.s.supervisorID, "push.register", nonce, body), []byte(mustJSON(body)), nonce)
		if r.status != c.status || (c.want != "" && r.body["reason"] != c.want) {
			t.Fatalf("%s: %d %s", c.topic, r.status, r.raw)
		}
	}
	toks := e.s.push.store.snapshot()
	if len(toks) != 1 || toks[0].Topic != "com.wardenclaw.app" || toks[0].DeviceID != phone.id {
		t.Fatalf("tokens: %+v", toks)
	}
}
