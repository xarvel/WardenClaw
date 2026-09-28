// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// End-to-end scenario of wardend's own transport under a real seccomp filter: phone pairing via
// the QR link (HTTP), confirmation with `pair approve` (RPC), the root card over HTTP long-poll
// with the response signature checked against the pinned key, a ticket over HTTP → execve runs.
//
// Inside a wardend tree (e.g. in an agent session) a nested filter is forbidden: the test is run
// by a human from their own terminal outside wardend, or by CI, not by an agent via
// `systemd-run --user`.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

type phoneClient struct {
	t      *testing.T
	base   string
	pinned ed25519.PublicKey
	d      device
}

func (p *phoneClient) call(method, path string, hdr map[string]string, body []byte, nonce string) (int, map[string]any, error) {
	req, _ := http.NewRequest(method, p.base+path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if ok, _ := respSigOK(p.pinned, respCtxFor(path, hdr, body, nonce), res.StatusCode, raw, res.Header.Get("X-Wardend-Signature")); !ok {
		return res.StatusCode, nil, fmt.Errorf("%s: response is not signed by the pinned key for this request", path)
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	return res.StatusCode, m, nil
}

func TestE2EPairAndApproveOverHTTP(t *testing.T) {
	phone := newDevice()
	var paired, decided bool
	var cfgPath string
	r := run(t, Config{Mode: "ticket", TicketTTL: duration{20 * time.Second}, HTTPListen: "127.0.0.1:0"},
		[]string{"sh", "-c", `bash -c 'echo root-ran'`},
		func(sock string) {
			var st map[string]any
			if err := rpcDo(t, sock, "status", nil, &st); err != nil {
				t.Error(err)
				return
			}
			addr, _ := st["http"].(map[string]any)["addr"].(string)
			if head, _ := st["journalHead"].(map[string]any); head["seq"] == nil || len(fmt.Sprint(head["hash"])) != 64 {
				t.Errorf("status journalHead: %v", st["journalHead"])
			}
			var ps struct{ Link string }
			if err := rpcDo(t, sock, "pair.start", map[string]any{"url": "http://" + addr}, &ps); err != nil {
				t.Error(err)
				return
			}
			link, err := envelope.ParsePairLink(ps.Link)
			if err != nil {
				t.Error(err)
				return
			}
			pinned, _ := envelope.DecodeKey(link.Key)
			pc := &phoneClient{t: t, base: link.URL, pinned: pinned, d: phone}
			body, nonce := pairBody(phone, link.Code, envelope.DeviceID(pinned), "Pixel 9")
			code, m, err := pc.call("POST", "/v1/pair", nil, body, nonce)
			if err != nil || code != 200 {
				t.Errorf("pair: %d %v %v", code, m, err)
				return
			}
			var ap struct{ Config string }
			if err := rpcDo(t, sock, "pair.approve", map[string]any{"id": m["id"]}, &ap); err != nil {
				t.Error(err)
				return
			}
			paired, cfgPath = true, ap.Config
			var since int64
			for i := 0; i < 20 && !decided; i++ {
				n := envelope.NewNonce()
				code, m, err := pc.call("GET", "/v1/pending?since="+strconv.FormatInt(since, 10)+"&wait=2000", signedHeaders(phone.priv, envelope.DeviceID(pc.pinned), "pending", envelope.NowMs(), n), nil, n)
				if err != nil || code != 200 {
					t.Errorf("pending: %d %v %v", code, m, err)
					return
				}
				since = int64(m["seq"].(float64))
				items, _ := m["pending"].([]any)
				for _, x := range items {
					it := x.(map[string]any)
					env := it["envelope"].(map[string]any)
					dg, err := envelopeDigest(env)
					if err != nil || dg != it["digest"] || env["requester"].(map[string]any)["supervisorId"] != envelope.DeviceID(pinned) {
						t.Errorf("envelope check: %v %v", err, it)
						return
					}
					tk := envelope.Sign(phone.priv, envelope.DeviceID(pinned), it["id"].(string), dg, "allow", envelope.NowMs(), envelope.NewNonce())
					raw, _ := json.Marshal(tk)
					code, m, err := pc.call("POST", "/v1/decide", nil, raw, tk.Payload.Nonce)
					if err != nil || code != 200 || m["ok"] != true {
						t.Errorf("decide: %d %v %v", code, m, err)
						return
					}
					decided = true
				}
			}
		})
	if !paired || !decided || r.code != 0 || !strings.Contains(r.out, "root-ran") {
		t.Fatalf("paired=%v decided=%v code=%d\n%s", paired, decided, r.code, r.dump())
	}
	roots := r.byClass("root")
	tb, _ := json.Marshal(roots[0].Ticket)
	if len(roots) != 1 || !strings.Contains(string(tb), `"deviceId":"`+phone.id+`"`) {
		t.Fatalf("root ticket:\n%s", r.dump())
	}
	if cfgPath != filepath.Join(r.dir, "config.json") {
		t.Fatalf("config path %q", cfgPath)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil || len(cfg.TrustedDevices) != 1 || cfg.TrustedDevices[0].ID != phone.id {
		t.Fatalf("config: %v %+v", err, cfg)
	}
	kinds := map[string]bool{}
	for _, e := range r.entries {
		kinds[e.Kind] = true
	}
	for _, k := range []string{"pair_start", "pair_request", "pair_approved"} {
		if !kinds[k] {
			t.Errorf("journal: no %s", k)
		}
	}
}
