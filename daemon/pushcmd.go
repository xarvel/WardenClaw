// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardend push list: device tokens (truncated) and the APNs state.
// wardend push test [--device <deviceId|prefix>]: a test notification (cardId "wd-test") to all
// tokens (or the tokens of one device); prints the APNs answer for each token.
// Only from your own terminal on the server: refused under the wardend filter (the agent), as with
// pair.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const pushTestCard = "wd-test"

func (s *supervisor) pushList() map[string]any {
	toks := []map[string]any{}
	if s.push != nil {
		for _, t := range s.push.store.snapshot() {
			toks = append(toks, map[string]any{"deviceId": t.DeviceID, "alg": s.devices.Alg(t.DeviceID), "token": clip8(t.Token) + "…",
				"topic": t.Topic, "environment": t.Environment, "registeredAt": t.RegisteredAt})
		}
	}
	return map[string]any{"ok": true, "push": s.push.info(), "tokens": toks}
}

func (s *supervisor) pushTest(ctx context.Context, device string) (map[string]any, error) {
	if !s.push.enabled() {
		why := "apns is not configured (config.json → apns)"
		if s.push != nil && s.push.apnsErr != "" {
			why = "apns disabled: " + s.push.apnsErr
		}
		return nil, errors.New(why)
	}
	device = strings.ToLower(strings.TrimSpace(device))
	out := []map[string]any{}
	for _, t := range s.push.store.snapshot() {
		if device != "" && !strings.HasPrefix(t.DeviceID, device) {
			continue
		}
		r, err := s.push.apns.push(ctx, t, pushTestCard, time.Now().Add(time.Minute))
		m := map[string]any{"deviceId": t.DeviceID, "token": clip8(t.Token) + "…", "topic": t.Topic, "environment": t.Environment}
		if err != nil {
			m["error"] = err.Error()
		} else {
			m["status"], m["reason"], m["apnsId"] = r.Status, r.Reason, r.ID
		}
		out = append(out, m)
	}
	s.journal("push_test", map[string]any{"device": device, "tokens": len(out)})
	return map[string]any{"ok": true, "results": out}, nil
}

const pushUsage = `usage: wardend push list [--socket s]
       wardend push test [--socket s] [--device <deviceId|prefix>]
`

func cmdPush(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, pushUsage)
		return 2
	}
	var fs *cmdFlags
	switch sub := args[0]; {
	case isHelpArg(sub):
		fmt.Fprint(stdout, pushUsage+"\nPush notifications to iPhone and Apple Watch (APNs): registered tokens and a test push.\n"+
			"wardend push <subcommand> --help lists its flags.\n")
		return 0
	case sub == "list":
		fs = newCmdFlags("push list", "push list [--socket s]", "Push tokens of the devices (APNs, truncated) and the APNs state.", stdout, stderr)
	case sub == "test":
		fs = newCmdFlags("push test", "push test [--socket s] [--device <deviceId|prefix>]",
			"Sends a test push (cardId wd-test) to the registered tokens and prints the APNs answer for each.", stdout, stderr)
	default:
		fmt.Fprintf(stderr, "wardend push: unknown subcommand %q\n\n%s", sub, pushUsage)
		return 2
	}
	sock := socketFlag(fs.FlagSet)
	dev := new(string)
	if args[0] == "test" {
		dev = fs.String("device", "", "only the tokens of this device (deviceId or prefix)")
	}
	if _, code, ok := fs.parseArgs(args[1:], 0, 0); !ok {
		return code
	}
	c, ok := dialSupervisor(*sock, stderr)
	if !ok {
		return 1
	}
	defer c.Close()
	var out json.RawMessage
	if err := c.call("push."+args[0], map[string]any{"device": *dev}, &out); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	printIndentedJSON(stdout, out)
	return 0
}
