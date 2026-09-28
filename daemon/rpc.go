// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Transport: unix socket (0600, directory 0700), JSON-RPC 2.0, one JSON object per line.
// A connection can carry many requests; responses go out in completion order (by id).
// Additionally SO_PEERCRED: only processes with the supervisor's uid are accepted.
//
// Methods:
//   pending      {since?, wait?(ms, ≤ 25000)} → {seq, mode, supervisorId, host, pending:[item], now}
//   decide       {deviceId, payload:{id,digest,decision,ts,nonce}, signature}
//                → {ok:true, id, decision} | {ok:false, reason}
//   status       {} → metrics, queue, roots, trusted devices, journal key
//   journal.tail {n?} → {lines:[…]}
//   pair.start   {ttl?(ms), url?} → {code, link, expiresAt, …}     ┐ app pairing (pairing.go);
//   pair.list    {} → {requests, devices, activeCodes, http}        │ start/approve/reject/revoke:
//   pair.approve {id} | pair.reject {id} | pair.revoke {device}     ┘ only for clients NOT under the wardend filter
//   push.list    {} → {push, tokens}                                APNs tokens (pushcmd.go)
//   push.test    {device?} → {results}                              test push; only for clients NOT under the filter

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const longPollMax = 25 * time.Second

// JSON-RPC 2.0 error codes.
const (
	rpcParseError     = -32700
	rpcMethodNotFound = -32601
	rpcServerError    = -32000
)

const (
	rpcMaxRequest  = 1 << 20  // the longest request line the server reads
	rpcMaxResponse = 64 << 20 // the longest response line the client reads (journal.tail)

	journalTailDefault = 20
	journalTailMax     = 1000
)

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

type rpcServer struct {
	ln   *net.UnixListener
	path string
	s    *supervisor
	wg   sync.WaitGroup
	ctx  context.Context
	stop context.CancelFunc
}

func listenSocket(path string) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(dir, 0o700)
	if _, err := os.Stat(path); err == nil {
		// a live neighbor or garbage left by a crashed process?
		if c, err := net.DialTimeout("unix", path, 300*time.Millisecond); err == nil {
			c.Close()
			return nil, fmt.Errorf("%s: another wardend is listening", path)
		}
		_ = os.Remove(path)
	}
	old := unix.Umask(0o177)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	ln.SetUnlinkOnClose(true)
	return ln, nil
}

func startRPC(path string, s *supervisor) (*rpcServer, error) {
	ln, err := listenSocket(path)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &rpcServer{ln: ln, path: path, s: s, ctx: ctx, stop: cancel}
	r.wg.Add(1)
	s.goSafe("rpc accept", r.accept)
	return r, nil
}

func (r *rpcServer) close() {
	r.stop()
	r.ln.Close()
	r.wg.Wait()
}

func (r *rpcServer) accept() {
	defer r.wg.Done()
	for {
		c, err := r.ln.AcceptUnix()
		if err != nil {
			return
		}
		pid, ok := peerAllowed(c)
		if !ok {
			c.Close()
			continue
		}
		r.wg.Add(1)
		r.s.goSafe("rpc serve", func() { r.serve(c, pid) })
	}
}

func peerAllowed(c *net.UnixConn) (int, bool) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *unix.Ucred
	_ = raw.Control(func(fd uintptr) {
		cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cred == nil || int(cred.Uid) != os.Getuid() {
		return 0, false
	}
	return int(cred.Pid), true
}

func (r *rpcServer) serve(c *net.UnixConn, peerPid int) {
	defer r.wg.Done()
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	r.s.goSafe("rpc close", func() { <-ctx.Done(); c.Close() })
	var wmu sync.Mutex
	enc := json.NewEncoder(c)
	enc.SetEscapeHTML(false)
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64<<10), rpcMaxRequest)
	var inflight sync.WaitGroup
	for sc.Scan() {
		var req rpcReq
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			wmu.Lock()
			enc.Encode(rpcResp{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcErr{rpcParseError, "parse error"}})
			wmu.Unlock()
			continue
		}
		inflight.Add(1)
		r.s.goSafe("rpc request", func() {
			defer inflight.Done()
			res, err := r.dispatch(ctx, req.Method, req.Params, peerPid)
			resp := rpcResp{JSONRPC: "2.0", ID: req.ID, Result: res}
			if err != nil {
				resp.Result = nil
				resp.Error = &rpcErr{rpcServerError, err.Error()}
				if errors.Is(err, errNoMethod) {
					resp.Error.Code = rpcMethodNotFound
				}
			}
			if len(resp.ID) == 0 {
				resp.ID = json.RawMessage("null")
			}
			wmu.Lock()
			enc.Encode(resp)
			wmu.Unlock()
		})
	}
	cancel()
	inflight.Wait()
}

var errNoMethod = errors.New("method not found")

func (r *rpcServer) dispatch(ctx context.Context, method string, params json.RawMessage, peerPid int) (any, error) {
	s := r.s
	var pp struct {
		ID     string `json:"id"`
		Device string `json:"device"`
		TTL    int64  `json:"ttl"`
		URL    string `json:"url"`
	}
	switch method {
	case "pair.start", "pair.approve", "pair.reject", "pair.revoke", "push.test":
		if s.peerSupervised(peerPid) {
			s.journal("pair_refused", map[string]any{"method": method, "peerPid": peerPid})
			return nil, errPeerSupervised
		}
		if len(params) > 0 {
			if err := json.Unmarshal(params, &pp); err != nil {
				return nil, err
			}
		}
	}
	switch method {
	case "pair.start":
		return s.pairStart(time.Duration(pp.TTL)*time.Millisecond, pp.URL)
	case "pair.list":
		return s.pairList(), nil
	case "pair.approve":
		return s.pairApprove(pp.ID)
	case "pair.reject":
		return s.pairReject(pp.ID)
	case "pair.revoke":
		return s.pairRevoke(pp.Device)
	case "push.list":
		return s.pushList(), nil
	case "push.test":
		return s.pushTest(ctx, pp.Device)
	case "pending":
		var p struct {
			Since int64 `json:"since"`
			Wait  int64 `json:"wait"`
		}
		if len(params) > 0 {
			_ = json.Unmarshal(params, &p)
		}
		if p.Wait > 0 {
			s.q.waitChange(ctx, p.Since, min(time.Duration(p.Wait)*time.Millisecond, longPollMax))
		}
		return s.pendingSnapshot(), nil
	case "decide":
		return s.decide(params), nil
	case "status":
		return s.status(), nil
	case "journal.tail":
		var p struct {
			N int `json:"n"`
		}
		if len(params) > 0 {
			_ = json.Unmarshal(params, &p)
		}
		if p.N <= 0 || p.N > journalTailMax {
			p.N = journalTailDefault
		}
		lines, err := tailJournal(s.cfg.Journal, p.N)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "lines": lines}, nil
	}
	return nil, errNoMethod
}

// ---------- client ----------

type rpcClient struct {
	c   net.Conn
	sc  *bufio.Scanner
	mu  sync.Mutex
	seq int
}

func dialRPC(path string) (*rpcClient, error) {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64<<10), rpcMaxResponse)
	return &rpcClient{c: c, sc: sc}, nil
}

func (c *rpcClient) Close() error { return c.c.Close() }

// call makes a synchronous call (sequential over the connection).
func (c *rpcClient) call(method string, params any, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.seq, "method": method, "params": params})
	if _, err := c.c.Write(append(b, '\n')); err != nil {
		return err
	}
	if !c.sc.Scan() {
		if err := c.sc.Err(); err != nil {
			return err
		}
		return errors.New("connection closed")
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcErr         `json:"error"`
	}
	if err := json.Unmarshal(c.sc.Bytes(), &resp); err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("rpc %s: %s", method, resp.Error.Message)
	}
	if out != nil {
		return json.Unmarshal(resp.Result, out)
	}
	return nil
}
