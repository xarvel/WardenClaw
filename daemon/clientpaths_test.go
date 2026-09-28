package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clientPathsEnv points HOME and the system install at temp dirs; nothing in them yet.
func clientPathsEnv(t *testing.T) (home, etc, state string) {
	t.Helper()
	root := t.TempDir()
	home, etc, state = filepath.Join(root, "home"), filepath.Join(root, "etc"), filepath.Join(root, "var")
	for _, d := range []string{filepath.Join(home, ".wardend"), etc, state} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldConf, oldState := systemConfigPath, systemStateDir
	systemConfigPath, systemStateDir = filepath.Join(etc, "config.json"), state
	t.Cleanup(func() { systemConfigPath, systemStateDir = oldConf, oldState })
	t.Setenv("HOME", home)
	t.Setenv(socketEnv, "")
	return home, etc, state
}

func putFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClientSocketOrder(t *testing.T) {
	const userSock, sysSock = "<home>/.wardend/wardend.sock", "<var>/wardend.sock"
	cases := []struct {
		name       string
		flag, env  string
		userSocket bool
		config     *string // nil: no system install
		unreadable bool    // the config directory is closed to this user
		want       string
	}{
		{name: "nothing installed", want: userSock},
		{name: "flag wins", flag: "/x/flag.sock", env: "/x/env.sock", userSocket: true, config: ptr(`{}`), want: "/x/flag.sock"},
		{name: "env over both installs", env: "/x/env.sock", userSocket: true, config: ptr(`{}`), want: "/x/env.sock"},
		{name: "user socket over system", userSocket: true, config: ptr(`{}`), want: userSock},
		{name: "system default", config: ptr(`{"mode":"observe"}`), want: sysSock},
		{name: "system config socket", config: ptr(`{"socket":"/run/w/s.sock","state_dir":"/srv/w"}`), want: "/run/w/s.sock"},
		{name: "system config state_dir", config: ptr(`{"state_dir":"/srv/w"}`), want: "/srv/w/wardend.sock"},
		{name: "system config broken", config: ptr(`{"socket":`), want: sysSock},
		{name: "system config unreadable", config: ptr(`{"socket":"/run/w/s.sock"}`), unreadable: true, want: sysSock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home, etc, state := clientPathsEnv(t)
			t.Setenv(socketEnv, tc.env)
			if tc.userSocket {
				putFile(t, filepath.Join(home, ".wardend", "wardend.sock"), "")
			}
			if tc.config != nil {
				putFile(t, systemConfigPath, *tc.config)
			}
			if tc.unreadable {
				if os.Geteuid() == 0 {
					t.Skip("root reads everything")
				}
				os.Chmod(etc, 0)
				t.Cleanup(func() { os.Chmod(etc, 0o700) })
			}
			want := strings.NewReplacer("<home>", home, "<var>", state).Replace(tc.want)
			if got := clientSocket(tc.flag); got != want {
				t.Fatalf("clientSocket(%q) = %s, want %s", tc.flag, got, want)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestDefaultConfigPathOrder(t *testing.T) {
	home, _, _ := clientPathsEnv(t)
	user := filepath.Join(home, ".wardend", "config.json")
	if got := defaultConfigPath(); got != user {
		t.Fatalf("nothing installed: %s, want %s", got, user)
	}
	putFile(t, systemConfigPath, `{}`)
	if got := defaultConfigPath(); got != systemConfigPath {
		t.Fatalf("system install: %s, want %s", got, systemConfigPath)
	}
	putFile(t, user, `{}`)
	if got := defaultConfigPath(); got != user {
		t.Fatalf("both: %s, want %s", got, user)
	}
}

// The root socket of the system install: the error is the command to retype.
func TestDialErrorSudo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root connects to everything")
	}
	_, _, state := clientPathsEnv(t)
	putFile(t, systemConfigPath, `{}`)
	os.Chmod(state, 0)
	t.Cleanup(func() { os.Chmod(state, 0o700) })
	sock := clientSocket("")
	_, err := dialRPC(sock)
	if err == nil {
		t.Fatal("connected to a socket in a closed directory")
	}
	got := dialError(sock, err, []string{"pair", "approve", "p-1234"}).Error()
	if want := "run it with sudo: sudo wardend pair approve p-1234"; !strings.HasSuffix(got, want) || !strings.Contains(got, sock) {
		t.Fatalf("got %q, want the socket and %q", got, want)
	}
}

// No socket in either place: not running, and both places are named.
func TestDialErrorNotRunning(t *testing.T) {
	home, _, state := clientPathsEnv(t)
	user, system := filepath.Join(home, ".wardend", "wardend.sock"), filepath.Join(state, "wardend.sock")
	want := "wardend is not running: no socket at " + user + " or " + system
	for _, withSystem := range []bool{false, true} {
		if withSystem {
			putFile(t, systemConfigPath, `{}`)
		}
		sock := clientSocket("")
		_, err := dialRPC(sock)
		if err == nil {
			t.Fatal("connected to a missing socket")
		}
		if got := dialError(sock, err, []string{"status"}).Error(); got != want {
			t.Fatalf("system install %v: got %q, want %q", withSystem, got, want)
		}
	}
	// a socket named by hand keeps the plain wording with the path
	_, err := dialRPC("/nonexistent/w.sock")
	if got := dialError("/nonexistent/w.sock", err, nil).Error(); !strings.HasPrefix(got, "wardend is not running or the socket is wrong (/nonexistent/w.sock)") {
		t.Fatalf("explicit socket: %q", got)
	}
}
