package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The system install (install.sh, deploy/wardend.service): wardend runs as a root service with
// its config and state here. Variables, so that tests point them at a temp dir.
var (
	systemConfigPath = "/etc/wardend/config.json"
	systemStateDir   = "/var/lib/wardend"
)

// socketEnv names the supervisor socket for the client commands, below --socket.
const socketEnv = "WARDEND_SOCKET"

const socketName = "wardend.sock"

func userSocketPath() string { return filepath.Join(defaultStateDir(), socketName) }

// present: the file is there, or it is behind a directory this user may not look into.
func present(p string) bool {
	_, err := os.Stat(p)
	return err == nil || errors.Is(err, fs.ErrPermission)
}

// systemSocketPath: the socket of the system install, "" if there is none. The config names it
// (socket, else <state_dir>/wardend.sock); a config this user cannot read or that does not parse
// leaves the installer's location.
func systemSocketPath() string {
	if !present(systemConfigPath) {
		return ""
	}
	def := filepath.Join(systemStateDir, socketName)
	b, err := os.ReadFile(systemConfigPath)
	if err != nil {
		return def
	}
	var c struct {
		Socket   string `json:"socket"`
		StateDir string `json:"state_dir"`
	}
	if json.Unmarshal(b, &c) != nil {
		return def
	}
	if c.Socket != "" {
		return c.Socket
	}
	if c.StateDir != "" {
		return filepath.Join(c.StateDir, socketName)
	}
	return def
}

// clientSocket: the supervisor socket of a client command (status, journal, approve, pair):
// --socket, else $WARDEND_SOCKET, else this user's own wardend (~/.wardend/wardend.sock, if it
// exists), else the system install, else the per-user path again, for the error to name.
func clientSocket(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if s := os.Getenv(socketEnv); s != "" {
		return s
	}
	user := userSocketPath()
	if fileExists(user) {
		return user
	}
	if s := systemSocketPath(); s != "" {
		return s
	}
	return user
}

// defaultConfigPath: the config of the client commands that edit or read it (hw-register,
// hw-keys), in the order of clientSocket: this user's ~/.wardend/config.json if it exists, else
// the system install's, else the per-user path.
func defaultConfigPath() string {
	user := filepath.Join(defaultStateDir(), "config.json")
	if fileExists(user) {
		return user
	}
	if present(systemConfigPath) {
		return systemConfigPath
	}
	return user
}

// dialClient connects a client command to the supervisor socket; a failure comes back as
// something the owner can act on.
func dialClient(sock string) (*rpcClient, error) {
	c, err := dialRPC(sock)
	if err != nil {
		return nil, dialError(sock, err, os.Args[1:])
	}
	return c, nil
}

// dialError explains a failed connection: the root socket of the system install needs sudo, no
// socket in either place means wardend is not running. args is the command line after "wardend".
func dialError(sock string, err error, args []string) error {
	system := filepath.Join(systemStateDir, socketName)
	if s := systemSocketPath(); s != "" {
		system = s
	}
	user := userSocketPath()
	switch {
	case sock == system && errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("the wardend socket (%s) belongs to root; run it with sudo: sudo wardend %s", sock, strings.Join(args, " "))
	case (sock == system || sock == user) && errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("wardend is not running: no socket at %s or %s", user, system)
	}
	return fmt.Errorf("wardend is not running or the socket is wrong (%s): %v", sock, err)
}
