// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

import (
	"strings"
	"unicode/utf8"
)

// EnvVar is an environment variable in the envelope: name and value; Cut is the number of
// code points trimmed from the value (0 means the full value is included).
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Cut   int    `json:"cut,omitempty"`
}

// EnvValueMax is the maximum number of code points from a value included in the envelope;
// the rest is trimmed and the count of trimmed code points is written to cut
// (the envelope still covers the full environment via envHash).
const EnvValueMax = 1024

// Variables that affect the behavior of the launched program: loader, shell startup files,
// interpreter paths and options, config files and directories, pager and editor,
// proxy and root certificates. Comparison uses uppercase ASCII names (npm_config_*,
// https_proxy). The list is not exhaustive: the rest of the environment is covered only
// by envHash.
var (
	envExact = map[string]bool{
		"BASH_ENV": true, "ENV": true, "SHELLOPTS": true, "BASHOPTS": true, "PS4": true, "PROMPT_COMMAND": true,
		"ZDOTDIR": true, "SHELL": true, "PAGER": true, "MANPAGER": true, "EDITOR": true, "VISUAL": true,
		"BROWSER": true, "GLIBC_TUNABLES": true, "HOSTALIASES": true, "LOCALDOMAIN": true, "MAKEFILES": true,
		"CC": true, "CXX": true, "CPP": true, "LESSOPEN": true, "LESSCLOSE": true, "RUSTC": true,
		"RUSTC_WRAPPER": true, "DOCKER_HOST": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
	}
	envPrefixes = []string{"LD_", "DYLD_", "GIT_", "BASH_FUNC_", "PYTHON", "PIP_", "NODE_", "NPM_CONFIG_", "YARN_",
		"PERL", "RUBY", "BUNDLE_", "GEM_", "LUA_", "CARGO_", "GO", "CGO_", "DOCKER_", "KUBE"}
	envSuffixes = []string{"PATH", "HOME", "CONFIG", "RC", "_OPTIONS", "_OPTS", "FLAGS", "_PROXY", "ASKPASS", "_CA_BUNDLE"}
	// secret-like names: value does not leave the host (covered by envHash)
	envSecret = []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE_KEY", "API_KEY", "APIKEY",
		"ACCESS_KEY", "COOKIE", "AUTH_CONFIG"}
)

// LoaderNames are loader variables that cause the approved process to execute foreign code
// (always shown on the card, tripwire category "loader-env").
var LoaderNames = []string{"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}

// EnvShown reports whether a variable with the given name is included in the envelope.
func EnvShown(name string) bool {
	u := asciiUpper(name)
	for _, s := range envSecret {
		if strings.Contains(u, s) {
			return false
		}
	}
	if strings.HasSuffix(u, "_AUTH") {
		return false
	}
	if envExact[u] {
		return true
	}
	for _, p := range envPrefixes {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	for _, s := range envSuffixes {
		if strings.HasSuffix(u, s) {
			return true
		}
	}
	return false
}

// SelectEnv returns the envp variables for the envelope: in envp order, duplicate names are
// preserved, entries without "=" are skipped. Values longer than EnvValueMax code points are
// trimmed (Cut > 0). Non-UTF-8 is kept as-is: such an envelope cannot be built
// (Canonical returns an error).
func SelectEnv(envp []string) []EnvVar {
	out := []EnvVar{}
	for _, kv := range envp {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || name == "" || !EnvShown(name) {
			continue
		}
		v := EnvVar{Name: name, Value: value}
		if utf8.ValidString(value) {
			v.Value, v.Cut = truncateRunes(value, EnvValueMax)
		}
		out = append(out, v)
	}
	return out
}

// truncateRunes keeps the first limit code points of a valid UTF-8 string and returns how many
// code points were dropped.
func truncateRunes(s string, limit int) (string, int) {
	n := utf8.RuneCountInString(s)
	if n <= limit {
		return s, 0
	}
	end := 0
	for i := 0; i < limit; i++ {
		_, size := utf8.DecodeRuneInString(s[end:])
		end += size
	}
	return s[:end], n - limit
}

// LoaderVars returns distinct loader variable names with non-empty values, in order of appearance.
func LoaderVars(env []EnvVar) []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range env {
		if e.Value == "" || seen[e.Name] {
			continue
		}
		for _, n := range LoaderNames {
			if e.Name == n {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}

// asciiUpper uppercases ASCII letters only and leaves other bytes as they are.
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
