// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import "strings"

const (
	shPunct  = ";&|()"
	shSpace  = " \t\r\n"
	shQuotes = `'"`
)

// shlexSplit states; inside quotes the state is the quote character itself.
const (
	stGap    = ' '  // between tokens
	stWord   = 'a'  // in a word
	stPunct  = 'c'  // in a run of punctuation characters
	stEscape = '\\' // after a backslash
)

// shlexSplit returns tokens like Python shlex.shlex(text, posix=True,
// punctuation_chars=";&|()") with whitespace_split=True: POSIX quoting and escaping,
// ;&|() sequences as separate tokens, # starts a comment to end of line.
// Needed for `adb shell ...` commands (a shell string on the phone): split into segments
// and check each command. Unclosed quote: ok=false.
func shlexSplit(s string) (toks []string, ok bool) {
	rs := []rune(s)
	pos := 0
	var pushback []rune
	next := func() (rune, bool) {
		if n := len(pushback); n > 0 {
			c := pushback[n-1]
			pushback = pushback[:n-1]
			return c, true
		}
		if pos >= len(rs) {
			return 0, false
		}
		c := rs[pos]
		pos++
		return c, true
	}
	skipLine := func() {
		for pos < len(rs) {
			c := rs[pos]
			pos++
			if c == '\n' {
				return
			}
		}
	}
	isIn := func(c rune, set string) bool { return strings.ContainsRune(set, c) }
	for {
		var tok strings.Builder
		quoted := false
		state := rune(stGap)
		escState := rune(stWord)
		eof := false
	loop:
		for {
			c, more := next()
			switch {
			case state == stGap:
				switch {
				case !more:
					eof = true
					break loop
				case isIn(c, shSpace):
					if tok.Len() > 0 || quoted {
						break loop
					}
				case c == '#':
					skipLine()
				case c == '\\':
					escState, state = stWord, stEscape
				case isIn(c, shPunct):
					tok.WriteRune(c)
					state = stPunct
				case isIn(c, shQuotes):
					state = c
				default:
					tok.WriteRune(c)
					state = stWord
				}
			case state == stWord || state == stPunct:
				switch {
				case !more:
					eof = true
					break loop
				case isIn(c, shSpace):
					state = stGap
					if tok.Len() > 0 || quoted {
						break loop
					}
				case c == '#':
					skipLine()
					state = stGap
					if tok.Len() > 0 || quoted {
						break loop
					}
				case state == stPunct:
					if isIn(c, shPunct) {
						tok.WriteRune(c)
					} else {
						if !isIn(c, shSpace) {
							pushback = append(pushback, c)
						}
						state = stGap
						break loop
					}
				case isIn(c, shQuotes):
					state = c
				case c == '\\':
					escState, state = stWord, stEscape
				case !isIn(c, shPunct):
					tok.WriteRune(c)
				default:
					pushback = append(pushback, c)
					state = stGap
					if tok.Len() > 0 || quoted {
						break loop
					}
				}
			case state == '\'' || state == '"':
				quoted = true
				switch {
				case !more:
					return nil, false // No closing quotation
				case c == state:
					state = stWord
				case c == '\\' && state == '"':
					escState, state = state, stEscape
				default:
					tok.WriteRune(c)
				}
			case state == stEscape:
				if !more {
					return nil, false // No escaped character
				}
				if (escState == '\'' || escState == '"') && c != state && c != escState {
					tok.WriteRune(state)
				}
				tok.WriteRune(c)
				state = escState
			}
		}
		if tok.Len() > 0 || quoted {
			toks = append(toks, tok.String())
		}
		if eof {
			return toks, true
		}
	}
}
