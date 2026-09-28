// SPDX-License-Identifier: AGPL-3.0-or-later

package qr

import "strings"

// Quiet is the quiet zone width per standard (modules).
const Quiet = 4

func (c *Code) dark(x, y int) bool {
	x, y = x-Quiet, y-Quiet
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return false
	}
	return c.Modules[y][x]
}

// halfBlocks renders two module rows per text line. glyph(top, bottom) returns the character.
func (c *Code) halfBlocks(glyph func(top, bottom bool) string, lineStart, lineEnd string) string {
	var b strings.Builder
	n := c.Size + 2*Quiet
	for y := 0; y < n; y += 2 {
		b.WriteString(lineStart)
		for x := 0; x < n; x++ {
			b.WriteString(glyph(c.dark(x, y), y+1 < n && c.dark(x, y+1)))
		}
		b.WriteString(lineEnd)
		b.WriteByte('\n')
	}
	return b.String()
}

func glyphOf(top, bottom bool) string {
	switch {
	case top && bottom:
		return "█"
	case top:
		return "▀"
	case bottom:
		return "▄"
	}
	return " "
}

// ANSI renders black modules on white background using escape color codes:
// readable by a camera regardless of the terminal theme.
func (c *Code) ANSI() string {
	return c.halfBlocks(glyphOf, "\x1b[30;47m", "\x1b[0m")
}

// UTF8 renders without color, dark modules as blocks (for a light background: file, print).
func (c *Code) UTF8() string { return c.halfBlocks(glyphOf, "", "") }

// UTF8Inverted renders without color for a dark terminal theme: light modules are drawn as blocks.
func (c *Code) UTF8Inverted() string {
	return c.halfBlocks(func(t, b bool) string { return glyphOf(!t, !b) }, "", "")
}
