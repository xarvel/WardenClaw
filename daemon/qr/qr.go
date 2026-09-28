// SPDX-License-Identifier: AGPL-3.0-or-later

// Package qr is a minimal QR encoder (ISO/IEC 18004) for `wardend pair start`:
// byte mode, correction level M, versions 1..15 (up to 412 bytes), mask selection by penalty.
// No dependencies: the pairing URL is printed in the terminal using UTF-8 block characters.
package qr

import (
	"errors"
	"strings"
)

// Code holds the module matrix: Modules[y][x] == true means dark.
type Code struct {
	Version int
	Size    int
	Mask    int
	Modules [][]bool
}

// ErrTooLong is returned when data does not fit in version 15-M.
var ErrTooLong = errors.New("qr: data too long (max 412 bytes)")

const (
	maxVersion = 15
	numMasks   = 8
	modeByte   = 0b0100 // mode indicator of byte mode
	eccLevelM  = 0b00   // error correction level bits in the format information
)

// blockSpec is the level M block structure of a version: ec codewords per block, then
// {block count, data codewords per block} of group 1 and group 2.
type blockSpec struct{ ec, n1, d1, n2, d2 int }

var specM = [16]blockSpec{
	{},
	{10, 1, 16, 0, 0}, {16, 1, 28, 0, 0}, {26, 1, 44, 0, 0}, {18, 2, 32, 0, 0}, {24, 2, 43, 0, 0},
	{16, 4, 27, 0, 0}, {18, 4, 31, 0, 0}, {22, 2, 38, 2, 39}, {22, 3, 36, 2, 37}, {26, 4, 43, 1, 44},
	{30, 1, 50, 4, 51}, {22, 6, 36, 2, 37}, {22, 8, 37, 1, 38}, {24, 4, 40, 5, 41}, {24, 5, 41, 5, 42},
}

var alignPos = [16][]int{
	{}, {}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42}, {6, 26, 46},
	{6, 28, 50}, {6, 30, 54}, {6, 32, 58}, {6, 34, 62}, {6, 26, 46, 66}, {6, 26, 48, 70},
}

func (s blockSpec) dataLen() int { return s.n1*s.d1 + s.n2*s.d2 }

// Encode encodes bytes into the smallest fitting version.
func Encode(data []byte) (*Code, error) { return encode(data, -1) }

// encode encodes data with the given mask, or with the lowest-penalty mask if mask < 0 (tests
// force a mask).
func encode(data []byte, mask int) (*Code, error) {
	ver := 0
	for v := 1; v <= maxVersion; v++ {
		if 4+charCountBits(v)+8*len(data) <= specM[v].dataLen()*8 {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, ErrTooLong
	}
	cw := codewords(ver, data)
	var best *Code
	bestPen := -1
	for m := 0; m < numMasks; m++ {
		if mask >= 0 && m != mask {
			continue
		}
		c := newBuilder(ver)
		c.drawFunctionPatterns()
		c.drawData(cw)
		c.applyMask(m)
		c.drawFormat(m)
		c.Mask = m
		if p := c.penalty(); bestPen < 0 || p < bestPen {
			best, bestPen = c.Code, p
		}
	}
	return best, nil
}

// ---------- codewords ----------

type bitBuf struct {
	b []byte
	n int
}

func (w *bitBuf) put(v uint, bits int) {
	for i := bits - 1; i >= 0; i-- {
		if w.n%8 == 0 {
			w.b = append(w.b, 0)
		}
		if v>>uint(i)&1 == 1 {
			w.b[w.n/8] |= 0x80 >> uint(w.n%8)
		}
		w.n++
	}
}

// charCountBits is the width of the byte-mode character count field.
func charCountBits(ver int) int {
	if ver >= 10 {
		return 16
	}
	return 8
}

// codewords builds the data codewords (mode, count, data, terminator, padding), appends
// Reed-Solomon codewords per block and interleaves the blocks.
func codewords(ver int, data []byte) []byte {
	sp := specM[ver]
	capBits := sp.dataLen() * 8
	var w bitBuf
	w.put(modeByte, 4)
	w.put(uint(len(data)), charCountBits(ver))
	for _, b := range data {
		w.put(uint(b), 8)
	}
	w.put(0, min(4, capBits-w.n))
	if w.n%8 != 0 {
		w.put(0, 8-w.n%8)
	}
	for pad := byte(0xEC); len(w.b) < sp.dataLen(); pad ^= 0xEC ^ 0x11 {
		w.b = append(w.b, pad)
	}
	// blocks + Reed-Solomon, then interleaving
	var blocks, ecs [][]byte
	off := 0
	for i := 0; i < sp.n1+sp.n2; i++ {
		n := sp.d1
		if i >= sp.n1 {
			n = sp.d2
		}
		d := w.b[off : off+n]
		off += n
		blocks = append(blocks, d)
		ecs = append(ecs, rsRemainder(d, sp.ec))
	}
	var out []byte
	for i := 0; i < max(sp.d1, sp.d2); i++ {
		for _, b := range blocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := 0; i < sp.ec; i++ {
		for _, e := range ecs {
			out = append(out, e[i])
		}
	}
	return out
}

// gfMul multiplies in GF(256) with the primitive polynomial 0x11D.
func gfMul(x, y byte) byte {
	var z byte
	for i := 7; i >= 0; i-- {
		hi := z >> 7
		z = z<<1 ^ hi*0x1D
		if y>>uint(i)&1 == 1 {
			z ^= x
		}
	}
	return z
}

// rsRemainder returns the degree Reed-Solomon error correction codewords of data.
func rsRemainder(data []byte, degree int) []byte {
	// generator: product of (x - a^i) for i=0..degree-1; coefficients from MSB (without leading 1)
	gen := make([]byte, degree)
	gen[degree-1] = 1
	root := byte(1)
	for i := 0; i < degree; i++ {
		for j := 0; j < degree; j++ {
			gen[j] = gfMul(gen[j], root)
			if j+1 < degree {
				gen[j] ^= gen[j+1]
			}
		}
		root = gfMul(root, 0x02)
	}
	rem := make([]byte, degree)
	for _, b := range data {
		f := b ^ rem[0]
		copy(rem, rem[1:])
		rem[degree-1] = 0
		for j := range rem {
			rem[j] ^= gfMul(gen[j], f)
		}
	}
	return rem
}

// ---------- matrix ----------

type builder struct {
	*Code
	fn [][]bool // functional modules (mask not applied)
}

func newBuilder(ver int) *builder {
	size := 17 + 4*ver
	c := &Code{Version: ver, Size: size, Modules: make([][]bool, size)}
	fn := make([][]bool, size)
	for i := range c.Modules {
		c.Modules[i] = make([]bool, size)
		fn[i] = make([]bool, size)
	}
	return &builder{Code: c, fn: fn}
}

func (b *builder) set(x, y int, dark bool) {
	b.Modules[y][x] = dark
	b.fn[y][x] = true
}

// drawFunctionPatterns draws everything that is not data: timing, finder and alignment
// patterns, a placeholder format area and the version information.
func (b *builder) drawFunctionPatterns() {
	n := b.Size
	for i := 0; i < n; i++ { // timing
		b.set(6, i, i%2 == 0)
		b.set(i, 6, i%2 == 0)
	}
	b.finder(3, 3)
	b.finder(n-4, 3)
	b.finder(3, n-4)
	ap := alignPos[b.Version]
	for i, x := range ap {
		for j, y := range ap {
			if (i == 0 && j == 0) || (i == 0 && j == len(ap)-1) || (i == len(ap)-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					b.set(x+dx, y+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	b.drawFormat(0) // placeholder (will be redrawn with the real mask)
	if b.Version >= 7 {
		rem := b.Version
		for i := 0; i < 12; i++ {
			rem = rem<<1 ^ (rem>>11)*0x1F25
		}
		bits := b.Version<<12 | rem
		for i := 0; i < 18; i++ {
			dark := bits>>uint(i)&1 == 1
			a, c := n-11+i%3, i/3
			b.set(a, c, dark)
			b.set(c, a, dark)
		}
	}
}

func (b *builder) finder(cx, cy int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			x, y := cx+dx, cy+dy
			if x < 0 || y < 0 || x >= b.Size || y >= b.Size {
				continue
			}
			d := max(abs(dx), abs(dy))
			b.set(x, y, d != 2 && d != 4)
		}
	}
}

func (b *builder) drawFormat(mask int) {
	data := eccLevelM<<3 | mask
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return bits>>uint(i)&1 == 1 }
	for i := 0; i <= 5; i++ {
		b.set(8, i, bit(i))
	}
	b.set(8, 7, bit(6))
	b.set(8, 8, bit(7))
	b.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		b.set(14-i, 8, bit(i))
	}
	n := b.Size
	for i := 0; i < 8; i++ {
		b.set(n-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		b.set(8, n-15+i, bit(i))
	}
	b.set(8, n-8, true) // dark module
}

func (b *builder) drawData(cw []byte) {
	n := b.Size
	i := 0
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < n; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				upward := (right+1)&2 == 0
				y := vert
				if upward {
					y = n - 1 - vert
				}
				if !b.fn[y][x] && i < len(cw)*8 {
					b.Modules[y][x] = cw[i>>3]>>uint(7-i&7)&1 == 1
					i++
				}
			}
		}
	}
}

func maskBit(m, x, y int) bool {
	switch m {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	default:
		return ((x+y)%2+x*y%3)%2 == 0
	}
}

func (b *builder) applyMask(m int) {
	for y := 0; y < b.Size; y++ {
		for x := 0; x < b.Size; x++ {
			if !b.fn[y][x] && maskBit(m, x, y) {
				b.Modules[y][x] = !b.Modules[y][x]
			}
		}
	}
}

// penalty applies rules 1-4 of the standard (simplified 1:1:3:1:1 pattern search).
func (c *Code) penalty() int {
	n := c.Size
	at := func(x, y int, col bool) bool {
		if col {
			return c.Modules[x][y]
		}
		return c.Modules[y][x]
	}
	p := 0
	for _, col := range []bool{false, true} {
		for y := 0; y < n; y++ {
			run := 1
			for x := 1; x <= n; x++ {
				if x < n && at(x, y, col) == at(x-1, y, col) {
					run++
					continue
				}
				if run >= 5 {
					p += 3 + run - 5
				}
				run = 1
			}
			var line strings.Builder
			for x := 0; x < n; x++ {
				if at(x, y, col) {
					line.WriteByte('1')
				} else {
					line.WriteByte('0')
				}
			}
			s := "0000" + line.String() + "0000"
			p += 40 * (strings.Count(s, "10111010000") + strings.Count(s, "00001011101"))
		}
	}
	dark := 0
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if c.Modules[y][x] {
				dark++
			}
			if x+1 < n && y+1 < n {
				v := c.Modules[y][x]
				if c.Modules[y][x+1] == v && c.Modules[y+1][x] == v && c.Modules[y+1][x+1] == v {
					p += 3
				}
			}
		}
	}
	pct := dark * 100 / (n * n)
	p += 10 * (abs(pct-50) / 5)
	return p
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
