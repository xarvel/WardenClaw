// SPDX-License-Identifier: AGPL-3.0-or-later

package qr

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionsAndStructure(t *testing.T) {
	for _, tc := range []struct{ n, ver int }{{1, 1}, {14, 1}, {15, 2}, {26, 2}, {27, 3}, {150, 8}, {180, 9}, {181, 10}, {412, 15}} {
		c, err := Encode(bytes.Repeat([]byte{'a'}, tc.n))
		if err != nil {
			t.Fatal(tc, err)
		}
		if c.Version != tc.ver || c.Size != 17+4*tc.ver {
			t.Fatalf("%d bytes: version %d size %d, want %d", tc.n, c.Version, c.Size, tc.ver)
		}
		// finders: center dark, separator light; timing alternates
		for _, p := range [][2]int{{3, 3}, {c.Size - 4, 3}, {3, c.Size - 4}} {
			if !c.Modules[p[1]][p[0]] {
				t.Fatalf("finder center %v light", p)
			}
		}
		if c.Modules[7][7] || !c.Modules[c.Size-8][8] {
			t.Fatal("separator/dark module")
		}
		for i := 8; i < c.Size-8; i++ {
			if c.Modules[6][i] != (i%2 == 0) || c.Modules[i][6] != (i%2 == 0) {
				t.Fatalf("timing at %d", i)
			}
		}
	}
	if _, err := Encode(make([]byte, 413)); err != ErrTooLong {
		t.Fatal("413 bytes must not fit")
	}
}

func TestRenderRoundTrip(t *testing.T) {
	c, _ := Encode([]byte("wardenclaw://pair?v=1"))
	lines := strings.Split(strings.TrimRight(c.UTF8(), "\n"), "\n")
	n := c.Size + 2*Quiet
	if len(lines) != (n+1)/2 {
		t.Fatalf("lines %d", len(lines))
	}
	for y, l := range lines {
		r := []rune(l)
		if len(r) != n {
			t.Fatalf("line %d: %d runes", y, len(r))
		}
		for x, ch := range r {
			top, bot := c.dark(x, 2*y), c.dark(x, 2*y+1)
			if string(ch) != glyphOf(top, bot) {
				t.Fatalf("glyph %d,%d", x, y)
			}
		}
	}
	if !strings.HasPrefix(c.ANSI(), "\x1b[30;47m") || strings.Contains(c.UTF8Inverted(), "\x1b") {
		t.Fatal("ansi/inverted")
	}
}

// External verification with a real decoder (zxing-cpp):
//
//	WARDEND_QR_DECODER=/path/to/python-with-zxingcpp go test ./qr -run Decode
func TestDecodeWithZXing(t *testing.T) {
	py := os.Getenv("WARDEND_QR_DECODER")
	if py == "" {
		t.Skip("WARDEND_QR_DECODER not set")
	}
	dir := t.TempDir()
	var want []string
	for i, n := range []int{1, 10, 20, 40, 60, 80, 100, 120, 150, 180, 200, 230, 260, 300, 350, 412} {
		var s strings.Builder
		s.WriteString("wardenclaw://pair?v=1&code=")
		for s.Len() < n {
			fmt.Fprintf(&s, "%x", s.Len()*7919%16)
		}
		data := s.String()[:n]
		c, err := Encode([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		writePNG(t, filepath.Join(dir, fmt.Sprintf("%02d.png", i)), c)
		want = append(want, data)
	}
	for m := 0; m < 8; m++ { // each mask separately (penalty selection might not have picked some)
		data := fmt.Sprintf("wardenclaw://pair?mask=%d&pad=%s", m, strings.Repeat("x", 30*m))
		c, _ := encode([]byte(data), m)
		writePNG(t, filepath.Join(dir, fmt.Sprintf("m%d.png", m)), c)
		want = append(want, data)
	}
	script := `import sys, glob, zxingcpp
from PIL import Image
for f in sorted(glob.glob(sys.argv[1] + "/*.png")):
    r = zxingcpp.read_barcodes(Image.open(f))
    print(r[0].text if r else "<none>")`
	out, err := exec.Command(py, "-c", script, dir).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(got) != len(want) {
		t.Fatalf("got %d results: %s", len(got), out)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("#%d (%d bytes): decoded %q", i, len(want[i]), got[i])
		}
	}
}

func writePNG(t *testing.T, path string, c *Code) {
	const scale = 6
	n := (c.Size + 2*Quiet) * scale
	img := image.NewGray(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			v := uint8(255)
			if c.dark(x/scale, y/scale) {
				v = 0
			}
			img.SetGray(x, y, color.Gray{v})
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	png.Encode(f, img)
}
