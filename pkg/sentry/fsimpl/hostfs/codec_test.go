// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostfs

import (
	"errors"
	"math/rand/v2"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// foldingSet models the entries of one directory on a volume that folds case.
type foldingSet map[string]struct{}

func (s foldingSet) exists(host string) bool {
	_, ok := s[foldKey(host, false)]
	return ok
}

func (s foldingSet) add(host string) { s[foldKey(host, false)] = struct{}{} }

func TestNameCodecToHostTable(t *testing.T) {
	tests := []struct {
		name  string
		caps  WorkspaceCaps
		guest string
		want  string
	}{
		{"linux plain", linuxCaps, "main.go", "main.go"},
		{"linux reserved name", linuxCaps, "aux.c", "aux.c"},
		{"linux prefix", linuxCaps, "~gvx~literal", "~gvx~literal"},
		{"linux colon", linuxCaps, "Net::HTTP.3pm", "Net::HTTP.3pm"},
		{"linux invalid UTF-8", linuxCaps, "a\xffb", "a\xffb"},
		{"windows plain", winCaps, "main.go", "main.go"},
		{"windows reserved with extension", winCaps, "aux.c", "~gvx~aux.c"},
		{"windows reserved upper case", winCaps, "CON", "~gvx~CON"},
		{"windows com port", winCaps, "com1", "~gvx~com1"},
		{"windows lpt with extension", winCaps, "LPT9.txt", "~gvx~LPT9.txt"},
		{"windows nul with space", winCaps, "nul .txt", "~gvx~nul .txt"},
		{"windows not a device", winCaps, "console", "console"},
		{"windows com10 is not a device", winCaps, "com10", "com10"},
		{"windows colons", winCaps, "Net::HTTP.3pm", "~gvx~Net%3A%3AHTTP.3pm"},
		{"windows every forbidden byte", winCaps, "a*b?c\"d<e>f|g\\h", "~gvx~a%2Ab%3Fc%22d%3Ce%3Ef%7Cg%5Ch"},
		{"windows control byte", winCaps, "a\x01b", "~gvx~a%01b"},
		{"windows percent alone stays", winCaps, "100%", "100%"},
		{"windows percent in an escaped name", winCaps, "a%:", "~gvx~a%25%3A"},
		{"windows trailing dot", winCaps, "name.", "~gvx~name%2E"},
		{"windows trailing space", winCaps, "name ", "~gvx~name%20"},
		{"windows leading dot", winCaps, ".hidden", ".hidden"},
		{"windows literal prefix", winCaps, "~gvx~literal", "~gvx~~gvx~literal"},
		{"windows literal prefix with percent", winCaps, "~gvx~100%", "~gvx~~gvx~100%25"},
		{"windows invalid UTF-8", winCaps, "a\xffb", "~gvx~a%FFb"},
		{"windows tmp guard", winCaps, "tmp.x:", "~gvx~%74mp.x%3A"},
		{"windows case-sensitive keeps the case", winCSCaps, "Net::HTTP.3pm", "~gvx~Net%3A%3AHTTP.3pm"},
		{"mac plain", macCaps, "Readme.md", "Readme.md"},
		{"mac colon", macCaps, "a:b", "a:b"},
		{"mac reserved name", macCaps, "aux.c", "aux.c"},
		{"mac literal prefix", macCaps, "~gvx~literal", "~gvx~~gvx~literal"},
		{"mac invalid UTF-8", macCaps, "a\xffb", "~gvx~a%FFb"},
		{"mac trailing dot", macCaps, "name.", "name."},
		{"apfs case-sensitive literal prefix", apfsCSCaps, "~gvx~literal", "~gvx~~gvx~literal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newNameCodec(tc.caps)
			got, err := c.ToHost(tc.guest, nil)
			if err != nil {
				t.Fatalf("ToHost(%q) = %v", tc.guest, err)
			}
			if got != tc.want {
				t.Fatalf("ToHost(%q) = %q, want %q", tc.guest, got, tc.want)
			}
			if back := c.ToGuest(got); back != tc.guest {
				t.Fatalf("ToGuest(%q) = %q, want %q", got, back, tc.guest)
			}
		})
	}
}

func TestNameCodecCaseCollisionTable(t *testing.T) {
	// The spec table: the first name stays plain, and later case variants
	// become escaped names. A name occupies its slot for every later name.
	c := newNameCodec(winCaps)
	stored := foldingSet{}
	steps := []struct{ guest, want string }{
		{"Readme.md", "Readme.md"},
		{"readme.md", "~gvx~readme.md"},
		{"README.md", "~gvx~%52%45%41%44%4D%45.md"},
		{"ReadMe.md", "~gvx~%52ead%4De.md"},
	}
	for _, s := range steps {
		got, err := c.ToHost(s.guest, stored.exists)
		if err != nil {
			t.Fatalf("ToHost(%q) = %v", s.guest, err)
		}
		if got != s.want {
			t.Fatalf("ToHost(%q) = %q, want %q", s.guest, got, s.want)
		}
		if back := c.ToGuest(got); back != s.guest {
			t.Fatalf("ToGuest(%q) = %q, want %q", got, back, s.guest)
		}
		stored.add(got)
	}

	// A third level exists for names whose escaped form with only upper-case
	// letters escaped collides: two restricted names that differ in case.
	stored = foldingSet{}
	first, _ := c.ToHost("Net::HTTP.3pm", stored.exists)
	stored.add(first)
	second, err := c.ToHost("net::http.3pm", stored.exists)
	if err != nil {
		t.Fatal(err)
	}
	if first != "~gvx~Net%3A%3AHTTP.3pm" || second != "~gvx~%6E%65%74%3A%3A%68%74%74%70.3%70%6D" {
		t.Fatalf("restricted case variants = %q, %q", first, second)
	}
	if c.ToGuest(second) != "net::http.3pm" {
		t.Fatalf("ToGuest(%q) = %q", second, c.ToGuest(second))
	}

	// A volume that keeps case needs no collision form.
	cs := newNameCodec(winCSCaps)
	got, _ := cs.ToHost("readme.md", func(string) bool { return true })
	if got != "readme.md" {
		t.Fatalf("case-sensitive volume ToHost = %q, want the plain name", got)
	}
}

func TestNameCodecToGuestTable(t *testing.T) {
	win := newNameCodec(winCaps)
	linux := newNameCodec(linuxCaps)
	tests := []struct {
		host      string
		codec     NameCodec
		want      string
		canonical bool
	}{
		{"main.go", win, "main.go", true},
		{"~gvx~aux.c", win, "aux.c", true},
		{"~gvx~~gvx~literal", win, "~gvx~literal", true},
		{"~gvx~%52%45%41%44%4D%45.md", win, "README.md", true},
		// The prefix with a plain name is form 1 on a volume that folds case.
		{"~gvx~notes", win, "notes", true},
		// Another tool wrote these names. A plain name never needs the prefix
		// on a volume that keeps case, and a lower-case escape is no grammar.
		{"~gvx~notes", newNameCodec(winCSCaps), "notes", false},
		{"~gvx~%4d", win, "~gvx~%4d", false},
		{"~gvx~%4", win, "~gvx~%4", false},
		{"~gvx~%ZZ", win, "~gvx~%ZZ", false},
		{"~gvx~100%", win, "~gvx~100%", false},
		{"~gvx~", win, "~gvx~", false},
		{"~gvx~%2F", win, "~gvx~%2F", false},
		{"~gvx~%00", win, "~gvx~%00", false},
		// A listing never shows the internal names.
		{"~gvx~tmp.1", win, "tmp.1", false},
		{"~gvx~swap.1", win, "swap.1", false},
		{"~gvx~foo", linux, "~gvx~foo", true},
		{"~gvx~%41", linux, "~gvx~%41", true},
	}
	for _, tc := range tests {
		if got := tc.codec.ToGuest(tc.host); got != tc.want {
			t.Errorf("ToGuest(%q) = %q, want %q", tc.host, got, tc.want)
		}
		if tc.codec.active {
			if _, ok := tc.codec.canonicalGuest(tc.host); ok != tc.canonical {
				t.Errorf("canonicalGuest(%q) = %v, want %v", tc.host, ok, tc.canonical)
			}
		}
	}
}

func TestNameCodecLengthLimit(t *testing.T) {
	win := newNameCodec(winCaps)
	mac := newNameCodec(macCaps)
	linux := newNameCodec(linuxCaps)
	tests := []struct {
		name  string
		codec NameCodec
		guest string
		fails bool
	}{
		{"windows 255 units", win, strings.Repeat("a", 255), false},
		{"windows 256 units", win, strings.Repeat("a", 256), true},
		{"windows escape growth", win, strings.Repeat(":", 90), true},
		{"windows escape fits", win, strings.Repeat(":", 70), false},
		{"windows 127 astral runes", win, strings.Repeat("\U0001F600", 127), false},
		{"windows 128 astral runes", win, strings.Repeat("\U0001F600", 128), true},
		{"mac 255 bytes", mac, strings.Repeat("a", 255), false},
		{"mac 128 two-byte runes", mac, strings.Repeat("\u00e9", 128), true},
		{"mac prefix pushes over", mac, "~gvx~" + strings.Repeat("a", 251), true},
		{"linux has no codec limit", linux, strings.Repeat("a", 300), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.codec.ToHost(tc.guest, nil)
			if tc.fails != (err != nil) {
				t.Fatalf("ToHost error = %v, want failure %v", err, tc.fails)
			}
			if tc.fails {
				if !errors.Is(err, errNameTooLong) {
					t.Fatalf("ToHost error = %v, want errNameTooLong", err)
				}
				if got := translateHostError(err); !linuxerr.Equals(linuxerr.ENAMETOOLONG, got) {
					t.Fatalf("translateHostError = %v, want ENAMETOOLONG", got)
				}
			}
		})
	}
}

func TestNameCodecRejectsNamesThatNeverExist(t *testing.T) {
	for _, guest := range []string{"", ".", "..", "a/b", "a\x00b"} {
		if _, err := newNameCodec(winCaps).ToHost(guest, nil); !errors.Is(err, errInvalidHostName) {
			t.Errorf("ToHost(%q) = %v, want errInvalidHostName", guest, err)
		}
	}
}

// codecConfigs lists the volumes that the property tests cover.
var codecConfigs = map[string]WorkspaceCaps{
	"linux":   linuxCaps,
	"mac":     macCaps,
	"windows": winCaps,
	"win-cs":  winCSCaps,
	"apfs-cs": apfsCSCaps,
}

// randomGuestNames returns deterministic names that stress the grammar.
func randomGuestNames(n int) []string {
	r := rand.New(rand.NewPCG(7, 11))
	alphabet := []string{
		"a", "A", "b", "B", "k", "K", "\u212a", "s", "S", "\u017f", "\u00df", "\u1e9e", "\u01c5", "\u01c6", "\u00e9", "e\u0301",
		".", " ", ":", "*", "?", "\"", "<", ">", "|", "\\", "%", "%4", "%41", "~", "~gvx~", "~gvx~tmp.", "tmp.", "swap.",
		"\x01", "\x7f", "\xff", "\xc3", "\U0001F600", "aux", "com1", "nul", "-", "_", "0", "9",
	}
	seen := map[string]struct{}{}
	var out []string
	for len(out) < n {
		var b strings.Builder
		for range 1 + r.IntN(7) {
			b.WriteString(alphabet[r.IntN(len(alphabet))])
		}
		s := b.String()
		if !validGuestName(s) {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	// Names with a fixed shape that the table tests name.
	return append(out, "aux.c", "Net::HTTP.3pm", "Readme.md", "readme.md", "README.md", "~gvx~literal", "CON", "COM9.x", "LPT1")
}

func TestNameCodecBijection(t *testing.T) {
	names := randomGuestNames(4000)
	for cfgName, caps := range codecConfigs {
		t.Run(cfgName, func(t *testing.T) {
			c := newNameCodec(caps)
			byHost := map[string]string{}
			for _, g := range names {
				h, err := c.ToHost(g, nil)
				if err != nil {
					if !errors.Is(err, errNameTooLong) {
						t.Fatalf("ToHost(%q) = %v", g, err)
					}
					continue
				}
				if back := c.ToGuest(h); back != g {
					t.Fatalf("ToGuest(ToHost(%q)) = %q (host %q)", g, back, h)
				}
				if other, dup := byHost[h]; dup {
					t.Fatalf("ToHost is not injective: %q and %q both map to %q", other, g, h)
				}
				byHost[h] = g
				if c.active {
					if gg, ok := c.canonicalGuest(h); !ok || gg != g {
						t.Fatalf("canonicalGuest(%q) = (%q, %v), want (%q, true)", h, gg, ok, g)
					}
				}
			}
		})
	}
}

// TestNameCodecCoexistenceOnFoldingVolume inserts many names in random order
// into a directory that folds case. Every stored name must differ from the
// others under case folding, and each must decode to its guest name.
func TestNameCodecCoexistenceOnFoldingVolume(t *testing.T) {
	names := randomGuestNames(1500)
	for _, cfgName := range []string{"windows", "mac"} {
		t.Run(cfgName, func(t *testing.T) {
			caps := codecConfigs[cfgName]
			done := map[string]bool{}
			c := newNameCodec(caps)
			fold := func(s string) string { return foldKey(s, caps.UnicodeNormalized) }
			stored := map[string]string{} // fold key to guest name
			exists := func(host string) bool { _, ok := stored[fold(host)]; return ok }
			// Insert each base name with every case variant of its first letters.
			for _, base := range names[:200] {
				for _, g := range []string{base, strings.ToUpper(base), strings.ToLower(base), strings.ToUpper(base[:1]) + base[1:]} {
					if done[g] {
						continue
					}
					done[g] = true
					h, err := c.ToHost(g, exists)
					if err != nil {
						continue
					}
					if c.ToGuest(h) != g {
						t.Fatalf("ToGuest(ToHost(%q)) = %q", g, c.ToGuest(h))
					}
					if prev, dup := stored[fold(h)]; dup {
						t.Fatalf("%q and %q fold to the same host name %q", prev, g, h)
					}
					stored[fold(h)] = g
				}
			}
		})
	}
}

func TestNameCodecLinuxIsAllocationFree(t *testing.T) {
	c := newNameCodec(linuxCaps)
	if c.active {
		t.Fatal("the Linux codec must be the identity")
	}
	allocs := testing.AllocsPerRun(200, func() {
		h, _ := c.ToHost("~gvx~aux.c:literal%", nil)
		_ = c.ToGuest(h)
	})
	if allocs != 0 {
		t.Fatalf("the Linux codec allocates %v times per call, want 0", allocs)
	}

	plain := newNameCodec(winCaps)
	allocs = testing.AllocsPerRun(200, func() {
		h, _ := plain.ToHost("main.go", nil)
		_ = plain.ToGuest(h)
	})
	if allocs != 0 {
		t.Fatalf("a plain name on a translating codec allocates %v times per call, want 0", allocs)
	}
}

func TestFoldKey(t *testing.T) {
	tests := []struct {
		a, b string
		norm bool
		same bool
	}{
		{"Readme.md", "README.MD", false, true},
		{"readme", "readmf", false, false},
		{"\u212a", "k", false, true},
		{"\u017f", "S", false, true},
		{"\u00df", "\u1e9e", false, true},
		{"\u00e9", "e\u0301", false, false},
		{"\u00e9", "e\u0301", true, true},
		{"\u00c9", "e\u0301", true, true},
		{"a.txt", "a.txt", false, true},
	}
	for _, tc := range tests {
		if got := foldKey(tc.a, tc.norm) == foldKey(tc.b, tc.norm); got != tc.same {
			t.Errorf("foldKey(%q) == foldKey(%q) (normalize %v) = %v, want %v", tc.a, tc.b, tc.norm, got, tc.same)
		}
	}
}
