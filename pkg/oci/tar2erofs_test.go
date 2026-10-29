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

package oci

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

func patternBytes(n int, seed int64) []byte {
	var key [32]byte
	binary.LittleEndian.PutUint64(key[:], uint64(seed))
	b := make([]byte, n)
	rand.NewChaCha8(key).Read(b)
	return b
}

func TestCompileRoundTripsEveryEntryType(t *testing.T) {
	big := patternBytes(3*testBlockSize+123, 1)
	long := strings.Repeat("l", 3000)
	longName := strings.Repeat("n", 255)

	entries := []tarEntry{
		dirEntry("./"),
		dirEntry("etc/"),
		dirEntry("usr/include/linux/netfilter/"),
		fileEntry("etc/empty", ""),
		fileEntry("etc/one", "x"),
		fileEntry("etc/exact", string(patternBytes(testBlockSize, 2))),
		fileEntry("etc/just-over", string(patternBytes(testBlockSize+1, 3))),
		fileEntry("etc/big", string(big)),
		fileEntry("etc/near-full-tail", string(patternBytes(testBlockSize-80, 4))),
		fileEntry("usr/include/linux/netfilter/xt_CONNMARK.h", "upper"),
		fileEntry("usr/include/linux/netfilter/xt_connmark.h", "lower"),
		fileEntry("etc/CON", "reserved"),
		fileEntry("etc/AUX", "reserved"),
		fileEntry("etc/a:b", "colon"),
		fileEntry("etc/back\\slash", "backslash"),
		fileEntry("etc/"+longName, "long name"),
		fileEntry("etc/\u00e9\u4e16\u754c", "unicode"),
		symlinkEntry("etc/short-link", "one"),
		symlinkEntry("etc/long-link", long),
		linkEntry("etc/hard-one", "etc/one"),
		linkEntry("etc/hard-one-b", "./etc/one"),
		deviceEntry("etc/null", tar.TypeChar, 1, 3),
		deviceEntry("etc/loop0", tar.TypeBlock, 7, 0),
		deviceEntry("etc/bigdev", tar.TypeChar, 4095, 1048575),
		{hdr: tar.Header{Name: "etc/fifo", Typeflag: tar.TypeFifo, Mode: 0o600, ModTime: epoch}},
		{hdr: tar.Header{Name: "etc/setuid", Typeflag: tar.TypeReg, Mode: 0o4755, Uid: 1000, Gid: 2000, Size: 2, ModTime: epoch}, data: []byte("su")},
		{hdr: tar.Header{Name: "etc/mode-zero", Typeflag: tar.TypeReg, Mode: 0, Size: 1, ModTime: epoch}, data: []byte("0")},
		{hdr: tar.Header{Name: "etc/ping", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1, ModTime: epoch,
			PAXRecords: map[string]string{
				"SCHILY.xattr.security.capability": "\x01\x00\x00\x02",
				"SCHILY.xattr.user.comment":        "hi",
			}}, data: []byte("p")},
	}
	// Names that sort before "." must survive in a directory that also has
	// "." and "..".
	for _, name := range []string{"!bang", "#hash", "+plus", "-minus", " space"} {
		entries = append(entries, fileEntry("etc/"+name, name))
	}
	// A directory that spans several 4 KiB blocks.
	for i := range 1500 {
		entries = append(entries, fileEntry(fmt.Sprintf("etc/many/file-%04d", i), "v"))
	}

	p, stats := compileTar(t, buildTar(t, entries...))
	tree := readImage(t, p)

	if stats.TotalBytes%testBlockSize != 0 || stats.InodeCount != uint64(len(tree)-hardlinkAliases(tree)) {
		t.Errorf("stats = %+v, tree has %d paths", stats, len(tree))
	}

	wantFiles := map[string]string{
		"/etc/empty": "", "/etc/one": "x", "/etc/exact": string(patternBytes(testBlockSize, 2)),
		"/etc/just-over": string(patternBytes(testBlockSize+1, 3)), "/etc/big": string(big),
		"/etc/near-full-tail":                        string(patternBytes(testBlockSize-80, 4)),
		"/usr/include/linux/netfilter/xt_CONNMARK.h": "upper",
		"/usr/include/linux/netfilter/xt_connmark.h": "lower",
		"/etc/CON": "reserved", "/etc/AUX": "reserved", "/etc/a:b": "colon",
		"/etc/back\\slash": "backslash", "/etc/" + longName: "long name",
		"/etc/\u00e9\u4e16\u754c": "unicode", "/etc/hard-one": "x", "/etc/hard-one-b": "x",
		"/etc/!bang": "!bang", "/etc/#hash": "#hash", "/etc/+plus": "+plus",
		"/etc/-minus": "-minus", "/etc/ space": " space",
	}
	for p, want := range wantFiles {
		n, ok := tree[p]
		if !ok {
			t.Errorf("%q is missing", p)
			continue
		}
		if string(n.content) != want {
			t.Errorf("%q content differs (got %d bytes, want %d)", p, len(n.content), len(want))
		}
	}

	if n := tree["/etc/short-link"]; n.target != "one" || n.mode != linux.S_IFLNK|0o777 {
		t.Errorf("short link = %q mode %o", n.target, n.mode)
	}
	if n := tree["/etc/long-link"]; n.target != long {
		t.Errorf("long link has %d bytes, want %d", len(n.target), len(long))
	}

	one, hard, hardB := tree["/etc/one"], tree["/etc/hard-one"], tree["/etc/hard-one-b"]
	if one.nid != hard.nid || one.nid != hardB.nid || one.nlink != 3 {
		t.Errorf("hardlinks: nids %d %d %d, nlink %d; want one inode with nlink 3", one.nid, hard.nid, hardB.nid, one.nlink)
	}

	if n := tree["/etc/null"]; n.mode != linux.S_IFCHR|0o600 || n.major != 1 || n.minor != 3 {
		t.Errorf("char device = mode %o %d:%d", n.mode, n.major, n.minor)
	}
	if n := tree["/etc/loop0"]; n.mode != linux.S_IFBLK|0o600 || n.major != 7 || n.minor != 0 {
		t.Errorf("block device = mode %o %d:%d", n.mode, n.major, n.minor)
	}
	if n := tree["/etc/bigdev"]; n.major != 4095 || n.minor != 1048575 {
		t.Errorf("largest device = %d:%d", n.major, n.minor)
	}
	if n := tree["/etc/fifo"]; n.mode != linux.S_IFIFO|0o600 {
		t.Errorf("fifo mode = %o", n.mode)
	}
	if n := tree["/etc/setuid"]; n.mode != linux.S_IFREG|0o4755 || n.uid != 1000 || n.gid != 2000 {
		t.Errorf("setuid file = mode %o owner %d:%d", n.mode, n.uid, n.gid)
	}
	if n := tree["/etc/mode-zero"]; n.mode != linux.S_IFREG {
		t.Errorf("mode 0 file = %o, want the zero permission bits kept", n.mode)
	}
	if n := tree["/etc/ping"]; n.xattrs["security.capability"] != "\x01\x00\x00\x02" || n.xattrs["user.comment"] != "hi" || len(n.xattrs) != 2 {
		t.Errorf("ping xattrs = %q", n.xattrs)
	}

	many := tree["/etc/many"]
	if len(many.children) != 1500 || !slices.IsSorted(many.children) {
		t.Errorf("many has %d children, sorted=%v", len(many.children), slices.IsSorted(many.children))
	}
	if len(many.children) > 0 && many.size <= testBlockSize {
		t.Errorf("many directory size %d does not span blocks", many.size)
	}
	if n := tree["/etc"]; n.nlink != 3 {
		t.Errorf("/etc nlink = %d, want 2 plus one subdirectory", n.nlink)
	}
}

func hardlinkAliases(tree map[string]*node) int {
	seen := make(map[uint64]bool)
	aliases := 0
	for _, n := range tree {
		if n.isDir() {
			continue
		}
		if seen[n.nid] {
			aliases++
		}
		seen[n.nid] = true
	}
	return aliases
}

func TestCompileKeepsObservableTreeIndependentOfEntryOrder(t *testing.T) {
	a := []tarEntry{
		dirEntry("d/"), fileEntry("d/!first", "1"), fileEntry("d/.wh..wh..opq", ""),
		fileEntry("d/.wh.gone", ""), fileEntry("d/zzz", "z"),
	}
	b := []tarEntry{
		dirEntry("d/"), fileEntry("d/.wh.gone", ""), fileEntry("d/zzz", "z"),
		fileEntry("d/.wh..wh..opq", ""), fileEntry("d/!first", "1"),
	}
	pa, sa := compileTar(t, buildTar(t, a...))
	pb, sb := compileTar(t, buildTar(t, b...))
	if !maps.Equal(treeSummary(readImage(t, pa)), treeSummary(readImage(t, pb))) {
		t.Error("the observable tree depends on tar entry order")
	}
	if !slices.Equal(sa.OpaqueDirs, sb.OpaqueDirs) || !slices.Equal(sa.Whiteouts, sb.Whiteouts) {
		t.Errorf("stats depend on tar entry order: %+v vs %+v", sa, sb)
	}
	if !slices.Equal(sa.OpaqueDirs, []string{"/d"}) || !slices.Equal(sa.Whiteouts, []string{"/d/gone"}) {
		t.Errorf("stats = %+v", sa)
	}
}

func TestCompileConvertsWhiteoutsAndOpaqueDirs(t *testing.T) {
	p, stats := compileTar(t, buildTar(t,
		dirEntry("opq/"),
		fileEntry("opq/.wh..wh..opq", ""),
		fileEntry("opq/new", "n"),
		fileEntry("opq/aaa-first", "a"),
		fileEntry("plain/.wh.removed", ""),
		fileEntry("plain/.wh..wh.plnk", ""),
		fileEntry("both/keep", "k"),
		fileEntry("both/.wh.keep", ""),
	))
	tree := readImage(t, p)

	opq := tree["/opq"]
	if opq.xattrs[OpaqueXattrName] != "y" {
		t.Errorf("/opq xattrs = %q, want %s=y", opq.xattrs, OpaqueXattrName)
	}
	for _, name := range []string{"/opq/new", "/opq/aaa-first"} {
		if _, ok := tree[name]; !ok {
			t.Errorf("same-layer sibling %s was dropped by the opaque marker", name)
		}
	}
	if _, ok := tree["/opq/"+WhiteoutOpaqueMarker]; ok {
		t.Error("the opaque marker file itself is in the image")
	}
	wh := tree["/plain/removed"]
	if wh == nil || wh.mode != linux.S_IFCHR || wh.major != 0 || wh.minor != 0 {
		t.Errorf("whiteout node = %+v, want char device 0:0 with mode 0", wh)
	}
	if _, ok := tree["/plain/.wh..wh.plnk"]; ok {
		t.Error("reserved aufs metadata name leaked into the image")
	}
	if string(tree["/both/keep"].content) != "k" {
		t.Error("a same-layer whiteout replaced a real file of the same layer")
	}
	if !slices.Equal(stats.Whiteouts, []string{"/plain/removed"}) {
		t.Errorf("Whiteouts = %v", stats.Whiteouts)
	}
}

func TestCompileStoresLargeSparseFilesAsHoles(t *testing.T) {
	const size = 5 << 20
	data := make([]byte, size)
	copy(data[3*testBlockSize:], patternBytes(testBlockSize, 7))
	copy(data[size-100:], patternBytes(100, 8))

	p, stats := compileTar(t, buildTar(t, fileEntry("sparse", string(data)), fileEntry("zeros", string(make([]byte, 1<<20)))))
	if stats.TotalBytes > 100*testBlockSize {
		t.Errorf("image is %d bytes, holes were stored as data", stats.TotalBytes)
	}
	tree := readImage(t, p)
	if !bytes.Equal(tree["/sparse"].content, data) {
		t.Error("sparse file content differs")
	}
	if !bytes.Equal(tree["/zeros"].content, make([]byte, 1<<20)) {
		t.Error("all-zero file content differs")
	}
}

func TestCompileLargeFileKeepsContent(t *testing.T) {
	big := patternBytes(9<<20+777, 11)
	p, _ := compileTar(t, buildTar(t, fileEntry("big", string(big))))
	if !bytes.Equal(readImage(t, p)["/big"].content, big) {
		t.Error("large file content differs")
	}
}

func TestCompileRejectsBadHardlinks(t *testing.T) {
	for name, entries := range map[string][]tarEntry{
		"missing target": {linkEntry("link", "nowhere")},
		"directory":      {dirEntry("d/"), linkEntry("link", "d")},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := CompileTarToEROFS(bytes.NewReader(buildTar(t, entries...)), newMemImage())
			if err == nil || !strings.Contains(err.Error(), "hardlink") {
				t.Errorf("err = %v, want a hardlink error", err)
			}
		})
	}
}

func TestCompileRejectsUnsafeNames(t *testing.T) {
	for name, entry := range map[string]tarEntry{
		"parent escape":   fileEntry("../evil", "x"),
		"deep escape":     fileEntry("a/../../evil", "x"),
		"component > 255": fileEntry(strings.Repeat("x", 256), "x"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileTarToEROFS(bytes.NewReader(buildTar(t, entry)), newMemImage()); err == nil {
				t.Error("compile succeeded, want an error")
			}
		})
	}

	// Absolute and dot-prefixed names stay inside the layer root, and
	// ".." that stays inside it is resolved.
	p, _ := compileTar(t, buildTar(t,
		fileEntry("/abs/file", "a"), fileEntry("./rel/file", "r"), fileEntry("x/../y", "y")))
	tree := readImage(t, p)
	for _, name := range []string{"/abs/file", "/rel/file", "/y"} {
		if _, ok := tree[name]; !ok {
			t.Errorf("%s is missing", name)
		}
	}
}

func TestCompileRejectsUnencodableInput(t *testing.T) {
	for name, entry := range map[string]tarEntry{
		"device major too large": deviceEntry("d", tar.TypeChar, 4096, 0),
		"device minor too large": deviceEntry("d", tar.TypeChar, 1, 1<<20),
		"empty symlink target":   symlinkEntry("l", ""),
		"huge symlink target":    symlinkEntry("l", strings.Repeat("t", testBlockSize)),
		"negative uid":           {hdr: tar.Header{Name: "f", Typeflag: tar.TypeReg, Uid: -1, Mode: 0o644}},
	} {
		t.Run(name, func(t *testing.T) {
			raw := buildTar(t, entry)
			if _, err := CompileTarToEROFS(bytes.NewReader(raw), newMemImage()); err == nil {
				t.Error("compile succeeded, want an error")
			}
		})
	}
}

func TestCompileRejectsCorruptStreams(t *testing.T) {
	raw := buildTar(t, fileEntry("a", strings.Repeat("a", 10000)), fileEntry("b", "b"))
	for name, input := range map[string][]byte{
		"truncated in data":   raw[:1000],
		"truncated in header": raw[:512+10000+512+100],
		"garbage":             bytes.Repeat([]byte{0xAB}, 2048),
		"truncated gzip":      gzipBytes(t, raw)[:100],
		"truncated zstd":      zstdBytes(t, raw)[:40],
		"bad gzip body":       append([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3}, bytes.Repeat([]byte{0xFF}, 64)...),
		"xz":                  {0xfd, '7', 'z', 'X', 'Z', 0x00, 0, 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileTarToEROFS(bytes.NewReader(input), newMemImage()); err == nil {
				t.Error("compile succeeded, want an error")
			}
		})
	}
}

func TestCompileDecompressesGzipAndZstd(t *testing.T) {
	raw := buildTar(t, dirEntry("d/"), fileEntry("d/f", strings.Repeat("payload", 1000)))
	_, plain := compileTar(t, raw)
	for name, input := range map[string][]byte{"gzip": gzipBytes(t, raw), "zstd": zstdBytes(t, raw)} {
		t.Run(name, func(t *testing.T) {
			_, stats := compileTar(t, input)
			if stats.SHA256Hex != plain.SHA256Hex {
				t.Errorf("%s layer compiles to %s, plain tar to %s", name, stats.SHA256Hex, plain.SHA256Hex)
			}
		})
	}
}

func TestCompileEnforcesBudgetsOnDecompressionBombs(t *testing.T) {
	const bombSize = 48 << 20
	bomb := buildTar(t, fileEntry("zeros", string(make([]byte, bombSize))))
	gz, zst := gzipBytes(t, bomb), zstdBytes(t, bomb)
	if len(gz) > 1<<20 || len(zst) > 1<<20 {
		t.Fatalf("test input is not a bomb: gzip %d, zstd %d bytes", len(gz), len(zst))
	}
	lim := DefaultLimits()
	lim.MaxLayerBytes = 4 << 20
	lim.MaxEntryBytes = 2 << 20

	for name, input := range map[string][]byte{"gzip": gz, "zstd": zst} {
		t.Run(name, func(t *testing.T) {
			var before, after runtimeMemStats
			before.read()
			_, err := CompileTarToEROFSWithLimits(bytes.NewReader(input), newMemImage(), lim)
			after.read()
			if !errors.Is(err, ErrLimitExceeded) {
				t.Fatalf("err = %v, want ErrLimitExceeded", err)
			}
			if grown := after.totalAlloc - before.totalAlloc; grown > 64<<20 {
				t.Errorf("rejecting the bomb allocated %d MiB", grown>>20)
			}
		})
	}

	// A layer within the layer budget but with a file over the entry budget.
	lim.MaxLayerBytes = 1 << 30
	small := buildTar(t, fileEntry("big", string(make([]byte, 3<<20))))
	if _, err := CompileTarToEROFSWithLimits(bytes.NewReader(small), newMemImage(), lim); !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("entry budget: err = %v, want ErrLimitExceeded", err)
	}

	lim.MaxEntries = 2
	many := buildTar(t, fileEntry("a", ""), fileEntry("b", ""), fileEntry("c", ""))
	if _, err := CompileTarToEROFSWithLimits(bytes.NewReader(many), newMemImage(), lim); !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("entry count budget: err = %v, want ErrLimitExceeded", err)
	}
}

func TestZstdWindowIsBounded(t *testing.T) {
	// A frame with a window above the cap must fail instead of allocating it.
	raw := buildTar(t, fileEntry("f", strings.Repeat("w", 1<<20)))
	lim := DefaultLimits()
	lim.MaxZstdWindowBytes = 1 << 10
	framed := zstdBytesWithWindow(t, raw, 1<<20)
	if _, err := CompileTarToEROFSWithLimits(bytes.NewReader(framed), newMemImage(), lim); err == nil {
		t.Error("compile succeeded with a window above the cap")
	}
}

func TestCompileKeepsPAXAndLongNames(t *testing.T) {
	longDir := strings.Repeat("d", 200)
	name := longDir + "/" + strings.Repeat("f", 200)
	entry := fileEntry(name, "pax")
	entry.hdr.Format = tar.FormatPAX
	entry.hdr.PAXRecords = map[string]string{"comment": "extra"}
	p, _ := compileTar(t, buildTar(t, entry, tarEntry{
		hdr:  tar.Header{Name: "gnu", Typeflag: tar.TypeReg, Mode: 0o600, Size: 3, Format: tar.FormatGNU, ModTime: epoch},
		data: []byte("gnu"),
	}))
	tree := readImage(t, p)
	if string(tree["/"+name].content) != "pax" || string(tree["/gnu"].content) != "gnu" {
		t.Error("PAX or GNU entry content differs")
	}
}

func TestCompileLaterEntriesReplaceEarlierOnes(t *testing.T) {
	p, _ := compileTar(t, buildTar(t,
		fileEntry("f", "old"), fileEntry("f", "new"),
		dirEntry("d/"), fileEntry("d/x", "x"), fileEntry("d", "now a file"),
	))
	tree := readImage(t, p)
	if string(tree["/f"].content) != "new" || string(tree["/d"].content) != "now a file" {
		t.Errorf("replacement failed: f=%q d=%q", tree["/f"].content, tree["/d"].content)
	}
	if _, ok := tree["/d/x"]; ok {
		t.Error("child of a replaced directory survived")
	}
}

func TestCompileEmptyLayer(t *testing.T) {
	p, stats := compileTar(t, buildTar(t))
	tree := readImage(t, p)
	if len(tree) != 1 || !tree["/"].isDir() || stats.InodeCount != 1 {
		t.Errorf("empty layer: tree=%v stats=%+v", tree, stats)
	}
}

func TestOCIImportsStayWithinSpecLayout(t *testing.T) {
	// pkg/oci may import only pkg/abi/linux, pkg/erofs, pkg/fd, and the embedded x/sys unix package among the gvx packages.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, `"z.gfire.dev/gvx/`) &&
				!strings.Contains(line, `"z.gfire.dev/gvx/pkg/abi/linux"`) &&
				!strings.Contains(line, `"z.gfire.dev/gvx/pkg/erofs"`) &&
				!strings.Contains(line, `"z.gfire.dev/gvx/pkg/fd"`) &&
				!strings.Contains(line, `"z.gfire.dev/gvx/third_party/x_sys/unix"`) {
				t.Errorf("%s imports %s", e.Name(), strings.TrimSpace(line))
			}
		}
	}
}

func TestCompileExpandsGNUSparseFiles(t *testing.T) {
	// PAX sparse format 1.0: the data section starts with a text map of
	// (offset, length) pairs, padded to a block, followed by the data runs.
	const realSize = 8 << 20
	runs := []struct {
		off  int
		data []byte
	}{
		{off: 0, data: []byte("head")},
		{off: 6 << 20, data: patternBytes(5000, 31)},
		{off: realSize - 4, data: []byte("tail")},
	}
	sparseMap := fmt.Sprintf("%d\n", len(runs))
	var payload []byte
	for _, r := range runs {
		sparseMap += fmt.Sprintf("%d\n%d\n", r.off, len(r.data))
		payload = append(payload, r.data...)
	}
	section := append(padBlock([]byte(sparseMap)), payload...)

	// The tar.Writer drops reserved GNU.sparse records, so the archive is
	// assembled by hand.
	paxData := paxRecords(map[string]string{
		"GNU.sparse.major": "1", "GNU.sparse.minor": "0",
		"GNU.sparse.name": "disk.img", "GNU.sparse.realsize": fmt.Sprint(realSize),
	})
	var raw []byte
	raw = append(raw, ustarHeader("PaxHeaders/disk.img", tar.TypeXHeader, int64(len(paxData)))...)
	raw = append(raw, padBlock(paxData)...)
	raw = append(raw, ustarHeader("GNUSparseFile.0/disk.img", tar.TypeReg, int64(len(section)))...)
	raw = append(raw, padBlock(section)...)
	raw = append(raw, make([]byte, 1024)...)

	p, stats := compileTar(t, raw)
	if stats.TotalBytes > 64*testBlockSize {
		t.Errorf("image is %d bytes, the sparse holes were stored as data", stats.TotalBytes)
	}
	want := make([]byte, realSize)
	for _, r := range runs {
		copy(want[r.off:], r.data)
	}
	n := readImage(t, p)["/disk.img"]
	if n == nil || !bytes.Equal(n.content, want) {
		t.Errorf("sparse file differs from the expanded content (present: %v)", n != nil)
	}
}

// paxRecords encodes PAX extended header records.
func paxRecords(records map[string]string) []byte {
	var out []byte
	for k, v := range records {
		body := " " + k + "=" + v + "\n"
		// The length field counts its own digits.
		n := len(body) + 1
		for len(fmt.Sprint(n))+len(body) != n {
			n = len(fmt.Sprint(n)) + len(body)
		}
		out = append(out, fmt.Sprint(n)...)
		out = append(out, body...)
	}
	return out
}

func padBlock(b []byte) []byte {
	return append(append([]byte(nil), b...), make([]byte, (512-len(b)%512)%512)...)
}

// ustarHeader returns one 512-byte ustar header block.
func ustarHeader(name string, typeflag byte, size int64) []byte {
	h := make([]byte, 512)
	copy(h[0:100], name)
	copy(h[100:108], "0000644\x00")
	copy(h[108:116], "0000000\x00")
	copy(h[116:124], "0000000\x00")
	copy(h[124:136], fmt.Sprintf("%011o\x00", size))
	copy(h[136:148], fmt.Sprintf("%011o\x00", epoch.Unix()))
	copy(h[148:156], "        ")
	h[156] = typeflag
	copy(h[257:263], "ustar\x00")
	copy(h[263:265], "00")
	sum := 0
	for _, b := range h {
		sum += int(b)
	}
	copy(h[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return h
}
