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
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/opencontainers/go-digest"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/erofs"
)

type tarEntry struct {
	hdr  tar.Header
	data []byte
}

var epoch = time.Unix(1_700_000_000, 0)

func dirEntry(name string) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755, Uid: 0, Gid: 0, ModTime: epoch}}
}

func fileEntry(name, data string) tarEntry {
	return tarEntry{
		hdr:  tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data)), ModTime: epoch},
		data: []byte(data),
	}
}

func symlinkEntry(name, target string) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777, ModTime: epoch}}
}

func linkEntry(name, target string) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeLink, Linkname: target, Mode: 0o644, ModTime: epoch}}
}

func deviceEntry(name string, typeflag byte, major, minor int64) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: typeflag, Devmajor: major, Devminor: minor, Mode: 0o600, ModTime: epoch}}
}

func buildTar(t testing.TB, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := e.hdr
		if hdr.Format == tar.FormatUnknown {
			hdr.Format = tar.FormatPAX
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("write tar header %q: %v", hdr.Name, err)
		}
		if len(e.data) > 0 {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatalf("write tar data %q: %v", hdr.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func gzipBytes(t testing.TB, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zstdBytes(t testing.TB, raw []byte) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	return enc.EncodeAll(raw, nil)
}

func sha256Digest(b []byte) string {
	return digest.FromBytes(b).String()
}

// compileTar compiles a layer into a fresh image file and returns its path.
func compileTar(t testing.TB, raw []byte) (string, CompileStats) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "layer.erofs")
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stats, err := CompileTarToEROFSWithOptions(bytes.NewReader(raw), f, CompileOptions{BlockSize: testBlockSize})
	if err != nil {
		t.Fatalf("CompileTarToEROFS: %v", err)
	}
	return p, stats
}

// node is one inode of a compiled image as pkg/erofs reports it.
type node struct {
	mode     uint16
	uid, gid uint32
	nlink    uint32
	nid      uint64
	size     uint64
	content  []byte
	target   string
	major    uint32
	minor    uint32
	xattrs   map[string]string
	children []string
}

func (n *node) isDir() bool { return n.mode&linux.S_IFMT == linux.S_IFDIR }

// readImage walks a compiled image with the upstream pkg/erofs reader.
func readImage(t testing.TB, p string) map[string]*node {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	img, err := erofs.OpenImage(f)
	if err != nil {
		_ = f.Close()
		t.Fatalf("erofs.OpenImage: %v", err)
	}
	t.Cleanup(img.Close)

	out := make(map[string]*node)
	var walk func(nid uint64, p string)
	walk = func(nid uint64, p string) {
		ino, err := img.Inode(nid)
		if err != nil {
			t.Fatalf("Inode(%d) of %q: %v", nid, p, err)
		}
		n := &node{mode: ino.Mode(), uid: ino.UID(), gid: ino.GID(), nlink: ino.Nlink(), nid: nid, size: ino.Size()}
		out[p] = n
		names, err := ino.ListXattrs()
		if err != nil {
			t.Fatalf("ListXattrs of %q: %v", p, err)
		}
		if len(names) > 0 {
			n.xattrs = make(map[string]string)
			for _, name := range names {
				v, err := ino.GetXattr(name)
				if err != nil {
					t.Fatalf("GetXattr(%q) of %q: %v", name, p, err)
				}
				n.xattrs[name] = string(v)
			}
		}
		switch {
		case ino.IsDir():
			err := ino.IterDirents(func(name string, typ uint8, child uint64) error {
				if name == "." || name == ".." {
					return nil
				}
				n.children = append(n.children, name)
				walk(child, path.Join(p, name))
				return nil
			})
			if err != nil {
				t.Fatalf("IterDirents of %q: %v", p, err)
			}
		case ino.IsSymlink():
			if n.target, err = ino.Readlink(); err != nil {
				t.Fatalf("Readlink of %q: %v", p, err)
			}
		case ino.IsRegular():
			n.content = readFileContent(t, img, &ino)
		case ino.IsCharDev() || ino.IsBlockDev():
			n.major, n.minor = ino.Rdev()
		}
	}
	walk(img.RootNid(), "/")
	return out
}

func readFileContent(t testing.TB, img *erofs.Image, ino *erofs.Inode) []byte {
	t.Helper()
	out := make([]byte, ino.Size())
	for off := uint64(0); off < ino.Size(); {
		e, err := ino.MapBlocks(off)
		if err != nil {
			t.Fatalf("MapBlocks(%d): %v", off, err)
		}
		if e.Off > off || e.Length == 0 {
			t.Fatalf("MapBlocks(%d) returned extent %+v", off, e)
		}
		n := min(e.Off+e.Length, ino.Size()) - off
		if e.Mapped {
			b, err := img.BytesAt(e.ImageOff+(off-e.Off), n)
			if err != nil {
				t.Fatalf("BytesAt: %v", err)
			}
			copy(out[off:], b)
		}
		off += n
	}
	return out
}

// memImage is an in-memory ImageFile.
type memImage struct{ buf []byte }

func newMemImage() *memImage { return &memImage{} }

func (m *memImage) WriteAt(p []byte, off int64) (int, error) {
	if end := int(off) + len(p); end > len(m.buf) {
		m.buf = append(m.buf, make([]byte, end-len(m.buf))...)
	}
	copy(m.buf[off:], p)
	return len(p), nil
}

func (m *memImage) ReadAt(p []byte, off int64) (int, error) {
	if int(off) >= len(m.buf) {
		return 0, io.EOF
	}
	n := copy(p, m.buf[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// zstdBytesWithWindow encodes raw as a stream whose frame header declares a
// window of the given size.
func zstdBytesWithWindow(t testing.TB, raw []byte, window int) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf, zstd.WithWindowSize(window), zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// treeSummary reduces a compiled image to what a guest can observe. It omits
// inode numbers and block placement, which depend on the order of tar entries.
func treeSummary(tree map[string]*node) map[string]string {
	out := make(map[string]string, len(tree))
	for p, n := range tree {
		out[p] = fmt.Sprintf("mode=%o uid=%d gid=%d nlink=%d size=%d content=%s target=%q dev=%d:%d xattrs=%v children=%v",
			n.mode, n.uid, n.gid, n.nlink, n.size, digest.FromBytes(n.content).Encoded(), n.target, n.major, n.minor, n.xattrs, n.children)
	}
	return out
}

// newCacheAt opens a layer cache that uses the test block size.
func newCacheAt(dir string) (*LayerCache, error) {
	return NewLayerCacheWithOptions(dir, CacheOptions{BlockSize: testBlockSize})
}
