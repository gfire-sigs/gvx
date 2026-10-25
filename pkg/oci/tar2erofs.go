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

// Package oci resolves multi-arch OCI images and compiles layer tarballs into
// cached EROFS v1 filesystem images without host extraction.
package oci

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"path"
	"sort"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/erofs"
)

const (
	// EROFSSuperBlockMagicV1 is the EROFS v1 magic number at byte offset 1024.
	EROFSSuperBlockMagicV1 uint32 = erofs.SuperBlockMagicV1
	// EROFSSuperBlockOffset is the byte offset of the EROFS superblock.
	EROFSSuperBlockOffset = erofs.SuperBlockOffset
	// EROFSBlockSize is the default block size of gvx EROFS images.
	EROFSBlockSize = 4096
	// EROFSBlockSizeBits is log2(EROFSBlockSize).
	EROFSBlockSizeBits = 12
	// DefaultBlockSize is the block size that a zero BlockSize option selects.
	DefaultBlockSize = EROFSBlockSize
	// MinBlockSize is the smallest block size that the compiler emits.
	MinBlockSize = 4096
	// MaxBlockSize is the largest block size that the compiler emits.
	MaxBlockSize = 65536
	// EROFSInodeSlotBits is log2(32), the EROFS inode slot alignment.
	EROFSInodeSlotBits = erofs.InodeSlotBits
	// EROFSInodeExtendedSize is the 64-byte extended inode size (2 slots).
	EROFSInodeExtendedSize = erofs.InodeExtendedSize
	// EROFSDirentSize is the 12-byte on-disk directory entry size.
	EROFSDirentSize = erofs.DirentSize

	// WhiteoutPrefix is the OCI/OverlayFS whiteout file prefix.
	WhiteoutPrefix = ".wh."
	// WhiteoutOpaqueMarker is the OCI/OverlayFS opaque directory marker.
	WhiteoutOpaqueMarker = ".wh..wh..opq"

	// whiteoutMetaPrefix marks reserved aufs bookkeeping names that carry no content.
	whiteoutMetaPrefix = ".wh..wh."

	// paxXattrPrefix prefixes the PAX records that carry POSIX xattrs.
	paxXattrPrefix = "SCHILY.xattr."

	// minHoleBytes is the shortest run of zero bytes that becomes a sparse
	// hole. Shorter runs stay data so that ordinary files keep a flat layout.
	minHoleBytes = 64 << 10

	// copyBytes is the size of one streaming read, rounded down to whole blocks.
	copyBytes = 256 << 10
)

// ValidBlockSize reports whether n is a block size that the compiler emits:
// a power of two from MinBlockSize to MaxBlockSize.
func ValidBlockSize(n int) bool {
	return n >= MinBlockSize && n <= MaxBlockSize && n&(n-1) == 0
}

// resolveBlockSize maps the zero value to DefaultBlockSize and rejects invalid sizes.
func resolveBlockSize(n int) (int, error) {
	if n == 0 {
		return DefaultBlockSize, nil
	}
	if !ValidBlockSize(n) {
		return 0, fmt.Errorf("oci: block size %d is not a power of two from %d to %d", n, MinBlockSize, MaxBlockSize)
	}
	return n, nil
}

// ImageFile is the output of the compiler. The compiler writes file data
// blocks while the tar stream arrives, then the metadata and the superblock.
type ImageFile interface {
	io.ReaderAt
	io.WriterAt
}

// CompileStats summarizes a compiled EROFS layer image.
type CompileStats struct {
	SHA256Hex   string
	BlockSize   int
	TotalBytes  int64
	TotalBlocks uint32
	InodeCount  uint64
	OpaqueDirs  []string
	Whiteouts   []string
}

// blockRun is a run of consecutive blocks of one file. A run whose start is
// erofsNullAddr is a sparse hole.
type blockRun struct {
	start uint32
	n     uint32
}

// fsNode is one inode of the layer under construction.
type fsNode struct {
	mode      uint16
	uid, gid  uint32
	mtime     uint64
	mtimeNsec uint32
	rdev      uint32
	nlink     uint32
	ino       uint32
	xattrs    []xattrKV

	// Directory state.
	parent    *fsNode
	children  map[string]*fsNode
	whiteouts map[string]*fsNode
	opaque    bool

	// Regular file state.
	size    uint64
	runs    []blockRun
	chunked bool

	// Symlink state.
	target string
}

func (n *fsNode) isDir() bool     { return n.mode&linux.S_IFMT == linux.S_IFDIR }
func (n *fsNode) isRegular() bool { return n.mode&linux.S_IFMT == linux.S_IFREG }
func (n *fsNode) isSymlink() bool { return n.mode&linux.S_IFMT == linux.S_IFLNK }

func newDir(parent *fsNode) *fsNode {
	n := &fsNode{
		mode:     linux.S_IFDIR | 0o755,
		parent:   parent,
		children: make(map[string]*fsNode),
	}
	if parent == nil {
		n.parent = n
	}
	return n
}

// compiler streams one layer into an image file.
type compiler struct {
	dst     ImageFile
	lim     Limits
	bs      int
	root    *fsNode
	entries int64

	// nextBlk is the next free data block. Block 0 holds the superblock.
	nextBlk uint32

	// minHoleBlocks is the shortest run of zero blocks that becomes a hole.
	minHoleBlocks uint32
	// copyBlocks is the number of blocks per streaming read.
	copyBlocks uint64

	buf       []byte
	zeroBlock []byte
	opaque    []string
}

func newCompiler(dst ImageFile, lim Limits, bs int) *compiler {
	copyBlocks := max(1, copyBytes/bs)
	return &compiler{
		dst:           dst,
		lim:           lim,
		bs:            bs,
		root:          newDir(nil),
		nextBlk:       1,
		minHoleBlocks: uint32(max(1, minHoleBytes/bs)),
		copyBlocks:    uint64(copyBlocks),
		buf:           make([]byte, copyBlocks*bs),
		zeroBlock:     make([]byte, copyBlocks*bs),
	}
}

// CompileOptions selects the size budgets and the block size of a compilation.
// Zero fields select DefaultLimits and DefaultBlockSize.
type CompileOptions struct {
	Limits Limits
	// BlockSize is the EROFS block size. It must be a power of two from
	// MinBlockSize to MaxBlockSize. The sentry refuses images whose block size
	// is not a multiple of its page size, so callers pass at least that size.
	BlockSize int
}

// CompileTarToEROFS streams a raw, gzip, or zstd compressed tar layer and
// writes a complete 4KB-block EROFS v1 image to dst. File data goes straight
// to dst, so memory use depends on the number of entries, not on layer size.
func CompileTarToEROFS(src io.Reader, dst ImageFile) (CompileStats, error) {
	return CompileTarToEROFSWithOptions(src, dst, CompileOptions{})
}

// CompileTarToEROFSWithLimits is CompileTarToEROFS with explicit size budgets.
func CompileTarToEROFSWithLimits(src io.Reader, dst ImageFile, lim Limits) (CompileStats, error) {
	return CompileTarToEROFSWithOptions(src, dst, CompileOptions{Limits: lim})
}

// CompileTarToEROFSWithOptions is CompileTarToEROFS with explicit budgets and block size.
func CompileTarToEROFSWithOptions(src io.Reader, dst ImageFile, opts CompileOptions) (CompileStats, error) {
	if opts.Limits == (Limits{}) {
		opts.Limits = DefaultLimits()
	}
	if err := opts.Limits.validate(); err != nil {
		return CompileStats{}, err
	}
	bs, err := resolveBlockSize(opts.BlockSize)
	if err != nil {
		return CompileStats{}, err
	}
	return compileLayer(src, dst, opts.Limits, bs, nil, nil)
}

// diffVerifier verifies the sha256 of a decompressed layer, which an image
// config calls the diff ID.
type diffVerifier struct {
	want string
	h    hash.Hash
}

func newDiffVerifier(want string) *diffVerifier {
	return &diffVerifier{want: want, h: sha256.New()}
}

// compileLayer compiles one layer. A non-nil image budget accumulates the
// decompressed bytes of every layer of an image. A non-nil diff verifier
// verifies the whole decompressed stream against its diff ID.
func compileLayer(src io.Reader, dst ImageFile, lim Limits, bs int, image *byteBudget, diff *diffVerifier) (CompileStats, error) {
	dec, err := openDecompressed(src, lim)
	if err != nil {
		return CompileStats{}, err
	}
	defer dec.Close()
	var stream io.Reader = newBoundedReader(dec, "decompressed layer size", lim.MaxLayerBytes, image)
	if diff != nil {
		stream = io.TeeReader(stream, diff.h)
	}
	stats, err := compileTarReader(tar.NewReader(stream), dst, lim, bs)
	if err != nil {
		return CompileStats{}, err
	}
	if diff != nil {
		// The tar reader stops at the end-of-archive marker. The diff ID
		// covers any bytes after it too.
		if _, err := io.Copy(io.Discard, stream); err != nil {
			return CompileStats{}, fmt.Errorf("oci: read layer trailer: %w", err)
		}
		if got := hex.EncodeToString(diff.h.Sum(nil)); got != diff.want {
			return CompileStats{}, fmt.Errorf("%w: layer diff ID is %s, want %s", ErrDigestMismatch, got, diff.want)
		}
	}
	return stats, nil
}

func compileTarReader(tr *tar.Reader, dst ImageFile, lim Limits, bs int) (CompileStats, error) {
	c := newCompiler(dst, lim, bs)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return CompileStats{}, fmt.Errorf("oci: read tar entry: %w", err)
		}
		if err := c.addEntry(hdr, tr); err != nil {
			return CompileStats{}, err
		}
	}
	return c.finish()
}

// cleanTarPath returns the slash-separated path of a tar member relative to
// the layer root. It returns "" for the root itself and rejects names that
// escape the root or contain NUL bytes or oversized components.
func cleanTarPath(name string) (string, error) {
	if strings.IndexByte(name, 0) >= 0 {
		return "", fmt.Errorf("oci: tar entry name %q contains a NUL byte", name)
	}
	var parts []string
	for _, comp := range strings.Split(name, "/") {
		switch comp {
		case "", ".":
		case "..":
			if len(parts) == 0 {
				return "", fmt.Errorf("oci: tar entry %q escapes the layer root", name)
			}
			parts = parts[:len(parts)-1]
		default:
			if len(comp) > erofsMaxName {
				return "", fmt.Errorf("oci: tar entry %q has a component longer than %d bytes", name, erofsMaxName)
			}
			parts = append(parts, comp)
		}
	}
	return strings.Join(parts, "/"), nil
}

// ensureDir returns the directory at dirPath, creating implicit parents.
func (c *compiler) ensureDir(dirPath string) (*fsNode, error) {
	cur := c.root
	if dirPath == "" {
		return cur, nil
	}
	for _, part := range strings.Split(dirPath, "/") {
		next, ok := cur.children[part]
		if !ok {
			next = newDir(cur)
			cur.children[part] = next
		} else if !next.isDir() {
			return nil, fmt.Errorf("oci: tar entry below non-directory %q", part)
		}
		cur = next
	}
	return cur, nil
}

// lookupFile returns the non-directory node at p, or nil.
func (c *compiler) lookupFile(p string) *fsNode {
	cur := c.root
	if p == "" {
		return nil
	}
	for _, part := range strings.Split(p, "/") {
		if !cur.isDir() {
			return nil
		}
		next, ok := cur.children[part]
		if !ok {
			return nil
		}
		cur = next
	}
	if cur.isDir() {
		return nil
	}
	return cur
}

func headerOwner(hdr *tar.Header) (uid, gid uint32, err error) {
	if hdr.Uid < 0 || hdr.Uid > math.MaxUint32 || hdr.Gid < 0 || hdr.Gid > math.MaxUint32 {
		return 0, 0, fmt.Errorf("oci: tar entry %q has owner %d:%d outside the 32-bit range", hdr.Name, hdr.Uid, hdr.Gid)
	}
	return uint32(hdr.Uid), uint32(hdr.Gid), nil
}

func headerXattrs(hdr *tar.Header) []xattrKV {
	var xs []xattrKV
	for k, v := range hdr.PAXRecords {
		if name, ok := strings.CutPrefix(k, paxXattrPrefix); ok && name != "" {
			xs = append(xs, xattrKV{name: name, value: []byte(v)})
		}
	}
	return xs
}

// newNode builds a node of the given file type from a tar header.
func newNode(hdr *tar.Header, fileType uint16) (*fsNode, error) {
	uid, gid, err := headerOwner(hdr)
	if err != nil {
		return nil, err
	}
	n := &fsNode{
		mode: fileType | uint16(hdr.Mode&0o7777),
		uid:  uid,
		gid:  gid,
	}
	if !hdr.ModTime.IsZero() {
		n.mtime = uint64(max(hdr.ModTime.Unix(), 0))
		n.mtimeNsec = uint32(max(hdr.ModTime.Nanosecond(), 0))
	}
	n.xattrs = headerXattrs(hdr)
	// Encode once now so that an unencodable xattr names its entry.
	if _, err := encodeXattrIbody(n.xattrs); err != nil {
		return nil, fmt.Errorf("oci: tar entry %q: %w", hdr.Name, err)
	}
	return n, nil
}

// applyDirMeta copies header metadata onto an existing directory node.
func applyDirMeta(d *fsNode, hdr *tar.Header) error {
	nd, err := newNode(hdr, linux.S_IFDIR)
	if err != nil {
		return err
	}
	d.mode, d.uid, d.gid, d.mtime, d.mtimeNsec = nd.mode, nd.uid, nd.gid, nd.mtime, nd.mtimeNsec
	d.xattrs = nd.xattrs
	for _, x := range d.xattrs {
		if x.name == OpaqueXattrName && string(x.value) == opaqueXattrValue {
			d.opaque = true
		}
	}
	d.xattrs = filterOpaqueXattr(d.xattrs)
	return nil
}

// filterOpaqueXattr drops the opaque marker from xs. The compiler re-adds it
// from the node's opaque flag so that it is stored exactly once.
func filterOpaqueXattr(xs []xattrKV) []xattrKV {
	out := xs[:0]
	for _, x := range xs {
		if x.name != OpaqueXattrName {
			out = append(out, x)
		}
	}
	return out
}

func (c *compiler) addEntry(hdr *tar.Header, tr *tar.Reader) error {
	if hdr.Typeflag == tar.TypeXGlobalHeader {
		return nil
	}
	if c.entries++; c.entries > c.lim.MaxEntries {
		return &LimitError{What: "tar entry count", Limit: c.lim.MaxEntries}
	}
	clean, err := cleanTarPath(hdr.Name)
	if err != nil {
		return err
	}
	if clean == "" {
		if hdr.Typeflag != tar.TypeDir {
			return fmt.Errorf("oci: tar entry %q names the layer root but is not a directory", hdr.Name)
		}
		return applyDirMeta(c.root, hdr)
	}
	dirPath, base := path.Split(clean)
	parent, err := c.ensureDir(strings.TrimSuffix(dirPath, "/"))
	if err != nil {
		return err
	}

	switch {
	case base == WhiteoutOpaqueMarker:
		// The marker hides lower layers only. It must not remove siblings of
		// this layer, whatever their order in the tar stream.
		parent.opaque = true
		return nil
	case strings.HasPrefix(base, whiteoutMetaPrefix):
		return nil
	case strings.HasPrefix(base, WhiteoutPrefix):
		target := strings.TrimPrefix(base, WhiteoutPrefix)
		if target == "" {
			return fmt.Errorf("oci: tar entry %q is an empty whiteout", hdr.Name)
		}
		wh, err := newNode(hdr, linux.S_IFCHR)
		if err != nil {
			return err
		}
		// Linux marks whiteouts as character device 0:0 with no permissions.
		wh.mode = linux.S_IFCHR
		wh.xattrs, wh.rdev = nil, 0
		if parent.whiteouts == nil {
			parent.whiteouts = make(map[string]*fsNode)
		}
		parent.whiteouts[target] = wh
		return nil
	}

	switch hdr.Typeflag {
	case tar.TypeDir:
		existing, ok := parent.children[base]
		if !ok || !existing.isDir() {
			existing = newDir(parent)
			parent.children[base] = existing
		}
		return applyDirMeta(existing, hdr)

	case tar.TypeReg, tar.TypeRegA, tar.TypeGNUSparse, tar.TypeCont:
		if hdr.Size < 0 || hdr.Size > c.lim.MaxEntryBytes {
			return &LimitError{What: fmt.Sprintf("size of %q", hdr.Name), Limit: c.lim.MaxEntryBytes}
		}
		n, err := newNode(hdr, linux.S_IFREG)
		if err != nil {
			return err
		}
		if err := c.streamFile(tr, n, hdr.Size); err != nil {
			return fmt.Errorf("oci: read regular file %q: %w", hdr.Name, err)
		}
		parent.children[base] = n

	case tar.TypeSymlink:
		n, err := newNode(hdr, linux.S_IFLNK)
		if err != nil {
			return err
		}
		if hdr.Linkname == "" || len(hdr.Linkname) >= maxSymlinkTarget {
			return fmt.Errorf("oci: symlink %q has an invalid target length %d", hdr.Name, len(hdr.Linkname))
		}
		n.mode = linux.S_IFLNK | 0o777
		n.target = hdr.Linkname
		parent.children[base] = n

	case tar.TypeLink:
		targetPath, err := cleanTarPath(hdr.Linkname)
		if err != nil {
			return err
		}
		target := c.lookupFile(targetPath)
		if target == nil {
			return fmt.Errorf("oci: hardlink %q targets %q, which is not in the same layer", hdr.Name, hdr.Linkname)
		}
		parent.children[base] = target

	case tar.TypeFifo:
		n, err := newNode(hdr, linux.S_IFIFO)
		if err != nil {
			return err
		}
		parent.children[base] = n

	case tar.TypeChar, tar.TypeBlock:
		fileType := uint16(linux.S_IFCHR)
		if hdr.Typeflag == tar.TypeBlock {
			fileType = linux.S_IFBLK
		}
		n, err := newNode(hdr, fileType)
		if err != nil {
			return err
		}
		if hdr.Devmajor < 0 || hdr.Devmajor > 0xfff || hdr.Devminor < 0 || hdr.Devminor > 0xfffff {
			return fmt.Errorf("oci: device %q has number %d:%d that EROFS cannot encode", hdr.Name, hdr.Devmajor, hdr.Devminor)
		}
		n.rdev = linux.MakeDeviceID(uint16(hdr.Devmajor), uint32(hdr.Devminor))
		parent.children[base] = n

	default:
		return fmt.Errorf("oci: tar entry %q has unsupported type %q", hdr.Name, hdr.Typeflag)
	}
	return nil
}

// fileWriter places the blocks of one regular file.
type fileWriter struct {
	c       *compiler
	runs    []blockRun
	zeros   uint32
	hasHole bool
}

func (w *fileWriter) isZero(block []byte) bool {
	return bytes.Equal(block, w.c.zeroBlock[:len(block)])
}

// addData writes whole blocks at the next free block address.
func (w *fileWriter) addData(p []byte) error {
	c := w.c
	nb := uint32(len(p) / c.bs)
	if uint64(c.nextBlk)+uint64(nb) >= erofsNullAddr {
		return errors.New("oci: layer exceeds the EROFS block address space")
	}
	if _, err := c.dst.WriteAt(p, int64(c.nextBlk)*int64(c.bs)); err != nil {
		return fmt.Errorf("write EROFS data blocks: %w", err)
	}
	if last := len(w.runs) - 1; last >= 0 && w.runs[last].start != erofsNullAddr && w.runs[last].start+w.runs[last].n == c.nextBlk {
		w.runs[last].n += nb
	} else {
		w.runs = append(w.runs, blockRun{start: c.nextBlk, n: nb})
	}
	c.nextBlk += nb
	return nil
}

// settleZeros turns the pending zero blocks into a hole when the run is long
// enough, and into data blocks otherwise.
func (w *fileWriter) settleZeros() error {
	z := w.zeros
	w.zeros = 0
	if z == 0 {
		return nil
	}
	if z >= w.c.minHoleBlocks {
		w.runs = append(w.runs, blockRun{start: erofsNullAddr, n: z})
		w.hasHole = true
		return nil
	}
	return w.addData(w.c.zeroBlock[:int(z)*w.c.bs])
}

// addBlocks classifies whole blocks as zero or data. Data blocks reach the
// image file immediately, zero blocks wait until their run length is known.
func (w *fileWriter) addBlocks(p []byte) error {
	bs := w.c.bs
	nb := len(p) / bs
	block := func(i int) []byte { return p[i*bs : (i+1)*bs] }
	for i := 0; i < nb; {
		j := i + 1
		if w.isZero(block(i)) {
			for j < nb && w.isZero(block(j)) {
				j++
			}
			w.zeros += uint32(j - i)
		} else {
			for j < nb && !w.isZero(block(j)) {
				j++
			}
			if err := w.settleZeros(); err != nil {
				return err
			}
			if err := w.addData(p[i*bs : j*bs]); err != nil {
				return err
			}
		}
		i = j
	}
	return nil
}

// streamFile copies size bytes of file content from tr into data blocks.
func (c *compiler) streamFile(tr io.Reader, n *fsNode, size int64) error {
	n.size = uint64(size)
	w := &fileWriter{c: c}
	full := uint64(size) / uint64(c.bs)
	tailLen := int(uint64(size) % uint64(c.bs))

	for remaining := full; remaining > 0; {
		cnt := min(remaining, c.copyBlocks)
		chunk := c.buf[:cnt*uint64(c.bs)]
		if _, err := io.ReadFull(tr, chunk); err != nil {
			return unexpectedEOF(err)
		}
		if err := w.addBlocks(chunk); err != nil {
			return err
		}
		remaining -= cnt
	}

	if tailLen > 0 {
		tail := c.buf[:c.bs]
		if _, err := io.ReadFull(tr, tail[:tailLen]); err != nil {
			return unexpectedEOF(err)
		}
		clear(tail[tailLen:])
		if w.isZero(tail) {
			w.zeros++
		} else {
			if err := w.settleZeros(); err != nil {
				return err
			}
			// Regular files never tail-pack. The sentry maps files by image
			// offset, so every file byte must sit in a block of its own.
			if err := w.addData(tail); err != nil {
				return err
			}
		}
	}
	if err := w.settleZeros(); err != nil {
		return err
	}
	n.runs = w.runs
	n.chunked = w.hasHole
	if !n.chunked && len(n.runs) > 1 {
		return errors.New("oci: internal error: flat file with split data")
	}
	return nil
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// finish lays out the metadata and writes the image.
func (c *compiler) finish() (CompileStats, error) {
	var whiteouts []string
	var walk func(d *fsNode, p string)
	walk = func(d *fsNode, p string) {
		if d.opaque {
			c.opaque = append(c.opaque, "/"+p)
		}
		for name, wh := range d.whiteouts {
			// A real entry of the same layer wins over its whiteout.
			if _, exists := d.children[name]; !exists {
				d.children[name] = wh
				whiteouts = append(whiteouts, "/"+path.Join(p, name))
			}
		}
		for name, child := range d.children {
			if child.isDir() && child.parent == d {
				walk(child, path.Join(p, name))
			}
		}
	}
	walk(c.root, "")

	layout, err := buildLayout(c.root, c.nextBlk, c.bs)
	if err != nil {
		return CompileStats{}, err
	}
	if err := writeImage(c.dst, c.root, layout); err != nil {
		return CompileStats{}, err
	}

	total := int64(layout.total) * int64(c.bs)
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(c.dst, 0, total)); err != nil {
		return CompileStats{}, fmt.Errorf("oci: hash EROFS image: %w", err)
	}
	sort.Strings(c.opaque)
	sort.Strings(whiteouts)
	return CompileStats{
		SHA256Hex:   hex.EncodeToString(h.Sum(nil)),
		BlockSize:   c.bs,
		TotalBytes:  total,
		TotalBlocks: layout.total,
		InodeCount:  uint64(len(layout.nodes)),
		OpaqueDirs:  c.opaque,
		Whiteouts:   whiteouts,
	}, nil
}
