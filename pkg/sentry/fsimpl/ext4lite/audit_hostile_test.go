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

package ext4lite

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime/debug"
	"strconv"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// auSpan is a byte range of the image that holds metadata.
type auSpan struct {
	off, n int64
	what   string
}

// auMetadataSpans lists where the metadata of the image lives.
func auMetadataSpans(img *auPages, res *auResult) []auSpan {
	spans := []auSpan{
		{1024, 1024, "superblock"},
		{auBlock, auDescSz, "group descriptor"},
		{65 * auBlock, 512, "block bitmap"},
		{66 * auBlock, 512, "inode bitmap"},
	}
	var maxIno uint32
	for _, e := range res.Tree {
		maxIno = max(maxIno, e.ino)
	}
	spans = append(spans, auSpan{67 * auBlock, int64(maxIno) * auISize, "inode table"})
	for blk, owner := range res.Blocks {
		var e *auEnt
		for _, x := range res.Tree {
			if x.ino == owner {
				e = x
				break
			}
		}
		var head [4]byte
		img.readAt(head[:], int64(blk)*auBlock)
		switch {
		case e != nil && e.mode&0xF000 == 0x4000:
			spans = append(spans, auSpan{int64(blk) * auBlock, 256, "directory block"})
		case head[0] == 0x0A && head[1] == 0xF3:
			spans = append(spans, auSpan{int64(blk) * auBlock, 64, "extent leaf"})
		case head[2] == 0x02 && head[3] == 0xEA:
			spans = append(spans, auSpan{int64(blk) * auBlock, 128, "xattr block"})
		}
	}
	return spans
}

var auInteresting = []uint32{0, 1, 2, 0xFF, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 4095, 4096, 4097, 65536, 1 << 20}

// auMutate damages the image in one of several ways and returns a short
// description.
func auMutate(img *auPages, spans []auSpan, rng *rand.Rand) string {
	sp := spans[rng.IntN(len(spans))]
	off := sp.off + rng.Int64N(sp.n)
	switch rng.IntN(5) {
	case 0:
		var b [1]byte
		img.readAt(b[:], off)
		b[0] ^= 1 << rng.IntN(8)
		img.writeAt(b[:], off)
		return fmt.Sprintf("flip a bit at %d in the %s", off, sp.what)
	case 1:
		img.writeAt([]byte{byte(rng.IntN(256))}, off)
		return fmt.Sprintf("set a byte at %d in the %s", off, sp.what)
	case 2:
		var b [4]byte
		v := auInteresting[rng.IntN(len(auInteresting))]
		auLE.PutUint32(b[:], v)
		img.writeAt(b[:], off&^3)
		return fmt.Sprintf("set the word at %d in the %s to %#x", off&^3, sp.what, v)
	case 3:
		var b [2]byte
		auLE.PutUint16(b[:], uint16(auInteresting[rng.IntN(len(auInteresting))]))
		img.writeAt(b[:], off&^1)
		return fmt.Sprintf("set the half-word at %d in the %s", off&^1, sp.what)
	default:
		n := 16 + rng.IntN(240)
		img.writeAt(make([]byte, n), off)
		return fmt.Sprintf("zero %d bytes at %d in the %s", n, off, sp.what)
	}
}

// auTryMount mounts a volume without a test hook. It returns the VFS
// environment pieces that the walk needs.
func auTryMount(f *auFile) (*env, *Volume, error) {
	v, err := mountHostFile(f, VolumeOptions{})
	if err != nil {
		return nil, nil, err
	}
	v.now = fakeClock()
	v.assertGate.Store(true)
	vol := &Volume{v: v}
	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		return nil, nil, err
	}
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	var mopts vfs.MountOptions
	mopts.GetFilesystemOptions.InternalData = InternalFilesystemOptions{Volume: vol}
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &mopts, nil)
	if err != nil {
		_ = vol.Close()
		return nil, nil, err
	}
	root := mntns.Root(ctx)
	e := &env{ctx: cookieContext{vfs.WithMountNamespace(ctx, mntns)}, creds: creds, vfsObj: vfsObj, root: root, mntns: mntns, vol: vol,
		fs: root.Mount().Filesystem().Impl().(*filesystem)}
	return e, vol, nil
}

// auWalk reads everything that the mounted tree offers and returns the number
// of objects that it met. Errors are fine: an image that fails a check must
// fail with an errno. The walk never calls the test.
func auWalk(e *env, dir string, depth int, budget *int) {
	if depth > 40 || *budget <= 0 {
		return
	}
	fd, err := e.open(dir, linux.O_RDONLY|linux.O_DIRECTORY, 0)
	if err != nil {
		return
	}
	var names []string
	_ = fd.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		if d.Name != "." && d.Name != ".." {
			names = append(names, d.Name)
		}
		if len(names) > 20_000 {
			return errors.New("too many entries")
		}
		return nil
	}))
	fd.DecRef(e.ctx)
	for _, name := range names {
		*budget--
		p := auJoin(dir, name)
		st, err := e.lstat(p)
		if err != nil {
			continue
		}
		switch st.Mode & linux.S_IFMT {
		case linux.S_IFDIR:
			auWalk(e, p, depth+1, budget)
		case linux.S_IFREG:
			fd, err := e.open(p, linux.O_RDONLY, 0)
			if err != nil {
				continue
			}
			buf := make([]byte, 64<<10)
			for off := int64(0); off < 4<<20; {
				n, err := fd.PRead(e.ctx, usermem.BytesIOSequence(buf), off, vfs.ReadOptions{})
				if n == 0 || err != nil {
					break
				}
				off += n
			}
			var list [256]byte
			_, _ = fd.ListXattr(e.ctx, uint64(len(list)))
			fd.DecRef(e.ctx)
		case linux.S_IFLNK:
			_, _ = e.vfsObj.ReadlinkAt(e.ctx, e.creds, e.pop(p))
		}
	}
}

// auPoke writes to a mounted volume, so that the allocator and the flush
// meet the damaged state.
func auPoke(e *env) {
	_ = e.mkdir("/poked")
	for i := range 6 {
		fd, err := e.open(fmt.Sprintf("/poked/f%d", i), linux.O_CREAT|linux.O_WRONLY, 0o644)
		if err != nil {
			continue
		}
		_, _ = fd.PWrite(e.ctx, usermem.BytesIOSequence(auFill(uint32(i), 0, 20_000)), 0, vfsWriteOpts)
		_ = fd.Sync(e.ctx)
		fd.DecRef(e.ctx)
	}
	_ = e.unlink("/poked/f0")
	_ = e.rename("/poked/f1", "/poked/g1")
	_ = e.fs.syncAll()
	_ = e.vfsObj.SetXattrAt(e.ctx, e.creds, &vfs.PathOperation{Root: e.root, Start: e.root, Path: fspath.Parse("/poked")}, &vfs.SetXattrOptions{Name: "user.k", Value: "v"})
}

func auMutantCount() int {
	if s := os.Getenv("EXT4LITE_AUDIT_MUTANTS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	if testing.Short() {
		return 150
	}
	return 800
}

// TestAuditHostileImages damages one byte range of a valid image per mutant and
// mounts the result. The engine may accept the image or reject it with an
// errno. It must never panic, never hang, and never write an image that it
// cannot mount again after a clean unmount.
func TestAuditHostileImages(t *testing.T) {
	auNoFlusher(t)
	d := newAuDrv(t)
	auRichWorkload(d)
	_ = d.e.vfsObj.SetXattrAt(d.e.ctx, d.e.creds, d.e.pop("/h1"), &vfs.SetXattrOptions{Name: "user.attr", Value: "value-of-the-attribute"})
	d.e.unmount()
	base := d.f.snapshot()
	res := auFsck(base, true)
	if !res.OK() {
		t.Fatalf("the base image fails the oracle:\n%s", res)
	}
	spans := auMetadataSpans(base, res)
	t.Logf("%d metadata spans", len(spans))

	rng := rand.New(rand.NewPCG(2026, 4))
	var rejected, accepted, damaged int
	for i := range auMutantCount() {
		img := base.clone()
		desc := auMutate(img, spans, rng)
		if rng.IntN(4) == 0 {
			desc += "; " + auMutate(img, spans, rng)
		}
		func() {
			done := make(chan struct{})
			timer := time.AfterFunc(60*time.Second, func() {
				panic(fmt.Sprintf("mutant %d hangs: %s", i, desc))
			})
			defer timer.Stop()
			defer close(done)
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("mutant %d panics (%s): %v\n%s", i, desc, r, debug.Stack())
				}
			}()
			f := newAuFile(img)
			e, _, err := auTryMount(f)
			if err != nil {
				rejected++
				return
			}
			accepted++
			budget := 50_000
			auWalk(e, "/", 0, &budget)
			auPoke(e)
			e.unmount()
			if _, err := auRecoverRaw(f.snapshot()); err != nil {
				damaged++
				t.Errorf("mutant %d (%s): the engine accepted the image and wrote one that does not mount again: %v", i, desc, err)
			}
		}()
	}
	t.Logf("%d mutants rejected, %d accepted, %d left unmountable", rejected, accepted, damaged)
}

// auRecoverRaw mounts and closes an image and returns the mount error.
func auRecoverRaw(img *auPages) (*auResult, error) {
	f := newAuFile(img.clone())
	v, err := mountHostFile(f, VolumeOptions{})
	if err != nil {
		return nil, err
	}
	return nil, (&Volume{v: v}).Close()
}
