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
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/usermem"
)

var auSiteRE = regexp.MustCompile(`fsimpl/[A-Za-z0-9_]+/([a-z0-9_]+\.go:\d+)`)

// auPanicSite names the first frame of the engine in a stack that is not a
// test file.
func auPanicSite(stack []byte) string {
	for _, m := range auSiteRE.FindAllSubmatch(stack, -1) {
		if !strings.HasSuffix(string(m[1][:strings.IndexByte(string(m[1]), ':')]), "_test.go") &&
			!strings.HasPrefix(string(m[1]), "audit_") {
			return string(m[1])
		}
	}
	return "unknown"
}

// auGuarded runs fn and turns a panic into a message.
func auGuarded(fn func()) (panicked string) {
	defer func() {
		if r := recover(); r != nil {
			panicked = fmt.Sprintf("%v at %s", r, auPanicSite(debug.Stack()))
		}
	}()
	fn()
	return ""
}

// TestAuditCraftedInodeFields sets each size, flag, count, and pointer field
// of the main inode kinds to a hostile value. The mount, a full walk, and a
// few writes must end with an errno and never with a panic. A panic in the
// Sentry takes down every sandbox of the process, so a volume file must not
// be able to cause one.
func TestAuditCraftedInodeFields(t *testing.T) {
	auNoFlusher(t)
	d := newAuDrv(t)
	auRichWorkload(d)
	d.e.unmount()
	base := d.f.snapshot()
	tree := auFsck(base, true).Tree

	targets := []string{"/", "/big", "/deep", "/sym-short", "/sym-long", "/frag-a", "/sparse", "/h1", "/sizes2/f4096", "/sizes2/f100000", "/sizes2/f129", "/sizes2/f0"}
	fields := []struct {
		name string
		off  int64
		n    int
	}{
		{"mode", 0x00, 2}, {"size_lo", 0x04, 4}, {"size_hi", 0x6C, 4}, {"links", 0x1A, 2},
		{"blocks_lo", 0x1C, 4}, {"flags", 0x20, 4}, {"i_block[0]", 0x28, 4}, {"i_block[1]", 0x2C, 4},
		{"i_block[2]", 0x30, 4}, {"i_block[3]", 0x34, 4}, {"file_acl", 0x68, 4}, {"extra_isize", 0x80, 2},
	}
	// As size_hi, 0xFFFF gives a size of 2^48 bytes. The engine rejects such a
	// size at parse time, before it allocates anything from it.
	values := []uint32{0, 1, 0x7FFFFFFF, 0x80000000, 0x10000000, 0xFFFF, 0xFFFFFFFF}

	sites := map[string]string{}
	counts := map[string]int{}
	total := 0
	for _, path := range targets {
		e := tree[path]
		if e == nil {
			t.Fatalf("%s is missing from the base image", path)
		}
		inodeOff := int64(4)*auBlock + int64(e.ino-1)*auISize
		for _, f := range fields {
			for _, v := range values {
				img := base.clone()
				var b [4]byte
				auLE.PutUint32(b[:], v)
				img.writeAt(b[:f.n], inodeOff+f.off)
				total++
				msg := auGuarded(func() {
					fl := newAuFile(img)
					env, _, err := auTryMount(fl)
					if err != nil {
						return
					}
					budget := 50_000
					auWalk(env, "/", 0, &budget)
					auPoke(env)
					env.unmount()
				})
				if msg != "" {
					site := msg[strings.LastIndex(msg, " at ")+4:]
					counts[site]++
					if _, ok := sites[site]; !ok {
						sites[site] = fmt.Sprintf("%s %s=%#x: %s", path, f.name, v, msg)
					}
				}
			}
		}
	}
	t.Logf("%d crafted images", total)
	var problems []string
	for site, example := range sites {
		problems = append(problems, fmt.Sprintf("panic at %s in %d images, e.g. %s", site, counts[site], example))
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// TestAuditPartialExtentLeavesDoNotPanicFlush splits the one extent leaf of a
// fragmented file into two half-full leaves. Other ext4 implementations write
// such trees, for example after a truncate. The engine must read the file and
// write the inode back without a panic.
func TestAuditPartialExtentLeavesDoNotPanicFlush(t *testing.T) {
	auNoFlusher(t)
	d := newAuDrv(t)
	auRichWorkload(d)
	d.e.unmount()
	base := d.f.snapshot()
	res := auFsck(base, true)
	e := res.Tree["/frag-a"]
	ioff := int64(4)*auBlock + int64(e.ino-1)*auISize
	var raw [auISize]byte
	base.readAt(raw[:], ioff)
	if auLE.Uint16(raw[0x28+6:]) != 1 {
		t.Fatalf("/frag-a has extent depth %d, want 1", auLE.Uint16(raw[0x28+6:]))
	}
	leaf1 := uint64(auLE.Uint32(raw[0x28+12+4:])) | uint64(auLE.Uint16(raw[0x28+12+8:]))<<32
	var lb [auBlock]byte
	base.readAt(lb[:], int64(leaf1)*auBlock)
	n := int(auLE.Uint16(lb[2:]))
	if n < 8 {
		t.Fatalf("the leaf holds %d extents, want 8 or more", n)
	}
	// A free block takes the second half of the extents.
	var leaf2 uint64
	for b := uint64(4000); b > 400; b-- {
		if _, used := res.Blocks[b]; !used {
			leaf2 = b
			break
		}
	}
	half := n / 2
	var l1, l2 [auBlock]byte
	copy(l1[:], lb[:])
	auLE.PutUint16(l1[2:], uint16(half))
	copy(l2[:12], lb[:12])
	auLE.PutUint16(l2[2:], uint16(n-half))
	copy(l2[12:], lb[12+12*half:12+12*n])
	for i := 12 + 12*half; i < 12+12*n; i++ {
		l1[i] = 0
	}
	img := base.clone()
	img.writeAt(l1[:], int64(leaf1)*auBlock)
	img.writeAt(l2[:], int64(leaf2)*auBlock)
	// Root: two index entries.
	auLE.PutUint16(raw[0x28+2:], 2)
	copy(raw[0x28+24:0x28+36], make([]byte, 12))
	auLE.PutUint32(raw[0x28+24:], auLE.Uint32(l2[12:]))
	auLE.PutUint32(raw[0x28+24+4:], uint32(leaf2))
	auLE.PutUint16(raw[0x28+24+8:], uint16(leaf2>>32))
	img.writeAt(raw[:], ioff)

	var problems []string
	if msg := auGuarded(func() {
		fl := newAuFile(img)
		env, _, err := auTryMount(fl)
		if err != nil {
			problems = append(problems, "mount: "+err.Error())
			return
		}
		fd, err := env.open("/frag-a", linux.O_WRONLY, 0)
		if err != nil {
			problems = append(problems, "open: "+err.Error())
			return
		}
		// A write marks the inode dirty, so the flush serializes it.
		_, _ = fd.PWrite(env.ctx, usermem.BytesIOSequence([]byte("x")), 0, vfsWriteOpts)
		fd.DecRef(env.ctx)
		if err := env.fs.syncAll(); err != nil {
			problems = append(problems, "sync: "+err.Error())
		}
		env.unmount()
	}); msg != "" {
		problems = append(problems, "panic: "+msg)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestAuditDirectoryRenameIsAtomicForFlush renames a directory back and forth
// while another goroutine flushes and reads the log after each flush. The
// engine adds the new name before it removes the old name. A flush between the
// two steps would commit a directory with two names. The rename holds the
// operation gate across both steps, so no log may ever hold that state.
func TestAuditDirectoryRenameIsAtomicForFlush(t *testing.T) {
	d := newAuDrv(t)
	d.mkdir("/a")
	d.mkdir("/b")
	d.mkdir("/a/d")
	d.create("/a/d/f", 1000)
	d.syncAll()

	stop := make(chan struct{})
	var bad []string
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := d.e.fs.syncAll(); err != nil {
				bad = append(bad, "sync: "+err.Error())
				return
			}
			replayed, _ := auReplayImage(d.f.snapshot())
			if res := auFsck(replayed, false); !res.OK() {
				bad = append(bad, fmt.Sprintf("after flush %d: %s", i, res.String()))
				return
			}
		}
	})
	from, to := "/a/d", "/b/d"
	for range 600 {
		if err := d.e.rename(from, to); err != nil {
			t.Fatalf("rename %s %s: %v", from, to, err)
		}
		from, to = to, from
	}
	close(stop)
	wg.Wait()
	for _, msg := range bad {
		t.Error(msg)
	}
}

// TestAuditReservedInodesStayReserved clears the reserved inode bits of an
// otherwise clean image. The engine must not hand out an inode below 11, which
// it cannot load again.
func TestAuditReservedInodesStayReserved(t *testing.T) {
	auNoFlusher(t)
	d := newAuDrv(t)
	d.create("/x", 10)
	d.e.unmount()
	img := d.f.snapshot()
	var bm [4]byte
	img.readAt(bm[:], 3*auBlock)
	bm[0], bm[1] = 0x02, 0 // keep only the root inode
	img.writeAt(bm[:2], 3*auBlock)

	var problems []string
	if msg := auGuarded(func() {
		env, _, err := auTryMount(newAuFile(img))
		if err != nil {
			return // a mount that refuses the image is acceptable
		}
		fd, err := env.open("/new", linux.O_CREAT|linux.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		fd.DecRef(env.ctx)
		if st, err := env.stat("/new"); err == nil && st.Ino < firstIno {
			problems = append(problems, fmt.Sprintf("the new file got reserved inode %d", st.Ino))
		}
		env.unmount()
	}); msg != "" {
		problems = append(problems, "panic: "+msg)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestAuditBackupSuperblockLocation checks where a backup superblock lives. On
// a file system with 4 KiB blocks, the copy in a backup group starts at byte 0
// of the first block of the group. The primary copy sits at byte 1024 of block
// 0 only because block 0 starts with the boot sector. e2fsck -b reads the copy
// at byte 0.
func TestAuditBackupSuperblockLocation(t *testing.T) {
	auNoFlusher(t)
	d := newAuDrv(t)
	d.create("/big", 20<<20) // two groups
	d.e.unmount()
	img := d.f.snapshot()
	res := auFsck(img, true)
	if res.Groups < 2 {
		t.Fatalf("the volume has %d groups, want 2", res.Groups)
	}
	var magic [2]byte
	img.readAt(magic[:], 4096*auBlock+0x38)
	var problems []string
	if auLE.Uint16(magic[:]) != auSuperMagic {
		problems = append(problems, "the superblock copy of group 1 has no magic at byte 0x38 of its first block")
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestAuditLongNameErrno requires ENAMETOOLONG for a name of 300 bytes on
// every call that takes a name.
func TestAuditLongNameErrno(t *testing.T) {
	d := newAuDrv(t)
	long := "/" + strings.Repeat("n", 300)
	var problems []string
	check := func(what string, err error) {
		if !errors.Is(err, linuxerr.ENAMETOOLONG) {
			problems = append(problems, fmt.Sprintf("%s returns %v, want ENAMETOOLONG", what, err))
		}
	}
	_, err := d.e.open(long, linux.O_CREAT|linux.O_WRONLY, 0o644)
	check("create", err)
	check("mkdir", d.e.mkdir(long))
	check("unlink", d.e.unlink(long))
	check("rmdir", d.e.rmdir(long))
	d.create("/short", 1)
	check("rename of a long source", d.e.rename(long, "/other"))
	check("rename to a long target", d.e.rename("/short", long))
	for _, p := range problems {
		t.Error(p)
	}
}

// TestAuditHeldInodeDoesNotFailCreate uses every inode of group 0, syncs, and
// unlinks one file. The inode is held until the next flush, and the volume can
// grow. A create must succeed.
func TestAuditHeldInodeDoesNotFailCreate(t *testing.T) {
	d := newAuDrv(t)
	d.mkdir("/d")
	v := d.e.fs.v
	var last string
	for i := 0; ; i++ {
		v.mu.Lock()
		free := v.freeInodesTotal
		v.mu.Unlock()
		if free == 0 {
			break
		}
		p := fmt.Sprintf("/d/f%05d", i)
		fd, err := d.e.open(p, linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
		if err != nil {
			t.Fatalf("create %s: %v", p, err)
		}
		fd.DecRef(d.e.ctx)
		last = p
	}
	if v.numGroups() != 1 {
		t.Fatalf("the volume has %d groups, want 1 full group", v.numGroups())
	}
	d.syncAll()
	if err := d.e.unlink(last); err != nil {
		t.Fatal(err)
	}
	var problems []string
	fd, err := d.e.open("/d/again", linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
	if err != nil {
		problems = append(problems, fmt.Sprintf("create fails with %v while the volume can grow", err))
	} else {
		fd.DecRef(d.e.ctx)
	}
	for _, p := range problems {
		t.Error(p)
	}
}
