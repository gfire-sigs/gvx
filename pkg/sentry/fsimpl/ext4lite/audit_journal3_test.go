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
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"
)

// auDowngrade turns a clean image with a journal into the image of an older
// release: no journal flag, no journal inode, and the journal blocks free.
func auDowngrade(t *testing.T, img *auPages) *auPages {
	t.Helper()
	out := img.clone()
	j, _ := auReadJournal(out)
	if j == nil {
		t.Fatal("the image has no journal to remove")
	}
	var sb [1024]byte
	out.readAt(sb[:], 1024)
	auLE.PutUint32(sb[0x5C:], auLE.Uint32(sb[0x5C:])&^auCompatJournal)
	auLE.PutUint32(sb[0xE0:], 0)
	clear(sb[0xFD:0xFE])
	clear(sb[0x10C : 0x10C+68])
	free := uint64(auLE.Uint32(sb[0x0C:])) + uint64(j.blocks)
	auLE.PutUint32(sb[0x0C:], uint32(free))
	out.writeAt(sb[:], 1024)

	const inodeTable = 4
	out.writeAt(make([]byte, auISize), int64(inodeTable)*auBlock+7*auISize)

	var bm [512]byte
	out.readAt(bm[:], 2*auBlock)
	for _, e := range j.exts {
		for i := uint32(0); i < e.n; i++ {
			b := e.pblk + uint64(i)
			bm[b/8] &^= 1 << (b % 8)
		}
	}
	out.writeAt(bm[:], 2*auBlock)
	var gd [auDescSz]byte
	out.readAt(gd[:], auBlock)
	auLE.PutUint16(gd[0x0C:], uint16(auLE.Uint16(gd[0x0C:])+uint16(j.blocks)))
	out.writeAt(gd[:], auBlock)
	return out
}

// auFreshImage returns the clean image of a volume with some content and the
// model of that content.
func auFreshImage(t *testing.T) (*auPages, *auModel) {
	t.Helper()
	d := newAuDrv(t)
	d.mkdir("/etc")
	d.create("/etc/passwd", 700)
	d.create("/big", 3<<20)
	d.symlink("etc/passwd", "/link")
	d.e.unmount()
	return d.f.snapshot(), d.m
}

// TestAuditLegacyVolumeGetsAJournal mounts the image of an older release. The
// mount adds a journal in the free space of group 0. The host file keeps its
// size, no content changes, and the next mount finds a valid journal.
func TestAuditLegacyVolumeGetsAJournal(t *testing.T) {
	img, model := auFreshImage(t)
	legacy := auDowngrade(t, img)
	if res := auFsck(legacy, true); !res.OK() {
		t.Fatalf("the downgraded image is not a clean old volume:\n%s", res)
	}
	size := legacy.size

	d := auMount(t, newAuFile(legacy), model)
	if d.e.fs.v.j == nil {
		t.Fatal("the mount did not create a journal")
	}
	d.verifyLive("legacy volume after the upgrade")
	d.create("/after", 12_345)
	d.syncAll()
	d.e.unmount()

	got := d.f.snapshot()
	if got.size != size {
		t.Errorf("the host file changed from %d to %d bytes", size, got.size)
	}
	res := auFsck(got, true)
	if !res.OK() {
		t.Fatalf("image after the upgrade:\n%s", res)
	}
	for _, msg := range auCompareImage(res, d.m) {
		t.Errorf("%s", msg)
	}
	if j, _ := auReadJournal(got); j == nil || j.exts[0].pblk >= blocksPerGroup {
		t.Errorf("the new journal is not in group 0: %+v", j)
	}
}

// TestAuditLegacyVolumeWithoutRoomStaysLegacy removes the free run of 1024
// blocks from group 0 of an older volume. The mount must not add a journal and
// must not grow the host file. The volume works and ends clean.
func TestAuditLegacyVolumeWithoutRoomStaysLegacy(t *testing.T) {
	img, model := auFreshImage(t)
	legacy := auDowngrade(t, img)
	// Mark every 400th free block of group 0 as used. No free run reaches 1024
	// blocks, and the blocks look like data that no inode names.
	var bm [512]byte
	legacy.readAt(bm[:], 2*auBlock)
	marked := 0
	for b := 260 + 200; b < blocksPerGroup; b += 400 {
		if bm[b/8]&(1<<(b%8)) == 0 {
			bm[b/8] |= 1 << (b % 8)
			marked++
		}
	}
	legacy.writeAt(bm[:], 2*auBlock)
	var sb [1024]byte
	legacy.readAt(sb[:], 1024)
	auLE.PutUint32(sb[0x0C:], auLE.Uint32(sb[0x0C:])-uint32(marked))
	legacy.writeAt(sb[:], 1024)
	var gd [auDescSz]byte
	legacy.readAt(gd[:], auBlock)
	auLE.PutUint16(gd[0x0C:], auLE.Uint16(gd[0x0C:])-uint16(marked))
	legacy.writeAt(gd[:], auBlock)
	size := legacy.size

	d := auMount(t, newAuFile(legacy), model)
	if d.e.fs.v.j != nil {
		t.Fatal("the mount created a journal although no run of 1024 blocks is free")
	}
	d.verifyLive("legacy volume without room")
	d.create("/after", 5000)
	d.syncAll()
	d.e.unmount()
	got := d.f.snapshot()
	if got.size != size {
		t.Errorf("the host file changed from %d to %d bytes", size, got.size)
	}
	res := auFsck(got, false)
	if !res.OK() {
		t.Fatalf("image:\n%s", res)
	}
	for _, msg := range auCompareImage(res, d.m) {
		t.Errorf("%s", msg)
	}
	var sb2 [1024]byte
	got.readAt(sb2[:], 1024)
	if auLE.Uint16(sb2[0x3A:])&1 == 0 {
		t.Errorf("a clean unmount of a legacy volume leaves no valid bit")
	}
}

// TestAuditReplayIsRestartable crashes the replay of the mount at every host
// call. Each partial replay must leave an image that the next mount replays to
// the same result.
func TestAuditReplayIsRestartable(t *testing.T) {
	d := newAuDrv(t)
	auRichWorkload(d)
	d.syncAll()
	crash := d.f.snapshot() // the log holds every transaction of the workload

	f := newAuFile(crash.clone())
	_, end := f.beginWindow()
	v, err := mountHostFile(f, VolumeOptions{})
	if err != nil {
		t.Fatalf("first mount: %v", err)
	}
	if err := (&Volume{v: v}).Close(); err != nil {
		t.Fatal(err)
	}
	w := end()
	if len(w.ops) < 4 {
		t.Fatalf("the mount made %d host calls, a replay needs more", len(w.ops))
	}
	want := auFsck(f.snapshot(), true)
	if !want.OK() {
		t.Fatalf("image after the first mount:\n%s", want)
	}
	for _, msg := range auCompareImage(want, d.m) {
		t.Fatalf("the replay lost content: %s", msg)
	}
	for n := range len(w.ops) {
		res, err := auRecover(t, w.prefix(n))
		if err != nil {
			t.Fatalf("mount after %d of %d host calls of the replay: %v", n, len(w.ops), err)
		}
		if !res.OK() {
			t.Fatalf("image after %d of %d host calls of the replay:\n%s", n, len(w.ops), res)
		}
		for _, msg := range auCompareImage(res, d.m) {
			t.Fatalf("after %d host calls of the replay: %s", n, msg)
		}
	}
}

// TestAuditHostileJournal damages the journal superblock and the log of a
// crashed volume. The engine must mount or refuse with an errno, never panic,
// and never grow the host file. Damage ends the log early, so the volume then
// shows an earlier committed state.
func TestAuditHostileJournal(t *testing.T) {
	d := newAuDrv(t)
	auRichWorkload(d)
	d.syncAll()
	crash := d.f.snapshot()
	j, _ := auReadJournal(crash)
	if j == nil {
		t.Fatal("no journal")
	}
	logBlocks := auScanLog(crash, j)
	used := uint32(0)
	for _, tx := range logBlocks {
		used += tx.blocks
	}
	size := crash.size

	rng := rand.New(rand.NewPCG(8, 9))
	rejected, accepted := 0, 0
	for i := range 400 {
		img := crash.clone()
		var desc string
		switch rng.IntN(4) {
		case 0:
			// A byte of the journal superblock.
			blk, _ := j.phys(0)
			off := int64(rng.IntN(0x50))
			img.writeAt([]byte{byte(rng.IntN(256))}, int64(blk)*auBlock+off)
			desc = fmt.Sprintf("superblock byte %#x", off)
		case 1:
			// A byte of a log block.
			pos := j.first + uint32(rng.IntN(int(used)))
			blk, _ := j.phys(pos)
			off := int64(rng.IntN(auBlock))
			img.writeAt([]byte{byte(rng.IntN(256))}, int64(blk)*auBlock+off)
			desc = fmt.Sprintf("log block %d byte %d", pos, off)
		case 2:
			// A word of a descriptor or revoke header area.
			pos := j.first + uint32(rng.IntN(int(used)))
			blk, _ := j.phys(pos)
			var w [4]byte
			auLE.PutUint32(w[:], auInteresting[rng.IntN(len(auInteresting))])
			img.writeAt(w[:], int64(blk)*auBlock+int64(rng.IntN(64))&^3)
			desc = fmt.Sprintf("word near the start of log block %d", pos)
		default:
			// Aim a tag at a block beyond the end of the host file.
			pos := j.first
			blk, _ := j.phys(pos)
			var w [4]byte
			auBE.PutUint32(w[:], uint32(1<<30+rng.IntN(1<<20)))
			img.writeAt(w[:], int64(blk)*auBlock+12)
			desc = "tag block number beyond the host file"
		}
		msg := auGuarded(func() {
			f := newAuFile(img)
			v, err := mountHostFile(f, VolumeOptions{})
			if err != nil {
				rejected++
				return
			}
			accepted++
			if err := (&Volume{v: v}).Close(); err != nil {
				t.Errorf("mutant %d (%s): close: %v", i, desc, err)
			}
			if got, _ := f.Size(); got > size {
				t.Errorf("mutant %d (%s): the host file grew from %d to %d bytes", i, desc, size, got)
			}
		})
		if msg != "" {
			t.Errorf("mutant %d (%s): panic: %s", i, desc, msg)
		}
	}
	t.Logf("%d images refused, %d mounted", rejected, accepted)
}

// TestAuditMigrationReplicaReplaysTheJournal copies a live volume the way a
// pre-copy migration does: the allocated blocks first, then the blocks that a
// drain reports. The journal blocks are allocated blocks, and the replica holds
// a log that the first mount replays. The replica must show every file of the
// source.
func TestAuditMigrationReplicaReplaysTheJournal(t *testing.T) {
	d := newAuDrv(t)
	d.create("/before", 50_000)
	d.syncAll()
	d.e.vol.EnableMigrationTracking()
	runs := d.e.vol.AllocatedBlocks()

	covers := func(blk uint64) bool {
		for _, r := range runs {
			if blk >= r.Block && blk < r.Block+r.Count {
				return true
			}
		}
		return false
	}
	j, _ := auReadJournal(d.f.snapshot())
	if !covers(j.exts[0].pblk) || !covers(j.exts[0].pblk+uint64(j.exts[0].n)-1) {
		t.Fatal("the allocated blocks of the volume do not include the journal")
	}

	replica := newAuPages()
	copyRuns := func(src *auPages, list []BlockExtent) {
		buf := make([]byte, blockSize)
		for _, r := range list {
			for b := r.Block; b < r.Block+r.Count; b++ {
				src.readAt(buf, int64(b)*blockSize)
				replica.writeAt(buf, int64(b)*blockSize)
			}
		}
	}
	copyRuns(d.f.snapshot(), runs)

	d.create("/during", 90_000)
	d.mkdir("/dir")
	dirty, err := d.e.vol.DrainDirtyBlocks()
	if err != nil {
		t.Fatal(err)
	}
	copyRuns(d.f.snapshot(), dirty)
	d.create("/after", 3000)
	last, err := d.e.vol.DrainDirtyBlocks()
	if err != nil {
		t.Fatal(err)
	}
	copyRuns(d.f.snapshot(), last)
	replica.ensure(d.f.snapshot().size)

	res, err := auRecover(t, replica)
	if err != nil {
		t.Fatalf("mount of the replica: %v", err)
	}
	if !res.OK() {
		t.Errorf("replica:\n%s", res)
	}
	for _, msg := range auCompareImage(res, d.m) {
		t.Errorf("replica against the source: %s", msg)
	}
}

// TestAuditReplayNeverWritesIntoTheJournal aims a tag of a committed transaction
// at a block of the journal itself. The replay must skip the tag. The log then
// stays as it was, so a second replay after a crash gives the same volume.
func TestAuditReplayNeverWritesIntoTheJournal(t *testing.T) {
	d := newAuDrv(t)
	auRichWorkload(d)
	d.syncAll()
	crash := d.f.snapshot()
	j, _ := auReadJournal(crash)
	if j == nil {
		t.Fatal("no journal")
	}
	// Plant a transaction after the last one. Its single tag names the last
	// block of the journal, which holds no log yet.
	used := uint32(0)
	for _, tx := range auScanLog(crash, j) {
		used += tx.blocks
	}
	victimPos := j.first + used + 4
	victim, _ := j.phys(victimPos)
	img := crash.clone()
	stamp := bytes.Repeat([]byte{0x5A}, auBlock)
	img.writeAt(stamp, int64(victim)*auBlock)
	data := bytes.Repeat([]byte{0xC3}, auBlock)
	tid := j.sequence + uint32(len(auScanLog(crash, j)))
	txn := encodeTxn(tid, [16]byte{}, []blockWrite{{victim, data}}, nil, 0)
	pos := j.first + used
	for i := range txn.blocks {
		blk, _ := j.phys(pos + i)
		img.writeAt(txn.buf[int(i)*auBlock:int(i+1)*auBlock], int64(blk)*auBlock)
	}
	f := newAuFile(img)
	v, err := mountHostFile(f, VolumeOptions{})
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	if err := (&Volume{v: v}).Close(); err != nil {
		t.Fatal(err)
	}
	var got [auBlock]byte
	f.snapshot().readAt(got[:], int64(victim)*auBlock)
	if bytes.Equal(got[:], data) {
		t.Error("the replay wrote a tag into a block of the journal")
	}
}
