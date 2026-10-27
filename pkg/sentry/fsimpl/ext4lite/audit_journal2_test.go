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
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

// auFakeJournal returns an image with a journal of 1024 blocks that starts at
// host block 100, and the info of an independent reader for it.
func auFakeJournal() (*auPages, *auJInfo, journalSuper) {
	img := newAuPages()
	img.ensure(2000 * auBlock)
	j := &auJInfo{exts: []auExtent{{lblk: 0, n: 1024, pblk: 100}}, blocks: 1024, maxlen: 1024, first: 1, sequence: 7, start: 1, compat: 1, incompat: 3}
	s := journalSuper{blockType: jbd2BlockSuperV2, maxlen: 1024, first: 1, sequence: 7, start: 1, compat: jbd2WrittenCompat, incompat: jbd2WrittenIncompat}
	return img, j, s
}

// TestAuditJournalCodecsAgree writes a transaction with the engine encoder and
// reads it with the independent reader and with the engine scanner. A
// transaction with 700 blocks needs three descriptor blocks. 1500 revoke
// records need two revoke blocks. One image starts with the magic number of the
// journal, so the log must escape it.
func TestAuditJournalCodecsAgree(t *testing.T) {
	img, info, super := auFakeJournal()
	rng := rand.New(rand.NewPCG(5, 6))
	var images []blockWrite
	want := map[uint64][]byte{}
	for i := range 700 {
		data := make([]byte, blockSize)
		for k := range data {
			data[k] = byte(rng.IntN(256))
		}
		if i == 123 {
			be.PutUint32(data[0:], jbd2Magic)
		}
		blk := uint64(5000 + i*3)
		images = append(images, blockWrite{blk, data})
		want[blk] = data
	}
	var revokes []uint64
	for i := range 1500 {
		revokes = append(revokes, uint64(70000+i))
	}
	var uuid [16]byte
	uuid[0] = 9
	txn := encodeTxn(7, uuid, images, revokes, 1700000000)
	if txn.blocks != txnBlocks(len(images), len(revokes)) {
		t.Fatalf("encodeTxn made %d blocks, txnBlocks says %d", txn.blocks, txnBlocks(len(images), len(revokes)))
	}
	img.writeAt(txn.buf, (100+1)*auBlock)

	got := auScanLog(img, info)
	if len(got) != 1 {
		t.Fatalf("independent reader found %d transactions, want 1", len(got))
	}
	if len(got[0].writes) != len(want) || len(got[0].revoked) != len(revokes) {
		t.Fatalf("independent reader: %d writes and %d revokes, want %d and %d", len(got[0].writes), len(got[0].revoked), len(want), len(revokes))
	}
	for blk, data := range want {
		if !bytes.Equal(got[0].writes[blk], data) {
			t.Fatalf("independent reader: block %d differs (escape of the magic number?)", blk)
		}
	}

	f := newAuFile(img)
	v := &volume{hf: f}
	j := &journal{extents: []extent{{lblk: 0, n: 1024, pblk: 100}}, super: super}
	engine, err := scanLog(&j.super, func(pos uint32) ([]byte, error) { return v.readLog(j, pos) })
	if err != nil {
		t.Fatal(err)
	}
	if len(engine) != 1 || len(engine[0].tags) != len(images) || len(engine[0].revokes) != len(revokes) {
		t.Fatalf("engine scanner: %d transactions, %d tags, %d revokes", len(engine), len(engine[0].tags), len(engine[0].revokes))
	}
}

// TestAuditJournalScanStopsAtDamage damages one block of the second of three
// transactions. The log ends before it, so a replay applies only the first
// transaction. A checksum mismatch and a wrong sequence number both end the
// log.
func TestAuditJournalScanStopsAtDamage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		damage func(img *auPages, at int64)
	}{
		{"flipped data byte", func(img *auPages, at int64) { img.writeAt([]byte{0x5A}, at+auBlock+77) }},
		{"wrong sequence number", func(img *auPages, at int64) { img.writeAt([]byte{0, 0, 0, 99}, at+8) }},
		{"missing commit block", func(img *auPages, at int64) { img.writeAt(make([]byte, auBlock), at+2*auBlock) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img, info, super := auFakeJournal()
			pos := int64(1)
			var starts []int64
			for tid := uint32(7); tid < 10; tid++ {
				data := bytes.Repeat([]byte{byte(tid)}, blockSize)
				txn := encodeTxn(tid, [16]byte{}, []blockWrite{{uint64(3000 + tid), data}}, nil, 0)
				starts = append(starts, (100+pos)*auBlock)
				img.writeAt(txn.buf, (100+pos)*auBlock)
				pos += int64(txn.blocks)
			}
			tc.damage(img, starts[1])
			if got := auScanLog(img, info); len(got) != 1 {
				t.Fatalf("independent reader found %d transactions, want 1", len(got))
			}
			f := newAuFile(img)
			v := &volume{hf: f}
			j := &journal{extents: []extent{{lblk: 0, n: 1024, pblk: 100}}, super: super}
			engine, err := scanLog(&j.super, func(p uint32) ([]byte, error) { return v.readLog(j, p) })
			if err != nil || len(engine) != 1 {
				t.Fatalf("engine scanner: %d transactions, error %v, want 1", len(engine), err)
			}
		})
	}
}

// TestAuditJournalLayoutOfAFlush runs three syncs and reads the log of the
// live image. The log holds three transactions with consecutive sequence
// numbers, and each commit block carries the checksum that the independent
// code computes.
func TestAuditJournalLayoutOfAFlush(t *testing.T) {
	d := newAuDrv(t)
	d.syncAll()
	d.mkdir("/a")
	d.syncAll()
	d.create("/a/f", 10_000)
	d.syncAll()
	d.rename("/a/f", "/a/g")
	d.syncAll()

	img := d.f.snapshot()
	j, problems := auReadJournal(img)
	if len(problems) != 0 {
		t.Fatalf("journal problems: %v", problems)
	}
	if j == nil || j.start != j.first {
		t.Fatalf("a mounted volume has a log that starts at %v, want the first block", j)
	}
	txns := auScanLog(img, j)
	if len(txns) < 3 {
		t.Fatalf("the log holds %d transactions after 3 changing syncs, want at least 3", len(txns))
	}
	for i := 1; i < len(txns); i++ {
		if txns[i].tid != txns[i-1].tid+1 {
			t.Errorf("transaction %d has the sequence number %d after %d", i, txns[i].tid, txns[i-1].tid)
		}
	}
	d.e.unmount()
	if j, _ := auReadJournal(d.f.snapshot()); j.start != 0 {
		t.Errorf("after a clean unmount the log starts at %d, want 0", j.start)
	}
}

// TestAuditJournalReplayAloneGivesConsistency crashes at every host call and at
// random subsets of the writes of each epoch. The raw image after the replay of
// the independent reader must pass the structural checks of the oracle. The
// engine plays no part, so the test shows what the Linux kernel sees.
func TestAuditJournalReplayAloneGivesConsistency(t *testing.T) {
	samples := auSamples()
	for _, c := range auCrashTests {
		t.Run(c.name, func(t *testing.T) {
			w, _, _ := auRun(t, c)
			check := func(label string, img *auPages) {
				t.Helper()
				replayed, _ := auReplayImage(img)
				if res := auFsck(replayed, false); !res.OK() {
					t.Fatalf("%s: raw image after replay is inconsistent:\n%s", label, res)
				}
			}
			for n := 0; n <= len(w.ops); n++ {
				check(fmt.Sprintf("after %d host calls", n), w.prefix(n))
			}
			rng := auSeed("replay-alone-" + c.name)
			for _, ep := range w.epochs() {
				if ep[1] <= ep[0] {
					continue
				}
				for s := range samples {
					keep := []float64{0.3, 0.6, 0.9}[s%3]
					check(fmt.Sprintf("epoch %v sample %d", ep, s), w.powerLoss(ep[0], ep[1], rng, keep, s%2 == 1))
				}
			}
		})
	}
}

// TestAuditJournalWrapStaysInsideTheFile writes 1500 small commits, which is
// more than the journal holds. The log starts again several times. The host
// file must not grow, and the sequence numbers must keep rising.
func TestAuditJournalWrapStaysInsideTheFile(t *testing.T) {
	d := newAuDrv(t)
	start, _ := d.f.Size()
	var lastSeq uint32
	resets := 0
	for i := range 1500 {
		d.create(fmt.Sprintf("/f%04d", i), 10)
		d.syncAll()
		j, _ := auReadJournal(d.f.snapshot())
		if j.sequence < lastSeq {
			t.Fatalf("the journal sequence went from %d to %d", lastSeq, j.sequence)
		}
		if j.sequence != lastSeq && lastSeq != 0 {
			resets++
		}
		lastSeq = j.sequence
	}
	if end, _ := d.f.Size(); end != start {
		t.Errorf("the host file grew from %d to %d bytes", start, end)
	}
	if resets < 2 {
		t.Errorf("the log started again %d times, want at least 2 for 1500 commits", resets)
	}
	res, err := auRecover(t, d.f.snapshot())
	if err != nil {
		t.Fatalf("mount after the run: %v", err)
	}
	if !res.OK() {
		t.Errorf("image:\n%s", res)
	}
	for _, msg := range auCompareImage(res, d.m) {
		t.Errorf("%s", msg)
	}
}

// TestAuditJournalRevokeProtectsReusedBlocks frees a directory block that an
// earlier transaction of the log holds, reuses the block for file data, and
// crashes. The replay must not write the old directory block over the data.
// The revoke record of the rmdir stops it.
func TestAuditJournalRevokeProtectsReusedBlocks(t *testing.T) {
	d := newAuDrv(t)
	d.mkdir("/dir")
	d.syncAll()
	before := auFsck(d.f.snapshot(), false)
	var dirBlock uint64
	for blk, owner := range before.Blocks {
		if owner == before.Tree["/dir"].ino {
			dirBlock = blk
		}
	}
	if dirBlock == 0 {
		t.Fatal("the oracle found no block of /dir")
	}
	d.rmdir("/dir")
	d.syncAll()
	d.create("/data", 5*blockSize)
	d.syncAll()

	img := d.f.snapshot()
	replayed, txns := auReplayImage(img)
	revoked := false
	for _, tx := range txns {
		revoked = revoked || slices.Contains(tx.revoked, dirBlock)
	}
	if !revoked {
		t.Fatalf("no transaction of the log revokes the freed block %d", dirBlock)
	}
	res := auFsck(replayed, false)
	if owner := res.Blocks[dirBlock]; owner != uint32(d.e.mustStat("/data").Ino) {
		t.Fatalf("the data of /data does not reuse block %d, so the test proves nothing", dirBlock)
	}
	if got := res.Tree["/data"]; got == nil || !bytes.Equal(got.data, d.m.nodes["/data"].data) {
		t.Errorf("independent replay: /data does not hold its data")
	}
	rec, err := auRecover(t, img)
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	if got := rec.Tree["/data"]; got == nil || !bytes.Equal(got.data, d.m.nodes["/data"].data) {
		t.Errorf("engine replay: /data does not hold its data")
	}
}

// TestAuditJournalOrderedDataBarrier counts host flush calls. A commit that
// allocates a block flushes the file data first, so it needs two flushes. A
// commit that only overwrites needs one.
func TestAuditJournalOrderedDataBarrier(t *testing.T) {
	d := newAuDrv(t)
	d.create("/db", 1<<20)
	d.syncAll()
	fd := d.e.mustOpen("/db", linux.O_WRONLY)
	defer fd.DecRef(d.e.ctx)

	mark := d.f.mark()
	d.e.pwrite(fd, auFill(1, 0, 4096), 0)
	if err := fd.Sync(d.e.ctx); err != nil {
		t.Fatal(err)
	}
	if got := d.f.syncsSince(mark); got != 1 {
		t.Errorf("an overwrite and its fsync made %d host flush calls, want 1", got)
	}

	mark = d.f.mark()
	d.e.pwrite(fd, auFill(1, 1<<20, 4096), 1<<20)
	if err := fd.Sync(d.e.ctx); err != nil {
		t.Fatal(err)
	}
	if got := d.f.syncsSince(mark); got != 2 {
		t.Errorf("an append and its fsync made %d host flush calls, want 2", got)
	}
}

// TestAuditOrphanChainIsWrittenToTheSuperblock unlinks three open files and
// syncs. The superblock names the first inode of a chain, and the field dtime
// of each inode names the next one, as the Linux kernel expects.
func TestAuditOrphanChainIsWrittenToTheSuperblock(t *testing.T) {
	d := newAuDrv(t)
	names := []string{"/a", "/b", "/c"}
	var inos []uint32
	for _, p := range names {
		d.create(p, 20_000)
	}
	d.syncAll()
	for _, p := range names {
		inos = append(inos, uint32(d.e.mustStat(p).Ino))
	}
	for _, p := range names {
		fd := d.e.mustOpen(p, linux.O_RDONLY)
		defer fd.DecRef(d.e.ctx)
		d.unlink(p)
	}
	d.syncAll()

	img := d.f.snapshot()
	replayed, _ := auReplayImage(img)
	var sb [1024]byte
	replayed.readAt(sb[:], 1024)
	head := auLE.Uint32(sb[0xE8:])
	if head == 0 {
		t.Fatal("the superblock names no orphan after three unlinks of open files")
	}
	seen := map[uint32]bool{}
	for ino := head; ino != 0; {
		if seen[ino] {
			t.Fatalf("the orphan chain has a cycle at inode %d", ino)
		}
		seen[ino] = true
		var raw [auISize]byte
		blk, off := uint64(4)+uint64((ino-1)/16), int64((ino-1)%16)*auISize
		replayed.readAt(raw[:], int64(blk)*auBlock+off)
		if links := auLE.Uint16(raw[0x1A:]); links != 0 {
			t.Errorf("orphan inode %d has %d links", ino, links)
		}
		ino = auLE.Uint32(raw[0x14:])
	}
	for _, ino := range inos {
		if !seen[ino] {
			t.Errorf("inode %d is not in the orphan chain", ino)
		}
	}
	// A crash now must return the blocks of the three files.
	res, err := auRecover(t, img)
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	if !res.OK() {
		t.Errorf("repaired image:\n%s", res)
	}
}
