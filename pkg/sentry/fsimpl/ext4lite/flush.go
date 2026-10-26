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

// The dirtyTracker of the specification is spread over three places. Every
// node registers itself in volume.dirtyNodes when a change needs a write.
// Every group has a dirty flag for its bitmaps and its descriptor. The volume
// has flags for the superblock, the descriptor area, and the resize inode.
//
// A flush has two steps. The snapshot copies every dirty structure into block
// images. It runs while the operation gate is closed, so the images show a
// state between two guest operations. The write step then makes the images
// durable. With a journal, the write step is one transaction. Without a
// journal, the write step follows an order that leaves a state that fsckLite
// repairs: extent leaves and xattr blocks first, then inode table blocks, then
// directory blocks, and last bitmaps, descriptors, and the superblock.

import (
	"errors"
	"slices"
)

// blockWrite is one 4 KiB block image for the host file.
type blockWrite struct {
	blk  uint64
	data []byte
}

// inodeImage is the image of one inode for the inode table.
type inodeImage struct {
	ino uint32
	raw [inodeSize]byte
}

// groupSnap records the holds that one flush releases when it succeeds.
type groupSnap struct {
	gi                     uint32
	heldBlocks, heldInodes *bitmap
}

// flushPlan collects the images of one flush.
type flushPlan struct {
	leaves   []blockWrite
	inodes   []inodeImage
	dirs     []blockWrite
	bitmaps  []blockWrite
	descs    []blockWrite
	resize   []blockWrite
	backups  []blockWrite
	super    blockWrite
	hasSuper bool
	backupOf []uint32

	nodes  []*node
	groups []groupSnap
	// revokes lists the blocks that this transaction frees and that an earlier
	// transaction of the log can hold.
	revokes []uint64
	// allocated is true when the guest allocated a block since the last
	// snapshot. Such a transaction needs the file data to be durable first.
	allocated bool
	// snapshot of the flags that a failure restores
	sbDirty, descDirty, resizeDirty, journalInode bool
	// orphanChanged is true when this plan writes a new orphan chain head.
	orphanChanged bool
}

// empty reports whether the plan writes nothing.
func (p *flushPlan) empty() bool {
	return len(p.leaves) == 0 && len(p.inodes) == 0 && len(p.dirs) == 0 && len(p.bitmaps) == 0 &&
		len(p.descs) == 0 && len(p.resize) == 0 && len(p.backups) == 0 && !p.hasSuper && len(p.revokes) == 0
}

// blockNumbers returns the numbers of the blocks that the plan writes.
func (p *flushPlan) blockNumbers() []uint64 {
	var out []uint64
	for _, list := range [][]blockWrite{p.leaves, p.dirs, p.resize, p.bitmaps, p.descs, p.backups} {
		for _, w := range list {
			out = append(out, w.blk)
		}
	}
	for _, im := range p.inodes {
		blk, _ := inodeLocation(im.ino)
		out = append(out, blk)
	}
	if p.hasSuper {
		out = append(out, 0)
	}
	return out
}

// markDirty registers n for the next flush. The caller holds n.mu.
func (v *volume) markDirty(n *node) {
	v.nodeMu.Lock()
	v.dirtyNodes[n.ino] = n
	v.nodeMu.Unlock()
}

// maxDirtyNodes is the number of dirty nodes at which a guest operation waits
// for a flush. A node adds an inode block and a few more blocks to the next
// transaction, so the limit keeps a transaction far below the size of the
// journal.
const maxDirtyNodes = 96

// throttle flushes before an operation when too many nodes wait for a flush.
// The caller holds no lock and has not entered the gate.
func (v *volume) throttle() error {
	v.nodeMu.Lock()
	n := len(v.dirtyNodes)
	v.nodeMu.Unlock()
	if n < maxDirtyNodes {
		return nil
	}
	return v.sync()
}

// sync writes every dirty metadata block and flushes the host file. Callers
// write their own dirty data before they call sync.
func (v *volume) sync() error {
	v.flushMu.Lock()
	defer v.flushMu.Unlock()
	return v.flushLocked()
}

func (v *volume) flushLocked() error {
	if v.readOnly {
		return nil
	}
	if err := v.writePendingHome(); err != nil {
		return err
	}
	plan, err := v.snapshotPlan()
	if err != nil {
		return err
	}
	if plan.empty() {
		return v.syncData()
	}
	if v.j != nil {
		return v.writePlanJournal(plan)
	}
	return v.writePlanDirect(plan)
}

// flushDirectLocked flushes without the journal. The mount uses it to write a
// new journal, and the format uses it for the first image.
func (v *volume) flushDirectLocked() error {
	plan, err := v.snapshotPlan()
	if err != nil {
		return err
	}
	if plan.empty() {
		return nil
	}
	return v.writePlanDirect(plan)
}

// syncData flushes file data that no metadata change covers.
func (v *volume) syncData() error {
	if t, ok := v.hf.(*trackedFile); ok && !t.dataDirty.Load() && (v.j == nil || !v.j.unsynced) {
		return nil
	}
	if err := v.hf.Sync(); err != nil {
		return hostError(err)
	}
	if v.j != nil {
		v.j.unsynced = false
	}
	return nil
}

// snapshotPlan copies the dirty state into block images. The gate is closed
// while it copies.
func (v *volume) snapshotPlan() (*flushPlan, error) {
	v.gate.closeForCopy()
	defer v.gate.openAfterCopy()
	plan := &flushPlan{}

	v.nodeMu.Lock()
	dirty := make([]*node, 0, len(v.dirtyNodes))
	for _, n := range v.dirtyNodes {
		dirty = append(dirty, n)
	}
	clear(v.dirtyNodes)
	v.nodeMu.Unlock()
	slices.SortFunc(dirty, func(a, b *node) int { return int(a.ino) - int(b.ino) })
	for _, n := range dirty {
		n.snapshot(plan)
	}
	plan.nodes = dirty
	v.updateOrphans(plan, dirty)

	v.mu.Lock()
	err := v.snapshotAllocLocked(plan)
	v.mu.Unlock()
	if err != nil {
		v.restorePlan(plan)
		return nil, err
	}
	return plan, nil
}

// snapshotAllocLocked captures the bitmaps, the descriptors, the resize inode,
// and the superblock. The caller holds v.mu.
func (v *volume) snapshotAllocLocked(p *flushPlan) error {
	p.sbDirty, p.descDirty, p.resizeDirty = v.sbDirty, v.descDirty, v.resizeDirty
	p.allocated = v.allocSinceSnap
	v.allocSinceSnap = false
	p.revokes = v.revokePending
	v.revokePending = nil

	if p.orphanChanged {
		v.setSbU32(sbLastOrphan, v.orphanHead)
		v.sbDirty = true
		p.sbDirty = true
	}
	if v.pendingJournalInode {
		p.inodes = append(p.inodes, v.journalInode)
		p.journalInode = true
		v.pendingJournalInode = false
	}
	if v.resizeDirty {
		if err := v.buildResizeLocked(p); err != nil {
			return err
		}
		v.resizeDirty = false
	}

	descBlocksDirty := make(map[uint32]bool)
	for gi, g := range v.groups {
		if !g.dirty && !v.descDirty {
			continue
		}
		if g.dirty {
			var bm [blockSize]byte
			g.blocks.encode(bm[:])
			fill(bm[bitmapWords*8:], 0xFF)
			p.bitmaps = append(p.bitmaps, blockWrite{g.desc.blockBitmap, bm[:]})
			var ib [blockSize]byte
			g.inodes.encode(ib[:])
			fill(ib[bitmapWords*8:], 0xFF)
			p.bitmaps = append(p.bitmaps, blockWrite{g.desc.inodeBitmap, ib[:]})
			descBlocksDirty[uint32(gi)/descsPerBlock] = true
			snap := groupSnap{gi: uint32(gi)}
			if g.heldBlocks != nil {
				c := *g.heldBlocks
				snap.heldBlocks = &c
			}
			if g.heldInodes != nil {
				c := *g.heldInodes
				snap.heldInodes = &c
			}
			p.groups = append(p.groups, snap)
			// The flush records every block that it writes now. A block that a
			// later free releases must wait for the next flush.
			g.freshBlocks, g.freshInodes = nil, nil
			g.dirty = false
		}
	}
	if v.descDirty {
		for i := uint32(0); i < descBlocks(uint32(len(v.groups))); i++ {
			descBlocksDirty[i] = true
		}
	}
	for bi := range descBlocksDirty {
		p.descs = append(p.descs, blockWrite{1 + uint64(bi), v.descBlockLocked(bi)})
	}
	slices.SortFunc(p.descs, func(a, b blockWrite) int { return int(a.blk) - int(b.blk) })

	v.fillSuperLocked()
	var b0 [blockSize]byte
	copy(b0[superOffset:], v.sb[:])
	p.super = blockWrite{0, b0[:]}
	p.hasSuper = v.sbDirty || len(p.bitmaps) > 0 || len(p.descs) > 0 || len(p.resize) > 0

	// A new group with a superblock copy gets its copy of the superblock and of
	// the descriptor blocks. Later flushes leave the copies as they are, as the
	// kernel does outside a resize. A copy of a backup group starts at byte 0
	// of the first block of the group.
	for gi, g := range v.groups {
		if !g.needsBackup {
			continue
		}
		g.needsBackup = false
		p.backupOf = append(p.backupOf, uint32(gi))
		start := groupStart(uint32(gi))
		p.backups = append(p.backups, blockWrite{start, v.backupSuperLocked(uint32(gi))})
		for i := uint32(0); i < descBlocks(uint32(len(v.groups))); i++ {
			p.backups = append(p.backups, blockWrite{start + 1 + uint64(i), v.descBlockLocked(i)})
		}
	}
	v.sbDirty, v.descDirty = false, false

	// The transaction holds these blocks, so a free of one of them needs a
	// revoke record from now on.
	for _, b := range p.blockNumbers() {
		v.inflight[b] = struct{}{}
	}
	return nil
}

// descBlockLocked returns the image of descriptor block bi.
func (v *volume) descBlockLocked(bi uint32) []byte {
	blk := make([]byte, blockSize)
	for j := uint32(0); j < descsPerBlock; j++ {
		gi := bi*descsPerBlock + j
		if gi >= uint32(len(v.groups)) {
			break
		}
		v.groups[gi].desc.encode(blk[j*descSize:])
	}
	return blk
}

// backupSuperLocked returns the image of the superblock copy of backup group
// gi. The copy describes a volume that is not mounted.
func (v *volume) backupSuperLocked(gi uint32) []byte {
	cp := make([]byte, blockSize)
	copy(cp, v.sb[:])
	le.PutUint16(cp[sbBlockGroupNr:], uint16(gi))
	le.PutUint16(cp[sbState:], stateValid)
	le.PutUint32(cp[sbFeatureIncompat:], le.Uint32(cp[sbFeatureIncompat:])&^incompatRecover)
	return cp
}

func fill(b []byte, x byte) {
	for i := range b {
		b[i] = x
	}
}

// fillSuperLocked refreshes the counters of the superblock image.
func (v *volume) fillSuperLocked() {
	blocks := v.blocksCountLocked()
	v.setSbU32(sbBlocksCountLo, uint32(blocks))
	v.setSbU32(sbBlocksCountHi, uint32(blocks>>32))
	v.setSbU32(sbInodesCount, uint32(len(v.groups))*inodesPerGroup)
	v.setSbU32(sbFreeBlocksLo, uint32(v.freeBlocksTotal))
	v.setSbU32(sbFreeBlocksHi, uint32(v.freeBlocksTotal>>32))
	v.setSbU32(sbFreeInodes, uint32(v.freeInodesTotal))
	v.setSbU16(sbReservedGDT, uint16(reservedGDTBlocks(uint32(len(v.groups)))))
	v.setSbU16(sbState, v.state)
	v.setSbU32(sbWtime, uint32(v.now().Unix()))
}

// blockImages returns the images of the plan as whole blocks. The inode
// images patch the blocks of the inode table, which the call reads from the
// host file. A block appears once.
func (p *flushPlan) blockImages(hf hostFile) ([]blockWrite, error) {
	inodeBlocks, err := patchInodeBlocks(hf, p.inodes)
	if err != nil {
		return nil, err
	}
	var out []blockWrite
	seen := make(map[uint64]int)
	add := func(list []blockWrite) {
		for _, w := range list {
			if i, ok := seen[w.blk]; ok {
				out[i] = w
				continue
			}
			seen[w.blk] = len(out)
			out = append(out, w)
		}
	}
	add(p.leaves)
	add(inodeBlocks)
	add(p.dirs)
	add(p.resize)
	add(p.bitmaps)
	add(p.descs)
	add(p.backups)
	if p.hasSuper {
		add([]blockWrite{p.super})
	}
	return out, nil
}

// patchInodeBlocks returns the inode table blocks that the images change. Each
// block holds 16 inodes.
func patchInodeBlocks(hf hostFile, imgs []inodeImage) ([]blockWrite, error) {
	byBlock := make(map[uint64][]*inodeImage)
	var order []uint64
	for i := range imgs {
		blk, _ := inodeLocation(imgs[i].ino)
		if _, ok := byBlock[blk]; !ok {
			order = append(order, blk)
		}
		byBlock[blk] = append(byBlock[blk], &imgs[i])
	}
	slices.Sort(order)
	out := make([]blockWrite, 0, len(order))
	for _, blk := range order {
		buf := make([]byte, blockSize)
		if _, err := hf.ReadAt(buf, int64(blk)*blockSize); err != nil {
			return nil, err
		}
		for _, im := range byBlock[blk] {
			_, off := inodeLocation(im.ino)
			copy(buf[off:off+inodeSize], im.raw[:])
		}
		out = append(out, blockWrite{blk, buf})
	}
	return out, nil
}

// writePlanDirect writes the plan to the home blocks in the order that
// fsckLite can repair, and flushes the host file. A volume without a journal
// uses it.
func (v *volume) writePlanDirect(plan *flushPlan) error {
	inodeBlocks, err := patchInodeBlocks(v.hf, plan.inodes)
	if err != nil {
		v.restorePlan(plan)
		return hostError(err)
	}
	var nodes, groups []blockWrite
	nodes = append(append(append(nodes, plan.leaves...), inodeBlocks...), plan.dirs...)
	groups = append(append(append(append(groups, plan.resize...), plan.bitmaps...), plan.descs...), plan.backups...)

	write := func(list []blockWrite) error {
		for _, w := range list {
			if err := v.writeMeta(w.data, int64(w.blk)*blockSize); err != nil {
				return err
			}
		}
		return nil
	}
	sync := func() error { return hostError(v.hf.Sync()) }
	super := func() error {
		if !plan.hasSuper {
			return nil
		}
		return write([]blockWrite{plan.super})
	}

	// The mount reads the superblock first and rejects a block that lies beyond
	// the volume, so the order depends on the change of the volume size. A volume
	// that grows writes the blocks of the new group, then the new size, and then
	// the inodes that use the new blocks. A volume that shrinks writes the inodes
	// that left the removed groups, then the new size, and then the descriptors.
	// Otherwise the superblock goes last.
	v.mu.Lock()
	now := len(v.groups)
	v.mu.Unlock()
	var steps []func() error
	switch {
	case now > v.diskGroups:
		steps = []func() error{func() error { return write(groups) }, sync, super, sync, func() error { return write(nodes) }, sync}
	case now < v.diskGroups:
		steps = []func() error{func() error { return write(nodes) }, sync, super, sync, func() error { return write(groups) }, sync}
	default:
		steps = []func() error{func() error { return write(nodes) }, func() error { return write(groups) }, sync, super, sync}
	}
	for _, step := range steps {
		if err := step(); err != nil {
			v.restorePlan(plan)
			return err
		}
	}
	v.diskGroups = now
	v.commitPlan(plan)
	v.evictIdle(plan.nodes)
	v.mu.Lock()
	v.flushedOnce = true
	v.mu.Unlock()
	return nil
}

// writePlanJournal commits the plan as a transaction and then writes the
// images to the home blocks.
func (v *volume) writePlanJournal(plan *flushPlan) error {
	images, err := plan.blockImages(v.hf)
	if err != nil {
		v.restorePlan(plan)
		return hostError(err)
	}
	barrier := false
	if t, ok := v.hf.(*trackedFile); ok {
		barrier = plan.allocated && t.dataDirty.Load()
	}
	err = v.commitTxn(images, plan.revokes, barrier)
	if errors.Is(err, errJournalTooBig) {
		err = v.commitChunked(plan, images)
	}
	if err != nil {
		v.restorePlan(plan)
		return err
	}
	v.commitPlan(plan)
	v.writeHome(images)
	v.evictIdle(plan.nodes)
	v.mu.Lock()
	v.flushedOnce = true
	v.mu.Unlock()
	return nil
}

// commitChunked commits a plan that is larger than the journal in several
// transactions. The transactions cannot be atomic together, so the first one
// sets the error flag of the superblock, and the last one clears it. A crash in
// between makes the next mount repair the volume with fsckLite. A plan this big
// is rare: the throttle of the guest operations keeps the dirty set small.
func (v *volume) commitChunked(plan *flushPlan, images []blockWrite) error {
	j := v.j
	limit := int((j.super.maxlen-j.super.first)/2) - 8
	if limit < 16 {
		return errJournalTooBig
	}
	var body []blockWrite
	for _, w := range images {
		if w.blk != 0 {
			body = append(body, w)
		}
	}
	super := func(state uint16) blockWrite {
		var b0 [blockSize]byte
		v.mu.Lock()
		copy(b0[superOffset:], v.sb[:])
		v.mu.Unlock()
		le.PutUint16(b0[superOffset+sbState:], state)
		return blockWrite{0, b0[:]}
	}
	v.mu.Lock()
	state := v.state
	v.mu.Unlock()
	if err := v.commitTxn([]blockWrite{super(state | stateError)}, plan.revokes, plan.allocated); err != nil {
		return err
	}
	for len(body) > 0 {
		n := min(len(body), limit)
		if err := v.commitTxn(body[:n], nil, false); err != nil {
			return err
		}
		body = body[n:]
	}
	return v.commitTxn([]blockWrite{super(state)}, nil, false)
}

// writeHome writes the committed images to their home blocks. A failure keeps
// the image in the overlay of the host file and in the pending list, so reads
// stay correct and the next flush writes it again. The transaction is durable,
// so the failure does not fail the flush.
func (v *volume) writeHome(images []blockWrite) {
	t, _ := v.hf.(*trackedFile)
	for _, w := range images {
		if err := v.writeMeta(w.data, int64(w.blk)*blockSize); err != nil && t != nil {
			t.pmu.Lock()
			if t.pending == nil {
				t.pending = make(map[uint64][]byte)
			}
			t.pending[w.blk] = w.data
			t.pmu.Unlock()
		}
	}
	v.j.unsynced = true
}

// writePendingHome retries the home writes that failed after a commit.
func (v *volume) writePendingHome() error {
	t, ok := v.hf.(*trackedFile)
	if !ok {
		return nil
	}
	t.pmu.Lock()
	list := make([]blockWrite, 0, len(t.pending))
	for blk, data := range t.pending {
		list = append(list, blockWrite{blk, data})
	}
	t.pmu.Unlock()
	for _, w := range list {
		if err := v.writeMeta(w.data, int64(w.blk)*blockSize); err != nil {
			return err
		}
		t.pmu.Lock()
		delete(t.pending, w.blk)
		t.pmu.Unlock()
	}
	return nil
}

// commitPlan releases the holds that the flush covered. It runs after the
// plan is durable.
func (v *volume) commitPlan(p *flushPlan) {
	v.mu.Lock()
	defer v.mu.Unlock()
	clear(v.inflight)
	for _, s := range p.groups {
		if s.gi >= uint32(len(v.groups)) {
			continue
		}
		g := v.groups[s.gi]
		if s.heldBlocks != nil && g.heldBlocks != nil {
			g.heldBlocks.andNot(s.heldBlocks)
			now := g.heldBlocks.count()
			v.heldBlocksTotal -= uint64(g.heldBlockCount - now)
			g.heldBlockCount = now
			if now == 0 {
				g.heldBlocks = nil
			}
		}
		if s.heldInodes != nil && g.heldInodes != nil {
			g.heldInodes.andNot(s.heldInodes)
			now := g.heldInodes.count()
			v.heldInodesTotal -= uint64(g.heldInodeCount - now)
			g.heldInodeCount = now
			if now == 0 {
				g.heldInodes = nil
			}
		}
	}
}

// restorePlan makes the next flush write again what a failed flush tried.
func (v *volume) restorePlan(p *flushPlan) {
	for _, n := range p.nodes {
		n.markAllDirty()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	clear(v.inflight)
	for _, s := range p.groups {
		if s.gi < uint32(len(v.groups)) {
			v.groups[s.gi].dirty = true
		}
	}
	v.sbDirty = v.sbDirty || p.sbDirty
	v.descDirty = v.descDirty || p.descDirty
	v.resizeDirty = v.resizeDirty || p.resizeDirty
	v.allocSinceSnap = v.allocSinceSnap || p.allocated
	v.revokePending = append(p.revokes, v.revokePending...)
	if p.journalInode {
		v.pendingJournalInode = true
	}
	if p.orphanChanged {
		for _, n := range v.orphans {
			n.markAllDirty()
		}
	}
	for _, gi := range p.backupOf {
		if gi < uint32(len(v.groups)) {
			v.groups[gi].needsBackup = true
		}
	}
}

// writeSuperblockNow writes block 0 and flushes the host file. A mount of a
// volume without a journal uses it to clear the valid bit before the first
// write of a guest.
func (v *volume) writeSuperblockNow() error {
	v.mu.Lock()
	v.fillSuperLocked()
	var b0 [blockSize]byte
	copy(b0[superOffset:], v.sb[:])
	v.sbDirty = false
	v.mu.Unlock()
	if err := v.writeMeta(b0[:], 0); err != nil {
		return err
	}
	return hostError(v.hf.Sync())
}
