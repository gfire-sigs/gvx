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
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// volumeOptions configures openVolume.
type volumeOptions struct {
	// readOnly opens the volume without any write to the host file. A volume
	// that was not unmounted cleanly fails to open read-only.
	readOnly bool
	// now returns the current time. The default is time.Now.
	now func() time.Time
}

// volume is an open ext4lite image. Every method is safe for concurrent use.
//
// The lock order is: node.mu, then volume.mu. flushMu is only held by flush,
// which takes node.mu and volume.mu one after the other.
type volume struct {
	hf       hostFile
	readOnly bool
	now      func() time.Time

	// flushMu serializes flushes and the close.
	flushMu sync.Mutex

	// mu protects the allocator state and the fields up to the next blank
	// line.
	mu              sync.Mutex
	groups          []*group
	freeBlocksTotal uint64
	freeInodesTotal uint64
	heldBlocksTotal uint64
	heldInodesTotal uint64
	hostBytes       int64
	sbDirty         bool
	descDirty       bool
	resizeDirty     bool
	sb              [superSize]byte
	resizeDind      uint64
	state           uint16
	closed          bool
	flushedOnce     bool
	// fixups lists the repairs that fsckLite queued for the first mount.
	fixups []func() error
	// migTracking is true while a live migration records the written blocks in
	// group.migDirty. EnableMigrationTracking sets it.
	//
	// +checklocks:mu
	migTracking bool
	// migOn mirrors migTracking for trackedFile.WriteAt, which skips v.mu while
	// no migration runs. Only the holder of v.mu writes it.
	migOn atomic.Bool

	// nodeMu protects nodes and dirtyNodes.
	nodeMu     sync.Mutex
	nodes      map[uint32]*node
	dirtyNodes map[uint32]*node
}

// blocksCountLocked returns the size of the volume in blocks.
func (v *volume) blocksCountLocked() uint64 { return uint64(len(v.groups)) * blocksPerGroup }

// numGroups returns the number of block groups.
func (v *volume) numGroups() uint32 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return uint32(len(v.groups))
}

func (v *volume) sbU32(off int) uint32       { return le.Uint32(v.sb[off:]) }
func (v *volume) sbU16(off int) uint16       { return le.Uint16(v.sb[off:]) }
func (v *volume) setSbU32(off int, x uint32) { le.PutUint32(v.sb[off:], x) }
func (v *volume) setSbU16(off int, x uint16) { le.PutUint16(v.sb[off:], x) }

// checkSuperblock validates the superblock against the ext4lite profile. A
// volume of another profile is not safe to mount, because the allocator
// assumes the geometry.
func checkSuperblock(sb []byte, hostSize int64) (groups uint32, err error) {
	if le.Uint16(sb[sbMagic:]) != superMagic {
		return 0, corrupt("bad superblock magic %#x", le.Uint16(sb[sbMagic:]))
	}
	checks := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"revision level", uint64(le.Uint32(sb[sbRevLevel:])), 1},
		{"log block size", uint64(le.Uint32(sb[sbLogBlockSize:])), 2},
		{"blocks per group", uint64(le.Uint32(sb[sbBlocksPerGroup:])), blocksPerGroup},
		{"clusters per group", uint64(le.Uint32(sb[sbClustersPerGrp:])), blocksPerGroup},
		{"inodes per group", uint64(le.Uint32(sb[sbInodesPerGroup:])), inodesPerGroup},
		{"inode size", uint64(le.Uint16(sb[sbInodeSize:])), inodeSize},
		{"descriptor size", uint64(le.Uint16(sb[sbDescSize:])), descSize},
		{"first data block", uint64(le.Uint32(sb[sbFirstDataBlock:])), 0},
		{"first inode", uint64(le.Uint32(sb[sbFirstIno:])), firstIno},
		{"compat features", uint64(le.Uint32(sb[sbFeatureCompat:])), featCompat},
		{"incompat features", uint64(le.Uint32(sb[sbFeatureIncompat:])), featIncompat},
		{"ro_compat features", uint64(le.Uint32(sb[sbFeatureRoCompat:])), featRoCompat},
	}
	for _, c := range checks {
		if c.got != c.want {
			return 0, corrupt("superblock %s is %d, want %d", c.name, c.got, c.want)
		}
	}
	blocks := uint64(le.Uint32(sb[sbBlocksCountLo:])) | uint64(le.Uint32(sb[sbBlocksCountHi:]))<<32
	if blocks == 0 || blocks%blocksPerGroup != 0 || blocks/blocksPerGroup > maxGroups {
		return 0, corrupt("superblock block count %d is not 1 to %d groups", blocks, maxGroups)
	}
	groups = uint32(blocks / blocksPerGroup)
	if got := uint64(le.Uint32(sb[sbInodesCount:])); got != uint64(groups)*inodesPerGroup {
		return 0, corrupt("superblock inode count %d, want %d", got, uint64(groups)*inodesPerGroup)
	}
	if got, want := uint32(le.Uint16(sb[sbReservedGDT:])), reservedGDTBlocks(groups); got != want {
		return 0, corrupt("superblock reserves %d descriptor blocks, want %d", got, want)
	}
	return groups, nil
}

// openVolume mounts the image in hf. It checks the superblock and the group
// descriptors, loads the bitmaps, and runs fsckLite when the last mount did not
// end cleanly. A writable mount clears the valid bit before it returns, so a
// crash after that point triggers fsckLite at the next mount.
func openVolume(hf hostFile, opts volumeOptions) (*volume, error) {
	v := &volume{
		hf:         hf,
		readOnly:   opts.readOnly,
		now:        opts.now,
		nodes:      make(map[uint32]*node),
		dirtyNodes: make(map[uint32]*node),
	}
	// Every write to the image goes through v.hf, so one wrapper sees them all.
	v.hf = &trackedFile{hostFile: hf, v: v}
	if v.now == nil {
		v.now = time.Now
	}
	size, err := hf.Size()
	if err != nil {
		return nil, hostError(err)
	}
	v.hostBytes = size
	var block0 [blockSize]byte
	if _, err := hf.ReadAt(block0[:], 0); err != nil {
		return nil, hostError(err)
	}
	copy(v.sb[:], block0[superOffset:superOffset+superSize])
	groups, err := checkSuperblock(v.sb[:], size)
	if err != nil {
		return nil, err
	}
	v.state = le.Uint16(v.sb[sbState:])

	if err := v.loadGroups(groups); err != nil {
		return nil, err
	}
	if v.hf.Tier() != tierFallback {
		if want := int64(groups) * groupBytes; size < want {
			if opts.readOnly {
				return nil, corrupt("host file has %d bytes, the volume needs %d", size, want)
			}
			if err := hf.EnsureSize(want); err != nil {
				return nil, hostError(err)
			}
			v.hostBytes = want
		}
	}

	if v.state&stateValid == 0 {
		if err := v.fsckLite(); err != nil {
			return nil, err
		}
	}
	if err := v.loadResizeInode(); err != nil {
		return nil, err
	}
	root, err := v.getNode(rootIno)
	if err != nil {
		return nil, err
	}
	if !root.isDir() {
		return nil, corrupt("root inode is not a directory")
	}
	root.mu.Lock()
	err = root.loadDirLocked()
	root.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := v.runFixups(); err != nil {
		return nil, err
	}
	if !v.readOnly {
		// Clear the valid bit first. The next mount runs fsckLite when this
		// mount ends abnormally.
		v.state &^= stateValid
		v.sbDirty = true
		if err := v.writeSuperblockNow(); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// loadGroups reads the group descriptors and the bitmaps.
func (v *volume) loadGroups(n uint32) error {
	v.groups = make([]*group, n)
	var blk [blockSize]byte
	for gi := uint32(0); gi < n; gi++ {
		if gi%descsPerBlock == 0 {
			if _, err := v.hf.ReadAt(blk[:], int64(1+gi/descsPerBlock)*blockSize); err != nil {
				return hostError(err)
			}
		}
		g := &group{}
		g.desc.decode(blk[(gi%descsPerBlock)*descSize:])
		if g.desc.blockBitmap != blockBitmapBlock(gi) || g.desc.inodeBitmap != inodeBitmapBlock(gi) || g.desc.inodeTable != inodeTableStart(gi) {
			return corrupt("group %d descriptor places its metadata at %d, %d, %d", gi, g.desc.blockBitmap, g.desc.inodeBitmap, g.desc.inodeTable)
		}
		var bm [blockSize]byte
		if _, err := v.hf.ReadAt(bm[:], int64(g.desc.blockBitmap)*blockSize); err != nil {
			return hostError(err)
		}
		g.blocks.decode(bm[:])
		if _, err := v.hf.ReadAt(bm[:], int64(g.desc.inodeBitmap)*blockSize); err != nil {
			return hostError(err)
		}
		g.inodes.decode(bm[:])
		for b := uint32(0); b < metaBlocksOf(gi); b++ {
			if !g.blocks.test(b) {
				return corrupt("group %d block bitmap frees metadata block %d", gi, b)
			}
		}
		g.desc.freeBlocks = blocksPerGroup - g.blocks.count()
		g.desc.freeInodes = inodesPerGroup - g.inodes.count()
		v.groups[gi] = g
		v.freeBlocksTotal += uint64(g.desc.freeBlocks)
		v.freeInodesTotal += uint64(g.desc.freeInodes)
	}
	return nil
}

// close performs the unmount. It compacts the trailing groups, flushes the
// metadata, truncates the host file, marks the volume clean, and releases the
// host file. A second call returns nil.
func (v *volume) close() error {
	v.flushMu.Lock()
	defer v.flushMu.Unlock()
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		return nil
	}
	v.closed = true
	v.mu.Unlock()

	var errs []error
	if !v.readOnly {
		if err := v.shutdownLocked(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := v.hf.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// statfsInfo is the result of volume.statfs.
type statfsInfo struct {
	blocks, bfree uint64
	files, ffree  uint64
}

// statfs reports the space of the volume. The free space adds the room that the
// volume can still gain by new groups, limited by the size limit of 64 GiB and
// by the free space of the host volume.
func (v *volume) statfs() statfsInfo {
	v.mu.Lock()
	defer v.mu.Unlock()
	groups := uint64(len(v.groups))
	var meta uint64
	for gi := range v.groups {
		meta += uint64(metaBlocksOf(uint32(gi)))
	}
	total := groups*blocksPerGroup - meta
	growBlocks := uint64(0)
	if groups < maxGroups {
		growBlocks = (maxGroups - groups) * (blocksPerGroup - uint64(headerBlocks) - 2 - inodeTableBlocks)
		if avail, err := v.hf.AvailBytes(); err == nil {
			growBlocks = min(growBlocks, avail/blockSize)
		}
	}
	growInodes := uint64(0)
	if groups < maxGroups {
		growInodes = (maxGroups - groups) * inodesPerGroup
		growInodes = min(growInodes, growBlocks)
	}
	return statfsInfo{
		blocks: total + growBlocks,
		bfree:  v.freeBlocksTotal + growBlocks,
		files:  groups*inodesPerGroup + growInodes,
		ffree:  v.freeInodesTotal + growInodes,
	}
}

// errVolumeClosed reports a use of a volume after close.
var errVolumeClosed = fmt.Errorf("ext4lite: the volume is closed: %w", linuxerr.EIO)
