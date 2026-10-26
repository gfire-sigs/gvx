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
	"crypto/rand"
	"time"
)

// mkfsMarker starts block 0 of a file while the first format runs. The boot
// area of an ext4 file system, the first 1024 bytes, is unused, so the marker
// does not collide with the format. The final write of block 0 clears it. A
// file that has the marker and no superblock is a format that a crash cut
// short. No guest ever mounted it, so the next open formats it again.
const mkfsMarker = "EXT4LITE-MKFS-IN-PROGRESS"

// unfinishedFormat reports whether hf holds the remains of a format that did
// not finish.
func unfinishedFormat(hf hostFile) (bool, error) {
	var b [blockSize]byte
	if _, err := hf.ReadAt(b[:], 0); err != nil {
		return false, hostError(err)
	}
	return string(b[:len(mkfsMarker)]) == mkfsMarker && le.Uint16(b[superOffset+sbMagic:]) != superMagic, nil
}

// formatVolume writes an empty volume of one block group into hf. The file
// must be empty. The result has the root directory, the resize inode, and the
// journal, and it has the valid bit set, as mke2fs leaves a new file system.
//
// The format is restartable. It writes the marker first, flushes the file, and
// writes the superblock last, after a second flush. A crash in between leaves
// a file that unfinishedFormat recognizes.
func formatVolume(hf hostFile, now time.Time) error {
	if err := hf.Truncate(0); err != nil {
		return hostError(err)
	}
	var marker [blockSize]byte
	copy(marker[:], mkfsMarker)
	if _, err := hf.WriteAt(marker[:], 0); err != nil {
		return hostError(err)
	}
	if err := hf.Sync(); err != nil {
		return hostError(err)
	}
	if err := hf.EnsureSize(groupBytes); err != nil {
		return hostError(err)
	}
	size, err := hf.Size()
	if err != nil {
		return hostError(err)
	}
	v := &volume{
		hf:         hf,
		now:        func() time.Time { return now },
		nodes:      make(map[uint32]*node),
		dirtyNodes: make(map[uint32]*node),
		inflight:   make(map[uint64]struct{}),
		orphans:    make(map[uint32]*node),
		hostBytes:  size,
		state:      stateValid,
		// The first image writes its superblock last, as a format that a crash
		// cut short must leave no superblock behind.
		diskGroups: 1,
	}
	v.gate.init()
	g := newGroup(0)
	for i := uint32(0); i < firstIno-1; i++ {
		g.inodes.set(i)
	}
	g.desc.freeInodes = inodesPerGroup - (firstIno - 1)
	g.desc.usedDirs = 1
	v.groups = []*group{g}
	v.freeBlocksTotal = uint64(g.desc.freeBlocks)
	v.freeInodesTotal = uint64(g.desc.freeInodes)
	v.initSuperLocked(now)
	v.sbDirty, v.descDirty, v.resizeDirty = true, true, true
	// The journal takes its blocks before the root directory does. The file is
	// new, so the journal area already reads as zeros.
	if _, err := v.createJournal(false); err != nil {
		return err
	}

	ts := tstamp{sec: now.Unix(), nsec: uint32(now.Nanosecond())}
	root := &node{
		v: v, ino: rootIno, mode: modeDir | 0o755, links: 2, flags: flagExtents,
		atime: ts, mtime: ts, ctime: ts, crtime: ts,
	}
	root.dir = &dirData{index: make(map[string]*dirEntry)}
	v.nodes[rootIno] = root
	if err := root.initDir(rootIno); err != nil {
		return err
	}
	if err := v.flushDirectLocked(); err != nil {
		return err
	}
	return nil
}

// initSuperLocked fills the fixed fields of the superblock.
func (v *volume) initSuperLocked(now time.Time) {
	sb := v.sb[:]
	clear(sb)
	t := uint32(now.Unix())
	le.PutUint32(sb[sbLogBlockSize:], 2)
	le.PutUint32(sb[sbLogClusterSize:], 2)
	le.PutUint32(sb[sbBlocksPerGroup:], blocksPerGroup)
	le.PutUint32(sb[sbClustersPerGrp:], blocksPerGroup)
	le.PutUint32(sb[sbInodesPerGroup:], inodesPerGroup)
	le.PutUint16(sb[sbMaxMntCount:], 0xFFFF)
	le.PutUint16(sb[sbMagic:], superMagic)
	le.PutUint16(sb[sbErrors:], 1)
	le.PutUint32(sb[sbLastCheck:], t)
	le.PutUint32(sb[sbRevLevel:], 1)
	le.PutUint32(sb[sbFirstIno:], firstIno)
	le.PutUint16(sb[sbInodeSize:], inodeSize)
	le.PutUint32(sb[sbFeatureCompat:], featCompat)
	le.PutUint32(sb[sbFeatureIncompat:], featIncompat)
	le.PutUint32(sb[sbFeatureRoCompat:], featRoCompat)
	// A failure of the random source leaves the identifiers at zero, which
	// does not harm a private volume.
	_, _ = rand.Read(sb[sbUUID : sbUUID+16])
	_, _ = rand.Read(sb[sbHashSeed : sbHashSeed+16])
	sb[sbDefHashVersion] = 1
	le.PutUint16(sb[sbDescSize:], descSize)
	le.PutUint32(sb[sbDefaultMountOpt:], 0xC)
	le.PutUint32(sb[sbMkfsTime:], t)
	le.PutUint16(sb[sbMinExtraIsize:], extraIsize)
	le.PutUint16(sb[sbWantExtraIsize:], extraIsize)
	le.PutUint32(sb[sbFlags:], 2)
}
