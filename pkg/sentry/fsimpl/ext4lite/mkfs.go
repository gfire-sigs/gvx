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

// formatVolume writes an empty volume of one block group into hf. The file
// must be empty. The result has the root directory and the resize inode, and
// it has the valid bit set, as mke2fs leaves a new file system.
func formatVolume(hf hostFile, now time.Time) error {
	if err := hf.Truncate(0); err != nil {
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
		hostBytes:  size,
		state:      stateValid,
	}
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
	if err := v.sync(); err != nil {
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
