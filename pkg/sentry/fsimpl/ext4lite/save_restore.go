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
	goContext "context"
	"errors"
	"fmt"
	"math"
	"slices"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

type restoreContextID int

const (
	// CtxRestoreVolumeMap is a Context.Value key for a map[string]*Volume
	// that maps each filesystem UniqueID to its pre-opened Volume.
	CtxRestoreVolumeMap restoreContextID = iota
)

// RestoreVolumeMount pairs a filesystem UniqueID with its pre-opened Volume.
type RestoreVolumeMount struct {
	UniqueID string
	Volume   *Volume
}

// BuildRestoreVolumeMap validates mounts and builds a UniqueID-to-Volume map
// for WithRestoreVolumeMap.
func BuildRestoreVolumeMap(mounts []RestoreVolumeMount) (map[string]*Volume, error) {
	volumes := make(map[string]*Volume, len(mounts))
	for _, m := range mounts {
		if m.UniqueID == "" {
			return nil, fmt.Errorf("ext4lite: restore volume mount has empty UniqueID")
		}
		if m.Volume == nil {
			return nil, fmt.Errorf("ext4lite: restore volume mount %q has nil Volume", m.UniqueID)
		}
		if _, exists := volumes[m.UniqueID]; exists {
			return nil, fmt.Errorf("ext4lite: duplicate restore volume UniqueID %q", m.UniqueID)
		}
		volumes[m.UniqueID] = m.Volume
	}
	return volumes, nil
}

// WithRestoreVolumeMap returns a copy of ctx carrying volumes for
// CompleteRestore.
func WithRestoreVolumeMap(ctx context.Context, volumes map[string]*Volume) context.Context {
	return context.WithValue(ctx, CtxRestoreVolumeMap, volumes)
}

// RestoreVolumeMapFromContext returns the pre-opened restore volume map from
// ctx, or nil when none is attached.
func RestoreVolumeMapFromContext(ctx goContext.Context) map[string]*Volume {
	if v := ctx.Value(CtxRestoreVolumeMap); v != nil {
		return v.(map[string]*Volume)
	}
	return nil
}

// volumeIdentity records the superblock and journal sequence state of a
// checkpointed ext4lite volume.
//
// +stateify savable
type volumeIdentity struct {
	uuid        [16]byte
	hasJournal  bool
	journalSeq  uint32
	mntCount    uint16
	wtime       uint32
	blocksCount uint64
	freeBlocks  uint64
	freeInodes  uint32
	lastOrphan  uint32
	clean       bool
}

func (v *volume) captureIdentity(clean bool) volumeIdentity {
	v.mu.Lock()
	defer v.mu.Unlock()
	id := volumeIdentity{
		uuid:        v.fsUUID(),
		mntCount:    v.sbU16(sbMntCount),
		wtime:       v.sbU32(sbWtime),
		blocksCount: uint64(v.sbU32(sbBlocksCountLo)) | uint64(v.sbU32(sbBlocksCountHi))<<32,
		freeBlocks:  uint64(v.sbU32(sbFreeBlocksLo)) | uint64(v.sbU32(sbFreeBlocksHi))<<32,
		freeInodes:  v.sbU32(sbFreeInodes),
		lastOrphan:  v.sbU32(sbLastOrphan),
		clean:       clean,
	}
	if v.j != nil {
		id.hasJournal = true
		id.journalSeq = v.j.seq
	}
	return id
}

func verifyIdentity(want, got volumeIdentity) error {
	if got.uuid != want.uuid {
		return vfs.ErrCorruption{
			Err: fmt.Errorf("ext4lite: superblock UUID mismatch: got %x, want %x", got.uuid, want.uuid),
		}
	}
	if want.clean && !got.clean {
		return vfs.ErrCorruption{
			Err: fmt.Errorf("ext4lite: backing volume was modified or left unclean before restore"),
		}
	}
	if got.hasJournal != want.hasJournal || got.journalSeq != want.journalSeq {
		return vfs.ErrCorruption{
			Err: fmt.Errorf("ext4lite: journal sequence mismatch: got (journal=%v, seq=%d), want (journal=%v, seq=%d)",
				got.hasJournal, got.journalSeq, want.hasJournal, want.journalSeq),
		}
	}
	if got.mntCount != want.mntCount ||
		got.wtime != want.wtime ||
		got.blocksCount != want.blocksCount ||
		got.freeBlocks != want.freeBlocks ||
		got.freeInodes != want.freeInodes ||
		got.lastOrphan != want.lastOrphan {
		return vfs.ErrCorruption{
			Err: fmt.Errorf("ext4lite: superblock generation mismatch: got (mnt=%d, wtime=%d, blocks=%d, freeBlocks=%d, freeInodes=%d, orphan=%d), want (mnt=%d, wtime=%d, blocks=%d, freeBlocks=%d, freeInodes=%d, orphan=%d)",
				got.mntCount, got.wtime, got.blocksCount, got.freeBlocks, got.freeInodes, got.lastOrphan,
				want.mntCount, want.wtime, want.blocksCount, want.freeBlocks, want.freeInodes, want.lastOrphan),
		}
	}
	return nil
}

// checkpointForSave flushes dirty metadata and pending home blocks to disk.
// It closes the active journal session cleanly while preserving open orphan
// inodes, and returns the resulting volumeIdentity.
func (v *volume) checkpointForSave() (volumeIdentity, error) {
	v.flushMu.Lock()
	defer v.flushMu.Unlock()
	if v.readOnly {
		return v.openedIdentity, nil
	}
	v.mu.Lock()
	alreadySaved := v.savedForCheckpoint
	v.mu.Unlock()
	if alreadySaved {
		return v.captureIdentity(true), nil
	}
	if err := v.ensureSessionStartedLocked(); err != nil {
		return volumeIdentity{}, err
	}
	if err := v.flushLocked(); err != nil {
		return volumeIdentity{}, err
	}
	if err := v.writePendingHome(); err != nil {
		return volumeIdentity{}, err
	}
	if err := v.syncData(); err != nil {
		return volumeIdentity{}, err
	}
	v.mu.Lock()
	groups := len(v.groups)
	v.mu.Unlock()
	if v.hf.Tier() == tierFallback {
		if err := v.hf.EnsureSize(int64(groups) * groupBytes); err != nil {
			return volumeIdentity{}, hostError(err)
		}
	}
	if v.j != nil {
		if err := v.endSession(true); err != nil {
			return volumeIdentity{}, err
		}
	} else {
		v.mu.Lock()
		v.state |= stateValid
		v.sbDirty = true
		v.mu.Unlock()
		if err := v.writeSuperblockNow(); err != nil {
			return volumeIdentity{}, err
		}
	}
	v.mu.Lock()
	v.savedForCheckpoint = true
	v.sessionStarted = false
	v.mu.Unlock()
	return v.captureIdentity(true), nil
}

// resumeAfterSave restarts the writable session when the sandbox resumes
// execution after a checkpoint save.
func (v *volume) resumeAfterSave() error {
	v.flushMu.Lock()
	defer v.flushMu.Unlock()
	if v.readOnly {
		return nil
	}
	v.mu.Lock()
	wasSaved := v.savedForCheckpoint
	v.savedForCheckpoint = false
	v.mu.Unlock()
	if !wasSaved {
		return nil
	}
	if v.j != nil {
		if err := v.startSession(); err != nil {
			return err
		}
	} else {
		v.mu.Lock()
		v.state &^= stateValid
		v.sbDirty = true
		v.mu.Unlock()
		if err := v.writeSuperblockNow(); err != nil {
			return err
		}
	}
	v.mu.Lock()
	v.sessionStarted = true
	v.mu.Unlock()
	return nil
}

var _ vfs.FilesystemImplSaveRestoreExtension = (*filesystem)(nil)

// flushMappedForSave writes dirty chunks of active mappings without consuming
// deferred write-back errors recorded in WBErr.
func (fs *filesystem) flushMappedForSave() error {
	fs.mu.Lock()
	list := make([]*inode, 0, len(fs.inodes))
	for _, ino := range fs.inodes {
		if ino.isRegular() {
			list = append(list, ino)
		}
	}
	fs.mu.Unlock()
	var errs []error
	for _, ino := range list {
		err := ino.flushMapped(0, math.MaxUint64)
		if errors.Is(err, errSpaceHeld) && fs.v.hasHeld() {
			if serr := fs.v.sync(); serr == nil {
				err = ino.flushMapped(0, math.MaxUint64)
			}
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context, _ vfs.PrepareSaveOptions) error {
	fs.stopFlusher()
	if !fs.readOnly {
		if err := fs.flushMappedForSave(); err != nil {
			return toLinuxErr(err)
		}
		id, err := fs.v.checkpointForSave()
		if err != nil {
			return toLinuxErr(err)
		}
		fs.savedIdentity = id
	} else {
		fs.savedIdentity = fs.v.openedIdentity
	}

	fs.mu.Lock()
	fs.saved = true
	list := make([]*inode, 0, len(fs.inodes))
	for _, ino := range fs.inodes {
		if ino.isRegular() {
			list = append(list, ino)
		}
	}
	fs.mu.Unlock()

	for _, ino := range list {
		ino.data.dropForSave()
	}
	return nil
}

// BeforeResume implements vfs.FilesystemImplSaveRestoreExtension.BeforeResume.
func (fs *filesystem) BeforeResume(ctx context.Context) {
	fs.mu.Lock()
	fs.saved = false
	fs.mu.Unlock()
	if fs.v == nil || fs.readOnly {
		return
	}
	if err := fs.v.resumeAfterSave(); err != nil {
		ctx.Warningf("ext4lite: resume volume after save: %v", err)
		return
	}
	fs.startFlusher()
}

// CompleteRestore implements vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, _ vfs.CompleteRestoreOptions) error {
	if fs.uniqueID == "" {
		return fmt.Errorf("ext4lite: cannot restore filesystem with empty UniqueID")
	}
	vmap := RestoreVolumeMapFromContext(ctx)
	if vmap == nil {
		return fmt.Errorf("ext4lite: missing CtxRestoreVolumeMap in restore context")
	}
	vol, ok := vmap[fs.uniqueID]
	if !ok || vol == nil {
		return fmt.Errorf("ext4lite: no pre-opened Volume in CtxRestoreVolumeMap for unique ID %q", fs.uniqueID)
	}
	if vol.v.readOnly != fs.readOnly {
		return fmt.Errorf("ext4lite: restore volume readOnly=%v does not match saved filesystem readOnly=%v", vol.v.readOnly, fs.readOnly)
	}
	if err := verifyIdentity(fs.savedIdentity, vol.v.openedIdentity); err != nil {
		return err
	}
	if fs.savedIdentity.lastOrphan != 0 && !vol.v.deferredOrphanCleanup {
		return vfs.ErrCorruption{
			Err: fmt.Errorf("ext4lite: restore volume for unique ID %q must open with DeferOrphanCleanup=true", fs.uniqueID),
		}
	}
	if !vol.mounted.CompareAndSwap(false, true) {
		return fmt.Errorf("ext4lite: restore volume for unique ID %q is already mounted", fs.uniqueID)
	}

	rollback := func(bound []*node, err error) error {
		for _, n := range bound {
			vol.v.unrebindNode(n)
		}
		fs.mu.Lock()
		for _, ino := range fs.inodes {
			ino.n = nil
		}
		fs.mu.Unlock()
		vol.mounted.Store(false)
		return err
	}

	fs.mu.Lock()
	inos := make([]uint32, 0, len(fs.inodes))
	for inoNum := range fs.inodes {
		inos = append(inos, inoNum)
	}
	slices.Sort(inos)
	inodes := make([]*inode, len(inos))
	for i, inoNum := range inos {
		inodes[i] = fs.inodes[inoNum]
	}
	fs.mu.Unlock()

	bound := make([]*node, 0, len(inodes))
	for _, ino := range inodes {
		n, err := vol.v.rebindNode(ino.ino)
		if err != nil {
			return rollback(bound, vfs.ErrCorruption{Err: err})
		}
		bound = append(bound, n)
		n.mu.RLock()
		kind := n.mode & modeTypeMask
		n.mu.RUnlock()
		if kind != ino.kind {
			return rollback(bound, vfs.ErrCorruption{
				Err: fmt.Errorf("ext4lite: inode %d mode kind %#x does not match saved kind %#x", ino.ino, kind, ino.kind),
			})
		}
		ino.n = n
	}

	if !fs.readOnly {
		if err := vol.v.ensureSessionStarted(); err != nil {
			return rollback(bound, err)
		}
		if err := vol.v.completeDeferredOrphans(); err != nil {
			return rollback(bound, err)
		}
	}

	sectors := fs.devSectors
	if sectors == 0 {
		sectors = vol.v.statfs().blocks * (blockSize / blockdev.SectorSize)
		fs.devSectors = sectors
	}
	if fs.dev != nil {
		fs.dev.SetSectors(sectors, blockdev.SectorsStatic)
		if fs.dev.Stats != nil {
			fs.dev.Stats.SetClock(nil)
			vol.v.setStats(fs.dev.Stats)
		} else {
			fs.dev.Stats = vol.v.stats
		}
	} else {
		dev, err := blockdev.Of(fs.vfsfs.VirtualFilesystem()).Add(blockdev.Options{
			Stats:        vol.v.stats,
			SectorsCount: sectors,
			ReadOnly:     vol.v.readOnly,
		})
		if err != nil {
			return rollback(bound, err)
		}
		fs.dev = dev
	}

	fs.vol = vol
	fs.v = vol.v
	vol.dataSync.Store(&dataSyncHook{fn: fs.syncMapped})
	if !fs.readOnly {
		fs.startFlusher()
	}
	return nil
}
