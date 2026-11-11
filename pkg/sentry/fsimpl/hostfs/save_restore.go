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

package hostfs

import (
	goContext "context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"time"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/checkpoint"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

type restoreContextKey int

const ctxRestoreWorkspaceMap restoreContextKey = iota

// WithRestoreWorkspaces attaches pre-opened workspaces keyed by mount UniqueID
// to ctx for CompleteRestore.
func WithRestoreWorkspaces(ctx goContext.Context, wsMap map[checkpoint.ResourceID]*Workspace) goContext.Context {
	return goContext.WithValue(ctx, ctxRestoreWorkspaceMap, wsMap)
}

// WithRestoreWorkspace attaches one pre-opened workspace under id to ctx.
func WithRestoreWorkspace(ctx goContext.Context, id checkpoint.ResourceID, ws *Workspace) goContext.Context {
	merged := make(map[checkpoint.ResourceID]*Workspace)
	if existing := RestoreWorkspacesFromContext(ctx); existing != nil {
		maps.Copy(merged, existing)
	}
	merged[id] = ws
	return goContext.WithValue(ctx, ctxRestoreWorkspaceMap, merged)
}

type restoreWorkspacePkgContext struct {
	context.Context
	wsMap map[checkpoint.ResourceID]*Workspace
}

// Value implements context.Context.Value.
func (c restoreWorkspacePkgContext) Value(key any) any {
	if key == ctxRestoreWorkspaceMap {
		return c.wsMap
	}
	return c.Context.Value(key)
}

// WithRestoreWorkspacesContext attaches pre-opened workspaces to a Sentry context.
func WithRestoreWorkspacesContext(ctx context.Context, wsMap map[checkpoint.ResourceID]*Workspace) context.Context {
	return restoreWorkspacePkgContext{Context: ctx, wsMap: wsMap}
}

// WithRestoreWorkspaceContext attaches one pre-opened workspace under id to a Sentry context.
func WithRestoreWorkspaceContext(ctx context.Context, id checkpoint.ResourceID, ws *Workspace) context.Context {
	merged := make(map[checkpoint.ResourceID]*Workspace)
	if existing := RestoreWorkspacesFromContext(ctx); existing != nil {
		maps.Copy(merged, existing)
	}
	merged[id] = ws
	return restoreWorkspacePkgContext{Context: ctx, wsMap: merged}
}

// RestoreWorkspacesFromContext reads the pre-opened workspace map attached to ctx.
func RestoreWorkspacesFromContext(ctx goContext.Context) map[checkpoint.ResourceID]*Workspace {
	if ctx == nil {
		return nil
	}
	wsMap, _ := ctx.Value(ctxRestoreWorkspaceMap).(map[checkpoint.ResourceID]*Workspace)
	return wsMap
}

// OpenWorkspaceForRestore opens hostPath via os.OpenRoot before hostlockdown.Apply()
// without sweeping existing ephemeral or unlinked backing files. CompleteRestore
// sweeps unclaimed ephemeral files after reattaching restored inodes.
func OpenWorkspaceForRestore(hostPath string, readOnly bool) (*Workspace, error) {
	return openWorkspace(hostPath, readOnly, workspaceOptions{
		coalesce:    defaultCoalesceWindow,
		restoreMode: true,
	})
}

func newUnlinkedTmpLeaf() string {
	return fmt.Sprintf("%s%x.%x.%x", unlinkedTmpPrefix, os.Getpid(), time.Now().UnixNano(), tmpSeq.Add(1))
}

func (fs *filesystem) trackRegularFD(fd *regularFD) {
	fs.openFDsMu.Lock()
	if fs.openFDs == nil {
		fs.openFDs = make(map[*regularFD]struct{})
	}
	fs.openFDs[fd] = struct{}{}
	fs.openFDsMu.Unlock()
}

func (fs *filesystem) untrackRegularFD(fd *regularFD) {
	fs.openFDsMu.Lock()
	delete(fs.openFDs, fd)
	fs.openFDsMu.Unlock()
}

func (fs *filesystem) snapshotRegularFDs() []*regularFD {
	fs.openFDsMu.Lock()
	defer fs.openFDsMu.Unlock()
	out := make([]*regularFD, 0, len(fs.openFDs))
	for fd := range fs.openFDs {
		out = append(out, fd)
	}
	return out
}

func collectLiveDentriesLocked(d *dentry, dst *[]*dentry) {
	if d == nil {
		return
	}
	*dst = append(*dst, d)
	for _, child := range d.children {
		collectLiveDentriesLocked(child, dst)
	}
}

func (fs *filesystem) collectStateGraph(openFDs []*regularFD) ([]*dentry, []*inode) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	var dentries []*dentry
	collectLiveDentriesLocked(fs.root, &dentries)

	seenIno := make(map[*inode]struct{}, len(fs.inodes)+len(dentries)+len(openFDs))
	var inodes []*inode
	addIno := func(ino *inode) {
		if ino == nil {
			return
		}
		if _, ok := seenIno[ino]; ok {
			return
		}
		seenIno[ino] = struct{}{}
		inodes = append(inodes, ino)
	}

	for _, d := range dentries {
		if !d.dead {
			d.inode.savedRel = d.path()
		}
		addIno(d.inode)
	}
	for _, ino := range fs.inodes {
		addIno(ino)
	}
	for ino := range fs.liveInodes {
		addIno(ino)
	}
	for _, fd := range openFDs {
		fd.savedRel = fd.dentry.path()
		if !fd.dentry.dead && fd.dentry.inode.savedRel == "" {
			fd.dentry.inode.savedRel = fd.savedRel
		}
		addIno(fd.dentry.inode)
	}
	return dentries, inodes
}

func liveHandleForInode(ino *inode, openFDs []*regularFD) *hostHandle {
	ino.data.DataMu.Lock()
	mh := ino.data.mh
	if mh == nil {
		mh = ino.data.pending
	}
	ino.data.DataMu.Unlock()
	if mh != nil {
		return mh
	}
	for _, fd := range openFDs {
		if fd.dentry.inode == ino && fd.h != nil {
			return fd.h
		}
	}
	return nil
}

// stageUnlinkedBacking copies an open unlinked regular file into a hidden
// .gvx_tmp_* file inside the pinned workspace root for checkpoint persistence.
func (w *Workspace) stageUnlinkedBacking(src *hostHandle) (string, error) {
	if w.readOnly {
		return "", ErrReadOnly
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return "", os.ErrClosed
	}
	if w.single != "" {
		return "", errNotPermitted
	}
	info, err := src.fstat(w.host)
	if err != nil {
		return "", err
	}
	leaf := newUnlinkedTmpLeaf()
	dst, err := w.host.openChildAt(w.rootPin.h, leaf, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	cleanup := func(cause error) (string, error) {
		_ = dst.Close()
		_ = w.host.unlink(leaf)
		return "", cause
	}
	buf := make([]byte, chunkSize)
	for off := int64(0); off < info.size; {
		want := int(min(int64(len(buf)), info.size-off))
		n, rErr := src.readAt(buf[:want], off)
		if n > 0 {
			if _, wErr := dst.WriteAt(buf[:n], off); wErr != nil {
				return cleanup(wErr)
			}
			off += int64(n)
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				break
			}
			return cleanup(rErr)
		}
		if n == 0 {
			break
		}
	}
	if err := setFileSize(dst, info.size); err != nil {
		return cleanup(err)
	}
	if err := dst.Sync(); err != nil {
		return cleanup(err)
	}
	if err := dst.Close(); err != nil {
		_ = w.host.unlink(leaf)
		return "", err
	}
	return leaf, nil
}

// openEphemeralHandle opens a hidden ephemeral or unlinked backing file
// relative to the pinned os.Root without unbound host path resolution.
func (w *Workspace) openEphemeralHandle(rel string, flags int) (*hostHandle, error) {
	if w.readOnly && flags&(os.O_WRONLY|os.O_RDWR|os.O_TRUNC) != 0 {
		return nil, ErrReadOnly
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return nil, os.ErrClosed
	}
	dirRel, leaf := splitParent(rel)
	hostDir, err := w.hostPath(dirRel)
	if err != nil {
		return nil, err
	}
	f, err := w.host.open(hostChild(hostDir, leaf), flags&^(os.O_CREATE|os.O_EXCL), 0)
	if err != nil {
		return nil, err
	}
	return w.wrapLocked(rel, f, flags), nil
}

func (w *Workspace) removeEphemeral(rel string) {
	if w.readOnly || w.single != "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	dirRel, leaf := splitParent(rel)
	hostDir, err := w.hostPath(dirRel)
	if err != nil {
		return
	}
	w.handles.detach(rel)
	_ = w.host.unlink(hostChild(hostDir, leaf))
}

var _ vfs.FilesystemImplSaveRestoreExtension = (*filesystem)(nil)

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context, _ vfs.PrepareSaveOptions) error {
	if fs.ws == nil {
		return linuxerr.EINVAL
	}
	openFDs := fs.snapshotRegularFDs()
	_, inodes := fs.collectStateGraph(openFDs)

	fs.mu.Lock()
	fs.preserveSavedTmp = true
	fs.mu.Unlock()

	for _, ino := range inodes {
		if err := ino.syncFile(); err != nil {
			return translateHostError(err)
		}
	}
	for _, fd := range openFDs {
		if fd.h != nil && fd.hostFlags != os.O_RDONLY {
			if err := fd.h.sync(); err != nil {
				return translateHostError(err)
			}
		}
	}

	for _, ino := range inodes {
		if !ino.isRegular() {
			continue
		}
		h := liveHandleForInode(ino, openFDs)
		if h != nil {
			if info, err := h.fstat(fs.ws.host); err == nil {
				e := ino.snapshot()
				e.info = info
				ino.update(e)
				ino.data.DataMu.Lock()
				ino.data.size = info.size
				ino.data.DataMu.Unlock()
			}
		}
		if !ino.unlinked.Load() {
			ino.savedTmpRel = ""
			continue
		}
		fs.mu.Lock()
		t := ino.tmp
		fs.mu.Unlock()
		if t != nil && t.named() {
			ino.savedTmpRel = ""
			continue
		}
		if ino.savedTmpRel == "" && h != nil && !fs.ws.ReadOnly() && !fs.ws.SingleFile() {
			rel, err := fs.ws.stageUnlinkedBacking(h)
			if err != nil {
				return translateHostError(err)
			}
			ino.savedTmpRel = rel
		}
	}

	if err := fs.ws.Sync(); err != nil {
		return translateHostError(err)
	}

	// Invalidate active mappings before releasing chunk memory so no MemoryFile
	// pages remain allocated across checkpoint serialization.
	for _, ino := range inodes {
		if !ino.isRegular() {
			continue
		}
		c := &ino.data
		c.MapsMu.Lock()
		c.DataMu.Lock()
		if err := c.FlushLocked(0, math.MaxUint64); err != nil {
			c.DataMu.Unlock()
			c.MapsMu.Unlock()
			return translateHostError(err)
		}
		c.savedMappings = c.Mappings
		c.savedWritableMaps = c.WritableMaps
		var dropped []*cacheChunk
		for idx, ch := range c.Chunks {
			dropped = append(dropped, ch)
			delete(c.Chunks, idx)
		}
		c.DataMu.Unlock()
		c.Mappings.InvalidateAll(memmap.InvalidateOpts{})
		for _, ch := range dropped {
			ch.Release()
		}
		c.MapsMu.Unlock()
	}
	return nil
}

// BeforeResume implements vfs.FilesystemImplSaveRestoreExtension.BeforeResume.
func (fs *filesystem) BeforeResume(ctx context.Context) {
	openFDs := fs.snapshotRegularFDs()
	_, inodes := fs.collectStateGraph(openFDs)

	var staged []string
	fs.mu.Lock()
	fs.preserveSavedTmp = false
	for _, ino := range inodes {
		if ino.savedTmpRel != "" && (ino.tmp == nil || !ino.tmp.named()) {
			staged = append(staged, ino.savedTmpRel)
			ino.savedTmpRel = ""
		}
	}
	fs.mu.Unlock()

	if fs.ws != nil {
		for _, rel := range staged {
			fs.ws.removeEphemeral(rel)
		}
	}
}

func (fs *filesystem) reopenInodeHandle(ino *inode, fallbackRel string, flags int) (*hostHandle, error) {
	if fs.ws.SingleFile() {
		return fs.ws.openSingle(flags)
	}
	if ino.unlinked.Load() {
		fs.mu.Lock()
		t := ino.tmp
		fs.mu.Unlock()
		if t != nil && t.named() {
			return fs.ws.openTmp(t, flags)
		}
		if ino.savedTmpRel != "" {
			return fs.ws.openEphemeralHandle(ino.savedTmpRel, flags)
		}
		return nil, os.ErrNotExist
	}
	rel := fallbackRel
	if rel == "" {
		rel = ino.savedRel
	}
	if rel == "" {
		return nil, os.ErrNotExist
	}
	return fs.ws.openHandle(rel, flags)
}

// CompleteRestore implements vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, _ vfs.CompleteRestoreOptions) error {
	wsMap := RestoreWorkspacesFromContext(ctx)
	if wsMap == nil {
		return vfs.ErrCorruption{Err: errors.New("hostfs: missing restore workspace map in context")}
	}
	ws, ok := wsMap[fs.uniqueID]
	if !ok || ws == nil {
		return vfs.ErrCorruption{Err: fmt.Errorf("hostfs: missing restore workspace for id %v", fs.uniqueID)}
	}
	if ws.SingleFile() != fs.singleFile {
		return vfs.ErrCorruption{Err: fmt.Errorf("hostfs: single-file mode mismatch for workspace %v", fs.uniqueID)}
	}
	fs.ws = ws
	fs.ownsWS = false

	openFDs := fs.snapshotRegularFDs()
	var dentries []*dentry
	fs.mu.Lock()
	collectLiveDentriesLocked(fs.root, &dentries)
	seenIno := make(map[*inode]struct{}, len(fs.inodes)+len(dentries)+len(openFDs))
	var inodes []*inode
	addIno := func(ino *inode) {
		if ino == nil {
			return
		}
		if _, exists := seenIno[ino]; exists {
			return
		}
		seenIno[ino] = struct{}{}
		inodes = append(inodes, ino)
	}
	for _, d := range dentries {
		if !d.dead && d.inode.savedRel == "" {
			d.inode.savedRel = d.path()
		}
		addIno(d.inode)
	}
	for _, ino := range fs.inodes {
		addIno(ino)
	}
	for ino := range fs.liveInodes {
		addIno(ino)
	}
	for _, fd := range openFDs {
		addIno(fd.dentry.inode)
	}
	if fs.liveInodes == nil {
		fs.liveInodes = make(map[*inode]struct{}, len(inodes))
	}
	for _, ino := range inodes {
		if ino.refs > 0 {
			fs.liveInodes[ino] = struct{}{}
		}
	}

	claimed := make(map[string]struct{})
	for _, ino := range inodes {
		ino.data.init(ino)
		ino.data.Mappings = ino.data.savedMappings
		ino.data.WritableMaps = ino.data.savedWritableMaps
		if ino.tmp != nil && ino.tmp.named() {
			rel := joinRelPath(ino.tmp.parent.path(), ino.tmp.leaf)
			ino.savedTmpRel = ""
			claimed[rel] = struct{}{}
		} else if ino.savedTmpRel != "" {
			claimed[ino.savedTmpRel] = struct{}{}
		}
	}
	fs.mu.Unlock()

	refreshedInodes := make(map[hostID]*inode, len(inodes))
	for _, ino := range inodes {
		if ino.virtual || ino.unlinked.Load() {
			continue
		}
		rel := ino.savedRel
		if rel == "" {
			continue
		}
		e, err := ws.lookup(rel)
		if err != nil {
			return vfs.ErrCorruption{Err: fmt.Errorf("hostfs: lookup %q during restore: %w", rel, err)}
		}
		if ws.SingleFile() {
			// Single-file mode keeps guest mode, uid, gid, and xattrs in memory;
			// preserve the saved POSIXAttr while refreshing host size and times.
			saved := ino.snapshot()
			e.attr = saved.attr
			ws.mu.Lock()
			ws.putRec(e.key, saved.attr, rel)
			ws.mu.Unlock()
		}
		ino.id = e.info.id
		ino.update(e)
		refreshedInodes[ino.id] = ino
	}
	fs.mu.Lock()
	fs.inodes = refreshedInodes
	fs.mu.Unlock()

	for _, fd := range openFDs {
		ino := fd.dentry.inode
		h, err := fs.reopenInodeHandle(ino, fd.savedRel, fd.hostFlags)
		if err != nil {
			return vfs.ErrCorruption{Err: fmt.Errorf("hostfs: reopen file %q during restore: %w", fd.savedRel, err)}
		}
		fd.h = h
		if ino.unlinked.Load() {
			if info, statErr := h.fstat(ws.host); statErr == nil {
				ino.id = info.id
				e := ino.snapshot()
				e.info = info
				ino.update(e)
			}
		}
	}

	for _, ino := range inodes {
		if !ino.isRegular() || ino.data.Mappings.IsEmpty() {
			continue
		}
		writable := ino.data.WritableMaps > 0
		flags := os.O_RDONLY
		if writable {
			flags = os.O_RDWR
		}
		rel := ino.savedRel
		if rel == "" && ino.data.src != nil {
			rel = ino.data.src.path()
		}
		mh, err := fs.reopenInodeHandle(ino, rel, flags)
		if err != nil {
			return vfs.ErrCorruption{Err: fmt.Errorf("hostfs: reopen mapped file %q during restore: %w", rel, err)}
		}
		if ino.unlinked.Load() {
			if info, statErr := mh.fstat(ws.host); statErr == nil {
				ino.id = info.id
				e := ino.snapshot()
				e.info = info
				ino.update(e)
			}
		}
		attachErr := ino.data.attachHandle(mh, writable)
		_ = mh.decRef()
		if attachErr != nil {
			return vfs.ErrCorruption{Err: fmt.Errorf("hostfs: attach mapped handle %q during restore: %w", rel, attachErr)}
		}
	}

	watchedIno := make(map[*inode]struct{})
	for _, d := range dentries {
		if d.dead || d.inode.watches.Size() == 0 {
			continue
		}
		if _, seen := watchedIno[d.inode]; seen {
			continue
		}
		watchedIno[d.inode] = struct{}{}
		if err := ws.watchDentry(d); err != nil {
			ws.logWatchRefusal(d, err)
		}
	}

	ws.sweepUnclaimedEphemeral(claimed)
	return nil
}
