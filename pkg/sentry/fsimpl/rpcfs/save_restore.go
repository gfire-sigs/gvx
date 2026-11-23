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

package rpcfs

import (
	goContext "context"
	"fmt"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

type restoreContextID int

const (
	// CtxRestoreConfig is a Context.Value key for a *RestoreConfig used by
	// CompleteRestore to reattach pre-configured clients and collect handles
	// for restored rpcfs filesystems.
	CtxRestoreConfig restoreContextID = iota
)

// RestoreClient supplies a pre-opened rpcfs backend to attach during restore.
type RestoreClient struct {
	Client     Client
	Label      string
	ReadOnly   bool
	SingleFile bool
}

// RestoreConfig configures rpcfs filesystem restoration during Kernel.LoadFrom.
type RestoreConfig struct {
	// Clients maps guest mount target paths (such as "/mnt/proj") to pre-opened
	// clients to attach immediately during CompleteRestore. Targets absent from
	// Clients restore in detached mode (returning EIO until AttachClient runs).
	Clients map[string]RestoreClient
	// OnRestored is invoked once for every restored rpcfs filesystem with its
	// live Handle.
	OnRestored func(*Handle)
}

// WithRestoreConfig returns a copy of ctx carrying cfg for CompleteRestore.
func WithRestoreConfig(ctx context.Context, cfg *RestoreConfig) context.Context {
	return context.WithValue(ctx, CtxRestoreConfig, cfg)
}

// RestoreConfigFromContext returns the RestoreConfig attached to ctx, or nil.
func RestoreConfigFromContext(ctx goContext.Context) *RestoreConfig {
	if v := ctx.Value(CtxRestoreConfig); v != nil {
		return v.(*RestoreConfig)
	}
	return nil
}

// Handle exposes lifecycle controls for a mounted or restored rpcfs filesystem.
type Handle struct {
	fs *filesystem
}

// HandleOf returns a lifecycle Handle for fs when fs is an rpcfs filesystem.
func HandleOf(fs *vfs.Filesystem) (*Handle, bool) {
	if fs == nil {
		return nil, false
	}
	impl, ok := fs.Impl().(*filesystem)
	if !ok || impl == nil {
		return nil, false
	}
	return &Handle{fs: impl}, true
}

// Target returns the guest mount target path recorded for this filesystem.
func (h *Handle) Target() string {
	return h.fs.target
}

// Label returns the current client-side label (typically the host path).
func (h *Handle) Label() string {
	h.fs.clientMu.Lock()
	label := h.fs.label
	h.fs.clientMu.Unlock()
	return label
}

// ReadOnly reports whether the filesystem is read-only.
func (h *Handle) ReadOnly() bool {
	return h.fs.isReadOnly(nil)
}

// BackingReadOnly reports whether the saved filesystem itself was created read-only.
func (h *Handle) BackingReadOnly() bool {
	return h.fs.readOnly
}

// SingleFile reports whether the mount exposes a single regular file.
func (h *Handle) SingleFile() bool {
	return h.fs.singleFile
}

// Detached reports whether no client is currently attached to the filesystem.
func (h *Handle) Detached() bool {
	h.fs.clientMu.Lock()
	detached := h.fs.client == nil
	h.fs.clientMu.Unlock()
	return detached
}

// QuiesceForSave blocks new RPCs and waits until all in-flight RPCs and notify
// deliveries finish so the filesystem state is immutable during checkpoint save.
func (h *Handle) QuiesceForSave() {
	h.fs.quiesceForSave()
}

// ResumeAfterSave lifts the save quiesce barrier and triggers pending watch
// reconciliation.
func (h *Handle) ResumeAfterSave() error {
	return h.fs.resumeAfterSave()
}

// DetachClient stops the host watcher, detaches the active client without
// clearing guest inotify watch records, and closes the old client.
func (h *Handle) DetachClient() {
	h.fs.detachClient()
}

// AttachClient binds client to the filesystem, updating the optional label and
// client read-only restriction, and re-registers any active guest watches.
func (h *Handle) AttachClient(client Client, readOnly bool, label string) error {
	return h.fs.attachClient(client, readOnly, label)
}

func (fs *filesystem) quiesceForSave() {
	fs.clientMu.Lock()
	if !fs.quiesced {
		fs.quiesced = true
		fs.quiesceCh = make(chan struct{})
	}
	var waitCh chan struct{}
	if fs.inFlight > 0 {
		if fs.inFlightZero == nil {
			fs.inFlightZero = make(chan struct{})
		}
		waitCh = fs.inFlightZero
	}
	fs.clientMu.Unlock()
	if waitCh != nil {
		<-waitCh
	}
}

func (fs *filesystem) resumeAfterSave() error {
	fs.clientMu.Lock()
	if fs.quiesced {
		fs.quiesced = false
		if fs.quiesceCh != nil {
			close(fs.quiesceCh)
			fs.quiesceCh = nil
		}
	}
	fs.clientMu.Unlock()
	fs.signalWatchReconcile()
	return nil
}

func (fs *filesystem) detachClientLocked() {
	fs.clientMu.Lock()
	oldClient := fs.client
	oldWatcher := fs.watcher
	oldCancel := fs.watchCancel
	oldDone := fs.watchDone
	fs.client = nil
	fs.watcher = nil
	fs.clientReadOnly = false
	fs.watchCtx = nil
	fs.watchCancel = nil
	fs.watchNotify = nil
	fs.watchDone = nil
	fs.clientMu.Unlock()

	if oldWatcher != nil {
		oldWatcher.SetNotifyHandler(nil)
	}
	if oldCancel != nil {
		oldCancel()
	}
	if oldDone != nil {
		<-oldDone
	}
	if oldClient != nil {
		_ = oldClient.Close()
	}

	fs.watchMu.Lock()
	clear(fs.watchSynced)
	fs.watchMu.Unlock()
}

func (fs *filesystem) detachClient() {
	fs.clientLifecycleMu.Lock()
	defer fs.clientLifecycleMu.Unlock()
	fs.detachClientLocked()
}

func (fs *filesystem) attachClient(client Client, readOnly bool, label string) error {
	fs.clientLifecycleMu.Lock()
	defer fs.clientLifecycleMu.Unlock()
	return fs.attachClientLocked(client, readOnly, label)
}

func (fs *filesystem) attachClientLocked(client Client, readOnly bool, label string) error {
	if client == nil {
		fs.detachClientLocked()
		return nil
	}
	if !readOnly && fs.readOnly {
		return linuxerr.EROFS
	}

	fs.detachClientLocked()

	fs.watchMu.Lock()
	if fs.watchClosed {
		fs.watchMu.Unlock()
		_ = client.Close()
		return linuxerr.EIO
	}
	if fs.watchSynced == nil {
		fs.watchSynced = make(map[string]struct{})
	} else {
		clear(fs.watchSynced)
	}
	hasWatched := len(fs.watched) > 0
	fs.watchMu.Unlock()

	maxChunk := int64(defaultChunkSize)
	if cs, ok := client.(ChunkSizer); ok {
		if n := cs.MaxChunkBytes(); n >= 512 {
			maxChunk = n
		}
	}

	var (
		wc          WatchClient
		watchCtx    goContext.Context
		watchCancel goContext.CancelFunc
		watchNotify chan struct{}
		watchDone   chan struct{}
	)
	if w, ok := client.(WatchClient); ok {
		wc = w
		watchCtx, watchCancel = goContext.WithCancel(goContext.Background())
		watchNotify = make(chan struct{}, 1)
		watchDone = make(chan struct{})
	}

	fs.clientMu.Lock()
	fs.client = client
	fs.watcher = wc
	fs.clientReadOnly = readOnly
	fs.maxChunk = maxChunk
	if label != "" {
		fs.label = label
	}
	fs.watchCtx = watchCtx
	fs.watchCancel = watchCancel
	fs.watchNotify = watchNotify
	fs.watchDone = watchDone
	fs.clientMu.Unlock()

	if wc != nil {
		wc.SetNotifyHandler(fs.deliverNotify)
		go fs.watchLoop(watchCtx, watchNotify, watchDone)
		if hasWatched {
			fs.signalWatchReconcile()
		}
	}
	return nil
}

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(_ context.Context, _ vfs.PrepareSaveOptions) error {
	fs.quiesceForSave()
	return nil
}

// BeforeResume implements vfs.FilesystemImplSaveRestoreExtension.BeforeResume.
func (fs *filesystem) BeforeResume(_ context.Context) {
	_ = fs.resumeAfterSave()
}

// CompleteRestore implements vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, _ vfs.CompleteRestoreOptions) error {
	fs.watchMu.Lock()
	if fs.watched == nil {
		fs.watched = make(map[*dentry]string)
	}
	fs.watchSynced = make(map[string]struct{})
	fs.watchMu.Unlock()

	cfg := RestoreConfigFromContext(ctx)
	if cfg != nil && fs.target != "" {
		if rc, ok := cfg.Clients[fs.target]; ok && rc.Client != nil {
			if rc.SingleFile != fs.singleFile {
				return fmt.Errorf("rpcfs: restore target %q singleFile=%v does not match saved singleFile=%v", fs.target, rc.SingleFile, fs.singleFile)
			}
			if !rc.ReadOnly && fs.readOnly {
				return fmt.Errorf("rpcfs: restore target %q is read-only in checkpoint and cannot attach read-write", fs.target)
			}
			if err := fs.attachClient(rc.Client, rc.ReadOnly, rc.Label); err != nil {
				return fmt.Errorf("rpcfs: attach restore client for %q: %w", fs.target, err)
			}
		}
	}
	if cfg != nil && cfg.OnRestored != nil {
		cfg.OnRestored(&Handle{fs: fs})
	}
	return nil
}

var _ vfs.FilesystemImplSaveRestoreExtension = (*filesystem)(nil)
