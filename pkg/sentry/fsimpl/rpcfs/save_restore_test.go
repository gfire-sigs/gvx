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
	"bytes"
	goContext "context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/usermem"
)

type watchTestClient struct {
	*localRootClient
	wmu     sync.Mutex
	watched map[string]int
	handler func(NotifyEvent)
}

func newWatchTestClient(root *os.Root) *watchTestClient {
	return &watchTestClient{
		localRootClient: &localRootClient{root: root},
		watched:         make(map[string]int),
	}
}

func (c *watchTestClient) Watch(_ goContext.Context, relPath string) error {
	c.wmu.Lock()
	c.watched[relPath]++
	c.wmu.Unlock()
	return nil
}

func (c *watchTestClient) Unwatch(_ goContext.Context, relPath string) error {
	c.wmu.Lock()
	delete(c.watched, relPath)
	c.wmu.Unlock()
	return nil
}

func (c *watchTestClient) SetNotifyHandler(fn func(NotifyEvent)) {
	c.wmu.Lock()
	c.handler = fn
	c.wmu.Unlock()
}

func (c *watchTestClient) emit(ev NotifyEvent) {
	c.wmu.Lock()
	fn := c.handler
	c.wmu.Unlock()
	if fn != nil {
		fn(ev)
	}
}

func (c *watchTestClient) hasWatch(relPath string) bool {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.watched[relPath] > 0
}

type saveRestoreBundle struct {
	vfsObj *vfs.VirtualFilesystem
	rootVD vfs.VirtualDentry
	regFD  *vfs.FileDescription
	dirFD  *vfs.FileDescription
	watchD *vfs.Dentry
}

func (b *saveRestoreBundle) StateTypeName() string {
	return "pkg/sentry/fsimpl/rpcfs.saveRestoreBundle"
}

func (b *saveRestoreBundle) StateFields() []string {
	return []string{"vfsObj", "rootVD", "regFD", "dirFD", "watchD"}
}

func (b *saveRestoreBundle) StateSave(s state.Sink) {
	s.Save(0, &b.vfsObj)
	s.Save(1, &b.rootVD)
	s.Save(2, &b.regFD)
	s.Save(3, &b.dirFD)
	s.Save(4, &b.watchD)
}

func (b *saveRestoreBundle) StateLoad(_ goContext.Context, s state.Source) {
	s.Load(0, &b.vfsObj)
	s.Load(1, &b.rootVD)
	s.Load(2, &b.regFD)
	s.Load(3, &b.dirFD)
	s.Load(4, &b.watchD)
}

func init() {
	state.Register((*saveRestoreBundle)(nil))
}

func TestRPCFSSaveRestoreDetachedReconnectAndWatches(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("0123456789abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extra.txt"), []byte("extra"), 0o644); err != nil {
		t.Fatal(err)
	}

	root1, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	cli1 := newWatchTestClient(root1)

	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	var vfsObj vfs.VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer vfsObj.Release(ctx)

	fs, rootD, err := NewFilesystemWithOptions(ctx, &vfsObj, cli1, Options{
		Target: "/mnt/proj",
		Label:  dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	mnt := vfsObj.NewDisconnectedMount(fs, rootD, &vfs.MountOptions{})
	fs.DecRef(ctx)
	rootVD := vfs.MakeVirtualDentry(mnt, rootD)
	defer rootVD.DecRef(ctx)

	// Open a regular file and advance offset to 6 bytes.
	regFD, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root: rootVD, Start: rootVD, Path: fspath.Parse("/note.txt"),
	}, &vfs.OpenOptions{Flags: linux.O_RDWR})
	if err != nil {
		t.Fatalf("OpenAt(note.txt): %v", err)
	}
	defer regFD.DecRef(ctx)
	head := make([]byte, 6)
	if n, err := regFD.Read(ctx, usermem.BytesIOSequence(head), vfs.ReadOptions{}); err != nil || n != 6 || string(head) != "012345" {
		t.Fatalf("initial Read = (%d, %q, %v), want (6, 012345, nil)", n, head, err)
	}

	// Open root directory and register a watch on it.
	dirFD, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root: rootVD, Start: rootVD, Path: fspath.Parse("/"),
	}, &vfs.OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY})
	if err != nil {
		t.Fatalf("OpenAt(/): %v", err)
	}
	defer dirFD.DecRef(ctx)

	rootDentry := rootVD.Dentry()
	if err := rootDentry.Impl().(*dentry).AdmitInotifyWatch(); err != nil {
		t.Fatalf("AdmitInotifyWatch: %v", err)
	}
	if !cli1.hasWatch(".") {
		t.Fatal("expected initial host watch on '.'")
	}

	// PrepareSave and serialize via state.Save.
	if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave: %v", err)
	}
	orig := saveRestoreBundle{
		vfsObj: &vfsObj,
		rootVD: rootVD,
		regFD:  regFD,
		dirFD:  dirFD,
		watchD: rootDentry,
	}
	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &orig); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	vfsObj.BeforeResume(ctx)

	// Verify original mount still reads cleanly after BeforeResume.
	var nextBuf [4]byte
	if n, err := regFD.Read(ctx, usermem.BytesIOSequence(nextBuf[:]), vfs.ReadOptions{}); err != nil || n != 4 || string(nextBuf[:]) != "6789" {
		t.Fatalf("Read after BeforeResume = (%d, %q, %v), want (4, 6789, nil)", n, nextBuf[:], err)
	}

	// Restore detached (no client in RestoreConfig).
	restoreCtx := gvcontext.Background()
	var restoredHandle *Handle
	restoreCtx = WithRestoreConfig(restoreCtx, &RestoreConfig{
		OnRestored: func(h *Handle) {
			restoredHandle = h
		},
	})
	var restored saveRestoreBundle
	if _, err := state.Load(restoreCtx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer restored.vfsObj.Release(restoreCtx)
	defer restored.rootVD.DecRef(restoreCtx)
	defer restored.regFD.DecRef(restoreCtx)
	defer restored.dirFD.DecRef(restoreCtx)

	if err := restored.vfsObj.CompleteRestore(restoreCtx, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}
	if restoredHandle == nil {
		t.Fatal("OnRestored callback was not invoked")
	}
	if restoredHandle.Target() != "/mnt/proj" || restoredHandle.Label() != dir || !restoredHandle.Detached() {
		t.Fatalf("restored handle = (target=%q label=%q detached=%v), want (/mnt/proj, %q, true)",
			restoredHandle.Target(), restoredHandle.Label(), restoredHandle.Detached(), dir)
	}

	// Detached reads on the restored open FD must return EIO without advancing offset.
	var tmp [4]byte
	if _, err := restored.regFD.Read(restoreCtx, usermem.BytesIOSequence(tmp[:]), vfs.ReadOptions{}); !errors.Is(err, linuxerr.EIO) {
		t.Fatalf("detached Read err = %v, want EIO", err)
	}

	// Reattach a fresh WatchClient and verify open FD resumes from exact offset 6.
	root2, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	cli2 := newWatchTestClient(root2)
	if err := restoredHandle.AttachClient(cli2, false, dir); err != nil {
		t.Fatalf("AttachClient: %v", err)
	}
	if restoredHandle.Detached() {
		t.Fatal("handle still reports Detached after AttachClient")
	}

	tail := make([]byte, 10)
	if n, err := restored.regFD.Read(restoreCtx, usermem.BytesIOSequence(tail), vfs.ReadOptions{}); err != nil || n != 10 || string(tail) != "6789abcdef" {
		t.Fatalf("reattached Read = (%d, %q, %v), want (10, 6789abcdef, nil)", n, tail, err)
	}

	// Write through the same reattached FD.
	if n, err := restored.regFD.Write(restoreCtx, usermem.BytesIOSequence([]byte("!")), vfs.WriteOptions{}); err != nil || n != 1 {
		t.Fatalf("reattached Write = (%d, %v), want (1, nil)", n, err)
	}
	gotDisk, err := os.ReadFile(filepath.Join(dir, "note.txt"))
	if err != nil || string(gotDisk) != "0123456789abcdef!" {
		t.Fatalf("host note.txt = (%q, %v), want 0123456789abcdef!", gotDisk, err)
	}

	// Directory FD still iterates entries cleanly after reconnect.
	var cb testDirCB
	if err := restored.dirFD.IterDirents(restoreCtx, &cb); err != nil {
		t.Fatalf("reattached IterDirents: %v", err)
	}
	if !slices.Contains(cb.names, "note.txt") || !slices.Contains(cb.names, "extra.txt") {
		t.Fatalf("reattached dirents = %v, want note.txt and extra.txt", cb.names)
	}

	// Saved inotify watch must be reconciled onto cli2 automatically.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !cli2.hasWatch(".") {
		time.Sleep(10 * time.Millisecond)
	}
	if !cli2.hasWatch(".") {
		t.Fatal("saved inotify watch on '.' was not re-registered on reattached WatchClient")
	}
}

func TestRPCFSQuiesceBlocksNewRPCsUntilResume(t *testing.T) {
	dir, _, vfsObj, rootVD, ctx, creds := setupRPCFSMount(t, false)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	handle, ok := HandleOf(rootVD.Mount().Filesystem())
	if !ok {
		t.Fatal("HandleOf returned false")
	}

	handle.QuiesceForSave()
	done := make(chan error, 1)
	go func() {
		_, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
			Root: rootVD, Start: rootVD, Path: fspath.Parse("/a.txt"),
		}, &vfs.StatOptions{})
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("StatAt completed while quiesced: err=%v", err)
	case <-time.After(40 * time.Millisecond):
	}

	if err := handle.ResumeAfterSave(); err != nil {
		t.Fatalf("ResumeAfterSave: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("StatAt after ResumeAfterSave: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("StatAt did not resume after ResumeAfterSave")
	}
}
