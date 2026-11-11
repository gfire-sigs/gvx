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

package memdev

import (
	"bytes"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/uniqueid"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/usermem"
)

type fixedKmsgClock struct{}

func (fixedKmsgClock) Now() ktime.Time { return ktime.FromNanoseconds(1_700_000_000_000_000_000) }
func (fixedKmsgClock) NewTimer(ktime.Listener) ktime.Timer {
	panic("fixedKmsgClock has no timers")
}

func newKmsgTestCtx(k *kernel.Kernel, creds *auth.Credentials) context.Context {
	return context.WithValues(context.Background(), map[any]any{
		kernel.CtxKernel:          k,
		auth.CtxCredentials:       creds,
		ktime.CtxRealtimeClock:    fixedKmsgClock{},
		limits.CtxLimits:          limits.NewLimitSet(),
		uniqueid.CtxInotifyCookie: uint32(1),
	})
}

func openRegisteredKmsg(t *testing.T, ctx context.Context, vfsObj *vfs.VirtualFilesystem, flags uint32) *vfs.FileDescription {
	t.Helper()
	vd := vfsObj.NewAnonVirtualDentry("kmsg")
	defer vd.DecRef(ctx)
	fd, err := vfsObj.OpenDeviceSpecialFile(ctx, vd.Mount(), vd.Dentry(), vfs.CharDevice, linux.MEM_MAJOR, kmsgDevMinor, &vfs.OpenOptions{Flags: flags})
	if err != nil {
		t.Fatalf("OpenDeviceSpecialFile(/dev/kmsg): %v", err)
	}
	return fd
}

func TestKmsgDeviceAndFDSaveLoadRoundTrip(t *testing.T) {
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	kOrig := &kernel.Kernel{}
	ctx := newKmsgTestCtx(kOrig, creds)

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	if err := RegisterKmsg(vfsObj); err != nil {
		t.Fatalf("RegisterKmsg: %v", err)
	}
	t.Cleanup(func() { vfsObj.Release(ctx) })

	klog := kOrig.KernelLog()
	klog.Printk(kernel.LogInfo, "record-zero")
	klog.Printk(kernel.LogWarning, "record-one")
	klog.Printk(kernel.LogErr, "record-two")

	fd := openRegisteredKmsg(t, ctx, vfsObj, linux.O_RDWR|linux.O_NONBLOCK)
	t.Cleanup(func() { fd.DecRef(ctx) })

	// Advance the open FD past record-zero so seq == 1 before save.
	readBuf := make([]byte, 4096)
	n, err := fd.Read(ctx, usermem.BytesIOSequence(readBuf), vfs.ReadOptions{})
	if err != nil || !strings.HasSuffix(string(readBuf[:n]), ";record-zero\n") {
		t.Fatalf("initial Read = %q, %v, want record-zero", string(readBuf[:n]), err)
	}

	// Write 12 lines so 2 lines are suppressed by the per-FD rate limiter before save.
	for range 12 {
		if _, err := fd.Write(ctx, usermem.BytesIOSequence([]byte("burst")), vfs.WriteOptions{}); err != nil {
			t.Fatalf("Write(/dev/kmsg): %v", err)
		}
	}

	if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave: %v", err)
	}
	bundle := []any{vfsObj, fd, creds}
	var saveBuf bytes.Buffer
	if _, err := state.Save(ctx, &saveBuf, &bundle); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	kRestored := &kernel.Kernel{}
	var loaded []any
	loadCtx := newKmsgTestCtx(kRestored, creds)
	if _, err := state.Load(loadCtx, &saveBuf, &loaded); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoredVFS := loaded[0].(*vfs.VirtualFilesystem)
	restoredFD := loaded[1].(*vfs.FileDescription)
	restoredCreds := loaded[2].(*auth.Credentials)
	loadCtx = newKmsgTestCtx(kRestored, restoredCreds)
	if err := restoredVFS.CompleteRestore(loadCtx, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}
	t.Cleanup(func() { restoredVFS.Release(loadCtx) })

	// Reading from the restored open FD must resume at sequence 1 ("record-one").
	n, err = restoredFD.Read(loadCtx, usermem.BytesIOSequence(readBuf), vfs.ReadOptions{})
	if err != nil || !strings.HasSuffix(string(readBuf[:n]), ";record-one\n") {
		t.Fatalf("restored Read = %q, %v, want record-one", string(readBuf[:n]), err)
	}

	// Opening a fresh /dev/kmsg FD on the restored VFS starts at sequence 0.
	freshFD := openRegisteredKmsg(t, loadCtx, restoredVFS, linux.O_RDONLY|linux.O_NONBLOCK)
	defer freshFD.DecRef(loadCtx)
	n, err = freshFD.Read(loadCtx, usermem.BytesIOSequence(readBuf), vfs.ReadOptions{})
	if err != nil || !strings.HasSuffix(string(readBuf[:n]), ";record-zero\n") {
		t.Fatalf("fresh Read after restore = %q, %v, want record-zero", string(readBuf[:n]), err)
	}

	// Closing the restored FD flushes the saved suppression count into kRestored.KernelLog().
	restoredFD.DecRef(loadCtx)
	restoredLog := kRestored.KernelLog()
	last, ok := restoredLog.Lookup(restoredLog.NextSeq() - 1)
	if !ok || last.Text != "kernel: 2 output lines suppressed due to ratelimiting" {
		t.Errorf("last record after restored FD close = (%+v, %t), want 2 suppressed lines notice", last, ok)
	}
}
