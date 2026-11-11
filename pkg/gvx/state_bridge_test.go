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

package gvx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

type bridgeTestContext struct {
	gvcontext.Context
	creds *auth.Credentials
	lims  *limits.LimitSet
	mf    *pgalloc.MemoryFile
	clock ktime.Clock
}

func (c bridgeTestContext) Value(key any) any {
	switch key {
	case auth.CtxCredentials:
		return c.creds
	case limits.CtxLimits:
		return c.lims
	case pgalloc.CtxMemoryFile:
		return c.mf
	case ktime.CtxRealtimeClock:
		return c.clock
	}
	return c.Context.Value(key)
}

func newBridgeTestContext(t *testing.T) (gvcontext.Context, *auth.Credentials, *pgalloc.MemoryFile) {
	t.Helper()
	memFD, err := memutil.CreateMemFD("gvx-state-bridge-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(memFD), "gvx-state-bridge-test"), pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	mf.MarkSavable()
	t.Cleanup(mf.Destroy)

	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	return bridgeTestContext{
		Context: gvcontext.Background(),
		creds:   creds,
		lims:    limits.NewLimitSet(),
		mf:      mf,
		clock:   &ktime.SyntheticClock{},
	}, creds, mf
}

// savedBridgeGraph groups the VFS, stdio FDs, ttyState, netns creator, and chunk wrapper for state round-trip tests.
type savedBridgeGraph struct {
	vfsObj *vfs.VirtualFilesystem
	fds    [3]*vfs.FileDescription
	tty    *ttyState
	pump   *stdinPump
	netns  *guestNetnsCreator
	chunks *memoryFileChunks
}

func (g *savedBridgeGraph) StateTypeName() string {
	return "pkg/gvx.savedBridgeGraph"
}

func (g *savedBridgeGraph) StateFields() []string {
	return []string{"vfsObj", "fds", "tty", "pump", "netns", "chunks"}
}

func (g *savedBridgeGraph) StateSave(sink state.Sink) {
	sink.Save(0, &g.vfsObj)
	sink.Save(1, &g.fds)
	sink.Save(2, &g.tty)
	sink.Save(3, &g.pump)
	sink.Save(4, &g.netns)
	sink.Save(5, &g.chunks)
}

func (g *savedBridgeGraph) StateLoad(_ context.Context, src state.Source) {
	src.Load(0, &g.vfsObj)
	src.Load(1, &g.fds)
	src.Load(2, &g.tty)
	src.Load(3, &g.pump)
	src.Load(4, &g.netns)
	src.Load(5, &g.chunks)
}

func init() {
	state.RegisterNoHooks((*savedBridgeGraph)(nil))
}

func readBlockingFD(t *testing.T, ctx gvcontext.Context, fd *vfs.FileDescription, maxBytes int) string {
	t.Helper()
	buf := make([]byte, maxBytes)
	n, err := fd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if !errors.Is(err, linuxerr.ErrWouldBlock) {
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("fd.Read: %v", err)
		}
		return string(buf[:n])
	}

	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventHUp)
	if err := fd.EventRegister(&we); err != nil {
		t.Fatalf("EventRegister: %v", err)
	}
	defer fd.EventUnregister(&we)

	deadline := time.After(2 * time.Second)
	for {
		n, err = fd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
		if errors.Is(err, linuxerr.ErrWouldBlock) {
			select {
			case <-ch:
				continue
			case <-deadline:
				t.Fatal("timed out waiting for restored stdin readiness")
			}
		}
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("fd.Read: %v", err)
		}
		return string(buf[:n])
	}
}

func TestStateBridgeNonTTYStdioRoundTrip(t *testing.T) {
	ctx, creds, _ := newBridgeTestContext(t)
	_, _, restoreMF := newBridgeTestContext(t)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("vfsObj.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(tmpfs.Name, tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	var oldStdout, oldStderr bytes.Buffer
	oldStdin := strings.NewReader("ignored-after-save")
	pump := newStdinPump(oldStdin)
	pump.buf = []byte("buffered-pre-save:")

	fds, err := openStdioFDs(ctx, vfsObj, creds, oldStdin, &oldStdout, &oldStderr, nil, pump)
	if err != nil {
		t.Fatalf("openStdioFDs: %v", err)
	}

	orig := &savedBridgeGraph{
		vfsObj: vfsObj,
		fds:    fds,
		pump:   pump,
		chunks: &memoryFileChunks{},
	}
	var stateBuf bytes.Buffer
	if _, err := state.Save(context.Background(), &stateBuf, orig); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	for _, fd := range fds {
		fd.DecRef(ctx)
	}
	vfsObj.Release(ctx)

	var newStdout, newStderr bytes.Buffer
	loadCtx := context.WithValue(context.Background(), pgalloc.CtxMemoryFile, restoreMF)
	loadCtx = WithRestoreStdio(loadCtx, RestoreStdio{
		Stdin:  strings.NewReader("fresh-post-restore\n"),
		Stdout: &newStdout,
		Stderr: &newStderr,
	})
	var restored savedBridgeGraph
	if _, err := state.Load(loadCtx, bytes.NewReader(stateBuf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer func() {
		restored.pump.stop()
		for _, fd := range restored.fds {
			fd.DecRef(ctx)
		}
		restored.vfsObj.Release(ctx)
	}()

	// Verify restored stdout and stderr write to the newly injected host buffers.
	if _, err := restored.fds[1].Write(ctx, usermem.BytesIOSequence([]byte("hello-stdout\n")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("restored stdout Write: %v", err)
	}
	if _, err := restored.fds[2].Write(ctx, usermem.BytesIOSequence([]byte("hello-stderr\n")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("restored stderr Write: %v", err)
	}
	if oldStdout.Len() != 0 || oldStderr.Len() != 0 {
		t.Fatalf("writes leaked to pre-save buffers: stdout=%q stderr=%q", oldStdout.String(), oldStderr.String())
	}
	if newStdout.String() != "hello-stdout\n" {
		t.Fatalf("newStdout = %q, want %q", newStdout.String(), "hello-stdout\n")
	}
	if newStderr.String() != "hello-stderr\n" {
		t.Fatalf("newStderr = %q, want %q", newStderr.String(), "hello-stderr\n")
	}

	// First read drains saved unread bytes in stdinPump.buf, second read pulls from fresh host Stdin.
	first := readBlockingFD(t, ctx, restored.fds[0], 64)
	if first != "buffered-pre-save:" {
		t.Fatalf("first restored stdin Read = %q, want %q", first, "buffered-pre-save:")
	}
	second := readBlockingFD(t, ctx, restored.fds[0], 64)
	if second != "fresh-post-restore\n" {
		t.Fatalf("second restored stdin Read = %q, want %q", second, "fresh-post-restore\n")
	}

	// Reopening the character device node creates a fresh stdioFD bound to the restored host writer.
	stdoutVD := restored.fds[1].VirtualDentry()
	reopened, err := restored.vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:               stdoutVD,
		Start:              stdoutVD,
		Path:               fspath.Parse(""),
		FollowFinalSymlink: true,
	}, &vfs.OpenOptions{Flags: linux.O_WRONLY})
	if err != nil {
		t.Fatalf("reopen stdout device node: %v", err)
	}
	defer reopened.DecRef(ctx)
	if _, err := reopened.Write(ctx, usermem.BytesIOSequence([]byte("reopened-ok\n")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("reopened stdout Write: %v", err)
	}
	if newStdout.String() != "hello-stdout\nreopened-ok\n" {
		t.Fatalf("newStdout after reopen = %q, want %q", newStdout.String(), "hello-stdout\nreopened-ok\n")
	}
}

func TestStateBridgeTTYAndNetnsCreatorRoundTrip(t *testing.T) {
	ctx, creds, _ := newBridgeTestContext(t)
	_, _, restoreMF := newBridgeTestContext(t)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("vfsObj.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(tmpfs.Name, tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	var oldOut bytes.Buffer
	tty := newTTYState(nil, &oldOut, true, 40, 120)
	tty.consumeInput([]byte("queued-line\r"))
	oldOut.Reset()

	fds, err := openStdioFDs(ctx, vfsObj, creds, nil, &oldOut, &oldOut, tty, nil)
	if err != nil {
		t.Fatalf("openStdioFDs(tty): %v", err)
	}

	netns := newGuestNetnsCreator(nil, netbackend.StackOptions{
		RawSockets:        true,
		PacketSocketWrite: true,
	})

	orig := &savedBridgeGraph{
		vfsObj: vfsObj,
		fds:    fds,
		tty:    tty,
		netns:  netns,
	}
	var stateBuf bytes.Buffer
	if _, err := state.Save(context.Background(), &stateBuf, orig); err != nil {
		t.Fatalf("state.Save(tty+netns): %v", err)
	}

	for _, fd := range fds {
		fd.DecRef(ctx)
	}
	vfsObj.Release(ctx)

	var newOut, newErr bytes.Buffer
	var hookCalled bool
	var hookOpts netbackend.StackOptions
	hook := func(k *kernel.Kernel, opts netbackend.StackOptions) (inet.Stack, error) {
		hookCalled = true
		hookOpts = opts
		return (&guestNetnsCreator{
			k:                 k,
			rawSockets:        opts.RawSockets,
			packetSocketWrite: opts.PacketSocketWrite,
		}).CreateStack()
	}

	loadCtx := context.WithValue(context.Background(), pgalloc.CtxMemoryFile, restoreMF)
	loadCtx = WithRestoreStdio(loadCtx, RestoreStdio{
		Stdin:  strings.NewReader("after-restore-tty\n"),
		Stdout: &newOut,
		Stderr: &newErr,
	})
	loadCtx = WithRestoreNetnsHook(loadCtx, hook)

	var restored savedBridgeGraph
	if _, err := state.Load(loadCtx, bytes.NewReader(stateBuf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load(tty+netns): %v", err)
	}
	defer func() {
		restored.tty.stop()
		for _, fd := range restored.fds {
			fd.DecRef(ctx)
		}
		restored.vfsObj.Release(ctx)
	}()

	if restored.tty.winsize.Row != 40 || restored.tty.winsize.Col != 120 {
		t.Fatalf("restored tty winsize = (%d, %d), want (40, 120)", restored.tty.winsize.Row, restored.tty.winsize.Col)
	}

	// ONLCR translates \n to \r\n on the restored TTY stdout stream.
	if _, err := restored.fds[1].Write(ctx, usermem.BytesIOSequence([]byte("tty-out\n")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("restored tty stdout Write: %v", err)
	}
	if !strings.Contains(newOut.String(), "tty-out\r\n") {
		t.Fatalf("newOut = %q, want substring %q", newOut.String(), "tty-out\r\n")
	}
	if _, err := restored.fds[2].Write(ctx, usermem.BytesIOSequence([]byte("tty-err\n")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("restored tty stderr Write: %v", err)
	}
	if newErr.String() != "tty-err\r\n" {
		t.Fatalf("newErr = %q, want %q", newErr.String(), "tty-err\r\n")
	}

	// Drain pre-checkpoint queued line, then read fresh post-restore TTY input.
	line1 := readBlockingFD(t, ctx, restored.fds[0], 64)
	if line1 != "queued-line\n" {
		t.Fatalf("first restored tty Read = %q, want %q", line1, "queued-line\n")
	}
	line2 := readBlockingFD(t, ctx, restored.fds[0], 64)
	if line2 != "after-restore-tty\n" {
		t.Fatalf("second restored tty Read = %q, want %q", line2, "after-restore-tty\n")
	}

	// Verify guestNetnsCreator restored options and rebound NetnsStackHook via context.
	stack, err := restored.netns.CreateStack()
	if err != nil || stack == nil {
		t.Fatalf("restored netns.CreateStack = (%v, %v), want non-nil stack", stack, err)
	}
	stack.Destroy()
	if !hookCalled {
		t.Fatal("expected restored guestNetnsCreator to invoke NetnsStackHook from context")
	}
	if !hookOpts.RawSockets || !hookOpts.PacketSocketWrite || hookOpts.IPTables == nil {
		t.Fatalf("restored NetnsStackHook StackOptions = %+v, want RawSockets=true PacketSocketWrite=true IPTables!=nil", hookOpts)
	}
}

func TestStateBridgeDrainBufferedStdinWithoutRestoreReader(t *testing.T) {
	ctx, creds, _ := newBridgeTestContext(t)
	_, _, restoreMF := newBridgeTestContext(t)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("vfsObj.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(tmpfs.Name, tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	pump := newStdinPump(strings.NewReader("unused"))
	pump.buf = []byte("saved-pump-bytes")
	fds, err := openStdioFDs(ctx, vfsObj, creds, strings.NewReader("unused"), io.Discard, io.Discard, nil, pump)
	if err != nil {
		t.Fatalf("openStdioFDs(pump): %v", err)
	}

	var buf bytes.Buffer
	orig := &savedBridgeGraph{
		vfsObj: vfsObj,
		fds:    fds,
		pump:   pump,
		chunks: &memoryFileChunks{},
	}
	if _, err := state.Save(context.Background(), &buf, orig); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	for _, fd := range fds {
		fd.DecRef(ctx)
	}
	vfsObj.Release(ctx)

	// Load without WithRestoreStdio so Stdin is nil, and verify buffered bytes still drain before EOF.
	loadCtx := context.WithValue(context.Background(), pgalloc.CtxMemoryFile, restoreMF)
	var restored savedBridgeGraph
	if _, err := state.Load(loadCtx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer func() {
		restored.pump.stop()
		for _, fd := range restored.fds {
			fd.DecRef(ctx)
		}
		restored.vfsObj.Release(ctx)
	}()

	if restored.chunks.MemoryFile != restoreMF {
		t.Fatalf("restored memoryFileChunks.MemoryFile = %p, want %p", restored.chunks.MemoryFile, restoreMF)
	}
	if got := readBlockingFD(t, ctx, restored.fds[0], 64); got != "saved-pump-bytes" {
		t.Fatalf("restored pump Read with nil Stdin = %q, want %q", got, "saved-pump-bytes")
	}
	eofBuf := make([]byte, 16)
	n, err := restored.fds[0].Read(ctx, usermem.BytesIOSequence(eofBuf), vfs.ReadOptions{})
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("subsequent Read after draining pump = (%d, %v), want (0, io.EOF)", n, err)
	}
}
