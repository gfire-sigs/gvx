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
	"context"
	"fmt"
	"io"
	"sync"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/socket/netfilter"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/waiter"
)

type restoreContextKey int

const (
	ctxRestoreStdio restoreContextKey = iota
	ctxRestoreNetnsHook
)

// RestoreStdio carries the host standard streams attached during checkpoint restore.
type RestoreStdio struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	RawHost *bool
}

// WithRestoreStdio binds host stdio streams to ctx for state.Load rebinding.
func WithRestoreStdio(ctx context.Context, stdio RestoreStdio) context.Context {
	return context.WithValue(ctx, ctxRestoreStdio, stdio)
}

// RestoreStdioFromContext reads the host stdio streams bound to ctx.
func RestoreStdioFromContext(ctx context.Context) (RestoreStdio, bool) {
	if ctx == nil {
		return RestoreStdio{}, false
	}
	stdio, ok := ctx.Value(ctxRestoreStdio).(RestoreStdio)
	return stdio, ok
}

// NetnsStackHook builds a guest network stack for a newly unshared network namespace.
type NetnsStackHook func(k *kernel.Kernel, opts netbackend.StackOptions) (inet.Stack, error)

// WithRestoreNetnsHook binds a guest network-namespace stack hook to ctx for state.Load.
func WithRestoreNetnsHook(ctx context.Context, hook NetnsStackHook) context.Context {
	return context.WithValue(ctx, ctxRestoreNetnsHook, hook)
}

// RestoreNetnsHookFromContext reads the guest network-namespace stack hook bound to ctx.
func RestoreNetnsHookFromContext(ctx context.Context) NetnsStackHook {
	if ctx == nil {
		return nil
	}
	hook, _ := ctx.Value(ctxRestoreNetnsHook).(NetnsStackHook)
	return hook
}

// stdioStreamKind identifies which host stream backs a stdioDevice or stdioFD.
type stdioStreamKind uint8

const (
	stdioStreamStdin stdioStreamKind = iota
	stdioStreamStdout
	stdioStreamStderr
	stdioStreamCTTY
)

func resolveStdioStreams(stream stdioStreamKind, sharedOutErr, isTTY bool, stdio RestoreStdio) (io.Reader, io.Writer) {
	if isTTY {
		switch stream {
		case stdioStreamStderr:
			errw := stdio.Stderr
			if errw == nil && sharedOutErr {
				errw = stdio.Stdout
			}
			return stdio.Stdin, errw
		default:
			return stdio.Stdin, stdio.Stdout
		}
	}
	switch stream {
	case stdioStreamStdin:
		return stdio.Stdin, nil
	case stdioStreamStdout:
		return nil, stdio.Stdout
	case stdioStreamStderr:
		return nil, stdio.Stderr
	default:
		return nil, nil
	}
}

// ttyState implements kernel.TTYOperations for a guest console or host terminal.
//
// +stateify savable
type ttyState struct {
	mu          sync.Mutex `state:"nosave"`
	termios     linux.KernelTermios
	winsize     linux.Winsize
	fgPgrp      int32
	session     int32
	rawHost     bool
	lineBuf     []byte
	readBuf     []byte
	pendingEOF  bool
	hostEOF     bool
	hostErr     error `state:"nosave"`
	stopped     bool
	pumpStarted bool `state:"nosave"`

	in    io.Reader   `state:"nosave"`
	out   io.Writer   `state:"nosave"`
	outMu *sync.Mutex `state:"nosave"`
	ktty  *kernel.TTY
	wq    waiter.Queue
}

var _ kernel.TTYOperations = (*ttyState)(nil)

func (t *ttyState) afterLoad(ctx context.Context) {
	t.outMu = new(sync.Mutex)
	if stdio, ok := RestoreStdioFromContext(ctx); ok {
		t.in = stdio.Stdin
		t.out = stdio.Stdout
		if stdio.RawHost != nil {
			t.rawHost = *stdio.RawHost
		}
		t.hostErr = nil
		t.stopped = false
	}
	if t.in == nil {
		t.hostEOF = true
	} else {
		t.hostEOF = false
	}
}

// ActivateRestoredTTY starts the background host terminal reader pump when a
// restored TTY has a live stdin stream.
func (t *ttyState) ActivateRestoredTTY() {
	if t == nil {
		return
	}
	t.ensurePumpStarted()
}

// stdinPump reads a host io.Reader in a helper goroutine so guest reads stay interruptible.
//
// At most one host read runs at a time. The pump starts a read only when a guest
// read or poll waits for input, avoiding read-ahead beyond one chunk.
//
// +stateify savable
type stdinPump struct {
	r  io.Reader `state:"nosave"`
	wq waiter.Queue

	mu sync.Mutex `state:"nosave"`
	// buf holds bytes returned by the host reader that the guest has not consumed yet.
	buf []byte
	// err records the terminal error returned by the host reader.
	err error `state:"nosave"`
	// pending reports whether a helper goroutine currently reads the host stream.
	pending bool `state:"nosave"`
	// stopped reports whether the sandbox stopped the pump.
	stopped bool `state:"nosave"`
	// readDone closes when the active helper goroutine exits.
	readDone chan struct{} `state:"nosave"`
}

func (p *stdinPump) afterLoad(ctx context.Context) {
	if stdio, ok := RestoreStdioFromContext(ctx); ok {
		p.r = stdio.Stdin
	}
	if p.r == nil {
		p.err = io.EOF
	}
}

// stdioDevice implements vfs.Device for one guest standard stream.
//
// Each standard stream lives behind a character device node on a private tmpfs
// mount so guests can reopen /dev/std* and /proc/self/fd/N cleanly.
//
// +stateify savable
type stdioDevice struct {
	stream       stdioStreamKind
	sharedOutErr bool
	reader       io.Reader   `state:"nosave"`
	writer       io.Writer   `state:"nosave"`
	tty          *ttyState   `state:"wait"`
	pump         *stdinPump  `state:"wait"`
	mu           *sync.Mutex `state:"nosave"`
}

var _ vfs.Device = (*stdioDevice)(nil)

func (d *stdioDevice) afterLoad(ctx context.Context) {
	stdio, hasStdio := RestoreStdioFromContext(ctx)
	if hasStdio {
		d.reader, d.writer = resolveStdioStreams(d.stream, d.sharedOutErr, d.tty != nil, stdio)
	}
	if d.tty != nil && (d.stream != stdioStreamStderr || d.sharedOutErr || (hasStdio && d.writer == d.tty.out)) {
		d.mu = d.tty.outMu
		return
	}
	d.mu = new(sync.Mutex)
}

// stdioFD implements vfs.FileDescriptionImpl for one open guest standard stream.
//
// +stateify savable
type stdioFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.NoLockFD

	stream       stdioStreamKind
	sharedOutErr bool
	dev          *stdioDevice `state:"wait"`
	reader       io.Reader    `state:"nosave"`
	writer       io.Writer    `state:"nosave"`
	tty          *ttyState    `state:"wait"`
	pump         *stdinPump   `state:"wait"`
	mu           *sync.Mutex  `state:"nosave"`
}

var _ vfs.FileDescriptionImpl = (*stdioFD)(nil)

func (f *stdioFD) afterLoad(ctx context.Context) {
	if f.dev != nil {
		f.reader = f.dev.reader
		f.writer = f.dev.writer
		f.mu = f.dev.mu
		return
	}
	if stdio, ok := RestoreStdioFromContext(ctx); ok {
		f.reader, f.writer = resolveStdioStreams(f.stream, f.sharedOutErr, f.tty != nil, stdio)
	}
	if f.tty != nil && (f.stream != stdioStreamStderr || f.sharedOutErr || f.writer == f.tty.out) {
		f.mu = f.tty.outMu
		return
	}
	f.mu = new(sync.Mutex)
}

// guestNetnsCreator creates the loopback network stack of a newly unshared guest network namespace.
//
// +stateify savable
type guestNetnsCreator struct {
	k                 *kernel.Kernel
	rawSockets        bool
	packetSocketWrite bool
	createStackHook   NetnsStackHook `state:"nosave"`
}

var _ inet.NetworkStackCreator = (*guestNetnsCreator)(nil)

func newGuestNetnsCreator(k *kernel.Kernel, opts netbackend.StackOptions) *guestNetnsCreator {
	return &guestNetnsCreator{
		k:                 k,
		rawSockets:        opts.RawSockets,
		packetSocketWrite: opts.PacketSocketWrite,
	}
}

func (c *guestNetnsCreator) stackOptions() netbackend.StackOptions {
	opts := netbackend.StackOptions{
		RawSockets:        c.rawSockets,
		PacketSocketWrite: c.packetSocketWrite,
	}
	if c.rawSockets {
		opts.IPTables = netfilter.DefaultLinuxTables
	}
	return opts
}

func (c *guestNetnsCreator) afterLoad(ctx context.Context) {
	c.createStackHook = RestoreNetnsHookFromContext(ctx)
}

// CreateStack implements inet.NetworkStackCreator.CreateStack.
func (c *guestNetnsCreator) CreateStack() (inet.Stack, error) {
	opts := c.stackOptions()
	if c.createStackHook != nil {
		return c.createStackHook(c.k, opts)
	}
	st, err := netbackend.NewLoopbackStack(opts)
	if err != nil {
		return nil, err
	}
	if c.k == nil {
		stack := netstack.NewStack(st, 0)
		stack.InitConntrackLimit(nil)
		return stack, nil
	}
	stack := netstack.NewStack(st, c.k.UniqueID())
	// Linux copies IPv4 forwarding switches and rp_filter from the root network namespace.
	var root *netstack.Stack
	if rootNS := c.k.RootNetworkNamespace(); rootNS != nil {
		root, _ = rootNS.Stack().(*netstack.Stack)
	}
	if root != nil {
		if err := stack.InheritForwarding(root); err != nil {
			return nil, fmt.Errorf("gvx: copy the forwarding switches to a new network namespace: %w", err)
		}
		netfilter.ShareRecentModule(st, root.Stack)
		stack.InheritRPFilter(root)
	}
	stack.InitConntrackLimit(root)
	return stack, nil
}

// memoryFileChunks stores mapped hostfs and ext4lite file chunks inside the kernel MemoryFile.
//
// +stateify savable
type memoryFileChunks struct {
	*pgalloc.MemoryFile `state:"nosave"`
}

func (m *memoryFileChunks) afterLoad(ctx context.Context) {
	if mf := pgalloc.MemoryFileFromContext(ctx); mf != nil {
		m.MemoryFile = mf
	}
}
